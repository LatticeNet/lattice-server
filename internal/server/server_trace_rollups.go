package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-server/internal/tracestore"
)

// GET /api/trace/rollups: trends from the five-minute rollups, the first
// reader rollups_5m has had. Counts, measured bytes and close reasons per
// node, line, user or reason; never a destination, because the rollups never
// hold one.
//
// The step follows the window so R2 can switch the source to its hourly and
// daily tiers without changing the wire. In R1 every step is coarsened from
// rollups_5m on read and tier is always "5m".
//
// Design: lattice/docs/designs/design-26-evidence-retention.md section 8.

const (
	// traceRollupsDefaultWindow is the window when since is not given.
	traceRollupsDefaultWindow = 24 * time.Hour
	// traceRollupsMaxWindow is the longest tier R2 will hold. Refusing more
	// now keeps the wire stable when that tier arrives.
	traceRollupsMaxWindow = 400 * 24 * time.Hour
	// traceRollupsMinYear and traceRollupsMaxYear bound since and until well
	// inside what unix nanoseconds can hold (1678 to 2262).
	traceRollupsMinYear = 1970
	traceRollupsMaxYear = 2200
)

// traceRollupGroupings are the accepted group_by values.
var traceRollupGroupings = map[string]bool{
	tracestore.RollupGroupNode:   true,
	tracestore.RollupGroupLine:   true,
	tracestore.RollupGroupUser:   true,
	tracestore.RollupGroupReason: true,
}

// traceRollupStep picks the point width from the window: up to 7 days five
// minutes, up to 90 days an hour, longer a day. The same thresholds pick the
// tier in R2.
func traceRollupStep(window time.Duration) time.Duration {
	switch {
	case window <= 7*24*time.Hour:
		return tracestore.RollupBucket
	case window <= 90*24*time.Hour:
		return time.Hour
	default:
		return 24 * time.Hour
	}
}

// traceRollupSeriesView is one series in columnar form. T is each step's
// start in unix seconds and is sparse: a step with nothing recorded is
// absent, so consecutive values further apart than step_seconds are a gap.
// Every other array is aligned with T. A reason series carries T and
// Connections only.
type traceRollupSeriesView struct {
	Key             string             `json:"key"`
	T               []int64            `json:"t"`
	Connections     []int64            `json:"connections"`
	BytesKnownCount []int64            `json:"bytes_known_count,omitempty"`
	Upload          []int64            `json:"upload,omitempty"`
	Download        []int64            `json:"download,omitempty"`
	CloseReasons    map[string][]int64 `json:"close_reasons,omitempty"`
}

// traceRollupsView follows the vocabulary of metricsQueryView
// (server_selfmon_api.go) so the console reads both histories the same way.
type traceRollupsView struct {
	Tier              string    `json:"tier"`
	ResolutionSeconds int64     `json:"resolution_seconds"`
	StepSeconds       int64     `json:"step_seconds"`
	Since             time.Time `json:"since"`
	Until             time.Time `json:"until"`
	// RetainedFrom is the oldest bucket held for the nodes the caller may see.
	// Absent when nothing is held.
	RetainedFrom time.Time               `json:"retained_from,omitzero"`
	GroupBy      string                  `json:"group_by"`
	Series       []traceRollupSeriesView `json:"series"`
	Truncated    bool                    `json:"truncated"`
}

func (s *Server) handleTraceRollups(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireScope(w, p, "log:read") || !s.traceStoreReady(w) {
		return
	}
	q := r.URL.Query()
	until, err := rfc3339Param(q, "until")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if until.IsZero() {
		until = s.now()
	}
	since, err := rfc3339Param(q, "since")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if since.IsZero() {
		since = until.Add(-traceRollupsDefaultWindow)
	}
	since, until = since.UTC(), until.UTC()
	// Outside these years an instant does not fit in the store's unix
	// nanoseconds, and the window arithmetic below would wrap.
	if since.Year() < traceRollupsMinYear || until.Year() > traceRollupsMaxYear {
		writeError(w, http.StatusBadRequest, fmt.Errorf("since and until must fall between %d and %d", traceRollupsMinYear, traceRollupsMaxYear))
		return
	}
	if !since.Before(until) {
		writeError(w, http.StatusBadRequest, errors.New("since must be before until"))
		return
	}
	window := until.Sub(since)
	if window > traceRollupsMaxWindow {
		writeError(w, http.StatusBadRequest, errors.New("the window may be at most 400 days"))
		return
	}
	groupBy := strings.TrimSpace(q.Get("group_by"))
	if !traceRollupGroupings[groupBy] {
		writeError(w, http.StatusBadRequest, errors.New("group_by must be node, line, user or reason"))
		return
	}
	step := traceRollupStep(window)
	view := traceRollupsView{
		Tier:              "5m",
		ResolutionSeconds: int64(tracestore.RollupBucket / time.Second),
		StepSeconds:       int64(step / time.Second),
		// The leading step is whole: since is truncated down to the step, the
		// same truncation the store applies.
		Since:   time.Unix(0, since.UnixNano()/int64(step)*int64(step)).UTC(),
		Until:   until,
		GroupBy: groupBy,
		Series:  []traceRollupSeriesView{},
	}
	nodes := s.visibleNodeIDs(p, "log:read", csvParam(q, "node_id"))
	if len(nodes) == 0 {
		// No visible node is an empty answer, not a 403, as on
		// /api/trace/connections: a narrow allowlist is legitimate.
		writeJSON(w, http.StatusOK, view)
		return
	}
	points, retainedFrom, truncated, err := s.traceStore.RollupSeries(tracestore.RollupSeriesFilter{
		Since:     since,
		Until:     until,
		Step:      step,
		GroupBy:   groupBy,
		NodeIDs:   nodes,
		LineUUIDs: csvParam(q, "line_uuid"),
		UserIDs:   csvParam(q, "user_id"),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	view.RetainedFrom = retainedFrom
	view.Truncated = truncated
	view.Series = traceRollupSeries(points, groupBy == tracestore.RollupGroupReason)
	writeJSON(w, http.StatusOK, view)
}

// traceRollupSeries turns the store's points, which arrive grouped by key and
// ascending in time, into columnar series in the same order.
func traceRollupSeries(points []tracestore.RollupPoint, byReason bool) []traceRollupSeriesView {
	out := []traceRollupSeriesView{}
	for start := 0; start < len(points); {
		end := start
		for end < len(points) && points[end].Key == points[start].Key {
			end++
		}
		run := points[start:end]
		sv := traceRollupSeriesView{
			Key:         run[0].Key,
			T:           make([]int64, len(run)),
			Connections: make([]int64, len(run)),
		}
		if !byReason {
			sv.BytesKnownCount = make([]int64, len(run))
			sv.Upload = make([]int64, len(run))
			sv.Download = make([]int64, len(run))
			sv.CloseReasons = map[string][]int64{}
		}
		for i, pt := range run {
			sv.T[i] = pt.BucketStart.Unix()
			sv.Connections[i] = pt.Connections
			if byReason {
				continue
			}
			sv.BytesKnownCount[i] = pt.BytesKnownCount
			sv.Upload[i] = pt.Upload
			sv.Download[i] = pt.Download
			for reason, n := range pt.CloseReasons {
				col := sv.CloseReasons[reason]
				if col == nil {
					// A reason first seen mid-series reads zero before it.
					col = make([]int64, len(run))
					sv.CloseReasons[reason] = col
				}
				col[i] = n
			}
		}
		out = append(out, sv)
		start = end
	}
	return out
}
