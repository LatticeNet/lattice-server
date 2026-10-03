package server

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// Latency rollup reads: per pair p50 and p95 handshake round trip and loss
// over 1 h, 24 h and 7 d, and one pair's series over one window.
//
// Where each window comes from:
//
//   - 1 h: the pair's raw rows, exactly. A pair keeps MonitorResultsPerPair
//     rows, which is more than an hour at any allowed interval.
//   - 24 h: the five-minute rollups, from the bucket holding now minus 24 h.
//   - 7 d: the one-hour rollups, from the bucket holding now minus 7 d.
//
// Unknown stays unknown. A window counts the probes the control plane heard
// (Samples) beside the probes the interval would have produced over the span
// it covers (Expected); percentiles and loss are absent when nothing was
// heard. A gap in the results is therefore never drawn as up or as down.
// Expected uses the interval configured now; a window that spans an interval
// change says so only through Samples running ahead of or behind it.
//
// This is also the seam for a degradation alert: an evaluator in the
// incident path can call latencyRollupsFor on its own schedule and judge the
// 1 h loss against a threshold, without any probe result being audited or
// paged one by one (notifyMonitorTransition skips generated monitors).

var latencyWindows = []struct {
	name string
	span time.Duration
	res  time.Duration
}{
	{model.LatencyWindowHour, time.Hour, time.Minute},
	{model.LatencyWindowDay, 24 * time.Hour, store.MonitorRollupFine},
	{model.LatencyWindowWeek, 7 * 24 * time.Hour, store.MonitorRollupCoarse},
}

func latencyWindowSpec(name string) (span, res time.Duration, ok bool) {
	for _, w := range latencyWindows {
		if w.name == name {
			return w.span, w.res, true
		}
	}
	return 0, 0, false
}

func latencyRound(v float64) *float64 {
	r := math.Round(v*10) / 10
	return &r
}

// latencyStatsOf turns a merged bucket into the wire shape.
func latencyStatsOf(b store.MonitorRollup, expected int) model.LatencyStats {
	st := model.LatencyStats{Samples: b.N, Failures: b.F, Expected: max(expected, 0)}
	if b.N > 0 {
		loss := math.Round(float64(b.F)/float64(b.N)*10000) / 10000
		st.Loss = &loss
	}
	if p, ok := b.Quantile(0.5); ok {
		st.P50Ms = latencyRound(p)
	}
	if p, ok := b.Quantile(0.95); ok {
		st.P95Ms = latencyRound(p)
	}
	return st
}

func latencyExpected(span, interval time.Duration) int {
	if interval <= 0 || span <= 0 {
		return 0
	}
	return int(span / interval)
}

// latencyRecentRows reads one pair's rows of the last hour, oldest first.
func (s *Server) latencyRecentRows(monitorID, sourceID string, interval time.Duration, from time.Time) ([]store.MonitorResultRecord, error) {
	limit := store.MonitorResultsPerPair
	if interval > 0 {
		limit = min(int(time.Hour/interval)+5, store.MonitorResultsPerPair)
	}
	rows, err := s.store.MonitorPairResults(monitorID, sourceID, limit)
	if err != nil {
		return nil, err
	}
	kept := rows[:0]
	for _, row := range rows {
		if !row.At.Before(from) {
			kept = append(kept, row)
		}
	}
	return kept, nil
}

// latencyRollupsFor summarizes every pair of the plan that has a monitor.
func (s *Server) latencyRollupsFor(plan model.LatencyProbePlan, now time.Time) (model.LatencyRollups, error) {
	now = now.UTC()
	interval := time.Duration(plan.Config.IntervalSec) * time.Second
	out := model.LatencyRollups{GeneratedAt: now, IntervalSec: plan.Config.IntervalSec, Pairs: []model.LatencyPairRollup{}}
	var pairs []store.MonitorPair
	for _, pair := range plan.Pairs {
		if pair.MonitorID != "" {
			pairs = append(pairs, store.MonitorPair{MonitorID: pair.MonitorID, NodeID: pair.Source})
		}
	}
	if len(pairs) == 0 {
		return out, nil
	}
	tiers := map[string]map[store.MonitorPair][]store.MonitorRollup{}
	spans := map[string]time.Duration{}
	for _, w := range latencyWindows {
		if w.name == model.LatencyWindowHour {
			spans[w.name] = w.span
			continue
		}
		from := now.Add(-w.span).Truncate(w.res)
		buckets, err := s.store.MonitorRollups(pairs, w.res, from, now.Add(time.Nanosecond))
		if err != nil {
			return out, err
		}
		tiers[w.name] = buckets
		spans[w.name] = now.Sub(from)
	}
	latest, err := s.store.LatestMonitorResults()
	if err != nil {
		return out, err
	}
	hourFrom := now.Add(-time.Hour)
	for _, pair := range pairs {
		rows, err := s.latencyRecentRows(pair.MonitorID, pair.NodeID, interval, hourFrom)
		if err != nil {
			return out, err
		}
		windows := map[string]model.LatencyStats{
			model.LatencyWindowHour: latencyStatsOf(store.SummarizeMonitorResults(rows), latencyExpected(spans[model.LatencyWindowHour], interval)),
		}
		for name, buckets := range tiers {
			windows[name] = latencyStatsOf(store.MergeMonitorRollups(buckets[pair]), latencyExpected(spans[name], interval))
		}
		rollup := model.LatencyPairRollup{Source: pair.NodeID, MonitorID: pair.MonitorID, Windows: windows}
		for _, p := range plan.Pairs {
			if p.MonitorID == pair.MonitorID && p.Source == pair.NodeID {
				rollup.Target = p.Target
				break
			}
		}
		for _, l := range latest[pair.MonitorID] {
			if l.NodeID == pair.NodeID {
				res := l.MonitorResult
				rollup.Latest = &res
				break
			}
		}
		out.Pairs = append(out.Pairs, rollup)
	}
	return out, nil
}

// latencySeriesFor is one pair over one window, every bucket present.
func (s *Server) latencySeriesFor(monitorID, sourceID, targetID, window string, interval time.Duration, now time.Time) (model.LatencySeries, error) {
	span, res, ok := latencyWindowSpec(window)
	if !ok {
		return model.LatencySeries{}, fmt.Errorf("window must be %s, %s or %s", model.LatencyWindowHour, model.LatencyWindowDay, model.LatencyWindowWeek)
	}
	now = now.UTC()
	from := now.Add(-span).Truncate(res)
	to := now.Add(time.Nanosecond)
	var buckets []store.MonitorRollup
	if window == model.LatencyWindowHour {
		rows, err := s.latencyRecentRows(monitorID, sourceID, interval, from)
		if err != nil {
			return model.LatencySeries{}, err
		}
		buckets = store.RollupMonitorResults(rows, res, from, to)
	} else {
		pair := store.MonitorPair{MonitorID: monitorID, NodeID: sourceID}
		read, err := s.store.MonitorRollups([]store.MonitorPair{pair}, res, from, to)
		if err != nil {
			return model.LatencySeries{}, err
		}
		buckets = read[pair]
	}
	byStart := make(map[time.Time]store.MonitorRollup, len(buckets))
	for _, b := range buckets {
		byStart[b.At.UTC()] = b
	}
	out := model.LatencySeries{
		Source:    sourceID,
		Target:    targetID,
		MonitorID: monitorID,
		Window:    window,
		BucketSec: int(res / time.Second),
		From:      from,
		To:        now,
		Buckets:   []model.LatencyBucket{},
	}
	for start := from; !start.After(now); start = start.Add(res) {
		covered := res
		if end := start.Add(res); end.After(now) {
			covered = now.Sub(start)
		}
		b := byStart[start]
		out.Buckets = append(out.Buckets, model.LatencyBucket{At: start, LatencyStats: latencyStatsOf(b, latencyExpected(covered, interval))})
	}
	return out, nil
}

// handleLatencyRollups answers GET /api/monitors/latency/rollups.
func (s *Server) handleLatencyRollups(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	now := s.now()
	plan := latencyPlanForPrincipal(s.planLatencyProbes(now).plan, p)
	out, err := s.latencyRollupsFor(plan, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleLatencySeries answers GET /api/monitors/latency/series?source=&target=&window=.
func (s *Server) handleLatencySeries(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	q := r.URL.Query()
	sourceID, targetID, window := q.Get("source"), q.Get("target"), q.Get("window")
	if window == "" {
		window = model.LatencyWindowDay
	}
	if sourceID == "" || targetID == "" {
		writeError(w, http.StatusBadRequest, errors.New("source and target are required"))
		return
	}
	if !latencyNodeVisible(p, sourceID) || !latencyNodeVisible(p, targetID) {
		writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
		return
	}
	monitorID := latencyMonitorID(targetID)
	mon, ok := s.store.Monitor(monitorID)
	if !ok || mon.ManagedBy != model.MonitorManagedLatency {
		writeError(w, http.StatusNotFound, apiError(model.APIErrorNotFound, "no latency probe targets that node"))
		return
	}
	interval := time.Duration(mon.IntervalSec) * time.Second
	if cfg, stored := s.store.LatencyProbeConfig(); stored && cfg.IntervalSec > 0 {
		interval = time.Duration(cfg.IntervalSec) * time.Second
	}
	series, err := s.latencySeriesFor(monitorID, sourceID, targetID, window, interval, s.now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, series)
}
