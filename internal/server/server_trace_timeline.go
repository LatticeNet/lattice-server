package server

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/tracestitch"
	"github.com/LatticeNet/lattice-server/internal/tracestore"
)

// The trace timeline and the cross-machine hop view.
//
// Every marker is derived from a signal Lattice already records. Nothing here
// adds instrumentation, which is deliberate: the point of the timeline is to
// put the events that already exist on one clock, because the cost in the
// incident this feature was designed from was never missing data, it was three
// machines on three clocks with no shared identifier.

// traceConfigApplyActions are the audit actions that mean "a node's proxy
// configuration changed". A restart usually follows one of these, and the pair
// is what turns "connections all died at 01:38" into "because of this apply".
const (
	// traceHopMaxPages and traceMarkerMaxPages bound the paging loops so a
	// pathological window cannot turn one request into an unbounded scan. When
	// a loop hits its ceiling the caller is told the set is incomplete rather
	// than handed a truncated answer that looks whole.
	traceHopMaxPages    = 20
	traceMarkerMaxPages = 50
)

var traceConfigApplyActions = map[string]bool{
	"proxy.apply":           true,
	"proxy.plan.execute":    true,
	"network.apply":         true,
	"linechain.apply":       true,
	"vpn.line.apply":        true,
	"plugin.operation.exec": true,
}

func (s *Server) handleTraceMarkers(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireScope(w, p, "log:read") || !s.traceStoreReady(w) {
		return
	}
	q := r.URL.Query()
	since, err := rfc3339Param(q, "since")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	until, err := rfc3339Param(q, "until")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if since.IsZero() {
		since = s.now().Add(-6 * time.Hour)
	}
	if until.IsZero() {
		until = s.now()
	}
	nodes := s.visibleNodeIDs(p, "log:read", csvParam(q, "node_id"))
	if len(nodes) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"markers": []model.TraceMarker{}})
		return
	}
	visible := map[string]bool{}
	for _, n := range nodes {
		visible[n] = true
	}

	markers := []model.TraceMarker{}
	markers = append(markers, s.coreRestartMarkers(since, until, nodes)...)
	markers = append(markers, s.auditMarkers(since, until, visible)...)
	markers = append(markers, s.sessionMarkers(since, until, p)...)

	sort.Slice(markers, func(i, j int) bool {
		if markers[i].At.Equal(markers[j].At) {
			return markers[i].Kind < markers[j].Kind
		}
		return markers[i].At.Before(markers[j].At)
	})
	writeJSON(w, http.StatusOK, map[string]any{"markers": markers})
}

// coreRestartMarkers reconstructs restarts from the records the restart itself
// swept. The count is the blast radius: how many live connections that restart
// destroyed. That number is the single line nobody was writing during the
// incident this feature came from, where establishing it cost seventeen probes
// and three failed hunts through log directories.
func (s *Server) coreRestartMarkers(since, until time.Time, nodes []string) []model.TraceMarker {
	// Page to the end. A restart that closed 2500 connections must not be
	// reported as exactly 1000 because that is where the page stopped: a capped
	// count presented as a blast radius is worse than no number.
	filter := tracestore.Filter{
		Since:        since,
		Until:        until,
		NodeIDs:      nodes,
		CloseReasons: []string{model.CloseCoreRestart},
		IncludeOpen:  true,
		Limit:        tracestore.MaxQueryLimit,
	}
	var page tracestore.RecordPage
	for i := 0; i < traceMarkerMaxPages; i++ {
		got, err := s.traceStore.QueryRecords(filter)
		if err != nil {
			s.logger.Printf("trace: core restart markers: %v", err)
			return nil
		}
		page.Records = append(page.Records, got.Records...)
		if got.NextCursor == "" {
			break
		}
		filter.Cursor = got.NextCursor
	}
	type key struct {
		node string
		gen  uint64
		sec  int64
	}
	counts := map[key]int{}
	when := map[key]time.Time{}
	for _, rec := range page.Records {
		at := rec.EndedAt
		if at.IsZero() {
			at = rec.StartedAt
		}
		k := key{node: rec.NodeID, gen: rec.CoreGeneration, sec: at.Unix()}
		counts[k]++
		if prev, ok := when[k]; !ok || at.Before(prev) {
			when[k] = at
		}
	}
	out := make([]model.TraceMarker, 0, len(counts))
	for k, n := range counts {
		out = append(out, model.TraceMarker{
			Kind:   model.MarkerCoreRestart,
			At:     when[k],
			NodeID: k.node,
			Title:  "sing-box restarted",
			Detail: "closed " + strconv.Itoa(n) + " live connection(s); core generation " + strconv.FormatUint(k.gen, 10),
			Count:  n,
		})
	}
	return out
}

// auditMarkers pulls config applies out of the existing audit log. It reads the
// tail rather than the whole log because AuditEvents copies and sorts the full
// slice on every call, a known cost documented in the product design.
func (s *Server) auditMarkers(since, until time.Time, visible map[string]bool) []model.TraceMarker {
	events := s.store.AuditEvents()
	out := []model.TraceMarker{}
	for _, ev := range events {
		if ev.At.Before(since) || ev.At.After(until) {
			continue
		}
		if !traceConfigApplyActions[ev.Action] {
			continue
		}
		if ev.NodeID != "" && !visible[ev.NodeID] {
			continue
		}
		detail := ev.Action
		if ev.Decision != "" {
			detail += " (" + ev.Decision + ")"
		}
		out = append(out, model.TraceMarker{
			Kind:          model.MarkerConfigApply,
			At:            ev.At,
			NodeID:        ev.NodeID,
			Title:         "configuration applied",
			Detail:        detail,
			CorrelationID: ev.CorrelationID,
		})
	}
	return out
}

func (s *Server) sessionMarkers(since, until time.Time, p principal) []model.TraceMarker {
	out := []model.TraceMarker{}
	for _, sess := range s.store.TraceSessions() {
		if !s.traceSessionVisible(p, sess) {
			continue
		}
		if !sess.StartedAt.Before(since) && !sess.StartedAt.After(until) {
			out = append(out, model.TraceMarker{
				Kind:          model.MarkerSession,
				At:            sess.StartedAt,
				Title:         "trace session started",
				Detail:        sess.Name + " at " + string(sess.Level),
				CorrelationID: sess.CorrelationID,
			})
		}
		if !sess.EndedAt.IsZero() && !sess.EndedAt.Before(since) && !sess.EndedAt.After(until) {
			out = append(out, model.TraceMarker{
				Kind:          model.MarkerSession,
				At:            sess.EndedAt,
				Title:         "trace session " + sess.State,
				Detail:        sess.Name,
				CorrelationID: sess.CorrelationID,
			})
		}
	}
	return out
}

// handleTraceHops answers "where else did this connection go". It stitches the
// requested record against the candidates in a window around it and returns the
// path WITH its confidence, always. A hop path presented without its confidence
// would be the most misleading thing this subsystem could render, because an
// inferred join looks exactly like a proven one once the wording is dropped.
func (s *Server) handleTraceHops(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireScope(w, p, "log:read") || !s.traceStoreReady(w) {
		return
	}
	q := r.URL.Query()
	nodeID := strings.TrimSpace(q.Get("node_id"))
	if nodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	if !s.requireNodeScope(w, p, "log:read", nodeID) {
		return
	}
	gen, err := strconv.ParseUint(strings.TrimSpace(q.Get("core_generation")), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("core_generation must be a uint64"))
		return
	}
	logID, err := strconv.ParseUint(strings.TrimSpace(q.Get("log_id")), 10, 32)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("log_id must be a uint32"))
		return
	}
	// started_at completes the identity. Without it a reused log id resolves to
	// whichever connection the query ordered first, and the hop view can walk
	// into a different connection than the one that was clicked.
	startedAt, err := rfc3339Param(q, "started_at")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// Point lookup, not a scan of the newest page: a record older than that page
	// is stored and would be reported as missing.
	anchor, found, err := s.traceStore.RecordByKey(nodeID, gen, uint32(logID), startedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, errors.New("connection record not found"))
		return
	}

	window := tracestitch.DefaultWindow
	// Page the candidate window to completion.
	//
	// Reading one page and stitching it changes the ANSWER when the window is
	// busy: a second valid candidate that fell onto the next page turns a
	// genuinely ambiguous join into a confident one, and a valid join into
	// none. Confidence has to be a statement about the whole candidate set, so
	// either enumerate it or say the set could not be proven complete.
	filter := tracestore.Filter{
		Since:       anchor.StartedAt.Add(-window),
		Until:       anchor.StartedAt.Add(window),
		NodeIDs:     s.visibleNodeIDs(p, "log:read", nil),
		IncludeOpen: true,
		Limit:       tracestore.MaxQueryLimit,
	}
	var (
		candidateRecordsAll []model.ConnRecord
		complete            bool
	)
	for page := 0; page < traceHopMaxPages; page++ {
		got, err := s.traceStore.QueryRecords(filter)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		candidateRecordsAll = append(candidateRecordsAll, got.Records...)
		if got.NextCursor == "" {
			complete = true
			break
		}
		filter.Cursor = got.NextCursor
	}
	candidates := tracestore.RecordPage{Records: candidateRecordsAll}
	paths := tracestitch.Stitch(candidates.Records, s.traceChainEdges(), tracestitch.Options{
		Window:        window,
		NodePublicIPs: s.traceNodePublicIPs(),
	})

	anchorKey := model.KeyOf(anchor)
	var path model.HopPath
	for _, candidate := range paths {
		for _, k := range candidate.RecordKeys {
			if k == anchorKey {
				path = candidate
				break
			}
		}
		if path.ID != "" {
			break
		}
	}
	if path.ID == "" {
		path = model.HopPath{Confidence: model.HopConfidenceNone, RecordKeys: []model.ConnRecordKey{anchorKey}}
	}

	byKey := map[model.ConnRecordKey]model.ConnRecord{}
	for _, rec := range candidates.Records {
		byKey[model.KeyOf(rec)] = rec
	}
	ordered := make([]model.ConnRecord, 0, len(path.RecordKeys))
	for _, k := range path.RecordKeys {
		if rec, ok := byKey[k]; ok {
			ordered = append(ordered, rec)
		}
	}
	candidateRecords := make([]model.ConnRecord, 0, len(path.Candidates))
	for _, k := range path.Candidates {
		if rec, ok := byKey[k]; ok {
			candidateRecords = append(candidateRecords, rec)
		}
	}
	if !complete {
		// The candidate universe could not be enumerated, so no confidence
		// claim about it is honest. Say that rather than publish one derived
		// from a truncated set.
		path.Confidence = model.HopConfidenceAmbiguous
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":                path,
		"records":             ordered,
		"candidates":          candidateRecords,
		"candidates_complete": complete,
	})
}

// traceChainEdges projects the declared line chain definitions into the edge
// list the stitcher needs. Declared edges only: an inferred topology joined to
// an inferred hop would compound two guesses into one confident-looking answer.
func (s *Server) traceChainEdges() []tracestitch.Edge {
	snapshot := s.store.LineChainSnapshot()
	out := make([]tracestitch.Edge, 0, len(snapshot.Definitions))
	for _, def := range snapshot.Definitions {
		if def.SourceLineUUID == "" || def.TargetLineUUID == "" {
			continue
		}
		out = append(out, tracestitch.Edge{
			SourceLineUUID: def.SourceLineUUID,
			TargetLineUUID: def.TargetLineUUID,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SourceLineUUID == out[j].SourceLineUUID {
			return out[i].TargetLineUUID < out[j].TargetLineUUID
		}
		return out[i].SourceLineUUID < out[j].SourceLineUUID
	})
	return out
}

func (s *Server) traceNodePublicIPs() map[string][]string {
	out := map[string][]string{}
	for _, n := range s.store.Nodes() {
		ips := []string{}
		if ip := strings.TrimSpace(n.PublicIP); ip != "" {
			ips = append(ips, ip)
		}
		if ip := strings.TrimSpace(n.PublicIPv6); ip != "" {
			ips = append(ips, ip)
		}
		if len(ips) > 0 {
			out[n.ID] = ips
		}
	}
	return out
}
