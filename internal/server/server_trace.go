package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/tracestore"
)

// sing-box connection tracing. Design: Lattice/SINGBOX-TRACE-DESIGN.md.
//
// Scopes are deliberately the existing log:read and log:admin rather than a new
// pair. What this subsystem exposes is the same class of data the log viewer
// already exposes, from the same nodes, so a second scope would only create a
// way for the two to drift apart.
const (
	// traceSessionDefaultTTL and traceSessionMaxTTL bound a capture. The ceiling
	// is enforced here AND independently on the agent, so a session still ends
	// if the control plane disappears mid-capture. An unbounded trace left
	// running on a node is a privacy and disk problem nobody would notice.
	traceSessionDefaultTTL = 15 * time.Minute
	traceSessionMaxTTL     = 2 * time.Hour

	traceBatchBodyLimit = 8 << 20

	// traceDefaultBudgetLines is the per-node ingest ceiling applied when a
	// policy does not set one.
	traceDefaultBudgetLines = 500

	// singBoxLogPathPrefix marks the virtual log source that carries a node's
	// ordinary sing-box lines. Like agent-debug://, it is managed here rather
	// than through operator CRUD and is never a real file on the node.
	singBoxLogPathPrefix = "singbox://"
	// The raw path is where volume lives, so its per-line and per-batch caps
	// are the general log defaults rather than the smaller debug ones.
	singBoxLogMaxLineBytes  = 8192
	singBoxLogMaxBatchLines = 500
)

func (s *Server) traceStoreReady(w http.ResponseWriter) bool {
	if s.traceStore == nil {
		writeError(w, http.StatusServiceUnavailable, apiError(model.APIErrorInternal, "connection tracing is not enabled on this server"))
		return false
	}
	return true
}

// visibleNodeIDs narrows a requested node set to what this principal may see,
// and when nothing was requested returns every node it may see. Returning the
// allowed set rather than filtering after the query keeps a node allowlist from
// leaking existence through result counts.
func (s *Server) visibleNodeIDs(p principal, scope string, requested []string) []string {
	if len(requested) > 0 {
		out := make([]string, 0, len(requested))
		for _, n := range requested {
			if rbac.Allows(p.Principal, scope, n) {
				out = append(out, n)
			}
		}
		return out
	}
	nodes := s.store.Nodes()
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if rbac.Allows(p.Principal, scope, n.ID) {
			out = append(out, n.ID)
		}
	}
	return out
}

func csvParam(q map[string][]string, key string) []string {
	raw := ""
	if v, ok := q[key]; ok && len(v) > 0 {
		raw = v[0]
	}
	out := []string{}
	for _, part := range strings.Split(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func rfc3339Param(q map[string][]string, key string) (time.Time, error) {
	v, ok := q[key]
	if !ok || len(v) == 0 || strings.TrimSpace(v[0]) == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(v[0]))
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be RFC3339", key)
	}
	return t, nil
}

func boolParam(q map[string][]string, key string) bool {
	v, ok := q[key]
	if !ok || len(v) == 0 {
		return false
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v[0]))
	return err == nil && b
}

func intParam(q map[string][]string, key string) (int, error) {
	v, ok := q[key]
	if !ok || len(v) == 0 || strings.TrimSpace(v[0]) == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v[0]))
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer", key)
	}
	return n, nil
}

// --- operator endpoints --------------------------------------------------

func (s *Server) handleTraceConnections(w http.ResponseWriter, r *http.Request, p principal) {
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
	limit, err := intParam(q, "limit")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	nodes := s.visibleNodeIDs(p, "log:read", csvParam(q, "node_id"))
	if len(nodes) == 0 {
		// No visible nodes is an empty result, not a 403: the operator may
		// legitimately hold a narrow allowlist.
		writeJSON(w, http.StatusOK, tracestore.RecordPage{Records: []model.ConnRecord{}})
		return
	}
	page, err := s.traceStore.QueryRecords(tracestore.Filter{
		Since:        since,
		Until:        until,
		NodeIDs:      nodes,
		UserIDs:      csvParam(q, "user_id"),
		LineUUIDs:    csvParam(q, "line_uuid"),
		SessionIDs:   csvParam(q, "session_id"),
		DstContains:  strings.TrimSpace(q.Get("dst")),
		CloseReasons: csvParam(q, "close_reason"),
		UserKinds:    csvParam(q, "user_kind"),
		OnlyStalled:  boolParam(q, "stalled"),
		IncludeOpen:  boolParam(q, "include_open"),
		Limit:        limit,
		Cursor:       strings.TrimSpace(q.Get("cursor")),
	})
	if err != nil {
		// A bad cursor is the caller's fault, not the server's. Everything else
		// is ours.
		if strings.Contains(err.Error(), "cursor") {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) handleTraceLines(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireScope(w, p, "log:read") || !s.traceStoreReady(w) {
		return
	}
	q := r.URL.Query()
	sessionID := strings.TrimSpace(q.Get("session_id"))
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, errors.New("session_id is required"))
		return
	}
	sess, ok := s.store.TraceSession(sessionID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("trace session not found"))
		return
	}
	// A session's captured lines are visible only if every node it targeted is
	// visible. A session with no node filter spans the fleet, so it needs fleet
	// visibility.
	if !s.traceSessionVisible(p, sess) {
		writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
		return
	}
	afterSeq, err := intParam(q, "after_seq")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	limit, err := intParam(q, "limit")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	lines, err := s.traceStore.QueryLines(sessionID, uint64(afterSeq), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// The cursor never goes backwards. A quiet interval returns no lines, and
	// reporting next_seq=0 there would send the client back to the beginning
	// and re-deliver everything it already has. Floor it at what was asked for.
	next := uint64(afterSeq)
	for _, l := range lines {
		if l.Seq > next {
			next = l.Seq
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"lines": lines, "next_seq": next})
}

// traceSessionVisible reports whether the principal may see this session. A
// session that named no nodes captured from every node it could reach, so it
// requires visibility of the whole fleet rather than of none.
func (s *Server) traceSessionVisible(p principal, sess model.TraceSession) bool {
	targets := sess.Filter.NodeIDs
	if len(targets) == 0 {
		for _, n := range s.store.Nodes() {
			if !rbac.Allows(p.Principal, "log:read", n.ID) {
				return false
			}
		}
		return true
	}
	for _, n := range targets {
		if !rbac.Allows(p.Principal, "log:read", n) {
			return false
		}
	}
	return true
}

func (s *Server) handleTraceSessions(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireScope(w, p, "log:read") || !s.traceStoreReady(w) {
			return
		}
		// Expire on read so a session cannot outlive its deadline just because a
		// sweeper did not run.
		if _, err := s.store.ExpireTraceSessions(s.now()); err != nil {
			s.logger.Printf("trace: expire sessions: %v", err)
		}
		all := s.store.TraceSessions()
		out := make([]model.TraceSession, 0, len(all))
		for _, sess := range all {
			if s.traceSessionVisible(p, sess) {
				out = append(out, sess)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
	case http.MethodPost:
		s.createTraceSession(w, r, p)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) createTraceSession(w http.ResponseWriter, r *http.Request, p principal) {
	if !s.traceStoreReady(w) {
		return
	}
	var req struct {
		Name       string            `json:"name"`
		Filter     model.TraceFilter `json:"filter"`
		Level      model.TraceLevel  `json:"level"`
		TTLSeconds int               `json:"ttl_seconds"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, errors.New("name is required"))
		return
	}
	if req.Level == "" {
		req.Level = model.TraceLevelDebug
	}
	if !model.ValidTraceLevel(req.Level) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("level %q must be info, debug or trace", req.Level))
		return
	}
	// Every targeted node must be writable by this principal. A capture is a
	// read of user traffic metadata, so it is gated at admin level rather than
	// read level.
	targets := req.Filter.NodeIDs
	if len(targets) == 0 {
		targets = s.visibleNodeIDs(p, "log:admin", nil)
		if len(targets) == 0 {
			writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "no nodes are in scope for log:admin"))
			return
		}
	}
	for _, n := range req.Filter.NodeIDs {
		if !s.requireNodeScope(w, p, "log:admin", n) {
			return
		}
	}
	if len(req.Filter.NodeIDs) == 0 && !s.requireScope(w, p, "log:admin") {
		return
	}

	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = traceSessionDefaultTTL
	}
	if ttl > traceSessionMaxTTL {
		ttl = traceSessionMaxTTL
	}
	now := s.now()
	// Persist the RESOLVED target set, never the request's empty node list.
	//
	// An empty Filter.NodeIDs means "every node" everywhere it is later read:
	// traceAgentConfig ships the session to any node that polls, and
	// traceSessionVisible and the stop path both treat it as fleet scope. An
	// operator confined to one node who leaves the node filter blank, which is
	// the dashboard default, would otherwise have authorised a capture of one
	// node and started a capture of the fleet. Freezing the authorised set here
	// makes every later read agree with what was actually permitted.
	filter := req.Filter
	filter.NodeIDs = append([]string(nil), targets...)
	sess := model.TraceSession{
		ID:            id.New("trace"),
		Name:          req.Name,
		Filter:        filter,
		Level:         req.Level,
		StartedAt:     now,
		ExpiresAt:     now.Add(ttl),
		State:         model.TraceSessionRunning,
		StartedBy:     p.ActorID,
		CorrelationID: correlationOrNew(p),
	}
	if err := s.store.UpsertTraceSession(sess); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:            id.New("audit"),
		Action:        "trace.session.start",
		Scope:         "log:admin",
		CorrelationID: sess.CorrelationID,
		Metadata: map[string]string{
			"session_id": sess.ID,
			"level":      string(sess.Level),
			"ttl":        ttl.String(),
			"users":      strings.Join(sess.Filter.UserIDs, ","),
			"lines":      strings.Join(sess.Filter.LineUUIDs, ","),
			"nodes":      strings.Join(sess.Filter.NodeIDs, ","),
			"dst":        strings.Join(sess.Filter.DstPatterns, ","),
		},
	})
	s.pushTraceConfig(targets)
	writeJSON(w, http.StatusOK, sess)
}

func (s *Server) handleTraceSessionStop(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.traceStoreReady(w) {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	sess, ok := s.store.TraceSession(strings.TrimSpace(req.ID))
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("trace session not found"))
		return
	}
	for _, n := range sess.Filter.NodeIDs {
		if !s.requireNodeScope(w, p, "log:admin", n) {
			return
		}
	}
	if len(sess.Filter.NodeIDs) == 0 && !s.requireScope(w, p, "log:admin") {
		return
	}
	if sess.State == model.TraceSessionRunning {
		sess.State = model.TraceSessionStopped
		sess.EndedAt = s.now()
		if err := s.store.UpsertTraceSession(sess); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:            id.New("audit"),
		Action:        "trace.session.stop",
		Scope:         "log:admin",
		CorrelationID: sess.CorrelationID,
		Metadata:      map[string]string{"session_id": sess.ID},
	})
	s.pushTraceConfig(s.traceSessionNodes(sess))
	writeJSON(w, http.StatusOK, sess)
}

func (s *Server) traceSessionNodes(sess model.TraceSession) []string {
	if len(sess.Filter.NodeIDs) > 0 {
		return sess.Filter.NodeIDs
	}
	nodes := s.store.Nodes()
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.ID)
	}
	return out
}

// pushTraceConfig nudges the named nodes to re-read their trace config. It is a
// latency optimisation only: an agent that misses the push picks the same state
// up on its next poll, so a failed delivery is never retried and never an error.
func (s *Server) pushTraceConfig(nodeIDs []string) {
	for _, nodeID := range nodeIDs {
		cfg, err := s.traceAgentConfig(nodeID)
		if err != nil {
			continue
		}
		s.agentControlHub.notifyTraceConfig(nodeID, cfg)
	}
}

func (s *Server) handleTracePolicy(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireScope(w, p, "log:read") || !s.traceStoreReady(w) {
			return
		}
		requested := strings.TrimSpace(r.URL.Query().Get("node_id"))
		out := []model.TracePolicy{}
		for _, n := range s.store.Nodes() {
			if requested != "" && n.ID != requested {
				continue
			}
			if !rbac.Allows(p.Principal, "log:read", n.ID) {
				continue
			}
			pol := n.Trace
			pol.NodeID = n.ID
			out = append(out, pol)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
		writeJSON(w, http.StatusOK, map[string]any{"policies": out})
	case http.MethodPost:
		if !s.traceStoreReady(w) {
			return
		}
		var req struct {
			NodeID            string           `json:"node_id"`
			Enabled           *bool            `json:"enabled"`
			Level             model.TraceLevel `json:"level"`
			BudgetLinesPerSec int              `json:"budget_lines_per_sec"`
			ClashAPIAddr      string           `json:"clash_api_addr"`
			SecretPath        string           `json:"secret_path"`
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		req.NodeID = strings.TrimSpace(req.NodeID)
		if req.NodeID == "" {
			writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
			return
		}
		if !s.requireNodeScope(w, p, "log:admin", req.NodeID) {
			return
		}
		node, ok := s.store.Node(req.NodeID)
		if !ok {
			writeError(w, http.StatusNotFound, errors.New("node not found"))
			return
		}
		pol := node.Trace
		pol.NodeID = req.NodeID
		if req.Level != "" {
			if !model.ValidTraceLevel(req.Level) {
				writeError(w, http.StatusBadRequest, fmt.Errorf("level %q must be info, debug or trace", req.Level))
				return
			}
			pol.Level = req.Level
		}
		if pol.Level == "" {
			pol.Level = model.TraceLevelInfo
		}
		if req.Enabled != nil {
			pol.Enabled = *req.Enabled
		}
		if req.BudgetLinesPerSec > 0 {
			pol.BudgetLinesPerSec = req.BudgetLinesPerSec
		}
		if pol.BudgetLinesPerSec <= 0 {
			pol.BudgetLinesPerSec = traceDefaultBudgetLines
		}
		if addr := strings.TrimSpace(req.ClashAPIAddr); addr != "" {
			if err := validateLoopbackHostPort(addr); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("clash_api_addr: %w", err))
				return
			}
			pol.ClashAPIAddr = addr
		}
		if sp := strings.TrimSpace(req.SecretPath); sp != "" {
			pol.SecretPath = sp
		}
		pol.UpdatedAt = s.now()
		node.Trace = pol
		if err := s.store.UpsertNode(node); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:     id.New("audit"),
			NodeID: req.NodeID,
			Action: "trace.policy.set",
			Scope:  "log:admin",
			Metadata: map[string]string{
				"enabled": strconv.FormatBool(pol.Enabled),
				"level":   string(pol.Level),
				"budget":  strconv.Itoa(pol.BudgetLinesPerSec),
			},
		})
		s.pushTraceConfig([]string{req.NodeID})
		writeJSON(w, http.StatusOK, pol)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleTraceStats(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireScope(w, p, "log:read") || !s.traceStoreReady(w) {
		return
	}
	stats, err := s.traceStore.Stats()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// Server-local diagnostics are for whoever administers the server, not for
	// anyone holding log:read on one node. The path, size, schema version and
	// cipher state say nothing about that node, and the counts cover the whole
	// fleet, which is activity outside the caller's allowlist.
	if !rbac.Allows(p.Principal, "log:read", "") || !s.principalSeesEveryNode(p) {
		writeJSON(w, http.StatusOK, map[string]any{
			"scoped":         true,
			"schema_version": stats.SchemaVersion,
			"cipher_enabled": stats.CipherEnabled,
		})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// --- agent endpoints -----------------------------------------------------

// traceAgentConfig expands the stored policy and every active session into the
// node-local predicates one agent can evaluate: user ids become the u_<hex>
// names that node actually renders, and line uuids become inbound tags.
func (s *Server) traceAgentConfig(nodeID string) (model.TraceAgentConfig, error) {
	node, ok := s.store.Node(nodeID)
	if !ok {
		return model.TraceAgentConfig{}, errors.New("node not found")
	}
	pol := node.Trace
	pol.NodeID = nodeID
	if pol.Level == "" {
		pol.Level = model.TraceLevelInfo
	}
	if pol.BudgetLinesPerSec <= 0 {
		pol.BudgetLinesPerSec = traceDefaultBudgetLines
	}
	now := s.now()
	cfg := model.TraceAgentConfig{Policy: pol, ServerTime: now}
	if pol.Enabled && s.logStore != nil {
		if ls, err := s.ensureSingBoxLogSource(node); err != nil {
			s.logger.Printf("trace: raw log source for %s: %v", nodeID, err)
		} else {
			cfg.RawSourceID = ls.ID
		}
	}
	for _, sess := range s.store.ActiveTraceSessions(now) {
		if len(sess.Filter.NodeIDs) > 0 && !containsString(sess.Filter.NodeIDs, nodeID) {
			continue
		}
		agentSess := model.TraceAgentSession{
			ID:          sess.ID,
			Level:       sess.Level,
			ExpiresAt:   sess.ExpiresAt,
			DstPatterns: sess.Filter.DstPatterns,
			UserNames:   s.traceUserNamesForNode(nodeID, sess.Filter),
			InboundTags: s.traceInboundTagsForNode(nodeID, sess.Filter),
		}
		// A session that named users or lines but resolved to nothing on this
		// node must NOT degrade into "capture everything here". Skip it instead.
		if len(sess.Filter.UserIDs) > 0 && len(agentSess.UserNames) == 0 {
			continue
		}
		if len(sess.Filter.LineUUIDs) > 0 && len(agentSess.InboundTags) == 0 {
			continue
		}
		cfg.Sessions = append(cfg.Sessions, agentSess)
	}
	return cfg, nil
}

func (s *Server) handleAgentTraceConfig(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	if _, ok := s.authenticateNode(r, nodeID, bearerToken(r)); !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	if s.traceStore == nil {
		// Tracing off means "collect nothing", expressed as a disabled policy
		// rather than an error, so an older or newer agent behaves the same.
		writeJSON(w, http.StatusOK, model.TraceAgentConfig{
			Policy:     model.TracePolicy{NodeID: nodeID, Enabled: false, Level: model.TraceLevelInfo},
			ServerTime: s.now(),
		})
		return
	}
	cfg, err := s.traceAgentConfig(nodeID)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleAgentTrace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		agentAuthRequest
		Batch model.TraceBatch `json:"batch"`
	}
	if !decodeJSONBody(w, r, &req, traceBatchBodyLimit, false) {
		return
	}
	if _, ok := s.authenticateAgentRequest(r, req.NodeID); !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	if s.traceStore == nil {
		writeError(w, http.StatusServiceUnavailable, apiError(model.APIErrorInternal, "connection tracing is not enabled"))
		return
	}
	// Reject a bare TraceBatch sent where the {node_id, batch} envelope belongs.
	// TraceBatch carries its own node_id, so the wrong shape authenticates
	// cleanly and then decodes to an EMPTY batch, and the node is told 200 OK
	// with zero records accepted. A collector could ship into that void
	// indefinitely. Detecting it costs one check; not detecting it cost a live
	// debugging round.
	if req.Batch.SourceLooksBare() {
		writeError(w, http.StatusBadRequest, errors.New(`trace batch must be sent as {"node_id":...,"batch":{...}}; a bare batch was received`))
		return
	}
	// Fail closed on cross-node writes: a node may only report its own traffic.
	for i := range req.Batch.Records {
		if req.Batch.Records[i].NodeID != "" && req.Batch.Records[i].NodeID != req.NodeID {
			writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "record node_id does not match the reporting node"))
			return
		}
		req.Batch.Records[i].NodeID = req.NodeID
	}
	for i := range req.Batch.Lines {
		if req.Batch.Lines[i].NodeID != "" && req.Batch.Lines[i].NodeID != req.NodeID {
			writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "line node_id does not match the reporting node"))
			return
		}
		req.Batch.Lines[i].NodeID = req.NodeID
	}
	if !s.logIngestLimiter.AllowN("trace:"+req.NodeID, float64(len(req.Batch.Records)+len(req.Batch.Lines))) {
		w.Header().Set("Retry-After", logIngestRetryAfter)
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   req.NodeID,
			Action:   "trace.ingest.throttled",
			Decision: "deny",
			Reason:   "per-node trace ingest budget exceeded",
		})
		writeError(w, http.StatusTooManyRequests, apiError(model.APIErrorRateLimited, "ingest rate exceeded"))
		return
	}

	s.attributeTraceRecords(req.Batch.Records)

	records, err := s.traceStore.AppendRecords(req.Batch.Records)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	lines, err := s.traceStore.AppendLines(req.Batch.Lines)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if req.Batch.Dropped > 0 || req.Batch.Unparsed > 0 {
		// Both numbers are evidence of a gap, and a gap that is not recorded
		// reads later as a quiet network. Unparsed in particular means sing-box
		// changed its log format, which is the failure most easily mistaken for
		// "nothing is happening".
		s.recordRequestAudit(r, model.AuditEvent{
			ID:     id.New("audit"),
			NodeID: req.NodeID,
			Action: "trace.ingest.gap",
			Reason: "the agent reported dropped or unparsed lines",
			Metadata: map[string]string{
				"dropped":  strconv.FormatUint(req.Batch.Dropped, 10),
				"unparsed": strconv.FormatUint(req.Batch.Unparsed, 10),
			},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"accepted_records": records,
		"accepted_lines":   lines,
	})
}

// correlationOrNew ties a session to the request that started it when there is
// one, so the existing correlation view can show the capture inside the wider
// operation instead of as an orphan.
func correlationOrNew(p principal) string {
	if c := strings.TrimSpace(p.CorrelationID); c != "" {
		return c
	}
	return id.New("corr")
}

// traceRetentionInterval is how often the trace store is swept. The TTLs are
// measured in days and the size cap in gigabytes, so sweeping hourly is ample
// and keeps each pass small enough not to hold a long write lock.
const traceRetentionInterval = time.Hour

// startTraceRetention runs the trace store's retention sweep on an interval.
//
// Without it the TTLs and the size cap are inert: Open honours them as
// configuration and nothing ever enforces them, so trace.db grows until the
// disk fills. Connection records accumulate on every node at the always-on
// info floor, so this is not a slow leak on a busy fleet.
//
// A sweep that reports it could not get under the cap is retried promptly
// rather than waiting a full interval, because at that point the store is
// already over budget.
func (s *Server) startTraceRetention() {
	if s.traceStore == nil {
		return
	}
	go func() {
		for {
			res, err := s.traceStore.Retain(s.now())
			if err != nil {
				s.logger.Printf("trace retention: %v", err)
			} else if res.Truncated {
				// Still above the cap after a bounded pass. Come back sooner.
				s.logger.Printf("trace retention: still above the size cap after a pass; sweeping again shortly")
				time.Sleep(traceRetentionRetryDelay)
				continue
			}
			time.Sleep(traceRetentionInterval)
		}
	}()
}

const traceRetentionRetryDelay = time.Minute

// principalSeesEveryNode reports whether this principal is unrestricted across
// the fleet. Fleet-wide aggregates are only honest to show to someone who may
// see every node that contributed to them.
func (s *Server) principalSeesEveryNode(p principal) bool {
	for _, n := range s.store.Nodes() {
		if !rbac.Allows(p.Principal, "log:read", n.ID) {
			return false
		}
	}
	return true
}

// singBoxLogSourceID is the stable id of a node's raw sing-box log source.
func singBoxLogSourceID(nodeID string) string {
	sum := sha256.Sum256([]byte("singbox|" + nodeID))
	return "singbox-" + hex.EncodeToString(sum[:8])
}

func isSingBoxLogSource(ls model.LogSource) bool {
	return strings.HasPrefix(ls.Path, singBoxLogPathPrefix)
}

// ensureSingBoxLogSource creates or repairs the virtual source that receives a
// node's ordinary sing-box lines.
//
// Without it the only thing that survives outside an active capture session is
// the assembled record, so there is no parser evidence to go back to and the
// existing Logs view shows nothing for a traced node. It mirrors the
// agent-debug source: managed here, invisible to operator CRUD, and never a
// path anyone tails.
func (s *Server) ensureSingBoxLogSource(node model.Node) (model.LogSource, error) {
	if strings.TrimSpace(node.ID) == "" {
		return model.LogSource{}, errors.New("node id is required")
	}
	now := s.now().UTC()
	sourceID := singBoxLogSourceID(node.ID)
	ls, ok := s.store.LogSource(sourceID)
	changed := !ok
	if !ok {
		ls = model.LogSource{ID: sourceID, CreatedAt: now}
	}
	name := "sing-box"
	if nodeName := strings.TrimSpace(node.Name); nodeName != "" {
		name = "sing-box - " + nodeName
	}
	if ls.Name != name {
		ls.Name, changed = name, true
	}
	if ls.NodeID != node.ID {
		ls.NodeID, changed = node.ID, true
	}
	if path := singBoxLogPathPrefix + node.ID; ls.Path != path {
		ls.Path, changed = path, true
	}
	if !ls.Enabled {
		ls.Enabled, changed = true, true
	}
	if ls.MaxLineBytes != singBoxLogMaxLineBytes {
		ls.MaxLineBytes, changed = singBoxLogMaxLineBytes, true
	}
	if ls.MaxBatchLines != singBoxLogMaxBatchLines {
		ls.MaxBatchLines, changed = singBoxLogMaxBatchLines, true
	}
	if !changed {
		return ls, nil
	}
	ls.UpdatedAt = now
	if err := s.store.UpsertLogSource(ls); err != nil {
		return model.LogSource{}, err
	}
	return ls, nil
}
