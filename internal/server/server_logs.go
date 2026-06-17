package server

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/logstore"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

const (
	defaultLogMaxLineBytes  = 16384
	maxLogMaxLineBytes      = 65536
	defaultLogMaxBatchLines = 500
	maxLogMaxBatchLines     = 2000
	// maxLogBatchPayload bounds maxLineBytes*maxBatchLines so a legal batch always
	// fits the ingest decode cap with room for JSON overhead.
	maxLogBatchPayload   = 8 << 20  // 8 MiB
	logBatchBodyLimit    = 16 << 20 // 16 MiB decode cap (payload + JSON overhead)
	logPathDefaultAllow  = "/var/log/"
	logIngestRetryAfter  = "2"
	logQueryDefaultLimit = logstore.DefaultQueryLimit
	logQueryMaxLimit     = logstore.MaxQueryLimit
)

var logPathDenyPrefixes = []string{"/proc/", "/sys/", "/dev/"}

// logStoreReady reports whether log ingestion is enabled (a store was injected).
func (s *Server) logStoreReady(w http.ResponseWriter) bool {
	if s.logStore == nil {
		writeError(w, http.StatusServiceUnavailable, apiError(model.APIErrorInternal, "log ingestion is not enabled on this server"))
		return false
	}
	return true
}

// logPathAllowlist returns the prefixes a tailable path may sit under. The
// default is /var/log/; operators may widen it with LATTICE_LOG_PATH_ALLOW
// (comma-separated absolute prefixes). Deny prefixes always win.
func logPathAllowlist() []string {
	out := []string{logPathDefaultAllow}
	for _, raw := range strings.Split(os.Getenv("LATTICE_LOG_PATH_ALLOW"), ",") {
		p := strings.TrimSpace(raw)
		if p == "" || !strings.HasPrefix(p, "/") {
			continue
		}
		if !strings.HasSuffix(p, "/") {
			p += "/"
		}
		out = append(out, p)
	}
	return out
}

// validateLogPath gates a tailable file path, fail-closed. It must be absolute,
// clean, free of glob/control characters and ".." components, outside the deny
// list, and under an allowed prefix.
func validateLogPath(p string, allow []string) error {
	if strings.TrimSpace(p) != p {
		return errors.New("path has leading or trailing whitespace")
	}
	if p == "" {
		return errors.New("path is required")
	}
	if !filepath.IsAbs(p) {
		return errors.New("path must be absolute")
	}
	if p != filepath.Clean(p) {
		return errors.New("path must be clean (no '.', '..', or redundant separators)")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return errors.New("path must not contain a '..' segment")
		}
	}
	if strings.ContainsAny(p, "*?[]") {
		return errors.New("path must not contain glob characters")
	}
	for _, r := range p {
		if r < 32 || r == 127 {
			return errors.New("path contains control characters")
		}
	}
	if strings.HasSuffix(p, "/") {
		return errors.New("path must name a file, not a directory")
	}
	for _, deny := range logPathDenyPrefixes {
		if p == strings.TrimSuffix(deny, "/") || strings.HasPrefix(p, deny) {
			return fmt.Errorf("path under %s is not allowed", strings.TrimSuffix(deny, "/"))
		}
	}
	for _, prefix := range allow {
		if strings.HasPrefix(p, prefix) {
			return nil
		}
	}
	return fmt.Errorf("path must be under an allowed prefix (default %s; widen with LATTICE_LOG_PATH_ALLOW)", logPathDefaultAllow)
}

func logSourceVisibleToPrincipal(p principal, scope string, ls model.LogSource) bool {
	return rbac.Allows(p.Principal, scope, ls.NodeID)
}

// --- operator endpoints --------------------------------------------------

func (s *Server) handleLogSources(w http.ResponseWriter, r *http.Request, p principal) {
	if !s.logStoreReady(w) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		sources := s.store.LogSources()
		visible := make([]model.LogSource, 0, len(sources))
		for _, ls := range sources {
			if logSourceVisibleToPrincipal(p, "log:read", ls) {
				visible = append(visible, ls)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"sources": visible})
	case http.MethodPost:
		var req struct {
			ID            string `json:"id"`
			Name          string `json:"name"`
			NodeID        string `json:"node_id"`
			Path          string `json:"path"`
			Enabled       *bool  `json:"enabled"`
			MaxLineBytes  int    `json:"max_line_bytes"`
			MaxBatchLines int    `json:"max_batch_lines"`
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		req.NodeID = strings.TrimSpace(req.NodeID)
		req.Path = strings.TrimSpace(req.Path)
		if req.Name == "" {
			writeError(w, http.StatusBadRequest, errors.New("name is required"))
			return
		}
		if req.NodeID == "" {
			writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
			return
		}
		if !s.requireNodeScope(w, p, "log:admin", req.NodeID) {
			return
		}
		if _, ok := s.store.Node(req.NodeID); !ok {
			writeError(w, http.StatusNotFound, errors.New("node not found"))
			return
		}
		if err := validateLogPath(req.Path, logPathAllowlist()); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		existing, had := model.LogSource{}, false
		if strings.TrimSpace(req.ID) != "" {
			existing, had = s.store.LogSource(strings.TrimSpace(req.ID))
			if had && existing.NodeID != req.NodeID {
				writeError(w, http.StatusBadRequest, errors.New("node_id cannot change for an existing source"))
				return
			}
			if had && isAgentDebugLogSource(existing) {
				writeError(w, http.StatusBadRequest, errors.New("agent debug sources are managed by node debug policy"))
				return
			}
		}
		ls := existing
		if !had {
			ls = model.LogSource{ID: id.New("logsrc")}
		}
		ls.Name = req.Name
		ls.NodeID = req.NodeID
		ls.Path = req.Path
		ls.MaxLineBytes = clampLogInt(req.MaxLineBytes, defaultLogMaxLineBytes, maxLogMaxLineBytes)
		ls.MaxBatchLines = clampLogInt(req.MaxBatchLines, defaultLogMaxBatchLines, maxLogMaxBatchLines)
		if ls.MaxLineBytes*ls.MaxBatchLines > maxLogBatchPayload {
			writeError(w, http.StatusBadRequest, fmt.Errorf("max_line_bytes*max_batch_lines must not exceed %d bytes", maxLogBatchPayload))
			return
		}
		enabled := true
		if had {
			enabled = existing.Enabled
		}
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		ls.Enabled = enabled
		if err := s.store.UpsertLogSource(ls); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		action := "log.source.create"
		if had {
			switch {
			case !existing.Enabled && ls.Enabled:
				action = "log.source.enable"
			case existing.Enabled && !ls.Enabled:
				action = "log.source.disable"
			default:
				action = "log.source.update"
			}
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:     id.New("audit"),
			NodeID: ls.NodeID,
			Action: action,
			Scope:  "log:admin",
			Metadata: map[string]string{
				"source_id": ls.ID,
				"path":      ls.Path,
				"enabled":   strconv.FormatBool(ls.Enabled),
			},
		})
		writeJSON(w, http.StatusOK, ls)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleDeleteLogSource(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.logStoreReady(w) {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	ls, ok := s.store.LogSource(req.ID)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	if !s.requireNodeScope(w, p, "log:admin", ls.NodeID) {
		return
	}
	if err := s.store.DeleteLogSource(req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.logStore.PurgeSource(req.ID); err != nil {
		s.logger.Printf("log source %s: purge store: %v", req.ID, err)
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:       id.New("audit"),
		NodeID:   ls.NodeID,
		Action:   "log.source.delete",
		Scope:    "log:admin",
		Metadata: map[string]string{"source_id": req.ID},
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleLogQuery(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.logStoreReady(w) {
		return
	}
	q := r.URL.Query()
	sourceID := strings.TrimSpace(q.Get("source_id"))
	if sourceID == "" {
		writeError(w, http.StatusBadRequest, errors.New("source_id is required"))
		return
	}
	ls, ok := s.store.LogSource(sourceID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("log source not found"))
		return
	}
	if !logSourceVisibleToPrincipal(p, "log:read", ls) {
		writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
		return
	}
	filter := logstore.Filter{SourceID: sourceID, Contains: q.Get("q")}
	if v := strings.TrimSpace(q.Get("since")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("since must be RFC3339"))
			return
		}
		filter.Since = t
	}
	if v := strings.TrimSpace(q.Get("until")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("until must be RFC3339"))
			return
		}
		filter.Until = t
	}
	if v := strings.TrimSpace(q.Get("limit")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, errors.New("limit must be a non-negative integer"))
			return
		}
		filter.Limit = n
	}
	if v := strings.TrimSpace(q.Get("before_seq")); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("before_seq must be a uint64"))
			return
		}
		filter.BeforeSeq = n
	}
	res, err := s.logStore.Query(filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if res.Truncated {
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   ls.NodeID,
			Action:   "log.chunk.decode_error",
			Decision: "deny",
			Reason:   "a stored log chunk failed to decode and was skipped",
			Metadata: map[string]string{"source_id": sourceID},
		})
	}
	out := map[string]any{"lines": res.Lines, "truncated": res.Truncated}
	if res.NextBeforeSeq != 0 {
		out["next_before_seq"] = res.NextBeforeSeq
	}
	writeJSON(w, http.StatusOK, out)
}

type logSourceStatsView struct {
	SourceID     string    `json:"source_id"`
	NodeID       string    `json:"node_id"`
	Name         string    `json:"name"`
	Path         string    `json:"path"`
	Enabled      bool      `json:"enabled"`
	Lines        uint64    `json:"lines"`
	Bytes        uint64    `json:"bytes"`
	FirstAt      time.Time `json:"first_at,omitempty"`
	LastAt       time.Time `json:"last_at,omitempty"`
	LastIngestAt time.Time `json:"last_ingest_at,omitempty"`
	RotID        string    `json:"rot_id,omitempty"`
}

func (s *Server) handleLogStats(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.logStoreReady(w) {
		return
	}
	sourceID := strings.TrimSpace(r.URL.Query().Get("source_id"))
	var sources []model.LogSource
	if sourceID != "" {
		ls, ok := s.store.LogSource(sourceID)
		if !ok {
			writeError(w, http.StatusNotFound, errors.New("log source not found"))
			return
		}
		sources = []model.LogSource{ls}
	} else {
		sources = s.store.LogSources()
	}
	views := make([]logSourceStatsView, 0, len(sources))
	for _, ls := range sources {
		if !logSourceVisibleToPrincipal(p, "log:read", ls) {
			continue
		}
		meta, firstAt, lastAt, _ := s.logStore.Stats(ls.ID)
		views = append(views, logSourceStatsView{
			SourceID:     ls.ID,
			NodeID:       ls.NodeID,
			Name:         ls.Name,
			Path:         ls.Path,
			Enabled:      ls.Enabled,
			Lines:        meta.Lines,
			Bytes:        meta.Bytes,
			FirstAt:      firstAt,
			LastAt:       lastAt,
			LastIngestAt: meta.LastIngestAt,
			RotID:        meta.RotID,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"stats": views})
}

// --- agent endpoints -----------------------------------------------------

func (s *Server) handleAgentLogSources(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	if _, ok := s.authenticateNode(nodeID, bearerToken(r)); !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	if s.logStore == nil {
		writeJSON(w, http.StatusOK, map[string]any{"sources": []model.LogSource{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": s.store.LogSourcesForNode(nodeID)})
}

func (s *Server) handleAgentLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		agentAuthRequest
		Batch model.LogBatch `json:"batch"`
	}
	if !decodeJSONBody(w, r, &req, logBatchBodyLimit, false) {
		return
	}
	node, ok := s.authenticateAgentRequest(r, req.NodeID)
	if !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	_ = node
	if s.logStore == nil {
		writeError(w, http.StatusServiceUnavailable, apiError(model.APIErrorInternal, "log ingestion is not enabled"))
		return
	}
	sourceID := strings.TrimSpace(req.Batch.SourceID)
	ls, ok := s.store.LogSource(sourceID)
	if !ok || ls.NodeID != req.NodeID {
		// Fail-closed: the source must exist and belong to this node.
		writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "unknown source for this node"))
		return
	}
	if !ls.Enabled {
		writeError(w, http.StatusConflict, errors.New("source is disabled"))
		return
	}
	if strings.TrimSpace(req.Batch.Path) != "" && req.Batch.Path != ls.Path {
		writeError(w, http.StatusBadRequest, errors.New("batch path does not match the source record"))
		return
	}
	if len(req.Batch.Lines) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "accepted": 0, "next_off": req.Batch.LastOff})
		return
	}
	maxLine := ls.MaxLineBytes
	if maxLine <= 0 {
		maxLine = defaultLogMaxLineBytes
	}
	// Per-source ingest budget (lines/sec). Over budget => 429, hold position.
	if !s.logIngestLimiter.AllowN(sourceID, float64(len(req.Batch.Lines))) {
		w.Header().Set("Retry-After", logIngestRetryAfter)
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   req.NodeID,
			Action:   "log.ingest.throttled",
			Decision: "deny",
			Reason:   "per-source ingest budget exceeded",
			Metadata: map[string]string{"source_id": sourceID, "lines": strconv.Itoa(len(req.Batch.Lines))},
		})
		writeError(w, http.StatusTooManyRequests, apiError(model.APIErrorRateLimited, "ingest rate exceeded"))
		return
	}
	at := req.Batch.CapturedAt
	if at.IsZero() {
		at = s.now()
	}
	lines := make([]model.LogLine, 0, len(req.Batch.Lines))
	for _, raw := range req.Batch.Lines {
		truncated := false
		if len(raw) > maxLine {
			raw = raw[:maxLine]
			truncated = true
		}
		lines = append(lines, model.LogLine{
			SourceID:  sourceID,
			NodeID:    req.NodeID,
			Path:      ls.Path,
			At:        at.UTC(),
			Line:      raw,
			Truncated: truncated,
		})
	}
	if _, err := s.logStore.Append(sourceID, lines, strings.TrimSpace(req.Batch.RotID), req.Batch.LastOff, at); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "accepted": len(lines), "next_off": req.Batch.LastOff})
}

func clampLogInt(v, def, max int) int {
	if v <= 0 {
		return def
	}
	if v > max {
		return max
	}
	return v
}
