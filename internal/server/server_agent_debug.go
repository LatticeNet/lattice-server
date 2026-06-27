package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

const (
	agentDebugPathPrefix           = "agent-debug://"
	defaultAgentDebugMaxLineBytes  = 4096
	defaultAgentDebugMaxBatchLines = 100
	agentDebugBatchBodyLimit       = 1 << 20
	agentDebugRotID                = "agent-debug"
)

func (s *Server) handleNodeDebugPolicy(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		NodeID  string `json:"node_id"`
		Enabled *bool  `json:"enabled"`
		Collect *bool  `json:"collect"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.NodeID = strings.TrimSpace(req.NodeID)
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	if req.Enabled == nil {
		writeError(w, http.StatusBadRequest, errors.New("enabled is required"))
		return
	}
	if !s.requireNodeScope(w, p, "node:admin", req.NodeID) {
		return
	}
	node, ok := s.store.Node(req.NodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	collect := *req.Enabled
	if req.Collect != nil {
		collect = *req.Collect
	}
	if !*req.Enabled {
		collect = false
	}
	node.AgentDebug = model.AgentDebugPolicy{
		Enabled:   *req.Enabled,
		Collect:   collect,
		UpdatedAt: s.now().UTC(),
	}
	if err := s.store.UpsertNode(node); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:     id.New("audit"),
		NodeID: node.ID,
		Action: "node.debug.update",
		Scope:  "node:admin",
		Metadata: map[string]string{
			"enabled": strconv.FormatBool(node.AgentDebug.Enabled),
			"collect": strconv.FormatBool(node.AgentDebug.Collect),
		},
	})
	writeJSON(w, http.StatusOK, toNodeView(node))
}

func (s *Server) handleAgentConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	node, ok := s.authenticateNode(nodeID, bearerToken(r))
	if !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	collect := node.AgentDebug.Enabled && node.AgentDebug.Collect && s.logStore != nil
	writeJSON(w, http.StatusOK, model.AgentConfig{
		Debug: model.AgentDebugConfig{
			Enabled:       node.AgentDebug.Enabled,
			Collect:       collect,
			MaxLineBytes:  defaultAgentDebugMaxLineBytes,
			MaxBatchLines: defaultAgentDebugMaxBatchLines,
		},
		TerminalTransport: normalizeNodeTerminalTransport(node.TerminalTransport),
		IPConfig:          node.IPConfig,
	})
}

// normalizeNodeTerminalTransport clamps a stored per-node transport to the wire
// vocabulary the agent understands. An unrecognized or empty value yields ""
// (no override), so the agent keeps its startup transport.
func normalizeNodeTerminalTransport(transport string) string {
	switch strings.ToLower(strings.TrimSpace(transport)) {
	case "stream":
		return "stream"
	case "poll":
		return "poll"
	default:
		return ""
	}
}

// handleNodeTerminalTransport sets (or clears) a node's terminal transport
// override — the per-node rollout lever for promoting the streaming terminal.
// An empty transport clears the override so the node falls back to its agent's
// startup default. Mirrors handleNodeDebugPolicy's node:admin gating and audit.
func (s *Server) handleNodeTerminalTransport(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		NodeID    string `json:"node_id"`
		Transport string `json:"transport"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.NodeID = strings.TrimSpace(req.NodeID)
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	transport := strings.ToLower(strings.TrimSpace(req.Transport))
	switch transport {
	case "", "poll", "stream":
	default:
		writeError(w, http.StatusBadRequest, errors.New(`transport must be "poll", "stream", or "" to clear`))
		return
	}
	if !s.requireNodeScope(w, p, "node:admin", req.NodeID) {
		return
	}
	node, ok := s.store.Node(req.NodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	node.TerminalTransport = transport
	if err := s.store.UpsertNode(node); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:     id.New("audit"),
		NodeID: node.ID,
		Action: "node.terminal.transport",
		Scope:  "node:admin",
		Metadata: map[string]string{
			"transport": transport,
		},
	})
	writeJSON(w, http.StatusOK, toNodeView(node))
}

// handleNodeIPConfig sets (or clears) a node's public-IP discovery override —
// the per-node IP config the agent polls via AgentConfig. An empty mode clears
// the override so the node falls back to its agent's startup flags. Mirrors
// handleNodeTerminalTransport's node:admin gating and audit. Script-based
// discovery is intentionally not accepted here (separate sandboxed feature).
func (s *Server) handleNodeIPConfig(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		NodeID     string   `json:"node_id"`
		Mode       string   `json:"mode"`
		StaticIPv4 string   `json:"static_ipv4"`
		StaticIPv6 string   `json:"static_ipv6"`
		Resolvers  []string `json:"resolvers"`
		Script     string   `json:"script"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.NodeID = strings.TrimSpace(req.NodeID)
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	if !s.requireNodeScope(w, p, "node:admin", req.NodeID) {
		return
	}
	node, ok := s.store.Node(req.NodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	cfg, err := validateNodeIPConfig(req.Mode, req.StaticIPv4, req.StaticIPv6, req.Resolvers, req.Script, node.IPConfig)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	mode := ""
	if cfg != nil {
		cfg.UpdatedAt = s.now().UTC()
		mode = cfg.Mode
	}
	node.IPConfig = cfg
	if err := s.store.UpsertNode(node); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:       id.New("audit"),
		NodeID:   node.ID,
		Action:   "node.ip.config",
		Scope:    "node:admin",
		Metadata: map[string]string{"mode": mode},
	})
	writeJSON(w, http.StatusOK, toNodeView(node))
}

// validateNodeIPConfig validates an operator-supplied per-node IP override. An
// empty mode returns (nil, nil) meaning "clear the override". Static addresses
// must parse for their family; static mode requires at least one; resolver URLs
// must be http(s). Script mode requires a script body on first save, but an
// empty body preserves the existing script so the UI can show only a hash and
// still let operators change metadata without re-pasting secret-bearing code.
// Trimmed/cleaned values are returned ready to persist.
func validateNodeIPConfig(mode, v4, v6 string, resolvers []string, script string, existing *model.NodeIPConfig) (*model.NodeIPConfig, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	v4 = strings.TrimSpace(v4)
	v6 = strings.TrimSpace(v6)
	switch mode {
	case "":
		return nil, nil
	case model.NodeIPModeAuto, model.NodeIPModeStatic, model.NodeIPModeResolver, model.NodeIPModeScript:
	default:
		return nil, errors.New("mode must be auto, static, resolver, script, or empty to clear")
	}
	if v4 != "" {
		if ip := net.ParseIP(v4); ip == nil || ip.To4() == nil {
			return nil, errors.New("static_ipv4 is not a valid IPv4 address")
		}
	}
	if v6 != "" {
		if ip := net.ParseIP(v6); ip == nil || ip.To4() != nil {
			return nil, errors.New("static_ipv6 is not a valid IPv6 address")
		}
	}
	if mode == model.NodeIPModeStatic && v4 == "" && v6 == "" {
		return nil, errors.New("static mode requires static_ipv4 and/or static_ipv6")
	}
	cleaned := make([]string, 0, len(resolvers))
	for _, raw := range resolvers {
		r := strings.TrimSpace(raw)
		if r == "" {
			continue
		}
		if !strings.HasPrefix(r, "http://") && !strings.HasPrefix(r, "https://") {
			return nil, fmt.Errorf("resolver %q must be an http(s) URL", r)
		}
		cleaned = append(cleaned, r)
	}
	script = strings.TrimSpace(script)
	scriptSHA := ""
	if mode == model.NodeIPModeScript {
		if script == "" && existing != nil && existing.Mode == model.NodeIPModeScript {
			script = existing.Script
			scriptSHA = existing.ScriptSHA256
		}
		if script == "" {
			return nil, errors.New("script mode requires a script body")
		}
		if len(script) > 16*1024 {
			return nil, errors.New("script body must be 16 KiB or smaller")
		}
		if scriptSHA == "" {
			scriptSHA = shortSHA256(script)
		}
	}
	return &model.NodeIPConfig{
		Mode:         mode,
		StaticIPv4:   v4,
		StaticIPv6:   v6,
		Resolvers:    cleaned,
		Script:       script,
		ScriptSHA256: scriptSHA,
	}, nil
}

func redactNodeIPConfig(cfg *model.NodeIPConfig) *model.NodeIPConfig {
	if cfg == nil {
		return nil
	}
	out := *cfg
	out.Script = ""
	if out.Mode == model.NodeIPModeScript && out.ScriptSHA256 == "" && cfg.Script != "" {
		out.ScriptSHA256 = shortSHA256(cfg.Script)
	}
	return &out
}

func shortSHA256(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:16]
}

func (s *Server) handleAgentDebugEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		agentAuthRequest
		Batch model.AgentDebugBatch `json:"batch"`
	}
	if !decodeJSONBody(w, r, &req, agentDebugBatchBodyLimit, false) {
		return
	}
	node, ok := s.authenticateAgentRequest(r, req.NodeID)
	if !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	if req.Batch.NodeID != "" && req.Batch.NodeID != req.NodeID {
		writeError(w, http.StatusBadRequest, errors.New("batch node_id does not match request node_id"))
		return
	}
	if len(req.Batch.Lines) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "accepted": 0})
		return
	}
	if !node.AgentDebug.Enabled || !node.AgentDebug.Collect || s.logStore == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "accepted": 0})
		return
	}
	ls, err := s.ensureAgentDebugLogSource(node)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	maxBatch := ls.MaxBatchLines
	if maxBatch <= 0 {
		maxBatch = defaultAgentDebugMaxBatchLines
	}
	rawLines := req.Batch.Lines
	if len(rawLines) > maxBatch {
		rawLines = rawLines[:maxBatch]
	}
	if !s.logIngestLimiter.AllowN(ls.ID, float64(len(rawLines))) {
		w.Header().Set("Retry-After", logIngestRetryAfter)
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   req.NodeID,
			Action:   "agent.debug.throttled",
			Decision: "deny",
			Reason:   "per-source ingest budget exceeded",
			Metadata: map[string]string{"source_id": ls.ID, "lines": strconv.Itoa(len(rawLines))},
		})
		writeError(w, http.StatusTooManyRequests, apiError(model.APIErrorRateLimited, "debug ingest rate exceeded"))
		return
	}
	at := req.Batch.CapturedAt
	if at.IsZero() {
		at = s.now()
	}
	maxLine := ls.MaxLineBytes
	if maxLine <= 0 {
		maxLine = defaultAgentDebugMaxLineBytes
	}
	lines := make([]model.LogLine, 0, len(rawLines))
	for _, raw := range rawLines {
		truncated := false
		if len(raw) > maxLine {
			raw = raw[:maxLine]
			truncated = true
		}
		lines = append(lines, model.LogLine{
			SourceID:  ls.ID,
			NodeID:    req.NodeID,
			Path:      ls.Path,
			At:        at.UTC(),
			Line:      raw,
			Truncated: truncated,
		})
	}
	lastOff := uint64(at.UTC().UnixNano())
	if _, err := s.logStore.Append(ls.ID, lines, agentDebugRotID, lastOff, at); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "accepted": len(lines), "source_id": ls.ID})
}

func (s *Server) ensureAgentDebugLogSource(node model.Node) (model.LogSource, error) {
	if strings.TrimSpace(node.ID) == "" {
		return model.LogSource{}, fmt.Errorf("node id is required")
	}
	sourceID := agentDebugSourceID(node.ID)
	now := s.now().UTC()
	ls, ok := s.store.LogSource(sourceID)
	changed := !ok
	if !ok {
		ls = model.LogSource{
			ID:        sourceID,
			CreatedAt: now,
		}
	}
	sourceName := "Agent debug"
	if nodeName := firstNonEmpty(node.Name, node.ID); nodeName != "" {
		sourceName = "Agent debug - " + nodeName
	}
	if ls.Name != sourceName {
		ls.Name = sourceName
		changed = true
	}
	if ls.NodeID != node.ID {
		ls.NodeID = node.ID
		changed = true
	}
	path := agentDebugPathPrefix + node.ID
	if ls.Path != path {
		ls.Path = path
		changed = true
	}
	if !ls.Enabled {
		ls.Enabled = true
		changed = true
	}
	if ls.MaxLineBytes != defaultAgentDebugMaxLineBytes {
		ls.MaxLineBytes = defaultAgentDebugMaxLineBytes
		changed = true
	}
	if ls.MaxBatchLines != defaultAgentDebugMaxBatchLines {
		ls.MaxBatchLines = defaultAgentDebugMaxBatchLines
		changed = true
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

func agentDebugSourceID(nodeID string) string {
	sum := sha256.Sum256([]byte(nodeID))
	return "agent-debug-" + hex.EncodeToString(sum[:8])
}

func isAgentDebugLogSource(ls model.LogSource) bool {
	return strings.HasPrefix(ls.Path, agentDebugPathPrefix)
}
