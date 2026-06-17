package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

const (
	terminalDefaultShell    = "/bin/sh"
	terminalDefaultCols     = 120
	terminalDefaultRows     = 32
	terminalMaxCols         = 300
	terminalMaxRows         = 120
	terminalMaxInputBytes   = 16 * 1024
	terminalMaxEventBytes   = 32 * 1024
	terminalMaxEventCount   = 600
	terminalMaxSessionBytes = 512 * 1024
)

type terminalBroker struct {
	mu       sync.Mutex
	sessions map[string]*terminalSessionState
}

type terminalSessionState struct {
	session      model.TerminalSession
	nextEventSeq int64
	nextInputSeq int64
	events       []model.TerminalEvent
	inputs       []model.TerminalInput
}

func newTerminalBroker() *terminalBroker {
	return &terminalBroker{sessions: map[string]*terminalSessionState{}}
}

func (b *terminalBroker) create(nodeID, actorID, tokenID, shell string, cols, rows int, now time.Time) model.TerminalSession {
	b.mu.Lock()
	defer b.mu.Unlock()
	shell = normalizeTerminalShell(shell)
	cols, rows = normalizeTerminalSize(cols, rows)
	session := model.TerminalSession{
		ID:        id.New("term"),
		NodeID:    nodeID,
		ActorID:   actorID,
		TokenID:   tokenID,
		Shell:     shell,
		Cols:      cols,
		Rows:      rows,
		Status:    model.TerminalPending,
		CreatedAt: now.UTC(),
		LastSeen:  now.UTC(),
	}
	b.sessions[session.ID] = &terminalSessionState{session: session, nextEventSeq: 1, nextInputSeq: 1}
	return session
}

func (b *terminalBroker) list() []model.TerminalSession {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]model.TerminalSession, 0, len(b.sessions))
	for _, state := range b.sessions {
		out = append(out, state.session)
	}
	return out
}

func (b *terminalBroker) get(sessionID string) (model.TerminalSession, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	state, ok := b.sessions[sessionID]
	if !ok {
		return model.TerminalSession{}, false
	}
	return state.session, true
}

func (b *terminalBroker) eventsAfter(sessionID string, cursor int64) (model.TerminalSession, []model.TerminalEvent, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	state, ok := b.sessions[sessionID]
	if !ok {
		return model.TerminalSession{}, nil, false
	}
	events := make([]model.TerminalEvent, 0, len(state.events))
	for _, event := range state.events {
		if event.Seq > cursor {
			events = append(events, event)
		}
	}
	return state.session, events, true
}

func (b *terminalBroker) pendingForAgent(nodeID string, now time.Time) []model.TerminalSession {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []model.TerminalSession
	for _, state := range b.sessions {
		if state.session.NodeID != nodeID || state.session.Status != model.TerminalPending {
			continue
		}
		state.session.LastSeen = now.UTC()
		out = append(out, state.session)
	}
	return out
}

func (b *terminalBroker) addInput(sessionID, kind, data string, cols, rows int, now time.Time) (model.TerminalSession, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	state, ok := b.sessions[sessionID]
	if !ok {
		return model.TerminalSession{}, errors.New("terminal session not found")
	}
	if state.session.Status == model.TerminalClosed || state.session.Status == model.TerminalFailed {
		return model.TerminalSession{}, errors.New("terminal session is closed")
	}
	switch kind {
	case "data":
		if data == "" {
			return model.TerminalSession{}, errors.New("input data is required")
		}
		if len([]byte(data)) > terminalMaxInputBytes {
			return model.TerminalSession{}, fmt.Errorf("input exceeds %d bytes", terminalMaxInputBytes)
		}
		state.session.BytesIn += int64(len([]byte(data)))
	case "resize":
		cols, rows = normalizeTerminalSize(cols, rows)
		state.session.Cols = cols
		state.session.Rows = rows
	case "close":
		if state.session.Status == model.TerminalPending {
			state.session.Status = model.TerminalClosed
			state.session.ClosedAt = now.UTC()
		}
	default:
		return model.TerminalSession{}, errors.New("unsupported terminal input kind")
	}
	input := model.TerminalInput{
		Seq:       state.nextInputSeq,
		Kind:      kind,
		Data:      data,
		Cols:      cols,
		Rows:      rows,
		CreatedAt: now.UTC(),
	}
	state.nextInputSeq++
	state.inputs = append(state.inputs, input)
	state.session.LastSeen = now.UTC()
	return state.session, nil
}

func (b *terminalBroker) inputsAfter(sessionID, nodeID string, cursor int64, now time.Time) (model.TerminalSession, []model.TerminalInput, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	state, ok := b.sessions[sessionID]
	if !ok || state.session.NodeID != nodeID {
		return model.TerminalSession{}, nil, false
	}
	state.session.LastSeen = now.UTC()
	inputs := make([]model.TerminalInput, 0, len(state.inputs))
	for _, input := range state.inputs {
		if input.Seq > cursor {
			inputs = append(inputs, input)
		}
	}
	return state.session, inputs, true
}

func (b *terminalBroker) agentUpdate(sessionID, nodeID, status, message string, events []model.TerminalEvent, now time.Time) (model.TerminalSession, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	state, ok := b.sessions[sessionID]
	if !ok {
		return model.TerminalSession{}, errors.New("terminal session not found")
	}
	if state.session.NodeID != nodeID {
		return model.TerminalSession{}, errors.New("terminal session does not belong to node")
	}
	now = now.UTC()
	switch status {
	case "", model.TerminalPending:
	case model.TerminalOpen:
		if state.session.Status == model.TerminalPending {
			state.session.OpenedAt = now
		}
		if state.session.Status != model.TerminalClosed && state.session.Status != model.TerminalFailed {
			state.session.Status = model.TerminalOpen
			state.session.Error = ""
		}
	case model.TerminalClosed, model.TerminalFailed:
		state.session.Status = status
		state.session.Error = clampPrintable(message, 256)
		if state.session.ClosedAt.IsZero() {
			state.session.ClosedAt = now
		}
	default:
		return model.TerminalSession{}, errors.New("unsupported terminal status")
	}
	state.session.LastSeen = now
	for _, event := range events {
		if event.Kind == "" {
			event.Kind = "output"
		}
		if len([]byte(event.Data)) > terminalMaxEventBytes {
			event.Data = string([]byte(event.Data)[:terminalMaxEventBytes]) + "...truncated"
		}
		if event.Data == "" && event.Kind == "output" {
			continue
		}
		event.Seq = state.nextEventSeq
		event.CreatedAt = now
		state.nextEventSeq++
		state.session.BytesOut += int64(len([]byte(event.Data)))
		state.events = append(state.events, event)
	}
	trimTerminalEvents(state)
	return state.session, nil
}

func trimTerminalEvents(state *terminalSessionState) {
	if len(state.events) > terminalMaxEventCount {
		state.events = state.events[len(state.events)-terminalMaxEventCount:]
	}
	var total int
	start := len(state.events)
	for i := len(state.events) - 1; i >= 0; i-- {
		total += len([]byte(state.events[i].Data))
		if total > terminalMaxSessionBytes {
			break
		}
		start = i
	}
	if start > 0 && start < len(state.events) {
		state.events = state.events[start:]
	}
}

func normalizeTerminalShell(shell string) string {
	shell = strings.TrimSpace(shell)
	switch shell {
	case "", "sh":
		return terminalDefaultShell
	case "bash":
		return "/bin/bash"
	case "/bin/sh", "/bin/bash", "/usr/bin/bash", "/usr/bin/zsh", "/bin/zsh":
		return shell
	default:
		return terminalDefaultShell
	}
}

func normalizeTerminalSize(cols, rows int) (int, int) {
	if cols <= 0 {
		cols = terminalDefaultCols
	}
	if rows <= 0 {
		rows = terminalDefaultRows
	}
	if cols > terminalMaxCols {
		cols = terminalMaxCols
	}
	if rows > terminalMaxRows {
		rows = terminalMaxRows
	}
	return cols, rows
}

func (s *Server) handleTerminalSessions(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireScope(w, p, "terminal:open") {
			return
		}
		sessions := s.terminalBroker.list()
		visible := make([]model.TerminalSession, 0, len(sessions))
		for _, session := range sessions {
			if rbac.Allows(p.Principal, "terminal:open", session.NodeID) {
				visible = append(visible, session)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"sessions": visible})
	case http.MethodPost:
		var req struct {
			NodeID string `json:"node_id"`
			Shell  string `json:"shell,omitempty"`
			Cols   int    `json:"cols,omitempty"`
			Rows   int    `json:"rows,omitempty"`
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		req.NodeID = strings.TrimSpace(req.NodeID)
		if req.NodeID == "" {
			writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
			return
		}
		if !s.requireNodeScope(w, p, "terminal:open", req.NodeID) {
			return
		}
		if _, ok := s.store.Node(req.NodeID); !ok {
			writeError(w, http.StatusNotFound, errors.New("node not found"))
			return
		}
		session := s.terminalBroker.create(req.NodeID, p.ActorID, p.TokenID, req.Shell, req.Cols, req.Rows, s.now())
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:     id.New("audit"),
			NodeID: req.NodeID,
			Action: "terminal.open",
			Scope:  "terminal:open",
			Metadata: map[string]string{
				"session_id": session.ID,
				"shell":      session.Shell,
			},
		})
		writeJSON(w, http.StatusOK, session)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleTerminalSessionPath(w http.ResponseWriter, r *http.Request, p principal) {
	sessionID, action := splitTerminalPath(strings.TrimPrefix(r.URL.Path, "/api/terminal/sessions/"))
	if sessionID == "" || action == "" {
		writeError(w, http.StatusNotFound, errors.New("terminal endpoint not found"))
		return
	}
	session, ok := s.terminalBroker.get(sessionID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("terminal session not found"))
		return
	}
	if !s.requireNodeScope(w, p, "terminal:open", session.NodeID) {
		return
	}
	switch action {
	case "events":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		cursor := parseInt64Query(r, "cursor")
		session, events, ok := s.terminalBroker.eventsAfter(sessionID, cursor)
		if !ok {
			writeError(w, http.StatusNotFound, errors.New("terminal session not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"session": session, "events": events})
	case "input":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var req struct {
			Data string `json:"data"`
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		session, err := s.terminalBroker.addInput(sessionID, "data", req.Data, 0, 0, s.now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, session)
	case "resize":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var req struct {
			Cols int `json:"cols"`
			Rows int `json:"rows"`
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		session, err := s.terminalBroker.addInput(sessionID, "resize", "", req.Cols, req.Rows, s.now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, session)
	case "close":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		session, err := s.terminalBroker.addInput(sessionID, "close", "", 0, 0, s.now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:     id.New("audit"),
			NodeID: session.NodeID,
			Action: "terminal.close",
			Scope:  "terminal:open",
			Metadata: map[string]string{
				"session_id": session.ID,
			},
		})
		writeJSON(w, http.StatusOK, session)
	default:
		writeError(w, http.StatusNotFound, errors.New("terminal endpoint not found"))
	}
}

func (s *Server) handleAgentTerminalSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	nodeID := r.URL.Query().Get("node_id")
	if _, ok := s.authenticateNode(nodeID, bearerToken(r)); !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	sessions := s.terminalBroker.pendingForAgent(nodeID, s.now())
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

func (s *Server) handleAgentTerminalSessionPath(w http.ResponseWriter, r *http.Request) {
	sessionID, action := splitTerminalPath(strings.TrimPrefix(r.URL.Path, "/api/agent/terminal/sessions/"))
	if sessionID == "" || action == "" {
		writeError(w, http.StatusNotFound, errors.New("terminal endpoint not found"))
		return
	}
	switch action {
	case "inputs":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		nodeID := r.URL.Query().Get("node_id")
		if _, ok := s.authenticateNode(nodeID, bearerToken(r)); !ok {
			writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
			return
		}
		cursor := parseInt64Query(r, "cursor")
		session, inputs, ok := s.terminalBroker.inputsAfter(sessionID, nodeID, cursor, s.now())
		if !ok {
			writeError(w, http.StatusNotFound, errors.New("terminal session not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"session": session, "inputs": inputs})
	case "events":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var req struct {
			agentAuthRequest
			Status string                `json:"status,omitempty"`
			Error  string                `json:"error,omitempty"`
			Events []model.TerminalEvent `json:"events,omitempty"`
		}
		if !decodeAgentJSON(w, r, &req) {
			return
		}
		if _, ok := s.authenticateAgentRequest(r, req.NodeID); !ok {
			writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
			return
		}
		session, err := s.terminalBroker.agentUpdate(sessionID, req.NodeID, req.Status, req.Error, req.Events, s.now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.Status == model.TerminalClosed || req.Status == model.TerminalFailed {
			s.recordRequestAudit(r, model.AuditEvent{
				ID:       id.New("audit"),
				NodeID:   req.NodeID,
				Action:   "terminal.agent.close",
				Decision: "observe",
				Metadata: map[string]string{
					"session_id": session.ID,
					"status":     session.Status,
				},
			})
		}
		writeJSON(w, http.StatusOK, session)
	default:
		writeError(w, http.StatusNotFound, errors.New("terminal endpoint not found"))
	}
}

func splitTerminalPath(path string) (string, string) {
	path = strings.Trim(path, "/")
	if path == "" {
		return "", ""
	}
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}

func parseInt64Query(r *http.Request, key string) int64 {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return 0
	}
	out, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || out < 0 {
		return 0
	}
	return out
}
