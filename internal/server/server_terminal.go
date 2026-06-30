package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/websocketx"
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
	terminalMaxSessions     = 128

	terminalMaxActiveSessionsPerNode = 4
	terminalPendingTTL               = 10 * time.Minute
	// terminalIdleTTL bounds an open session that is NOT currently bridged (no
	// live viewer↔agent splice). A bridged session is exempt: its bytes flow over
	// the WebSocket relay and never touch the broker, so LastSeen cannot track its
	// liveness — the agent enforces real idle (no PTY output AND no stdin) itself
	// and closes the session explicitly. This is therefore a backstop for the
	// not-currently-bridged case (e.g. a stuck pending→open with no viewer).
	terminalIdleTTL = 30 * time.Minute
	// terminalDetachGrace bounds how long a session whose viewer disconnected is
	// kept alive awaiting a reattach. Within this window a brief network blip,
	// page reload, or laptop-sleep is forgiven and the kept-alive PTY is rejoined;
	// past it the session is reaped (the node is presumed unreachable / abandoned).
	terminalDetachGrace = 90 * time.Second
	// terminalMaxLifeTTL is an absolute cap from OpenedAt regardless of activity —
	// defense in depth so a forgotten-but-busy session cannot live forever.
	terminalMaxLifeTTL = 8 * time.Hour
	// terminalClosedTTL retains a closed session so the UI can render its final
	// status before it is garbage-collected.
	terminalClosedTTL = 30 * time.Minute
	// terminalReaperTick is the background reaper cadence; it sets the granularity
	// at which the detach grace and idle/max caps are enforced.
	terminalReaperTick = 5 * time.Second
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
	// bridged is true while a live browser↔agent splice exists for this session
	// (streaming transport). A bridged session is exempt from the idle/detach
	// reaper: its liveness is owned by the agent, which sees every byte and
	// enforces the real idle cap itself.
	bridged bool
	// detachedAt is set when a live bridge ends with the session still open (the
	// viewer left or the link blipped) and cleared when a new bridge forms. The
	// detach grace is measured from it. Zero when bridged or never-bridged.
	detachedAt time.Time
}

func newTerminalBroker() *terminalBroker {
	return &terminalBroker{sessions: map[string]*terminalSessionState{}}
}

// startTerminalReaper runs the terminal lifecycle GC on a fixed cadence so the
// detach grace and idle/max caps are enforced even for a stable streaming
// session that otherwise never re-touches the broker. Mirrors the renewal
// scheduler: a single goroutine for the process lifetime.
func (s *Server) startTerminalReaper() {
	go func() {
		ticker := time.NewTicker(terminalReaperTick)
		defer ticker.Stop()
		for range ticker.C {
			s.terminalBroker.reap(s.now())
		}
	}()
}

func (b *terminalBroker) create(nodeID, actorID, tokenID, shell string, cols, rows int, now time.Time) (model.TerminalSession, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now = now.UTC()
	b.pruneLocked(now)
	var activeForNode int
	for _, state := range b.sessions {
		if state.session.NodeID == nodeID && terminalActiveStatus(state.session.Status) {
			activeForNode++
		}
	}
	if activeForNode >= terminalMaxActiveSessionsPerNode {
		return model.TerminalSession{}, fmt.Errorf("node already has %d active terminal sessions", terminalMaxActiveSessionsPerNode)
	}
	for len(b.sessions) >= terminalMaxSessions && b.dropOldestClosedLocked() {
	}
	if len(b.sessions) >= terminalMaxSessions {
		return model.TerminalSession{}, errors.New("terminal session capacity reached")
	}
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
		CreatedAt: now,
		LastSeen:  now,
	}
	b.sessions[session.ID] = &terminalSessionState{session: session, nextEventSeq: 1, nextInputSeq: 1}
	return session, nil
}

func (b *terminalBroker) list(now time.Time) []model.TerminalSession {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked(now.UTC())
	out := make([]model.TerminalSession, 0, len(b.sessions))
	for _, state := range b.sessions {
		out = append(out, state.session)
	}
	return out
}

func (b *terminalBroker) get(sessionID string, now time.Time) (model.TerminalSession, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked(now.UTC())
	state, ok := b.sessions[sessionID]
	if !ok {
		return model.TerminalSession{}, false
	}
	return state.session, true
}

func (b *terminalBroker) eventsAfter(sessionID string, cursor int64, now time.Time) (model.TerminalSession, []model.TerminalEvent, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked(now.UTC())
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
	now = now.UTC()
	b.pruneLocked(now)
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
	now = now.UTC()
	b.pruneLocked(now)
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
		state.session.Status = model.TerminalClosed
		if state.session.ClosedAt.IsZero() {
			state.session.ClosedAt = now
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
		CreatedAt: now,
	}
	state.nextInputSeq++
	state.inputs = append(state.inputs, input)
	state.session.LastSeen = now
	return state.session, nil
}

func (b *terminalBroker) inputsAfter(sessionID, nodeID string, cursor int64, now time.Time) (model.TerminalSession, []model.TerminalInput, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now = now.UTC()
	b.pruneLocked(now)
	state, ok := b.sessions[sessionID]
	if !ok || state.session.NodeID != nodeID {
		return model.TerminalSession{}, nil, false
	}
	state.session.LastSeen = now
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
	now = now.UTC()
	b.pruneLocked(now)
	state, ok := b.sessions[sessionID]
	if !ok {
		return model.TerminalSession{}, errors.New("terminal session not found")
	}
	if state.session.NodeID != nodeID {
		return model.TerminalSession{}, errors.New("terminal session does not belong to node")
	}
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

// markOpen transitions a session to open when its live agent stream connects.
// It mirrors the status-transition half of agentUpdate(status=open) without
// touching the event byte buffers, which the streaming transport bypasses.
func (b *terminalBroker) markOpen(sessionID string, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now = now.UTC()
	b.pruneLocked(now)
	state, ok := b.sessions[sessionID]
	if !ok {
		return
	}
	if state.session.Status == model.TerminalClosed || state.session.Status == model.TerminalFailed {
		return
	}
	if state.session.Status == model.TerminalPending {
		state.session.OpenedAt = now
	}
	state.session.Status = model.TerminalOpen
	state.session.Error = ""
	state.session.LastSeen = now
}

// markClosed transitions a session to a terminal status when its live stream
// ends. It mirrors the status-transition half of agentUpdate(status=closed|
// failed) without touching the event byte buffers. status defaults to closed
// for any non-terminal value; an already-closed session is left unchanged.
func (b *terminalBroker) markClosed(sessionID, status, errMsg string, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now = now.UTC()
	b.pruneLocked(now)
	state, ok := b.sessions[sessionID]
	if !ok {
		return
	}
	if status != model.TerminalClosed && status != model.TerminalFailed {
		status = model.TerminalClosed
	}
	if state.session.Status != model.TerminalClosed && state.session.Status != model.TerminalFailed {
		state.session.Status = status
		state.session.Error = clampPrintable(errMsg, 256)
		if state.session.ClosedAt.IsZero() {
			state.session.ClosedAt = now
		}
	}
	state.bridged = false
	state.detachedAt = time.Time{}
	state.session.LastSeen = now
}

// clearDetached marks a session as live-bridged: a browser↔agent splice has just
// formed. It cancels any pending detach grace and refreshes LastSeen. Called
// (under no other lock) by the attach handler the instant the agent leg arrives,
// so a reattach within the grace window seamlessly resumes the kept-alive PTY.
func (b *terminalBroker) clearDetached(sessionID string, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	state, ok := b.sessions[sessionID]
	if !ok {
		return
	}
	state.bridged = true
	state.detachedAt = time.Time{}
	state.session.LastSeen = now.UTC()
}

// markDetached records that a live bridge ended with the session still open (the
// viewer's WebSocket dropped — a tab close, reload, or network blip). It does
// NOT close the session: the PTY is kept alive on the agent, and the detach
// grace (enforced by the reaper) governs how long we wait for a reattach. An
// already-closed session is left closed.
func (b *terminalBroker) markDetached(sessionID string, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now = now.UTC()
	state, ok := b.sessions[sessionID]
	if !ok {
		return
	}
	state.bridged = false
	if terminalActiveStatus(state.session.Status) && state.detachedAt.IsZero() {
		state.detachedAt = now
	}
	state.session.LastSeen = now
}

// reap runs the lifecycle GC out of band. The lazy prune on every broker access
// is retained, but a stable streaming session touches the broker only on (re)dial
// and explicit close, so without a periodic sweep a detached/idle/over-age
// session could linger until the next unrelated access. The reaper bounds that
// to terminalReaperTick.
func (b *terminalBroker) reap(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked(now.UTC())
}

func (b *terminalBroker) pruneLocked(now time.Time) {
	for sessionID, state := range b.sessions {
		session := &state.session
		switch {
		case session.Status == model.TerminalPending && now.Sub(session.CreatedAt) > terminalPendingTTL:
			failTerminalSession(state, "terminal session expired before node accepted it", now)
		case terminalActiveStatus(session.Status):
			switch {
			case !session.OpenedAt.IsZero() && now.Sub(session.OpenedAt) > terminalMaxLifeTTL:
				failTerminalSession(state, "terminal session reached maximum duration", now)
			case !state.bridged && !state.detachedAt.IsZero() && now.Sub(state.detachedAt) > terminalDetachGrace:
				failTerminalSession(state, "terminal viewer disconnected and did not return", now)
			case !state.bridged && !session.LastSeen.IsZero() && now.Sub(session.LastSeen) > terminalIdleTTL:
				failTerminalSession(state, "terminal session expired after inactivity", now)
			}
		}
		if terminalClosedStatus(session.Status) && now.Sub(terminalClosedAt(*session)) >= terminalClosedTTL {
			delete(b.sessions, sessionID)
		}
	}
	for len(b.sessions) > terminalMaxSessions && b.dropOldestClosedLocked() {
	}
}

// failTerminalSession transitions a state to failed with a reason, recording the
// close time once. It also clears the bridge/detach bookkeeping so the closed
// session is inert.
func failTerminalSession(state *terminalSessionState, reason string, now time.Time) {
	state.session.Status = model.TerminalFailed
	state.session.Error = reason
	if state.session.ClosedAt.IsZero() {
		state.session.ClosedAt = now
	}
	state.session.LastSeen = now
	state.bridged = false
	state.detachedAt = time.Time{}
}

func (b *terminalBroker) dropOldestClosedLocked() bool {
	var oldestID string
	var oldestAt time.Time
	for sessionID, state := range b.sessions {
		if !terminalClosedStatus(state.session.Status) {
			continue
		}
		closedAt := terminalClosedAt(state.session)
		if oldestID == "" || closedAt.Before(oldestAt) {
			oldestID = sessionID
			oldestAt = closedAt
		}
	}
	if oldestID == "" {
		return false
	}
	delete(b.sessions, oldestID)
	return true
}

func terminalActiveStatus(status string) bool {
	return status != model.TerminalClosed && status != model.TerminalFailed
}

// activeSessionsForNode counts the node's currently-active (non-terminal)
// sessions. Used by the node-delete plan to preview how many sessions a delete
// would close.
func (b *terminalBroker) activeSessionsForNode(nodeID string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	count := 0
	for _, state := range b.sessions {
		if state.session.NodeID == nodeID && terminalActiveStatus(state.session.Status) {
			count++
		}
	}
	return count
}

// closeForNode terminates every active session belonging to nodeID (used when
// the node is hard-deleted) and returns how many it closed. IDs are collected
// under the broker lock, then markClosed is called per-session without the lock
// held (markClosed takes the non-reentrant broker mutex itself).
func (b *terminalBroker) closeForNode(nodeID string, now time.Time) int {
	now = now.UTC()
	b.mu.Lock()
	ids := make([]string, 0)
	for _, state := range b.sessions {
		if state.session.NodeID == nodeID && terminalActiveStatus(state.session.Status) {
			ids = append(ids, state.session.ID)
		}
	}
	b.mu.Unlock()
	for _, sid := range ids {
		b.markClosed(sid, model.TerminalClosed, "node deleted", now)
	}
	return len(ids)
}

func terminalClosedStatus(status string) bool {
	return status == model.TerminalClosed || status == model.TerminalFailed
}

func terminalClosedAt(session model.TerminalSession) time.Time {
	if !session.ClosedAt.IsZero() {
		return session.ClosedAt
	}
	if !session.LastSeen.IsZero() {
		return session.LastSeen
	}
	return session.CreatedAt
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
		sessions := s.terminalBroker.list(s.now())
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
		session, err := s.terminalBroker.create(req.NodeID, p.ActorID, p.TokenID, req.Shell, req.Cols, req.Rows, s.now())
		if err != nil {
			writeError(w, http.StatusTooManyRequests, err)
			return
		}
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
	session, ok := s.terminalBroker.get(sessionID, s.now())
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
		session, events, ok := s.terminalBroker.eventsAfter(sessionID, cursor, s.now())
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
	case "attach":
		// Live WebSocket attach (dark-launched; no client uses it yet). The RBAC
		// gate above (requireNodeScope terminal:open) has already run, so the
		// upgrade is reached only for an authorized principal on this node.
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		conn, err := terminalUpgrader.Upgrade(w, r, nil)
		if err != nil {
			// Upgrade has already written an error response to the client.
			return
		}
		// If the session already ended (shell exited, reaped, or closed), tell the
		// browser cleanly with a normal close so it stops reconnecting instead of
		// waiting out the agent-dial timeout. A WebSocket handshake failure can't
		// convey this — the browser only sees an abnormal 1006 — so we must upgrade
		// first and then send the 1000 close frame.
		if cur, ok := s.terminalBroker.get(session.ID, s.now()); ok && terminalClosedStatus(cur.Status) {
			_ = conn.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, "terminal session closed"),
				time.Now().Add(time.Second),
			)
			_ = conn.Close()
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:     id.New("audit"),
			NodeID: session.NodeID,
			Action: "terminal.attach",
			Scope:  "terminal:open",
			Metadata: map[string]string{
				"session_id": session.ID,
			},
		})
		// attachBrowser blocks until the agent bridges and the byte pump tears
		// down (or the attach times out). When a live bridge forms, onBridge
		// clears any detach grace (a reattach within the window resumes the
		// kept-alive PTY). When the bridge ends with the session still open we do
		// NOT close it: the viewer's socket merely dropped (tab close, reload,
		// network blip). markDetached starts the detach grace; the agent keeps the
		// shell alive and redials, and the reaper closes the session only if no
		// reattach arrives in time or the agent reports the shell exited. If no
		// agent ever connected (bridged == false), the session was never live, so
		// its lifecycle is left to the pending/idle reaper.
		browserConn := websocketx.NewConn(conn)
		browserConn.SetReadLimit(terminalMaxInputBytes)
		bridged := s.terminalHub.attachBrowser(session.ID, browserConn, func() {
			s.terminalBroker.clearDetached(session.ID, s.now())
		})
		if bridged {
			s.terminalBroker.markDetached(session.ID, s.now())
		}
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
