package server

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/LatticeNet/lattice-sdk/model"
)

const (
	agentControlSendBuffer   = 16
	agentControlReadLimit    = 16 * 1024
	agentControlPingInterval = 25 * time.Second
	agentControlPongWait     = 75 * time.Second
)

type agentControlMessage struct {
	Type    string                `json:"type"`
	Session model.TerminalSession `json:"session,omitempty"`
}

type agentControlHub struct {
	mu    sync.Mutex
	conns map[string]map[*agentControlConn]struct{}
}

type agentControlConn struct {
	nodeID string
	send   chan agentControlMessage
}

func newAgentControlHub() *agentControlHub {
	return &agentControlHub{conns: map[string]map[*agentControlConn]struct{}{}}
}

func (h *agentControlHub) register(nodeID string) *agentControlConn {
	conn := &agentControlConn{
		nodeID: nodeID,
		send:   make(chan agentControlMessage, agentControlSendBuffer),
	}
	h.mu.Lock()
	if h.conns[nodeID] == nil {
		h.conns[nodeID] = map[*agentControlConn]struct{}{}
	}
	h.conns[nodeID][conn] = struct{}{}
	h.mu.Unlock()
	return conn
}

func (h *agentControlHub) unregister(conn *agentControlConn) {
	h.mu.Lock()
	if conns := h.conns[conn.nodeID]; conns != nil {
		if _, ok := conns[conn]; ok {
			delete(conns, conn)
			close(conn.send)
		}
		if len(conns) == 0 {
			delete(h.conns, conn.nodeID)
		}
	}
	h.mu.Unlock()
}

func (h *agentControlHub) notifyTerminalOpen(session model.TerminalSession) bool {
	return h.notify(session.NodeID, agentControlMessage{
		Type:    "terminal.open",
		Session: session,
	})
}

func (h *agentControlHub) notify(nodeID string, msg agentControlMessage) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	var delivered bool
	for conn := range h.conns[nodeID] {
		select {
		case conn.send <- msg:
			delivered = true
		default:
			// A wedged control connection must not block operator actions. The
			// agent's fallback poll loop covers a dropped notification.
		}
	}
	return delivered
}

func (s *Server) handleAgentControlStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	if _, ok := s.authenticateNode(r, nodeID, bearerToken(r)); !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	conn, err := terminalUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	control := s.agentControlHub.register(nodeID)
	defer s.agentControlHub.unregister(control)

	done := make(chan struct{})
	defer close(done)
	go agentControlWriteLoop(conn, control.send, done)
	agentControlReadLoop(conn)
}

func agentControlReadLoop(conn *websocket.Conn) {
	conn.SetReadLimit(agentControlReadLimit)
	_ = conn.SetReadDeadline(time.Now().Add(agentControlPongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(agentControlPongWait))
	})
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

func agentControlWriteLoop(conn *websocket.Conn, send <-chan agentControlMessage, done <-chan struct{}) {
	ticker := time.NewTicker(agentControlPingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case msg, ok := <-send:
			if !ok {
				return
			}
			if err := conn.SetWriteDeadline(time.Now().Add(terminalStreamWriteWait)); err != nil {
				_ = conn.Close()
				return
			}
			if err := conn.WriteJSON(msg); err != nil {
				_ = conn.Close()
				return
			}
		case <-ticker.C:
			if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(terminalStreamWriteWait)); err != nil {
				_ = conn.Close()
				return
			}
		}
	}
}
