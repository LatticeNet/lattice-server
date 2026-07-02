package server

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/websocketx"
)

const (
	// terminalAttachTimeout bounds how long a browser attach waits for the agent
	// to dial in before giving up and closing the browser with a try-again code.
	terminalAttachTimeout = 30 * time.Second
	// terminalAgentDeliverWindow bounds how long an agent dial-in retries to find
	// its waiting browser before the agent connection is closed. Browsers attach
	// first, so this is a safety net for the registration race, not a steady wait.
	terminalAgentDeliverWindow = 5 * time.Second
	// terminalAgentDeliverPoll is the retry granularity used while an agent waits
	// for its browser within terminalAgentDeliverWindow.
	terminalAgentDeliverPoll = 50 * time.Millisecond
	// terminalCloseTryAgain is WebSocket close code 1013 (Try Again Later); sent
	// to the browser when the agent never dials in (node offline).
	terminalCloseTryAgain = 1013
	// terminalStreamBufferBytes sizes the upgrader's read/write buffers.
	terminalStreamBufferBytes = 32 * 1024

	// Keepalive + write-deadline tunables for the spliced bridge legs. The server
	// pings both peers so a half-open connection (browser tab frozen, agent host
	// off the network, a proxy that dropped the flow) is detected within pongWait
	// instead of wedging the byte pump. writeWait bounds a single frame write so a
	// stalled peer errors the leg rather than blocking the opposite leg's drain.
	terminalStreamPingInterval = 10 * time.Second
	terminalStreamPongWait     = 30 * time.Second
	terminalStreamWriteWait    = 10 * time.Second
)

// terminalUpgrader upgrades terminal HTTP requests to WebSocket. CheckOrigin
// enforces same-origin for browser clients (which always send Origin); the
// agent dial-out sends no Origin and is authenticated by node token instead.
var terminalUpgrader = websocket.Upgrader{
	ReadBufferSize:  terminalStreamBufferBytes,
	WriteBufferSize: terminalStreamBufferBytes,
	CheckOrigin:     terminalCheckOrigin,
}

// terminalCheckOrigin allows a WebSocket upgrade only when the browser Origin
// matches the externally-visible host the request was sent to. A missing Origin
// is allowed: non-browser clients (the agent dial-out) send none and are
// authenticated by node token, and the browser WebSocket API forbids JS from
// forging an Origin, so a cross-origin attach attempt always carries a truthful
// mismatching Origin and is rejected here.
func terminalCheckOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return requestHost(u.Host) == terminalForwardedHost(r)
}

// terminalForwardedHost returns the externally-visible host the request was sent
// to. Cloudflare terminates TLS and nginx proxies to the origin, so the public
// host arrives via X-Forwarded-Host when the proxy sets it, falling back to the
// Host header. Browser JS cannot set X-Forwarded-Host on a WebSocket handshake,
// so honoring it for the same-origin comparison cannot be abused from a
// victim's browser.
func terminalForwardedHost(r *http.Request) string {
	if fwd := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); fwd != "" {
		if comma := strings.IndexByte(fwd, ','); comma >= 0 {
			fwd = fwd[:comma]
		}
		return requestHost(fwd)
	}
	return requestHost(r.Host)
}

// terminalHub matches a waiting browser WebSocket to the agent WebSocket that
// dials in for the same session, then splices them with a byte pump. It owns no
// session metadata: terminalBroker remains the source of truth for session
// lifecycle, RBAC subject, audit identity, and per-node caps.
type terminalHub struct {
	mu      sync.Mutex
	pending map[string]*pendingBridge
}

func newTerminalHub() *terminalHub {
	return &terminalHub{pending: map[string]*pendingBridge{}}
}

// pendingBridge tracks a browser attach awaiting its agent dial-in. agentCh is
// unbuffered: delivery is a rendezvous, so an agent that arrives after the
// browser has given up cannot leave a connection buffered and unread. done is
// closed when the browser side gives up, so a late agent falls through to its
// done case and closes its own connection instead of leaking.
type pendingBridge struct {
	sessionID string
	browser   *websocketx.Conn
	agentCh   chan *websocketx.Conn
	done      chan struct{}
	closeOnce sync.Once
}

func (p *pendingBridge) close() {
	p.closeOnce.Do(func() { close(p.done) })
}

// attachBrowser registers the browser connection for sessionID and waits for the
// agent to dial in. On agent arrival it invokes onBridge (used by the caller to
// clear the session's detached state under the broker lock) and splices the two
// connections, blocking until the bridge tears down; it then returns true. On
// timeout it closes the browser with a try-again close so the UI can report the
// node as unreachable, and returns false. The bridged return value lets the
// caller distinguish "the user's viewer left a live session" (start the detach
// window) from "no agent ever connected" (leave lifecycle to the TTL reaper).
func (h *terminalHub) attachBrowser(sessionID string, c *websocketx.Conn, onBridge func()) bool {
	bridge := &pendingBridge{
		sessionID: sessionID,
		browser:   c,
		agentCh:   make(chan *websocketx.Conn),
		done:      make(chan struct{}),
	}
	h.mu.Lock()
	// A stale waiter (e.g. a browser reconnect) is superseded by the new attach.
	if existing, ok := h.pending[sessionID]; ok {
		existing.close()
	}
	h.pending[sessionID] = bridge
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		if h.pending[sessionID] == bridge {
			delete(h.pending, sessionID)
		}
		h.mu.Unlock()
		bridge.close()
	}()

	timer := time.NewTimer(terminalAttachTimeout)
	defer timer.Stop()
	select {
	case agent := <-bridge.agentCh:
		if onBridge != nil {
			onBridge()
		}
		h.bridge(c, agent)
		return true
	case <-bridge.done:
		_ = c.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseServiceRestart, "terminal attach superseded"),
			time.Now().Add(time.Second),
		)
		_ = c.Close()
		return false
	case <-timer.C:
		_ = c.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(terminalCloseTryAgain, "terminal node offline"),
			time.Now().Add(time.Second),
		)
		_ = c.Close()
		return false
	}
}

// bridgeAgent delivers the agent connection to the browser attach waiting on
// sessionID. Browsers attach before the agent learns (via its discovery poll) to
// dial, so the waiter is normally already present; a short retry window absorbs
// the registration race. If no browser is waiting, the agent connection is
// closed.
func (h *terminalHub) bridgeAgent(sessionID string, c *websocketx.Conn) {
	deadline := time.Now().Add(terminalAgentDeliverWindow)
	for {
		h.mu.Lock()
		bridge, ok := h.pending[sessionID]
		if ok {
			delete(h.pending, sessionID)
		}
		h.mu.Unlock()
		if ok {
			select {
			case bridge.agentCh <- c:
				// Handed off; the browser goroutine now owns both connections.
			case <-bridge.done:
				_ = c.Close()
			}
			return
		}
		if !time.Now().Before(deadline) {
			_ = c.Close()
			return
		}
		time.Sleep(terminalAgentDeliverPoll)
	}
}

// bridge splices two terminal connections with a pair of byte pumps. The first
// side to error or hit EOF tears both down. errc is buffered (cap 2) so the
// second goroutine never blocks on send after we have already returned.
//
// Both legs get a per-write deadline (a stalled peer errors its write instead of
// pinning the opposite leg's drain) and a ping/pong keepalive (a half-open
// connection is detected within pongWait and torn down, rather than appearing
// alive forever). When the browser leg ends, the agent leg is closed too, which
// surfaces to the agent as a WS error — the agent keeps its PTY alive and
// redials, so this teardown is a detach, not a kill.
func (h *terminalHub) bridge(b, a *websocketx.Conn) {
	defer b.Close()
	defer a.Close()
	b.SetWriteWait(terminalStreamWriteWait)
	a.SetWriteWait(terminalStreamWriteWait)
	stop := make(chan struct{})
	defer close(stop)
	go keepAliveLeg(b, stop)
	go keepAliveLeg(a, stop)
	errc := make(chan error, 2)
	go func() { _, err := io.Copy(a, b); errc <- err }()
	go func() { _, err := io.Copy(b, a); errc <- err }()
	<-errc
}

// keepAliveLeg pings c every pingInterval and arms a read deadline that the pong
// handler resets, so a peer that stops responding is detected within pongWait
// and its next Read errors (tearing the bridge down). Data frames do not reset
// the deadline; the steady stream of pongs does, so an idle-but-alive leg stays
// open while a dead leg is reaped. Stops when the bridge signals via stop.
func keepAliveLeg(c *websocketx.Conn, stop <-chan struct{}) {
	_ = c.SetReadDeadline(time.Now().Add(terminalStreamPongWait))
	c.SetPongHandler(func(string) error {
		return c.SetReadDeadline(time.Now().Add(terminalStreamPongWait))
	})
	ticker := time.NewTicker(terminalStreamPingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if err := c.WriteControl(websocket.PingMessage, nil, time.Now().Add(terminalStreamWriteWait)); err != nil {
				return
			}
		}
	}
}

// handleAgentTerminalStream upgrades an agent's outbound WebSocket dial and hands
// it to the hub to be spliced with the waiting browser. Auth mirrors
// handleAgentTerminalSessions: node-token bearer auth, plus a session-ownership
// check (sess.NodeID == nodeID) so a leaked session UUID alone cannot bridge a
// foreign node.
func (s *Server) handleAgentTerminalStream(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	if _, ok := s.authenticateNode(r, nodeID, bearerToken(r)); !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	sessionID := strings.TrimSpace(r.URL.Query().Get("session_id"))
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, errors.New("session_id is required"))
		return
	}
	sess, ok := s.terminalBroker.get(sessionID, s.now())
	if !ok || sess.NodeID != nodeID {
		writeError(w, http.StatusNotFound, errors.New("terminal session not found"))
		return
	}
	if terminalClosedStatus(sess.Status) {
		writeError(w, http.StatusNotFound, errors.New("terminal session is closed"))
		return
	}
	s.terminalBroker.markOpen(sessionID, s.now())
	conn, err := terminalUpgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade has already written an error response to the client.
		s.terminalBroker.markClosed(sessionID, model.TerminalFailed, "agent websocket upgrade failed", s.now())
		return
	}
	wsConn := websocketx.NewConn(conn)
	wsConn.SetReadLimit(terminalMaxInputBytes)
	s.terminalHub.bridgeAgent(sessionID, wsConn)
}
