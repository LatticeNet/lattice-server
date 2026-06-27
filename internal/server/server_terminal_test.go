package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestTerminalSessionPollProtocol(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeToken := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	create := doJSON(t, handler, http.MethodPost, "/api/terminal/sessions", `{"node_id":"node-a","shell":"sh","cols":100,"rows":30}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create terminal failed: %d", create.StatusCode)
	}
	var session model.TerminalSession
	if err := json.NewDecoder(create.Body).Decode(&session); err != nil {
		t.Fatal(err)
	}
	if session.Status != model.TerminalPending || session.NodeID != "node-a" || session.Shell != "/bin/sh" {
		t.Fatalf("unexpected session: %+v", session)
	}

	pending := doAgentRaw(t, handler, http.MethodGet, "/api/agent/terminal/sessions?node_id=node-a", "", nodeToken)
	if pending.Code != http.StatusOK {
		t.Fatalf("pending sessions failed: %d", pending.Code)
	}
	var pendingBody struct {
		Sessions []model.TerminalSession `json:"sessions"`
	}
	if err := json.NewDecoder(pending.Body).Decode(&pendingBody); err != nil {
		t.Fatal(err)
	}
	if len(pendingBody.Sessions) != 1 || pendingBody.Sessions[0].ID != session.ID {
		t.Fatalf("pending session missing: %+v", pendingBody.Sessions)
	}

	open := doAgentRaw(t, handler, http.MethodPost, "/api/agent/terminal/sessions/"+session.ID+"/events",
		`{"node_id":"node-a","status":"open","events":[{"kind":"output","data":"ready\r\n"}]}`, nodeToken)
	if open.Code != http.StatusOK {
		t.Fatalf("agent open failed: %d", open.Code)
	}

	input := doJSON(t, handler, http.MethodPost, "/api/terminal/sessions/"+session.ID+"/input", `{"data":"whoami\n"}`, cookies, csrf)
	defer input.Body.Close()
	if input.StatusCode != http.StatusOK {
		t.Fatalf("operator input failed: %d", input.StatusCode)
	}

	inputs := doAgentRaw(t, handler, http.MethodGet, "/api/agent/terminal/sessions/"+session.ID+"/inputs?node_id=node-a&cursor=0", "", nodeToken)
	if inputs.Code != http.StatusOK {
		t.Fatalf("agent input poll failed: %d", inputs.Code)
	}
	var inputsBody struct {
		Inputs []model.TerminalInput `json:"inputs"`
	}
	if err := json.NewDecoder(inputs.Body).Decode(&inputsBody); err != nil {
		t.Fatal(err)
	}
	if len(inputsBody.Inputs) != 1 || inputsBody.Inputs[0].Data != "whoami\n" {
		t.Fatalf("input not delivered: %+v", inputsBody.Inputs)
	}

	output := doAgentRaw(t, handler, http.MethodPost, "/api/agent/terminal/sessions/"+session.ID+"/events",
		`{"node_id":"node-a","events":[{"kind":"output","data":"root\r\n"}]}`, nodeToken)
	if output.Code != http.StatusOK {
		t.Fatalf("agent output failed: %d", output.Code)
	}

	events := doJSON(t, handler, http.MethodGet, "/api/terminal/sessions/"+session.ID+"/events?cursor=0", "", cookies, "")
	defer events.Body.Close()
	if events.StatusCode != http.StatusOK {
		t.Fatalf("operator event poll failed: %d", events.StatusCode)
	}
	var eventsBody struct {
		Session model.TerminalSession `json:"session"`
		Events  []model.TerminalEvent `json:"events"`
	}
	if err := json.NewDecoder(events.Body).Decode(&eventsBody); err != nil {
		t.Fatal(err)
	}
	if eventsBody.Session.Status != model.TerminalOpen || len(eventsBody.Events) != 2 || eventsBody.Events[1].Data != "root\r\n" {
		t.Fatalf("events not visible: %+v", eventsBody)
	}
}

func TestTerminalRequiresTerminalScope(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	token := createPAT(t, handler, cookies, csrf, []string{"node:read"}, []string{"node-a"})
	denied := doBearerJSON(t, handler, http.MethodPost, "/api/terminal/sessions", `{"node_id":"node-a"}`, token)
	defer denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("expected terminal scope denial, got %d", denied.StatusCode)
	}
}

func TestTerminalCloseMarksOpenSessionClosedAndDeliversCloseInput(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeToken := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	create := doJSON(t, handler, http.MethodPost, "/api/terminal/sessions", `{"node_id":"node-a","shell":"sh"}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create terminal failed: %d", create.StatusCode)
	}
	var session model.TerminalSession
	if err := json.NewDecoder(create.Body).Decode(&session); err != nil {
		t.Fatal(err)
	}

	open := doAgentRaw(t, handler, http.MethodPost, "/api/agent/terminal/sessions/"+session.ID+"/events",
		`{"node_id":"node-a","status":"open"}`, nodeToken)
	if open.Code != http.StatusOK {
		t.Fatalf("agent open failed: %d", open.Code)
	}

	closeResp := doJSON(t, handler, http.MethodPost, "/api/terminal/sessions/"+session.ID+"/close", `{}`, cookies, csrf)
	defer closeResp.Body.Close()
	if closeResp.StatusCode != http.StatusOK {
		t.Fatalf("operator close failed: %d", closeResp.StatusCode)
	}
	var closed model.TerminalSession
	if err := json.NewDecoder(closeResp.Body).Decode(&closed); err != nil {
		t.Fatal(err)
	}
	if closed.Status != model.TerminalClosed || closed.ClosedAt.IsZero() {
		t.Fatalf("close should immediately mark session closed: %+v", closed)
	}

	inputs := doAgentRaw(t, handler, http.MethodGet, "/api/agent/terminal/sessions/"+session.ID+"/inputs?node_id=node-a&cursor=0", "", nodeToken)
	if inputs.Code != http.StatusOK {
		t.Fatalf("agent input poll failed: %d", inputs.Code)
	}
	var inputsBody struct {
		Inputs []model.TerminalInput `json:"inputs"`
	}
	if err := json.NewDecoder(inputs.Body).Decode(&inputsBody); err != nil {
		t.Fatal(err)
	}
	if len(inputsBody.Inputs) != 1 || inputsBody.Inputs[0].Kind != "close" {
		t.Fatalf("close input not delivered to agent: %+v", inputsBody.Inputs)
	}
}

func TestTerminalBrokerLimitsAndPrunesSessions(t *testing.T) {
	broker := newTerminalBroker()
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)

	for i := 0; i < terminalMaxActiveSessionsPerNode; i++ {
		if _, err := broker.create("node-a", "admin", "", "sh", 0, 0, now); err != nil {
			t.Fatalf("create active session %d failed: %v", i, err)
		}
	}
	if _, err := broker.create("node-a", "admin", "", "sh", 0, 0, now); err == nil {
		t.Fatal("expected per-node active terminal limit")
	}
	if sessions := broker.pendingForAgent("node-a", now.Add(terminalPendingTTL+time.Second)); len(sessions) != 0 {
		t.Fatalf("expired pending sessions should not be offered to agent: %+v", sessions)
	}
	if sessions := broker.list(now.Add(terminalPendingTTL + time.Second)); len(sessions) != terminalMaxActiveSessionsPerNode {
		t.Fatalf("expired sessions should remain visible until closed TTL, got %d", len(sessions))
	}
	if sessions := broker.list(now.Add(terminalPendingTTL + terminalClosedTTL + time.Second)); len(sessions) != 0 {
		t.Fatalf("closed TTL should prune expired sessions, got %+v", sessions)
	}
	if _, err := broker.create("node-a", "admin", "", "sh", 0, 0, now.Add(terminalPendingTTL+terminalClosedTTL+2*time.Second)); err != nil {
		t.Fatalf("create after prune failed: %v", err)
	}
}

// TestTerminalBrokerDetachGraceReaped covers the streaming detach window: when a
// live bridge ends with the session still open (the viewer dropped), the session
// is kept alive for the detach grace so a reattach can resume the PTY, then
// reaped if no reattach arrives.
func TestTerminalBrokerDetachGraceReaped(t *testing.T) {
	broker := newTerminalBroker()
	t0 := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	sess, err := broker.create("node-a", "admin", "", "sh", 0, 0, t0)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	broker.markOpen(sess.ID, t0)      // agent dialed in
	broker.clearDetached(sess.ID, t0) // browser bridged
	if st := broker.sessions[sess.ID]; !st.bridged || !st.detachedAt.IsZero() {
		t.Fatalf("after clearDetached: bridged=%v detachedAt=%v", st.bridged, st.detachedAt)
	}

	dropAt := t0.Add(time.Minute)
	broker.markDetached(sess.ID, dropAt) // browser WebSocket dropped
	if st := broker.sessions[sess.ID]; st.bridged || st.detachedAt.IsZero() {
		t.Fatalf("after markDetached: bridged=%v detachedAt=%v", st.bridged, st.detachedAt)
	}

	// Within the grace window the kept-alive session must survive for a reattach.
	withinGrace := dropAt.Add(terminalDetachGrace / 2)
	broker.reap(withinGrace)
	if s, _ := broker.get(sess.ID, withinGrace); s.Status != model.TerminalOpen {
		t.Fatalf("within detach grace should stay open, got %s", s.Status)
	}

	// Past the grace window with no reattach, the reaper closes it.
	pastGrace := dropAt.Add(terminalDetachGrace + 2*time.Second)
	broker.reap(pastGrace)
	if s, _ := broker.get(sess.ID, pastGrace); s.Status != model.TerminalFailed {
		t.Fatalf("past detach grace should fail the session, got %s", s.Status)
	}
}

// TestTerminalBrokerBridgedExemptFromIdle covers the liveness fix: a session with
// a live bridge carries its bytes over the WebSocket relay (which never touches
// the broker), so it must be exempt from the idle TTL — only the absolute
// max-life cap may close it.
func TestTerminalBrokerBridgedExemptFromIdle(t *testing.T) {
	broker := newTerminalBroker()
	t0 := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	sess, err := broker.create("node-a", "admin", "", "sh", 0, 0, t0)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	broker.markOpen(sess.ID, t0)
	broker.clearDetached(sess.ID, t0) // live bridge, viewer present

	// Far past the idle TTL: a bridged session must NOT be idle-reaped.
	late := t0.Add(terminalIdleTTL + time.Hour)
	broker.reap(late)
	if s, _ := broker.get(sess.ID, late); s.Status != model.TerminalOpen {
		t.Fatalf("bridged session must be exempt from idle TTL, got %s", s.Status)
	}

	// The absolute max-life cap still applies even to a bridged session.
	beyond := t0.Add(terminalMaxLifeTTL + time.Minute)
	broker.reap(beyond)
	if s, _ := broker.get(sess.ID, beyond); s.Status != model.TerminalFailed {
		t.Fatalf("max-life cap should fail even a bridged session, got %s", s.Status)
	}
}
