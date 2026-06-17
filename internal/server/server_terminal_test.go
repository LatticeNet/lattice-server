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
