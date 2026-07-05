package server

import (
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestAgentControlHubNotifiesTerminalOpen(t *testing.T) {
	hub := newAgentControlHub()
	conn := hub.register("node-a")
	defer hub.unregister(conn)

	session := model.TerminalSession{ID: "term-a", NodeID: "node-a"}
	if !hub.notifyTerminalOpen(session) {
		t.Fatal("expected control notification to be delivered")
	}

	select {
	case msg := <-conn.send:
		if msg.Type != "terminal.open" || msg.Session.ID != session.ID || msg.Session.NodeID != session.NodeID {
			t.Fatalf("unexpected control message: %+v", msg)
		}
	default:
		t.Fatal("missing control message")
	}
}

func TestAgentControlHubMissFallsBackToPoll(t *testing.T) {
	hub := newAgentControlHub()
	if hub.notifyTerminalOpen(model.TerminalSession{ID: "term-a", NodeID: "node-a"}) {
		t.Fatal("notify without a control connection should report no delivery")
	}
}
