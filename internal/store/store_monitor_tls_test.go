package store

import (
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// A tls monitor is evaluated by the server. Whatever a stored record claims
// about node assignment, an agent must never be handed one to probe.
func TestMonitorsForNodeExcludesTLS(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertMonitor(model.Monitor{ID: "mon-tls", Name: "cert", Type: model.MonitorTypeTLS, Target: "dns.example.org:8443", NodeIDs: []string{"n1"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertMonitor(model.Monitor{ID: "mon-tcp", Name: "port", Type: model.MonitorTypeTCP, Target: "dns.example.org:53", NodeIDs: []string{"n1"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	got := s.MonitorsForNode("n1")
	if len(got) != 1 || got[0].ID != "mon-tcp" {
		t.Fatalf("agent assignment = %+v, want only the tcp monitor", got)
	}
}
