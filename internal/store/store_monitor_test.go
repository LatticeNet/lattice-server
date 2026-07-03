package store

import (
	"os"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
)

func TestAddMonitorResultThrottlesStableResultPersistence(t *testing.T) {
	path := t.TempDir() + "/state.json"
	s, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}

	first := model.MonitorResult{MonitorID: "mon-a", NodeID: "node-a", At: time.Unix(100, 0).UTC(), Success: true, LatencyMs: 12}
	if err := s.AddMonitorResult(first); err != nil {
		t.Fatalf("first monitor result: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	second := model.MonitorResult{MonitorID: "mon-a", NodeID: "node-a", At: time.Unix(110, 0).UTC(), Success: true, LatencyMs: 15}
	if err := s.AddMonitorResult(second); err != nil {
		t.Fatalf("second monitor result: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("stable monitor result rewrote persisted state")
	}
	latest, ok := s.LastMonitorResultForNode("mon-a", "node-a")
	if !ok {
		t.Fatal("missing latest in-memory monitor result")
	}
	if !latest.At.Equal(second.At) || latest.LatencyMs != second.LatencyMs {
		t.Fatalf("in-memory monitor result not refreshed: %+v", latest)
	}
}

func TestAddMonitorResultPersistsStateTransitionImmediately(t *testing.T) {
	path := t.TempDir() + "/state.json"
	s, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddMonitorResult(model.MonitorResult{
		MonitorID: "mon-a",
		NodeID:    "node-a",
		At:        time.Unix(100, 0).UTC(),
		Success:   true,
		LatencyMs: 12,
	}); err != nil {
		t.Fatalf("first monitor result: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	failed := model.MonitorResult{MonitorID: "mon-a", NodeID: "node-a", At: time.Unix(110, 0).UTC(), Success: false, Error: "timeout"}
	if err := s.AddMonitorResult(failed); err != nil {
		t.Fatalf("transition monitor result: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) == string(before) {
		t.Fatalf("monitor result transition was not persisted")
	}
	reopened, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	latest, ok := reopened.LastMonitorResultForNode("mon-a", "node-a")
	if !ok {
		t.Fatal("missing durable monitor result after reopen")
	}
	if latest.Success || latest.Error != "timeout" {
		t.Fatalf("transition result not durable: %+v", latest)
	}
}
