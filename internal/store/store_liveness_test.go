package store

import (
	"os"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
)

func TestMarkStaleNodesOffline(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	seed := func(id string, online bool, lastSeen time.Time) {
		if err := s.UpsertNode(model.Node{ID: id, Name: id, Online: online, LastSeen: lastSeen}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	seed("fresh", true, now.Add(-5*time.Second)) // recent beat -> stays online
	seed("stale", true, now.Add(-5*time.Minute)) // stale beat -> flips offline
	seed("never", false, time.Time{})            // never online -> untouched
	seed("down", false, now.Add(-9*time.Minute)) // already offline -> not a transition

	flipped, err := s.MarkStaleNodesOffline(90*time.Second, now)
	if err != nil {
		t.Fatalf("MarkStaleNodesOffline: %v", err)
	}
	if len(flipped) != 1 || flipped[0].ID != "stale" {
		t.Fatalf("expected only 'stale' to transition, got %+v", flipped)
	}

	want := map[string]bool{"fresh": true, "stale": false, "never": false, "down": false}
	for id, online := range want {
		n, ok := s.Node(id)
		if !ok {
			t.Fatalf("node %s missing", id)
		}
		if n.Online != online {
			t.Fatalf("node %s online=%v, want %v", id, n.Online, online)
		}
	}

	// Idempotent: a second sweep at the same instant flips nothing new.
	flipped2, err := s.MarkStaleNodesOffline(90*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(flipped2) != 0 {
		t.Fatalf("second sweep should be a no-op, got %+v", flipped2)
	}
}

func TestTouchNodeTokenRecordsUseAndThrottles(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_700_000_000, 0).UTC()
	if err := s.UpsertNode(model.Node{ID: "node-a", Name: "Node A"}); err != nil {
		t.Fatal(err)
	}

	touched, err := s.TouchNodeToken("node-a", base, time.Minute)
	if err != nil || !touched {
		t.Fatalf("first touch: touched=%v err=%v", touched, err)
	}
	n, ok := s.Node("node-a")
	if !ok || !n.TokenLastUsedAt.Equal(base) {
		t.Fatalf("first touch not stored: ok=%v node=%+v", ok, n)
	}

	touched, err = s.TouchNodeToken("node-a", base.Add(30*time.Second), time.Minute)
	if err != nil || touched {
		t.Fatalf("throttled touch: touched=%v err=%v", touched, err)
	}
	n, _ = s.Node("node-a")
	if !n.TokenLastUsedAt.Equal(base) {
		t.Fatalf("throttled touch changed timestamp: %s", n.TokenLastUsedAt)
	}

	next := base.Add(61 * time.Second)
	touched, err = s.TouchNodeToken("node-a", next, time.Minute)
	if err != nil || !touched {
		t.Fatalf("second window touch: touched=%v err=%v", touched, err)
	}
	n, _ = s.Node("node-a")
	if !n.TokenLastUsedAt.Equal(next) {
		t.Fatalf("second window touch not stored: %s", n.TokenLastUsedAt)
	}

	touched, err = s.TouchNodeToken("missing", next, time.Minute)
	if err != nil || touched {
		t.Fatalf("missing node touch: touched=%v err=%v", touched, err)
	}

	rotated, err := s.RotateNodeToken("node-a", "new-token-hash")
	if err != nil || !rotated {
		t.Fatalf("rotate token: rotated=%v err=%v", rotated, err)
	}
	n, _ = s.Node("node-a")
	if !n.TokenLastUsedAt.IsZero() {
		t.Fatalf("token rotation must clear stale last-used timestamp: %s", n.TokenLastUsedAt)
	}
}

func TestUpdateMetricsThrottlesPureHeartbeatPersistence(t *testing.T) {
	path := t.TempDir() + "/state.json"
	s, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNode(model.Node{ID: "node-a", Name: "Node A"}); err != nil {
		t.Fatal(err)
	}

	first := model.Metrics{CPUPercent: 10, Load1: 0.25, NetRxBytes: 100, CollectedAt: time.Unix(100, 0).UTC()}
	if err := s.UpdateMetrics("node-a", first, "0.2.7", "203.0.113.10", "", "10.0.0.10", "", "10.44.0.10", model.HostFacts{}); err != nil {
		t.Fatalf("first metrics update: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	n, ok := s.Node("node-a")
	if !ok {
		t.Fatal("node missing after first metrics update")
	}
	firstSeen := n.LastSeen

	time.Sleep(time.Millisecond)
	second := model.Metrics{CPUPercent: 42, Load1: 1.5, NetRxBytes: 250, CollectedAt: time.Unix(110, 0).UTC()}
	if err := s.UpdateMetrics("node-a", second, "0.2.7", "203.0.113.10", "", "10.0.0.10", "", "10.44.0.10", model.HostFacts{}); err != nil {
		t.Fatalf("second metrics update: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("pure metrics heartbeat rewrote persisted state")
	}
	n, ok = s.Node("node-a")
	if !ok {
		t.Fatal("node missing after second metrics update")
	}
	if n.Metrics.CPUPercent != second.CPUPercent || n.Metrics.NetRxBytes != second.NetRxBytes {
		t.Fatalf("in-memory metrics not refreshed: %+v", n.Metrics)
	}
	if !n.LastSeen.After(firstSeen) {
		t.Fatalf("in-memory last_seen did not advance: first=%s second=%s", firstSeen, n.LastSeen)
	}
}

func TestUpdateMetricsPersistsSlowChangingAgentFieldsImmediately(t *testing.T) {
	path := t.TempDir() + "/state.json"
	s, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNode(model.Node{ID: "node-a", Name: "Node A"}); err != nil {
		t.Fatal(err)
	}
	metrics := model.Metrics{CPUPercent: 10, CollectedAt: time.Unix(100, 0).UTC()}
	if err := s.UpdateMetrics("node-a", metrics, "0.2.7", "203.0.113.10", "", "", "", "", model.HostFacts{}); err != nil {
		t.Fatalf("first metrics update: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.UpdateMetrics("node-a", metrics, "0.2.8", "203.0.113.11", "", "", "", "", model.HostFacts{}); err != nil {
		t.Fatalf("slow field metrics update: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) == string(before) {
		t.Fatalf("agent version/public IP change was not persisted")
	}
	reopened, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	n, ok := reopened.Node("node-a")
	if !ok {
		t.Fatal("node missing after reopen")
	}
	if n.AgentVersion != "0.2.8" || n.PublicIP != "203.0.113.11" {
		t.Fatalf("slow-changing fields not durable: version=%q public_ip=%q", n.AgentVersion, n.PublicIP)
	}
}

func TestUpdateMetricsIgnoresVolatileHostFactsForDurableWrites(t *testing.T) {
	path := t.TempDir() + "/state.json"
	s, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNode(model.Node{ID: "node-a", Name: "Node A"}); err != nil {
		t.Fatal(err)
	}
	metrics := model.Metrics{CPUPercent: 10, CollectedAt: time.Unix(100, 0).UTC()}
	boot := time.Unix(1_699_999_000, 123_000_000).UTC()
	firstFacts := model.HostFacts{
		Hostname:      "node-a",
		OS:            "linux",
		KernelVersion: "6.1.0",
		BootTime:      boot,
		ReportedAt:    time.Unix(1_700_000_000, 0).UTC(),
	}
	if err := s.UpdateMetrics("node-a", metrics, "0.2.7", "203.0.113.10", "", "", "", "", firstFacts); err != nil {
		t.Fatalf("first metrics update: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	secondFacts := firstFacts
	secondFacts.ReportedAt = secondFacts.ReportedAt.Add(30 * time.Second)
	secondFacts.BootTime = secondFacts.BootTime.Add(30 * time.Second)
	if err := s.UpdateMetrics("node-a", metrics, "0.2.7", "203.0.113.10", "", "", "", "", secondFacts); err != nil {
		t.Fatalf("volatile host facts metrics update: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("volatile host facts rewrote persisted state")
	}
	n, ok := s.Node("node-a")
	if !ok {
		t.Fatal("node missing after second metrics update")
	}
	if !n.HostFacts.ReportedAt.Equal(secondFacts.ReportedAt) || !n.HostFacts.BootTime.Equal(secondFacts.BootTime) {
		t.Fatalf("in-memory host facts not refreshed: %+v", n.HostFacts)
	}

	changedFacts := secondFacts
	changedFacts.KernelVersion = "6.8.0"
	if err := s.UpdateMetrics("node-a", metrics, "0.2.7", "203.0.113.10", "", "", "", "", changedFacts); err != nil {
		t.Fatalf("durable host facts metrics update: %v", err)
	}
	changed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(changed) == string(before) {
		t.Fatalf("durable host fact change was not persisted")
	}
}
