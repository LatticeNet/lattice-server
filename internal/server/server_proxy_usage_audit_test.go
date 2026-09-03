package server

import (
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Every node posts usage every ten seconds. Auditing each report wrote about
// 285,000 events a day across the fleet, so 95 percent of the audit log was
// heartbeats and every query hit its scan cap inside a day, which put an
// incident from the previous week out of reach. A heartbeat is not an event.
func TestProxyUsageAuditSkipsUnchangedHeartbeats(t *testing.T) {
	s := &Server{}
	base := time.Date(2026, 9, 3, 6, 0, 0, 0, time.UTC)
	meta := map[string]string{"collector_status": "ok", "collector_source": "singbox-stats-api"}

	if !s.shouldAuditProxyUsage("node-a", meta, base) {
		t.Fatal("the first report from a node must be audited")
	}
	for i := 1; i <= 60; i++ {
		if s.shouldAuditProxyUsage("node-a", meta, base.Add(time.Duration(i)*10*time.Second)) {
			t.Fatalf("an unchanged report %d intervals later was audited again", i)
		}
	}
}

// What an operator would actually want an event for still produces one
// immediately, without waiting out the interval.
func TestProxyUsageAuditRecordsRealChanges(t *testing.T) {
	base := time.Date(2026, 9, 3, 6, 0, 0, 0, time.UTC)
	steady := map[string]string{"collector_status": "ok"}

	for name, changed := range map[string]map[string]string{
		"the collector started failing": {"collector_status": "error"},
		"stats were switched off":       {"collector_status": "stats_off"},
		"a profile was registered":      {"collector_status": "ok", "profile_registered": "true"},
		"counters were dropped":         {"collector_status": "ok", "ignored_counters": "12"},
		"the collector source changed":  {"collector_status": "ok", "collector_source": "file"},
	} {
		s := &Server{}
		if !s.shouldAuditProxyUsage("node-a", steady, base) {
			t.Fatalf("%s: first report must be audited", name)
		}
		if !s.shouldAuditProxyUsage("node-a", changed, base.Add(10*time.Second)) {
			t.Fatalf("%s: a changed report must be audited rather than suppressed", name)
		}
	}
}

// A node reporting the same thing for a long time still leaves a trace, so
// "was this node reporting" stays answerable.
func TestProxyUsageAuditRecordsOncePerInterval(t *testing.T) {
	s := &Server{}
	base := time.Date(2026, 9, 3, 6, 0, 0, 0, time.UTC)
	meta := map[string]string{"collector_status": "ok"}

	if !s.shouldAuditProxyUsage("node-a", meta, base) {
		t.Fatal("first report must be audited")
	}
	if s.shouldAuditProxyUsage("node-a", meta, base.Add(proxyUsageAuditInterval-time.Second)) {
		t.Fatal("audited again before the interval elapsed")
	}
	if !s.shouldAuditProxyUsage("node-a", meta, base.Add(proxyUsageAuditInterval)) {
		t.Fatal("a node reporting steadily must still leave a trace once per interval")
	}
}

// Nodes are tracked separately: one node's heartbeat must not silence another.
func TestProxyUsageAuditIsPerNode(t *testing.T) {
	s := &Server{}
	base := time.Date(2026, 9, 3, 6, 0, 0, 0, time.UTC)
	meta := map[string]string{"collector_status": "ok"}

	if !s.shouldAuditProxyUsage("node-a", meta, base) {
		t.Fatal("node-a first report must be audited")
	}
	if !s.shouldAuditProxyUsage("node-b", meta, base) {
		t.Fatal("node-b is a different node and its first report must be audited")
	}
}

// The sing-box discovery gate was written to stop exactly this flood and did
// not work: Runtime.ProbedAt moves on every probe, so the fingerprint differed
// every time and no report was ever suppressed. 25 nodes reporting every ten
// seconds wrote 217,000 audit events a day, two thirds of the entire log.
func TestSingBoxDiscoveryFingerprintIgnoresTheProbeClock(t *testing.T) {
	probedAt := time.Date(2026, 9, 3, 6, 0, 0, 0, time.UTC)
	inv := func(probe time.Time) model.SingBoxInventory {
		return model.SingBoxInventory{
			NodeID: "node-a",
			At:     probe,
			Nodes:  []model.SingBoxNode{{Name: "line-a", Protocol: "vless", Port: "443"}},
			Runtime: &model.SingBoxRuntime{
				Running: true, PID: 1234, ActiveState: "active", ProbedAt: probe,
			},
		}
	}

	first := inv(probedAt)
	second := inv(probedAt.Add(10 * time.Second))
	if singBoxDiscoveryFingerprint(first) != singBoxDiscoveryFingerprint(second) {
		t.Fatal("two identical inventories probed ten seconds apart hashed differently, which defeats the gate")
	}
	if first.Runtime.ProbedAt != probedAt {
		t.Fatal("fingerprinting mutated the caller's runtime, which is shared state")
	}

	restarted := inv(probedAt.Add(10 * time.Second))
	restarted.Runtime.RestartCount = 1
	if singBoxDiscoveryFingerprint(first) == singBoxDiscoveryFingerprint(restarted) {
		t.Fatal("a restart count that moved is a real change and must still be audited")
	}

	failing := inv(probedAt.Add(10 * time.Second))
	failing.Runtime.ProbeError = "connection refused"
	if singBoxDiscoveryFingerprint(first) == singBoxDiscoveryFingerprint(failing) {
		t.Fatal("a probe error is a state, not a clock, and must still be audited")
	}
}
