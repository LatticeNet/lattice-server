package server

import (
	"testing"
	"time"
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
