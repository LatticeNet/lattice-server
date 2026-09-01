package server

import (
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// TestAuditMarkersScanWindowAndFilters pins the bounded-scan rewrite: only
// events inside [since, until] with apply actions on visible nodes become
// markers, newest first, and history below the window is never touched.
func TestAuditMarkersScanWindowAndFilters(t *testing.T) {
	s, st := newShareTestServer(t)
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	append_ := func(at time.Time, action, node string) {
		t.Helper()
		if err := st.AppendAudit(model.AuditEvent{
			ID: "audit-" + at.Format("150405") + action, At: at,
			Action: action, Decision: "allow", NodeID: node, CorrelationID: "corr-" + action,
		}); err != nil {
			t.Fatal(err)
		}
	}
	append_(base.Add(-3*time.Hour), "proxy.apply", "node-a") // below the window
	append_(base.Add(-30*time.Minute), "proxy.apply", "node-a")
	append_(base.Add(-20*time.Minute), "task.create", "node-a")   // not an apply
	append_(base.Add(-10*time.Minute), "network.apply", "node-b") // not visible
	append_(base.Add(-5*time.Minute), "linechain.apply", "node-a")
	append_(base.Add(time.Hour), "proxy.apply", "node-a") // above the window

	got := s.auditMarkers(base.Add(-time.Hour), base, map[string]bool{"node-a": true})
	if len(got) != 2 {
		t.Fatalf("markers = %d want 2: %+v", len(got), got)
	}
	// Newest first, matching the descending scan.
	if got[0].Detail != "linechain.apply (allow)" || got[1].Detail != "proxy.apply (allow)" {
		t.Fatalf("order/content wrong: %+v", got)
	}
	if got[0].CorrelationID == "" {
		t.Fatalf("correlation id lost: %+v", got[0])
	}
}
