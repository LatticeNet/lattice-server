package server

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// queryAuditEvents runs a query over events already in hand. Production pages
// through the store's cursor; this keeps the shape for callers and tests that
// hold a slice. The slice is walked newest-first, the order collectAuditPage
// requires for its at_from short-circuit to be exact.
func queryAuditEvents(r *http.Request, events []model.AuditEvent) (auditQueryResponse, error) {
	q, err := parseAuditQuery(r)
	if err != nil {
		return auditQueryResponse{}, err
	}
	ordered := append([]model.AuditEvent(nil), events...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].At.After(ordered[j].At) })
	scan := func(visit func(model.AuditEvent) bool) error {
		for _, ev := range ordered {
			if !visit(ev) {
				return nil
			}
		}
		return nil
	}
	return collectAuditPage(scan, func(model.AuditEvent) bool { return true }, q)
}

func auditQuery(t *testing.T, rawQuery string, events []model.AuditEvent) auditQueryResponse {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/audit?"+rawQuery, nil)
	out, err := queryAuditEvents(r, events)
	if err != nil {
		t.Fatalf("queryAuditEvents(%q): %v", rawQuery, err)
	}
	return out
}

func TestAuditQueryTextAndPrefixAndTime(t *testing.T) {
	base := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	events := []model.AuditEvent{
		{ID: "1", At: base, Action: "task.create", Decision: "allow", ActorID: "alice", Reason: "deploy nginx"},
		{ID: "2", At: base.Add(time.Hour), Action: "task.cancel", Decision: "deny", Scope: "task:run", Metadata: map[string]string{"node_id": "hkg-1"}},
		{ID: "3", At: base.Add(2 * time.Hour), Action: "node.geo.resolve", Decision: "observe", ActorID: "bob"},
	}

	// Free-text "q" hits reason text.
	if got := auditQuery(t, "q=nginx", events); got.Total != 1 || got.Events[0].ID != "1" {
		t.Fatalf("q=nginx: total=%d ids=%v, want only event 1", got.Total, ids(got.Events))
	}
	// Free-text "q" hits metadata values.
	if got := auditQuery(t, "q=hkg", events); got.Total != 1 || got.Events[0].ID != "2" {
		t.Fatalf("q=hkg: total=%d, want only event 2", got.Total)
	}
	// Prefix action match returns both task.* events.
	if got := auditQuery(t, "action=task.%2A", events); got.Total != 2 { // %2A == *
		t.Fatalf("action=task.*: total=%d, want 2", got.Total)
	}
	// Exact action still works.
	if got := auditQuery(t, "action=task.create", events); got.Total != 1 || got.Events[0].ID != "1" {
		t.Fatalf("action=task.create: total=%d, want 1", got.Total)
	}
	// Time range excludes the earliest and latest.
	from := base.Add(30 * time.Minute).Format(time.RFC3339)
	to := base.Add(90 * time.Minute).Format(time.RFC3339)
	if got := auditQuery(t, "at_from="+from+"&at_to="+to, events); got.Total != 1 || got.Events[0].ID != "2" {
		t.Fatalf("time range: total=%d, want only event 2", got.Total)
	}
	// Bad time is a clear 400-style error.
	r := httptest.NewRequest("GET", "/api/audit?at_from=nonsense", nil)
	if _, err := queryAuditEvents(r, events); err == nil {
		t.Fatal("expected error for malformed at_from")
	}
}

func ids(evs []model.AuditEvent) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.ID
	}
	return out
}
