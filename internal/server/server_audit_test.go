package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestAuditDefaultResponseRemainsArray(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, _ := loginSession(t, handler)
	if err := st.AppendAudit(model.AuditEvent{
		ID:       "audit_default_array",
		At:       time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC),
		Action:   "audit.default",
		Decision: "allow",
	}); err != nil {
		t.Fatal(err)
	}

	res := doJSON(t, handler, http.MethodGet, "/api/audit", "", cookies, "")
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("audit list failed: %d", res.StatusCode)
	}
	var events []model.AuditEvent
	if err := json.NewDecoder(res.Body).Decode(&events); err != nil {
		t.Fatalf("default audit response must remain an array: %v", err)
	}
	for _, ev := range events {
		if ev.ID == "audit_default_array" {
			return
		}
	}
	t.Fatalf("default audit response missing inserted event: %+v", events)
}

func TestAuditQueryFiltersAndPaginates(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, _ := loginSession(t, handler)
	base := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	events := []model.AuditEvent{
		{ID: "audit_old_deny", At: base.Add(time.Minute), NodeID: "node-a", Action: "task.result", Decision: "deny", CorrelationID: "req-old"},
		{ID: "audit_new_deny", At: base.Add(2 * time.Minute), NodeID: "node-a", Action: "task.result", Decision: "deny", CorrelationID: "req-new"},
		{ID: "audit_allow", At: base.Add(3 * time.Minute), NodeID: "node-a", Action: "task.result", Decision: "allow", CorrelationID: "req-allow"},
		{ID: "audit_other_node", At: base.Add(4 * time.Minute), NodeID: "node-b", Action: "task.result", Decision: "deny", CorrelationID: "req-other"},
	}
	for _, ev := range events {
		if err := st.AppendAudit(ev); err != nil {
			t.Fatal(err)
		}
	}

	res := doJSON(t, handler, http.MethodGet,
		"/api/audit?action=task.result&decision=deny&node_id=node-a&limit=1&offset=1", "", cookies, "")
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("audit query failed: %d", res.StatusCode)
	}
	var out struct {
		Events []model.AuditEvent `json:"events"`
		Total  int                `json:"total"`
		Limit  int                `json:"limit"`
		Offset int                `json:"offset"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 2 || out.Limit != 1 || out.Offset != 1 {
		t.Fatalf("unexpected page metadata: %+v", out)
	}
	if len(out.Events) != 1 || out.Events[0].ID != "audit_old_deny" {
		t.Fatalf("expected second newest matching deny event, got %+v", out.Events)
	}
}

func TestAuditQueryFiltersByCorrelationID(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, _ := loginSession(t, handler)
	base := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	for _, ev := range []model.AuditEvent{
		{ID: "audit_req_a", At: base, NodeID: "node-a", Action: "task.result", Decision: "deny", CorrelationID: "req-a"},
		{ID: "audit_req_b", At: base.Add(time.Minute), NodeID: "node-a", Action: "task.result", Decision: "deny", CorrelationID: "req-b"},
	} {
		if err := st.AppendAudit(ev); err != nil {
			t.Fatal(err)
		}
	}

	res := doJSON(t, handler, http.MethodGet, "/api/audit?correlation_id=req-a", "", cookies, "")
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("audit correlation query failed: %d", res.StatusCode)
	}
	var out struct {
		Events []model.AuditEvent `json:"events"`
		Total  int                `json:"total"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 1 || len(out.Events) != 1 || out.Events[0].ID != "audit_req_a" {
		t.Fatalf("expected exact correlation match, got %+v", out)
	}
}

func TestAuditQueryRejectsInvalidPagination(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, _ := loginSession(t, handler)
	for _, path := range []string{"/api/audit?limit=0", "/api/audit?limit=501", "/api/audit?offset=-1"} {
		res := doJSON(t, handler, http.MethodGet, path, "", cookies, "")
		res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s should reject invalid pagination, got %d", path, res.StatusCode)
		}
	}
}
