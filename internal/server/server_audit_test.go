package server

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
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

func TestAuditVerifyReportsAnchorStatus(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	cookies, _ := loginSession(t, handler)
	if err := st.AppendAudit(model.AuditEvent{
		ID:       "audit_anchor_status",
		At:       time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC),
		Action:   "audit.anchor_status",
		Decision: "allow",
	}); err != nil {
		t.Fatal(err)
	}

	res := doJSON(t, handler, http.MethodGet, "/api/audit/verify", "", cookies, "")
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("audit verify failed: %d", res.StatusCode)
	}
	var out struct {
		Enabled     bool   `json:"enabled"`
		OK          bool   `json:"ok"`
		Count       int    `json:"count"`
		Head        string `json:"head"`
		Anchored    bool   `json:"anchored"`
		AnchorCount int    `json:"anchor_count"`
		AnchorHead  string `json:"anchor_head"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.Enabled || !out.OK || !out.Anchored || out.Count == 0 {
		t.Fatalf("unexpected verify response: %+v", out)
	}
	if out.AnchorCount != out.Count || out.AnchorHead == "" || out.AnchorHead != out.Head {
		t.Fatalf("anchor fields do not match verified head: %+v", out)
	}
}

func TestAuditReadTokenIsServerAllowlistScoped(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	base := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	for _, ev := range []model.AuditEvent{
		{ID: "audit_node_a", At: base, NodeID: "node-a", Action: "task.result", Decision: "allow"},
		{ID: "audit_node_b", At: base.Add(time.Minute), NodeID: "node-b", Action: "task.result", Decision: "allow"},
		{ID: "audit_global", At: base.Add(2 * time.Minute), Action: "token.create", Decision: "allow"},
	} {
		if err := st.AppendAudit(ev); err != nil {
			t.Fatal(err)
		}
	}
	token := createPAT(t, handler, cookies, csrf, []string{"audit:read"}, []string{"node-a"})

	defaultRes := doBearerJSON(t, handler, http.MethodGet, "/api/audit", "", token)
	defer defaultRes.Body.Close()
	if defaultRes.StatusCode != http.StatusOK {
		t.Fatalf("default audit list failed: %d", defaultRes.StatusCode)
	}
	var defaultEvents []model.AuditEvent
	if err := json.NewDecoder(defaultRes.Body).Decode(&defaultEvents); err != nil {
		t.Fatal(err)
	}
	if len(defaultEvents) != 1 || defaultEvents[0].ID != "audit_node_a" {
		t.Fatalf("restricted default audit events = %+v, want only node-a", defaultEvents)
	}

	queryRes := doBearerJSON(t, handler, http.MethodGet, "/api/audit?action=task.result&limit=10", "", token)
	defer queryRes.Body.Close()
	if queryRes.StatusCode != http.StatusOK {
		t.Fatalf("audit query failed: %d", queryRes.StatusCode)
	}
	var out struct {
		Events []model.AuditEvent `json:"events"`
		Total  int                `json:"total"`
	}
	if err := json.NewDecoder(queryRes.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 1 || len(out.Events) != 1 || out.Events[0].ID != "audit_node_a" {
		t.Fatalf("restricted query audit events = %+v total=%d, want only node-a", out.Events, out.Total)
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
