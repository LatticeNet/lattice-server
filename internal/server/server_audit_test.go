package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
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

func TestAuditBareModeCapsAtDefaultLimit(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, _ := loginSession(t, handler)
	for i := 0; i < defaultAuditLimit+20; i++ {
		if err := st.AppendAudit(model.AuditEvent{
			ID:       "audit_cap_" + strconv.Itoa(i),
			At:       time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Second),
			Action:   "audit.cap",
			Decision: "allow",
		}); err != nil {
			t.Fatal(err)
		}
	}
	res := doJSON(t, handler, http.MethodGet, "/api/audit", "", cookies, "")
	defer res.Body.Close()
	var events []model.AuditEvent
	if err := json.NewDecoder(res.Body).Decode(&events); err != nil {
		t.Fatal(err)
	}
	if len(events) != defaultAuditLimit {
		t.Fatalf("bare audit mode returned %d events, want cap %d", len(events), defaultAuditLimit)
	}
	seen := make(map[string]bool, len(events))
	for _, ev := range events {
		seen[ev.ID] = true
	}
	if !seen["audit_cap_"+strconv.Itoa(defaultAuditLimit+19)] {
		t.Fatal("bare audit mode must keep the newest synthetic event")
	}
	if seen["audit_cap_0"] {
		t.Fatal("bare audit mode must drop the oldest events beyond the cap")
	}
}

func TestLoginUnknownUsernameIsAudited(t *testing.T) {
	handler, st := newTestServer(t)
	res := doJSON(t, handler, http.MethodPost, "/api/login",
		`{"username":"no-such-operator","password":"guess"}`, nil, "")
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown-user login = %d, want 401", res.StatusCode)
	}
	for _, ev := range st.AuditEvents() {
		if ev.Action == "login" && ev.Decision == "deny" && ev.Reason == "unknown username" {
			if ev.Metadata["username"] != "no-such-operator" {
				t.Fatalf("unknown-username audit metadata = %+v", ev.Metadata)
			}
			if ev.Metadata["source_ip"] == "" {
				t.Fatalf("unknown-username audit missing source_ip: %+v", ev.Metadata)
			}
			return
		}
	}
	t.Fatalf("no audit event for unknown-username login: %+v", st.AuditEvents())
}

func TestAuthenticateNodeAuditsFailuresThrottled(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/agent/poll", nil)
	req.RemoteAddr = "203.0.113.9:41000"

	if _, ok := srv.authenticateNode(req, "node-missing", "token"); ok {
		t.Fatal("unknown node must not authenticate")
	}
	if _, ok := srv.authenticateNode(req, "node-missing", "token"); ok {
		t.Fatal("unknown node must not authenticate")
	}
	denies := 0
	for _, ev := range st.AuditEvents() {
		if ev.Action == "agent.auth" && ev.Reason == "unknown node" {
			denies++
			if ev.Metadata["source_ip"] != "203.0.113.9" {
				t.Fatalf("agent.auth audit source_ip = %+v", ev.Metadata)
			}
		}
	}
	if denies != 1 {
		t.Fatalf("repeated agent auth failures inside the window must audit once, got %d", denies)
	}
}

func TestAuditFailureThrottleWindowRollover(t *testing.T) {
	th := newAuditFailureThrottle(time.Minute, 100, 100)
	base := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	if emit, _, _ := th.Allow("k", base); !emit {
		t.Fatal("first event must emit")
	}
	for i := 0; i < 3; i++ {
		if emit, _, _ := th.Allow("k", base.Add(time.Duration(i+1)*time.Second)); emit {
			t.Fatal("repeats inside the window must be suppressed")
		}
	}
	emit, suppressed, _ := th.Allow("k", base.Add(2*time.Minute))
	if !emit || suppressed != 3 {
		t.Fatalf("window rollover: emit=%v suppressed=%d, want true/3", emit, suppressed)
	}
}

func TestAuditFailureThrottleGlobalBucketCapsRotation(t *testing.T) {
	// Small bucket: burst 3, refill 1/sec. Distinct keys (source rotation)
	// must not exceed the global emission rate.
	th := newAuditFailureThrottle(time.Minute, 3, 1)
	base := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	emitted, dropped := 0, 0
	for i := 0; i < 50; i++ {
		emit, _, _ := th.Allow(fmt.Sprintf("ip-%d", i), base) // all at the same instant
		if emit {
			emitted++
		} else {
			dropped++
		}
	}
	if emitted != 3 {
		t.Fatalf("global bucket must cap simultaneous fresh-key emissions at burst 3, got %d", emitted)
	}
	if dropped != 47 {
		t.Fatalf("remaining fresh keys must be dropped, got %d", dropped)
	}
	// After 2 seconds, 2 tokens refill; the next emit carries the dropped count.
	emit, _, carried := th.Allow("ip-later", base.Add(2*time.Second))
	if !emit {
		t.Fatal("token should have refilled after 2s")
	}
	if carried != 47 {
		t.Fatalf("global_suppressed must carry the dropped count, got %d", carried)
	}
}

func TestAuditFailureThrottleFailsClosedUnderKeyChurn(t *testing.T) {
	// Generous global bucket so the map bound (not the bucket) is what is
	// exercised: every distinct key would emit if unbounded, but the map must
	// stay capped by evicting the oldest instead of failing open.
	th := newAuditFailureThrottle(time.Minute, 1e9, 1e9)
	base := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	for i := 0; i < auditThrottleMaxKeys*2; i++ {
		th.Allow(fmt.Sprintf("ip-%d", i), base.Add(time.Duration(i)*time.Millisecond))
	}
	th.mu.Lock()
	n := len(th.entries)
	th.mu.Unlock()
	if n > auditThrottleMaxKeys {
		t.Fatalf("throttle map must stay bounded at %d, got %d (failed open)", auditThrottleMaxKeys, n)
	}
}

func TestAuditBucketedIPCollapsesIPv6To64(t *testing.T) {
	a := auditBucketedIP("2001:db8:abcd:1234:1::1")
	b := auditBucketedIP("2001:db8:abcd:1234:ffff:ffff:ffff:ffff")
	if a != b {
		t.Fatalf("addresses in the same /64 must bucket together: %q vs %q", a, b)
	}
	if auditBucketedIP("2001:db8:abcd:9999::1") == a {
		t.Fatal("addresses in different /64s must not collide")
	}
	if auditBucketedIP("203.0.113.9") != "203.0.113.9" {
		t.Fatal("IPv4 must pass through unchanged")
	}
}
