package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// proxyNodePlanText files a proxycore plan for the node through the handler
// and returns the plan text the operator reviews.
func proxyNodePlanText(t *testing.T, srv *Server, nodeID string) string {
	t.Helper()
	p := principal{Principal: rbac.Principal{ActorID: "op-1", Scopes: []string{"network:plan", "proxy:read"}}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/proxy/nodes/"+nodeID+"/plan", strings.NewReader(`{}`))
	srv.handleProxyNodePlan(rec, req, p)
	if rec.Code != http.StatusOK {
		t.Fatalf("proxy plan: %d %s", rec.Code, rec.Body.String())
	}
	var view approvalView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	return view.Plan
}

// planAddOnLine files plan_add for the user on the line and returns the
// reviewed line-user plan.
func planAddOnLine(t *testing.T, srv *Server, userID, lineHashID string) lineUserPlan {
	t.Helper()
	out, err := srv.vpnUserLinePlan(lineUserTestPrincipal(), mustJSON(t, map[string]string{"user_id": userID, "line_hash_id": lineHashID}), lineUserOpAdd)
	if err != nil {
		t.Fatalf("plan_add: %v", err)
	}
	var response struct {
		Approval model.Approval `json:"approval"`
	}
	if err := json.Unmarshal(out, &response); err != nil {
		t.Fatal(err)
	}
	var plan lineUserPlan
	if err := json.Unmarshal([]byte(response.Approval.Plan), &plan); err != nil {
		t.Fatal(err)
	}
	return plan
}

// A plan for an unrelated change names the users its render already leaves
// out by policy, by email for an identity and by stored name for a record
// with no identity behind it, so an approval that goes stale because one of
// them crossed its quota is not a surprise. Nothing omitted, nothing listed.
func TestPlansNameUsersTheRenderLeavesOut(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	line, identity := seedManagedLineUserFixture(t, srv)
	identity.Bindings = []LineBinding{{LineHashID: line.LineHashID, Enabled: true}}
	identity.QuotaBytes, identity.QuotaPeriod, identity.QuotaResetDay = 1000, vpnQuotaPeriodMonthly, 15
	if err := srv.putVpnUser(identity); err != nil {
		t.Fatal(err)
	}
	second := VpnUser{
		ID: "vpnuser_second", Email: "second@example.com", Enabled: true,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: "55555555-5555-4555-8555-555555555555", Flow: "xtls-rprx-vision"}},
	}
	if err := srv.putVpnUser(second); err != nil {
		t.Fatal(err)
	}

	if plan := planAddOnLine(t, srv, second.ID, line.LineHashID); len(plan.Omitted) != 0 || strings.Contains(plan.Summary, "left out") {
		t.Fatalf("nothing is omitted yet: %+v", plan)
	}
	if text := proxyNodePlanText(t, srv, "managed-a"); strings.Contains(text, "omitted_users") {
		t.Fatalf("nothing is omitted yet:\n%s", text)
	}

	// The bound identity crosses its monthly quota; the legacy record with no
	// identity behind it expires.
	if err := srv.store.ApplyProxyUsage(store.ProxyUsageUpdate{DayUsers: []store.UsageDayUser{
		{UserID: identity.ID, Day: "20260916", Uplink: 600, Downlink: 500},
	}}); err != nil {
		t.Fatal(err)
	}
	other, _ := srv.store.ProxyUser("other-keepalive")
	other.ExpiresAt = now.Add(-time.Hour)
	if err := srv.store.UpsertProxyUser(other); err != nil {
		t.Fatal(err)
	}
	want := []string{"Other (expired)", "managed@example.com (over_quota)"}
	plan := planAddOnLine(t, srv, second.ID, line.LineHashID)
	if !reflect.DeepEqual(plan.Omitted, want) {
		t.Fatalf("omitted = %q, want %q", plan.Omitted, want)
	}
	if !strings.HasSuffix(plan.Summary, "; already left out by policy: Other (expired), managed@example.com (over_quota)") {
		t.Fatalf("summary: %q", plan.Summary)
	}

	// Unbound, the migrated identity is rendered through its legacy record,
	// which is listed under the identity's email too.
	identity, _ = srv.getVpnUser(identity.ID)
	identity.Bindings = nil
	identity.ExpiresAt = now.Add(-time.Hour)
	if err := srv.putVpnUser(identity); err != nil {
		t.Fatal(err)
	}
	want = []string{"Other (expired)", "managed@example.com (expired)"}
	plan = planAddOnLine(t, srv, second.ID, line.LineHashID)
	if !reflect.DeepEqual(plan.Omitted, want) {
		t.Fatalf("omitted through the legacy record = %q, want %q", plan.Omitted, want)
	}

	// The proxycore plan lists them the same way. It renders the stored
	// bindings only, so the second identity is bound first to leave the
	// inbound one eligible user.
	second.Bindings = []LineBinding{{LineHashID: line.LineHashID, Enabled: true}}
	if err := srv.putVpnUser(second); err != nil {
		t.Fatal(err)
	}
	text := proxyNodePlanText(t, srv, "managed-a")
	if !strings.Contains(text, "\nomitted_users: 2\n- Other (expired)\n- managed@example.com (expired)\nTheir policy leaves these users out of this config.") {
		t.Fatalf("proxycore plan must list the omitted users by name:\n%s", text)
	}
}

func TestOmittedSummaryCountsPastFive(t *testing.T) {
	entries := []string{"a (expired)", "b (expired)", "c (expired)", "d (expired)", "e (expired)"}
	if got := omittedSummary(entries); got != "a (expired), b (expired), c (expired), d (expired), e (expired)" {
		t.Fatalf("five: %q", got)
	}
	entries = append(entries, "f (over_quota)", "g (disabled)")
	if got := omittedSummary(entries); got != "a (expired), b (expired), c (expired), d (expired), e (expired) and 2 more" {
		t.Fatalf("seven: %q", got)
	}
}

// A line-user plan names identities by email, the users its render leaves
// out included, so it is listed only to a principal that may read
// identities: unrestricted, holding the vpn-core read or admin scope, and
// network:plan on the node. Bare network:plan read it before, with or
// without an allowlist; deciding still asks for vpncore:admin.
func TestLineUserPlanIsListedOnlyToPrincipalsWhoReadIdentities(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	line, identity := seedManagedLineUserFixture(t, srv)
	identity.Bindings = []LineBinding{{LineHashID: line.LineHashID, Enabled: true}}
	identity.QuotaBytes, identity.QuotaPeriod, identity.QuotaResetDay = 1000, vpnQuotaPeriodMonthly, 15
	if err := srv.putVpnUser(identity); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.ApplyProxyUsage(store.ProxyUsageUpdate{DayUsers: []store.UsageDayUser{
		{UserID: identity.ID, Day: "20260916", Uplink: 600, Downlink: 500},
	}}); err != nil {
		t.Fatal(err)
	}
	second := VpnUser{
		ID: "vpnuser_second", Email: "second@example.com", Enabled: true,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: "55555555-5555-4555-8555-555555555555", Flow: "xtls-rprx-vision"}},
	}
	if err := srv.putVpnUser(second); err != nil {
		t.Fatal(err)
	}
	if plan := planAddOnLine(t, srv, second.ID, line.LineHashID); len(plan.Omitted) == 0 {
		t.Fatalf("the fixture must leave a user out: %+v", plan)
	}

	cases := []struct {
		name      string
		scopes    []string
		allowlist []string
		listed    bool
	}{
		{name: "network:plan", scopes: []string{"network:plan"}},
		{name: "network:plan on the node", scopes: []string{"network:plan"}, allowlist: []string{"managed-a"}},
		{name: "proxy:read confined to the node", scopes: []string{"network:plan", "proxy:read"}, allowlist: []string{"managed-a"}},
		{name: "vpncore:read without network:plan", scopes: []string{"vpncore:read"}},
		{name: "vpncore:read", scopes: []string{"network:plan", "vpncore:read"}, listed: true},
		{name: "proxy:read", scopes: []string{"network:plan", "proxy:read"}, listed: true},
		{name: "vpncore:admin", scopes: []string{"network:plan", "vpncore:admin"}, listed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := principal{Principal: rbac.Principal{ActorID: "reader", Scopes: tc.scopes, ServerAllowlist: tc.allowlist}}
			rec := httptest.NewRecorder()
			srv.handleApprovals(rec, httptest.NewRequest(http.MethodGet, "/api/network/approvals?include=plan", nil), p)
			if rec.Code != http.StatusOK {
				t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			listed := strings.Contains(body, `"plugin":"`+singBoxLineUserPlugin+`"`)
			if listed != tc.listed {
				t.Fatalf("line-user approval listed = %v, want %v: %s", listed, tc.listed, body)
			}
			if !tc.listed && strings.Contains(body, "@example.com") {
				t.Fatalf("an identity email reached a principal that cannot read identities: %s", body)
			}
			if tc.listed && !strings.Contains(body, "managed@example.com (over_quota)") {
				t.Fatalf("the listed plan must keep the omitted user: %s", body)
			}
		})
	}
}

// Both plans say that another user crossing its policy before approval makes
// them stale, and the approval path holds them to it: the render drops that
// user's row, so the config hash each plan pinned no longer matches.
func TestPlansGoStaleWhenAnotherUserCrossesItsPolicy(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	line, identity := seedManagedLineUserFixture(t, srv)
	identity.Bindings = []LineBinding{{LineHashID: line.LineHashID, Enabled: true}}
	identity.QuotaBytes, identity.QuotaPeriod, identity.QuotaResetDay = 1000, vpnQuotaPeriodMonthly, 15
	if err := srv.putVpnUser(identity); err != nil {
		t.Fatal(err)
	}
	second := VpnUser{
		ID: "vpnuser_second", Email: "second@example.com", Enabled: true,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: "55555555-5555-4555-8555-555555555555", Flow: "xtls-rprx-vision"}},
	}
	if err := srv.putVpnUser(second); err != nil {
		t.Fatal(err)
	}
	lineUser := filePlan(t, srv, lineUserOpAdd, second.ID, line.LineHashID)
	proxyNodePlanText(t, srv, "managed-a")
	var proxy model.Approval
	for _, approval := range srv.store.Approvals() {
		if approval.Plugin == proxyCorePlugin {
			proxy = approval
		}
	}
	if proxy.ID == "" {
		t.Fatal("no proxycore approval was filed")
	}
	if err := srv.requireCurrentProxyCoreApproval(proxy); err != nil {
		t.Fatalf("proxycore plan before the crossing: %v", err)
	}
	if _, _, _, _, _, err := srv.validateLineUserApproval(lineUser, true); err != nil {
		t.Fatalf("line-user plan before the crossing: %v", err)
	}

	if err := srv.store.ApplyProxyUsage(store.ProxyUsageUpdate{DayUsers: []store.UsageDayUser{
		{UserID: identity.ID, Day: "20260916", Uplink: 600, Downlink: 500},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := srv.requireCurrentProxyCoreApproval(proxy); err == nil || !strings.Contains(err.Error(), "proxycore config changed since this plan was created") {
		t.Fatalf("proxycore plan after another user crossed its quota: %v", err)
	}
	if _, _, _, _, _, err := srv.validateLineUserApproval(lineUser, true); err == nil || !strings.Contains(err.Error(), "managed config changed since approval") {
		t.Fatalf("line-user plan after another user crossed its quota: %v", err)
	}
}
