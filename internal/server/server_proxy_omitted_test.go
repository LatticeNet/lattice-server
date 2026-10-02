package server

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
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

// omittingLineUserApproval files a managed plan_add for second@example.com on
// a line whose render already leaves managed@example.com out over its quota,
// so the plan names two identities by email. It returns the server and the
// pending approval.
func omittingLineUserApproval(t *testing.T) (*Server, model.Approval) {
	t.Helper()
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
	approval := filePlan(t, srv, lineUserOpAdd, second.ID, line.LineHashID)
	var plan lineUserPlan
	if err := json.Unmarshal([]byte(approval.Plan), &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Omitted) == 0 {
		t.Fatalf("the fixture must leave a user out: %+v", plan)
	}
	return srv, approval
}

// Approve, reject and dismiss answer with the full plan, so a decider must
// clear the read gate the listing applies. A principal confined to the node
// with network:apply and vpncore:admin there could reject a line-user
// approval by id and read the identities its plan names, the users its
// render leaves out included, which the listing hides from it. A decider
// who may read the plan still decides it.
func TestDecidingALineUserPlanRequiresReadingIt(t *testing.T) {
	srv, approval := omittingLineUserApproval(t)
	planSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(approval.Plan)))
	bodies := map[string]string{
		"approve": `{"approval_id":"` + approval.ID + `","queue_apply":true,"plan_sha256":"` + planSHA + `"}`,
		"reject":  `{"approval_id":"` + approval.ID + `"}`,
		"dismiss": `{"approval_id":"` + approval.ID + `"}`,
	}
	refused := []struct {
		name      string
		scopes    []string
		allowlist []string
	}{
		{name: "confined to the node", scopes: []string{"network:apply", "network:plan", "vpncore:admin"}, allowlist: []string{"managed-a"}},
		{name: "without network:plan", scopes: []string{"network:apply", "vpncore:admin"}},
	}
	checkRefused := func(t *testing.T) {
		t.Helper()
		for _, tc := range refused {
			p := principal{Principal: rbac.Principal{ActorID: "decider", Scopes: tc.scopes, ServerAllowlist: tc.allowlist}}
			for _, verb := range []string{"approve", "reject", "dismiss"} {
				rec := decideApproval(srv, verb, bodies[verb], p)
				if rec.Code != http.StatusForbidden {
					t.Fatalf("%s, %s: status %d, want 403: %s", tc.name, verb, rec.Code, rec.Body.String())
				}
				if body := rec.Body.String(); strings.Contains(body, "@example.com") || strings.Contains(body, "render full sing-box config") {
					t.Fatalf("%s, %s: the refusal carried the plan: %s", tc.name, verb, body)
				}
			}
		}
	}

	t.Run("refused while pending", func(t *testing.T) {
		checkRefused(t)
		stored, _ := srv.store.Approval(approval.ID)
		if stored.Status != model.ApprovalPending {
			t.Fatalf("a refused decider changed the approval to %q", stored.Status)
		}
		if tasks := tasksFor(srv, approval.ID); len(tasks) != 0 {
			t.Fatalf("a refused decider queued %d task(s)", len(tasks))
		}
	})

	reader := principal{Principal: rbac.Principal{ActorID: "decider", Scopes: []string{"network:apply", "network:plan", "vpncore:admin"}}}
	t.Run("allowed", func(t *testing.T) {
		rec := decideApproval(srv, "approve", bodies["approve"], reader)
		if rec.Code != http.StatusOK {
			t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "managed@example.com (over_quota)") {
			t.Fatalf("a decider who may read the plan gets it back: %s", rec.Body.String())
		}
		if tasks := tasksFor(srv, approval.ID); len(tasks) != 1 {
			t.Fatalf("approve queued %d task(s), want 1", len(tasks))
		}
		// Rejecting a decided approval changes nothing and still answers
		// with the plan, to a decider who may read it.
		rec = decideApproval(srv, "reject", bodies["reject"], reader)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "second@example.com") {
			t.Fatalf("reject of a decided approval: %d %s", rec.Code, rec.Body.String())
		}
	})

	// On a decided approval reject mutates nothing, so before this it was a
	// pure read.
	t.Run("refused once decided", checkRefused)
}

// A proxycore plan names the users its render leaves out by email, and its
// decision path had the same gap: proxy:admin on the node, confined to it,
// rejected the approval by id and read them.
func TestDecidingAProxyCorePlanRequiresReadingIt(t *testing.T) {
	srv, _ := omittingLineUserApproval(t)
	planner := principal{Principal: rbac.Principal{ActorID: "op-1", Scopes: []string{"network:plan", "proxy:read"}}}
	rec := httptest.NewRecorder()
	srv.handleProxyNodePlan(rec, httptest.NewRequest(http.MethodPost, "/api/proxy/nodes/managed-a/plan", strings.NewReader(`{}`)), planner)
	if rec.Code != http.StatusOK {
		t.Fatalf("proxy plan: %d %s", rec.Code, rec.Body.String())
	}
	var view approvalView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(view.Plan, "managed@example.com") {
		t.Fatalf("the fixture's proxycore plan must name the omitted user:\n%s", view.Plan)
	}
	reject := `{"approval_id":"` + view.ID + `"}`

	confined := principal{Principal: rbac.Principal{ActorID: "decider",
		Scopes: []string{"network:apply", "network:plan", "proxy:admin", "proxy:read"}, ServerAllowlist: []string{"managed-a"}}}
	rec = decideApproval(srv, "reject", reject, confined)
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "@example.com") {
		t.Fatalf("a confined decider: %d %s, want 403 without the plan", rec.Code, rec.Body.String())
	}
	if stored, _ := srv.store.Approval(view.ID); stored.Status != model.ApprovalPending {
		t.Fatalf("a refused decider changed the approval to %q", stored.Status)
	}

	reader := principal{Principal: rbac.Principal{ActorID: "decider",
		Scopes: []string{"network:apply", "network:plan", "proxy:admin", "proxy:read"}}}
	rec = decideApproval(srv, "reject", reject, reader)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "managed@example.com") {
		t.Fatalf("a decider who may read the plan: %d %s", rec.Code, rec.Body.String())
	}
	if stored, _ := srv.store.Approval(view.ID); stored.Status != model.ApprovalRejected {
		t.Fatalf("status = %q, want rejected", stored.Status)
	}
}

// A line-user plan names identities by email, the users its render leaves
// out included, so it is listed only to a principal that may read
// identities: unrestricted, holding the vpn-core read or admin scope, and
// network:plan on the node. Bare network:plan read it before, with or
// without an allowlist; deciding still asks for vpncore:admin.
func TestLineUserPlanIsListedOnlyToPrincipalsWhoReadIdentities(t *testing.T) {
	srv, _ := omittingLineUserApproval(t)

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
