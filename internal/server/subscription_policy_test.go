package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// adopted-suspend F7 and P12: graph subscription eligibility follows the
// identity's effective status. An identity over its quota was still offered
// and composed because only enabled and expiry were checked.
func TestGraphEligibilityFollowsTheIdentityPolicy(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	req := graphSubscriptionRequest{SchemaVersion: 1, IdentityID: "identity", EntryRoots: []string{composeRootUUID}}
	for _, tc := range []struct {
		name           string
		edit           func(*lineChainCompileSnapshot)
		status, reason string
	}{
		{name: "over quota, as captured", status: "over_quota", reason: "identity_over_quota", edit: func(s *lineChainCompileSnapshot) {
			u := s.Users["identity"]
			u.QuotaBytes = policyGiB
			s.Users["identity"] = u
			s.Policies = map[string]vpnUserPolicy{"identity": decideVpnUserPolicy(u, vpnUserQuotaUsage{Used: 2 * policyGiB}, now)}
		}},
		{name: "suspended by an operator", status: "suspended", reason: "identity_suspended", edit: func(s *lineChainCompileSnapshot) {
			u := s.Users["identity"]
			u.Suspension = &VpnSuspension{Reason: vpnSuspendReasonOperator, By: "op-9"}
			s.Users["identity"] = u
		}},
		{name: "expired", status: "expired", reason: "identity_expired", edit: func(s *lineChainCompileSnapshot) {
			u := s.Users["identity"]
			u.ExpiresAt = now
			s.Users["identity"] = u
		}},
		{name: "disabled", status: "disabled", reason: "identity_disabled", edit: func(s *lineChainCompileSnapshot) {
			u := s.Users["identity"]
			u.Enabled = false
			s.Users["identity"] = u
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := testGraphComposeSnapshot()
			if _, err := composeGraphSubscription(snapshot, req, now); err != nil {
				t.Fatalf("fixture must compose before the edit: %v", err)
			}
			tc.edit(&snapshot)
			options, err := graphSubscriptionOptions(snapshot, now)
			if err != nil {
				t.Fatal(err)
			}
			if got := options.Identities[0]; got.Selectable || got.Status != tc.status || got.Reason != tc.reason {
				t.Fatalf("identity option = %+v, want %s/%s and not selectable", got, tc.status, tc.reason)
			}
			for _, root := range options.Roots {
				if root.Selectable || len(root.EligibleIdentityIDs) != 0 {
					t.Fatalf("a root still offers the identity: %+v", root)
				}
			}
			if _, err := composeGraphSubscription(snapshot, req, now); err == nil || composeFailureView(err).Code != "identity_unavailable" {
				t.Fatalf("compose for the identity: %v", err)
			}
		})
	}
}

// The live capture fills each identity's policy from the store, so a quota
// crossing reaches graph eligibility without anything rewriting the identity.
func TestGraphCaptureCarriesEachIdentityPolicy(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	u := VpnUser{ID: "vpnuser_graph", Email: "graph@example.com", Enabled: true, QuotaBytes: policyGiB, QuotaPeriod: vpnQuotaPeriodMonthly,
		QuotaResetDay: 1, Credentials: []VpnCredential{}, Bindings: []LineBinding{}}
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.ApplyProxyUsage(store.ProxyUsageUpdate{DayUsers: []store.UsageDayUser{{UserID: u.ID, Day: "20261019", Downlink: 2 * policyGiB}}}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := srv.captureLineChainCompileSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	snapshot = srv.withIdentityPolicies(snapshot, now)
	if p := snapshot.identityPolicy(snapshot.Users[u.ID], now); p.Reason != vpnSuspendReasonQuota || p.Usage.Used != 2*policyGiB {
		t.Fatalf("captured policy = %+v", p)
	}
}

// identity-sub D5 and P9, adopted-suspend P12: a core.proxy_user share serves
// a user exactly when the identity behind it is active, with the identity's
// figures in its quota header. The rendered body used to be cached for 30
// minutes with nothing invalidating it, so a disabled, expired or over-quota
// user kept receiving working nodes from the cache.
func TestCoreShareServesWhatTheIdentityPolicyAllows(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	srv.now = func() time.Time { return now }
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	createProxyPlanFixtures(t, handler, cookies, csrf, "node-a")
	profile, _ := st.ProxyNodeProfile("node-a")
	profile.AppliedSHA256, profile.LastError = strings.Repeat("a", 64), ""
	if err := st.UpsertProxyNodeProfile(profile); err != nil {
		t.Fatal(err)
	}
	identity := VpnUser{ID: "vu_alice", Email: "alice@example.com", Enabled: true, MigratedFromProxyUser: "alice",
		QuotaBytes: policyGiB, QuotaPeriod: vpnQuotaPeriodMonthly, QuotaResetDay: 1,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: "11111111-1111-4111-8111-111111111111"}}, Bindings: []LineBinding{}}
	if err := srv.putVpnUser(identity); err != nil {
		t.Fatal(err)
	}
	subURL := publishProxyUserShare(t, st, "alice", "alice-team", "sub-token-secret-abcdefghijklmnopqrstuvwxyz")
	fetch := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		srv.handleSubscriptionShare(rec, httptest.NewRequest(http.MethodGet, subURL+"?format=plain", nil))
		return rec
	}
	admin := func(method string, body map[string]any) {
		t.Helper()
		ctx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, principal{Principal: rbac.Principal{ActorID: "op-1"}})
		if _, err := srv.vpnCoreUsersAdminRPC(ctx, method, mustJSON(t, body)); err != nil {
			t.Fatal(err)
		}
	}

	rec := fetch()
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "vless://") {
		t.Fatalf("active identity: %d %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Subscription-Userinfo"); !strings.Contains(got, "total="+strconv.FormatInt(policyGiB, 10)) {
		t.Fatalf("the quota header must carry the identity's quota: %q", got)
	}

	// A quota crossing writes no record a cache could be invalidated by.
	if err := st.ApplyProxyUsage(store.ProxyUsageUpdate{DayUsers: []store.UsageDayUser{{UserID: identity.ID, Day: store.UsageDay(now), Downlink: 2 * policyGiB}}}); err != nil {
		t.Fatal(err)
	}
	if rec := fetch(); rec.Code != http.StatusNotFound {
		t.Fatalf("over quota: %d %q, want the decoy", rec.Code, rec.Body.String())
	}

	admin("update", map[string]any{"id": identity.ID, "email": identity.Email, "quota_bytes": 10 * policyGiB})
	if rec := fetch(); rec.Code != http.StatusOK {
		t.Fatalf("after raising the quota: %d", rec.Code)
	}
	admin("update", map[string]any{"id": identity.ID, "email": identity.Email, "enabled": false})
	if rec := fetch(); rec.Code != http.StatusNotFound {
		t.Fatalf("disabled: %d %q, want the decoy", rec.Code, rec.Body.String())
	}
	expiry := now.Add(time.Minute)
	admin("update", map[string]any{"id": identity.ID, "email": identity.Email, "enabled": true, "expires_at": expiry})
	if rec := fetch(); rec.Code != http.StatusOK {
		t.Fatalf("re-enabled before its expiry: %d", rec.Code)
	}
	now = expiry
	if rec := fetch(); rec.Code != http.StatusNotFound {
		t.Fatalf("expired from a warm cache: %d %q, want the decoy", rec.Code, rec.Body.String())
	}
}

// Any identity write drops what core shares cached, so an edit the status
// gate cannot see (a new quota header, a binding) is served on the next fetch.
func TestIdentityWritesDropCachedCoreShares(t *testing.T) {
	srv := newLinemetaTestServer(t, mustOpenStore(t))
	mustUpsertShare(t, srv.store, model.SubscriptionShare{ID: "core", Slug: "core", Token: strings.Repeat("c", 32), Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourceCoreProxyUser, ProxyUserID: "u1"}})
	mustUpsertShare(t, srv.store, model.SubscriptionShare{ID: "plugin", Slug: "plugin", Token: strings.Repeat("p", 32), Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "s"}})
	warm := func() {
		for _, id := range []string{"core", "plugin"} {
			srv.subscriptionCache.Put(subscriptionCacheKey{ShareID: id, Format: "base64"}, []byte("body"), "text/plain", "", "hash", srv.now())
		}
	}
	cached := func(id string) bool {
		_, ok := srv.subscriptionCache.GetSnapshot(subscriptionCacheKey{ShareID: id, Format: "base64"}, srv.now())
		return ok
	}
	ctx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, principal{Principal: rbac.Principal{ActorID: "op-1"}})
	warm()
	raw, err := srv.vpnCoreUsersAdminRPC(ctx, "create", mustJSON(t, map[string]any{"email": "eve@example.com"}))
	if err != nil {
		t.Fatal(err)
	}
	if cached("core") || !cached("plugin") {
		t.Fatalf("an identity write must drop core shares and only those: core=%v plugin=%v", cached("core"), cached("plugin"))
	}
	warm()
	if _, err := srv.vpnCoreUsersAdminRPC(ctx, "update", mustJSON(t, map[string]any{"id": decodeCreatedUserID(t, raw), "email": "eve@example.com", "comment": "x"})); err != nil {
		t.Fatal(err)
	}
	if cached("core") {
		t.Fatal("an identity update must drop core shares")
	}
}
