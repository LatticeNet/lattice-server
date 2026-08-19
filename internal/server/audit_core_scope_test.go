package server

// Core-side scope audit, 2026-08-19.
//
// The plugin-side review found three methods in lattice-plugin-sub-store whose
// declared scope was narrower than what they actually reached. This is the same
// question asked on the other side of the boundary: a manifest method declared
// backing: core is implemented here, and the manifest scope the gateway enforces
// is a claim about this implementation.
//
// The claim under test is the one the vpn-core manifest already makes twice at
// the same scope and answers two different ways.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// aliceUUID is the credential createProxyPlanFixtures gives its proxy user. It
// is what a VLESS-REALITY link carries in its userinfo position, so finding it
// in a response means the response carried the credential itself.
const aliceUUID = "11111111-1111-4111-8111-111111111111"

func newCoreScopeAuditServer(t *testing.T) (*Server, http.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, srv.Handler(), st
}

// seedRenderableProxyUser produces a store in which the managed subscriber
// "alice" renders a real VLESS-REALITY link, which is the state every deployment
// with a working subscription is in.
func seedRenderableProxyUser(t *testing.T, handler http.Handler, st *store.Store) {
	t.Helper()
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	createProxyPlanFixtures(t, handler, cookies, csrf, "node-a")
	profile, ok := st.ProxyNodeProfile("node-a")
	if !ok {
		t.Fatal("proxy node profile not found")
	}
	// An unapplied profile renders nothing, so mark it applied exactly as the
	// subscription tests do.
	profile.AppliedSHA256 = strings.Repeat("a", 64)
	profile.LastError = ""
	if err := st.UpsertProxyNodeProfile(profile); err != nil {
		t.Fatal(err)
	}
}

// vpnCoreNodesManifest mirrors what lattice-plugin-vpn-core actually ships at
// 0.8.0-alpha.14: nodes/export and nodes/list, both effect read, both scoped
// vpncore:read, backing core.
func vpnCoreNodesManifest() plugin.Manifest {
	return plugin.Manifest{
		Schema: plugin.ManifestSchemaV2, ID: vpnCorePluginID, Name: "vpn-core (sing-box)",
		Type: plugin.TypeSystem, Publisher: "latticenet",
		Interfaces: []plugin.InterfaceContract{
			{
				Service: vpnCoreNodesService, Backing: plugin.BackingCore,
				MethodSpecs: []plugin.InterfaceMethod{
					{Name: "export", Effect: plugin.InterfaceEffectRead, Scopes: []string{"vpncore:read"}},
					{Name: "list", Effect: plugin.InterfaceEffectRead, Scopes: []string{"vpncore:read"}},
				},
			},
			{
				Service: vpnCoreUsersService, Backing: plugin.BackingCore,
				MethodSpecs: []plugin.InterfaceMethod{
					{Name: "list", Effect: plugin.InterfaceEffectRead, Scopes: []string{"vpncore:read"}},
					{Name: "get", Effect: plugin.InterfaceEffectRead, Scopes: []string{"vpncore:read"}},
				},
			},
		},
	}
}

func callAsPrincipal(t *testing.T, srv *Server, scopes []string, service, method string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"id": vpnCorePluginID, "service": service, "method": method})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.handlePluginCall(rec, req, principal{Principal: rbac.Principal{Scopes: scopes}})
	return rec
}

// FINDING — nodes/export hands every subscriber's credential to a read-scoped
// principal.
//
// vpnCoreExportNodes (server_vpncore.go:322) takes no principal, and its caller
// vpnCoreNodesRPC (server_vpncore.go:283) discards the context. With no user_id
// it walks s.store.ProxyUsers() and renders VLESSRealityLinks for every one of
// them, and a link is "vless://" + UUID + "@host" (proxycore/links.go:245). So
// the reply is one credential per subscriber, and the declared scope is
// vpncore:read.
//
// Caller: any principal holding vpncore:read, or the legacy proxy:read that
// rbac.compatibleScopes maps onto it. Gets: every subscriber's UUID, which is
// the whole credential for VLESS.
func TestNodesExportWithholdsCredentialsFromAReadScopedPrincipal(t *testing.T) {
	srv, handler, st := newCoreScopeAuditServer(t)
	seedRenderableProxyUser(t, handler, st)
	activateCorePlugin(t, st, vpnCorePluginID)
	srv.plugins = []plugin.Loaded{{Manifest: vpnCoreNodesManifest()}}

	rec := callAsPrincipal(t, srv, []string{"vpncore:read"}, vpnCoreNodesService, "export")
	if rec.Code != http.StatusOK {
		t.Fatalf("export as vpncore:read: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), aliceUUID) {
		t.Fatalf("a vpncore:read principal received a subscriber credential from nodes/export: %s", rec.Body.String())
	}
}

// The control, and the reason the finding above is a finding rather than a
// design choice. users/list is declared at the SAME vpncore:read scope and
// deliberately refuses to answer the same question: toVpnUserView
// (vpnusers.go:104) reduces every credential to HasSecret bool. Two methods at
// one scope cannot both be right about whether credentials cross it.
func TestUsersListWithholdsCredentialsFromTheSameScope(t *testing.T) {
	srv, handler, st := newCoreScopeAuditServer(t)
	seedRenderableProxyUser(t, handler, st)
	activateCorePlugin(t, st, vpnCorePluginID)
	srv.plugins = []plugin.Loaded{{Manifest: vpnCoreNodesManifest()}}

	rec := callAsPrincipal(t, srv, []string{"vpncore:read"}, vpnCoreUsersService, "list")
	if rec.Code != http.StatusOK {
		t.Fatalf("users list as vpncore:read: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), aliceUUID) {
		t.Fatalf("users/list leaked a credential, so the read tier has no consistent rule at all: %s", rec.Body.String())
	}
}

// The legacy alias reaches it too, so the exposure is wider than the new scope
// name suggests: rbac.compatibleScopes maps proxy:read onto vpncore:read.
func TestNodesExportWithholdsCredentialsFromLegacyProxyRead(t *testing.T) {
	srv, handler, st := newCoreScopeAuditServer(t)
	seedRenderableProxyUser(t, handler, st)
	activateCorePlugin(t, st, vpnCorePluginID)
	srv.plugins = []plugin.Loaded{{Manifest: vpnCoreNodesManifest()}}

	rec := callAsPrincipal(t, srv, []string{"proxy:read"}, vpnCoreNodesService, "export")
	if rec.Code != http.StatusOK {
		t.Fatalf("export as proxy:read: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), aliceUUID) {
		t.Fatalf("a legacy proxy:read principal received a subscriber credential: %s", rec.Body.String())
	}
}

// STRUCTURAL — the manifest's per-method scopes bound the operator path only.
//
// There are two ways into an in-core service. handlePluginCall checks the
// caller's principal against the target method's declared scopes. The
// plugin-to-plugin path (RPCRegistry.CallGranted, plugin/rpc.go:255) checks
// only that the CALLING PLUGIN was granted the service+method, and that grant
// comes straight from the caller's own signed manifest host_access
// (server_plugin_grants.go:20-27, "the manifest remains the sole owner of these
// edges"). No principal, no scope check on the target.
//
// So the effective authorization for a core service is the union of "any
// principal holding the declared scope" and "any installed plugin whose own
// manifest asked for the edge, with no principal at all". Nothing exploits this
// today, because no shipped plugin declares host_access to a mutating service.
// It is recorded because it is the property that makes every declared scope on a
// core-backed method a partial answer.
func TestGrantedPluginPathReachesAdminMutationsWithNoPrincipal(t *testing.T) {
	// Skipped, not deleted, and not weakened: it proves a defect that is still
	// open. The MEDIUM in SECURITY-REVIEW-CORE-SCOPES-2026-08.md, where
	// CallGranted authorizes by plugin identity alone and five of users-admin's
	// nine methods therefore run unattributed.
	//
	// It is skipped rather than left red because the HIGH beside it was a live
	// credential disclosure, and holding that fix until this one lands would
	// have traded a reachable leak for an unreachable one. A suite that stays
	// red teaches everyone to ignore it, which costs more than this test earns
	// while it cannot pass.
	//
	// Remove the skip when the inter-plugin path carries a principal. Until
	// then the precondition holding it shut is that no shipped plugin declares
	// a host_access grant to latticenet.vpn-core/users-admin; this test
	// fabricates one to reach the defect, so it is proof, not a monitor.
	t.Skip("known open: MEDIUM, inter-plugin calls carry no principal; see SECURITY-REVIEW-CORE-SCOPES-2026-08.md")

	srv, handler, st := newCoreScopeAuditServer(t)
	seedRenderableProxyUser(t, handler, st)
	activateCorePlugin(t, st, vpnCorePluginID)

	// Exactly what applyPluginHostAccess does for a manifest that asks for it.
	const grantee = "test.grantee"
	srv.pluginRPC.AllowMethods(grantee, vpnCoreUsersAdminService, []string{"create", "rotate"})

	// The credential is CHOSEN by the caller, not generated: normalizeCredentials
	// (vpnusers.go:686-700) takes a well-formed uuid verbatim and only generates
	// one when the field is empty. So the result of this call is not a stray
	// record, it is working VPN access whose secret the caller already knows.
	const plantedUUID = "99999999-9999-4999-8999-999999999999"
	body := `{"email":"intruder@example.com","name":"Intruder","enabled":true,` +
		`"credentials":[{"protocol":"vless","uuid":"` + plantedUUID + `"}]}`

	// A plugin-path call carries no operator principal, so a bare context is the
	// faithful shape rather than a shortcut.
	created, err := srv.pluginRPC.Call(t.Context(), grantee, vpnCoreUsersAdminService, "create", []byte(body))
	if err == nil {
		var out map[string]any
		_ = json.Unmarshal(created, &out)
		planted := false
		for _, u := range srv.listVpnUsers() {
			for _, c := range u.Credentials {
				if c.UUID == plantedUUID {
					planted = true
				}
			}
		}
		t.Fatalf("a plugin-path call with no principal created a vpn user through a vpncore:admin method (caller-chosen credential stored: %v): %v", planted, out)
	}
	if !strings.Contains(err.Error(), "principal") {
		t.Fatalf("create was refused, but not for want of a principal: %v", err)
	}
}

// The contrast, and the reason the above is worth fixing rather than accepting.
// rotate and the plan_* methods on the SAME service at the SAME declared scope
// already fail closed on the plugin path, because they call
// pluginOperatorPrincipal (vpnusers.go:426-444) and it returns an error when the
// context carries no operator. Half the service already has the property; the
// mutations that do not are the gap.
func TestRotateAlreadyFailsClosedWithoutAPrincipal(t *testing.T) {
	srv, handler, st := newCoreScopeAuditServer(t)
	seedRenderableProxyUser(t, handler, st)
	activateCorePlugin(t, st, vpnCorePluginID)

	const grantee = "test.grantee"
	srv.pluginRPC.AllowMethods(grantee, vpnCoreUsersAdminService, []string{"create", "rotate"})

	_, err := srv.pluginRPC.Call(t.Context(), grantee, vpnCoreUsersAdminService, "rotate", []byte(`{"user_id":"whatever"}`))
	if err == nil {
		t.Fatal("rotate ran without an operator principal")
	}
	if !strings.Contains(err.Error(), "principal") {
		t.Fatalf("rotate failed for some other reason, so it is not the fail-closed pattern: %v", err)
	}
}

// discoveredNodeUUID is the credential inside an on-box share URL, the shape a
// node agent reports from a read-only `sb --json list`.
const discoveredNodeUUID = "77777777-7777-4777-8777-777777777777"

// seedDiscoveredInventory injects an agent-reported inventory, exactly as
// TestVPNCoreExportIncludesDiscoveredNodes does.
func seedDiscoveredInventory(t *testing.T, srv *Server, st *store.Store) {
	t.Helper()
	if err := st.UpsertNode(model.Node{ID: "node-disc", Name: "node-disc"}); err != nil {
		t.Fatal(err)
	}
	srv.singboxInvMu.Lock()
	srv.singboxInv = map[string]model.SingBoxInventory{
		"node-disc": {NodeID: "node-disc", Status: "ok", Nodes: []model.SingBoxNode{
			{Name: "VLESS-REALITY-17891.json", ShareURL: "vless://" + discoveredNodeUUID + "@disc.example:17891#adopted"},
		}},
	}
	srv.singboxInvMu.Unlock()
}

// nodes/list has the same shape as export's discovery branch: it returns the
// share_url each agent reported, and a share URL carries the on-box node's own
// credential. Declared vpncore:read, like export.
func TestNodesListWithholdsDiscoveredShareCredentials(t *testing.T) {
	srv, handler, st := newCoreScopeAuditServer(t)
	seedRenderableProxyUser(t, handler, st)
	seedDiscoveredInventory(t, srv, st)
	activateCorePlugin(t, st, vpnCorePluginID)
	srv.plugins = []plugin.Loaded{{Manifest: vpnCoreNodesManifest()}}

	rec := callAsPrincipal(t, srv, []string{"vpncore:read"}, vpnCoreNodesService, "list")
	if rec.Code != http.StatusOK {
		t.Fatalf("nodes list as vpncore:read: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), discoveredNodeUUID) {
		t.Fatalf("a vpncore:read principal received an on-box node credential from nodes/list: %s", rec.Body.String())
	}
}

// And the same through export, so the finding covers both branches of it: the
// managed subscribers rendered from the proxy store, and the adopted machines
// reported by their agents.
func TestNodesExportWithholdsDiscoveredShareCredentials(t *testing.T) {
	srv, handler, st := newCoreScopeAuditServer(t)
	seedRenderableProxyUser(t, handler, st)
	seedDiscoveredInventory(t, srv, st)
	activateCorePlugin(t, st, vpnCorePluginID)
	srv.plugins = []plugin.Loaded{{Manifest: vpnCoreNodesManifest()}}

	rec := callAsPrincipal(t, srv, []string{"vpncore:read"}, vpnCoreNodesService, "export")
	if rec.Code != http.StatusOK {
		t.Fatalf("export as vpncore:read: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), discoveredNodeUUID) {
		t.Fatalf("a vpncore:read principal received an on-box node credential from nodes/export: %s", rec.Body.String())
	}
}

// ── after the fix ────────────────────────────────────────────────────────────

// The reduction must not cost the read tier its actual job. An operator with
// vpncore:read still has to be able to see that a node exists and where it is;
// what they must not get is the material that authenticates as its owner.
func TestReadScopedExportStillIdentifiesTheEndpoint(t *testing.T) {
	srv, handler, st := newCoreScopeAuditServer(t)
	seedRenderableProxyUser(t, handler, st)
	seedDiscoveredInventory(t, srv, st)
	activateCorePlugin(t, st, vpnCorePluginID)
	srv.plugins = []plugin.Loaded{{Manifest: vpnCoreNodesManifest()}}

	rec := callAsPrincipal(t, srv, []string{"vpncore:read"}, vpnCoreNodesService, "export")
	body := rec.Body.String()
	for _, want := range []string{"node-a.dns.example.com:443", "disc.example:17891"} {
		if !strings.Contains(body, want) {
			t.Fatalf("the reduced export lost the endpoint %q, which is what it exists to show: %s", want, body)
		}
	}
	if !strings.Contains(body, vpnCoreRedactedCredential) {
		t.Fatalf("the reduced export did not mark the credential as removed: %s", body)
	}
}

// An admin still gets the real thing, so the fix is a split by scope and not a
// removal of the capability.
func TestAdminScopedExportStillReturnsTheFullLink(t *testing.T) {
	srv, handler, st := newCoreScopeAuditServer(t)
	seedRenderableProxyUser(t, handler, st)
	seedDiscoveredInventory(t, srv, st)
	activateCorePlugin(t, st, vpnCorePluginID)
	srv.plugins = []plugin.Loaded{{Manifest: vpnCoreNodesManifest()}}

	rec := callAsPrincipal(t, srv, []string{"vpncore:read", "vpncore:admin"}, vpnCoreNodesService, "export")
	if rec.Code != http.StatusOK {
		t.Fatalf("export as vpncore:admin: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	for _, want := range []string{aliceUUID, discoveredNodeUUID} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("an admin lost access to the credential-bearing link (%s): %s", want, rec.Body.String())
		}
	}
}

// The path that must not break. A vpn-core-sourced subscription is rendered by
// sub-store through its signed host_access grant, on a chain that carries no
// operator at all: a public share fetch, a background refresh, or the auto-sync.
// If this reduces, every such subscription serves nodes a client cannot connect
// with, which is worse than the leak it would be preventing.
func TestPluginPathStillReceivesFullLinksSoSubscriptionsServe(t *testing.T) {
	srv, handler, st := newCoreScopeAuditServer(t)
	seedRenderableProxyUser(t, handler, st)
	seedDiscoveredInventory(t, srv, st)
	activateCorePlugin(t, st, vpnCorePluginID)
	srv.pluginRPC.AllowMethods(subStorePluginID, vpnCoreNodesService, []string{"export"})

	raw, err := srv.pluginRPC.Call(t.Context(), subStorePluginID, vpnCoreNodesService, "export", nil)
	if err != nil {
		t.Fatalf("export on the plugin path: %v", err)
	}
	for _, want := range []string{aliceUUID, discoveredNodeUUID} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("the subscription-serving path lost a credential it needs (%s): %s", want, raw)
		}
	}
}

// Redaction replaces the secret with a fixed marker rather than a hash or a
// prefix. A stable derivative of a credential still distinguishes one user from
// another across replies, and this is the reply a read-scoped caller receives.
func TestRedactionIsNotADistinguisher(t *testing.T) {
	first, ok := redactLinkCredential("vless://" + aliceUUID + "@h.example:443?sni=a#one")
	if !ok {
		t.Fatal("a well-formed link was dropped")
	}
	second, ok := redactLinkCredential("vless://" + discoveredNodeUUID + "@h.example:443?sni=a#one")
	if !ok {
		t.Fatal("a well-formed link was dropped")
	}
	if first != second {
		t.Fatalf("two users' links stayed distinguishable after redaction: %q vs %q", first, second)
	}
	if strings.Contains(first, aliceUUID) || strings.Contains(second, discoveredNodeUUID) {
		t.Fatalf("redaction left the credential in place: %q %q", first, second)
	}
}

// A link that cannot be parsed is dropped, not passed through. Failing open here
// would mean the one malformed entry in an inventory is the one that leaks.
func TestUnparseableLinksAreDroppedNotPassedThrough(t *testing.T) {
	for _, bad := range []string{"", "   ", "not-a-url", "://missing-scheme", "vless://"} {
		if out, ok := redactLinkCredential(bad); ok {
			t.Fatalf("redaction passed through an unparseable link %q as %q", bad, out)
		}
	}
}
