package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// s2GatewayEnv is a server with one plugin whose subscription service is
// served by a handler the test supplies, one share with a cached body and one
// fresh snapshot, so a gateway call's effect on each is visible.
type s2GatewayEnv struct {
	srv   *Server
	st    *store.Store
	key   subscriptionCacheKey
	calls map[string]int
}

func newS2GatewayEnv(t *testing.T, methods []string, handler func(ctx context.Context, srv *Server, method string) ([]byte, error)) *s2GatewayEnv {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	specs := make([]plugin.InterfaceMethod, 0, len(methods))
	for _, method := range methods {
		specs = append(specs, plugin.InterfaceMethod{Name: method, Effect: plugin.InterfaceEffectWrite, Scopes: []string{"substore:admin"}})
	}
	manifest := plugin.Manifest{Schema: plugin.ManifestSchemaV2, ID: "p", Name: "Subscription store", Type: plugin.TypeSystem, Publisher: "latticenet",
		Interfaces: []plugin.InterfaceContract{{Service: "p/subscription", Backing: plugin.BackingCore, MethodSpecs: specs}}}
	if err := st.UpsertPluginInstallation(model.PluginInstallation{ID: "p", Name: manifest.Name, Type: manifest.Type, Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	share := model.SubscriptionShare{ID: "share-1", Slug: "share-1", Token: strings.Repeat("a", 32), Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "rec"}}
	if err := st.UpsertSubscriptionShare(share); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "rec", Raw: "last-good", FetchedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	srv := &Server{store: st, plugins: []plugin.Loaded{{Manifest: manifest}}, pluginRPC: plugin.NewRPCRegistry(), now: time.Now,
		subscriptionCache: newSubscriptionCache(subscriptionCacheEntries, subscriptionCacheTTL)}
	env := &s2GatewayEnv{srv: srv, st: st, key: subscriptionCacheKey{ShareID: share.ID, Format: "raw"}, calls: map[string]int{}}
	if err := srv.pluginRPC.Register("p", "p/subscription", "v1", methods, func(ctx context.Context, method string, _ []byte) ([]byte, error) {
		env.calls[method]++
		return handler(ctx, srv, method)
	}); err != nil {
		t.Fatal(err)
	}
	return env
}

func (e *s2GatewayEnv) cacheBody() {
	e.srv.subscriptionCache.Put(e.key, []byte("cached body"), "text/plain", "", "hash", time.Now())
}

func (e *s2GatewayEnv) bodyCached() bool {
	_, _, _, ok := e.srv.subscriptionCache.Get(e.key, time.Now())
	return ok
}

func (e *s2GatewayEnv) generation() uint64 {
	state := e.srv.subscriptionPluginMutationStateFor("p")
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.generation
}

func (e *s2GatewayEnv) call(t *testing.T, method string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"id": "p", "service": "p/subscription", "method": method, "payload": map[string]any{}})
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.srv.handlePluginCall(rec, req, principal{Principal: rbac.Principal{Scopes: []string{"substore:admin"}}})
	return rec
}

// gateHeld reports whether the plugin's subscription gate is held: a try to
// take it that must not wait.
func gateHeld(srv *Server) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, release, err := srv.acquireSubscriptionPluginGate(ctx, "p")
	if err != nil {
		return true
	}
	release()
	return false
}

// TestGatewayGatesEveryWriteMethod: every write method of the subscription
// service runs under the plugin's subscription gate with the generation bumped
// around it, the eight that can change what a render reads stale-mark the
// plugin's snapshots and drop its shares' cached bodies, and reorder,
// migrate_record and discard_staged leave every snapshot and body untouched.
func TestGatewayGatesEveryWriteMethod(t *testing.T) {
	writes := append(slices.Clone(subscriptionGateOnlyWriteMethods), subscriptionInvalidatingWriteMethods...)
	if len(writes) != 11 {
		t.Fatalf("the gateway lists %d write methods, the plan names eleven", len(writes))
	}
	for _, want := range []string{"save", "delete", "import", "migrate", "restore", "purge", "reorder", "migrate_store", "migrate_record", "discard_staged", "save_settings"} {
		if !subscriptionWriteMethod(want) {
			t.Fatalf("%s is not on the gateway's write list", want)
		}
	}
	for _, read := range []string{"render", "preview", "list", "get", "probe", "depends_on", "fleet_preview", "identities", "export", "publish"} {
		if subscriptionWriteMethod(read) {
			t.Fatalf("%s is on the gateway's write list", read)
		}
	}
	held := map[string]bool{}
	env := newS2GatewayEnv(t, writes, func(_ context.Context, srv *Server, method string) ([]byte, error) {
		held[method] = gateHeld(srv)
		return []byte(`{"saved":true}`), nil
	})
	for _, method := range writes {
		if err := env.st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "rec", Raw: "last-good", FetchedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		env.cacheBody()
		before := env.generation()
		if rec := env.call(t, method); rec.Code != http.StatusOK {
			t.Fatalf("%s: code %d body %s", method, rec.Code, rec.Body.String())
		}
		if !held[method] {
			t.Fatalf("%s ran without the plugin's subscription gate", method)
		}
		if env.generation() == before {
			t.Fatalf("%s did not bump the plugin generation", method)
		}
		snap, _ := env.st.SubscriptionSnapshot("p", "rec")
		if subscriptionWriteInvalidates(method) {
			if !snap.Stale || env.bodyCached() {
				t.Fatalf("%s left the snapshot fresh (%v) or the body cached (%v)", method, !snap.Stale, env.bodyCached())
			}
			continue
		}
		if snap.Stale || !env.bodyCached() {
			t.Fatalf("%s, a gate-only method, stale-marked the snapshot (%v) or dropped the body (%v)", method, snap.Stale, !env.bodyCached())
		}
	}
	if gateHeld(env.srv) {
		t.Fatal("the gate is still held after the calls")
	}
}

// TestGatewayStripsMutationErrorsOnly: a write method's successful payload,
// including a structured refusal, passes through untouched, while its error
// is replaced with the one fixed string.
func TestGatewayStripsMutationErrorsOnly(t *testing.T) {
	const refused = `{"saved":false,"refused":{"code":"fleet_delete_requires_plan","ids":["rec"],"message":"subscription \"rec\" is fleet-bound; delete it through a plan"}}`
	const canary = "vless://11111111-1111-4111-8111-111111111111@provider.example:443"
	fail := false
	env := newS2GatewayEnv(t, []string{"delete", "reorder"}, func(_ context.Context, _ *Server, method string) ([]byte, error) {
		if fail {
			return nil, errors.New("fleet_delete_requires_plan: " + canary)
		}
		return []byte(refused), nil
	})
	for _, method := range []string{"delete", "reorder"} {
		fail = false
		rec := env.call(t, method)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: a structured refusal answered %d %s", method, rec.Code, rec.Body.String())
		}
		if !jsonEqual(rec.Body.Bytes(), []byte(refused)) {
			t.Fatalf("%s: the successful payload was altered: %s", method, rec.Body.String())
		}
		fail = true
		rec = env.call(t, method)
		if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), canary) || strings.Contains(rec.Body.String(), "fleet_delete_requires_plan") {
			t.Fatalf("%s: the error crossed the gateway: %d %s", method, rec.Code, rec.Body.String())
		}
		replaced := false
		for _, ev := range env.st.AuditEvents() {
			if strings.Contains(ev.Reason, canary) {
				t.Fatalf("%s: the plugin's error reached the audit trail: %+v", method, ev)
			}
			if ev.Decision == "deny" && ev.Reason == "subscription mutation execution failed" {
				replaced = true
			}
		}
		if !replaced {
			t.Fatalf("%s: the error was not replaced with the fixed string", method)
		}
	}
}

func jsonEqual(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	ax, _ := json.Marshal(x)
	by, _ := json.Marshal(y)
	return string(ax) == string(by)
}

// TestGatewayRefusesFetchForOperators: the Sub-Store's fetch answers no
// operator's gateway call, whatever its manifest declares, and every core path
// but the refresh refuses it too; the refresh's own call is admitted.
func TestGatewayRefusesFetchForOperators(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	service := subStorePluginID + "/subscription"
	manifest := plugin.Manifest{Schema: plugin.ManifestSchemaV2, ID: subStorePluginID, Name: "Sub-Store", Type: plugin.TypeSystem, Publisher: "latticenet",
		Interfaces: []plugin.InterfaceContract{{Service: service, Backing: plugin.BackingCore,
			MethodSpecs: []plugin.InterfaceMethod{{Name: "fetch", Effect: plugin.InterfaceEffectRead, Scopes: []string{"substore:admin"}}}}}}
	if err := st.UpsertPluginInstallation(model.PluginInstallation{ID: subStorePluginID, Name: manifest.Name, Type: manifest.Type, Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	srv := &Server{store: st, plugins: []plugin.Loaded{{Manifest: manifest}}, pluginRPC: plugin.NewRPCRegistry(), now: time.Now,
		subscriptionCache: newSubscriptionCache(subscriptionCacheEntries, subscriptionCacheTTL)}
	reached := 0
	if err := srv.pluginRPC.Register(subStorePluginID, service, "v1", []string{"fetch"}, func(context.Context, string, []byte) ([]byte, error) {
		reached++
		return []byte(`{"raw":"envelope"}`), nil
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/call",
		strings.NewReader(`{"id":"`+subStorePluginID+`","service":"`+service+`","method":"fetch","payload":{"subscription_id":"rec"}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.handlePluginCall(rec, req, principal{Principal: rbac.Principal{ActorID: "admin", Scopes: []string{"*"}}})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), subStoreFetchCoreOnlyReason) {
		t.Fatalf("an operator's fetch = %d %s, want 403 with the core-only reason", rec.Code, rec.Body.String())
	}
	if reached != 0 {
		t.Fatal("the operator's fetch reached the plugin")
	}
	denied := false
	for _, ev := range st.AuditEvents() {
		if ev.Decision == "deny" && ev.Reason == subStoreFetchCoreOnlyReason {
			denied = true
		}
	}
	if !denied {
		t.Fatal("the refusal was not audited")
	}

	// A core path without the refresh mark is refused before the runtime.
	srv.pluginRuntime = plugin.NewRuntimeManagerWithOptions(plugin.RuntimeManagerOptions{})
	if _, err := srv.callRuntimePluginService(context.Background(), subStorePluginID, service, "fetch", json.RawMessage(`{}`), nil, nil); !errors.Is(err, errSubStoreFetchCoreOnly) {
		t.Fatalf("an unmarked core fetch = %v, want the core-only refusal", err)
	}
	if err := subStoreCoreOnlyCallAllowed(withSubStoreRefreshCall(context.Background()), "fetch"); err != nil {
		t.Fatalf("the refresh's marked call was refused: %v", err)
	}
	// The mark admits fetch only: it is not an apply grant.
	if err := subStoreCoreOnlyCallAllowed(withSubStoreRefreshCall(context.Background()), subStoreApplyRevisionMethod); !errors.Is(err, errSubStoreCoreOnlyMethod) {
		t.Fatalf("the refresh mark admitted apply_revision: %v", err)
	}
	// Another plugin's fetch is not core-only.
	if subStoreCoreOnlyMethod("latticenet.other/subscription", "fetch") {
		t.Fatal("another plugin's fetch is core-only")
	}
}
