package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// TestPluginInvokeExecutesArtifact proves the Tier-2 system runner is wired and
// actually EXECUTES a plugin artifact end-to-end: load -> activate -> invoke ->
// the artifact's stdout flows back. Uses a node:read (read-risk) system plugin so
// no signature/trust is needed; a shell-script artifact implements the stdio
// {action,payload}->{ok,...} contract.
func TestPluginInvokeExecutesArtifact(t *testing.T) {
	pluginRoot := t.TempDir()
	bundle := filepath.Join(pluginRoot, "test.exec")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "manifest.json"),
		[]byte(`{"id":"test.exec","name":"Exec Test","type":"system","capabilities":["node:read"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Artifact echoes a result derived from the action, proving real execution.
	script := "#!/bin/sh\nread line\necho '{\"ok\":true,\"message\":\"executed\",\"result\":{\"ran\":true}}'\n"
	if err := os.WriteFile(filepath.Join(bundle, "artifact"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{
		Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true,
		PluginDir:        pluginRoot,
		PluginRuntimeDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)

	// verified -> installed -> active (verified->active is rejected by the FSM).
	for _, status := range []string{"installed", "active"} {
		resp := doJSON(t, handler, http.MethodPost, "/api/plugins/lifecycle",
			`{"id":"test.exec","status":"`+status+`"}`, cookies, csrf)
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("lifecycle %s: want 200, got %d (%s)", status, resp.StatusCode, b)
		}
		resp.Body.Close()
	}

	// Invoke -> the artifact runs and returns its JSON.
	inv := doJSON(t, handler, http.MethodPost, "/api/plugins/invoke",
		`{"id":"test.exec","action":"describe"}`, cookies, csrf)
	if inv.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(inv.Body)
		t.Fatalf("invoke: want 200, got %d (%s)", inv.StatusCode, b)
	}
	body, _ := io.ReadAll(inv.Body)
	inv.Body.Close()
	var out struct {
		OK      bool            `json:"ok"`
		Message string          `json:"message"`
		Result  json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	if !out.OK || out.Message != "executed" || string(out.Result) != `{"ran":true}` {
		t.Fatalf("artifact did not execute as expected: %+v (raw %s)", out, body)
	}
}

func TestPluginCallFallsBackToRuntimeArtifact(t *testing.T) {
	pluginRoot := t.TempDir()
	manifest := plugin.Manifest{
		ID: "test.runtime", Name: "Runtime Test", Type: "system", Version: "0.1.0",
		Capabilities: []string{"node:read"},
		Interfaces: []plugin.InterfaceContract{{
			Service: "test.runtime/items",
			Methods: []string{"list"},
			Scopes:  []string{"proxy:read"},
		}},
	}
	script := "#!/bin/sh\nread line\ncase \"$line\" in *'\"action\":\"call\"'*) echo '{\"ok\":true,\"result\":{\"rows\":[{\"id\":\"from-artifact\"}],\"count\":1}}' ;; *) echo '{\"ok\":false,\"message\":\"unexpected action\"}' ;; esac\n"
	writeServerBundle(t, pluginRoot, "test.runtime", manifest, []byte(script))
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{
		Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true,
		PluginDir:        pluginRoot,
		PluginRuntimeDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)
	for _, status := range []string{model.PluginStatusInstalled, model.PluginStatusActive} {
		resp := doJSON(t, handler, http.MethodPost, "/api/plugins/lifecycle",
			`{"id":"test.runtime","status":"`+status+`"}`, cookies, csrf)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("lifecycle %s: got %d", status, resp.StatusCode)
		}
	}

	readToken := createPAT(t, handler, cookies, csrf, []string{"proxy:read"}, nil)
	call := doBearerJSON(t, handler, http.MethodPost, "/api/plugins/call",
		`{"id":"test.runtime","service":"test.runtime/items","method":"list"}`, readToken)
	defer call.Body.Close()
	if call.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(call.Body)
		t.Fatalf("runtime call: want 200, got %d (%s)", call.StatusCode, b)
	}
	var out struct {
		Rows []struct {
			ID string `json:"id"`
		} `json:"rows"`
		Count int `json:"count"`
	}
	if err := json.NewDecoder(call.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Count != 1 || len(out.Rows) != 1 || out.Rows[0].ID != "from-artifact" {
		t.Fatalf("plugin call did not execute artifact: %+v", out)
	}
}

func TestPluginContributionsAndCallGatewayEnforceActionScopes(t *testing.T) {
	pluginRoot := t.TempDir()
	manifest := plugin.Manifest{
		ID: "test.ui", Name: "Test UI", Type: "system", Version: "0.1.0",
		Capabilities: []string{"node:read"},
		Interfaces: []plugin.InterfaceContract{{
			Service: "test.ui/nodes",
			Methods: []string{"list", "delete"},
			Scopes:  []string{"proxy:read"},
		}},
		UI: &plugin.ManifestUI{
			Nav: []plugin.NavContribution{{
				Section: "vpn-manage", SectionTitle: "VPN Manage", Title: "Nodes",
				Route: "vpn-core/nodes", Icon: "Radar", Scopes: []string{"proxy:read"},
			}},
			Views: []plugin.ViewContribution{{
				Route: "vpn-core/nodes", Title: "Nodes", Kind: "table",
				Source: &plugin.ViewSource{Interface: "test.ui/nodes", Method: "list"},
				Actions: []plugin.ViewAction{{
					Label: "Delete", Interface: "test.ui/nodes", Method: "delete", Scopes: []string{"proxy:admin"},
				}},
			}},
		},
	}
	writeServerBundle(t, pluginRoot, "test.ui", manifest, []byte("artifact"))
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, PluginDir: pluginRoot, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.pluginRPC.Register("test.ui", "test.ui/nodes", "v1", []string{"list", "delete"}, func(_ context.Context, method string, _ []byte) ([]byte, error) {
		if method == "list" {
			return []byte(`{"rows":[{"id":"n1"}],"count":1}`), nil
		}
		return []byte(`{"ok":true}`), nil
	}); err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)
	for _, status := range []string{model.PluginStatusInstalled, model.PluginStatusActive} {
		resp := doJSON(t, handler, http.MethodPost, "/api/plugins/lifecycle",
			`{"id":"test.ui","status":"`+status+`"}`, cookies, csrf)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("lifecycle %s: got %d", status, resp.StatusCode)
		}
	}
	readToken := createPAT(t, handler, cookies, csrf, []string{"proxy:read"}, nil)

	contrib := doBearerJSON(t, handler, http.MethodGet, "/api/plugin-contributions", "", readToken)
	if contrib.StatusCode != http.StatusOK {
		t.Fatalf("contributions should be visible with proxy:read, got %d", contrib.StatusCode)
	}
	var plugins []pluginView
	if err := json.NewDecoder(contrib.Body).Decode(&plugins); err != nil {
		t.Fatal(err)
	}
	contrib.Body.Close()
	if len(plugins) != 1 || plugins[0].UI == nil || len(plugins[0].UI.Nav) != 1 || plugins[0].UI.Nav[0].Section != "vpn-manage" {
		t.Fatalf("unexpected contributions: %+v", plugins)
	}
	if got := plugins[0].UI.Views[0].Actions; len(got) != 0 {
		t.Fatalf("proxy:read contribution view must not expose proxy:admin action, got %+v", got)
	}
	if got := plugins[0].Interfaces; len(got) != 1 || len(got[0].Methods) != 1 || got[0].Methods[0] != "list" {
		t.Fatalf("proxy:read contribution response must expose only visible interface methods, got %+v", got)
	}

	restrictedToken := createPAT(t, handler, cookies, csrf, []string{"proxy:read"}, []string{"node-a"})
	restrictedContrib := doBearerJSON(t, handler, http.MethodGet, "/api/plugin-contributions", "", restrictedToken)
	if restrictedContrib.StatusCode != http.StatusOK {
		t.Fatalf("restricted contributions should remain callable, got %d", restrictedContrib.StatusCode)
	}
	var restrictedPlugins []pluginView
	if err := json.NewDecoder(restrictedContrib.Body).Decode(&restrictedPlugins); err != nil {
		t.Fatal(err)
	}
	restrictedContrib.Body.Close()
	if len(restrictedPlugins) != 0 {
		t.Fatalf("server-allowlisted proxy token must not see global proxy plugin views, got %+v", restrictedPlugins)
	}

	list := doBearerJSON(t, handler, http.MethodPost, "/api/plugins/call",
		`{"id":"test.ui","service":"test.ui/nodes","method":"list"}`, readToken)
	list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list should be allowed with proxy:read, got %d", list.StatusCode)
	}
	restrictedList := doBearerJSON(t, handler, http.MethodPost, "/api/plugins/call",
		`{"id":"test.ui","service":"test.ui/nodes","method":"list"}`, restrictedToken)
	restrictedList.Body.Close()
	if restrictedList.StatusCode != http.StatusForbidden {
		t.Fatalf("restricted proxy token must not call global proxy plugin views, got %d", restrictedList.StatusCode)
	}
	denied := doBearerJSON(t, handler, http.MethodPost, "/api/plugins/call",
		`{"id":"test.ui","service":"test.ui/nodes","method":"delete"}`, readToken)
	denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("delete should require action scope proxy:admin, got %d", denied.StatusCode)
	}
	var sawDeny, sawRestrictedDeny bool
	for _, ev := range st.AuditEvents() {
		if ev.Action == "plugin.call" && ev.Decision == "deny" && ev.Metadata["method"] == "delete" && strings.Contains(ev.Scope, "proxy:admin") {
			sawDeny = true
		}
		if ev.Action == "plugin.call" && ev.Decision == "deny" && ev.Metadata["method"] == "list" && strings.Contains(ev.Reason, "unrestricted server allowlist") {
			sawRestrictedDeny = true
		}
	}
	if !sawDeny {
		t.Fatalf("expected plugin.call deny audit for action scope failure, got %+v", st.AuditEvents())
	}
	if !sawRestrictedDeny {
		t.Fatalf("expected plugin.call deny audit for restricted proxy token, got %+v", st.AuditEvents())
	}
}

func TestPluginCallV2UsesExactMethodScopes(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	manifest := plugin.Manifest{
		Schema: plugin.ManifestSchemaV2, ID: "test.v2", Name: "V2", Type: plugin.TypeSystem,
		Interfaces: []plugin.InterfaceContract{{
			Service: "test.v2/items",
			Backing: plugin.BackingRuntime,
			MethodSpecs: []plugin.InterfaceMethod{
				{Name: "list", Effect: plugin.InterfaceEffectRead, Scopes: []string{"proxy:read"}},
				{Name: "save", Effect: plugin.InterfaceEffectWrite, Scopes: []string{"proxy:admin"}, OperatorTargetFields: []string{"base_url"}},
			},
		}},
		UI: &plugin.ManifestUI{
			Nav:   []plugin.NavContribution{{Section: "extensions", Title: "V2", Route: "items", Scopes: []string{"proxy:read"}}},
			Views: []plugin.ViewContribution{{Route: "items", Title: "V2", Kind: "sandbox"}},
		},
	}
	if err := st.UpsertPluginInstallation(model.PluginInstallation{ID: manifest.ID, Name: manifest.Name, Type: manifest.Type, Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	srv := &Server{store: st, plugins: []plugin.Loaded{{Manifest: manifest}}}
	if got, ok := srv.pluginCallScopes(manifest.ID, "test.v2/items", "list"); !ok || len(got) != 1 || got[0] != "proxy:read" {
		t.Fatalf("read method scopes wrong: scopes=%v declared=%v", got, ok)
	}
	if got, ok := srv.pluginCallScopes(manifest.ID, "test.v2/items", "save"); !ok || len(got) != 1 || got[0] != "proxy:admin" {
		t.Fatalf("write method scopes wrong: scopes=%v declared=%v", got, ok)
	}
	if got, ok := srv.pluginCallMethod(manifest.ID, "test.v2/items", "save"); !ok || len(got.OperatorTargetFields) != 1 || got.OperatorTargetFields[0] != "base_url" {
		t.Fatalf("operator target fields were not preserved: contract=%+v declared=%v", got, ok)
	}

	readPrincipal := principal{Principal: rbac.Principal{Scopes: []string{"proxy:read"}}}
	filteredUI := filterPluginUIForPrincipal(manifest.UI, manifest.Interfaces, readPrincipal)
	filtered := filterPluginInterfacesForUI(filteredUI, manifest.Interfaces, readPrincipal)
	if len(filtered) != 1 || len(filtered[0].MethodSpecs) != 1 || filtered[0].MethodSpecs[0].Name != "list" {
		t.Fatalf("read principal saw unauthorized v2 methods: %+v", filtered)
	}
	adminPrincipal := principal{Principal: rbac.Principal{Scopes: []string{"proxy:read", "proxy:admin"}}}
	filtered = filterPluginInterfacesForUI(filterPluginUIForPrincipal(manifest.UI, manifest.Interfaces, adminPrincipal), manifest.Interfaces, adminPrincipal)
	if len(filtered) != 1 || len(filtered[0].MethodSpecs) != 2 {
		t.Fatalf("admin principal did not see both v2 methods: %+v", filtered)
	}
}

func TestPluginCallV2DispatchesOwnedCoreService(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	manifest := plugin.Manifest{
		Schema: plugin.ManifestSchemaV2, ID: "test.v2-owned", Name: "V2 owned", Type: plugin.TypeSystem,
		Publisher: "latticenet",
		Interfaces: []plugin.InterfaceContract{{
			Service: "test.v2-owned/items",
			Backing: plugin.BackingCore,
			MethodSpecs: []plugin.InterfaceMethod{{
				Name: "list", Effect: plugin.InterfaceEffectRead, Scopes: []string{"proxy:read"},
			}},
		}},
	}
	if err := st.UpsertPluginInstallation(model.PluginInstallation{
		ID: manifest.ID, Name: manifest.Name, Type: manifest.Type, Status: model.PluginStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		store:     st,
		plugins:   []plugin.Loaded{{Manifest: manifest}},
		pluginRPC: plugin.NewRPCRegistry(),
	}
	if err := srv.pluginRPC.Register(manifest.ID, "test.v2-owned/items", "v1", []string{"list"},
		func(_ context.Context, _ string, _ []byte) ([]byte, error) {
			return []byte(`{"rows":[{"id":"from-core"}]}`), nil
		}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", strings.NewReader(
		`{"id":"test.v2-owned","service":"test.v2-owned/items","method":"list"}`,
	))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.handlePluginCall(rec, req, principal{Principal: rbac.Principal{Scopes: []string{"proxy:read"}}})
	if rec.Code != http.StatusOK {
		t.Fatalf("owned v2 core service: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "from-core") {
		t.Fatalf("owned v2 call did not reach core service: %s", rec.Body.String())
	}
}

func TestPluginCallV2DoesNotDispatchCoreServiceForForeignPublisher(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	manifest := plugin.Manifest{
		Schema: plugin.ManifestSchemaV2, ID: "test.v2-foreign", Name: "V2 foreign", Type: plugin.TypeSystem,
		Publisher: "other",
		Interfaces: []plugin.InterfaceContract{{
			Service: "test.v2-foreign/items",
			Backing: plugin.BackingRuntime,
			MethodSpecs: []plugin.InterfaceMethod{{
				Name: "list", Effect: plugin.InterfaceEffectRead, Scopes: []string{"proxy:read"},
			}},
		}},
	}
	if err := st.UpsertPluginInstallation(model.PluginInstallation{
		ID: manifest.ID, Name: manifest.Name, Type: manifest.Type, Status: model.PluginStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	called := false
	srv := &Server{
		store: st, plugins: []plugin.Loaded{{Manifest: manifest}}, pluginRPC: plugin.NewRPCRegistry(),
	}
	if err := srv.pluginRPC.Register(manifest.ID, "test.v2-foreign/items", "v1", []string{"list"},
		func(_ context.Context, _ string, _ []byte) ([]byte, error) {
			called = true
			return []byte(`{"rows":[]}`), nil
		}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", strings.NewReader(
		`{"id":"test.v2-foreign","service":"test.v2-foreign/items","method":"list"}`,
	))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.handlePluginCall(rec, req, principal{Principal: rbac.Principal{Scopes: []string{"proxy:read"}}})
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("foreign publisher must not reach core service: got %d (%s)", rec.Code, rec.Body.String())
	}
	if called {
		t.Fatal("foreign publisher reached an in-core RPC handler")
	}
}

func TestPluginSubscriptionMutationRejectsFetchAfterLastShareDeletion(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	manifest := plugin.Manifest{
		Schema: plugin.ManifestSchemaV2, ID: "p", Name: "Subscription store", Type: plugin.TypeSystem,
		Publisher: "latticenet",
		Interfaces: []plugin.InterfaceContract{{
			Service: "p/subscription", Backing: plugin.BackingCore,
			MethodSpecs: []plugin.InterfaceMethod{{Name: "save", Effect: plugin.InterfaceEffectWrite, Scopes: []string{"proxy:read"}}},
		}},
	}
	if err := st.UpsertPluginInstallation(model.PluginInstallation{ID: "p", Name: manifest.Name, Type: manifest.Type, Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	share := model.SubscriptionShare{ID: "share", Slug: "share", Token: strings.Repeat("a", 32), Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "graph"}}
	if err := st.UpsertSubscriptionShare(share); err != nil {
		t.Fatal(err)
	}
	base := model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "graph", Raw: "base", FetchedAt: time.Now().UTC()}
	if err := st.UpsertSubscriptionSnapshot(base); err != nil {
		t.Fatal(err)
	}
	srv := &Server{store: st, plugins: []plugin.Loaded{{Manifest: manifest}}, pluginRPC: plugin.NewRPCRegistry(),
		now: time.Now, subscriptionCache: newSubscriptionCache(subscriptionCacheEntries, subscriptionCacheTTL)}
	mutationStarted, releaseMutation := make(chan struct{}), make(chan struct{})
	if err := srv.pluginRPC.Register("p", "p/subscription", "v1", []string{"save"},
		func(_ context.Context, _ string, _ []byte) ([]byte, error) {
			close(mutationStarted)
			<-releaseMutation
			return []byte(`{"ok":true}`), nil
		}); err != nil {
		t.Fatal(err)
	}
	fetchStarted, releaseFetch := make(chan struct{}), make(chan struct{})
	fetchCalls := 0
	srv.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		fetchCalls++
		if fetchCalls == 1 {
			close(fetchStarted)
			<-releaseFetch
			return model.SubscriptionSnapshot{Raw: "captured-before-mutation"}, nil
		}
		return model.SubscriptionSnapshot{Raw: "after-mutation"}, nil
	}
	fetchDone := make(chan error, 1)
	go func() { _, err := srv.snapshotFor(context.Background(), "p", "graph", true); fetchDone <- err }()
	<-fetchStarted
	if err := st.DeleteSubscriptionShare("share"); err != nil {
		t.Fatal(err)
	}
	callDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", strings.NewReader(`{"id":"p","service":"p/subscription","method":"save","payload":{}}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.handlePluginCall(rec, req, principal{Principal: rbac.Principal{Scopes: []string{"proxy:read"}}})
		callDone <- rec
	}()
	<-mutationStarted
	close(releaseFetch)
	close(releaseMutation)
	if rec := <-callDone; rec.Code != http.StatusOK {
		t.Fatalf("mutation response code=%d body=%q", rec.Code, rec.Body.String())
	}
	if err := <-fetchDone; err == nil || !strings.Contains(err.Error(), "plugin changed") {
		t.Fatalf("pre-mutation fetch error=%v", err)
	}
	stored, _ := st.SubscriptionSnapshot("p", "graph")
	if stored.Raw != "base" {
		t.Fatalf("obsolete fetch became durable authority: %+v", stored)
	}
	if err := st.UpsertSubscriptionShare(share); err != nil {
		t.Fatal(err)
	}
	got, err := srv.snapshotFor(context.Background(), "p", "graph", false)
	if err != nil || got.Raw != "after-mutation" || fetchCalls != 2 {
		t.Fatalf("recreated share snapshot=%+v calls=%d err=%v", got, fetchCalls, err)
	}
}

func TestGraphSaveWaitsForPluginGateBeforeTakingAuthorityRead(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	manifest := plugin.Manifest{Schema: plugin.ManifestSchemaV2, ID: "p", Name: "Subscription store", Type: plugin.TypeSystem, Publisher: "latticenet",
		Interfaces: []plugin.InterfaceContract{{Service: "p/subscription", Backing: plugin.BackingCore,
			MethodSpecs: []plugin.InterfaceMethod{{Name: "save", Effect: plugin.InterfaceEffectWrite, Scopes: []string{"proxy:read"}}}}}}
	if err := st.UpsertPluginInstallation(model.PluginInstallation{ID: "p", Name: manifest.Name, Type: manifest.Type, Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	srv := &Server{store: st, plugins: []plugin.Loaded{{Manifest: manifest}}, pluginRPC: plugin.NewRPCRegistry(), now: time.Now,
		subscriptionCache: newSubscriptionCache(subscriptionCacheEntries, subscriptionCacheTTL)}
	if err := srv.pluginRPC.Register("p", "p/subscription", "v1", []string{"save"}, func(context.Context, string, []byte) ([]byte, error) {
		return []byte(`{"ok":true}`), nil
	}); err != nil {
		t.Fatal(err)
	}
	_, releaseGate, err := srv.acquireSubscriptionPluginGate(context.Background(), "p")
	if err != nil {
		t.Fatal(err)
	}
	waiter := make(chan struct{}, 1)
	srv.subscriptionPluginGateWaiter = waiter
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", strings.NewReader(`{"id":"p","service":"p/subscription","method":"save","payload":{}}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.handlePluginCall(rec, req, principal{Principal: rbac.Principal{Scopes: []string{"proxy:read"}}})
		done <- rec
	}()
	<-waiter
	state := srv.subscriptionGraphAuthorityFor(vpnCorePluginID)
	if !state.mu.TryLock() {
		releaseGate()
		t.Fatal("graph save held R while waiting for the plugin mutation gate")
	}
	state.mu.Unlock()
	releaseGate()
	if rec := <-done; rec.Code != http.StatusOK {
		t.Fatalf("save response code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func graphAuthorityPluginFixture(t *testing.T, methods []string) (*Server, string, string, VpnUser) {
	t.Helper()
	srv, sourceUUID, _, user, _ := seedLineChainFixture(t)
	manifest := plugin.Manifest{Schema: plugin.ManifestSchemaV2, ID: "p", Name: "Subscription store", Type: plugin.TypeSystem, Publisher: "latticenet",
		Interfaces: []plugin.InterfaceContract{{Service: "p/subscription", Backing: plugin.BackingCore,
			MethodSpecs: []plugin.InterfaceMethod{}}}}
	for _, method := range methods {
		manifest.Interfaces[0].MethodSpecs = append(manifest.Interfaces[0].MethodSpecs,
			plugin.InterfaceMethod{Name: method, Effect: plugin.InterfaceEffectWrite, Scopes: []string{"proxy:read"}})
	}
	if err := srv.store.UpsertPluginInstallation(model.PluginInstallation{ID: "p", Name: manifest.Name, Type: manifest.Type, Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	srv.plugins = append(srv.plugins, plugin.Loaded{Manifest: manifest})
	srv.pluginRPC = plugin.NewRPCRegistry()
	options, err := srv.vpnCoreSubscriptionSourcesRPC(context.Background(), "graph_options", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	var decoded graphSubscriptionOptionsResponse
	if err := json.Unmarshal(options, &decoded); err != nil || !decoded.OK {
		t.Fatalf("initial graph options: %s err=%v", options, err)
	}
	return srv, decoded.OptionsVersion, sourceUUID, user
}

func invokeGraphPlugin(t *testing.T, srv *Server, method, payload string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", strings.NewReader(fmt.Sprintf(`{"id":"p","service":"p/subscription","method":%q,"payload":%s}`, method, payload)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.handlePluginCall(rec, req, principal{Principal: rbac.Principal{Scopes: []string{"proxy:read"}}})
	return rec
}

func TestGraphMutationFirstMakesLaterSaveObserveNewOptionsAndWriteNothing(t *testing.T) {
	srv, expected, _, user := graphAuthorityPluginFixture(t, []string{"save"})
	if err := srv.pluginRPC.Register("p", "p/subscription", "v1", []string{"save"}, func(ctx context.Context, _ string, _ []byte) ([]byte, error) {
		wire, err := srv.vpnCoreSubscriptionSourcesRPC(ctx, "graph_options", []byte(`{}`))
		if err != nil {
			return nil, err
		}
		var options graphSubscriptionOptionsResponse
		if err := json.Unmarshal(wire, &options); err != nil || options.OptionsVersion != expected {
			return nil, errors.New("graph options changed")
		}
		if err := srv.store.PutKV(model.KVEntry{Bucket: "plugin:p", Key: "saved", Value: `{"ok":true}`}); err != nil {
			return nil, err
		}
		return []byte(`{"ok":true}`), nil
	}); err != nil {
		t.Fatal(err)
	}
	state := srv.subscriptionGraphAuthorityFor(vpnCorePluginID)
	state.mu.Lock()
	public, private := splitVpnUserRecord(user)
	public.Name = "changed after options review"
	if err := srv.store.PutVpnUserRecord(public, private); err != nil {
		state.mu.Unlock()
		t.Fatal(err)
	}
	readWaiter := make(chan struct{}, 1)
	srv.subscriptionGraphReadWaiter = readWaiter
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- invokeGraphPlugin(t, srv, "save", `{}`) }()
	<-readWaiter
	if _, ok := srv.store.KVEntry("plugin:p", "saved"); ok {
		state.mu.Unlock()
		t.Fatal("save wrote before mutation publication released")
	}
	state.mu.Unlock()
	rec := <-done
	if rec.Code == http.StatusOK {
		t.Fatalf("stale save unexpectedly succeeded: %s", rec.Body.String())
	}
	if _, ok := srv.store.KVEntry("plugin:p", "saved"); ok {
		t.Fatal("stale save published KV state")
	}
}

func TestGraphSaveHoldsOneAuthorityReadThroughDurableCommit(t *testing.T) {
	srv, _, _, _ := graphAuthorityPluginFixture(t, []string{"save"})
	validated, allowCommit := make(chan struct{}), make(chan struct{})
	if err := srv.pluginRPC.Register("p", "p/subscription", "v1", []string{"save"}, func(ctx context.Context, _ string, _ []byte) ([]byte, error) {
		if _, err := srv.vpnCoreSubscriptionSourcesRPC(ctx, "graph_options", []byte(`{}`)); err != nil {
			return nil, err
		}
		close(validated)
		<-allowCommit
		if err := srv.store.PutKV(model.KVEntry{Bucket: "plugin:p", Key: "saved", Value: `{"ok":true}`}); err != nil {
			return nil, err
		}
		return []byte(`{"ok":true}`), nil
	}); err != nil {
		t.Fatal(err)
	}
	saveDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { saveDone <- invokeGraphPlugin(t, srv, "save", `{}`) }()
	<-validated
	writeWaiter := make(chan struct{}, 1)
	srv.subscriptionGraphWriteWaiter = writeWaiter
	mutationDone := make(chan struct{})
	go func() {
		_ = srv.withSubscriptionGraphWriteErr(vpnCorePluginID, func() error { return nil })
		close(mutationDone)
	}()
	<-writeWaiter
	close(allowCommit)
	if rec := <-saveDone; rec.Code != http.StatusOK {
		t.Fatalf("save failed: %d %s", rec.Code, rec.Body.String())
	}
	<-mutationDone
	if _, ok := srv.store.KVEntry("plugin:p", "saved"); !ok {
		t.Fatal("durable save commit missing")
	}
}

func TestGraphPreviewOptionsAndComposeShareOuterAuthorityRead(t *testing.T) {
	srv, _, sourceUUID, user := graphAuthorityPluginFixture(t, []string{"preview"})
	between, continueCompose := make(chan struct{}), make(chan struct{})
	if err := srv.pluginRPC.Register("p", "p/subscription", "v1", []string{"preview"}, func(ctx context.Context, _ string, _ []byte) ([]byte, error) {
		if _, err := srv.vpnCoreSubscriptionSourcesRPC(ctx, "graph_options", []byte(`{}`)); err != nil {
			return nil, err
		}
		close(between)
		<-continueCompose
		return srv.vpnCoreSubscriptionSourcesRPC(ctx, "compose", []byte(fmt.Sprintf(`{"schema_version":1,"identity_id":%q,"entry_roots":[%q]}`, user.ID, sourceUUID)))
	}); err != nil {
		t.Fatal(err)
	}
	previewDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { previewDone <- invokeGraphPlugin(t, srv, "preview", `{}`) }()
	<-between
	writeWaiter := make(chan struct{}, 1)
	srv.subscriptionGraphWriteWaiter = writeWaiter
	mutationDone := make(chan struct{})
	go func() {
		_ = srv.withSubscriptionGraphWriteErr(vpnCorePluginID, func() error { return nil })
		close(mutationDone)
	}()
	<-writeWaiter
	close(continueCompose)
	if rec := <-previewDone; rec.Code != http.StatusOK {
		t.Fatalf("preview failed: %d %s", rec.Code, rec.Body.String())
	}
	<-mutationDone
}

func TestGraphSaveCommitFailurePublishesNoKVAndReleasesAuthority(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "state")
	st, err := store.Open(filepath.Join(parent, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := plugin.Manifest{Schema: plugin.ManifestSchemaV2, ID: "p", Name: "Subscription store", Type: plugin.TypeSystem, Publisher: "latticenet",
		Interfaces: []plugin.InterfaceContract{{Service: "p/subscription", Backing: plugin.BackingCore,
			MethodSpecs: []plugin.InterfaceMethod{{Name: "save", Effect: plugin.InterfaceEffectWrite, Scopes: []string{"proxy:read"}}}}}}
	if err := st.UpsertPluginInstallation(model.PluginInstallation{ID: "p", Name: manifest.Name, Type: manifest.Type, Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	srv := &Server{store: st, plugins: []plugin.Loaded{{Manifest: manifest}}, pluginRPC: plugin.NewRPCRegistry(), now: time.Now,
		singboxInv: map[string]model.SingBoxInventory{}, agentCapabilities: map[string]map[string]struct{}{}, logger: log.New(io.Discard, "", 0)}
	if err := srv.pluginRPC.Register("p", "p/subscription", "v1", []string{"save"}, func(ctx context.Context, _ string, _ []byte) ([]byte, error) {
		if _, err := srv.vpnCoreSubscriptionSourcesRPC(ctx, "graph_options", []byte(`{}`)); err != nil {
			return nil, err
		}
		if err := os.RemoveAll(parent); err != nil {
			return nil, err
		}
		if err := os.WriteFile(parent, []byte("blocks mkdir"), 0o600); err != nil {
			return nil, err
		}
		return nil, srv.store.PutKV(model.KVEntry{Bucket: "plugin:p", Key: "saved", Value: `{"must_not_publish":true}`})
	}); err != nil {
		t.Fatal(err)
	}
	if rec := invokeGraphPlugin(t, srv, "save", `{}`); rec.Code == http.StatusOK {
		t.Fatalf("failed commit returned success: %s", rec.Body.String())
	}
	if _, ok := srv.store.KVEntry("plugin:p", "saved"); ok {
		t.Fatal("failed commit published KV state")
	}
	state := srv.subscriptionGraphAuthorityFor(vpnCorePluginID)
	if !state.mu.TryLock() {
		t.Fatal("failed save retained graph authority read")
	}
	state.mu.Unlock()
}

func TestLegacyVPNCorePreviewDoesNotUpgradeGraphReadForStalePruning(t *testing.T) {
	srv, _, _, _ := graphAuthorityPluginFixture(t, []string{"preview"})
	const staleNode = "stale-preview-node"
	if err := srv.store.UpsertNode(model.Node{ID: staleNode, Name: staleNode}); err != nil {
		t.Fatal(err)
	}
	srv.singboxInvMu.Lock()
	srv.singboxInv[staleNode] = model.SingBoxInventory{NodeID: staleNode, At: srv.now().Add(-nodeOfflineThreshold - time.Minute), Status: "ok"}
	srv.singboxInvMu.Unlock()
	skipped := make(chan struct{}, 1)
	srv.subscriptionGraphPruneSkipped = skipped
	if err := srv.pluginRPC.Register("p", "p/subscription", "v1", []string{"preview"}, func(ctx context.Context, _ string, _ []byte) ([]byte, error) {
		return srv.vpnCoreNodesRPC(ctx, "export", []byte(`{"include_managed":false}`))
	}); err != nil {
		t.Fatal(err)
	}
	rec := invokeGraphPlugin(t, srv, "preview", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy preview failed: %d %s", rec.Code, rec.Body.String())
	}
	select {
	case <-skipped:
	default:
		t.Fatal("nested nodes export did not skip the graph-authority prune upgrade")
	}
	if _, ok := srv.singBoxInventory(staleNode); !ok {
		t.Fatal("optional stale prune ran while the outer graph read was held")
	}
}

func TestPluginSubscriptionMutationPanicReleasesGate(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	manifest := plugin.Manifest{Schema: plugin.ManifestSchemaV2, ID: "p", Name: "Subscription store", Type: plugin.TypeSystem, Publisher: "latticenet",
		Interfaces: []plugin.InterfaceContract{{Service: "p/subscription", Backing: plugin.BackingCore,
			MethodSpecs: []plugin.InterfaceMethod{{Name: "save", Effect: plugin.InterfaceEffectWrite, Scopes: []string{"proxy:read"}}}}}}
	if err := st.UpsertPluginInstallation(model.PluginInstallation{ID: "p", Name: manifest.Name, Type: manifest.Type, Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	srv := &Server{store: st, plugins: []plugin.Loaded{{Manifest: manifest}}, pluginRPC: plugin.NewRPCRegistry(), now: time.Now,
		subscriptionCache: newSubscriptionCache(subscriptionCacheEntries, subscriptionCacheTTL)}
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "graph", Raw: "before-panic", FetchedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSubscriptionShare(model.SubscriptionShare{ID: "active", Slug: "active", Token: strings.Repeat("a", 32), Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "graph"}}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	if err := srv.pluginRPC.Register("p", "p/subscription", "v1", []string{"save"}, func(context.Context, string, []byte) ([]byte, error) {
		calls++
		if calls == 1 {
			panic("uncooperative plugin panic")
		}
		return []byte(`{"ok":true}`), nil
	}); err != nil {
		t.Fatal(err)
	}
	invoke := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", strings.NewReader(`{"id":"p","service":"p/subscription","method":"save","payload":{}}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.handlePluginCall(rec, req, principal{Principal: rbac.Principal{Scopes: []string{"proxy:read"}}})
		return rec
	}
	panicResponse := invoke()
	if panicResponse.Code == http.StatusOK || strings.Contains(panicResponse.Body.String(), "uncooperative plugin panic") {
		t.Fatalf("plugin panic was not safely classified code=%d body=%q", panicResponse.Code, panicResponse.Body.String())
	}
	if snapshot, ok := st.SubscriptionSnapshot("p", "graph"); !ok || !snapshot.Stale || snapshot.FetchError != "source_mutated" {
		t.Fatalf("failed plugin mutation did not retain conservative stale authority: %+v ok=%v", snapshot, ok)
	}
	recovered := invoke()
	if recovered.Code != http.StatusOK || calls != 2 {
		t.Fatalf("mutation gate stranded after panic code=%d calls=%d body=%q", recovered.Code, calls, recovered.Body.String())
	}
	srv.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		return model.SubscriptionSnapshot{Raw: "after-success"}, nil
	}
	refreshed, err := srv.snapshotFor(context.Background(), "p", "graph", false)
	if err != nil || refreshed.Raw != "after-success" || refreshed.Stale {
		t.Fatalf("fresh pre-mutation snapshot was reused after successful mutation: %+v err=%v", refreshed, err)
	}
}

func TestPluginSubscriptionMutationPersistenceFailurePreventsDispatch(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	manifest := plugin.Manifest{Schema: plugin.ManifestSchemaV2, ID: "p", Name: "Subscription store", Type: plugin.TypeSystem, Publisher: "latticenet",
		Interfaces: []plugin.InterfaceContract{{Service: "p/subscription", Backing: plugin.BackingCore,
			MethodSpecs: []plugin.InterfaceMethod{{Name: "save", Effect: plugin.InterfaceEffectWrite, Scopes: []string{"proxy:read"}}}}}}
	if err := st.UpsertPluginInstallation(model.PluginInstallation{ID: "p", Name: manifest.Name, Type: manifest.Type, Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	called := false
	srv := &Server{store: st, plugins: []plugin.Loaded{{Manifest: manifest}}, pluginRPC: plugin.NewRPCRegistry(), now: time.Now,
		subscriptionCache:           newSubscriptionCache(subscriptionCacheEntries, subscriptionCacheTTL),
		subscriptionMutationPersist: func(string, time.Time) (bool, error) { return false, errors.New("disk secret") }}
	if err := srv.pluginRPC.Register("p", "p/subscription", "v1", []string{"save"}, func(context.Context, string, []byte) ([]byte, error) {
		called = true
		return []byte(`{"ok":true}`), nil
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", strings.NewReader(`{"id":"p","service":"p/subscription","method":"save","payload":{}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.handlePluginCall(rec, req, principal{Principal: rbac.Principal{Scopes: []string{"proxy:read"}}})
	if rec.Code == http.StatusOK || called || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("persistence failure dispatched=%v code=%d body=%q", called, rec.Code, rec.Body.String())
	}
}

func TestPluginSubscriptionMutationCommittedPersistenceErrorPublishesStaleAuthority(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	manifest := plugin.Manifest{Schema: plugin.ManifestSchemaV2, ID: "p", Name: "Subscription store", Type: plugin.TypeSystem, Publisher: "latticenet",
		Interfaces: []plugin.InterfaceContract{{Service: "p/subscription", Backing: plugin.BackingCore,
			MethodSpecs: []plugin.InterfaceMethod{{Name: "save", Effect: plugin.InterfaceEffectWrite, Scopes: []string{"proxy:read"}}}}}}
	if err := st.UpsertPluginInstallation(model.PluginInstallation{ID: "p", Name: manifest.Name, Type: manifest.Type, Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	share := model.SubscriptionShare{ID: "share", Slug: "share", Token: strings.Repeat("a", 32), Enabled: true, DefaultFormat: "plain",
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "graph"}}
	if err := st.UpsertSubscriptionShare(share); err != nil {
		t.Fatal(err)
	}
	base := model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "graph", Raw: "fresh", FetchedAt: time.Now().UTC()}
	if err := st.UpsertSubscriptionSnapshot(base); err != nil {
		t.Fatal(err)
	}
	called := false
	canary := "vless://11111111-1111-4111-8111-111111111111?private_key=durability-secret"
	srv := &Server{store: st, plugins: []plugin.Loaded{{Manifest: manifest}}, pluginRPC: plugin.NewRPCRegistry(), now: time.Now,
		subscriptionCache: newSubscriptionCache(subscriptionCacheEntries, subscriptionCacheTTL)}
	key := subscriptionCacheKey{ShareID: "share", Format: "plain", UAClass: "surge"}
	srv.subscriptionCache.PutSnapshot(key, []byte("old-body"), "text/plain", "", subscriptionRevalidationVersion(base), "", false, base.FetchedAt, time.Now())
	publication := srv.subscriptionPublicationStateFor(subscriptionRefreshKey{pluginID: "p", subscriptionID: "graph"})
	publication.mu.Lock()
	beforeEpoch := publication.epoch
	publication.mu.Unlock()
	srv.subscriptionMutationPersist = func(pluginID string, now time.Time) (bool, error) {
		committed, err := st.MarkPluginSubscriptionSnapshotsStale(pluginID, now)
		if err != nil {
			return committed, err
		}
		return true, errors.New(canary)
	}
	if err := srv.pluginRPC.Register("p", "p/subscription", "v1", []string{"save"}, func(context.Context, string, []byte) ([]byte, error) {
		called = true
		return []byte(`{"ok":true}`), nil
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", strings.NewReader(`{"id":"p","service":"p/subscription","method":"save","payload":{}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.handlePluginCall(rec, req, principal{Principal: rbac.Principal{Scopes: []string{"proxy:read"}}})
	if rec.Code == http.StatusOK || called || strings.Contains(rec.Body.String(), canary) {
		t.Fatalf("committed persistence error dispatched=%v code=%d body=%q", called, rec.Code, rec.Body.String())
	}
	publication.mu.Lock()
	afterEpoch := publication.epoch
	publication.mu.Unlock()
	if afterEpoch != beforeEpoch+1 {
		t.Fatalf("committed mutation epoch=%d want=%d", afterEpoch, beforeEpoch+1)
	}
	if _, ok := srv.subscriptionCache.GetStale(key); ok {
		t.Fatal("committed mutation durability error left old cache visible")
	}
	if snapshot, ok := st.SubscriptionSnapshot("p", "graph"); !ok || !snapshot.Stale || snapshot.FetchError != "source_mutated" {
		t.Fatalf("committed stale authority=%+v ok=%v", snapshot, ok)
	}
	for _, event := range st.AuditEvents() {
		if strings.Contains(event.Reason+fmt.Sprint(event.Metadata), canary) {
			t.Fatalf("durability diagnostic reached audit: %+v", event)
		}
	}
}

func TestPluginSubscriptionMutationDiagnosticsAreContainedAtHTTPBoundary(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	manifest := plugin.Manifest{Schema: plugin.ManifestSchemaV2, ID: "p", Name: "Subscription store", Type: plugin.TypeSystem, Publisher: "latticenet",
		Interfaces: []plugin.InterfaceContract{{Service: "p/subscription", Backing: plugin.BackingCore,
			MethodSpecs: []plugin.InterfaceMethod{{Name: "save", Effect: plugin.InterfaceEffectWrite, Scopes: []string{"proxy:read"}}}}}}
	if err := st.UpsertPluginInstallation(model.PluginInstallation{ID: "p", Name: manifest.Name, Type: manifest.Type, Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "graph", Raw: "last-good", FetchedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	panicCanary := "vless://11111111-1111-4111-8111-111111111111?private_key=panic-secret"
	errorCanary := "lat$1$error-secret-private-key"
	var runtimeLog bytes.Buffer
	srv := &Server{store: st, plugins: []plugin.Loaded{{Manifest: manifest}}, pluginRPC: plugin.NewRPCRegistry(), now: time.Now,
		logger: log.New(&runtimeLog, "", 0), subscriptionCache: newSubscriptionCache(subscriptionCacheEntries, subscriptionCacheTTL)}
	calls := 0
	if err := srv.pluginRPC.Register("p", "p/subscription", "v1", []string{"save"}, func(context.Context, string, []byte) ([]byte, error) {
		calls++
		switch calls {
		case 1:
			panic(panicCanary)
		case 2:
			return nil, errors.New(errorCanary)
		default:
			return []byte(`{"ok":true}`), nil
		}
	}); err != nil {
		t.Fatal(err)
	}
	var httpLog bytes.Buffer
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.handlePluginCall(w, r, principal{Principal: rbac.Principal{Scopes: []string{"proxy:read"}}})
	})
	ts := httptest.NewUnstartedServer(handler)
	ts.Config.ErrorLog = log.New(&httpLog, "", 0)
	ts.Start()
	defer ts.Close()
	invoke := func() (int, string, error) {
		resp, err := http.Post(ts.URL, "application/json", strings.NewReader(`{"id":"p","service":"p/subscription","method":"save","payload":{}}`))
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body), err
	}
	for attempt := 1; attempt <= 3; attempt++ {
		code, body, err := invoke()
		if err != nil {
			t.Fatalf("mutation attempt %d transport error: %v", attempt, err)
		}
		if attempt < 3 && code == http.StatusOK {
			t.Fatalf("mutation diagnostic attempt %d returned success body=%q", attempt, body)
		}
		if attempt == 3 && code != http.StatusOK {
			t.Fatalf("gate did not recover code=%d body=%q", code, body)
		}
		if strings.Contains(body, panicCanary) || strings.Contains(body, errorCanary) {
			t.Fatalf("mutation diagnostic leaked in response: %q", body)
		}
	}
	snapshot, ok := st.SubscriptionSnapshot("p", "graph")
	if !ok || !snapshot.Stale || snapshot.FetchError != "source_mutated" {
		t.Fatalf("mutation diagnostics lost stale authority: %+v ok=%v", snapshot, ok)
	}
	evidence, err := json.Marshal(struct {
		Snapshots []model.SubscriptionSnapshot `json:"snapshots"`
		Audits    []model.AuditEvent           `json:"audits"`
	}{st.SubscriptionSnapshots(), st.AuditEvents()})
	if err != nil {
		t.Fatal(err)
	}
	all := string(evidence) + runtimeLog.String() + httpLog.String()
	if strings.Contains(all, panicCanary) || strings.Contains(all, errorCanary) {
		t.Fatalf("mutation diagnostic leaked outside protected boundary: %s", all)
	}
}

func TestPluginSubscriptionMutationCanceledWhileQueuedDoesNotDispatch(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	manifest := plugin.Manifest{Schema: plugin.ManifestSchemaV2, ID: "p", Name: "Subscription store", Type: plugin.TypeSystem, Publisher: "latticenet",
		Interfaces: []plugin.InterfaceContract{{Service: "p/subscription", Backing: plugin.BackingCore,
			MethodSpecs: []plugin.InterfaceMethod{{Name: "save", Effect: plugin.InterfaceEffectWrite, Scopes: []string{"proxy:read"}}}}}}
	if err := st.UpsertPluginInstallation(model.PluginInstallation{ID: "p", Name: manifest.Name, Type: manifest.Type, Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	srv := &Server{store: st, plugins: []plugin.Loaded{{Manifest: manifest}}, pluginRPC: plugin.NewRPCRegistry(), now: time.Now,
		subscriptionCache: newSubscriptionCache(subscriptionCacheEntries, subscriptionCacheTTL)}
	started, release := make(chan struct{}), make(chan struct{})
	calls := 0
	if err := srv.pluginRPC.Register("p", "p/subscription", "v1", []string{"save"}, func(context.Context, string, []byte) ([]byte, error) {
		calls++
		if calls == 1 {
			close(started)
			<-release // deliberately ignores the request context
		}
		return []byte(`{"ok":true}`), nil
	}); err != nil {
		t.Fatal(err)
	}
	invoke := func(ctx context.Context) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", strings.NewReader(`{"id":"p","service":"p/subscription","method":"save","payload":{}}`)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.handlePluginCall(rec, req, principal{Principal: rbac.Principal{Scopes: []string{"proxy:read"}}})
		return rec
	}
	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { firstDone <- invoke(context.Background()) }()
	<-started
	waiting := make(chan struct{}, 1)
	srv.subscriptionPluginGateWaiter = waiting
	canceled, cancel := context.WithCancel(context.Background())
	secondDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { secondDone <- invoke(canceled) }()
	<-waiting
	cancel()
	second := <-secondDone
	if second.Code == http.StatusOK || calls != 1 {
		t.Fatalf("canceled queued mutation code=%d calls=%d body=%q", second.Code, calls, second.Body.String())
	}
	close(release)
	if first := <-firstDone; first.Code != http.StatusOK {
		t.Fatalf("first mutation code=%d body=%q", first.Code, first.Body.String())
	}
	third := invoke(context.Background())
	if third.Code != http.StatusOK || calls != 2 {
		t.Fatalf("gate did not recover code=%d calls=%d body=%q", third.Code, calls, third.Body.String())
	}
}

func TestPluginGatewayGlobalNetworkScopesRequireUnrestrictedPrincipal(t *testing.T) {
	restricted := principal{Principal: rbac.Principal{
		Scopes:          []string{"node:read", "network:plan", "network:apply", "netguard:read", "netguard:admin"},
		ServerAllowlist: []string{"node-a"},
	}}
	for _, scope := range []string{"node:read", "network:plan", "network:apply", "netguard:read", "netguard:admin"} {
		if ok, _ := pluginGatewayScopeAllowed(restricted, scope); ok {
			t.Fatalf("restricted principal must not use global plugin scope %q", scope)
		}
	}
	unrestricted := principal{Principal: rbac.Principal{Scopes: []string{"node:read", "network:plan", "network:apply", "netguard:read", "netguard:admin"}}}
	for _, scope := range []string{"node:read", "network:plan", "network:apply", "netguard:read", "netguard:admin"} {
		if ok, reason := pluginGatewayScopeAllowed(unrestricted, scope); !ok {
			t.Fatalf("unrestricted principal should use scope %q: %s", scope, reason)
		}
	}
}

func TestPluginGatewayScopeMigrationCompatibilityAndIsolation(t *testing.T) {
	tests := []struct {
		name     string
		granted  string
		required string
		want     bool
	}{
		{name: "legacy proxy reaches migrated vpn-core", granted: "proxy:read", required: "vpncore:read", want: true},
		{name: "legacy proxy reaches migrated sub-store", granted: "proxy:read", required: "substore:read", want: true},
		{name: "vpn-core reaches legacy native scope", granted: "vpncore:read", required: "proxy:read", want: true},
		{name: "sub-store cannot reach legacy native scope", granted: "substore:read", required: "proxy:read", want: false},
		{name: "sub-store cannot reach vpn-core", granted: "substore:read", required: "vpncore:read", want: false},
		{name: "vpn-core cannot reach sub-store", granted: "vpncore:read", required: "substore:read", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := principal{Principal: rbac.Principal{Scopes: []string{tt.granted}}}
			got, _ := pluginGatewayScopeAllowed(p, tt.required)
			if got != tt.want {
				t.Fatalf("pluginGatewayScopeAllowed(%q, %q) = %v, want %v", tt.granted, tt.required, got, tt.want)
			}
		})
	}

	for _, scope := range []string{"vpncore:read", "vpncore:admin", "substore:read", "substore:admin"} {
		p := principal{Principal: rbac.Principal{
			Scopes:          []string{scope},
			ServerAllowlist: []string{"node-a"},
		}}
		if ok, reason := pluginGatewayScopeAllowed(p, scope); ok || !strings.Contains(reason, "unrestricted server allowlist") {
			t.Errorf("restricted principal with %q: allowed=%v reason=%q", scope, ok, reason)
		}
	}
}

func TestExtractOperatorTargetsRequiresDeclaredPayloadField(t *testing.T) {
	targets, err := extractOperatorTargets(json.RawMessage(`{"base_url":"https://10.0.0.5/secret"}`), []string{"base_url"})
	if err != nil || len(targets) != 1 || targets[0] != "https://10.0.0.5/secret" {
		t.Fatalf("valid operator target extraction: targets=%v err=%v", targets, err)
	}
	for _, payload := range []json.RawMessage{
		json.RawMessage(`{}`),
		json.RawMessage(`{"base_url":""}`),
		json.RawMessage(`{"base_url":"http://10.0.0.5/secret"}`),
		json.RawMessage(`{"base_url":"https://169.254.169.254/latest"}`),
	} {
		if _, err := extractOperatorTargets(payload, []string{"base_url"}); err == nil {
			t.Fatalf("payload %s must not mint an operator target", payload)
		}
	}
}

// The raw invoke channel is gated only by plugin:admin. It must therefore never reach
// an action with an effect on domain state: `call` and `plan` would bypass the
// manifest's per-method scopes and operator-target binding, and `execute` would bypass
// the plan/approval/one-time-capability binding entirely.
func TestPluginInvokeRefusesNonDiagnosticActions(t *testing.T) {
	pluginRoot := t.TempDir()
	bundle := filepath.Join(pluginRoot, "test.exec")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "manifest.json"),
		[]byte(`{"id":"test.exec","name":"Exec Test","type":"system","capabilities":["node:read"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// The artifact would happily answer anything; the host must refuse before it runs.
	script := "#!/bin/sh\nread line\necho '{\"ok\":true,\"message\":\"executed\",\"result\":{\"ran\":true}}'\n"
	if err := os.WriteFile(filepath.Join(bundle, "artifact"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{
		Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true,
		PluginDir:        pluginRoot,
		PluginRuntimeDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)

	for _, status := range []string{"installed", "active"} {
		resp := doJSON(t, handler, http.MethodPost, "/api/plugins/lifecycle",
			`{"id":"test.exec","status":"`+status+`"}`, cookies, csrf)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("lifecycle %s: %d", status, resp.StatusCode)
		}
		resp.Body.Close()
	}

	for _, action := range []string{"call", "plan", "execute", "migrate", "anything"} {
		resp := doJSON(t, handler, http.MethodPost, "/api/plugins/invoke",
			`{"id":"test.exec","action":"`+action+`"}`, cookies, csrf)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("invoke %q: want 403, got %d (%s)", action, resp.StatusCode, body)
		}
		if bytes.Contains(body, []byte("executed")) {
			t.Fatalf("invoke %q reached the artifact: %s", action, body)
		}
	}

	// Diagnostics remain reachable.
	for _, action := range []string{"describe", "health"} {
		resp := doJSON(t, handler, http.MethodPost, "/api/plugins/invoke",
			`{"id":"test.exec","action":"`+action+`"}`, cookies, csrf)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("invoke %q: want 200, got %d", action, resp.StatusCode)
		}
	}
}

// An operator target may carry its secret in the URL path. url.Parse errors echo the
// URL they failed on, and that text reaches both the audit record and the API
// response, so the guard's reason must be surfaced without the value.
func TestOperatorTargetErrorRedactsSecret(t *testing.T) {
	const secret = "https://sub.example.test/aVerySecretToken123/api"
	payload := json.RawMessage(`{"base_url":"` + secret + "\x7f" + `"}`)

	_, err := extractOperatorTargets(payload, []string{"base_url"})
	if err == nil {
		t.Fatal("want an error for a malformed operator target")
	}
	if strings.Contains(err.Error(), "aVerySecretToken123") {
		t.Fatalf("operator target secret leaked into the error: %q", err)
	}
}

// A manifest that declares a service as runtime-backed must never be answered by core.
// Silent core fallback is the exact ambiguity the backing declaration exists to remove:
// it let a plugin ship methods its own artifact could not serve while core quietly
// answered them, with no way for an operator to tell the difference.
func TestPluginCallRuntimeBackedServiceIsNeverAnsweredByCore(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	manifest := plugin.Manifest{
		Schema: plugin.ManifestSchemaV2, ID: "test.v2-runtime", Name: "V2 runtime", Type: plugin.TypeSystem,
		Publisher: "latticenet",
		Interfaces: []plugin.InterfaceContract{{
			Service: "test.v2-runtime/items",
			Backing: plugin.BackingRuntime,
			MethodSpecs: []plugin.InterfaceMethod{{
				Name: "list", Effect: plugin.InterfaceEffectRead, Scopes: []string{"proxy:read"},
			}},
		}},
	}
	if err := st.UpsertPluginInstallation(model.PluginInstallation{
		ID: manifest.ID, Name: manifest.Name, Type: manifest.Type, Status: model.PluginStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	srv := &Server{store: st, plugins: []plugin.Loaded{{Manifest: manifest}}, pluginRPC: plugin.NewRPCRegistry()}
	// Core owns a provider that shadows the runtime-backed service.
	if err := srv.pluginRPC.Register(manifest.ID, "test.v2-runtime/items", "v1", []string{"list"},
		func(_ context.Context, _ string, _ []byte) ([]byte, error) {
			return []byte(`{"rows":[{"id":"from-core"}]}`), nil
		}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", strings.NewReader(
		`{"id":"test.v2-runtime","service":"test.v2-runtime/items","method":"list"}`,
	))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.handlePluginCall(rec, req, principal{Principal: rbac.Principal{Scopes: []string{"proxy:read"}}})

	if strings.Contains(rec.Body.String(), "from-core") {
		t.Fatalf("a runtime-backed service was answered by core: %s", rec.Body.String())
	}
	if rec.Code == http.StatusOK {
		t.Fatalf("a core provider shadowing a runtime-backed service must fail closed, got 200: %s", rec.Body.String())
	}
}

// A core-backed declaration is honoured: the plugin owns the UI and the workflow, core
// owns the engine, and the manifest says so out loud.
func TestPluginCallCoreBackedServiceDispatchesToCore(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	manifest := plugin.Manifest{
		Schema: plugin.ManifestSchemaV2, ID: "test.v2-core", Name: "V2 core", Type: plugin.TypeSystem,
		Publisher: "latticenet",
		Interfaces: []plugin.InterfaceContract{{
			Service: "test.v2-core/items",
			Backing: plugin.BackingCore,
			MethodSpecs: []plugin.InterfaceMethod{{
				Name: "list", Effect: plugin.InterfaceEffectRead, Scopes: []string{"proxy:read"},
			}},
		}},
	}
	if err := st.UpsertPluginInstallation(model.PluginInstallation{
		ID: manifest.ID, Name: manifest.Name, Type: manifest.Type, Status: model.PluginStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	srv := &Server{store: st, plugins: []plugin.Loaded{{Manifest: manifest}}, pluginRPC: plugin.NewRPCRegistry()}
	srv.pluginRPC.SetOwnerActive(srv.pluginIsActive)
	if err := srv.pluginRPC.Register(manifest.ID, "test.v2-core/items", "v1", []string{"list"},
		func(_ context.Context, _ string, _ []byte) ([]byte, error) {
			return []byte(`{"rows":[{"id":"from-core"}]}`), nil
		}); err != nil {
		t.Fatal(err)
	}

	call := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", strings.NewReader(
			`{"id":"test.v2-core","service":"test.v2-core/items","method":"list"}`,
		))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.handlePluginCall(rec, req, principal{Principal: rbac.Principal{Scopes: []string{"proxy:read"}}})
		return rec
	}

	rec := call()
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "from-core") {
		t.Fatalf("core-backed call did not reach core: %d %s", rec.Code, rec.Body.String())
	}

	// Disable must stop the BACKEND, not merely hide the UI. The core provider is wired
	// at boot and never unregistered, so without a lifecycle gate it would keep serving.
	if err := st.UpsertPluginInstallation(model.PluginInstallation{
		ID: manifest.ID, Name: manifest.Name, Type: manifest.Type, Status: model.PluginStatusDisabled,
	}); err != nil {
		t.Fatal(err)
	}
	if rec := call(); rec.Code == http.StatusOK {
		t.Fatalf("a disabled plugin's core-backed service kept serving: %d %s", rec.Code, rec.Body.String())
	}
}

// A manifest cannot name core as its backend and have the host quietly find something
// else to answer with.
func TestPluginCallCoreBackedWithoutProviderFailsClosed(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	manifest := plugin.Manifest{
		Schema: plugin.ManifestSchemaV2, ID: "test.v2-orphan", Name: "V2 orphan", Type: plugin.TypeSystem,
		Publisher: "latticenet",
		Interfaces: []plugin.InterfaceContract{{
			Service: "test.v2-orphan/items",
			Backing: plugin.BackingCore,
			MethodSpecs: []plugin.InterfaceMethod{{
				Name: "list", Effect: plugin.InterfaceEffectRead, Scopes: []string{"proxy:read"},
			}},
		}},
	}
	if err := st.UpsertPluginInstallation(model.PluginInstallation{
		ID: manifest.ID, Name: manifest.Name, Type: manifest.Type, Status: model.PluginStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	srv := &Server{store: st, plugins: []plugin.Loaded{{Manifest: manifest}}, pluginRPC: plugin.NewRPCRegistry()}

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", strings.NewReader(
		`{"id":"test.v2-orphan","service":"test.v2-orphan/items","method":"list"}`,
	))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.handlePluginCall(rec, req, principal{Principal: rbac.Principal{Scopes: []string{"proxy:read"}}})
	if rec.Code == http.StatusOK {
		t.Fatalf("core-backed service with no core provider must fail closed, got 200: %s", rec.Body.String())
	}
}

func TestPluginCallServiceErrorKeepsItsMessageAs400(t *testing.T) {
	// A plugin's ErrorResponse is an operator-facing refusal, not an upstream
	// outage: it must surface as 400 with the plugin's own message, not the
	// sanitised 502 that reads like an infrastructure failure.
	pluginRoot := t.TempDir()
	manifest := plugin.Manifest{
		ID: "test.refusal", Name: "Refusal Test", Type: "system", Version: "0.1.0",
		Capabilities: []string{"node:read"},
		Interfaces: []plugin.InterfaceContract{{
			Service: "test.refusal/items",
			Methods: []string{"preview"},
			Scopes:  []string{"proxy:read"},
		}},
	}
	script := "#!/bin/sh\nread line\necho '{\"ok\":false,\"message\":\"preview needs subscription content\"}'\n"
	writeServerBundle(t, pluginRoot, "test.refusal", manifest, []byte(script))
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{
		Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true,
		PluginDir:        pluginRoot,
		PluginRuntimeDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)
	for _, status := range []string{model.PluginStatusInstalled, model.PluginStatusActive} {
		resp := doJSON(t, handler, http.MethodPost, "/api/plugins/lifecycle",
			`{"id":"test.refusal","status":"`+status+`"}`, cookies, csrf)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("lifecycle %s: got %d", status, resp.StatusCode)
		}
	}

	readToken := createPAT(t, handler, cookies, csrf, []string{"proxy:read"}, nil)
	call := doBearerJSON(t, handler, http.MethodPost, "/api/plugins/call",
		`{"id":"test.refusal","service":"test.refusal/items","method":"preview"}`, readToken)
	defer call.Body.Close()
	body, _ := io.ReadAll(call.Body)
	if call.StatusCode != http.StatusBadRequest {
		t.Fatalf("plugin refusal: want 400, got %d (%s)", call.StatusCode, body)
	}
	if !strings.Contains(string(body), "preview needs subscription content") {
		t.Fatalf("plugin refusal lost its message: %s", body)
	}
}
