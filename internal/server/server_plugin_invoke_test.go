package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
