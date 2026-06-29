package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
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

	list := doBearerJSON(t, handler, http.MethodPost, "/api/plugins/call",
		`{"id":"test.ui","service":"test.ui/nodes","method":"list"}`, readToken)
	list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list should be allowed with proxy:read, got %d", list.StatusCode)
	}
	denied := doBearerJSON(t, handler, http.MethodPost, "/api/plugins/call",
		`{"id":"test.ui","service":"test.ui/nodes","method":"delete"}`, readToken)
	denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("delete should require action scope proxy:admin, got %d", denied.StatusCode)
	}
	var sawDeny bool
	for _, ev := range st.AuditEvents() {
		if ev.Action == "plugin.call" && ev.Decision == "deny" && ev.Metadata["method"] == "delete" && strings.Contains(ev.Scope, "proxy:admin") {
			sawDeny = true
		}
	}
	if !sawDeny {
		t.Fatalf("expected plugin.call deny audit for action scope failure, got %+v", st.AuditEvents())
	}
}

func TestPluginContributionsHideBuiltinViewWithoutNavScope(t *testing.T) {
	pluginRoot := t.TempDir()
	manifest := plugin.Manifest{
		ID: "latticenet.vpn-core", Name: "vpn-core", Type: "system", Version: "0.1.0",
		Capabilities: []string{"node:read"},
		UI: &plugin.ManifestUI{
			Nav: []plugin.NavContribution{{
				Section: "vpn-manage", SectionTitle: "VPN Manage", Title: "Users",
				Route: "users", Icon: "Users", Scopes: []string{"proxy:read"},
			}},
			Views: []plugin.ViewContribution{{
				Route: "users", Title: "Users", Kind: "builtin", ComponentKey: "proxy.users",
			}},
		},
	}
	writeServerBundle(t, pluginRoot, "latticenet.vpn-core", manifest, []byte("artifact"))
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, PluginDir: pluginRoot, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)
	for _, status := range []string{model.PluginStatusInstalled, model.PluginStatusActive} {
		resp := doJSON(t, handler, http.MethodPost, "/api/plugins/lifecycle",
			`{"id":"latticenet.vpn-core","status":"`+status+`"}`, cookies, csrf)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("lifecycle %s: got %d", status, resp.StatusCode)
		}
	}

	noProxyToken := createPAT(t, handler, cookies, csrf, []string{"node:read"}, nil)
	hidden := doBearerJSON(t, handler, http.MethodGet, "/api/plugin-contributions", "", noProxyToken)
	if hidden.StatusCode != http.StatusOK {
		t.Fatalf("contributions should remain callable, got %d", hidden.StatusCode)
	}
	var hiddenPlugins []pluginView
	if err := json.NewDecoder(hidden.Body).Decode(&hiddenPlugins); err != nil {
		t.Fatal(err)
	}
	hidden.Body.Close()
	if len(hiddenPlugins) != 0 {
		t.Fatalf("source-less builtin view must be hidden when nav scope is missing, got %+v", hiddenPlugins)
	}

	readToken := createPAT(t, handler, cookies, csrf, []string{"proxy:read"}, nil)
	visible := doBearerJSON(t, handler, http.MethodGet, "/api/plugin-contributions", "", readToken)
	if visible.StatusCode != http.StatusOK {
		t.Fatalf("contributions should be visible with proxy:read, got %d", visible.StatusCode)
	}
	var visiblePlugins []pluginView
	if err := json.NewDecoder(visible.Body).Decode(&visiblePlugins); err != nil {
		t.Fatal(err)
	}
	visible.Body.Close()
	if len(visiblePlugins) != 1 || visiblePlugins[0].UI == nil || len(visiblePlugins[0].UI.Views) != 1 || visiblePlugins[0].UI.Views[0].Kind != "builtin" {
		t.Fatalf("expected builtin view visible with proxy:read, got %+v", visiblePlugins)
	}
}
