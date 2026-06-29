package server

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

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
