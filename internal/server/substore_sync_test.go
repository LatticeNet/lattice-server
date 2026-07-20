package server

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func newSubStoreSyncTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	return newLinemetaTestServer(t, st)
}

func seedSubStoreSecrets(t *testing.T, srv *Server, endpoint, autosync string) {
	t.Helper()
	if endpoint != "" {
		if err := srv.store.PutPluginSecret(model.KVEntry{Bucket: pluginSecretBucketPrefix + subStorePluginID, Key: "endpoint", Value: endpoint}); err != nil {
			t.Fatal(err)
		}
	}
	if autosync != "" {
		if err := srv.store.PutPluginSecret(model.KVEntry{Bucket: pluginSecretBucketPrefix + subStorePluginID, Key: "autosync", Value: autosync}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestResolveSecretOperatorTargets(t *testing.T) {
	srv := newSubStoreSyncTestServer(t)
	seedSubStoreSecrets(t, srv, "https://sub.example.com/api/token/abc", "")
	fields := []string{"base_url"}

	// secret:// ref resolves and rewrites the payload.
	out, err := srv.resolveSecretOperatorTargets(lineUserTestPrincipal(), subStorePluginID,
		json.RawMessage(`{"base_url":"secret://endpoint","sub_name":"x"}`), fields)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["base_url"] != "https://sub.example.com/api/token/abc" || got["sub_name"] != "x" {
		t.Fatalf("rewritten payload: %v", got)
	}

	// Plain URLs pass through untouched.
	in := json.RawMessage(`{"base_url":"https://direct.example.com"}`)
	out, err = srv.resolveSecretOperatorTargets(lineUserTestPrincipal(), subStorePluginID, in, fields)
	if err != nil || string(out) != string(in) {
		t.Fatalf("passthrough: out=%s err=%v", out, err)
	}

	// Unknown key fails loud.
	if _, err := srv.resolveSecretOperatorTargets(lineUserTestPrincipal(), subStorePluginID,
		json.RawMessage(`{"base_url":"secret://nope"}`), fields); err == nil || !strings.Contains(err.Error(), "not saved") {
		t.Fatalf("missing secret: %v", err)
	}
	// Malformed refs fail loud.
	if _, err := srv.resolveSecretOperatorTargets(lineUserTestPrincipal(), subStorePluginID,
		json.RawMessage(`{"base_url":"secret://"}`), fields); err == nil {
		t.Fatal("empty ref: want error")
	}
	// Secrets from another plugin's namespace are invisible.
	if _, err := srv.resolveSecretOperatorTargets(lineUserTestPrincipal(), "latticenet.other",
		json.RawMessage(`{"base_url":"secret://endpoint"}`), fields); err == nil {
		t.Fatal("cross-plugin namespace: want error")
	}
}

func TestSubStoreAutoSyncTarget(t *testing.T) {
	srv := newSubStoreSyncTestServer(t)
	if _, ok := srv.subStoreAutoSyncTarget(); ok {
		t.Fatal("no secrets: want disabled")
	}
	seedSubStoreSecrets(t, srv, "https://sub.example.com", "")
	if _, ok := srv.subStoreAutoSyncTarget(); ok {
		t.Fatal("endpoint without autosync flag: want disabled")
	}
	seedSubStoreSecrets(t, srv, "", "0")
	if _, ok := srv.subStoreAutoSyncTarget(); ok {
		t.Fatal("autosync=0: want disabled")
	}
	seedSubStoreSecrets(t, srv, "", "1")
	endpoint, ok := srv.subStoreAutoSyncTarget()
	if !ok || endpoint != "https://sub.example.com" {
		t.Fatalf("enabled: %q %v", endpoint, ok)
	}
}

func TestRunSubStoreAutoSync(t *testing.T) {
	srv := newSubStoreSyncTestServer(t)
	srv.pluginRuntime = plugin.NewRuntimeManagerWithOptions(plugin.RuntimeManagerOptions{})

	var calls atomic.Int32
	var gotEndpoint, gotPayload string
	srv.subStoreSync.invoke = func(_ context.Context, pluginID, service, method string, payload json.RawMessage, targets []string) ([]byte, error) {
		calls.Add(1)
		gotEndpoint = targets[0]
		gotPayload = string(payload)
		return json.RawMessage(`{"ok":true}`), nil
	}

	// Plugin inactive: no invocation.
	seedSubStoreSecrets(t, srv, "https://sub.example.com", "1")
	if err := srv.runSubStoreAutoSync(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("inactive plugin must not be invoked")
	}

	// Active plugin: exactly one invocation with the saved endpoint bound.
	if err := srv.store.UpsertPluginInstallation(model.PluginInstallation{ID: subStorePluginID, Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	if err := srv.runSubStoreAutoSync(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}
	if gotEndpoint != "https://sub.example.com" || !strings.Contains(gotPayload, `"base_url":"https://sub.example.com"`) {
		t.Fatalf("endpoint binding: %q payload %s", gotEndpoint, gotPayload)
	}

	// Failed invocation returns an error (and audits a deny).
	srv.subStoreSync.invoke = func(context.Context, string, string, string, json.RawMessage, []string) ([]byte, error) {
		return nil, context.DeadlineExceeded
	}
	if err := srv.runSubStoreAutoSync(); err == nil {
		t.Fatal("failed import: want error")
	}
}
