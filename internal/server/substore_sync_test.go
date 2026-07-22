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

	// Canonical namespace-bound ref resolves and rewrites the payload.
	out, err := srv.resolveSecretOperatorTargets(lineUserTestPrincipal(), subStorePluginID,
		json.RawMessage(`{"base_url":"secret://latticenet.sub-store/endpoint","sub_name":"x"}`), fields)
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
	// Historical shorthand remains safe because lookup is still forced into
	// the current plugin's own namespace.
	if _, err := srv.resolveSecretOperatorTargets(lineUserTestPrincipal(), subStorePluginID,
		json.RawMessage(`{"base_url":"secret://endpoint"}`), fields); err != nil {
		t.Fatalf("legacy shorthand: %v", err)
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
	if _, err := srv.resolveSecretOperatorTargets(lineUserTestPrincipal(), subStorePluginID,
		json.RawMessage(`{"base_url":"secret://latticenet.other/endpoint"}`), fields); err == nil {
		t.Fatal("canonical cross-plugin reference: want error")
	}
	if _, err := srv.resolveSecretOperatorTargets(lineUserTestPrincipal(), subStorePluginID,
		json.RawMessage(`{"base_url":"secret://latticenet.sub-store/autosync"}`), fields); err == nil {
		t.Fatal("wrong sub-store key: want missing-secret error")
	}
}

func TestResolveAtomicSubStoreEndpointSecret(t *testing.T) {
	srv := newSubStoreSyncTestServer(t)
	if err := srv.store.PutPluginSecret(model.KVEntry{
		Bucket: pluginSecretBucketPrefix + subStorePluginID,
		Key:    "endpoint", Value: `{"base_url":"https://sub.example.com/atomic","autosync":true}`,
	}); err != nil {
		t.Fatal(err)
	}
	out, err := srv.resolveSecretOperatorTargets(lineUserTestPrincipal(), subStorePluginID,
		json.RawMessage(`{"base_url":"secret://latticenet.sub-store/endpoint"}`), []string{"base_url"})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(out, &got); err != nil || got["base_url"] != "https://sub.example.com/atomic" {
		t.Fatalf("atomic endpoint resolution: %s err=%v", out, err)
	}
	if endpoint, enabled := srv.subStoreAutoSyncTarget(); !enabled || endpoint != "https://sub.example.com/atomic" {
		t.Fatalf("atomic autosync target: %q %v", endpoint, enabled)
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
	statusRaw, ok := srv.pluginSecretValue(subStorePluginID, "autosync_status")
	if !ok {
		t.Fatal("successful sync did not persist status")
	}
	var status subStoreAutoSyncStatus
	if err := json.Unmarshal([]byte(statusRaw), &status); err != nil || status.State != "success" || status.LastSuccessAt == "" {
		t.Fatalf("success status: %q err=%v", statusRaw, err)
	}
	if strings.Contains(statusRaw, "sub.example.com") {
		t.Fatalf("status leaked endpoint: %s", statusRaw)
	}

	// Failed invocation returns an error (and audits a deny).
	srv.subStoreSync.invoke = func(context.Context, string, string, string, json.RawMessage, []string) ([]byte, error) {
		return nil, context.DeadlineExceeded
	}
	if err := srv.runSubStoreAutoSync(); err == nil {
		t.Fatal("failed import: want error")
	}
	statusRaw, _ = srv.pluginSecretValue(subStorePluginID, "autosync_status")
	if err := json.Unmarshal([]byte(statusRaw), &status); err != nil || status.State != "error" || status.Error != "autosync import failed" || status.LastSuccessAt == "" {
		t.Fatalf("error status: %q err=%v", statusRaw, err)
	}
	if strings.Contains(statusRaw, "DeadlineExceeded") || strings.Contains(statusRaw, "sub.example.com") {
		t.Fatalf("error status leaked invocation detail: %s", statusRaw)
	}
}

func TestRunSubStoreAutoSyncSerializesAndCoalescesDirtyFollowUp(t *testing.T) {
	srv := newSubStoreSyncTestServer(t)
	srv.pluginRuntime = plugin.NewRuntimeManagerWithOptions(plugin.RuntimeManagerOptions{})
	seedSubStoreSecrets(t, srv, "https://sub.example.com", "1")
	if err := srv.store.UpsertPluginInstallation(model.PluginInstallation{ID: subStorePluginID, Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var calls atomic.Int32
	srv.subStoreSync.invoke = func(context.Context, string, string, string, json.RawMessage, []string) ([]byte, error) {
		if calls.Add(1) == 1 {
			entered <- struct{}{}
			<-release
		}
		return json.RawMessage(`{"ok":true}`), nil
	}
	done := make(chan error, 1)
	go func() { done <- srv.runSubStoreAutoSync() }()
	<-entered
	for i := 0; i < 3; i++ {
		srv.triggerVPNCoreMutation()
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("running sync plus one coalesced follow-up = 2 calls, got %d", got)
	}
}
