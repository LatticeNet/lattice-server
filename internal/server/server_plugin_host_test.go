package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestPluginHostServicesBrokeredKVAndAudit(t *testing.T) {
	srv, st := newServerForPluginHost(t)
	ctx := context.WithValue(context.Background(), requestIDContextKey{}, "req-plugin-host")
	broker, err := plugin.NewBroker(plugin.Loaded{
		Manifest: plugin.Manifest{
			ID:           "kv-plugin",
			Name:         "KV Plugin",
			Type:         plugin.TypeSystem,
			Capabilities: []string{"kv:read", "kv:write"},
		},
		Capabilities: []string{"kv:read", "kv:write"},
	}, srv.pluginHostServices())
	if err != nil {
		t.Fatal(err)
	}

	if err := broker.KVPut(ctx, "message", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	got, ok, err := broker.KVGet(ctx, "message")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || string(got) != "hello" {
		t.Fatalf("unexpected broker KV read: ok=%v got=%q", ok, string(got))
	}

	// C2: the broker pins the bucket to the plugin's own namespace; the value must
	// physically live under "plugin:<pluginID>" in the shared operator KV store.
	foundNamespaced := false
	for _, entry := range st.KV("plugin:kv-plugin") {
		if entry.Key == "message" && entry.Value == "hello" {
			foundNamespaced = true
		}
	}
	if !foundNamespaced {
		t.Fatalf("plugin value must be stored under its namespaced bucket, got %+v", st.KV("plugin:kv-plugin"))
	}

	deniedBroker, err := plugin.NewBroker(plugin.Loaded{
		Manifest: plugin.Manifest{
			ID:           "read-only-plugin",
			Name:         "Read Only Plugin",
			Type:         plugin.TypeWasm,
			Capabilities: []string{"kv:read"},
		},
		Capabilities: []string{"kv:read"},
	}, srv.pluginHostServices())
	if err != nil {
		t.Fatal(err)
	}
	if err := deniedBroker.KVPut(ctx, "message", []byte("denied")); err == nil {
		t.Fatal("expected kv:write denial")
	}
	got, ok, err = broker.KVGet(ctx, "message")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || string(got) != "hello" {
		t.Fatalf("denied write must not mutate KV: ok=%v got=%q", ok, string(got))
	}

	requirePluginHostAudit(t, st, "plugin.host.kv.put", "kv:write", "kv-plugin", "allow", "req-plugin-host")
	requirePluginHostAudit(t, st, "plugin.host.kv.get", "kv:read", "kv-plugin", "allow", "req-plugin-host")
	requirePluginHostAudit(t, st, "plugin.host.kv.put", "kv:write", "read-only-plugin", "deny", "req-plugin-host")
}

func TestPluginHostKVIsolatesPluginsAndRejectsForeignBucket(t *testing.T) {
	// C2: a plugin must only touch its OWN namespaced keys. Plugin "a" cannot read
	// a value written by plugin "b" under the same logical key, and the host
	// rejects any composite key whose bucket is not the plugin namespace.
	srv, _ := newServerForPluginHost(t)
	ctx := context.Background()

	newKVBroker := func(id string) *plugin.Broker {
		b, err := plugin.NewBroker(plugin.Loaded{
			Manifest: plugin.Manifest{
				ID:           id,
				Name:         id,
				Type:         plugin.TypeSystem,
				Capabilities: []string{"kv:read", "kv:write"},
			},
			Capabilities: []string{"kv:read", "kv:write"},
		}, srv.pluginHostServices())
		if err != nil {
			t.Fatalf("new broker %q: %v", id, err)
		}
		return b
	}

	a := newKVBroker("plugin-a")
	b := newKVBroker("plugin-b")

	if err := a.KVPut(ctx, "secret", []byte("a-only")); err != nil {
		t.Fatal(err)
	}
	if err := b.KVPut(ctx, "secret", []byte("b-only")); err != nil {
		t.Fatal(err)
	}

	// Each plugin reads back only its own value.
	got, ok, err := a.KVGet(ctx, "secret")
	if err != nil || !ok || string(got) != "a-only" {
		t.Fatalf("plugin-a own round-trip failed: ok=%v got=%q err=%v", ok, string(got), err)
	}
	got, ok, err = b.KVGet(ctx, "secret")
	if err != nil || !ok || string(got) != "b-only" {
		t.Fatalf("plugin-b own round-trip failed: ok=%v got=%q err=%v", ok, string(got), err)
	}

	// The host directly rejects a composite key that escapes the plugin namespace,
	// proving the server-side enforcement is independent of the broker.
	host := srv.pluginHostServices()
	if _, _, err := host.KV.Get(ctx, "operator-secrets/admin"); err == nil {
		t.Fatal("host must reject a non-plugin bucket on Get")
	}
	if err := host.KV.Put(ctx, "operator-secrets/admin", []byte("x")); err == nil {
		t.Fatal("host must reject a non-plugin bucket on Put")
	}
}

func TestPluginHostServicesHTTPUsesOutboundGuard(t *testing.T) {
	srv, st := newServerForPluginHost(t)
	ctx := context.WithValue(context.Background(), requestIDContextKey{}, "req-plugin-http")
	broker, err := plugin.NewBroker(plugin.Loaded{
		Manifest: plugin.Manifest{
			ID:           "http-plugin",
			Name:         "HTTP Plugin",
			Type:         plugin.TypeWasm,
			Capabilities: []string{"http:egress"},
		},
		Capabilities: []string{"http:egress"},
	}, srv.pluginHostServices())
	if err != nil {
		t.Fatal(err)
	}

	_, err = broker.HTTPDo(ctx, plugin.HostHTTPRequest{Method: "GET", URL: "http://127.0.0.1/"})
	if err == nil || !strings.Contains(err.Error(), "blocked address") {
		t.Fatalf("expected outbound guard to block loopback, got %v", err)
	}
	requirePluginHostAudit(t, st, "plugin.host.http.do", "http:egress", "http-plugin", "allow", "req-plugin-http")
}

func TestPluginHostServicesOperatorTargetAllowsLoopbackOnlyWithExplicitCapability(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/secret/status" {
			t.Fatalf("unexpected operator target path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	srv, st := newServerForPluginHost(t)
	ctx := context.WithValue(context.Background(), requestIDContextKey{}, "req-plugin-operator-http")
	ctx, err := plugin.BindOperatorTargets(ctx, []string{target.URL + "/secret"})
	if err != nil {
		t.Fatal(err)
	}
	broker, err := plugin.NewBroker(plugin.Loaded{
		Manifest: plugin.Manifest{ID: "operator-http-plugin", Name: "Operator HTTP Plugin", Type: plugin.TypeSystem,
			Capabilities: []string{"http:operator-target"}},
		Capabilities: []string{"http:operator-target"},
	}, srv.pluginHostServices())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := broker.HTTPOperatorDo(ctx, plugin.HostHTTPRequest{Method: http.MethodGet, URL: target.URL + "/secret/status"})
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("operator target response=%+v err=%v", resp, err)
	}
	requirePluginHostAudit(t, st, "plugin.host.http.operator.do", "http:operator-target", "operator-http-plugin", "allow", "req-plugin-operator-http")
}

func TestPluginHostServicesHTTPRejectsOversizedRequestBodyBeforeDial(t *testing.T) {
	srv, _ := newServerForPluginHost(t)
	// Exercise the host's Do directly: the broker now runs the egress guard before
	// delegating, so a loopback URL would be blocked there first. This test targets
	// the host's own ordering — the request-body size limit must be enforced before
	// the host attempts to construct/dial the request.
	host := srv.pluginHostServices()
	_, err := host.HTTP.Do(context.Background(), plugin.HostHTTPRequest{
		Method: "POST",
		URL:    "http://127.0.0.1/",
		Body:   bytes.Repeat([]byte("x"), 256*1024+1),
	})
	if err == nil || !strings.Contains(err.Error(), "request body exceeds size limit") {
		t.Fatalf("expected request body size rejection before dial, got %v", err)
	}
}

func newServerForPluginHost(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass})
	if err != nil {
		t.Fatal(err)
	}
	return srv, st
}

func requirePluginHostAudit(t *testing.T, st *store.Store, action, scope, pluginID, decision, correlationID string) model.AuditEvent {
	t.Helper()
	for _, ev := range st.AuditEvents() {
		if ev.Action == action && ev.Scope == scope && ev.Metadata["plugin_id"] == pluginID && ev.Decision == decision {
			if ev.CorrelationID != correlationID {
				t.Fatalf("audit %s correlation_id %q != %q", action, ev.CorrelationID, correlationID)
			}
			return ev
		}
	}
	t.Fatalf("missing plugin host audit action=%q scope=%q plugin=%q decision=%q in %+v", action, scope, pluginID, decision, st.AuditEvents())
	return model.AuditEvent{}
}
