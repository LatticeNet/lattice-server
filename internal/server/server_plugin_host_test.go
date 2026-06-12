package server

import (
	"bytes"
	"context"
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

	if err := broker.KVPut(ctx, "default/message", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	got, ok, err := broker.KVGet(ctx, "default/message")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || string(got) != "hello" {
		t.Fatalf("unexpected broker KV read: ok=%v got=%q", ok, string(got))
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
	if err := deniedBroker.KVPut(ctx, "default/message", []byte("denied")); err == nil {
		t.Fatal("expected kv:write denial")
	}
	got, ok, err = broker.KVGet(ctx, "default/message")
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

func TestPluginHostServicesHTTPRejectsOversizedRequestBodyBeforeDial(t *testing.T) {
	srv, _ := newServerForPluginHost(t)
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

	_, err = broker.HTTPDo(context.Background(), plugin.HostHTTPRequest{
		Method: "POST",
		URL:    "http://127.0.0.1/",
		Body:   bytes.Repeat([]byte("x"), 256*1024+1),
	})
	if err == nil || !strings.Contains(err.Error(), "request body exceeds size limit") {
		t.Fatalf("expected request body size rejection before outbound guard, got %v", err)
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
