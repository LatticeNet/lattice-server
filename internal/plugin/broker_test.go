package plugin

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestValidateManifestAcceptsBrokerCapabilitiesForWasm(t *testing.T) {
	err := ValidateManifest(Manifest{
		ID:           "webhook-card",
		Name:         "Webhook Card",
		Type:         TypeWasm,
		Capabilities: []string{"http:egress", "log:write"},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBrokerDeniesHostCallsWithoutDeclaredCapabilityAndAudits(t *testing.T) {
	services := &fakeHostServices{
		kvValues: map[string][]byte{"fleet/status": []byte("green")},
	}
	broker, err := NewBroker(Loaded{
		Manifest:     Manifest{ID: "readonly-card", Name: "Read Only Card", Type: TypeWasm, Capabilities: []string{"kv:read"}},
		Capabilities: []string{"kv:read"},
	}, HostServices{
		KV:     services,
		Notify: services,
		HTTP:   services,
		Log:    services,
		Audit:  services,
	})
	if err != nil {
		t.Fatal(err)
	}

	got, ok, err := broker.KVGet(context.Background(), "fleet/status")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || string(got) != "green" {
		t.Fatalf("unexpected kv get result: ok=%v got=%q", ok, string(got))
	}

	err = broker.KVPut(context.Background(), "fleet/status", []byte("red"))
	if !errors.Is(err, ErrCapabilityDenied) {
		t.Fatalf("expected kv write capability denial, got %v", err)
	}
	err = broker.Notify(context.Background(), "title", "body")
	if !errors.Is(err, ErrCapabilityDenied) {
		t.Fatalf("expected notify capability denial, got %v", err)
	}
	_, err = broker.HTTPDo(context.Background(), HostHTTPRequest{Method: "GET", URL: "https://example.com"})
	if !errors.Is(err, ErrCapabilityDenied) {
		t.Fatalf("expected http egress capability denial, got %v", err)
	}
	err = broker.Log(context.Background(), "info", "hello", map[string]string{"k": "v"})
	if !errors.Is(err, ErrCapabilityDenied) {
		t.Fatalf("expected log write capability denial, got %v", err)
	}

	if services.kvPuts != 0 || services.notifies != 0 || services.httpCalls != 0 || services.logs != 0 {
		t.Fatalf("denied calls must not reach host services: %+v", services)
	}
	want := []HostCallEvent{
		{PluginID: "readonly-card", Action: "kv.get", Capability: "kv:read", Decision: "allow"},
		{PluginID: "readonly-card", Action: "kv.put", Capability: "kv:write", Decision: "deny", Reason: `plugin "readonly-card" lacks capability "kv:write"`},
		{PluginID: "readonly-card", Action: "notify.send", Capability: "notify:send", Decision: "deny", Reason: `plugin "readonly-card" lacks capability "notify:send"`},
		{PluginID: "readonly-card", Action: "http.do", Capability: "http:egress", Decision: "deny", Reason: `plugin "readonly-card" lacks capability "http:egress"`},
		{PluginID: "readonly-card", Action: "log.write", Capability: "log:write", Decision: "deny", Reason: `plugin "readonly-card" lacks capability "log:write"`},
	}
	if !reflect.DeepEqual(services.events, want) {
		t.Fatalf("unexpected host audit events:\n got %#v\nwant %#v", services.events, want)
	}
}

func TestBrokerAllowsOnlyDeclaredHostAPIs(t *testing.T) {
	services := &fakeHostServices{kvValues: map[string][]byte{}}
	broker, err := NewBroker(Loaded{
		Manifest: Manifest{ID: "ops-plugin", Name: "Ops Plugin", Type: TypeSystem, Capabilities: []string{
			"http:egress",
			"kv:write",
			"log:write",
			"notify:send",
		}},
		Capabilities: []string{
			"http:egress",
			"kv:write",
			"log:write",
			"notify:send",
		},
	}, HostServices{
		KV:     services,
		Notify: services,
		HTTP:   services,
		Log:    services,
		Audit:  services,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := broker.KVPut(context.Background(), "release/channel", []byte("stable")); err != nil {
		t.Fatal(err)
	}
	if err := broker.Notify(context.Background(), "deploy", "started"); err != nil {
		t.Fatal(err)
	}
	resp, err := broker.HTTPDo(context.Background(), HostHTTPRequest{Method: "POST", URL: "https://api.example.com/hook", Body: []byte("payload")})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 202 {
		t.Fatalf("unexpected http response: %+v", resp)
	}
	if err := broker.Log(context.Background(), "info", "deploy started", map[string]string{"node": "node-a"}); err != nil {
		t.Fatal(err)
	}

	if _, ok, err := broker.KVGet(context.Background(), "release/channel"); !errors.Is(err, ErrCapabilityDenied) || ok {
		t.Fatalf("kv read must still be denied without kv:read: ok=%v err=%v", ok, err)
	}
	if services.kvPuts != 1 || services.notifies != 1 || services.httpCalls != 1 || services.logs != 1 {
		t.Fatalf("expected one allowed call per declared service, got %+v", services)
	}
	if services.lastLog.PluginID != "ops-plugin" || services.lastLog.Fields["node"] != "node-a" {
		t.Fatalf("broker must stamp plugin id onto log entries, got %+v", services.lastLog)
	}
}

func TestBrokerRejectsCapabilitySetThatDoesNotMatchManifest(t *testing.T) {
	_, err := NewBroker(Loaded{
		Manifest:     Manifest{ID: "scope-confusion", Name: "Scope Confusion", Type: TypeWasm, Capabilities: []string{"kv:read"}},
		Capabilities: []string{"kv:write"},
	}, HostServices{})
	if err == nil {
		t.Fatal("expected broker to reject loaded capabilities that do not match the verified manifest")
	}
	if !strings.Contains(err.Error(), "capabilities do not match manifest") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBrokerRejectsInvalidLoadedManifest(t *testing.T) {
	_, err := NewBroker(Loaded{
		Manifest:     Manifest{ID: "bad-wasm", Name: "Bad Wasm", Type: TypeWasm, Capabilities: []string{"network:apply"}},
		Capabilities: []string{"network:apply"},
	}, HostServices{})
	if err == nil {
		t.Fatal("expected broker to reject a loaded manifest that violates manifest validation")
	}
	if !strings.Contains(err.Error(), "invalid loaded manifest") {
		t.Fatalf("unexpected error: %v", err)
	}
}

type fakeHostServices struct {
	kvValues  map[string][]byte
	kvPuts    int
	notifies  int
	httpCalls int
	logs      int
	lastLog   HostLogEntry
	events    []HostCallEvent
}

func (f *fakeHostServices) Get(ctx context.Context, key string) ([]byte, bool, error) {
	value, ok := f.kvValues[key]
	return append([]byte(nil), value...), ok, nil
}

func (f *fakeHostServices) Put(ctx context.Context, key string, value []byte) error {
	f.kvPuts++
	f.kvValues[key] = append([]byte(nil), value...)
	return nil
}

func (f *fakeHostServices) Send(ctx context.Context, title, body string) error {
	f.notifies++
	return nil
}

func (f *fakeHostServices) Do(ctx context.Context, req HostHTTPRequest) (HostHTTPResponse, error) {
	f.httpCalls++
	return HostHTTPResponse{StatusCode: 202, Body: []byte("accepted")}, nil
}

func (f *fakeHostServices) Write(ctx context.Context, entry HostLogEntry) error {
	f.logs++
	f.lastLog = entry
	return nil
}

func (f *fakeHostServices) RecordHostCall(ctx context.Context, event HostCallEvent) {
	f.events = append(f.events, event)
}
