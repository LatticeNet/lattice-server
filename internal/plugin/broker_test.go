package plugin

import (
	"context"
	"errors"
	"fmt"
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
	// The broker pins KV access to the plugin's own bucket, so the seeded value
	// lives under "plugin:<pluginID>/<key>" and the plugin reads it by entry key.
	services := &fakeHostServices{
		kvValues: map[string][]byte{"plugin:readonly-card/status": []byte("green")},
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

	got, ok, err := broker.KVGet(context.Background(), "status")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || string(got) != "green" {
		t.Fatalf("unexpected kv get result: ok=%v got=%q", ok, string(got))
	}

	err = broker.KVPut(context.Background(), "status", []byte("red"))
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

func TestBrokerNamespacesKVToOwnBucketAndRejectsBucketSmuggling(t *testing.T) {
	services := &fakeHostServices{kvValues: map[string][]byte{}}
	newWritableKVBroker := func(id string) *Broker {
		b, err := NewBroker(Loaded{
			Manifest:     Manifest{ID: id, Name: id, Type: TypeSystem, Capabilities: []string{"kv:read", "kv:write"}},
			Capabilities: []string{"kv:read", "kv:write"},
		}, HostServices{KV: services, Audit: services})
		if err != nil {
			t.Fatalf("new broker %q: %v", id, err)
		}
		return b
	}

	a := newWritableKVBroker("alpha")
	b := newWritableKVBroker("beta")

	// Plugin "alpha" round-trips its OWN key.
	if err := a.KVPut(context.Background(), "shared", []byte("from-a")); err != nil {
		t.Fatal(err)
	}
	got, ok, err := a.KVGet(context.Background(), "shared")
	if err != nil || !ok || string(got) != "from-a" {
		t.Fatalf("alpha own key round-trip failed: ok=%v got=%q err=%v", ok, string(got), err)
	}

	// Plugin "beta" using the same logical key name must NOT see alpha's value:
	// the bucket is pinned per plugin id.
	if _, ok, err := b.KVGet(context.Background(), "shared"); err != nil || ok {
		t.Fatalf("beta must not read alpha's key: ok=%v err=%v", ok, err)
	}

	// Confirm the physical keys are namespaced under distinct plugin buckets.
	if _, ok := services.kvValues["plugin:alpha/shared"]; !ok {
		t.Fatalf("alpha value not stored under its namespace: %v", services.kvValues)
	}

	// A plugin cannot smuggle another bucket by stuffing a slash into the key.
	if err := a.KVPut(context.Background(), "beta/shared", []byte("evil")); err == nil {
		t.Fatal("expected slash-bearing key to be rejected (bucket smuggling)")
	}
	if _, ok, err := a.KVGet(context.Background(), "other-bucket/key"); err == nil || ok {
		t.Fatalf("expected slash-bearing get key to be rejected: ok=%v err=%v", ok, err)
	}
	if err := a.KVPut(context.Background(), "", []byte("x")); err == nil {
		t.Fatal("expected empty key to be rejected")
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
		// Use a permissive guard so this allow-path test stays hermetic (no real
		// DNS). The dedicated SSRF test below exercises the guard's reject path.
		GuardURL: func(string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := broker.KVPut(context.Background(), "release-channel", []byte("stable")); err != nil {
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

	if _, ok, err := broker.KVGet(context.Background(), "release-channel"); !errors.Is(err, ErrCapabilityDenied) || ok {
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

func TestBrokerHTTPDoGuardsEgressBeforeReachingHost(t *testing.T) {
	// C5: egress guarding must be structural in the broker. An internal/loopback
	// target is rejected by the broker BEFORE the HTTPHost's Do is ever called.
	services := &fakeHostServices{kvValues: map[string][]byte{}}
	broker, err := NewBroker(Loaded{
		Manifest:     Manifest{ID: "egress-card", Name: "Egress Card", Type: TypeSystem, Capabilities: []string{"http:egress"}},
		Capabilities: []string{"http:egress"},
	}, HostServices{HTTP: services, Audit: services})
	if err != nil {
		t.Fatal(err)
	}

	for _, raw := range []string{
		"http://127.0.0.1/",        // loopback
		"http://169.254.169.254/",  // link-local / cloud metadata
		"http://[::1]/",            // IPv6 loopback
		"http://10.0.0.5/internal", // private
	} {
		_, err := broker.HTTPDo(context.Background(), HostHTTPRequest{Method: "GET", URL: raw})
		if err == nil || !strings.Contains(err.Error(), "blocked") {
			t.Fatalf("expected broker to block egress to %q, got %v", raw, err)
		}
	}
	if services.httpCalls != 0 {
		t.Fatalf("broker must not delegate blocked egress to the host: httpCalls=%d", services.httpCalls)
	}

	// The capability-check still precedes the guard: a plugin lacking the cap is
	// denied for the capability, never reaching the guard.
	noCap, err := NewBroker(Loaded{
		Manifest:     Manifest{ID: "nocap-card", Name: "No Cap", Type: TypeWasm, Capabilities: []string{"kv:read"}},
		Capabilities: []string{"kv:read"},
	}, HostServices{HTTP: services, Audit: services})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noCap.HTTPDo(context.Background(), HostHTTPRequest{Method: "GET", URL: "http://127.0.0.1/"}); !errors.Is(err, ErrCapabilityDenied) {
		t.Fatalf("capability denial must precede the egress guard, got %v", err)
	}
}

func TestBrokerHTTPDoUsesInjectedGuard(t *testing.T) {
	// When a host injects HostServices.GuardURL, the broker uses it (not the
	// default outbound guard), and a guard rejection blocks the call.
	services := &fakeHostServices{kvValues: map[string][]byte{}}
	var guarded string
	broker, err := NewBroker(Loaded{
		Manifest:     Manifest{ID: "guard-card", Name: "Guard Card", Type: TypeSystem, Capabilities: []string{"http:egress"}},
		Capabilities: []string{"http:egress"},
	}, HostServices{
		HTTP:  services,
		Audit: services,
		GuardURL: func(u string) error {
			guarded = u
			return errors.New("policy reject")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = broker.HTTPDo(context.Background(), HostHTTPRequest{Method: "GET", URL: "https://public.example/api"})
	if err == nil || !strings.Contains(err.Error(), "policy reject") {
		t.Fatalf("expected injected guard rejection, got %v", err)
	}
	if guarded != "https://public.example/api" {
		t.Fatalf("injected guard saw wrong url: %q", guarded)
	}
	if services.httpCalls != 0 {
		t.Fatalf("guard rejection must not reach host: httpCalls=%d", services.httpCalls)
	}
}

func TestBrokerLogBoundsLevelMessageAndFields(t *testing.T) {
	// C17: plugin-controlled log inputs are bounded before reaching the sink.
	services := &fakeHostServices{kvValues: map[string][]byte{}}
	broker, err := NewBroker(Loaded{
		Manifest:     Manifest{ID: "log-card", Name: "Log Card", Type: TypeSystem, Capabilities: []string{"log:write"}},
		Capabilities: []string{"log:write"},
	}, HostServices{Log: services, Audit: services})
	if err != nil {
		t.Fatal(err)
	}

	// Unknown level maps to "info"; oversize message is truncated; field count is
	// capped at logMaxFields.
	bigMsg := strings.Repeat("A", logMaxMessageBytes+500)
	fields := make(map[string]string, logMaxFields+10)
	for i := 0; i < logMaxFields+10; i++ {
		fields[fmt.Sprintf("k%03d", i)] = "v"
	}
	if err := broker.Log(context.Background(), "VERBOSE", bigMsg, fields); err != nil {
		t.Fatal(err)
	}
	got := services.lastLog
	if got.Level != "info" {
		t.Fatalf("unknown level must map to info, got %q", got.Level)
	}
	if len(got.Message) > logMaxMessageBytes+len(logTruncatedSuffix) || !strings.HasSuffix(got.Message, logTruncatedSuffix) {
		t.Fatalf("oversize message must be truncated, got len=%d", len(got.Message))
	}
	if len(got.Fields) != logMaxFields {
		t.Fatalf("fields must be capped at %d, got %d", logMaxFields, len(got.Fields))
	}

	// A known level passes through unchanged; a small message/field set is intact.
	if err := broker.Log(context.Background(), "Warn", "ok", map[string]string{"a": "b"}); err != nil {
		t.Fatal(err)
	}
	if services.lastLog.Level != "warn" || services.lastLog.Message != "ok" || services.lastLog.Fields["a"] != "b" {
		t.Fatalf("valid log entry must pass through, got %+v", services.lastLog)
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
