package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	sdkplugin "github.com/LatticeNet/lattice-sdk/plugin"
)

// s0Host records what the broker hands the host for the host calls of
// host_store_schedule.go. It implements KVHost with KVDeleter, TaskHost with
// TaskScheduleHost, and both HTTP hosts.
type s0Host struct {
	mu          sync.Mutex
	deleted     []string
	scheduled   []sdkplugin.TaskSchedule
	scheduledBy []string
	unscheduled []string
	httpReqs    []HostHTTPRequest
	opReqs      []HostHTTPRequest
	events      []HostCallEvent
}

func (h *s0Host) Get(context.Context, string) ([]byte, bool, error) { return nil, false, nil }
func (h *s0Host) Put(context.Context, string, []byte) error         { return nil }
func (h *s0Host) Delete(_ context.Context, key string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.deleted = append(h.deleted, key)
	return nil
}
func (h *s0Host) Enqueue(context.Context, HostTaskRequest) (string, error) { return "", nil }
func (h *s0Host) Schedule(_ context.Context, pluginID string, s sdkplugin.TaskSchedule) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.scheduled = append(h.scheduled, s)
	h.scheduledBy = append(h.scheduledBy, pluginID)
	return nil
}
func (h *s0Host) Unschedule(_ context.Context, pluginID, id string) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.unscheduled = append(h.unscheduled, pluginID+"/"+id)
	return true, nil
}
func (h *s0Host) Do(_ context.Context, req HostHTTPRequest) (HostHTTPResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.httpReqs = append(h.httpReqs, req)
	return HostHTTPResponse{StatusCode: 200}, nil
}
func (h *s0Host) DoOperator(_ context.Context, req HostHTTPRequest) (HostHTTPResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.opReqs = append(h.opReqs, req)
	return HostHTTPResponse{StatusCode: 200}, nil
}
func (h *s0Host) RecordHostCall(_ context.Context, event HostCallEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, event)
}

func (h *s0Host) services() HostServices {
	return HostServices{KV: h, Task: h, HTTP: h, OperatorHTTP: h, Audit: h,
		GuardURL: func(string) error { return nil }, GuardOperatorURL: func(string) error { return nil }}
}

func s0Broker(t *testing.T, id string, caps []string, host *s0Host) *Broker {
	t.Helper()
	broker, err := NewBroker(Loaded{
		Manifest:     Manifest{ID: id, Name: "S0", Type: TypeSystem, Capabilities: caps},
		Capabilities: caps,
	}, host.services())
	if err != nil {
		t.Fatal(err)
	}
	return broker
}

func requireDeny(t *testing.T, host *s0Host, action, capability string) {
	t.Helper()
	for _, ev := range host.events {
		if ev.Action == action && ev.Capability == capability && ev.Decision == "deny" {
			return
		}
	}
	t.Fatalf("no deny event for %s (%s) in %+v", action, capability, host.events)
}

func validSchedule(service string) sdkplugin.TaskSchedule {
	return sdkplugin.TaskSchedule{ID: "sync-all", Cron: "*/5 * * * *", Service: service, Method: "sync", Payload: json.RawMessage(`{"all":true}`)}
}

func TestKVDeleteRequiresKVWriteAndStaysInThePluginBucket(t *testing.T) {
	host := &s0Host{}
	readOnly := s0Broker(t, "p.reader", []string{"kv:read"}, host)
	if err := readOnly.KVDelete(context.Background(), "record-1"); !errors.Is(err, ErrCapabilityDenied) {
		t.Fatalf("kv.delete without kv:write = %v, want a capability denial", err)
	}
	requireDeny(t, host, "kv.delete", "kv:write")
	if len(host.deleted) != 0 {
		t.Fatalf("a denied kv.delete reached the host: %v", host.deleted)
	}

	writer := s0Broker(t, "p.writer", []string{"kv:write"}, host)
	if err := writer.KVDelete(context.Background(), "record-1"); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"plugin:other/record-1", "../record-1", `a\b`, ""} {
		if err := writer.KVDelete(context.Background(), key); err == nil {
			t.Fatalf("kv.delete of %q was admitted", key)
		}
	}
	if len(host.deleted) != 1 || host.deleted[0] != "plugin:p.writer/record-1" {
		t.Fatalf("host deleted %v, want only the writer's own key", host.deleted)
	}

	noDeleter := s0Broker(t, "p.writer", []string{"kv:write"}, host)
	noDeleter.services.KV = &fakeHostServices{kvValues: map[string][]byte{}}
	if err := noDeleter.KVDelete(context.Background(), "k"); !errors.Is(err, ErrHostServiceUnavailable) {
		t.Fatalf("kv.delete on a host without delete = %v, want unavailable", err)
	}
}

func TestTaskScheduleAndUnscheduleRequireTaskSchedule(t *testing.T) {
	host := &s0Host{}
	// task:run is not task:schedule: one queues approved node work, the other
	// runs the plugin's own methods on a clock.
	without := s0Broker(t, "p.sched", []string{"task:run", "kv:write"}, host)
	if err := without.TaskSchedule(context.Background(), validSchedule("p.sched/jobs")); !errors.Is(err, ErrCapabilityDenied) {
		t.Fatalf("task.schedule without task:schedule = %v", err)
	}
	if _, err := without.TaskUnschedule(context.Background(), "sync-all"); !errors.Is(err, ErrCapabilityDenied) {
		t.Fatalf("task.unschedule without task:schedule = %v", err)
	}
	requireDeny(t, host, "task.schedule", "task:schedule")
	requireDeny(t, host, "task.unschedule", "task:schedule")
	if len(host.scheduled) != 0 || len(host.unscheduled) != 0 {
		t.Fatal("a denied schedule call reached the host")
	}

	with := s0Broker(t, "p.sched", []string{"task:schedule"}, host)
	if err := with.TaskSchedule(context.Background(), validSchedule("p.sched/jobs")); err != nil {
		t.Fatal(err)
	}
	if len(host.scheduledBy) != 1 || host.scheduledBy[0] != "p.sched" {
		t.Fatalf("schedule stored for %v, want the verified plugin id", host.scheduledBy)
	}
	fourMinutes := validSchedule("p.sched/jobs")
	fourMinutes.Cron = "*/4 * * * *"
	if err := with.TaskSchedule(context.Background(), fourMinutes); err == nil || !strings.Contains(err.Error(), "minimum") {
		t.Fatalf("a four-minute schedule = %v, want the five-minute minimum", err)
	}
	foreign := validSchedule("p.other/jobs")
	if err := with.TaskSchedule(context.Background(), foreign); err == nil {
		t.Fatal("a schedule naming another plugin's service was admitted")
	}
	if len(host.scheduled) != 1 {
		t.Fatalf("refused schedules reached the host: %d", len(host.scheduled))
	}
	if removed, err := with.TaskUnschedule(context.Background(), "sync-all"); err != nil || !removed {
		t.Fatalf("unschedule = %v, %v", removed, err)
	}
}

func TestHTTPHostCallsCarryTheInvocationResponseBudget(t *testing.T) {
	host := &s0Host{}
	broker := s0Broker(t, "p.fetch", []string{"http:egress"}, host)
	cases := []struct {
		name  string
		ctx   context.Context
		want  int
		limit int
	}{
		{"unbound uses the default", context.Background(), DefaultInvokeHTTPResponseBytes, 0},
		{"declared budget", BindInvocationMethod(context.Background(), "p.fetch/subscription", "fetch", 8<<20), 8 << 20, 0},
		{"absent budget", BindInvocationMethod(context.Background(), "p.fetch/subscription", "render", 0), DefaultInvokeHTTPResponseBytes, 0},
		{"clamped to the host maximum", BindInvocationMethod(context.Background(), "p.fetch/subscription", "fetch", 64<<20), HostMaxInvokeHTTPResponseBytes, 0},
		// The plugin does not choose its own limit.
		{"caller value overwritten", context.Background(), DefaultInvokeHTTPResponseBytes, 64 << 20},
	}
	for _, tc := range cases {
		if _, err := broker.HTTPDo(tc.ctx, HostHTTPRequest{Method: "GET", URL: "https://provider.example/sub", ResponseLimit: tc.limit}); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := host.httpReqs[len(host.httpReqs)-1].ResponseLimit; got != tc.want {
			t.Fatalf("%s: host got response limit %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestOperatorHTTPAdmitsReadAndRemoveOnlyOnTheArtifactMethods(t *testing.T) {
	const target = "https://10.0.0.5/store"
	cases := []struct {
		plugin, service, method, verb string
		ok                            bool
	}{
		{"latticenet.sub-store", "latticenet.sub-store/subscription", "publish", "PUT", true},
		{"latticenet.sub-store", "latticenet.sub-store/subscription", "publish", "post", true},
		{"latticenet.sub-store", "latticenet.sub-store/subscription", "publish", "PATCH", true},
		{"latticenet.sub-store", "latticenet.sub-store/subscription", "publish", "GET", false},
		{"latticenet.sub-store", "latticenet.sub-store/subscription", "publish", "", false},
		{"latticenet.sub-store", "latticenet.sub-store/subscription", "publish", "DELETE", false},
		{"latticenet.sub-store", "latticenet.sub-store/subscription", "publish", "HEAD", false},
		{"latticenet.sub-store", "latticenet.sub-store/artifact", "restore", "GET", true},
		{"latticenet.sub-store", "latticenet.sub-store/artifact", "restore", " get ", true},
		{"latticenet.sub-store", "latticenet.sub-store/artifact", "restore", "DELETE", false},
		{"latticenet.sub-store", "latticenet.sub-store/artifact", "restore", "OPTIONS", false},
		{"latticenet.sub-store", "latticenet.sub-store/artifact", "delete", "DELETE", true},
		{"latticenet.sub-store", "latticenet.sub-store/artifact", "delete", "GET", false},
		{"latticenet.sub-store", "latticenet.sub-store/artifact", "list", "GET", false},
		{"latticenet.sub-store", "", "", "GET", false},
		// The method's service must be the calling plugin's own.
		{"p.other", "latticenet.sub-store/artifact", "restore", "GET", false},
		// The one legacy reader: the installed Sub-Store's import.
		{"latticenet.sub-store", "latticenet.sub-store/subscription", "migrate", "GET", true},
		{"latticenet.sub-store", "latticenet.sub-store/subscription", "migrate", "DELETE", false},
		{"p.other", "latticenet.sub-store/subscription", "migrate", "GET", false},
	}
	for _, tc := range cases {
		host := &s0Host{}
		broker := s0Broker(t, tc.plugin, []string{"http:operator-target"}, host)
		ctx, err := BindOperatorTargets(context.Background(), []string{target})
		if err != nil {
			t.Fatal(err)
		}
		ctx = BindInvocationMethod(ctx, tc.service, tc.method, 0)
		_, err = broker.HTTPOperatorDo(ctx, HostHTTPRequest{Method: tc.verb, URL: target + "/a.yaml"})
		if tc.ok != (err == nil) {
			t.Fatalf("%s %s.%s %q: err=%v, want admitted=%v", tc.plugin, tc.service, tc.method, tc.verb, err, tc.ok)
		}
		if tc.ok {
			if got := host.opReqs[0].Method; got != strings.ToUpper(strings.TrimSpace(tc.verb)) {
				t.Fatalf("host got method %q for %q", got, tc.verb)
			}
			continue
		}
		if len(host.opReqs) != 0 {
			t.Fatalf("%s.%s %q reached the host", tc.service, tc.method, tc.verb)
		}
		requireDeny(t, host, "http.operator.do", "http:operator-target")
	}

	// GET on artifact.restore is still bound to the operator's origin.
	host := &s0Host{}
	broker := s0Broker(t, "latticenet.sub-store", []string{"http:operator-target"}, host)
	ctx, _ := BindOperatorTargets(context.Background(), []string{target})
	ctx = BindInvocationMethod(ctx, "latticenet.sub-store/artifact", "restore", 0)
	if _, err := broker.HTTPOperatorDo(ctx, HostHTTPRequest{Method: "GET", URL: "https://10.0.0.6/store/a.yaml"}); err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("GET on restore to another origin = %v, want not bound", err)
	}
	if len(host.opReqs) != 0 {
		t.Fatal("a GET to an unbound origin reached the host")
	}
}

// The system runner binds the method and the signed budget an invocation
// serves; nothing the plugin writes chooses them.
func TestSystemRunnerBindsTheInvokedMethodAndItsResponseBudget(t *testing.T) {
	r := newRunner(t, SystemRunnerOptions{})
	script := `#!/bin/sh
read req
echo '{"host_call":{"id":"h1","method":"http.operator.do","params":{"method":"GET","url":"https://10.0.0.5/store/a.yaml"}}}'
IFS= read -r op <&3
echo '{"host_call":{"id":"h2","method":"http.do","params":{"url":"https://provider.example/sub"}}}'
IFS= read -r egress <&3
case "$op" in *'"ok":true'*) op_ok=true ;; *) op_ok=false ;; esac
printf '{"ok":true,"result":{"op_ok":%s}}\n' "$op_ok"
`
	loaded := makeBundle(t, "p.restore", script, "")
	loaded.Manifest.Capabilities = []string{"http:operator-target", "http:egress"}
	loaded.Capabilities = loaded.Manifest.Capabilities
	host := &s0Host{}
	broker, err := NewBroker(loaded, host.services())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Start(context.Background(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Loaded: loaded, Broker: broker}); err != nil {
		t.Fatal(err)
	}
	invoke := func(method string, budget *InvokeBudgetSpec) bool {
		t.Helper()
		resp, err := r.Invoke(context.Background(), InvokeRequest{PluginID: loaded.Manifest.ID, Action: "call", Constraints: InvokeConstraints{
			OperatorTargets: []string{"https://10.0.0.5/store"}, Budget: budget,
			Service: "p.restore/artifact", Method: method,
		}})
		if err != nil {
			t.Fatalf("invoke %s: %v", method, err)
		}
		var out struct {
			OpOK bool `json:"op_ok"`
		}
		if err := json.Unmarshal(resp.Result, &out); err != nil {
			t.Fatal(err)
		}
		return out.OpOK
	}

	budget := &InvokeBudgetSpec{TimeoutMS: 5000, StdoutBytes: 1 << 20, StderrBytes: 1 << 16, HostCalls: 4, HTTPResponseBytes: 4 << 20}
	if !invoke("restore", budget) {
		t.Fatal("GET on artifact.restore was refused")
	}
	if len(host.opReqs) != 1 || host.opReqs[0].ResponseLimit != 4<<20 {
		t.Fatalf("operator request limit = %+v, want the signed 4 MiB", host.opReqs)
	}
	if got := host.httpReqs[0].ResponseLimit; got != 4<<20 {
		t.Fatalf("http.do limit = %d, want the signed 4 MiB", got)
	}
	if invoke("publish", nil) {
		t.Fatal("GET on publish was admitted")
	}
	if len(host.opReqs) != 1 {
		t.Fatal("GET on publish reached the host")
	}
	if got := host.httpReqs[1].ResponseLimit; got != DefaultInvokeHTTPResponseBytes {
		t.Fatalf("http.do limit without a budget = %d, want the default", got)
	}
}

func TestDispatchDecodesTheStoreAndScheduleHostCalls(t *testing.T) {
	host := &s0Host{}
	broker := s0Broker(t, "p.sched", []string{"kv:write", "task:schedule"}, host)
	ctx := context.Background()
	if out, err := dispatchHostCall(ctx, broker, systemHostCall{ID: "1", Method: "kv.delete", Params: json.RawMessage(`{"key":"record-1"}`)}); err != nil || string(out) != `{}` {
		t.Fatalf("kv.delete = %s, %v", out, err)
	}
	schedule := `{"id":"sync-all","cron":"0 * * * *","service":"p.sched/jobs","method":"sync","payload":{"all":true}}`
	if out, err := dispatchHostCall(ctx, broker, systemHostCall{ID: "2", Method: "task.schedule", Params: json.RawMessage(schedule)}); err != nil || string(out) != `{}` {
		t.Fatalf("task.schedule = %s, %v", out, err)
	}
	if string(host.scheduled[0].Payload) != `{"all":true}` {
		t.Fatalf("payload = %s", host.scheduled[0].Payload)
	}
	unknown := `{"id":"x","cron":"0 * * * *","service":"p.sched/jobs","method":"sync","every":"1m"}`
	if _, err := dispatchHostCall(ctx, broker, systemHostCall{ID: "3", Method: "task.schedule", Params: json.RawMessage(unknown)}); err == nil {
		t.Fatal("task.schedule with an unknown field was admitted")
	}
	if out, err := dispatchHostCall(ctx, broker, systemHostCall{ID: "4", Method: "task.unschedule", Params: json.RawMessage(`{"id":"sync-all"}`)}); err != nil || string(out) != `{"removed":true}` {
		t.Fatalf("task.unschedule = %s, %v", out, err)
	}
	if _, err := dispatchHostCall(ctx, broker, systemHostCall{ID: "5", Method: "kv.list", Params: json.RawMessage(`{}`)}); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("an unknown host call = %v", err)
	}
}

func TestInvokeBudgetHTTPResponseBytesWireRules(t *testing.T) {
	var with InvokeBudgetSpec
	if err := json.Unmarshal([]byte(`{"timeout_ms":1,"stdout_bytes":1,"stderr_bytes":1,"host_calls":0,"http_response_bytes":8388608}`), &with); err != nil {
		t.Fatal(err)
	}
	if with.HTTPResponseBytes != 8<<20 || ValidateInvokeBudgetSpec(with) != nil {
		t.Fatalf("an 8 MiB budget = %+v, %v", with, ValidateInvokeBudgetSpec(with))
	}
	over := with
	over.HTTPResponseBytes = 8<<20 + 1
	if err := ValidateInvokeBudgetSpec(over); err == nil {
		t.Fatal("a budget past the host maximum validated")
	}
	if err := json.Unmarshal([]byte(`{"timeout_ms":1,"stdout_bytes":1,"stderr_bytes":1,"host_calls":0,"http_response_bytes":0}`), &with); err == nil {
		t.Fatal("an explicit zero http_response_bytes was admitted")
	}
	// A budget signed before the field existed encodes to the same bytes, so
	// its signature still verifies.
	old := []byte(`{"timeout_ms":30000,"stdout_bytes":8388608,"stderr_bytes":65536,"host_calls":78}`)
	var absent InvokeBudgetSpec
	if err := json.Unmarshal(old, &absent); err != nil {
		t.Fatal(err)
	}
	again, _ := json.Marshal(absent)
	if string(again) != string(old) {
		t.Fatalf("an old budget re-encoded as %s", again)
	}
	if got := ResolveInvokeBudget(&absent, DefaultInvokeBudgetSpec()).HTTPResponseBytes; got != DefaultInvokeHTTPResponseBytes {
		t.Fatalf("an absent http_response_bytes resolved to %d", got)
	}
	if got := ResolveInvokeBudget(&with, DefaultInvokeBudgetSpec()).HTTPResponseBytes; got != 8<<20 {
		t.Fatalf("a signed 8 MiB resolved to %d", got)
	}
}

func TestTaskScheduleIsAHostRiskCapability(t *testing.T) {
	if risk, ok := CapabilityRisk("task:schedule"); !ok || risk != RiskHost {
		t.Fatalf("task:schedule risk = %q, %v", risk, ok)
	}
	if hostRiskExemptForNonSystem["task:schedule"] {
		t.Fatal("task:schedule must stay system-only")
	}
}
