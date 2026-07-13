package plugin

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// captureAudit records every broker host-call decision for assertions.
type captureAudit struct {
	mu     sync.Mutex
	events []HostCallEvent
}

func (a *captureAudit) RecordHostCall(_ context.Context, e HostCallEvent) {
	a.mu.Lock()
	a.events = append(a.events, e)
	a.mu.Unlock()
}

func (a *captureAudit) find(decision, capability string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.events {
		if e.Decision == decision && e.Capability == capability {
			return true
		}
	}
	return false
}

func newTestBroker(t *testing.T, id string, caps []string, services HostServices) *Broker {
	t.Helper()
	b, err := NewBroker(Loaded{
		Manifest:     Manifest{ID: id, Name: id, Type: TypeSystem, Capabilities: caps},
		Capabilities: caps,
	}, services)
	if err != nil {
		t.Fatalf("NewBroker(%s): %v", id, err)
	}
	return b
}

func TestRPCRegistryRegisterValidation(t *testing.T) {
	r := NewRPCRegistry()
	h := func(context.Context, string, []byte) ([]byte, error) { return nil, nil }
	cases := []struct {
		name                    string
		owner, service, version string
		methods                 []string
		handler                 RPCHandler
	}{
		{"no owner", "", "svc", "v1", []string{"m"}, h},
		{"no service", "p", "", "v1", []string{"m"}, h},
		{"nil handler", "p", "svc", "v1", []string{"m"}, nil},
		{"no methods", "p", "svc", "v1", nil, h},
		{"empty method", "p", "svc", "v1", []string{""}, h},
	}
	for _, c := range cases {
		if err := r.Register(c.owner, c.service, c.version, c.methods, c.handler); !errors.Is(err, ErrRPCInvalid) {
			t.Fatalf("%s: want ErrRPCInvalid, got %v", c.name, err)
		}
	}
	if err := r.Register("p", "svc", "v1", []string{"m"}, h); err != nil {
		t.Fatalf("valid register: %v", err)
	}
}

func TestRPCRegistryCallAuthorization(t *testing.T) {
	r := NewRPCRegistry()
	if err := r.Register("owner.plugin", "owner.plugin/nodes", "v1", []string{"export"},
		func(_ context.Context, method string, req []byte) ([]byte, error) {
			return []byte("ok:" + method + ":" + string(req)), nil
		}); err != nil {
		t.Fatalf("register: %v", err)
	}

	// owner may self-call without a grant
	if out, err := r.Call(context.Background(), "owner.plugin", "owner.plugin/nodes", "export", []byte("x")); err != nil || string(out) != "ok:export:x" {
		t.Fatalf("self-call: out=%q err=%v", out, err)
	}

	// a different caller is denied until granted
	if _, err := r.Call(context.Background(), "caller.plugin", "owner.plugin/nodes", "export", nil); !errors.Is(err, ErrRPCDenied) {
		t.Fatalf("ungranted caller: want ErrRPCDenied, got %v", err)
	}
	r.Allow("caller.plugin", "owner.plugin/nodes")
	if out, err := r.Call(context.Background(), "caller.plugin", "owner.plugin/nodes", "export", []byte("y")); err != nil || string(out) != "ok:export:y" {
		t.Fatalf("granted caller: out=%q err=%v", out, err)
	}
	// revoke removes access again
	r.Revoke("caller.plugin", "owner.plugin/nodes")
	if _, err := r.Call(context.Background(), "caller.plugin", "owner.plugin/nodes", "export", nil); !errors.Is(err, ErrRPCDenied) {
		t.Fatalf("after revoke: want ErrRPCDenied, got %v", err)
	}

	// unknown service / method
	if _, err := r.Call(context.Background(), "owner.plugin", "missing/svc", "export", nil); !errors.Is(err, ErrRPCNoService) {
		t.Fatalf("missing service: want ErrRPCNoService, got %v", err)
	}
	if _, err := r.Call(context.Background(), "owner.plugin", "owner.plugin/nodes", "nope", nil); !errors.Is(err, ErrRPCNoMethod) {
		t.Fatalf("missing method: want ErrRPCNoMethod, got %v", err)
	}

	// unregister
	r.Unregister("owner.plugin/nodes")
	if _, err := r.Call(context.Background(), "owner.plugin", "owner.plugin/nodes", "export", nil); !errors.Is(err, ErrRPCNoService) {
		t.Fatalf("after unregister: want ErrRPCNoService, got %v", err)
	}
}

func TestRPCRegistryServicesDiscovery(t *testing.T) {
	r := NewRPCRegistry()
	h := func(context.Context, string, []byte) ([]byte, error) { return nil, nil }
	_ = r.Register("p2", "b.svc", "v2", []string{"m2", "m1"}, h)
	_ = r.Register("p1", "a.svc", "v1", []string{"only"}, h)
	got := r.Services()
	if len(got) != 2 || got[0].Service != "a.svc" || got[1].Service != "b.svc" {
		t.Fatalf("services not sorted by id: %+v", got)
	}
	if got[1].Methods[0] != "m1" || got[1].Methods[1] != "m2" {
		t.Fatalf("methods not sorted: %+v", got[1].Methods)
	}
}

func TestRPCRegistryMethodGrantDoesNotExpandWithService(t *testing.T) {
	r := NewRPCRegistry()
	if err := r.Register("owner.plugin", "owner.plugin/nodes", "v1", []string{"export", "delete"},
		func(_ context.Context, method string, _ []byte) ([]byte, error) { return []byte(method), nil }); err != nil {
		t.Fatal(err)
	}
	r.AllowMethods("caller.plugin", "owner.plugin/nodes", []string{"export"})
	if out, err := r.Call(context.Background(), "caller.plugin", "owner.plugin/nodes", "export", nil); err != nil || string(out) != "export" {
		t.Fatalf("granted method failed: out=%q err=%v", out, err)
	}
	if _, err := r.Call(context.Background(), "caller.plugin", "owner.plugin/nodes", "delete", nil); !errors.Is(err, ErrRPCDenied) {
		t.Fatalf("undeclared dependency method: want ErrRPCDenied, got %v", err)
	}
}

func TestBrokerRPCCallRequiresCapability(t *testing.T) {
	reg := NewRPCRegistry()
	_ = reg.Register("owner.plugin", "owner.plugin/nodes", "v1", []string{"export"},
		func(context.Context, string, []byte) ([]byte, error) { return []byte("data"), nil })
	audit := &captureAudit{}

	// caller WITHOUT rpc:call -> capability denied + deny audited, registry untouched
	noCap := newTestBroker(t, "caller.nocap", []string{"kv:read"}, HostServices{RPC: reg, Audit: audit})
	if _, err := noCap.RPCCall(context.Background(), "owner.plugin/nodes", "export", nil); !errors.Is(err, ErrCapabilityDenied) {
		t.Fatalf("no rpc:call: want ErrCapabilityDenied, got %v", err)
	}
	if !audit.find("deny", capRPCCall) {
		t.Fatalf("capability denial not audited")
	}

	// caller WITH rpc:call but no grant -> registry denies + deny audited
	caller := newTestBroker(t, "caller.plugin", []string{"rpc:call"}, HostServices{RPC: reg, Audit: audit})
	if _, err := caller.RPCCall(context.Background(), "owner.plugin/nodes", "export", nil); !errors.Is(err, ErrRPCDenied) {
		t.Fatalf("ungranted: want ErrRPCDenied, got %v", err)
	}

	// grant -> success, allow audited
	reg.Allow("caller.plugin", "owner.plugin/nodes")
	out, err := caller.RPCCall(context.Background(), "owner.plugin/nodes", "export", nil)
	if err != nil || string(out) != "data" {
		t.Fatalf("granted call: out=%q err=%v", out, err)
	}
	if !audit.find("allow", capRPCCall) {
		t.Fatalf("allowed call not audited")
	}
}

func TestBrokerRPCCallServiceUnavailable(t *testing.T) {
	// rpc:call granted but no RPC host wired -> ErrHostServiceUnavailable, not panic.
	b := newTestBroker(t, "caller.plugin", []string{"rpc:call"}, HostServices{})
	if _, err := b.RPCCall(context.Background(), "x/y", "m", nil); !errors.Is(err, ErrHostServiceUnavailable) {
		t.Fatalf("nil RPC host: want ErrHostServiceUnavailable, got %v", err)
	}
}

func TestRPCRegistryConcurrentAccess(t *testing.T) {
	r := NewRPCRegistry()
	_ = r.Register("owner", "owner/svc", "v1", []string{"m"},
		func(context.Context, string, []byte) ([]byte, error) { return []byte("ok"), nil })
	r.Allow("caller", "owner/svc")
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func() { defer wg.Done(); _, _ = r.Call(context.Background(), "caller", "owner/svc", "m", nil) }()
		go func() { defer wg.Done(); _ = r.Services() }()
		go func() { defer wg.Done(); r.Allow("caller2", "owner/svc") }()
	}
	wg.Wait()
}
