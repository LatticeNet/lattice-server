package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
)

// countingKVStore counts the store reads the plugin KV host makes.
type countingKVStore struct {
	inner   pluginKVStore
	scans   atomic.Int64
	lookups atomic.Int64
}

func (c *countingKVStore) KV(bucket string) []model.KVEntry {
	c.scans.Add(1)
	return c.inner.KV(bucket)
}

func (c *countingKVStore) KVEntry(bucket, key string) (model.KVEntry, bool) {
	c.lookups.Add(1)
	return c.inner.KVEntry(bucket, key)
}

func (c *countingKVStore) PutKV(entry model.KVEntry) error { return c.inner.PutKV(entry) }
func (c *countingKVStore) DeleteKV(bucket, key string) error {
	return c.inner.DeleteKV(bucket, key)
}

func kvBroker(t *testing.T, services plugin.HostServices, id string, caps ...string) *plugin.Broker {
	t.Helper()
	broker, err := plugin.NewBroker(plugin.Loaded{
		Manifest:     plugin.Manifest{ID: id, Name: id, Type: plugin.TypeSystem, Capabilities: caps},
		Capabilities: caps,
	}, services)
	if err != nil {
		t.Fatal(err)
	}
	return broker
}

// kv.get reads one key by its key. The bucket scan it replaced read every KV
// entry of every bucket on each call, which is what made a per-record store
// cost a bucket walk per record.
func TestPluginKVGetIsOneIndexedRead(t *testing.T) {
	srv, st := newServerForPluginHost(t)
	for i := range 40 {
		if err := st.PutKV(model.KVEntry{Bucket: "plugin:p.store", Key: "record-v2-" + strconv.Itoa(i), Value: "v" + strconv.Itoa(i)}); err != nil {
			t.Fatal(err)
		}
		if err := st.PutKV(model.KVEntry{Bucket: "default", Key: "k" + strconv.Itoa(i), Value: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	counting := &countingKVStore{inner: st}
	services := srv.pluginHostServices()
	services.KV = &pluginHost{server: srv, kv: counting}
	broker := kvBroker(t, services, "p.store", "kv:read")

	value, ok, err := broker.KVGet(context.Background(), "record-v2-17")
	if err != nil || !ok || string(value) != "v17" {
		t.Fatalf("kv.get = %q, %v, %v", value, ok, err)
	}
	if scans, lookups := counting.scans.Load(), counting.lookups.Load(); scans != 0 || lookups != 1 {
		t.Fatalf("kv.get made %d bucket scans and %d key reads, want 0 and 1", scans, lookups)
	}
	if _, ok, err := broker.KVGet(context.Background(), "record-v2-404"); err != nil || ok {
		t.Fatalf("a missing key = %v, %v", ok, err)
	}
	if scans, lookups := counting.scans.Load(), counting.lookups.Load(); scans != 0 || lookups != 2 {
		t.Fatalf("a miss made %d bucket scans and %d key reads in total, want 0 and 2", scans, lookups)
	}
}

func TestPluginKVDeleteRemovesOnlyTheCallersOwnKey(t *testing.T) {
	srv, st := newServerForPluginHost(t)
	ctx := context.WithValue(context.Background(), requestIDContextKey{}, "req-kv-delete")
	alpha := kvBroker(t, srv.pluginHostServices(), "p.alpha", "kv:read", "kv:write")
	beta := kvBroker(t, srv.pluginHostServices(), "p.beta", "kv:read", "kv:write")
	for _, b := range []*plugin.Broker{alpha, beta} {
		for _, key := range []string{"shared", "kept"} {
			if err := b.KVPut(ctx, key, []byte(b.PluginID()+"/"+key)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := st.PutKV(model.KVEntry{Bucket: "default", Key: "shared", Value: "operator"}); err != nil {
		t.Fatal(err)
	}

	if err := alpha.KVDelete(ctx, "shared"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := alpha.KVGet(ctx, "shared"); ok {
		t.Fatal("the deleted key is still readable")
	}
	if v, ok, _ := alpha.KVGet(ctx, "kept"); !ok || string(v) != "p.alpha/kept" {
		t.Fatalf("the plugin's other key = %q, %v", v, ok)
	}
	if v, ok, _ := beta.KVGet(ctx, "shared"); !ok || string(v) != "p.beta/shared" {
		t.Fatalf("another plugin's key of the same name = %q, %v", v, ok)
	}
	if e, ok := st.KVEntry("default", "shared"); !ok || e.Value != "operator" {
		t.Fatalf("the operator's key of the same name = %+v, %v", e, ok)
	}
	// Deleting again is not an error: the key is gone either way.
	if err := alpha.KVDelete(ctx, "shared"); err != nil {
		t.Fatalf("a second delete = %v", err)
	}
	for _, key := range []string{"../default/shared", "plugin:p.beta/shared", ""} {
		if err := alpha.KVDelete(ctx, key); err == nil {
			t.Fatalf("kv.delete of %q was admitted", key)
		}
	}
	if _, ok, _ := beta.KVGet(ctx, "shared"); !ok {
		t.Fatal("a crafted key reached another plugin's entry")
	}
	// The host re-checks the namespace even for a composite key the broker
	// would never build.
	if err := (&pluginHost{server: srv}).Delete(ctx, "default/shared"); err == nil {
		t.Fatal("the host deleted outside a plugin bucket")
	}
	requirePluginHostAudit(t, st, "plugin.host.kv.delete", "kv:write", "p.alpha", "allow", "req-kv-delete")

	reader := kvBroker(t, srv.pluginHostServices(), "p.beta", "kv:read")
	if err := reader.KVDelete(ctx, "kept"); !errors.Is(err, plugin.ErrCapabilityDenied) {
		t.Fatalf("kv.delete without kv:write = %v", err)
	}
	if _, ok, _ := beta.KVGet(ctx, "kept"); !ok {
		t.Fatal("a denied delete removed the key")
	}
	requirePluginHostAudit(t, st, "plugin.host.kv.delete", "kv:write", "p.beta", "deny", "req-kv-delete")
}

// The response budget is enforced on the body the host reads: a body exactly
// at the method's signed budget passes, one byte more is refused.
func TestPluginHTTPResponseBudgetIsEnforcedOnTheBody(t *testing.T) {
	srv, _ := newServerForPluginHost(t)
	host := &pluginHost{server: srv}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		_, _ = w.Write(bytes.Repeat([]byte("n"), n))
	}))
	defer upstream.Close()
	fetch := func(n, limit int) ([]byte, error) {
		resp, err := host.doHTTP(context.Background(), plugin.HostHTTPRequest{
			Method: http.MethodGet, URL: upstream.URL + "/?n=" + strconv.Itoa(n), ResponseLimit: limit,
		}, upstream.Client())
		return resp.Body, err
	}
	const declared = 3 << 20
	if body, err := fetch(declared, declared); err != nil || len(body) != declared {
		t.Fatalf("a body at the budget = %d bytes, %v", len(body), err)
	}
	if _, err := fetch(declared+1, declared); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("a body one byte over the budget = %v", err)
	}
	// No budget is the 256 KiB every method had before budgets named one.
	if _, err := fetch(plugin.DefaultInvokeHTTPResponseBytes, 0); err != nil {
		t.Fatalf("a body at the default = %v", err)
	}
	if _, err := fetch(plugin.DefaultInvokeHTTPResponseBytes+1, 0); err == nil {
		t.Fatal("a body over the default passed without a budget")
	}
	// The host clamps to 8 MiB whatever the request says.
	if _, err := fetch(plugin.HostMaxInvokeHTTPResponseBytes+1, 64<<20); err == nil {
		t.Fatal("a body over the host maximum passed")
	}
}

// captureRunner records the constraints a service call is invoked with.
type captureRunner struct {
	mu   sync.Mutex
	reqs []plugin.InvokeRequest
}

func (r *captureRunner) Name() string { return "capture" }
func (r *captureRunner) Start(context.Context, plugin.RunnerStartRequest) (plugin.RunnerStartResult, error) {
	return plugin.RunnerStartResult{}, nil
}
func (r *captureRunner) Stop(context.Context, plugin.RunnerStopRequest) error { return nil }
func (r *captureRunner) Invoke(_ context.Context, req plugin.InvokeRequest) (plugin.InvokeResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, req)
	return plugin.InvokeResponse{OK: true, Result: json.RawMessage(`{}`)}, nil
}

// The broker admits GET and DELETE on http.operator.do by the method an
// invocation serves, so the server must hand the runner that method itself
// rather than leave it to the payload the plugin also reads.
func TestServiceCallsCarryTheirServiceAndMethodToTheRunner(t *testing.T) {
	srv, _ := newServerForPluginHost(t)
	runner := &captureRunner{}
	srv.pluginRuntime = plugin.NewRuntimeManagerWithOptions(plugin.RuntimeManagerOptions{
		Services: srv.pluginHostServices(), Runners: map[string]plugin.Runner{plugin.TypeSystem: runner},
	})
	loaded := plugin.Loaded{
		Manifest:     plugin.Manifest{ID: "p.capture", Name: "Capture", Type: plugin.TypeSystem, Capabilities: []string{"kv:read"}},
		Capabilities: []string{"kv:read"}, BundlePath: t.TempDir(),
	}
	if _, err := srv.pluginRuntime.Start(context.Background(), loaded); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.callRuntimePluginService(context.Background(), "p.capture", "p.capture/artifact", "restore", json.RawMessage(`{}`), nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(runner.reqs) != 1 {
		t.Fatalf("runner saw %d invocations", len(runner.reqs))
	}
	if c := runner.reqs[0].Constraints; c.Service != "p.capture/artifact" || c.Method != "restore" {
		t.Fatalf("constraints carried service %q method %q", c.Service, c.Method)
	}
}
