package plugin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	sdkplugin "github.com/LatticeNet/lattice-sdk/plugin"
)

// casHostServices is fakeHostServices with the compare-and-swap half, atomic
// under one lock the way the server's store holds its own.
type casHostServices struct {
	*fakeHostServices
	mu sync.Mutex
}

func (c *casHostServices) PutIfMatch(_ context.Context, key string, value []byte, ifMatch string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	current, exists := c.kvValues[key]
	if (ifMatch == "" && exists) || (ifMatch != "" && (!exists || KVValueDigest(current) != ifMatch)) {
		return ErrKVConflict
	}
	c.kvPuts++
	c.kvValues[key] = append([]byte(nil), value...)
	return nil
}

func kvFrame(t *testing.T, fields map[string]any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// kvGetFrame reads one key through the kv.get host call and returns the
// value and the sha256 the reply carries.
func kvGetFrame(t *testing.T, broker *Broker, key string) (string, string, bool) {
	t.Helper()
	out, err := dispatchHostCall(context.Background(), broker, systemHostCall{ID: "g", Method: "kv.get", Params: kvFrame(t, map[string]any{"key": key})})
	if err != nil {
		t.Fatalf("kv.get %s: %v", key, err)
	}
	var resp struct {
		OK          bool   `json:"ok"`
		ValueBase64 string `json:"value_base64"`
		SHA256      string `json:"sha256"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatal(err)
	}
	value, err := base64.StdEncoding.DecodeString(resp.ValueBase64)
	if err != nil {
		t.Fatal(err)
	}
	return string(value), resp.SHA256, resp.OK
}

func kvPutFrame(broker *Broker, key, value string, ifMatch *string) error {
	fields := map[string]any{"key": key, "value_base64": base64.StdEncoding.EncodeToString([]byte(value))}
	if ifMatch != nil {
		fields["if_match"] = *ifMatch
	}
	raw, _ := json.Marshal(fields)
	_, err := dispatchHostCall(context.Background(), broker, systemHostCall{ID: "p", Method: "kv.put", Params: raw})
	return err
}

// TestKVPutIfMatch drives the kv.get and kv.put host calls as a plugin sends
// them: kv.get carries the stored value's sha256, a kv.put with the digest
// it read writes, a stale digest is refused with kv_conflict and writes
// nothing, an empty if_match is a create that a present key refuses, a put
// without if_match writes unconditionally as before, and a malformed digest
// is refused before the store is read.
func TestKVPutIfMatch(t *testing.T) {
	services := &casHostServices{fakeHostServices: &fakeHostServices{kvValues: map[string][]byte{}}}
	broker := newTestBroker(t, "p.cas", []string{"kv:read", "kv:write"}, HostServices{KV: services, Audit: services})
	empty := ""

	if err := kvPutFrame(broker, "index", "v1", &empty); err != nil {
		t.Fatalf("a create of a missing key was refused: %v", err)
	}
	value, digest, ok := kvGetFrame(t, broker, "index")
	if !ok || value != "v1" || digest != KVValueDigest([]byte("v1")) {
		t.Fatalf("kv.get = %q digest %q ok %v, want v1 with its sha256", value, digest, ok)
	}
	if err := kvPutFrame(broker, "index", "v-other", &empty); err == nil || !strings.HasPrefix(err.Error(), sdkplugin.KVConflictCode) {
		t.Fatalf("a create of an existing key = %v, want kv_conflict", err)
	}
	if err := kvPutFrame(broker, "index", "v2", &digest); err != nil {
		t.Fatalf("a put with the digest it read was refused: %v", err)
	}
	stale := digest
	if err := kvPutFrame(broker, "index", "v3", &stale); err == nil || !strings.HasPrefix(err.Error(), sdkplugin.KVConflictCode) {
		t.Fatalf("a put with a stale digest = %v, want kv_conflict", err)
	}
	if value, _, _ := kvGetFrame(t, broker, "index"); value != "v2" {
		t.Fatalf("a refused put wrote: the key holds %q, want v2", value)
	}
	missing := KVValueDigest([]byte("anything"))
	if err := kvPutFrame(broker, "absent", "x", &missing); err == nil || !strings.HasPrefix(err.Error(), sdkplugin.KVConflictCode) {
		t.Fatalf("a put naming a digest for a missing key = %v, want kv_conflict", err)
	}
	if err := kvPutFrame(broker, "index", "v4", nil); err != nil {
		t.Fatalf("a put without if_match was refused: %v", err)
	}
	if value, _, _ := kvGetFrame(t, broker, "index"); value != "v4" {
		t.Fatalf("an unconditional put did not write: %q", value)
	}
	bad := "ABCDEF"
	if err := kvPutFrame(broker, "index", "v5", &bad); err == nil || strings.HasPrefix(err.Error(), sdkplugin.KVConflictCode) {
		t.Fatalf("a malformed if_match = %v, want a refusal that is not a conflict", err)
	}
	if _, digest, ok := kvGetFrame(t, broker, "absent"); ok || digest != "" {
		t.Fatalf("a missing key answered ok %v digest %q", ok, digest)
	}
}

// A host without the compare-and-swap half fails a conditional put closed:
// writing blind would let two invocations overwrite each other's index.
func TestKVPutIfMatchFailsClosedWithoutCompareHost(t *testing.T) {
	services := &fakeHostServices{kvValues: map[string][]byte{"plugin:p.old/index": []byte("v1")}}
	broker := newTestBroker(t, "p.old", []string{"kv:read", "kv:write"}, HostServices{KV: services, Audit: services})
	digest := KVValueDigest([]byte("v1"))
	if err := kvPutFrame(broker, "index", "v2", &digest); err == nil || !strings.Contains(err.Error(), "compare-and-swap") {
		t.Fatalf("a conditional put on a host without compare-and-swap = %v", err)
	}
	if services.kvPuts != 0 || string(services.kvValues["plugin:p.old/index"]) != "v1" {
		t.Fatal("the conditional put wrote through the unconditional path")
	}
}

// A conditional put needs kv:write like any put, and stays inside the
// plugin's own bucket.
func TestKVPutIfMatchKeepsTheCapabilityAndTheBucket(t *testing.T) {
	services := &casHostServices{fakeHostServices: &fakeHostServices{kvValues: map[string][]byte{}}}
	reader := newTestBroker(t, "p.ro", []string{"kv:read"}, HostServices{KV: services, Audit: services})
	empty := ""
	if err := kvPutFrame(reader, "index", "v1", &empty); err == nil {
		t.Fatal("a conditional put without kv:write was admitted")
	}
	writer := newTestBroker(t, "p.rw", []string{"kv:write"}, HostServices{KV: services, Audit: services})
	if err := kvPutFrame(writer, "other/index", "v1", &empty); err == nil {
		t.Fatal("a conditional put with a slash in the key was admitted")
	}
	if err := kvPutFrame(writer, "index", "v1", &empty); err != nil {
		t.Fatal(err)
	}
	if _, ok := services.kvValues["plugin:p.rw/index"]; !ok {
		t.Fatalf("the put landed outside the plugin's bucket: %v", services.kvValues)
	}
}
