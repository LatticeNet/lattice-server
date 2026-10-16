package server

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// TestKVPutIfMatchRefusesStaleDigest runs the conditional kv.put against the
// real host and store: the digest kv.get reports writes, the same digest a
// second time is stale and refused without writing, a create of an existing
// key is refused, and an unconditional put still writes. This is the CAS the
// sub-store plugin's index writes rely on from a124 on.
func TestKVPutIfMatchRefusesStaleDigest(t *testing.T) {
	srv, st := newServerForPluginHost(t)
	ctx := context.Background()
	broker := kvBroker(t, srv.pluginHostServices(), "p.index", "kv:read", "kv:write")

	if err := broker.KVPutIfMatch(ctx, "subscriptions-index-v2", []byte(`{"version":2}`), ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	value, ok, err := broker.KVGet(ctx, "subscriptions-index-v2")
	if err != nil || !ok {
		t.Fatalf("kv.get = %v, %v", ok, err)
	}
	read := plugin.KVValueDigest(value)
	if err := broker.KVPutIfMatch(ctx, "subscriptions-index-v2", []byte(`{"version":2,"records":[1]}`), read); err != nil {
		t.Fatalf("a put with the digest it read: %v", err)
	}
	if err := broker.KVPutIfMatch(ctx, "subscriptions-index-v2", []byte(`{"version":2,"records":[2]}`), read); !errors.Is(err, plugin.ErrKVConflict) {
		t.Fatalf("a put with the stale digest = %v, want kv_conflict", err)
	}
	if e, _ := st.KVEntry("plugin:p.index", "subscriptions-index-v2"); e.Value != `{"version":2,"records":[1]}` {
		t.Fatalf("a refused put wrote: %s", e.Value)
	}
	if err := broker.KVPutIfMatch(ctx, "subscriptions-index-v2", []byte(`{}`), ""); !errors.Is(err, plugin.ErrKVConflict) {
		t.Fatalf("a create of an existing key = %v, want kv_conflict", err)
	}
	if err := broker.KVPut(ctx, "subscriptions-index-v2", []byte(`{"blind":true}`)); err != nil {
		t.Fatalf("an unconditional put: %v", err)
	}
	if e, _ := st.KVEntry("plugin:p.index", "subscriptions-index-v2"); e.Value != `{"blind":true}` {
		t.Fatalf("the unconditional put did not write: %s", e.Value)
	}
}

// Of writers that all read the same value, exactly one conditional put wins;
// the rest are refused and none of their values is stored.
func TestKVPutIfMatchAdmitsOneOfConcurrentWriters(t *testing.T) {
	srv, st := newServerForPluginHost(t)
	ctx := context.Background()
	broker := kvBroker(t, srv.pluginHostServices(), "p.race", "kv:read", "kv:write")
	if err := broker.KVPut(ctx, "index", []byte("base")); err != nil {
		t.Fatal(err)
	}
	read := plugin.KVValueDigest([]byte("base"))
	const writers = 16
	var wg sync.WaitGroup
	results := make([]error, writers)
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = broker.KVPutIfMatch(ctx, "index", []byte("writer-"+strconv.Itoa(i)), read)
		}()
	}
	wg.Wait()
	won := -1
	for i, err := range results {
		switch {
		case err == nil && won >= 0:
			t.Fatalf("writers %d and %d both won", won, i)
		case err == nil:
			won = i
		case !errors.Is(err, plugin.ErrKVConflict):
			t.Fatalf("writer %d: %v", i, err)
		}
	}
	if won < 0 {
		t.Fatal("no writer won")
	}
	if e, _ := st.KVEntry("plugin:p.race", "index"); e.Value != "writer-"+strconv.Itoa(won) {
		t.Fatalf("stored %q, the winner was writer-%d", e.Value, won)
	}
}

// The store's compare-and-swap compares the digest of the stored bytes.
func TestStorePutKVIfMatchComparesTheStoredDigest(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	entry := model.KVEntry{Bucket: "plugin:p", Key: "k", Value: "one"}
	if err := st.PutKVIfMatch(entry, store.KVValueDigest("one")); !errors.Is(err, store.ErrKVConflict) {
		t.Fatalf("a digest for a missing key = %v", err)
	}
	if err := st.PutKVIfMatch(entry, ""); err != nil {
		t.Fatal(err)
	}
	entry.Value = "two"
	if err := st.PutKVIfMatch(entry, store.KVValueDigest("two")); !errors.Is(err, store.ErrKVConflict) {
		t.Fatalf("the digest of the new value instead of the stored one = %v", err)
	}
	if err := st.PutKVIfMatch(entry, store.KVValueDigest("one")); err != nil {
		t.Fatal(err)
	}
	if e, _ := st.KVEntry("plugin:p", "k"); e.Value != "two" {
		t.Fatalf("stored %q", e.Value)
	}
}
