package server

import (
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// The read model is built once and served from cache until an invalidation;
// line lookups go through the hash index, not a fleet rescan.
func TestLineReadModelCacheLifecycle(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	seedLinemetaNodes(t, srv)

	groups, index := srv.lineReadModel()
	hub := findLine(t, groups, "node-a", "hub-a")
	if index[hub.LineHashID].Tag != "hub-a" {
		t.Fatalf("index: %+v", index[hub.LineHashID])
	}

	// Inventory changes are invisible until invalidation.
	srv.singboxInvMu.Lock()
	inv := srv.singboxInv["node-a"]
	inv.Nodes = append(inv.Nodes, model.SingBoxNode{Name: "new-line", Protocol: "trojan", Port: "9999", Address: "203.0.113.5"})
	srv.singboxInv["node-a"] = inv
	srv.singboxInvMu.Unlock()
	cached, _ := srv.lineReadModel()
	for _, g := range cached {
		for _, ln := range g.Lines {
			if ln.Tag == "new-line" {
				t.Fatal("cache must not rebuild on its own")
			}
		}
	}
	srv.invalidateLineReadModel()
	fresh, freshIndex := srv.lineReadModel()
	found := false
	for _, g := range fresh {
		for _, ln := range g.Lines {
			if ln.Tag == "new-line" {
				found = true
				if freshIndex[ln.LineHashID].Tag != "new-line" {
					t.Fatalf("index miss after rebuild: %+v", freshIndex)
				}
			}
		}
	}
	if !found {
		t.Fatal("new line missing after invalidation")
	}

	// lineFromReadModel resolves via the index.
	if _, ok := srv.lineFromReadModel(hub.LineHashID); !ok {
		t.Fatal("index lookup failed")
	}

	// The TTL safety net rebuilds even without an explicit invalidation.
	srv.lineCache.mu.Lock()
	srv.lineCache.builtAt = time.Now().Add(-2 * lineReadModelTTL)
	srv.lineCache.mu.Unlock()
	srv.singboxInvMu.Lock()
	inv.Nodes = append(inv.Nodes, model.SingBoxNode{Name: "ttl-line", Protocol: "vless", Port: "9998", Address: "203.0.113.5"})
	srv.singboxInv["node-a"] = inv
	srv.singboxInvMu.Unlock()
	afterTTL, _ := srv.lineReadModel()
	seen := false
	for _, g := range afterTTL {
		for _, ln := range g.Lines {
			if ln.Tag == "ttl-line" {
				seen = true
			}
		}
	}
	if !seen {
		t.Fatal("TTL expiry must force a rebuild")
	}
}

// Invalidations wired into the mutation paths: an inventory ingest marks the
// model stale (the discover handler does this before queueing any sync).
func TestInventoryIngestInvalidates(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	seedLinemetaNodes(t, srv)
	srv.lineReadModel()
	if !srv.lineCache.valid {
		t.Fatal("cache should be valid after first build")
	}
	srv.singboxInvMu.Lock()
	srv.singboxInv["node-b"] = model.SingBoxInventory{NodeID: "node-b", Status: "ok"}
	srv.singboxInvMu.Unlock()
	srv.invalidateLineReadModel()
	if srv.lineCache.valid {
		t.Fatal("invalidation must mark the cache stale")
	}
}
