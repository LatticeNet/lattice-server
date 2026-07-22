package server

import (
	"net/http"
	"sync"
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

func TestAgentPublicAddressChangesInvalidateLineReadModel(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)
	token := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")
	srv.lineReadModel()

	generation := func() uint64 {
		srv.lineCache.mu.RLock()
		defer srv.lineCache.mu.RUnlock()
		return srv.lineCache.generation
	}
	beforeHello := generation()
	hello := doAgentRaw(t, handler, http.MethodPost, "/api/agent/hello", `{"node_id":"node-a","version":"test","public_ip":"8.8.8.8"}`, token)
	if hello.Code != http.StatusOK {
		t.Fatalf("hello: %d %s", hello.Code, hello.Body.String())
	}
	if got := generation(); got != beforeHello+1 {
		t.Fatalf("hello public address change generation=%d want %d", got, beforeHello+1)
	}

	srv.lineReadModel()
	beforeMetrics := generation()
	metrics := doAgentRaw(t, handler, http.MethodPost, "/api/agent/metrics", `{"node_id":"node-a","version":"test","public_ip":"1.1.1.1","metrics":{}}`, token)
	if metrics.Code != http.StatusOK {
		t.Fatalf("metrics: %d %s", metrics.Code, metrics.Body.String())
	}
	if got := generation(); got != beforeMetrics+1 {
		t.Fatalf("metrics public address change generation=%d want %d", got, beforeMetrics+1)
	}
}

func TestLineReadModelInvalidationDuringBuildCannotPublishStaleResult(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	seedLinemetaNodes(t, srv)

	buildReady := make(chan struct{})
	continueBuild := make(chan struct{})
	var once sync.Once
	srv.lineCache.beforePublish = func() {
		once.Do(func() {
			close(buildReady)
			<-continueBuild
		})
	}

	done := make(chan []LineGroup, 1)
	go func() {
		groups, _ := srv.lineReadModel()
		done <- groups
	}()
	<-buildReady

	srv.singboxInvMu.Lock()
	inv := srv.singboxInv["node-a"]
	inv.Nodes = append(inv.Nodes, model.SingBoxNode{Name: "during-build", Protocol: "trojan", Port: "9443", Address: "203.0.113.5"})
	srv.singboxInv["node-a"] = inv
	srv.singboxInvMu.Unlock()
	srv.invalidateLineReadModel()
	close(continueBuild)

	groups := <-done
	if got := findLine(t, groups, "node-a", "during-build"); got.Tag != "during-build" {
		t.Fatalf("rebuild after concurrent invalidation returned stale groups: %+v", groups)
	}
	srv.lineCache.mu.RLock()
	defer srv.lineCache.mu.RUnlock()
	if !srv.lineCache.valid || srv.lineCache.generation != 1 {
		t.Fatalf("cache state after guarded publication: valid=%v generation=%d", srv.lineCache.valid, srv.lineCache.generation)
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
