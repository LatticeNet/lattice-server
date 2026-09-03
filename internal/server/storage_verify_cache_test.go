package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func storageCacheFixture(t *testing.T) (*Server, *store.Store, http.Handler) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashSecret("the-real-secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertStorageBucket(model.StorageBucket{
		ID: "kv_public", Kind: model.StorageKindKV, Name: "public",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertStorageBucket(model.StorageBucket{
		ID: "kv_other", Kind: model.StorageKindKV, Name: "other",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertStorageBinding(model.StorageBinding{
		ID: "bind_kv", Kind: model.StorageKindKV, Bucket: "public",
		Hostname: "kv.example.com", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertStorageBinding(model.StorageBinding{
		ID: "bind_other", Kind: model.StorageKindKV, Bucket: "other",
		Hostname: "other.example.com", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertStorageAccessToken(model.StorageAccessToken{
		ID: "stok_good", Name: "good", TokenHash: hash,
		Kind: model.StorageKindKV, Access: model.StorageAccessRead,
		Buckets: []string{"public"},
	}); err != nil {
		t.Fatal(err)
	}
	return srv, st, srv.Handler()
}

func kvRequest(h http.Handler, host, bearer, addr string) int {
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	req.Host = host
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.RemoteAddr = addr
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// The whole point: simultaneous callers holding a valid credential are all
// served, and between them they cost one derivation rather than one each.
//
// Before the cache, the permit alone capped this route. Measured at 4 permits,
// 16 simultaneous callers got 4 served and 12 refused with 429, because every
// request derived and the permit does not block.
func TestSimultaneousCallersCostOneDerivationAndAreAllServed(t *testing.T) {
	srv, _, h := storageCacheFixture(t)
	n := cap(srv.secretVerifySlots) * 4
	if n < 16 {
		n = 16
	}
	codes := make([]int, n)
	var start, done sync.WaitGroup
	start.Add(1)
	for i := range n {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait() // released together, so they genuinely overlap
			codes[i] = kvRequest(h, "kv.example.com", "stok_good.the-real-secret",
				fmt.Sprintf("198.51.100.%d:1", i+1))
		}(i)
	}
	start.Done()
	done.Wait()

	for i, c := range codes {
		if c == http.StatusTooManyRequests {
			refused := 0
			for _, x := range codes {
				if x == http.StatusTooManyRequests {
					refused++
				}
			}
			t.Fatalf("caller %d of %d holding a valid credential was refused with 429 (%d refused in total, "+
				"permit pool is %d); a public storage route cannot be capped at the pool size",
				i+1, n, refused, cap(srv.secretVerifySlots))
		}
	}
	if got := srv.storageVerify.derivations.Load(); got > 2 {
		t.Fatalf("%d derivations for %d simultaneous requests on one credential; single-flight should collapse them", got, n)
	}
	if srv.storageVerify.size() != 1 {
		t.Fatalf("cache holds %d entries after one credential; waiters must leave a cached entry too", srv.storageVerify.size())
	}
}

// A cache hit must mean "this exact secret was proven", not "this id was proven
// by someone". Keying on the id alone would turn one legitimate success into a
// bypass for every later guess against it.
func TestASuccessDoesNotAuthorizeADifferentSecretForTheSameID(t *testing.T) {
	srv, _, h := storageCacheFixture(t)
	if code := kvRequest(h, "kv.example.com", "stok_good.the-real-secret", "203.0.113.1:1"); code == http.StatusUnauthorized {
		t.Fatalf("the fixture's own credential did not verify: %d", code)
	}
	before := srv.storageVerify.derivations.Load()
	code := kvRequest(h, "kv.example.com", "stok_good.a-different-secret", "203.0.113.2:1")
	if code != http.StatusUnauthorized {
		t.Fatalf("a wrong secret for a cached id returned %d, want 401", code)
	}
	if srv.storageVerify.derivations.Load() <= before {
		t.Fatal("a wrong secret for a cached id skipped the derivation; the key is not binding the secret")
	}
}

// The cache sits in front of the derivation only. Bucket and access checks run
// on every request, so a hit for one bucket cannot authorize another.
func TestACachedCredentialIsStillDeniedOnABucketItCannotReach(t *testing.T) {
	_, _, h := storageCacheFixture(t)
	if code := kvRequest(h, "kv.example.com", "stok_good.the-real-secret", "203.0.113.3:1"); code == http.StatusForbidden {
		t.Fatalf("the token should reach its own bucket, got %d", code)
	}
	code := kvRequest(h, "other.example.com", "stok_good.the-real-secret", "203.0.113.4:1")
	if code != http.StatusForbidden {
		t.Fatalf("a cached credential reached a bucket outside its list: got %d, want 403", code)
	}
}

// A revoked token stops working immediately, cached or not.
//
// This holds without the purge, because the token is read fresh on every
// request and RevokedAt is checked there rather than behind the cache. That is
// the property that matters and it is what this asserts.
func TestRevokeStopsACachedCredentialImmediately(t *testing.T) {
	srv, st, h := storageCacheFixture(t)
	if code := kvRequest(h, "kv.example.com", "stok_good.the-real-secret", "203.0.113.5:1"); code == http.StatusUnauthorized {
		t.Fatalf("the fixture's own credential did not verify: %d", code)
	}
	if srv.storageVerify.size() == 0 {
		t.Fatal("nothing was cached, so this test would pass for the wrong reason")
	}
	if _, ok, err := st.RevokeStorageAccessToken("stok_good"); err != nil || !ok {
		t.Fatalf("revoke: ok=%v err=%v", ok, err)
	}
	if code := kvRequest(h, "kv.example.com", "stok_good.the-real-secret", "203.0.113.6:1"); code != http.StatusUnauthorized {
		t.Fatalf("a revoked token still worked: got %d, want 401", code)
	}
}

// purgeToken forgets every credential for one token and leaves the rest alone.
//
// handleRevokeStorageToken calls this so a revoke does not leave a stale entry
// sitting for the rest of the TTL. The test covers the function rather than
// that call, and says so: the previous test already proves a revoked token is
// refused by the fresh read, so a test that went through the handler would pass
// whether or not the purge were wired, and would be worth less than it looks.
func TestPurgeTokenForgetsOnlyThatToken(t *testing.T) {
	now := time.Now()
	c := newStorageVerifyCache(func() time.Time { return now })
	c.remember("key-a1", "tok-a")
	c.remember("key-a2", "tok-a")
	c.remember("key-b1", "tok-b")
	c.purgeToken("tok-a")
	if c.verified("key-a1") || c.verified("key-a2") {
		t.Fatal("purge left a credential for the revoked token")
	}
	if !c.verified("key-b1") {
		t.Fatal("purge removed a credential belonging to a different token")
	}
	if c.size() != 1 {
		t.Fatalf("size %d after purging one of two tokens, want 1", c.size())
	}
}

// A TTL decides when an entry stops counting. It does not remove anything, so
// a credential used once and abandoned would sit in the map for the life of the
// process unless something evicts it. Both eviction paths are exercised here.
func TestExpiredEntriesAreActuallyEvictedNotJustIgnored(t *testing.T) {
	now := time.Now()
	c := newStorageVerifyCache(func() time.Time { return now })
	for i := range 50 {
		c.remember(fmt.Sprintf("key-%d", i), fmt.Sprintf("tok-%d", i))
	}
	if c.size() != 50 {
		t.Fatalf("size %d after 50 inserts", c.size())
	}
	now = now.Add(2 * storageVerifyTTL)

	// Path one: a lookup that finds a stale entry removes it.
	if c.verified("key-0") {
		t.Fatal("a stale entry was reported as verified")
	}
	if c.size() != 49 {
		t.Fatalf("a stale lookup left the entry behind: size %d, want 49", c.size())
	}

	// Path two: the sweep, for entries nothing looks up again.
	c.sweep()
	if c.size() != 0 {
		t.Fatalf("sweep left %d expired entries", c.size())
	}
}

// The cache never remembers a failure, so guessing cannot be made cheap by
// guessing more.
func TestWrongSecretsAreNeverCached(t *testing.T) {
	srv, _, h := storageCacheFixture(t)
	for i := range 3 {
		kvRequest(h, "kv.example.com", fmt.Sprintf("stok_good.wrong-%d", i), fmt.Sprintf("203.0.113.%d:1", 20+i))
	}
	if srv.storageVerify.size() != 0 {
		t.Fatalf("%d failures were cached", srv.storageVerify.size())
	}
	before := srv.storageVerify.derivations.Load()
	kvRequest(h, "kv.example.com", "stok_good.wrong-0", "203.0.113.30:1")
	if srv.storageVerify.derivations.Load() <= before {
		t.Fatal("a repeated wrong secret skipped the derivation")
	}
}
