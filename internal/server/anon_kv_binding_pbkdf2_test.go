package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// A KV publishing binding is reachable through the catch-all route, and the
// catch-all is the one credential-checking path in this server that carries no
// rate limiter.
//
// Every other place that verifies a secret is throttled first: /api/login has
// loginLimiter, /api/agent/* has withAgentLimit, /sub/ has withSubscriptionLimit,
// and every /api/ handler behind withAuth consumes apiLimiter. staticHandler is
// registered bare at server.go, wrapped only by request id, request logging and
// security headers, none of which throttle.
//
// That matters because serveKVBinding calls authorizeStorageToken before it does
// anything else, and authorizeStorageToken answers a missing or malformed
// Authorization header by running auth.DummyVerify, which performs a full
// PBKDF2-SHA256 at 210,000 iterations so that the failure takes as long as a
// success. Constant time is the right call; leaving it unthrottled is not. An
// anonymous caller who knows the host and path of any enabled KV binding can
// spend one cheap request to buy a fixed, expensive slice of server CPU, and
// nothing bounds how fast they may repeat it.
//
// The invariant asserted here is not "be fast". It is that an unauthenticated
// caller cannot force unbounded key-derivation work on this route.
func TestUnauthenticatedKVBindingCannotForceUnboundedKeyDerivation(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertStorageBucket(model.StorageBucket{
		ID: "kv_public", Kind: model.StorageKindKV, Name: "public",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertStorageBinding(model.StorageBinding{
		ID: "bind_kv", Kind: model.StorageKindKV, Bucket: "public",
		Hostname: "kv.example.com", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()

	const attempts = 12
	throttled := 0
	start := time.Now()
	for range attempts {
		req := httptest.NewRequest(http.MethodGet, "/anything", nil)
		req.Host = "kv.example.com"
		// One fixed source, so any per-IP limiter would engage.
		req.RemoteAddr = "203.0.113.7:40000"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			throttled++
		}
	}
	elapsed := time.Since(start)

	if throttled == 0 {
		t.Fatalf("all %d unauthenticated requests to a KV binding were served from one address with no throttling, "+
			"costing %v of key derivation (%v per request); an anonymous caller can repeat this without bound",
			attempts, elapsed.Round(time.Millisecond), (elapsed / attempts).Round(time.Millisecond))
	}
}
