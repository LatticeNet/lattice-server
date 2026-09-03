package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// A caller who knows a token id, and nothing else, does not get unmetered
// guesses on the storage route.
//
// The id is not a secret. It is the left half of the credential the operator
// hands out, it appears in the console and in the token list, and the caller
// sends it in the clear. Only the right half is secret.
//
// authorizeStorageToken charged its rate limiter on the two branches that call
// DummyVerify and left the branch doing the real verification with nothing, so
// a wrong secret against a known id reached a full PBKDF2 at 210,000 iterations
// with no budget consulted, as fast as the caller could repeat it. The route is
// reachable anonymously through the storage catch-all, which
// TestUnauthenticatedKVBindingCannotForceUnboundedKeyDerivation documents as
// the one credential-checking path here with no session in front of it.
func TestKnownStorageTokenIDWithWrongSecretIsMetered(t *testing.T) {
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
	if err := st.UpsertStorageBinding(model.StorageBinding{
		ID: "bind_kv", Kind: model.StorageKindKV, Bucket: "public",
		Hostname: "kv.example.com", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertStorageAccessToken(model.StorageAccessToken{
		ID: "stok_known", Name: "known", TokenHash: hash,
		Kind: model.StorageKindKV, Access: "read", Buckets: []string{"*"},
	}); err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()

	const attempts = 12
	throttled := 0
	for i := range attempts {
		req := httptest.NewRequest(http.MethodGet, "/anything", nil)
		req.Host = "kv.example.com"
		req.Header.Set("Authorization", fmt.Sprintf("Bearer stok_known.wrong-secret-%d", i))
		req.RemoteAddr = "203.0.113.9:40000"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			throttled++
		}
	}
	if throttled == 0 {
		t.Fatalf("all %d wrong-secret attempts against a known token id were verified from one address "+
			"with no budget consulted", attempts)
	}
}

// A caller holding a working token is never metered, which is why the budget is
// charged on failure rather than on arrival. At five attempts a minute a
// charge-on-arrival rule would throttle a storage bucket within seconds.
func TestWorkingStorageTokenIsNotMetered(t *testing.T) {
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
	if err := st.UpsertStorageBinding(model.StorageBinding{
		ID: "bind_kv", Kind: model.StorageKindKV, Bucket: "public",
		Hostname: "kv.example.com", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertStorageAccessToken(model.StorageAccessToken{
		ID: "stok_good", Name: "good", TokenHash: hash,
		Kind: model.StorageKindKV, Access: "read", Buckets: []string{"*"},
	}); err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()

	for i := range 20 {
		req := httptest.NewRequest(http.MethodGet, "/anything", nil)
		req.Host = "kv.example.com"
		req.Header.Set("Authorization", "Bearer stok_good.the-real-secret")
		req.RemoteAddr = "203.0.113.10:40000"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d of 20 with a working token was throttled; the budget must only "+
				"charge failures or it caps legitimate traffic", i+1)
		}
	}
}
