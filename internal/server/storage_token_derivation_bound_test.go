package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// A caller who knows a token id, and nothing else, cannot spend unbounded key
// derivation on the storage route.
//
// The id is not a secret. It is the left half of the credential the operator
// hands out, it appears in the console and in the token list, and it is what
// the caller sends. Only the right half is secret.
//
// authorizeStorageToken charged its rate limiter on the two branches that call
// DummyVerify, and left the branch that does the real verification with
// nothing. Presenting a known id with a wrong secret therefore reached a full
// PBKDF2 at 210,000 iterations with no budget consulted at all, as fast as the
// caller could repeat it. This test presents exactly that and requires the
// server to refuse.
func TestKnownStorageTokenIDWithWrongSecretIsBounded(t *testing.T) {
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
		Kind: model.StorageKindKV, Access: "read", Buckets: []string{"public"},
	}); err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()

	const attempts = 12
	throttled := 0
	for i := range attempts {
		req := httptest.NewRequest(http.MethodGet, "/anything", nil)
		req.Host = "kv.example.com"
		// A known id, a wrong secret, one fixed source address.
		req.Header.Set("Authorization", fmt.Sprintf("Bearer stok_known.wrong-secret-%d", i))
		req.RemoteAddr = "203.0.113.9:40000"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			throttled++
		}
	}
	if throttled == 0 {
		t.Fatalf("all %d wrong-secret attempts against a known token id were verified from one address with no budget consulted; "+
			"an anonymous caller can force key derivation without bound", attempts)
	}
}

// The derivation permit is one machine-wide budget, not one per route.
//
// Two semaphores sized at half the cores each add up to every core, which is
// the bound they exist to prevent. Holding every permit must refuse the storage
// route as well as the webhook route.
func TestStorageAndWebhookShareOneDerivationBudget(t *testing.T) {
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
	if cap(srv.secretVerifySlots) < 2 {
		t.Fatalf("the semaphore must leave room for real traffic, got %d", cap(srv.secretVerifySlots))
	}
	// Hold every permit, as a flood of concurrent verification would.
	for range cap(srv.secretVerifySlots) {
		srv.secretVerifySlots <- struct{}{}
	}
	defer func() {
		for range cap(srv.secretVerifySlots) {
			<-srv.secretVerifySlots
		}
	}()

	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	req.Host = "kv.example.com"
	req.Header.Set("Authorization", "Bearer stok_known.whatever")
	req.RemoteAddr = "203.0.113.11:40000"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("storage verification ran while every derivation permit was held: got %d, want 429", rec.Code)
	}
}

// A permit is released even when verification fails, so a run of bad
// credentials cannot exhaust the budget permanently.
func TestDerivationPermitsAreReleasedAfterAFailedStorageAttempt(t *testing.T) {
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
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/anything", nil)
			req.Host = "kv.example.com"
			req.Header.Set("Authorization", fmt.Sprintf("Bearer garbage-%d", i))
			req.RemoteAddr = fmt.Sprintf("198.51.100.%d:40000", i+1)
			handler.ServeHTTP(httptest.NewRecorder(), req)
		}(i)
	}
	wg.Wait()
	if len(srv.secretVerifySlots) != 0 {
		t.Fatalf("%d permits were never released", len(srv.secretVerifySlots))
	}
}
