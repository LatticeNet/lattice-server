package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// fakeSubStore records the requests the companion makes and emulates the upsert
// contract: PATCH /api/sub/:name returns 404 (not found) so the companion falls
// back to POST /api/subs (create).
func TestImportToSubStoreUpserts(t *testing.T) {
	var (
		mu       sync.Mutex
		patchHit bool
		postBody []byte
		envHit   bool
	)
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/api/sub/"):
			patchHit = true
			w.WriteHeader(http.StatusNotFound) // force create fallback
		case r.Method == http.MethodPost && r.URL.Path == "/api/subs":
			postBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/api/utils/env":
			envHit = true
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer fake.Close()

	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	pushed, err := srv.importToSubStore(context.Background(), fake.URL, "", "")
	if err != nil {
		t.Fatalf("importToSubStore: %v", err)
	}
	if pushed != 0 { // empty store -> no links, but the managed sub is still upserted
		t.Fatalf("expected 0 links from empty store, got %d", pushed)
	}

	// Snapshot under lock, then release BEFORE making further HTTP calls (the
	// fake handler also takes this lock, so holding it across a request deadlocks).
	mu.Lock()
	gotPatch := patchHit
	body := append([]byte(nil), postBody...)
	mu.Unlock()
	if !gotPatch {
		t.Fatalf("expected a PATCH update attempt first")
	}
	if len(body) == 0 {
		t.Fatalf("expected a POST create fallback")
	}
	var sub struct {
		Name    string `json:"name"`
		Source  string `json:"source"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(body, &sub); err != nil {
		t.Fatalf("decode POST body: %v", err)
	}
	if sub.Name != defaultSubStoreSubName || sub.Source != "local" {
		t.Fatalf("unexpected managed sub: %+v", sub)
	}

	// status probe hits /api/utils/env and reports reachable
	code, err := subStoreDo(context.Background(), http.MethodGet, fake.URL+"/api/utils/env", nil)
	mu.Lock()
	gotEnv := envHit
	mu.Unlock()
	if err != nil || code != http.StatusOK || !gotEnv {
		t.Fatalf("status probe: code=%d err=%v envHit=%v", code, err, gotEnv)
	}
}

func TestImportToSubStoreRequiresBaseURL(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := srv.importToSubStore(context.Background(), "  ", "", ""); err == nil {
		t.Fatalf("expected error for empty base url")
	}
}
