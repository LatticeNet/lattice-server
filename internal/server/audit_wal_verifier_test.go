package server

import (
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// Readiness used to walk the whole tamper-evident chain on every probe, holding
// the store lock for the length of the walk. It now reports what the last walk
// found. That is only an improvement if a probe can still tell the difference
// between a fresh pass, a failed one, and a verifier that has stopped running.

func readinessServer(t *testing.T, at time.Time) *Server {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	srv.now = func() time.Time { return at }
	return srv
}

func TestReadinessReportsAFreshChainWalk(t *testing.T) {
	srv := readinessServer(t, time.Now())
	// The record is stamped by the store from the wall clock, so the test
	// measures from it rather than inventing an epoch of its own.
	last, ok := srv.store.LastAuditWALVerification()
	if !ok || !last.Enabled {
		t.Fatalf("opening a file-backed store must record a verification: %+v ok=%v", last, ok)
	}

	// Opening the store verifies the chain, so a probe arriving before the
	// first background walk still has a real answer.
	line, ready := srv.auditWALReadiness(last.At.Add(time.Minute))
	if !ready {
		t.Fatalf("a chain verified one minute ago must be ready, got %q", line)
	}
	if !strings.HasPrefix(line, "ok (verified") {
		t.Fatalf("readiness line %q does not say when the chain was last verified", line)
	}
}

func TestReadinessRefusesAStaleChainWalk(t *testing.T) {
	srv := readinessServer(t, time.Now())
	last, _ := srv.store.LastAuditWALVerification()

	line, ready := srv.auditWALReadiness(last.At.Add(auditWALVerifyStaleAfter + time.Minute))
	if ready {
		t.Fatal("a verifier that has stopped must not keep reporting ready")
	}
	if !strings.Contains(line, "stale") {
		t.Fatalf("readiness line %q does not name staleness as the reason", line)
	}
}

func TestReadinessSaysDisabledWhenThereIsNoWAL(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	line, ready := srv.auditWALReadiness(time.Unix(1_700_000_000, 0).UTC())
	if !ready || line != "disabled" {
		t.Fatalf("a store with no WAL has nothing to verify: line=%q ready=%v", line, ready)
	}
}

// The walk itself must still find a broken chain, and the probe must surface it.
func TestReadinessSurfacesABrokenChain(t *testing.T) {
	at := time.Now()
	dir := t.TempDir()
	st, err := store.Open(dir + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	srv.now = func() time.Time { return at }

	if err := corruptAuditWALTail(dir + "/state.json.audit-wal"); err != nil {
		t.Fatal(err)
	}
	// A walk on the timer is what notices; run one directly.
	newAuditWALVerifier(st, nil, time.Minute).verifyOnce()

	line, ready := srv.auditWALReadiness(at.Add(time.Minute))
	if ready {
		t.Fatalf("a chain that no longer verifies must fail readiness, got %q", line)
	}
	if line == "" {
		t.Fatal("readiness must say what the walk found")
	}
}
