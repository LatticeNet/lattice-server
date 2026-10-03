package server

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// After a crash the fleet's heartbeats on disk are as old as the last state
// write, which may be minutes before the crash. The start sweep must not
// mark the fleet offline for that, and a node that really died just before
// the crash must still page once its delay has passed in the new process.
//
// The story: the last write was at t0, the fleet kept beating in memory, the
// late node died at t0+3m, the process crashed at t0+4m and the control
// plane was back at t0+4m45s. The sweeps run on the test's clock, so the
// other nodes do not beat here; they are tagged out of paging, and what is
// asserted for them is the start sweep, which runs before any agent can
// beat.
func TestCrashRestartFlipsNoFleetAndStillPagesTheNodeThatDied(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	first, err := store.OpenWithCipher(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	nodes := []model.Node{
		{ID: "n-a", Name: "a", Tags: []string{nodeQuietOfflineTag}},
		{ID: "n-b", Name: "b", Tags: []string{nodeQuietOfflineTag}},
		{ID: "n-c", Name: "c", Tags: []string{nodeQuietOfflineTag}},
		{ID: "n-late", Name: "late", Tags: []string{nodeOfflineAfterTagPrefix + "2m"}},
	}
	for _, n := range nodes {
		n.Online, n.LastSeen, n.OnlineSince = true, t0, t0.Add(-time.Hour)
		if err := first.UpsertNode(n); err != nil {
			t.Fatal(err)
		}
	}

	// The crash: the first store is never closed.
	st, err := store.OpenWithCipher(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	l := liveness{srv: srv, handler: srv.Handler(), st: st, sent: captureTypedNotices(srv)}
	boot := t0.Add(4*time.Minute + 45*time.Second)
	srv.nodeAlerts.start(boot)

	online := func(when string) {
		t.Helper()
		for _, n := range nodes {
			if got, _ := st.Node(n.ID); !got.Online {
				t.Fatalf("%s: %s was marked offline", when, n.ID)
			}
		}
	}
	srv.sweepNodeLiveness(boot, store.NodeStatusCauseServerStart)
	online("the start sweep")
	srv.sweepNodeLiveness(boot.Add(20*time.Second), sweepCause)
	online("the first tick")
	expectNoNotice(t, l, "the first tick")

	// Past 90 s plus the slack nothing has beaten, so every node is marked
	// offline; the late node's own two minute delay counts from boot.
	srv.sweepNodeLiveness(boot.Add(110*time.Second), sweepCause)
	if got, _ := st.Node("n-late"); got.Online {
		t.Fatal("the late node is still online past 90 s and the slack")
	}
	expectNoNotice(t, l, "before the late node's delay")
	srv.sweepNodeLiveness(boot.Add(2*time.Minute+time.Second), sweepCause)
	expectOneNotice(t, l, EventNodeOffline, "Lattice node offline: late")
	srv.sweepNodeLiveness(boot.Add(10*time.Minute), sweepCause)
	expectNoNotice(t, l, "the same spell, later")
}

// The console's status word and the pending incident list read the same
// LastSeen as the sweep. After a crash they judge it with the same slack, or
// a fleet that was beating shows offline, and pends a node.offline for every
// node, until each node beats again.
func TestCrashRestartShowsTheFleetOnlineUntilItCouldHaveBeaten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	first, err := store.OpenWithCipher(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	if err := first.UpsertNode(model.Node{ID: "n-a", Name: "a", Online: true, LastSeen: t0, OnlineSince: t0.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// The crash: the first store is never closed.
	st, err := store.OpenWithCipher(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	pendsOffline := func(at time.Time) bool {
		for _, inc := range srv.pendingIncidents(at) {
			if inc.Kind == EventNodeOffline && inc.NodeID == "n-a" {
				return true
			}
		}
		return false
	}
	n, _ := st.Node("n-a")

	boot := t0.Add(4*time.Minute + 45*time.Second)
	if got := srv.nodeStatusFor(n, boot); got.Status != NodeStatusOnline {
		t.Fatalf("status at start after a crash = %q (%s), want online", got.Status, got.Reason)
	}
	if pendsOffline(boot) {
		t.Fatal("a pending node.offline is listed at start after a crash")
	}
	past := t0.Add(nodeOfflineThreshold + store.NodeLastSeenDiskLag + time.Second)
	if got := srv.nodeStatusFor(n, past); got.Status != NodeStatusOffline {
		t.Fatalf("status past the threshold and the slack = %q, want offline", got.Status)
	}
	if !pendsOffline(past) {
		t.Fatal("no pending node.offline past the threshold and the slack, inside the delay")
	}
}
