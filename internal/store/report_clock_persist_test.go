package store

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func openReportClockStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenWithCipher(path, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	return s, path
}

func reopenReportClockStore(t *testing.T, s *Store, path string) *Store {
	t.Helper()
	cipher := s.cipher
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWithCipher(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	return reopened
}

func runningLiveness(nodeID string, at time.Time) SingBoxLiveness {
	return SingBoxLiveness{
		NodeID: nodeID,
		Runtime: model.SingBoxRuntime{
			Running:      true,
			PID:          4242,
			StartedAt:    at.Add(-time.Hour),
			ActiveState:  "active",
			SubState:     "running",
			RestartCount: 3,
			ProbedAt:     at,
		},
		State:      "running",
		StateSince: at,
		ReceivedAt: at,
	}
}

// Many reports that only move the clocks cost one write: the first.
func TestSingBoxLivenessClockOnlyReportsDoNotPersist(t *testing.T) {
	s, _ := openReportClockStore(t)
	defer s.Close()
	base := time.Date(2026, 10, 1, 17, 0, 0, 0, time.UTC)
	first := runningLiveness("node-a", base)

	before := s.testPersistCalls
	if _, _, err := s.UpsertSingBoxLiveness(first); err != nil {
		t.Fatal(err)
	}
	// Ten minutes of ten-second reports, inside the flush interval.
	var last SingBoxLiveness
	for i := 1; i <= 60; i++ {
		at := base.Add(time.Duration(i) * 10 * time.Second)
		last = first
		last.Runtime.ProbedAt = at
		last.ReceivedAt = at
		prev, hadPrev, err := s.UpsertSingBoxLiveness(last)
		if err != nil {
			t.Fatal(err)
		}
		if !hadPrev || !prev.ReceivedAt.Equal(at.Add(-10*time.Second)) {
			t.Fatalf("report %d: previous record not returned: had=%v %+v", i, hadPrev, prev)
		}
	}
	if calls := s.testPersistCalls - before; calls != 1 {
		t.Fatalf("61 reports with one durable state persisted %d times, want 1", calls)
	}
	got, ok := s.SingBoxLivenessRecord("node-a")
	if !ok || !got.ReceivedAt.Equal(last.ReceivedAt) || !got.Runtime.ProbedAt.Equal(last.Runtime.ProbedAt) {
		t.Fatalf("memory does not hold the newest report: %+v", got)
	}
}

// Every field other than the two clocks is state, and a change to any of
// them is written before the call returns.
func TestSingBoxLivenessDurableChangesPersistImmediately(t *testing.T) {
	base := time.Date(2026, 10, 1, 17, 0, 0, 0, time.UTC)
	cases := map[string]func(*SingBoxLiveness){
		"running to down": func(r *SingBoxLiveness) {
			r.Runtime.Running, r.Runtime.ActiveState, r.Runtime.SubState = false, "failed", "failed"
			r.State, r.StateSince, r.ProblemSince = "down", r.ReceivedAt, r.ReceivedAt
		},
		"notified":       func(r *SingBoxLiveness) { r.NotifiedDownAt = r.ReceivedAt },
		"restart count":  func(r *SingBoxLiveness) { r.Runtime.RestartCount++ },
		"probe error":    func(r *SingBoxLiveness) { r.Runtime.ProbeError = "ss: permission denied" },
		"sub state":      func(r *SingBoxLiveness) { r.Runtime.SubState = "auto-restart" },
		"new process":    func(r *SingBoxLiveness) { r.Runtime.PID, r.Runtime.StartedAt = 5151, r.ReceivedAt },
		"binary digest":  func(r *SingBoxLiveness) { r.Runtime.ExeSHA256 = strings.Repeat("c", 64) },
		"state since":    func(r *SingBoxLiveness) { r.StateSince = r.ReceivedAt },
		"problem closed": func(r *SingBoxLiveness) { r.ProblemSince = time.Time{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s, path := openReportClockStore(t)
			seed := runningLiveness("node-a", base)
			seed.ProblemSince = base.Add(-time.Minute)
			if _, _, err := s.UpsertSingBoxLiveness(seed); err != nil {
				t.Fatal(err)
			}
			next := seed
			next.ReceivedAt = base.Add(10 * time.Second)
			next.Runtime.ProbedAt = next.ReceivedAt
			mutate(&next)
			before := s.testPersistCalls
			if _, _, err := s.UpsertSingBoxLiveness(next); err != nil {
				t.Fatal(err)
			}
			if calls := s.testPersistCalls - before; calls != 1 {
				t.Fatalf("durable change persisted %d times, want 1", calls)
			}
			reopened := reopenReportClockStore(t, s, path)
			got, _ := reopened.SingBoxLivenessRecord("node-a")
			if !singBoxLivenessDurablyEqual(got, next) || !got.ReceivedAt.Equal(next.ReceivedAt) {
				t.Fatalf("disk does not hold the changed record:\n got %+v\nwant %+v", got, next)
			}
		})
	}
}

// A down to running recovery is a transition like any other, and the
// incident bookkeeping it clears is cleared on disk too.
func TestSingBoxLivenessRecoveryPersistsImmediately(t *testing.T) {
	s, path := openReportClockStore(t)
	base := time.Date(2026, 10, 1, 17, 0, 0, 0, time.UTC)
	down := runningLiveness("node-a", base)
	down.Runtime.Running, down.Runtime.ActiveState, down.Runtime.SubState = false, "failed", "failed"
	down.State, down.ProblemSince, down.NotifiedDownAt = "down", base, base.Add(2*time.Minute)
	if _, _, err := s.UpsertSingBoxLiveness(down); err != nil {
		t.Fatal(err)
	}
	up := runningLiveness("node-a", base.Add(5*time.Minute))
	before := s.testPersistCalls
	if _, _, err := s.UpsertSingBoxLiveness(up); err != nil {
		t.Fatal(err)
	}
	if calls := s.testPersistCalls - before; calls != 1 {
		t.Fatalf("recovery persisted %d times, want 1", calls)
	}
	got, _ := reopenReportClockStore(t, s, path).SingBoxLivenessRecord("node-a")
	if got.State != "running" || !got.ProblemSince.IsZero() || !got.NotifiedDownAt.IsZero() {
		t.Fatalf("recovery not on disk: %+v", got)
	}
}

// The clocks on disk never lag by more than the flush interval, and a write
// made for any other reason flushes them and restarts the interval.
func TestSingBoxLivenessClockFlushesOnInterval(t *testing.T) {
	s, path := openReportClockStore(t)
	base := time.Date(2026, 10, 1, 17, 0, 0, 0, time.UTC)
	rec := runningLiveness("node-a", base)
	if _, _, err := s.UpsertSingBoxLiveness(rec); err != nil {
		t.Fatal(err)
	}
	report := func(at time.Time) {
		t.Helper()
		next := rec
		next.ReceivedAt, next.Runtime.ProbedAt = at, at
		if _, _, err := s.UpsertSingBoxLiveness(next); err != nil {
			t.Fatal(err)
		}
	}

	before := s.testPersistCalls
	report(base.Add(reportClockPersistInterval - time.Second))
	if calls := s.testPersistCalls - before; calls != 0 {
		t.Fatalf("clock-only report inside the interval persisted %d times", calls)
	}
	report(base.Add(reportClockPersistInterval))
	if calls := s.testPersistCalls - before; calls != 1 {
		t.Fatalf("report at the interval persisted %d times, want 1", calls)
	}

	// An unrelated write carries the newest clock with it.
	flushedAt := base.Add(reportClockPersistInterval + 5*time.Minute)
	report(flushedAt)
	if err := s.UpsertNode(model.Node{ID: "node-b", Name: "node-b"}); err != nil {
		t.Fatal(err)
	}
	before = s.testPersistCalls
	report(flushedAt.Add(reportClockPersistInterval - time.Second))
	if calls := s.testPersistCalls - before; calls != 0 {
		t.Fatalf("the unrelated write did not restart the interval: %d writes", calls)
	}

	got, _ := reopenReportClockStore(t, s, path).SingBoxLivenessRecord("node-a")
	if !got.ReceivedAt.Equal(flushedAt) || !got.Runtime.ProbedAt.Equal(flushedAt) {
		t.Fatalf("disk holds received_at %s probed_at %s, want %s", got.ReceivedAt, got.Runtime.ProbedAt, flushedAt)
	}
}

// A store reopened from disk resumes clock-only throttling from what it read:
// the first steady report after a restart does not need a write.
func TestSingBoxLivenessReopenSeedsWhatIsOnDisk(t *testing.T) {
	s, path := openReportClockStore(t)
	base := time.Date(2026, 10, 1, 17, 0, 0, 0, time.UTC)
	rec := runningLiveness("node-a", base)
	if _, _, err := s.UpsertSingBoxLiveness(rec); err != nil {
		t.Fatal(err)
	}
	reopened := reopenReportClockStore(t, s, path)
	before := reopened.testPersistCalls
	next := rec
	next.ReceivedAt = base.Add(10 * time.Second)
	next.Runtime.ProbedAt = next.ReceivedAt
	if _, _, err := reopened.UpsertSingBoxLiveness(next); err != nil {
		t.Fatal(err)
	}
	if calls := reopened.testPersistCalls - before; calls != 0 {
		t.Fatalf("first steady report after reopen persisted %d times", calls)
	}
}

func guardRealityFixture(nodeID string, at time.Time) GuardRealitySnapshot {
	return GuardRealitySnapshot{
		Reality: model.GuardNodeReality{
			NodeID:     nodeID,
			ManagedSHA: strings.Repeat("a", 64),
			Listeners:  []model.GuardListener{{Protocol: "tcp", Port: 22, Process: "sshd"}},
			Interfaces: []model.GuardInterface{{Name: "eth0", Addresses: []string{"10.0.0.5/24"}, Up: true}},
			NFTVersion: "nftables v1.0.9",
			SSHD: &model.GuardSSHDFacts{
				PubkeyAuthentication: true,
				PermitRootLogin:      "prohibit-password",
				Ports:                []int{22},
				ObservedAt:           at,
			},
			CollectedAt: at,
		},
		ReceivedAt: at.Add(time.Second),
	}
}

func steadyGuardReality(snapshot GuardRealitySnapshot, at time.Time) GuardRealitySnapshot {
	next := snapshot
	next.Reality.CollectedAt = at
	sshd := *snapshot.Reality.SSHD
	sshd.ObservedAt = at
	next.Reality.SSHD = &sshd
	next.ReceivedAt = at.Add(time.Second)
	return next
}

func TestGuardRealityClockOnlyReportsDoNotPersist(t *testing.T) {
	s, path := openReportClockStore(t)
	if err := s.UpsertNode(model.Node{ID: "node-a", LatticeIdentityUUID: "generation-a"}); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 1, 17, 0, 0, 0, time.UTC)
	first := guardRealityFixture("node-a", base)
	before := s.testPersistCalls
	if _, _, err := s.UpsertGuardRealitySnapshot("generation-a", first); err != nil {
		t.Fatal(err)
	}
	var last GuardRealitySnapshot
	for i := 1; i <= 60; i++ {
		last = steadyGuardReality(first, base.Add(time.Duration(i)*10*time.Second))
		stored, changed, err := s.UpsertGuardRealitySnapshot("generation-a", last)
		if err != nil {
			t.Fatal(err)
		}
		if !changed || !stored.Reality.CollectedAt.Equal(last.Reality.CollectedAt) {
			t.Fatalf("report %d not taken: changed=%v %+v", i, changed, stored.Reality)
		}
	}
	if calls := s.testPersistCalls - before; calls != 1 {
		t.Fatalf("61 reports of unchanged facts persisted %d times, want 1", calls)
	}
	got, _ := s.GuardRealitySnapshot("node-a")
	if !got.Reality.CollectedAt.Equal(last.Reality.CollectedAt) || !got.ReceivedAt.Equal(last.ReceivedAt) {
		t.Fatalf("memory does not hold the newest report: %+v", got)
	}

	// Ordering still holds against the newer copy in memory, not the older
	// one on disk: a replay of an earlier report is stale.
	if _, _, err := s.UpsertGuardRealitySnapshot("generation-a", steadyGuardReality(first, base.Add(5*time.Minute))); err != ErrGuardRealityStale {
		t.Fatalf("older report against newer memory: err=%v, want ErrGuardRealityStale", err)
	}

	// A changed fact is written at once.
	changedFacts := steadyGuardReality(first, base.Add(11*time.Minute))
	changedFacts.Reality.ManagedSHA = strings.Repeat("b", 64)
	before = s.testPersistCalls
	if _, _, err := s.UpsertGuardRealitySnapshot("generation-a", changedFacts); err != nil {
		t.Fatal(err)
	}
	if calls := s.testPersistCalls - before; calls != 1 {
		t.Fatalf("changed managed sha persisted %d times, want 1", calls)
	}
	got, _ = reopenReportClockStore(t, s, path).GuardRealitySnapshot("node-a")
	if got.Reality.ManagedSHA != changedFacts.Reality.ManagedSHA || !got.Reality.CollectedAt.Equal(changedFacts.Reality.CollectedAt) {
		t.Fatalf("changed facts not on disk: %+v", got.Reality)
	}
}

func TestGuardRealityClockFlushesOnInterval(t *testing.T) {
	s, path := openReportClockStore(t)
	if err := s.UpsertNode(model.Node{ID: "node-a", LatticeIdentityUUID: "generation-a"}); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 1, 17, 0, 0, 0, time.UTC)
	first := guardRealityFixture("node-a", base)
	if _, _, err := s.UpsertGuardRealitySnapshot("generation-a", first); err != nil {
		t.Fatal(err)
	}
	before := s.testPersistCalls
	inside := steadyGuardReality(first, base.Add(reportClockPersistInterval-2*time.Second))
	if _, _, err := s.UpsertGuardRealitySnapshot("generation-a", inside); err != nil {
		t.Fatal(err)
	}
	if calls := s.testPersistCalls - before; calls != 0 {
		t.Fatalf("clock-only report inside the interval persisted %d times", calls)
	}
	due := steadyGuardReality(first, base.Add(reportClockPersistInterval))
	if _, _, err := s.UpsertGuardRealitySnapshot("generation-a", due); err != nil {
		t.Fatal(err)
	}
	if calls := s.testPersistCalls - before; calls != 1 {
		t.Fatalf("report at the interval persisted %d times, want 1", calls)
	}
	got, _ := reopenReportClockStore(t, s, path).GuardRealitySnapshot("node-a")
	if !got.ReceivedAt.Equal(due.ReceivedAt) || !got.Reality.CollectedAt.Equal(due.Reality.CollectedAt) {
		t.Fatalf("disk holds %s / %s, want %s / %s", got.ReceivedAt, got.Reality.CollectedAt, due.ReceivedAt, due.Reality.CollectedAt)
	}
}

// Clock-only updates mutate the live maps in place and every committed write
// rebuilds the on-disk markers; both must stay under the store lock while
// reports, unrelated writes and readers interleave.
func TestReportClockUpdatesInterleaveWithWritesAndReads(t *testing.T) {
	s, _ := openReportClockStore(t)
	defer s.Close()
	base := time.Date(2026, 10, 1, 17, 0, 0, 0, time.UTC)
	nodes := []string{"node-a", "node-b", "node-c", "node-d"}
	for _, nodeID := range nodes {
		if err := s.UpsertNode(model.Node{ID: nodeID, LatticeIdentityUUID: "generation-" + nodeID}); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for _, nodeID := range nodes {
		wg.Add(1)
		go func(nodeID string) {
			defer wg.Done()
			liveness := runningLiveness(nodeID, base)
			reality := guardRealityFixture(nodeID, base)
			for i := 0; i < 100; i++ {
				at := base.Add(time.Duration(i) * 10 * time.Second)
				next := liveness
				next.ReceivedAt, next.Runtime.ProbedAt = at, at
				if i%25 == 24 {
					next.Runtime.RestartCount += i
				}
				if _, _, err := s.UpsertSingBoxLiveness(next); err != nil {
					t.Error(err)
					return
				}
				if _, _, err := s.UpsertGuardRealitySnapshot("generation-"+nodeID, steadyGuardReality(reality, at)); err != nil {
					t.Error(err)
					return
				}
			}
		}(nodeID)
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			if err := s.UpsertNode(model.Node{ID: fmt.Sprintf("other-%d", i)}); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = s.SingBoxLivenessAll()
			_ = s.GuardRealitySnapshots()
		}
	}()
	wg.Wait()
	for _, nodeID := range nodes {
		rec, ok := s.SingBoxLivenessRecord(nodeID)
		if !ok || !rec.ReceivedAt.Equal(base.Add(99*10*time.Second)) {
			t.Fatalf("%s: newest liveness report lost: %+v", nodeID, rec)
		}
	}
}
