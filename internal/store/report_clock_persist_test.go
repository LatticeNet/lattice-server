package store

import (
	"fmt"
	"os"
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
	report := func(s *Store, at time.Time) {
		t.Helper()
		next := rec
		next.ReceivedAt, next.Runtime.ProbedAt = at, at
		if _, _, err := s.UpsertSingBoxLiveness(next); err != nil {
			t.Fatal(err)
		}
	}

	before := s.testPersistCalls
	report(s, base.Add(reportClockPersistInterval-time.Second))
	if calls := s.testPersistCalls - before; calls != 0 {
		t.Fatalf("clock-only report inside the interval persisted %d times", calls)
	}
	due := base.Add(reportClockPersistInterval)
	report(s, due)
	if calls := s.testPersistCalls - before; calls != 1 {
		t.Fatalf("report at the interval persisted %d times, want 1", calls)
	}
	// Nothing is left unflushed, so the reopened store reads exactly what
	// the interval write put on disk.
	s = reopenReportClockStore(t, s, path)
	got, _ := s.SingBoxLivenessRecord("node-a")
	if !got.ReceivedAt.Equal(due) || !got.Runtime.ProbedAt.Equal(due) {
		t.Fatalf("disk holds received_at %s probed_at %s, want %s", got.ReceivedAt, got.Runtime.ProbedAt, due)
	}

	// An unrelated write carries the newest clock with it.
	flushedAt := due.Add(5 * time.Minute)
	report(s, flushedAt)
	if err := s.UpsertNode(model.Node{ID: "node-b", Name: "node-b"}); err != nil {
		t.Fatal(err)
	}
	if written := s.livenessOnDisk["node-a"]; !written.Equal(flushedAt) {
		t.Fatalf("the unrelated write put received_at %s on disk, want %s", written, flushedAt)
	}
	before = s.testPersistCalls
	report(s, flushedAt.Add(reportClockPersistInterval-time.Second))
	if calls := s.testPersistCalls - before; calls != 0 {
		t.Fatalf("the unrelated write did not restart the interval: %d writes", calls)
	}
}

// A clean shutdown writes what is still only in memory, and writes nothing
// when memory and disk already agree.
func TestCloseFlushesClockOnlyReports(t *testing.T) {
	s, path := openReportClockStore(t)
	if err := s.UpsertNode(model.Node{ID: "node-a", LatticeIdentityUUID: "generation-a"}); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 1, 17, 0, 0, 0, time.UTC)
	rec := runningLiveness("node-a", base)
	reality := guardRealityFixture("node-a", base)
	if _, _, err := s.UpsertSingBoxLiveness(rec); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UpsertGuardRealitySnapshot("generation-a", reality); err != nil {
		t.Fatal(err)
	}
	latest := base.Add(5 * time.Minute)
	next := rec
	next.ReceivedAt, next.Runtime.ProbedAt = latest, latest
	if _, _, err := s.UpsertSingBoxLiveness(next); err != nil {
		t.Fatal(err)
	}
	latestReality := steadyGuardReality(reality, latest)
	if _, _, err := s.UpsertGuardRealitySnapshot("generation-a", latestReality); err != nil {
		t.Fatal(err)
	}
	before := s.testPersistCalls
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if calls := s.testPersistCalls - before; calls != 1 {
		t.Fatalf("close with unflushed clocks persisted %d times, want 1", calls)
	}
	reopened, err := OpenWithCipher(path, s.cipher)
	if err != nil {
		t.Fatal(err)
	}
	gotLiveness, _ := reopened.SingBoxLivenessRecord("node-a")
	gotReality, _ := reopened.GuardRealitySnapshot("node-a")
	if !gotLiveness.ReceivedAt.Equal(latest) || !gotReality.Reality.CollectedAt.Equal(latest) {
		t.Fatalf("close did not flush: liveness %s reality %s, want %s", gotLiveness.ReceivedAt, gotReality.Reality.CollectedAt, latest)
	}
	before = reopened.testPersistCalls
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if calls := reopened.testPersistCalls - before; calls != 0 {
		t.Fatalf("close with nothing unflushed persisted %d times", calls)
	}
}

// The inventory route reconciles the node's line chains on every report. A
// chain whose observation has not changed must not be written again, and its
// reconciliation audit, already recorded, must not be appended again.
func TestSteadyLineChainObservationsDoNotPersist(t *testing.T) {
	for _, hot := range []bool{false, true} {
		t.Run(fmt.Sprintf("bolt_hot_%v", hot), func(t *testing.T) {
			s, _ := openReportClockStore(t)
			defer s.Close()
			if hot {
				if err := s.EnableRuntimeBoltHotStore(filepath.Join(t.TempDir(), "hot.db")); err != nil {
					t.Fatal(err)
				}
			}
			at := time.Date(2026, 10, 1, 17, 0, 0, 0, time.UTC)
			definition := LineChainDefinition{
				SourceLineUUID: "line-src", SourceNodeID: "node-a", TargetLineUUID: "line-dst", TargetNodeID: "node-b",
				OutboundTag: "chain-out", ApprovalID: "approval-1", TaskID: "task-1",
				Status: LineChainStatusConverged, Generation: 1, CreatedAt: at, UpdatedAt: at,
			}
			s.mu.Lock()
			s.state.LineChainDefinitions[definition.SourceLineUUID] = definition
			s.mu.Unlock()
			observations := map[string]LineChainObservation{"line-src": {OutboundTag: "chain-out", DownstreamLineUUID: "line-dst"}}
			audit := model.AuditEvent{ID: "audit-linechain-1", At: at, NodeID: "node-a", Action: "linechain.apply", Decision: "allow"}
			if _, err := s.AppendAuditIdempotent(audit); err != nil {
				t.Fatal(err)
			}
			before := s.testPersistCalls
			for i := 0; i < 30; i++ {
				changed, err := s.ReconcileLineChainsWithAudits(observations, func(LineChainDefinition) (model.AuditEvent, bool) { return audit, true })
				if err != nil || changed {
					t.Fatalf("report %d: changed=%v err=%v", i, changed, err)
				}
				if appended, err := s.AppendAuditIdempotent(audit); err != nil || appended {
					t.Fatalf("report %d: audit appended=%v err=%v", i, appended, err)
				}
			}
			if calls := s.testPersistCalls - before; calls != 0 {
				t.Fatalf("30 unchanged chain observations persisted %d times", calls)
			}
		})
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

// A write that does not commit leaves the on-disk markers where they were, so
// the next report is still due and retries it; memory is not published either,
// as for every other commit-style write in the store.
func TestFailedReportWriteLeavesMarkersAndRetries(t *testing.T) {
	s, path := openReportClockStore(t)
	defer s.Close()
	if err := s.UpsertNode(model.Node{ID: "node-a", LatticeIdentityUUID: "generation-a"}); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 1, 17, 0, 0, 0, time.UTC)
	running := runningLiveness("node-a", base)
	reality := guardRealityFixture("node-a", base)
	if _, _, err := s.UpsertSingBoxLiveness(running); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UpsertGuardRealitySnapshot("generation-a", reality); err != nil {
		t.Fatal(err)
	}
	livenessMark, realityMark := s.livenessOnDisk["node-a"], s.guardRealityOnDisk["node-a"]

	// A directory where the temp file goes makes every write fail before
	// the rename, so nothing commits. It holds a file so the writer's cleanup
	// cannot remove it after the first failure.
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path+".tmp", "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	down := running
	down.Runtime.Running, down.Runtime.ActiveState, down.Runtime.SubState = false, "failed", "failed"
	down.State, down.StateSince, down.ProblemSince = "down", base.Add(10*time.Second), base.Add(10*time.Second)
	down.ReceivedAt, down.Runtime.ProbedAt = down.StateSince, down.StateSince
	if _, _, err := s.UpsertSingBoxLiveness(down); err == nil {
		t.Fatal("a durable change that could not be written reported success")
	}
	due := running
	due.ReceivedAt, due.Runtime.ProbedAt = base.Add(reportClockPersistInterval), base.Add(reportClockPersistInterval)
	if _, _, err := s.UpsertSingBoxLiveness(due); err == nil {
		t.Fatal("a due clock flush that could not be written reported success")
	}
	if _, _, err := s.UpsertGuardRealitySnapshot("generation-a", steadyGuardReality(reality, base.Add(reportClockPersistInterval))); err == nil {
		t.Fatal("a due guard reality flush that could not be written reported success")
	}
	if got := s.livenessOnDisk["node-a"]; !got.Equal(livenessMark) {
		t.Fatalf("a failed write moved the liveness marker to %s", got)
	}
	if got := s.guardRealityOnDisk["node-a"]; !got.Equal(realityMark) {
		t.Fatalf("a failed write moved the guard reality marker to %s", got)
	}
	if rec, _ := s.SingBoxLivenessRecord("node-a"); rec.State != "running" || !rec.ReceivedAt.Equal(base) {
		t.Fatalf("an uncommitted write was published: %+v", rec)
	}

	if err := os.RemoveAll(path + ".tmp"); err != nil {
		t.Fatal(err)
	}
	retryAt := base.Add(reportClockPersistInterval + 10*time.Second)
	before := s.testPersistCalls
	retry := running
	retry.ReceivedAt, retry.Runtime.ProbedAt = retryAt, retryAt
	if _, _, err := s.UpsertSingBoxLiveness(retry); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UpsertGuardRealitySnapshot("generation-a", steadyGuardReality(reality, retryAt)); err != nil {
		t.Fatal(err)
	}
	if calls := s.testPersistCalls - before; calls != 2 {
		t.Fatalf("the reports after the failure wrote %d times, want 2 (both still due)", calls)
	}
	if got := s.livenessOnDisk["node-a"]; !got.Equal(retryAt) {
		t.Fatalf("liveness marker after the retry is %s, want %s", got, retryAt)
	}
	down.ReceivedAt, down.Runtime.ProbedAt = retryAt.Add(10*time.Second), retryAt.Add(10*time.Second)
	before = s.testPersistCalls
	if _, _, err := s.UpsertSingBoxLiveness(down); err != nil {
		t.Fatal(err)
	}
	if calls := s.testPersistCalls - before; calls != 1 {
		t.Fatalf("the retried transition wrote %d times, want 1", calls)
	}
}

// A Close whose flush fails leaves clocks unflushed and the bolt sidecar
// closed. A second Close must not try again: without the sidecar, the write
// would carry the bolt-owned domains into the JSON file.
func TestSecondCloseAfterFailedFlushWritesNothing(t *testing.T) {
	s, path := openReportClockStore(t)
	if err := s.EnableRuntimeBoltHotStore(filepath.Join(t.TempDir(), "hot.db")); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNode(model.Node{ID: "node-a", LatticeIdentityUUID: "generation-a"}); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 1, 17, 0, 0, 0, time.UTC)
	rec := runningLiveness("node-a", base)
	if _, _, err := s.UpsertSingBoxLiveness(rec); err != nil {
		t.Fatal(err)
	}
	next := rec
	next.ReceivedAt, next.Runtime.ProbedAt = base.Add(time.Minute), base.Add(time.Minute)
	if _, _, err := s.UpsertSingBoxLiveness(next); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path+".tmp", "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err == nil {
		t.Fatal("a close whose flush could not be written reported success")
	}
	if err := os.RemoveAll(path + ".tmp"); err != nil {
		t.Fatal(err)
	}
	before := s.testPersistCalls
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if calls := s.testPersistCalls - before; calls != 0 {
		t.Fatalf("a second close persisted %d times, want 0", calls)
	}
}

// A clock stepped back past the copies on disk writes once for the fleet and
// restarts the interval from there. Clock-only reports used to wait until the
// clock caught up with the copy on disk, so the disk could go stale for as
// long as the step. And a write made then for one node leaves every other
// node's pre-step time on disk looking future, so judged naively each of
// them would write once more.
func TestReportClockStepBackWritesOnceAndRestartsTheInterval(t *testing.T) {
	s, _ := openReportClockStore(t)
	defer s.Close()
	nodes := []string{"node-a", "node-b", "node-c"}
	base := time.Date(2026, 10, 1, 17, 0, 0, 0, time.UTC)
	for _, id := range nodes {
		if err := s.UpsertNode(model.Node{ID: id, LatticeIdentityUUID: "generation-" + id}); err != nil {
			t.Fatal(err)
		}
	}
	firstGuard := map[string]GuardRealitySnapshot{}
	collected := base
	round := func(at time.Time) int {
		t.Helper()
		collected = collected.Add(10 * time.Second) // the agents' clocks did not move back
		before := s.testPersistCalls
		for _, id := range nodes {
			rec := runningLiveness(id, base)
			rec.ReceivedAt, rec.Runtime.ProbedAt = at, at
			if _, _, err := s.UpsertSingBoxLiveness(rec); err != nil {
				t.Fatal(err)
			}
			first, ok := firstGuard[id]
			if !ok {
				first = guardRealityFixture(id, collected)
				firstGuard[id] = first
			}
			snapshot := steadyGuardReality(first, collected)
			snapshot.ReceivedAt = at
			if _, _, err := s.UpsertGuardRealitySnapshot("generation-"+id, snapshot); err != nil {
				t.Fatal(err)
			}
		}
		return s.testPersistCalls - before
	}
	if got := round(base); got != 6 {
		t.Fatalf("first reports wrote %d times, want one each (6)", got)
	}
	if got := round(base.Add(10 * time.Second)); got != 0 {
		t.Fatalf("a clock-only round wrote %d times, want 0", got)
	}
	back := base.Add(-time.Hour)
	if got := round(back); got != 1 {
		t.Fatalf("the round after the clock went back an hour wrote %d times, want 1 for the fleet", got)
	}
	writes := 0
	for step := 1; step <= 90; step++ { // 15 minutes on the stepped-back clock
		writes += round(back.Add(time.Duration(step) * 10 * time.Second))
	}
	if writes != 1 {
		t.Fatalf("15 minutes after the step wrote %d times, want 1 when the interval came round", writes)
	}
}
