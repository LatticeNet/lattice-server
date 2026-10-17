package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	bolt "go.etcd.io/bbolt"

	"github.com/LatticeNet/lattice-server/internal/secret"
)

// The baseline read merges the hourly buckets of [from, to) exactly as the
// summary read merges them, counts the buckets with a run, aligns its bounds
// to the hour, and leaves out a pair with nothing in the window.
func TestMonitorRollupBaselinesMergeAndCountHours(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, AssignAll: true})
	to := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	from := to.Add(-7 * 24 * time.Hour)
	pair := MonitorPair{"mon-a", "node-a"}
	// Two runs an hour for 30 hours inside the window, one hour before it
	// and one in the current hour, which the baseline must not see.
	for h := 30; h >= 1; h-- {
		at := to.Add(-time.Duration(h) * time.Hour)
		recordAt(t, s, "mon-a", "node-a", at.Add(10*time.Minute), h%5 != 0, float64(40+h%3))
		recordAt(t, s, "mon-a", "node-a", at.Add(40*time.Minute), true, 41)
	}
	recordAt(t, s, "mon-a", "node-a", from.Add(-30*time.Minute), true, 500)
	recordAt(t, s, "mon-a", "node-a", to.Add(10*time.Minute), true, 500)

	bases, err := s.MonitorRollupBaselines([]MonitorPair{pair, {"mon-a", "node-z"}}, from.Add(17*time.Minute), to.Add(17*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := bases[pair]
	if !ok || len(bases) != 1 {
		t.Fatalf("baselines = %+v", bases)
	}
	if got.Hours != 30 || got.Merged.N != 60 || got.Merged.F != 6 || got.Merged.Max != 42 {
		t.Fatalf("baseline = hours %d, %+v", got.Hours, got.Merged)
	}
	sums, err := s.MonitorRollupSummaries([]MonitorPair{pair}, MonitorRollupCoarse, from.Add(-time.Hour), from, to)
	if err != nil {
		t.Fatal(err)
	}
	cur := sums[pair].Cur
	if cur.N != got.Merged.N || cur.F != got.Merged.F || cur.S != got.Merged.S || cur.L != got.Merged.L || len(cur.H) != len(got.Merged.H) {
		t.Fatalf("baseline %+v differs from the summary read %+v", got.Merged, cur)
	}
	for bin, n := range cur.H {
		if got.Merged.H[bin] != n {
			t.Fatalf("bin %d: baseline %d, summary %d", bin, got.Merged.H[bin], n)
		}
	}
	p50, _ := got.Merged.Quantile(0.5)
	want, _ := cur.Quantile(0.5)
	if p50 != want {
		t.Fatalf("p50 %v, summary p50 %v", p50, want)
	}
	// The JSON fallback folds its rows the same way.
	j, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	seedMonitor(t, j, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, AssignAll: true})
	for h := 3; h >= 1; h-- {
		if _, err := j.AddMonitorResult(model.MonitorResult{MonitorID: "mon-a", NodeID: "node-a", At: to.Add(-time.Duration(h) * time.Hour), Success: true, LatencyMs: 20}); err != nil {
			t.Fatal(err)
		}
	}
	jb, err := j.MonitorRollupBaselines([]MonitorPair{pair}, from, to)
	if err != nil {
		t.Fatal(err)
	}
	if jb[pair].Hours != 3 || jb[pair].Merged.N != 3 {
		t.Fatalf("json baseline = %+v", jb)
	}
}

// A record survives a reopen of the same files, and goes with its monitor's
// history and with its node's.
func TestPathDegradedRecordsPersistAndGoWithTheirHistory(t *testing.T) {
	dir := t.TempDir()
	s := openHotStore(t, dir)
	for _, n := range []string{"node-a", "node-b"} {
		if err := s.UpsertNode(model.Node{ID: n, Name: n}); err != nil {
			t.Fatal(err)
		}
	}
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, NodeIDs: []string{"node-a", "node-b"}})
	seedMonitor(t, s, model.Monitor{ID: "mon-b", Type: model.MonitorTypeTCP, NodeIDs: []string{"node-a", "node-b"}})
	since := time.Date(2026, 10, 16, 14, 2, 0, 0, time.UTC)
	rec := PathDegradedRecord{Since: since, EnteredAt: since.Add(time.Minute), ClearSince: since.Add(time.Hour), Reason: model.PathReasonDegradedLoss,
		EvaluatedAt: since.Add(time.Minute), Loss: &model.PathLossEvidence{Value: 0.05, Baseline: 0.01, Trigger: 0.02, Sent: 300, Lost: 15}}
	for _, pair := range []MonitorPair{{"mon-a", "node-a"}, {"mon-a", "node-b"}, {"mon-b", "node-a"}, {"mon-b", "node-b"}} {
		if err := s.PutPathDegradedRecord(pair, rec); err != nil {
			t.Fatal(err)
		}
	}
	// A pair whose monitor is gone is not written.
	if err := s.PutPathDegradedRecord(MonitorPair{"mon-gone", "node-a"}, rec); err != nil {
		t.Fatal(err)
	}
	if !s.PathDegradedDurable() {
		t.Fatal("hot store records should be durable")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openHotStore(t, dir)
	defer s.Close()
	got, err := s.PathDegradedRecords()
	if err != nil {
		t.Fatal(err)
	}
	back, ok := got[MonitorPair{"mon-a", "node-a"}]
	if len(got) != 4 || !ok || !back.Since.Equal(since) || !back.ClearSince.Equal(since.Add(time.Hour)) || !back.Clearing() || back.Loss == nil || back.Loss.Lost != 15 {
		t.Fatalf("after reopen: %+v", got)
	}
	if err := s.DeleteMonitor("mon-b"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.DeleteNode("node-b"); err != nil {
		t.Fatal(err)
	}
	got, err = s.PathDegradedRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("after deleting mon-b and node-b: %+v", got)
	}
	if _, ok := got[MonitorPair{"mon-a", "node-a"}]; !ok {
		t.Fatalf("the surviving pair is gone: %+v", got)
	}
	if err := s.DeletePathDegradedRecord(MonitorPair{"mon-a", "node-a"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.PathDegradedRecords(); len(got) != 0 {
		t.Fatalf("after the delete: %+v", got)
	}
}

// Without the hot store the records live in memory and still go with their
// monitor and node.
func TestPathDegradedRecordsInMemoryWithoutTheHotStore(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, n := range []string{"node-a", "node-b"} {
		if err := s.UpsertNode(model.Node{ID: n, Name: n}); err != nil {
			t.Fatal(err)
		}
	}
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, NodeIDs: []string{"node-a", "node-b"}})
	seedMonitor(t, s, model.Monitor{ID: "mon-b", Type: model.MonitorTypeTCP, NodeIDs: []string{"node-a"}})
	for _, pair := range []MonitorPair{{"mon-a", "node-a"}, {"mon-a", "node-b"}, {"mon-b", "node-a"}} {
		if err := s.PutPathDegradedRecord(pair, PathDegradedRecord{Reason: model.PathReasonDegradedLatency}); err != nil {
			t.Fatal(err)
		}
	}
	if s.PathDegradedDurable() {
		t.Fatal("memory records are not durable")
	}
	if err := s.DeleteMonitor("mon-b"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.DeleteNode("node-b"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.PathDegradedRecords()
	if _, ok := got[MonitorPair{"mon-a", "node-a"}]; len(got) != 1 || !ok {
		t.Fatalf("records = %+v", got)
	}
}

// A record write runs its bolt transaction outside the store lock: while
// another bolt writer holds the file, a pending put and delete wait on bbolt
// alone and every other store call goes on.
func TestPathDegradedRecordWritesDoNotHoldTheStoreLock(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	if err := s.UpsertNode(model.Node{ID: "node-a", Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, NodeIDs: []string{"node-a"}})
	pair := MonitorPair{"mon-a", "node-a"}
	held, release := make(chan struct{}), make(chan struct{})
	writer := make(chan error, 1)
	go func() {
		writer <- s.runtimeBoltHot.db.Update(func(*bolt.Tx) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	done := make(chan error, 2)
	go func() {
		done <- s.PutPathDegradedRecord(pair, PathDegradedRecord{Reason: model.PathReasonDegradedLoss})
	}()
	go func() { done <- s.DeletePathDegradedRecord(MonitorPair{"mon-a", "node-z"}) }()
	// Both writes are now queued behind the held transaction, or about to
	// be; neither may hold the store lock while they wait.
	time.Sleep(50 * time.Millisecond)
	read := make(chan struct{})
	go func() {
		s.Monitor("mon-a")
		s.Nodes()
		close(read)
	}()
	select {
	case <-read:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("a store read waited on a degraded record write")
	}
	close(release)
	if err := <-writer; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := s.PathDegradedRecords(); len(got) != 1 || got[pair].Reason != model.PathReasonDegradedLoss {
		t.Fatalf("records = %+v", got)
	}
}

// A delete that runs after a put's first existence check and before its
// bolt write finds no record to remove, so the put must take its record back
// once it lands. The seam puts the delete exactly in that window, for a
// monitor delete and a node delete alike; without the second check the
// record would outlive its pair.
func TestPathDegradedRecordPutTakesBackAfterADeleteInTheWindow(t *testing.T) {
	for _, tc := range []struct {
		name   string
		delete func(*Store) error
	}{
		{"monitor", func(s *Store) error { return s.DeleteMonitor("mon-a") }},
		{"node", func(s *Store) error {
			_, _, err := s.DeleteNode("node-a")
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := openHotStore(t, t.TempDir())
			defer s.Close()
			if err := s.UpsertNode(model.Node{ID: "node-a", Name: "node-a"}); err != nil {
				t.Fatal(err)
			}
			seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, NodeIDs: []string{"node-a"}})
			pair := MonitorPair{"mon-a", "node-a"}
			ran := 0
			s.testBeforePathDegradedWrite = func(got MonitorPair) {
				ran++
				if got != pair {
					t.Errorf("seam pair = %+v", got)
				}
				if err := tc.delete(s); err != nil {
					t.Error(err)
				}
				if recs, err := s.runtimeBoltHot.PathDegradedRecords(); err != nil || len(recs) != 0 {
					t.Errorf("records before the write = %+v, %v", recs, err)
				}
			}
			if err := s.PutPathDegradedRecord(pair, PathDegradedRecord{Reason: model.PathReasonDegradedLatency}); err != nil {
				t.Fatal(err)
			}
			if ran != 1 {
				t.Fatalf("seam ran %d times, want 1", ran)
			}
			if got, err := s.PathDegradedRecords(); err != nil || len(got) != 0 {
				t.Fatalf("records after a delete in the window = %+v, %v", got, err)
			}
		})
	}
}

// Puts racing deletes of their monitor, with no seam, never leave a record
// behind either. This exercises the unlocked write under -race; the test
// above is the one that pins the take-back.
func TestPathDegradedRecordPutRacingAMonitorDelete(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	if err := s.UpsertNode(model.Node{ID: "node-a", Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, NodeIDs: []string{"node-a"}})
		put := make(chan error, 1)
		go func() {
			put <- s.PutPathDegradedRecord(MonitorPair{"mon-a", "node-a"}, PathDegradedRecord{Reason: model.PathReasonDegradedLatency})
		}()
		if err := s.DeleteMonitor("mon-a"); err != nil {
			t.Fatal(err)
		}
		if err := <-put; err != nil {
			t.Fatal(err)
		}
		if got, err := s.PathDegradedRecords(); err != nil || len(got) != 0 {
			t.Fatalf("round %d: records after the delete = %+v, %v", i, got, err)
		}
	}
}
