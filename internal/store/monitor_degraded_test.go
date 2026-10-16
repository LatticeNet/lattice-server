package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
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
