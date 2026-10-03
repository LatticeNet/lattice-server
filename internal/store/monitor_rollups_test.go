package store

import (
	"math"
	"math/rand"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
)

// A percentile read off the histogram stays within 5 percent of the exact
// nearest-rank value, for latencies a probe from China actually sees.
func TestMonitorRollupQuantileIsWithinFivePercent(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for _, spread := range []struct{ base, jitter float64 }{{3, 2}, {48, 30}, {180, 120}, {900, 2500}} {
		var r MonitorRollup
		values := make([]float64, 0, 1440)
		for i := 0; i < 1440; i++ {
			v := spread.base + rng.ExpFloat64()*spread.jitter
			values = append(values, v)
			r.add(true, v)
		}
		sort.Float64s(values)
		for _, q := range []float64{0.5, 0.95} {
			exact := values[int(math.Ceil(q*float64(len(values))))-1]
			got, ok := r.Quantile(q)
			if !ok {
				t.Fatalf("no quantile from %d samples", r.N)
			}
			if rel := math.Abs(got-exact) / exact; rel > 0.05 {
				t.Fatalf("base %v q%.2f: got %.2f, exact %.2f (%.1f%% off)", spread.base, q, got, exact, rel*100)
			}
		}
	}
	var failures MonitorRollup
	failures.add(false, 0)
	if _, ok := failures.Quantile(0.5); ok || failures.N != 1 || failures.F != 1 {
		t.Fatalf("failures alone carry no latency: %+v", failures)
	}
	var one MonitorRollup
	one.add(true, 42.5)
	if got, _ := one.Quantile(0.95); got != 42.5 {
		t.Fatalf("one sample is its own percentile, got %v", got)
	}
}

// Merging buckets gives the same summary as counting every result once.
func TestMonitorRollupMergeMatchesOnePass(t *testing.T) {
	var whole MonitorRollup
	parts := make([]MonitorRollup, 3)
	for i := 0; i < 300; i++ {
		ok := i%7 != 0
		v := float64(20 + i%50)
		whole.add(ok, v)
		parts[i%3].add(ok, v)
	}
	merged := MergeMonitorRollups([]MonitorRollup{{}, parts[0], parts[1], parts[2]})
	if merged.N != whole.N || merged.F != whole.F || merged.Min != whole.Min || merged.Max != whole.Max {
		t.Fatalf("merged %+v, whole %+v", merged, whole)
	}
	for _, q := range []float64{0.5, 0.95} {
		a, _ := merged.Quantile(q)
		b, _ := whole.Quantile(q)
		if a != b {
			t.Fatalf("q%.2f merged %v whole %v", q, a, b)
		}
	}
}

// Results counted in the hot store land in both tiers in the same write, a
// batch sent again adds nothing, and a read returns only the asked window.
func TestHotMonitorRollupsCountEachResultOnce(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, AssignAll: true})
	now := time.Now().UTC()
	start := now.Add(-3 * time.Hour).Truncate(time.Hour)
	var batch []model.MonitorResult
	for i := 0; i < 180; i++ {
		batch = append(batch, model.MonitorResult{MonitorID: "mon-a", At: start.Add(time.Duration(i) * time.Minute), Success: i%10 != 9, LatencyMs: float64(40 + i%20)})
	}
	calls := s.testPersistCalls
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := s.IngestAgentMonitorResults("node-a", batch, now); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.testPersistCalls - calls; got != 0 {
		t.Fatalf("rollups wrote the state file %d times", got)
	}
	pair := MonitorPair{MonitorID: "mon-a", NodeID: "node-a"}
	coarse, err := s.MonitorRollups([]MonitorPair{pair}, MonitorRollupCoarse, start, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(coarse[pair]) != 3 {
		t.Fatalf("coarse buckets = %d, want 3", len(coarse[pair]))
	}
	for i, b := range coarse[pair] {
		if b.N != 60 || b.F != 6 || !b.At.Equal(start.Add(time.Duration(i)*time.Hour)) {
			t.Fatalf("coarse bucket %d = %+v", i, b)
		}
	}
	fine, err := s.MonitorRollups([]MonitorPair{pair}, MonitorRollupFine, start.Add(time.Hour), start.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(fine[pair]) != 12 {
		t.Fatalf("fine buckets in one hour = %d, want 12", len(fine[pair]))
	}
	total := MergeMonitorRollups(fine[pair])
	// i%20 == 19 always lands on a failure, so the slowest success is 58.
	if total.N != 60 || total.F != 6 || total.Min != 40 || total.Max != 58 {
		t.Fatalf("one hour of fine buckets = %+v", total)
	}
	if other, _ := s.MonitorRollups([]MonitorPair{{MonitorID: "mon-a", NodeID: "node-b"}}, MonitorRollupFine, start, now); len(other) != 0 {
		t.Fatalf("a pair with no results has buckets: %+v", other)
	}
}

// Buckets older than a tier keeps are trimmed as new ones open, so a pair's
// rollups stay bounded however long it runs.
func TestHotMonitorRollupsAreTrimmed(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, AssignAll: true})
	pair := MonitorPair{MonitorID: "mon-a", NodeID: "node-a"}
	now := time.Now().UTC()
	old := now.Add(-20 * time.Hour)
	// AddMonitorResult stamps ReceivedAt with the wall clock, so drive the
	// bolt half directly to place results ten days apart.
	for _, at := range []time.Time{now.Add(-10 * 24 * time.Hour), old, now} {
		rec := MonitorResultRecord{MonitorResult: model.MonitorResult{MonitorID: "mon-a", NodeID: "node-a", At: at, Success: true, LatencyMs: 10}, ReceivedAt: at}
		if _, err := s.runtimeBoltHot.RecordMonitorResults([]MonitorResultRecord{rec}, MonitorResultsPerPair); err != nil {
			t.Fatal(err)
		}
	}
	coarse, _ := s.MonitorRollups([]MonitorPair{pair}, MonitorRollupCoarse, now.Add(-30*24*time.Hour), now.Add(time.Hour))
	if len(coarse[pair]) != 2 {
		t.Fatalf("coarse keeps eight days: %d buckets %+v", len(coarse[pair]), coarse[pair])
	}
	fine, _ := s.MonitorRollups([]MonitorPair{pair}, MonitorRollupFine, now.Add(-30*24*time.Hour), now.Add(time.Hour))
	if len(fine[pair]) != 2 || !fine[pair][0].At.Equal(old.Truncate(MonitorRollupFine)) {
		t.Fatalf("fine keeps two days: %+v", fine[pair])
	}
}

// Deleting a monitor or a node takes its rollups with it, so a node enrolled
// again under the same id starts with no history.
func TestDeletesRemoveRollups(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, AssignAll: true})
	seedMonitor(t, s, model.Monitor{ID: "mon-b", Type: model.MonitorTypeTCP, AssignAll: true})
	if err := s.UpsertNode(model.Node{ID: "node-a", Name: "a"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, mon := range []string{"mon-a", "mon-b"} {
		for _, node := range []string{"node-a", "node-b"} {
			if _, err := s.IngestAgentMonitorResults(node, []model.MonitorResult{{MonitorID: mon, At: now.Add(-time.Minute), Success: true, LatencyMs: 5}}, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	all := []MonitorPair{{"mon-a", "node-a"}, {"mon-a", "node-b"}, {"mon-b", "node-a"}, {"mon-b", "node-b"}}
	count := func() int {
		got, err := s.MonitorRollups(all, MonitorRollupFine, now.Add(-time.Hour), now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return len(got)
	}
	if count() != 4 {
		t.Fatalf("pairs with rollups = %d, want 4", count())
	}
	if err := s.DeleteMonitor("mon-a"); err != nil {
		t.Fatal(err)
	}
	if count() != 2 {
		t.Fatalf("after the monitor delete = %d, want 2", count())
	}
	if _, _, err := s.DeleteNode("node-a"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.MonitorRollups(all, MonitorRollupCoarse, now.Add(-time.Hour), now.Add(time.Hour))
	if len(got) != 1 || len(got[MonitorPair{"mon-b", "node-b"}]) != 1 {
		t.Fatalf("after the node delete: %+v", got)
	}
}

// Without the hot store a rollup read folds the raw series it still holds.
func TestJSONMonitorRollupsFoldRawRows(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, AssignAll: true})
	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		if _, err := s.IngestAgentMonitorResults("node-a", []model.MonitorResult{{MonitorID: "mon-a", At: now.Add(-time.Duration(10-i) * time.Minute), Success: i != 3, LatencyMs: 30}}, now); err != nil {
			t.Fatal(err)
		}
	}
	pair := MonitorPair{MonitorID: "mon-a", NodeID: "node-a"}
	got, err := s.MonitorRollups([]MonitorPair{pair}, MonitorRollupCoarse, now.Add(-2*time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	total := MergeMonitorRollups(got[pair])
	if total.N != 10 || total.F != 1 {
		t.Fatalf("folded = %+v", total)
	}
}
