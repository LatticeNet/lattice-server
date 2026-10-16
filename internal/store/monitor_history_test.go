package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
)

// recordAt places one result in the hot store as if it had arrived when it
// was taken, which is how a pair that stopped long ago got its history.
func recordAt(t *testing.T, s *Store, monitorID, nodeID string, at time.Time, ok bool, ms float64) {
	t.Helper()
	rec := MonitorResultRecord{MonitorResult: model.MonitorResult{MonitorID: monitorID, NodeID: nodeID, At: at, Success: ok, LatencyMs: ms}, ReceivedAt: at}
	if _, err := s.runtimeBoltHot.RecordMonitorResults([]MonitorResultRecord{rec}, s.MonitorHistoryLimits()); err != nil {
		t.Fatal(err)
	}
}

func bucketStarts(t *testing.T, s *Store, pair MonitorPair, res time.Duration) []time.Time {
	t.Helper()
	got, err := s.MonitorRollups([]MonitorPair{pair}, res, time.Time{}, time.Now().Add(100*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var out []time.Time
	for _, b := range got[pair] {
		out = append(out, b.At)
	}
	return out
}

func sameInstants(a, b []time.Time) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

// The sweep deletes, for every pair whatever its monitor's state, the fine
// and coarse buckets that start before each tier's line and the raw rows
// stamped before the raw line, keeps everything on or after it, and lowers
// the pair's held count by the rows it took. Paused sources, sources taken
// off a check and paused generated checks never trim on their own, which is
// what the sweep is for.
func TestPruneMonitorHistoryAtEachTierBoundary(t *testing.T) {
	for _, batch := range []int{monitorPruneBatch, 1} {
		t.Run(fmt.Sprintf("batch-%d", batch), func(t *testing.T) {
			s := openHotStore(t, t.TempDir())
			defer s.Close()
			seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, NodeIDs: []string{"node-a", "node-p"}, PausedNodeIDs: []string{"node-p"}})
			seedMonitor(t, s, model.Monitor{ID: "mon-r", Type: model.MonitorTypeTCP, NodeIDs: []string{"node-a"}})
			if err := s.UpsertMonitor(model.Monitor{ID: "mon_lat_t", Type: model.MonitorTypeTCP, NodeIDs: []string{"node-a"}, ManagedBy: model.MonitorManagedLatency}); err != nil {
				t.Fatal(err)
			}
			base := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
			limits := s.MonitorHistoryLimits()
			fineCut := base.Add(-limits.FineKeep)
			coarseCut := base.Add(-limits.CoarseKeep)
			if !fineCut.Equal(fineCut.Truncate(time.Hour)) || !coarseCut.Equal(coarseCut.Truncate(time.Hour)) {
				t.Fatalf("the lines should fall on the hour: %s %s", fineCut, coarseCut)
			}
			stopped := []MonitorPair{{"mon-a", "node-p"}, {"mon-r", "node-x"}, {"mon_lat_t", "node-a"}}
			for _, pair := range stopped {
				for _, at := range []time.Time{coarseCut.Add(-time.Hour), coarseCut, fineCut.Add(-MonitorRollupFine), fineCut} {
					recordAt(t, s, pair.MonitorID, pair.NodeID, at, true, 10)
				}
			}
			active := MonitorPair{"mon-a", "node-a"}
			recordAt(t, s, active.MonitorID, active.NodeID, base.Add(-2*time.Minute), true, 10)
			recordAt(t, s, active.MonitorID, active.NodeID, base.Add(-time.Minute), true, 11)

			report, err := s.runtimeBoltHot.PruneMonitorHistory(context.Background(), base, limits, batch)
			if err != nil {
				t.Fatal(err)
			}
			if report.Fine != 3 || report.Coarse != 3 || report.Rows != 3 {
				t.Fatalf("report = %+v, want one fine bucket, one coarse bucket and one row per stopped pair", report)
			}
			if batch == 1 && report.Transactions < 9 {
				t.Fatalf("a batch of one deletes one key per transaction: %+v", report)
			}
			for _, pair := range stopped {
				if got := bucketStarts(t, s, pair, MonitorRollupFine); !sameInstants(got, []time.Time{fineCut}) {
					t.Fatalf("%v fine = %v, want only the bucket on the line", pair, got)
				}
				wantCoarse := []time.Time{coarseCut, fineCut.Add(-time.Hour), fineCut}
				if got := bucketStarts(t, s, pair, MonitorRollupCoarse); !sameInstants(got, wantCoarse) {
					t.Fatalf("%v coarse = %v, want %v", pair, got, wantCoarse)
				}
				rows, err := s.MonitorPairResults(pair.MonitorID, pair.NodeID, 0)
				if err != nil {
					t.Fatal(err)
				}
				if len(rows) != 3 || !rows[0].At.Equal(coarseCut) {
					t.Fatalf("%v rows = %+v", pair, rows)
				}
				latest, ok, err := s.MonitorLatest(pair.MonitorID, pair.NodeID)
				if err != nil || !ok || latest.Held != 3 || !latest.At.Equal(fineCut) {
					t.Fatalf("%v latest = %+v %v %v: the record stays and counts what is left", pair, latest, ok, err)
				}
			}
			if got := bucketStarts(t, s, active, MonitorRollupFine); len(got) != 1 {
				t.Fatalf("active pair lost buckets: %v", got)
			}
			again, err := s.PruneMonitorHistory(context.Background(), base)
			if err != nil {
				t.Fatal(err)
			}
			if again != (MonitorPruneReport{}) {
				t.Fatalf("a second sweep found work and wrote: %+v", again)
			}
		})
	}
}

// Lowering the fine retention reaches every pair at the next sweep, the
// active ones included, without waiting for their next bucket.
func TestPruneMonitorHistoryFollowsALoweredRetention(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, AssignAll: true})
	base := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	for d := 6; d >= 0; d-- {
		recordAt(t, s, "mon-a", "node-a", base.Add(-time.Duration(d)*24*time.Hour), true, 10)
	}
	pair := MonitorPair{"mon-a", "node-a"}
	if got := bucketStarts(t, s, pair, MonitorRollupFine); len(got) != 7 {
		t.Fatalf("fine buckets before = %v", got)
	}
	if _, err := s.SetMonitorSettings(model.MonitorSettings{FineRetentionDays: 3}, 0, "admin", base); err != nil {
		t.Fatal(err)
	}
	report, err := s.PruneMonitorHistory(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	// Days 6, 5 and 4 go; day 3 is inside three days and an hour.
	if report.Fine != 3 || report.Coarse != 0 || report.Rows != 0 {
		t.Fatalf("report = %+v", report)
	}
	if got := bucketStarts(t, s, pair, MonitorRollupFine); len(got) != 4 {
		t.Fatalf("fine buckets after = %v", got)
	}
}

// Jitter is the mean jump between consecutive successes, counted in the
// bucket of the later probe, so merging buckets gives the one-pass answer;
// a failure between two successes does not break the pair, a silence of
// more than an hour does. The hot store, the JSON fold and a raw summary
// agree.
func TestMonitorJitterSurvivesMergedBuckets(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, AssignAll: true})
	now := time.Now().UTC()
	start := now.Add(-3 * time.Hour).Truncate(time.Hour)
	type probe struct {
		after time.Duration
		ok    bool
		ms    float64
	}
	probes := []probe{
		{0, true, 10}, {2 * time.Minute, true, 14}, {4 * time.Minute, false, 0},
		{6 * time.Minute, true, 11}, {8 * time.Minute, true, 20},
		// More than an hour later: starts afresh.
		{90 * time.Minute, true, 50}, {92 * time.Minute, true, 47},
	}
	var batch []model.MonitorResult
	var rows []MonitorResultRecord
	for _, p := range probes {
		r := model.MonitorResult{MonitorID: "mon-a", NodeID: "node-a", At: start.Add(p.after), Success: p.ok, LatencyMs: p.ms}
		batch = append(batch, r)
		rows = append(rows, MonitorResultRecord{MonitorResult: r})
	}
	if _, err := s.IngestAgentMonitorResults("node-a", batch, now); err != nil {
		t.Fatal(err)
	}
	// 4 + 3 + 9 + 3 over four jumps.
	const wantJS, wantJN = 19.0, 4
	pair := MonitorPair{"mon-a", "node-a"}
	fine, err := s.MonitorRollups([]MonitorPair{pair}, MonitorRollupFine, start, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(fine[pair]) < 3 {
		t.Fatalf("the probes span three fine buckets: %+v", fine[pair])
	}
	merged := MergeMonitorRollups(fine[pair])
	if merged.JS != wantJS || merged.JN != wantJN {
		t.Fatalf("merged fine jitter = %v over %d, want %v over %d", merged.JS, merged.JN, wantJS, wantJN)
	}
	if j, ok := merged.Jitter(); !ok || math.Abs(j-wantJS/wantJN) > 1e-9 {
		t.Fatalf("jitter = %v %v", j, ok)
	}
	coarse, _ := s.MonitorRollups([]MonitorPair{pair}, MonitorRollupCoarse, start, now)
	if c := MergeMonitorRollups(coarse[pair]); c.JS != wantJS || c.JN != wantJN {
		t.Fatalf("coarse jitter = %v over %d", c.JS, c.JN)
	}
	one := SummarizeMonitorResults(rows)
	if one.JS != wantJS || one.JN != wantJN {
		t.Fatalf("one pass = %v over %d", one.JS, one.JN)
	}
	folded := MergeMonitorRollups(RollupMonitorResults(rows, MonitorRollupFine, start, now))
	if folded.JS != wantJS || folded.JN != wantJN {
		t.Fatalf("JSON fold = %v over %d", folded.JS, folded.JN)
	}
	sums, err := s.MonitorRowSummaries([]MonitorPair{pair}, start.Add(-time.Hour), start.Add(7*time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	// The later window starts between the successes of 11 and 20 ms: that
	// jump counts in the later window, where its second probe is, as it
	// does in the buckets.
	if got := sums[pair]; got.Prev.JS != 7 || got.Prev.JN != 2 || got.Cur.JS != 12 || got.Cur.JN != 2 {
		t.Fatalf("row summaries = prev %v/%d cur %v/%d", got.Prev.JS, got.Prev.JN, got.Cur.JS, got.Cur.JN)
	}
}

// The matrix reads a window and the one before it in one pass, split at the
// window's start.
func TestMonitorRollupSummariesSplitAtTheWindow(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, AssignAll: true})
	now := time.Now().UTC()
	from := now.Add(-time.Hour).Truncate(MonitorRollupFine)
	prevFrom := from.Add(-time.Hour)
	var batch []model.MonitorResult
	for i := 0; i < 120; i++ {
		at := prevFrom.Add(time.Duration(i) * time.Minute)
		batch = append(batch, model.MonitorResult{MonitorID: "mon-a", At: at, Success: at.Before(from) || i%4 != 0, LatencyMs: 30})
	}
	if _, err := s.IngestAgentMonitorResults("node-a", batch, now); err != nil {
		t.Fatal(err)
	}
	pair := MonitorPair{"mon-a", "node-a"}
	sums, err := s.MonitorRollupSummaries([]MonitorPair{pair, {"mon-a", "node-z"}}, MonitorRollupFine, prevFrom, from, now)
	if err != nil {
		t.Fatal(err)
	}
	got := sums[pair]
	if got.Prev.N != 60 || got.Prev.F != 0 || got.Cur.N != 60 || got.Cur.F != 15 || len(sums) != 1 {
		t.Fatalf("summaries = %+v", sums)
	}
}

// History written before this release (rows, rollups without jitter, latest
// records without the last success) keeps its keys and reads unchanged, the
// new tiers delete none of it, and jitter starts with the second success
// after the upgrade.
func TestMonitorHistoryFromBeforeTheNewTiersSurvives(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	seedMonitor(t, s, model.Monitor{ID: "mon_lat_t", Type: model.MonitorTypeTCP, NodeIDs: []string{"node-a"}})
	now := time.Now().UTC().Truncate(time.Minute)
	fineAt := now.Add(-40 * time.Hour).Truncate(MonitorRollupFine)
	coarseAt := now.Add(-7 * 24 * time.Hour).Truncate(MonitorRollupCoarse)
	rowAt := now.Add(-10 * time.Minute)
	put := func(tx *bolt.Tx, bucket []byte, key, value string) {
		k, err := boltStringKey(key)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Bucket(bucket).Put(k, []byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	err := s.runtimeBoltHot.db.Update(func(tx *bolt.Tx) error {
		put(tx, boltBucketMonResultRows, monitorResultKey("mon_lat_t", "node-a", rowAt), `{"success":true,"latency_ms":12,"received_at":"`+rowAt.Format(time.RFC3339Nano)+`"}`)
		put(tx, boltBucketMonResultLatest, monitorPairKey("mon_lat_t", "node-a"),
			`{"monitor_id":"mon_lat_t","node_id":"node-a","at":"`+rowAt.Format(time.RFC3339Nano)+`","success":true,"latency_ms":12,"fail_streak":0,"since":"`+rowAt.Format(time.RFC3339Nano)+`","held":1}`)
		put(tx, boltBucketMonRollupFine, monitorResultKey("mon_lat_t", "node-a", fineAt), `{"n":3,"f":1,"h":{"40":2},"min":12,"max":13}`)
		put(tx, boltBucketMonRollupCoarse, monitorResultKey("mon_lat_t", "node-a", coarseAt), `{"n":60,"f":2,"h":{"40":58},"min":11,"max":14}`)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := s.PruneMonitorHistory(context.Background(), now)
	if err != nil || report != (MonitorPruneReport{}) {
		t.Fatalf("the new tiers pruned old history: %+v %v", report, err)
	}
	pair := MonitorPair{"mon_lat_t", "node-a"}
	fine, _ := s.MonitorRollups([]MonitorPair{pair}, MonitorRollupFine, now.Add(-48*time.Hour), now.Add(time.Minute))
	if len(fine[pair]) != 1 || fine[pair][0].N != 3 || fine[pair][0].JN != 0 {
		t.Fatalf("old fine bucket = %+v", fine[pair])
	}
	if _, ok := fine[pair][0].Jitter(); ok {
		t.Fatal("a bucket from before jitter reports some")
	}
	coarse, _ := s.MonitorRollups([]MonitorPair{pair}, MonitorRollupCoarse, now.Add(-8*24*time.Hour), now.Add(time.Minute))
	if len(coarse[pair]) != 1 || coarse[pair][0].N != 60 {
		t.Fatalf("old coarse bucket = %+v", coarse[pair])
	}
	// The latest record has no last success yet, so the first new success
	// counts no jump and the second does.
	first, second := now.Add(-2*time.Minute), now.Add(-time.Minute)
	if _, err := s.IngestAgentMonitorResults("node-a", []model.MonitorResult{
		{MonitorID: "mon_lat_t", At: first, Success: true, LatencyMs: 20},
		{MonitorID: "mon_lat_t", At: second, Success: true, LatencyMs: 26},
	}, now); err != nil {
		t.Fatal(err)
	}
	recent, _ := s.MonitorRollups([]MonitorPair{pair}, MonitorRollupFine, now.Add(-5*time.Minute), now.Add(time.Minute))
	total := MergeMonitorRollups(recent[pair])
	if total.JN != 1 || total.JS != 6 {
		t.Fatalf("jitter after the upgrade = %v over %d, want 6 over 1", total.JS, total.JN)
	}
	latest, ok, err := s.MonitorLatest("mon_lat_t", "node-a")
	if err != nil || !ok || latest.Held != 3 || !latest.LastOKAt.Equal(second) || latest.LastOKMs != 26 {
		t.Fatalf("latest = %+v %v %v", latest, ok, err)
	}
}

// A paused source is not handed the monitor and a result it sends anyway is
// refused, while the other sources carry on.
func TestPausedSourceIsNotHandedTheMonitorAndIsRefused(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, NodeIDs: []string{"node-a", "node-b"}, PausedNodeIDs: []string{"node-b"}})
	seedMonitor(t, s, model.Monitor{ID: "mon-all", Type: model.MonitorTypeTCP, AssignAll: true, PausedNodeIDs: []string{"node-b"}})
	if got := s.MonitorsForNode("node-b"); len(got) != 0 {
		t.Fatalf("paused source is handed %+v", got)
	}
	if got := s.MonitorsForNode("node-a"); len(got) != 2 {
		t.Fatalf("running source is handed %+v", got)
	}
	now := time.Now().UTC()
	outcomes, err := s.IngestAgentMonitorResults("node-b", []model.MonitorResult{
		{MonitorID: "mon-a", At: now, Success: true},
		{MonitorID: "mon-all", At: now, Success: true},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range outcomes {
		if out.Dropped != MonitorResultDropNotAssigned {
			t.Fatalf("paused source result = %+v", out)
		}
	}
	outcomes, _ = s.IngestAgentMonitorResults("node-a", []model.MonitorResult{{MonitorID: "mon-a", At: now, Success: true}}, now)
	if !outcomes[0].Stored() {
		t.Fatalf("running source result = %+v", outcomes[0])
	}
}

// The setting is versioned like the latency configuration, bounded, and
// survives a restart of the JSON state and the bolt export.
func TestMonitorSettingsAreVersionedAndPersisted(t *testing.T) {
	dir := t.TempDir()
	s := openHotStore(t, dir)
	if got := s.MonitorSettings(); got.FineRetentionDays != model.MonitorFineRetentionDefaultDays || got.Version != 0 {
		t.Fatalf("default = %+v", got)
	}
	now := time.Now().UTC()
	if _, err := s.SetMonitorSettings(model.MonitorSettings{FineRetentionDays: 2}, 0, "admin", now); err == nil {
		t.Fatal("two days accepted")
	}
	stored, err := s.SetMonitorSettings(model.MonitorSettings{FineRetentionDays: 14}, 0, "admin", now)
	if err != nil || stored.Version != 1 {
		t.Fatalf("save = %+v %v", stored, err)
	}
	if _, err := s.SetMonitorSettings(model.MonitorSettings{FineRetentionDays: 3}, 0, "other", now); !errors.Is(err, ErrMonitorSettingsVersion) {
		t.Fatalf("stale save = %v", err)
	}
	if got := s.MonitorHistoryLimits(); got.FineKeep != 14*24*time.Hour+monitorRetentionSlack {
		t.Fatalf("limits = %+v", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWithCipher(filepath.Join(dir, "state.json"), secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.MonitorSettings(); got.FineRetentionDays != 14 || got.Version != 1 || got.UpdatedBy != "admin" {
		t.Fatalf("after reopen = %+v", got)
	}
	bs, err := OpenBoltState(filepath.Join(dir, "migrated.db"), secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()
	if err := bs.ImportState(reopened.state); err != nil {
		t.Fatal(err)
	}
	back, err := bs.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if back.MonitorSettings == nil || back.MonitorSettings.FineRetentionDays != 14 {
		t.Fatalf("bolt round trip = %+v", back.MonitorSettings)
	}
}

// History reads run outside the store lock beside ingest, the sweep and
// other store calls; the race detector holds this to account.
func TestMonitorHistoryReadsRunBesideIngest(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, AssignAll: true})
	now := time.Now().UTC()
	pairs := []MonitorPair{{"mon-a", "node-a"}, {"mon-a", "node-b"}}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			at := now.Add(-time.Hour + time.Duration(i)*time.Second)
			for _, node := range []string{"node-a", "node-b"} {
				if _, err := s.IngestAgentMonitorResults(node, []model.MonitorResult{{MonitorID: "mon-a", At: at, Success: i%9 != 0, LatencyMs: float64(i % 30)}}, now); err != nil {
					errs <- err
					return
				}
			}
		}
	}()
	for r := 0; r < 3; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if _, err := s.MonitorRollupSummaries(pairs, MonitorRollupFine, now.Add(-2*time.Hour), now.Add(-time.Hour), now); err != nil {
					errs <- err
					return
				}
				if _, err := s.MonitorRowSummaries(pairs, now.Add(-2*time.Hour), now.Add(-time.Hour), now); err != nil {
					errs <- err
					return
				}
				if _, err := s.LatestMonitorResults(); err != nil {
					errs <- err
					return
				}
				if _, err := s.MonitorStorageUsage(); err != nil {
					errs <- err
					return
				}
				_ = s.Monitors()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			if _, err := s.PruneMonitorHistory(context.Background(), now); err != nil {
				errs <- err
				return
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	usage, err := s.MonitorStorageUsage()
	if err != nil || !usage.Measured || usage.RowKeys != 400 || usage.Total() <= 0 || usage.FineKeys == 0 {
		t.Fatalf("usage = %+v %v", usage, err)
	}
}

// Deleting a node takes it off every paused list as well as every
// assignment, so a node enrolled again under the same id starts unpaused.
func TestDeleteNodeStripsItFromPausedSources(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	for _, n := range []string{"node-a", "node-b"} {
		if err := s.UpsertNode(model.Node{ID: n, Name: n}); err != nil {
			t.Fatal(err)
		}
	}
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, NodeIDs: []string{"node-a", "node-b"}, PausedNodeIDs: []string{"node-b"}})
	seedMonitor(t, s, model.Monitor{ID: "mon-all", Type: model.MonitorTypeTCP, AssignAll: true, PausedNodeIDs: []string{"node-b"}})
	report, _, err := s.DeleteNode("node-b")
	if err != nil {
		t.Fatal(err)
	}
	if report.MonitorsStripped != 2 {
		t.Fatalf("stripped = %d, want both monitors", report.MonitorsStripped)
	}
	for _, id := range []string{"mon-a", "mon-all"} {
		mon, _ := s.Monitor(id)
		if contains(mon.PausedNodeIDs, "node-b") || contains(mon.NodeIDs, "node-b") {
			t.Fatalf("%s still names the deleted node: %+v", id, mon)
		}
		// An edit read before the delete is refused rather than writing
		// the node back.
		if mon.Version != 1 {
			t.Fatalf("%s version = %d after the strip", id, mon.Version)
		}
	}
}

// A late success from an agent's buffer does not move the last success,
// which the next jump is measured from, back in time.
func TestLateSuccessKeepsTheNewerLastSuccess(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, AssignAll: true})
	now := time.Now().UTC()
	if _, err := s.IngestAgentMonitorResults("node-a", []model.MonitorResult{
		{MonitorID: "mon-a", At: now.Add(-time.Minute), Success: true, LatencyMs: 30},
		{MonitorID: "mon-a", At: now.Add(-3 * time.Minute), Success: true, LatencyMs: 90},
	}, now); err != nil {
		t.Fatal(err)
	}
	latest, _, err := s.MonitorLatest("mon-a", "node-a")
	if err != nil || !latest.LastOKAt.Equal(now.Add(-time.Minute)) || latest.LastOKMs != 30 {
		t.Fatalf("latest = %+v %v", latest, err)
	}
}
