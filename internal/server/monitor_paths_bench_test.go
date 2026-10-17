package server

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/secret"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// benchFleet is a full mesh of 25 nodes, every node probing the other 24:
// 600 generated paths, each with two weeks of hourly results, a day of
// five-minute results and an hour of one-minute results in the hot store.
type benchFleet struct {
	srv   *Server
	st    *store.Store
	nodes []string
	now   time.Time
}

func newBenchFleet(b *testing.B) *benchFleet {
	b.Helper()
	const n = 25
	dir := b.TempDir()
	hotPath := filepath.Join(dir, "state-hot.db")
	now := time.Now().UTC()
	nodes := make([]string, n)
	for i := range nodes {
		nodes[i] = fmt.Sprintf("node-%02d", i)
	}
	bs, err := store.OpenBoltState(hotPath, secret.Disabled())
	if err != nil {
		b.Fatal(err)
	}
	var batch []store.MonitorResultRecord
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if _, err := bs.RecordMonitorResults(batch, store.DefaultMonitorHistoryLimits()); err != nil {
			b.Fatal(err)
		}
		batch = batch[:0]
	}
	var ats []time.Time
	for h := 14 * 24; h > 24; h-- {
		ats = append(ats, now.Add(-time.Duration(h)*time.Hour+30*time.Second))
	}
	for m := 24 * 60; m > 60; m -= 5 {
		ats = append(ats, now.Add(-time.Duration(m)*time.Minute+10*time.Second))
	}
	for m := 60; m >= 1; m-- {
		ats = append(ats, now.Add(-time.Duration(m)*time.Minute+20*time.Second))
	}
	sort.Slice(ats, func(i, j int) bool { return ats[i].Before(ats[j]) })
	for _, target := range nodes {
		for _, source := range nodes {
			if source == target {
				continue
			}
			for i, at := range ats {
				ok := i%37 != 0
				batch = append(batch, store.MonitorResultRecord{
					MonitorResult: model.MonitorResult{MonitorID: latencyMonitorID(target), NodeID: source, At: at, Success: ok, LatencyMs: float64(40 + i%17)},
					ReceivedAt:    at,
				})
			}
			if len(batch) >= 20000 {
				flush()
			}
		}
	}
	flush()
	if err := bs.Close(); err != nil {
		b.Fatal(err)
	}
	st, err := store.OpenWithCipher(filepath.Join(dir, "state.json"), nil)
	if err != nil {
		b.Fatal(err)
	}
	for i, id := range nodes {
		if err := st.UpsertNode(model.Node{ID: id, Name: id, Online: true, PublicIP: fmt.Sprintf("203.0.113.%d", 10+i), Geo: &model.NodeGeo{Country: "JP"}}); err != nil {
			b.Fatal(err)
		}
	}
	for i, target := range nodes {
		var sources []string
		for _, source := range nodes {
			if source != target {
				sources = append(sources, source)
			}
		}
		if err := st.UpsertMonitor(model.Monitor{ID: latencyMonitorID(target), Name: "Latency to " + target, Type: model.MonitorTypeTCP,
			Target: fmt.Sprintf("203.0.113.%d:443", 10+i), IntervalSec: 60, TimeoutSec: 5, NodeIDs: sources, Enabled: true, ManagedBy: model.MonitorManagedLatency}); err != nil {
			b.Fatal(err)
		}
	}
	if _, err := st.SetLatencyProbeConfig(model.LatencyProbeConfig{Enabled: true, IntervalSec: 60, TimeoutSec: 5, Sources: nodes, AutoTargets: true}, 0, "admin", now); err != nil {
		b.Fatal(err)
	}
	if err := st.EnableRuntimeBoltHotStore(hotPath); err != nil {
		b.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		srv.Close(context.Background())
		st.Close()
	})
	return &benchFleet{srv: srv, st: st, nodes: nodes, now: now}
}

// ingestLoad posts one source's 24 results per call, as fast as the store
// takes them, until stop; it records how long each call took.
type ingestLoad struct {
	stop    chan struct{}
	done    sync.WaitGroup
	batches atomic.Int64
	mu      sync.Mutex
	lat     []time.Duration
}

func (f *benchFleet) startIngest(b *testing.B) *ingestLoad {
	l := &ingestLoad{stop: make(chan struct{})}
	l.done.Add(1)
	go func() {
		defer l.done.Done()
		tick := 0
		for {
			select {
			case <-l.stop:
				return
			default:
			}
			source := f.nodes[tick%len(f.nodes)]
			at := f.now.Add(time.Duration(tick) * time.Millisecond)
			results := make([]model.MonitorResult, 0, len(f.nodes)-1)
			for _, target := range f.nodes {
				if target != source {
					results = append(results, model.MonitorResult{MonitorID: latencyMonitorID(target), At: at, Success: true, LatencyMs: 41})
				}
			}
			started := time.Now()
			if _, err := f.st.IngestAgentMonitorResults(source, results, at); err != nil {
				b.Error(err)
				return
			}
			l.mu.Lock()
			l.lat = append(l.lat, time.Since(started))
			l.mu.Unlock()
			l.batches.Add(1)
			tick++
		}
	}()
	return l
}

func (l *ingestLoad) finish(b *testing.B, elapsed time.Duration) {
	close(l.stop)
	l.done.Wait()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.lat) == 0 || elapsed <= 0 {
		return
	}
	sort.Slice(l.lat, func(i, j int) bool { return l.lat[i] < l.lat[j] })
	b.ReportMetric(float64(l.batches.Load())/elapsed.Seconds(), "ingest-batches/s")
	b.ReportMetric(float64(l.lat[len(l.lat)/2].Microseconds()), "ingest-p50-us")
	b.ReportMetric(float64(l.lat[len(l.lat)*99/100].Microseconds()), "ingest-p99-us")
}

// BenchmarkMonitorPathMatrix reads the matrix of 600 paths while a writer
// ingests results as fast as the store takes them. "cold" drops the window
// cache before every read; "cached" reads within one bucket. "ingest-only"
// is the writer alone, the baseline for its latency under reads.
func BenchmarkMonitorPathMatrix(b *testing.B) {
	f := newBenchFleet(b)
	p := principal{Principal: adminPrincipalForTest()}
	m, err := f.srv.pathMatrixFor(p, model.PathWindowWeek, f.now)
	if err != nil {
		b.Fatal(err)
	}
	if len(m.Paths) != 600 {
		b.Fatalf("matrix has %d paths, want 600", len(m.Paths))
	}
	b.Run("ingest-only", func(b *testing.B) {
		l := f.startIngest(b)
		started := time.Now()
		for b.Loop() {
			time.Sleep(50 * time.Millisecond)
		}
		l.finish(b, time.Since(started))
	})
	for _, window := range []string{model.PathWindowHour, model.PathWindowDay, model.PathWindowWeek, model.PathWindowTwoWeeks} {
		for _, cold := range []bool{true, false} {
			name := window + "/cached"
			if cold {
				name = window + "/cold"
			}
			b.Run(name, func(b *testing.B) {
				l := f.startIngest(b)
				started := time.Now()
				for b.Loop() {
					if cold {
						f.srv.monitorPaths.forget()
					}
					if _, err := f.srv.pathMatrixFor(p, window, f.now); err != nil {
						b.Fatal(err)
					}
				}
				l.finish(b, time.Since(started))
			})
		}
	}
	b.Run("series-7d", func(b *testing.B) {
		checks := f.srv.generatedPathChecks(f.nodes[1])
		for b.Loop() {
			if _, err := f.srv.pathSeriesFor(checks, f.nodes[0], model.PathWindowWeek, time.Minute, f.now); err != nil {
				b.Fatal(err)
			}
		}
	})
}
