package metricsdb

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// realisticFleetBatch is fleetBatch with latencies spread the way they are in
// production (log-normal, a few failures), so the histograms carry as many
// non-empty bins as real ones do.
func realisticFleetBatch(rng *rand.Rand) []Sample {
	lat := func(median time.Duration, n int) []time.Duration {
		out := make([]time.Duration, n)
		for i := range out {
			out[i] = time.Duration(float64(median) * math.Exp(rng.NormFloat64()*0.9))
		}
		return out
	}
	var out []Sample
	for _, name := range []string{"proc.cpu", "proc.rss", "proc.heap", "proc.goroutines", "proc.gc_pause_max", "proc.fds",
		"host.load1", "host.mem_used", "host.mem_total", "host.disk_used", "host.disk_free",
		"file.state_hot", "file.audit_wal", "file.state_json", "file.metrics_db", "file.logs_db", "file.trace_db",
		"metricsdb.write"} {
		var vals []float64
		for i := 0; i < 6; i++ {
			vals = append(vals, rng.Float64()*1e9)
		}
		out = append(out, gauge("cp", name, vals...))
	}
	for c := 0; c < 15; c++ {
		if rng.Intn(3) == 0 {
			out = append(out, event("cp.store", fmt.Sprintf("Caller%02d", c), 0, lat(4*time.Millisecond, 1+rng.Intn(3))...))
		}
	}
	for g := 0; g < 60; g++ {
		if g < 25 || rng.Intn(4) == 0 {
			out = append(out, event("cp.http", fmt.Sprintf("/api/group%02d", g), rng.Intn(2), lat(15*time.Millisecond, 1+rng.Intn(40))...))
		}
	}
	for p := 0; p < 4; p++ {
		for m := 0; m < 8; m++ {
			if rng.Intn(3) == 0 {
				out = append(out, event(fmt.Sprintf("plugin/p%d", p), fmt.Sprintf("svc/method%d", m), 0, lat(80*time.Millisecond, 1+rng.Intn(5))...))
			}
		}
	}
	for n := 0; n < 34; n++ {
		owner := fmt.Sprintf("node/node_%02d", n)
		for _, name := range []string{"cpu", "mem", "disk", "load1", "net_rx", "net_tx", "beat_gap"} {
			out = append(out, gauge(owner, name, rng.Float64()*100, rng.Float64()*100, rng.Float64()*100, rng.Float64()*100))
		}
	}
	return out
}

// TestMeasureFleetFootprint writes METRICSDB_MEASURE_MINUTES minutes (2880
// fills the 1-minute tier) of a production-shaped fleet through the real
// write path and projects the steady-state file from what each tier's rows
// actually cost. It is a measurement, not a check, so it runs only on
// request:
//
//	METRICSDB_MEASURE_MINUTES=2880 go test -run TestMeasureFleetFootprint -v ./internal/metricsdb
func TestMeasureFleetFootprint(t *testing.T) {
	minutes, _ := strconv.Atoi(os.Getenv("METRICSDB_MEASURE_MINUTES"))
	if minutes <= 0 {
		t.Skip("set METRICSDB_MEASURE_MINUTES to measure")
	}
	c := &clock{t: t0}
	path := t.TempDir() + "/metrics.db"
	db, err := Open(path, Options{Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.bolt.NoSync = true
	rng := rand.New(rand.NewSource(1))
	var heapBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&heapBefore)
	var slowest time.Duration
	var total time.Duration
	for i := 0; i < minutes; i++ {
		res, err := db.Write(t0.Add(time.Duration(i)*time.Minute), realisticFleetBatch(rng))
		if err != nil {
			t.Fatal(err)
		}
		total += res.Duration
		slowest = max(slowest, res.Duration)
	}
	var heapAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&heapAfter)
	st, err := db.Stats()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d minutes: file %.1f MB, %d series in %d owners, write avg %v max %v (no fsync), live heap %+.1f MB",
		minutes, float64(st.SizeBytes)/1e6, st.Series, st.Owners, total/time.Duration(minutes), slowest,
		float64(int64(heapAfter.HeapAlloc)-int64(heapBefore.HeapAlloc))/1e6)
	var projected float64
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		for _, tier := range db.tiers {
			b := tx.Bucket([]byte(tierPrefix + tier.Name))
			bs := b.Stats()
			var rows, valueBytes int
			_ = b.ForEach(func(_, v []byte) error {
				rows++
				valueBytes += len(v)
				return nil
			})
			if rows == 0 {
				t.Logf("tier %s: no rows yet", tier.Name)
				continue
			}
			fill := 1.0
			if bs.LeafAlloc > 0 {
				fill = float64(bs.LeafInuse) / float64(bs.LeafAlloc)
			}
			perRow := float64(valueBytes)/float64(rows) + 12 + 16
			full := float64(st.Owners*tier.Slots()) * perRow / fill
			projected += full
			t.Logf("tier %s: %d rows, %.0f B a row on the page, leaf fill %.0f%%, at retention %.1f MB",
				tier.Name, rows, perRow, fill*100, full/1e6)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Logf("projected steady state for this fleet: %.1f MB of leaf pages", projected/1e6)
}
