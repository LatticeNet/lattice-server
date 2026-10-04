package metricsdb

import (
	"fmt"
	"testing"
	"time"
)

func TestPickTierByRange(t *testing.T) {
	db, _, _ := openTest(t, Options{})
	now := t0.Add(400 * 24 * time.Hour)
	cases := []struct {
		span      time.Duration
		maxPoints int
		want      string
	}{
		{time.Hour, 360, "1m"},
		{24 * time.Hour, 360, "1m"},           // 1440 rows read, merged four at a time
		{48 * time.Hour, 360, "1m"},           // 2880 rows, the read budget's edge
		{7 * 24 * time.Hour, 360, "5m"},       // the 1m tier does not reach back a week
		{30 * 24 * time.Hour, 360, "1h"},      // 5m keeps 14 days
		{90 * 24 * time.Hour, 360, "1h"},      // 2160 rows
		{365 * 24 * time.Hour, 360, "1d"},     // 1h keeps 180 days
		{5 * 365 * 24 * time.Hour, 360, "1d"}, // and 1d is the coarsest
		{10 * 365 * 24 * time.Hour, 360, "1d"},
		{24 * time.Hour, 48, "5m"},       // a sparkline: 288 rows for 48 points
		{10 * 24 * time.Hour, 360, "5m"}, // 2880 rows
		{14 * 24 * time.Hour, 360, "1h"}, // 4032 rows is past the budget
	}
	for _, tc := range cases {
		got := db.tiers[db.pickTier(now, now.Add(-tc.span), now, tc.maxPoints)].Name
		if got != tc.want {
			t.Errorf("span %v with %d points: tier %s, want %s", tc.span, tc.maxPoints, got, tc.want)
		}
	}
}

func TestQueryMergesStepsAndReachesTheCurrentMinute(t *testing.T) {
	db, c, _ := openTest(t, Options{})
	// Three hours and seven minutes of minutes for one node.
	total := 3*60 + 7
	for i := 0; i < total; i++ {
		mustWrite(t, db, t0.Add(time.Duration(i)*time.Minute),
			gauge("node/n1", "cpu", float64(i)),
			gauge("node/n1", "mem", 50),
			event("plugin/p", "svc/call", 0, 5*time.Millisecond))
	}
	end := t0.Add(time.Duration(total) * time.Minute)
	c.Set(end)

	// 60 points over three hours: 1m rows merged three at a time.
	res, err := db.Query("node/n1", []string{"cpu"}, end.Add(-3*time.Hour), end, 60)
	if err != nil {
		t.Fatal(err)
	}
	if res.Tier.Name != "1m" || res.Step != 3*time.Minute {
		t.Fatalf("tier %s step %v, want 1m merged to 3m", res.Tier.Name, res.Step)
	}
	pts := res.Series[0].Points
	if len(pts) > 61 {
		t.Fatalf("%d points for 60 asked", len(pts))
	}
	for _, p := range pts[1 : len(pts)-1] {
		if p.Gauge.Count != 3 {
			t.Fatalf("inner bucket %v holds %d samples, want 3", p.At, p.Gauge.Count)
		}
	}

	// Pretend the range is long enough to read the hour tier: the hours that
	// closed come from 1h rows, the open hour from 1m rows, so the newest
	// point is the current hour and counts its seven minutes.
	db.opts.Now = func() time.Time { return end.Add(3 * 24 * time.Hour) }
	far := end.Add(3 * 24 * time.Hour)
	res, err = db.Query("node/n1", []string{"cpu"}, far.Add(-30*24*time.Hour), far, 720)
	if err != nil {
		t.Fatal(err)
	}
	if res.Tier.Name != "1h" || res.Step != time.Hour {
		t.Fatalf("long query tier %s step %v", res.Tier.Name, res.Step)
	}
	pts = res.Series[0].Points
	if len(pts) != 4 {
		t.Fatalf("got %d hourly points, want 4 (three closed hours and the open one)", len(pts))
	}
	if last := pts[3]; !last.At.Equal(t0.Add(3*time.Hour)) || last.Gauge.Count != 7 {
		t.Fatalf("open hour point = %+v, want 7 samples at %v", last, t0.Add(3*time.Hour))
	}
	if pts[0].Gauge.Count != 60 || pts[0].Gauge.Max != 59 {
		t.Fatalf("first hour = %+v", pts[0].Gauge)
	}
	db.opts.Now = c.Now

	// All of an owner's series when no names are given, sorted by name.
	res, err = db.Query("node/n1", nil, end.Add(-time.Hour), end, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Series) != 2 || res.Series[0].Name != "cpu" || res.Series[1].Name != "mem" {
		t.Fatalf("series = %+v", res.Series)
	}
	// Unknown owner and unknown name: no points, no error.
	if res, err := db.Query("node/nope", nil, end.Add(-time.Hour), end, 0); err != nil || len(res.Series) != 0 {
		t.Fatalf("unknown owner = %+v, %v", res, err)
	}
	if res, err := db.Query("node/n1", []string{"nope"}, end.Add(-time.Hour), end, 0); err != nil || len(res.Series) != 0 {
		t.Fatalf("unknown name = %+v, %v", res, err)
	}
}

func TestQueryLeavesGapsAsGaps(t *testing.T) {
	db, c, _ := openTest(t, Options{})
	mustWrite(t, db, t0, gauge("node/n1", "cpu", 1))
	mustWrite(t, db, t0.Add(10*time.Minute), gauge("node/n1", "cpu", 2))
	c.Set(t0.Add(11 * time.Minute))
	res, err := db.Query("node/n1", nil, t0, t0.Add(11*time.Minute), 0)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(res.Series[0].Points); n != 2 {
		t.Fatalf("%d points, want 2: the minutes nothing was heard are absent", n)
	}
}

// fleetBatch is one minute's flush for the production fleet: the control
// plane's process and host, store callers, route groups, plugin methods, and
// seven series for each of 34 nodes.
func fleetBatch(i int) []Sample {
	var out []Sample
	for _, name := range []string{"proc.cpu", "proc.rss", "proc.heap", "proc.goroutines", "proc.gc_pause_max", "proc.fds",
		"host.load1", "host.mem_used", "host.mem_total", "host.disk_used", "host.disk_free",
		"file.state_hot", "file.audit_wal", "file.state_json", "file.metrics_db", "file.logs_db", "file.trace_db",
		"metricsdb.write"} {
		out = append(out, gauge("cp", name, float64(i), float64(i+1), float64(i+2), float64(i+3), float64(i+4), float64(i+5)))
	}
	for c := 0; c < 15; c++ {
		out = append(out, event("cp.store", fmt.Sprintf("Caller%02d", c), 0, 2*time.Millisecond, 3*time.Millisecond))
	}
	for g := 0; g < 30; g++ {
		out = append(out, event("cp.http", fmt.Sprintf("/api/group%02d", g), g%7, 3*time.Millisecond, 8*time.Millisecond, 21*time.Millisecond, 90*time.Millisecond, 250*time.Millisecond))
	}
	for p := 0; p < 4; p++ {
		for m := 0; m < 8; m++ {
			out = append(out, event(fmt.Sprintf("plugin/p%d", p), fmt.Sprintf("svc/method%d", m), 0, 40*time.Millisecond, 120*time.Millisecond))
		}
	}
	for n := 0; n < 34; n++ {
		owner := fmt.Sprintf("node/node_%02d", n)
		for _, name := range []string{"cpu", "mem", "disk", "load1", "net_rx", "net_tx", "beat_gap"} {
			out = append(out, gauge(owner, name, float64(n), float64(n+i%5)))
		}
	}
	return out
}

// TestWritePathCost bounds what one steady-state flush costs for the
// production fleet: one transaction, about one row per owner, and a small
// number of page writes. A layout that put one key per series per minute in
// series order would dirty a page per series, about 370.
func TestWritePathCost(t *testing.T) {
	db, _, _ := openTest(t, Options{})
	for i := 0; i < 30; i++ {
		mustWrite(t, db, t0.Add(time.Duration(i)*time.Minute), fleetBatch(i)...)
	}
	before := db.bolt.Stats()
	res := mustWrite(t, db, t0.Add(31*time.Minute), fleetBatch(31)...)
	after := db.bolt.Stats()
	diff := after.Sub(&before)
	if res.Rows != 1+1+1+4+34 {
		t.Fatalf("rows = %d, want one per owner (41)", res.Rows)
	}
	if res.Points != 18+15+30+32+34*7 {
		t.Fatalf("points = %d", res.Points)
	}
	if w := diff.TxStats.GetWrite(); w > 120 {
		t.Fatalf("one fleet flush wrote %d pages, want at most 120", w)
	}
	t.Logf("fleet flush: %d points in %d rows, %d pages written, %v", res.Points, res.Rows, diff.TxStats.GetWrite(), res.Duration)
}

func BenchmarkFleetFlush(b *testing.B) {
	db, err := Open(b.TempDir()+"/metrics.db", Options{})
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	batches := make([][]Sample, 8)
	for i := range batches {
		batches[i] = fleetBatch(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := db.Write(t0.Add(time.Duration(i)*time.Minute), batches[i%len(batches)]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkQueryNodeWeek(b *testing.B) {
	c := &clock{t: t0}
	db, err := Open(b.TempDir()+"/metrics.db", Options{Now: c.Now})
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	minutes := 3 * 24 * 60
	for i := 0; i < minutes; i++ {
		if _, err := db.Write(t0.Add(time.Duration(i)*time.Minute), fleetBatch(i)[95:102]); err != nil {
			b.Fatal(err)
		}
	}
	end := t0.Add(time.Duration(minutes) * time.Minute)
	c.Set(end)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := db.Query("node/node_00", nil, end.Add(-7*24*time.Hour), end, 360); err != nil {
			b.Fatal(err)
		}
	}
}
