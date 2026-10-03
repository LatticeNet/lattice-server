package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// The rollups report p50, p95 and loss per window and keep a gap unknown;
// the series has every bucket, empty ones included.
func TestLatencyRollupsAndSeries(t *testing.T) {
	dir := t.TempDir()
	st, err := store.OpenWithCipher(filepath.Join(dir, "state.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnableRuntimeBoltHotStore(filepath.Join(dir, "state-hot.db")); err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close(context.Background())
	for _, n := range []model.Node{
		{ID: "node-sh", Name: "cd-hs-sh", Geo: &model.NodeGeo{Country: "CN"}},
		{ID: "node-jp", Name: "jp", Geo: &model.NodeGeo{Country: "JP"}},
		{ID: "node-sg", Name: "sg", Geo: &model.NodeGeo{Country: "SG"}},
	} {
		if err := st.UpsertNode(n); err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range []string{"node-jp", "node-sg"} {
		if err := st.UpsertMonitor(model.Monitor{ID: latencyMonitorID(target), Name: "Latency to " + target, Type: model.MonitorTypeTCP, Target: "203.0.113.9:443", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-sh"}, Enabled: true, ManagedBy: model.MonitorManagedLatency}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	// jp: the last 30 minutes only, one probe a minute, every fifth failing,
	// latencies 50 to 59 ms. sg: nothing at all.
	var batch []model.MonitorResult
	for i := 30; i >= 1; i-- {
		batch = append(batch, model.MonitorResult{MonitorID: latencyMonitorID("node-jp"), At: now.Add(-time.Duration(i) * time.Minute), Success: i%5 != 0, LatencyMs: float64(50 + i%10)})
	}
	if _, err := st.IngestAgentMonitorResults("node-sh", batch, now); err != nil {
		t.Fatal(err)
	}
	plan := srv.planLatencyProbes(now).plan
	rollups, err := srv.latencyRollupsFor(plan, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rollups.Pairs) != 2 {
		t.Fatalf("pairs = %+v", rollups.Pairs)
	}
	byTarget := map[string]model.LatencyPairRollup{}
	for _, p := range rollups.Pairs {
		byTarget[p.Target] = p
	}
	hour := byTarget["node-jp"].Windows[model.LatencyWindowHour]
	if hour.Samples != 30 || hour.Failures != 6 || hour.Expected != 60 || hour.Loss == nil || *hour.Loss != 0.2 {
		t.Fatalf("jp 1h = %+v", hour)
	}
	if hour.P50Ms == nil || *hour.P50Ms < 52 || *hour.P50Ms > 56 || hour.P95Ms == nil || *hour.P95Ms < 57 || *hour.P95Ms > 59.5 {
		t.Fatalf("jp 1h percentiles = %v %v", deref(hour.P50Ms), deref(hour.P95Ms))
	}
	day := byTarget["node-jp"].Windows[model.LatencyWindowDay]
	week := byTarget["node-jp"].Windows[model.LatencyWindowWeek]
	if day.Samples != 30 || day.Expected < 1440 || week.Samples != 30 || week.Expected < 7*1440 {
		t.Fatalf("jp 24h = %+v, 7d = %+v", day, week)
	}
	if byTarget["node-jp"].Latest == nil {
		t.Fatal("no latest result")
	}
	sg := byTarget["node-sg"].Windows[model.LatencyWindowHour]
	if sg.Samples != 0 || sg.P50Ms != nil || sg.Loss != nil || sg.Expected != 60 {
		t.Fatalf("a pair never heard is not unknown: %+v", sg)
	}

	series, err := srv.latencySeriesFor(latencyMonitorID("node-jp"), "node-sh", "node-jp", model.LatencyWindowHour, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if series.BucketSec != 60 || len(series.Buckets) < 60 || len(series.Buckets) > 62 {
		t.Fatalf("1h series has %d buckets of %d s", len(series.Buckets), series.BucketSec)
	}
	empty, full := 0, 0
	for _, b := range series.Buckets {
		if b.Samples == 0 {
			if b.P50Ms != nil || b.Loss != nil {
				t.Fatalf("an empty bucket carries values: %+v", b)
			}
			empty++
		} else {
			full++
		}
	}
	if full != 30 || empty < 30 {
		t.Fatalf("series: %d full, %d empty", full, empty)
	}
	if _, err := srv.latencySeriesFor(latencyMonitorID("node-jp"), "node-sh", "node-jp", "30d", time.Minute, now); err == nil {
		t.Fatal("an unknown window was accepted")
	}
	daySeries, err := srv.latencySeriesFor(latencyMonitorID("node-jp"), "node-sh", "node-jp", model.LatencyWindowDay, time.Minute, now)
	if err != nil || daySeries.BucketSec != 300 || len(daySeries.Buckets) < 288 {
		t.Fatalf("24h series = %d buckets of %d s, %v", len(daySeries.Buckets), daySeries.BucketSec, err)
	}
}

// The rollup and series reads answer only for pairs whose nodes the caller
// may read.
func TestLatencyReadsAreNodeScoped(t *testing.T) {
	srv, handler, _ := latencyFleet(t)
	cookies, csrf := loginSession(t, handler)
	if _, _, err := srv.syncLatencyProbes(time.Now()); err != nil {
		t.Fatal(err)
	}
	confined := createPAT(t, handler, cookies, csrf, []string{"monitor:read"}, []string{"node-sh", "node-jp"})
	res := doBearerJSON(t, handler, http.MethodGet, "/api/monitors/latency/rollups", "", confined)
	defer res.Body.Close()
	var rollups model.LatencyRollups
	if err := json.NewDecoder(res.Body).Decode(&rollups); err != nil {
		t.Fatal(err)
	}
	if len(rollups.Pairs) != 1 || rollups.Pairs[0].Target != "node-jp" {
		t.Fatalf("confined rollups = %+v", rollups.Pairs)
	}
	if res := doBearerJSON(t, handler, http.MethodGet, "/api/monitors/latency/series?source=node-sh&target=node-us", "", confined); res.StatusCode != http.StatusForbidden {
		t.Fatalf("confined series of another node = %d", res.StatusCode)
	}
	if res := doBearerJSON(t, handler, http.MethodGet, "/api/monitors/latency/series?source=node-sh&target=node-jp&window=1h", "", confined); res.StatusCode != http.StatusOK {
		t.Fatalf("confined series of its own pair = %d", res.StatusCode)
	}
	// The generic monitor routes narrow generated monitors the same way: a
	// token confined to the source does not learn the address of a target
	// it cannot read.
	list := doBearerJSON(t, handler, http.MethodGet, "/api/monitors", "", confined)
	defer list.Body.Close()
	var monitors []monitorView
	if err := json.NewDecoder(list.Body).Decode(&monitors); err != nil {
		t.Fatal(err)
	}
	if len(monitors) != 1 || monitors[0].ID != latencyMonitorID("node-jp") {
		t.Fatalf("confined monitor list = %+v", monitors)
	}
	if res := doBearerJSON(t, handler, http.MethodGet, "/api/monitors/results?monitor_id="+latencyMonitorID("node-us"), "", confined); res.StatusCode != http.StatusForbidden {
		t.Fatalf("confined results of another node's probe = %d", res.StatusCode)
	}
	sourceOnly := createPAT(t, handler, cookies, csrf, []string{"monitor:read"}, []string{"node-sh"})
	list = doBearerJSON(t, handler, http.MethodGet, "/api/monitors", "", sourceOnly)
	defer list.Body.Close()
	monitors = nil
	if err := json.NewDecoder(list.Body).Decode(&monitors); err != nil {
		t.Fatal(err)
	}
	if len(monitors) != 0 {
		t.Fatalf("a source-only token sees target monitors: %+v", monitors)
	}
	full := doJSON(t, handler, http.MethodGet, "/api/monitors/latency/series?source=node-sh&target=node-hk", "", cookies, "")
	full.Body.Close()
	if full.StatusCode != http.StatusNotFound {
		t.Fatalf("series of a target nothing probes = %d", full.StatusCode)
	}
}

func deref(v *float64) string {
	if v == nil {
		return "nil"
	}
	return fmt.Sprintf("%.1f", *v)
}
