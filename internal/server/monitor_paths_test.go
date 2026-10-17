package server

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// newPathsServer is a server on a hot store, which holds the rollups, with
// the defaults a test reads paths through.
func newPathsServer(t testing.TB) (*Server, http.Handler, *store.Store) {
	t.Helper()
	return newPathsServerAt(t, t.TempDir())
}

// newPathsServerAt is newPathsServer on the state in dir, so a test can stop
// a server and start another on what the first one wrote.
func newPathsServerAt(t testing.TB, dir string) (*Server, http.Handler, *store.Store) {
	t.Helper()
	st, err := store.OpenWithCipher(filepath.Join(dir, "state.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnableRuntimeBoltHotStore(filepath.Join(dir, "state-hot.db")); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		srv.Close(context.Background())
		st.Close()
	})
	return srv, srv.Handler(), st
}

func upsertNodes(t testing.TB, st *store.Store, nodes ...model.Node) {
	t.Helper()
	for _, n := range nodes {
		if err := st.UpsertNode(n); err != nil {
			t.Fatal(err)
		}
	}
}

// The step rule: the finest tier covering the window, then the smallest
// multiple of its resolution within 720 points and no shorter than the
// interval.
func TestPathSeriesStepRule(t *testing.T) {
	day := 24 * time.Hour
	for _, tc := range []struct {
		span     time.Duration
		fineDays int
		interval time.Duration
		tier     pathTier
		step     time.Duration
	}{
		{time.Hour, 7, time.Minute, pathTierRaw, time.Minute},
		{time.Hour, 7, 30 * time.Second, pathTierRaw, time.Minute},
		{time.Hour, 7, 5 * time.Minute, pathTierRaw, 5 * time.Minute},
		{6 * time.Hour, 7, time.Minute, pathTierFine, 5 * time.Minute},
		{day, 7, time.Minute, pathTierFine, 5 * time.Minute},
		{3 * day, 7, time.Minute, pathTierFine, 10 * time.Minute},
		{3 * day, 3, time.Minute, pathTierFine, 10 * time.Minute},
		{7 * day, 7, time.Minute, pathTierFine, 15 * time.Minute},
		{7 * day, 3, time.Minute, pathTierCoarse, time.Hour},
		{14 * day, 14, time.Minute, pathTierFine, 30 * time.Minute},
		{14 * day, 7, time.Minute, pathTierCoarse, time.Hour},
		{day, 7, time.Hour, pathTierFine, time.Hour},
		{day, 7, 7 * time.Minute, pathTierFine, 10 * time.Minute},
	} {
		tier, step := pathSeriesStep(tc.span, tc.fineDays, tc.interval)
		if tier != tc.tier || step != tc.step {
			t.Errorf("span %s, fine %d d, interval %s: tier %d step %s, want tier %d step %s", tc.span, tc.fineDays, tc.interval, tier, step, tc.tier, tc.step)
		}
	}
}

// Every window stays within 720 points wherever now falls in a step, at
// both fine retentions that change the 14 d tier.
func TestPathSeriesNeverExceeds720Points(t *testing.T) {
	srv, _, st := newPathsServer(t)
	upsertNodes(t, st, model.Node{ID: "node-a", Name: "a"})
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-a", Name: "a", Type: model.MonitorTypeTCP, Target: "203.0.113.9:443", IntervalSec: 10, TimeoutSec: 5, NodeIDs: []string{"node-a"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	checks := []pathCheck{{monitorID: "mon-a", method: model.MonitorTypeTCP}}
	for _, fine := range []int{7, 14} {
		if fine == 14 {
			if _, err := st.SetMonitorSettings(model.MonitorSettings{FineRetentionDays: 14}, 0, "admin", time.Now()); err != nil {
				t.Fatal(err)
			}
		}
		for _, w := range pathWindows {
			for _, offset := range []time.Duration{0, time.Second, 7*time.Minute + 59*time.Second, 29*time.Minute + 59*time.Second} {
				now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC).Add(offset)
				series, err := srv.pathSeriesFor(checks, "node-a", w.name, 10*time.Second, now)
				if err != nil {
					t.Fatal(err)
				}
				if n := len(series.Buckets); n > pathSeriesMaxPoints || n < 2 {
					t.Fatalf("fine %d, %s at +%s: %d buckets of %d s", fine, w.name, offset, n, series.StepSeconds)
				}
				last := series.Buckets[len(series.Buckets)-1]
				if last.T.After(now) || now.Sub(last.T) >= time.Duration(series.StepSeconds)*time.Second {
					t.Fatalf("%s: last bucket %s does not hold now %s", w.name, last.T, now)
				}
			}
		}
	}
}

// A generated path joins every generated check for its pair by time, marks
// where the method changed, and shows a gap as a bucket with no runs where
// runs were expected.
func TestPathSeriesJoinsChecksAndShowsGaps(t *testing.T) {
	srv, _, st := newPathsServer(t)
	upsertNodes(t, st, model.Node{ID: "node-sh", Name: "sh"}, model.Node{ID: "node-jp", Name: "jp"})
	for _, id := range []string{"mon_lat_node-jp", "mon_lati_node-jp"} {
		if err := st.UpsertMonitor(model.Monitor{ID: id, Name: id, Type: model.MonitorTypeTCP, Target: "203.0.113.3:443", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-sh"}, Enabled: true, ManagedBy: model.MonitorManagedLatency}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	start := now.Add(-5 * time.Hour).Truncate(time.Hour)
	var tcp, icmp []model.MonitorResult
	// tcp for an hour, nothing for an hour, icmp for an hour.
	for i := 0; i < 60; i++ {
		tcp = append(tcp, model.MonitorResult{MonitorID: "mon_lat_node-jp", At: start.Add(time.Duration(i) * time.Minute), Success: true, LatencyMs: float64(40 + i%3)})
		icmp = append(icmp, model.MonitorResult{MonitorID: "mon_lati_node-jp", At: start.Add(2*time.Hour + time.Duration(i)*time.Minute), Success: i%10 != 0, LatencyMs: 35})
	}
	if _, err := st.IngestAgentMonitorResults("node-sh", append(tcp, icmp...), now); err != nil {
		t.Fatal(err)
	}
	checks := []pathCheck{{"mon_lat_node-jp", model.MonitorTypeTCP}, {"mon_lati_node-jp", model.MonitorTypeICMP}}
	series, err := srv.pathSeriesFor(checks, "node-sh", model.PathWindowSixHours, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	// Six hours of five-minute steps is 72 of them, the last in progress.
	if series.StepSeconds != 300 || !series.From.Equal(now.Truncate(5*time.Minute).Add(-6*time.Hour+5*time.Minute)) || len(series.Buckets) != 72 {
		t.Fatalf("6h series: step %d from %s, %d buckets", series.StepSeconds, series.From, len(series.Buckets))
	}
	if len(series.MethodChanges) != 2 || series.MethodChanges[0].Method != "tcp" || !series.MethodChanges[0].T.Equal(start) ||
		series.MethodChanges[1].Method != "icmp" || !series.MethodChanges[1].T.Equal(start.Add(2*time.Hour)) {
		t.Fatalf("method changes = %+v", series.MethodChanges)
	}
	byT := map[time.Time]model.PathBucket{}
	for _, b := range series.Buckets {
		byT[b.T] = b
	}
	gap := byT[start.Add(90*time.Minute)]
	if gap.N != 0 || gap.Expected != 5 || gap.P50Ms != nil || gap.Loss != nil || gap.MinMs != nil || gap.JitterMs != nil {
		t.Fatalf("gap bucket = %+v", gap)
	}
	tcpBucket := byT[start.Add(30*time.Minute)]
	if tcpBucket.N != 5 || tcpBucket.Fail != 0 || tcpBucket.MinMs == nil || *tcpBucket.MinMs != 40 || tcpBucket.MaxMs == nil || *tcpBucket.MaxMs != 42 ||
		tcpBucket.JitterMs == nil || *tcpBucket.Loss != 0 {
		t.Fatalf("tcp bucket = %+v", tcpBucket)
	}
	icmpBucket := byT[start.Add(2*time.Hour)]
	if icmpBucket.N != 5 || icmpBucket.Fail != 1 || icmpBucket.Loss == nil || *icmpBucket.Loss != 0.2 {
		t.Fatalf("icmp bucket = %+v", icmpBucket)
	}
	// The raw tier answers the hour with one-minute steps.
	hour, err := srv.pathSeriesFor(checks, "node-sh", model.PathWindowHour, time.Minute, start.Add(2*time.Hour+30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	full := 0
	for _, b := range hour.Buckets {
		if b.N > 0 {
			full++
		}
	}
	if hour.StepSeconds != 60 || full != 31 || len(hour.MethodChanges) != 1 || hour.MethodChanges[0].Method != "icmp" {
		t.Fatalf("1h series: step %d, %d buckets with runs, changes %+v", hour.StepSeconds, full, hour.MethodChanges)
	}
}

// The series route addresses a generated path by its nodes and an operator
// check by its id, and answers only for paths whose nodes the caller reads.
func TestPathSeriesRoute(t *testing.T) {
	srv, handler, st := latencyFleet(t)
	cookies, csrf := loginSession(t, handler)
	if _, _, err := srv.syncLatencyProbes(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-op", Name: "op", Type: model.MonitorTypeTCP, Target: "198.51.100.20:22", IntervalSec: 30, TimeoutSec: 5, NodeIDs: []string{"node-sh", "node-us"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-tls", Name: "cert", Type: model.MonitorTypeTLS, Target: "example.com:443", IntervalSec: 3600, TimeoutSec: 10, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// Its address is node-hk's, so a caller who cannot read node-hk does
	// not read its path, in the series as in the matrix.
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-hk", Name: "hk ssh", Type: model.MonitorTypeTCP, Target: "203.0.113.4:22", IntervalSec: 30, TimeoutSec: 5, NodeIDs: []string{"node-sh"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	get := func(path string) (*http.Response, model.PathSeries) {
		res := doJSON(t, handler, http.MethodGet, path, "", cookies, csrf)
		defer res.Body.Close()
		var out model.PathSeries
		if res.StatusCode == http.StatusOK {
			if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
				t.Fatal(err)
			}
		}
		return res, out
	}
	if res, s := get("/api/monitors/series?source=node-sh&target_node=node-jp&window=7d"); res.StatusCode != http.StatusOK || s.StepSeconds != 900 || s.Window != "7d" {
		t.Fatalf("generated path = %d %+v", res.StatusCode, s.StepSeconds)
	}
	if res, s := get("/api/monitors/series?source=node-sh&target_node=node-jp"); res.StatusCode != http.StatusOK || s.Window != "24h" || s.StepSeconds != 300 {
		t.Fatalf("default window = %d %s %d", res.StatusCode, s.Window, s.StepSeconds)
	}
	if res, s := get("/api/monitors/series?monitor=mon-op&source=node-us&window=1h"); res.StatusCode != http.StatusOK || s.StepSeconds != 60 || len(s.Buckets) < 60 {
		t.Fatalf("operator path = %d %+v", res.StatusCode, s)
	}
	if res, _ := get("/api/monitors/series?monitor=mon-tls&window=14d"); res.StatusCode != http.StatusOK {
		t.Fatalf("tls path = %d", res.StatusCode)
	}
	for path, want := range map[string]int{
		"/api/monitors/series?monitor=mon-tls&source=node-sh":                http.StatusBadRequest,
		"/api/monitors/series?monitor=mon-op":                                http.StatusBadRequest,
		"/api/monitors/series?source=node-sh&target_node=node-jp&w=1":        http.StatusOK,
		"/api/monitors/series?source=node-sh&target_node=node-jp&window=30d": http.StatusBadRequest,
		"/api/monitors/series?source=node-sh":                                http.StatusBadRequest,
		"/api/monitors/series?source=node-sh&target_node=node-bj":            http.StatusNotFound,
		"/api/monitors/series?monitor=mon-missing&source=node-sh":            http.StatusNotFound,
	} {
		if res, _ := get(path); res.StatusCode != want {
			t.Errorf("%s = %d, want %d", path, res.StatusCode, want)
		}
	}
	confined := createPAT(t, handler, cookies, csrf, []string{"monitor:read"}, []string{"node-sh", "node-jp"})
	for path, want := range map[string]int{
		"/api/monitors/series?source=node-sh&target_node=node-jp": http.StatusOK,
		"/api/monitors/series?source=node-sh&target_node=node-us": http.StatusForbidden,
		"/api/monitors/series?monitor=mon-op&source=node-sh":      http.StatusOK,
		"/api/monitors/series?monitor=mon-op&source=node-us":      http.StatusForbidden,
		"/api/monitors/series?monitor=mon-tls":                    http.StatusForbidden,
		"/api/monitors/series?monitor=mon-hk&source=node-sh":      http.StatusForbidden,
	} {
		res := doBearerJSON(t, handler, http.MethodGet, path, "", confined)
		res.Body.Close()
		if res.StatusCode != want {
			t.Errorf("confined %s = %d, want %d", path, res.StatusCode, want)
		}
	}
}

func pathCellFor(t *testing.T, m model.PathMatrix, source, monitorID string) model.PathCell {
	t.Helper()
	for _, c := range m.Paths {
		if c.Source == source && c.MonitorID == monitorID {
			return c
		}
	}
	t.Fatalf("no path %s from %q in %+v", monitorID, source, m.Paths)
	return model.PathCell{}
}

func pathCellTo(t *testing.T, m model.PathMatrix, source, targetNode string) model.PathCell {
	t.Helper()
	for _, c := range m.Paths {
		if c.Source == source && c.TargetNode == targetNode && c.Managed {
			return c
		}
	}
	t.Fatalf("no generated path %s to %s in %+v", source, targetNode, m.Paths)
	return model.PathCell{}
}

// The matrix judges every path now and reads its window figures: up and down
// from the latest record, unknown with the reason the data allows (agent
// offline, source paused, not probeable, no data), the previous window's
// figures, and nothing drawn for what was not measured.
func TestPathMatrixGapsAndUnknownReasons(t *testing.T) {
	srv, _, st := newPathsServer(t)
	now := time.Now().UTC()
	srv.now = func() time.Time { return now }
	upsertNodes(t, st,
		model.Node{ID: "node-sh", Name: "sh", Online: true, Geo: &model.NodeGeo{Country: "CN"}},
		model.Node{ID: "node-off", Name: "off", Online: false, Geo: &model.NodeGeo{Country: "CN"}},
		model.Node{ID: "node-jp", Name: "jp", Online: true, PublicIP: "203.0.113.3", Geo: &model.NodeGeo{Country: "JP"}},
		model.Node{ID: "node-sg", Name: "sg", Online: true, PublicIP: "203.0.113.4", Geo: &model.NodeGeo{Country: "SG"}},
		model.Node{ID: "node-kr", Name: "kr", Online: true, Geo: &model.NodeGeo{Country: "KR"}},
	)
	cfg := model.LatencyProbeConfig{Enabled: true, IntervalSec: 60, TimeoutSec: 5, Sources: []string{"node-off", "node-sh"}, AutoTargets: true,
		DisabledPairs: []model.LatencyPair{{Source: "node-sh", Target: "node-sg"}}}
	if _, err := st.SetLatencyProbeConfig(cfg, 0, "admin", now); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"node-jp", "node-sg"} {
		if err := st.UpsertMonitor(model.Monitor{ID: latencyMonitorID(target), Name: "Latency to " + target, Type: model.MonitorTypeTCP, Target: "203.0.113.9:443", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-off", "node-sh"}, Enabled: true, ManagedBy: model.MonitorManagedLatency}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := srv.syncLatencyProbes(now); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-op", Name: "ssh", Type: model.MonitorTypeTCP, Target: "203.0.113.4:22", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-jp", "node-sh"}, PausedNodeIDs: []string{"node-jp"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// sh to jp: the window before failed a fifth of the time, this one is
	// clean, and the last two runs failed. Nothing ever came from sh to the
	// operator check.
	var batch []model.MonitorResult
	for i := 120; i >= 1; i-- {
		at := now.Add(-time.Duration(i) * time.Minute)
		ok := !(i > 60 && i%5 == 0) && i > 2
		batch = append(batch, model.MonitorResult{MonitorID: latencyMonitorID("node-jp"), At: at, Success: ok, LatencyMs: float64(50 + i%4)})
	}
	if _, err := st.IngestAgentMonitorResults("node-sh", batch, now); err != nil {
		t.Fatal(err)
	}
	m, err := srv.pathMatrixFor(principal{Principal: adminPrincipalForTest()}, model.PathWindowHour, now)
	if err != nil {
		t.Fatal(err)
	}
	jp := pathCellTo(t, m, "node-sh", "node-jp")
	if jp.State != model.PathStateDown || jp.Reason != "" || jp.Method != "tcp" || jp.MonitorID != latencyMonitorID("node-jp") {
		t.Fatalf("sh to jp = %+v", jp)
	}
	if jp.Samples != 60 || jp.Expected != 60 || jp.Loss == nil || *jp.Loss != 0.0333 || jp.P50Ms == nil || jp.JitterMs == nil || jp.LastAt == nil {
		t.Fatalf("sh to jp figures = %+v", jp)
	}
	if jp.Prev == nil || jp.Prev.Loss == nil || *jp.Prev.Loss != 0.2 || jp.Prev.P50Ms == nil {
		t.Fatalf("sh to jp previous window = %+v", jp.Prev)
	}
	if off := pathCellTo(t, m, "node-off", "node-jp"); off.State != model.PathStateUnknown || off.Reason != model.PathReasonAgentOffline || off.Samples != 0 || off.Expected != 60 || off.Prev != nil || off.LastAt != nil || off.P50Ms != nil {
		t.Fatalf("offline source = %+v", off)
	}
	if sg := pathCellTo(t, m, "node-sh", "node-sg"); sg.State != model.PathStateUnknown || sg.Reason != model.PathReasonSourcePaused {
		t.Fatalf("disabled pair = %+v", sg)
	}
	if kr := pathCellTo(t, m, "node-sh", "node-kr"); kr.State != model.PathStateUnknown || kr.Reason != model.PathReasonNotProbeable || kr.MonitorID != "" || kr.Expected != 0 {
		t.Fatalf("not probeable target = %+v", kr)
	}
	if p := pathCellFor(t, m, "node-jp", "mon-op"); p.State != model.PathStateUnknown || p.Reason != model.PathReasonSourcePaused || p.Managed {
		t.Fatalf("paused operator source = %+v", p)
	}
	op := pathCellFor(t, m, "node-sh", "mon-op")
	if op.State != model.PathStateUnknown || op.Reason != model.PathReasonNoData || op.TargetNode != "node-sg" || op.Target != "203.0.113.4:22" || op.Method != "tcp" {
		t.Fatalf("silent operator path = %+v (its address resolves to node-sg)", op)
	}
	if len(m.Sources) != 3 || len(m.Targets) != 3 {
		t.Fatalf("sources %+v targets %+v", m.Sources, m.Targets)
	}
	for _, target := range m.Targets {
		if target.NodeID == "node-jp" && (target.Country != "JP" || target.Region != model.LatencyRegionOutside || target.Name != "jp") {
			t.Fatalf("target = %+v", target)
		}
	}
	// A stale latest record reads as no data once three intervals pass.
	later := now.Add(4 * time.Minute)
	srv.now = func() time.Time { return later }
	m, err = srv.pathMatrixFor(principal{Principal: adminPrincipalForTest()}, model.PathWindowDay, later)
	if err != nil {
		t.Fatal(err)
	}
	if jp := pathCellTo(t, m, "node-sh", "node-jp"); jp.State != model.PathStateUnknown || jp.Reason != model.PathReasonNoData || jp.Samples != 120 {
		t.Fatalf("stale path = %+v", jp)
	}
}

// A path is in the matrix only for a caller who reads both of its nodes, and
// an operator check only for one who reads the check.
func TestPathMatrixScope(t *testing.T) {
	srv, handler, st := latencyFleet(t)
	cookies, csrf := loginSession(t, handler)
	if _, _, err := srv.syncLatencyProbes(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-op", Name: "op", Type: model.MonitorTypeTCP, Target: "203.0.113.4:22", IntervalSec: 30, TimeoutSec: 5, NodeIDs: []string{"node-sh", "node-us"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-tls", Name: "cert", Type: model.MonitorTypeTLS, Target: "example.com:443", IntervalSec: 3600, TimeoutSec: 10, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	read := func(res *http.Response) model.PathMatrix {
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("matrix = %d", res.StatusCode)
		}
		var m model.PathMatrix
		if err := json.NewDecoder(res.Body).Decode(&m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	full := read(doJSON(t, handler, http.MethodGet, "/api/monitors/paths?window=7d", "", cookies, csrf))
	if full.Window != "7d" || len(full.Paths) == 0 {
		t.Fatalf("full matrix = %+v", full)
	}
	sawTLS := false
	for _, c := range full.Paths {
		if c.MonitorID == "mon-tls" && c.Source == "" {
			sawTLS = true
		}
	}
	if !sawTLS {
		t.Fatalf("the full matrix lacks the tls path: %+v", full.Paths)
	}
	confined := createPAT(t, handler, cookies, csrf, []string{"monitor:read"}, []string{"node-sh", "node-jp"})
	m := read(doBearerJSON(t, handler, http.MethodGet, "/api/monitors/paths", "", confined))
	for _, c := range m.Paths {
		visible := func(id string) bool { return id == "node-sh" || id == "node-jp" }
		if !visible(c.Source) || (c.TargetNode != "" && !visible(c.TargetNode)) {
			t.Fatalf("confined token sees %+v", c)
		}
	}
	var managed, operator int
	for _, c := range m.Paths {
		if c.Managed {
			managed++
		} else if c.MonitorID == "mon-op" {
			operator++
		}
	}
	// sh to jp only; mon-op dials node-hk's address, which this token
	// cannot read, so neither of its paths shows.
	if managed != 1 || operator != 0 {
		t.Fatalf("confined matrix = %+v", m.Paths)
	}
	for _, s := range m.Sources {
		if s.NodeID != "node-sh" {
			t.Fatalf("confined sources = %+v", m.Sources)
		}
	}
	if res := doJSON(t, handler, http.MethodGet, "/api/monitors/paths?window=2d", "", cookies, csrf); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown window = %d", res.StatusCode)
	}
}

// Each window's figures hold until its next bucket closes, and a path that
// appears meanwhile is read at once, over the same window, without
// rereading the others. The window is the whole buckets before the one in
// progress, so the runs here land in the bucket before base's, a late one
// after the first read included.
func TestPathMatrixCachesUntilTheBucketCloses(t *testing.T) {
	srv, _, st := newPathsServer(t)
	upsertNodes(t, st, model.Node{ID: "node-a", Name: "a", Online: true})
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-a", Name: "a", Type: model.MonitorTypeTCP, Target: "203.0.113.9:443", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-a"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(5 * time.Minute).Add(time.Minute)
	p := principal{Principal: adminPrincipalForTest()}
	ingest := func(at time.Time) {
		if _, err := st.IngestAgentMonitorResults("node-a", []model.MonitorResult{{MonitorID: "mon-a", At: at, Success: true, LatencyMs: 10}}, at); err != nil {
			t.Fatal(err)
		}
	}
	ingest(base.Add(-5 * time.Minute))
	first, err := srv.pathMatrixFor(p, model.PathWindowDay, base)
	if err != nil {
		t.Fatal(err)
	}
	ingest(base.Add(-4*time.Minute - 30*time.Second))
	cached, _ := srv.pathMatrixFor(p, model.PathWindowDay, base.Add(time.Minute))
	if a, b := pathCellFor(t, first, "node-a", "mon-a"), pathCellFor(t, cached, "node-a", "mon-a"); a.Samples != 1 || b.Samples != 1 {
		t.Fatalf("within the bucket the figures hold: %d then %d", a.Samples, b.Samples)
	}
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-b", Name: "b", Type: model.MonitorTypeTCP, Target: "203.0.113.9:80", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-a"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.IngestAgentMonitorResults("node-a", []model.MonitorResult{{MonitorID: "mon-b", At: base.Add(-3 * time.Minute), Success: true, LatencyMs: 12}}, base.Add(40*time.Second)); err != nil {
		t.Fatal(err)
	}
	withNew, _ := srv.pathMatrixFor(p, model.PathWindowDay, base.Add(2*time.Minute))
	if a, b := pathCellFor(t, withNew, "node-a", "mon-a"), pathCellFor(t, withNew, "node-a", "mon-b"); a.Samples != 1 || b.Samples != 1 {
		t.Fatalf("a new path is read at once and the others stay cached: a %d, b %d", a.Samples, b.Samples)
	}
	ingest(base.Add(90 * time.Second))
	closed, _ := srv.pathMatrixFor(p, model.PathWindowDay, base.Add(5*time.Minute))
	if c := pathCellFor(t, closed, "node-a", "mon-a"); c.Samples != 3 {
		t.Fatalf("after the bucket closed: %+v", c)
	}
}

// adminPrincipalForTest is an unconfined administrator, as the session of
// the bootstrap admin is.
func adminPrincipalForTest() rbac.Principal {
	return rbac.Principal{ActorID: "admin", Scopes: []string{"*"}}
}

// Matrix reads of one window, a cache that expires under them, a sweep and
// ingest all run at once; the race detector holds the cache to account.
func TestPathMatrixReadsConcurrently(t *testing.T) {
	srv, _, st := newPathsServer(t)
	upsertNodes(t, st, model.Node{ID: "node-a", Name: "a", Online: true}, model.Node{ID: "node-b", Name: "b", Online: true})
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-a", Name: "a", Type: model.MonitorTypeTCP, Target: "203.0.113.9:443", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-a", "node-b"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC()
	p := principal{Principal: adminPrincipalForTest()}
	done := make(chan error, 8)
	for g := 0; g < 4; g++ {
		go func(g int) {
			for i := 0; i < 40; i++ {
				window := pathWindows[(g+i)%len(pathWindows)].name
				if _, err := srv.pathMatrixFor(p, window, base.Add(time.Duration(i)*time.Minute)); err != nil {
					done <- err
					return
				}
				if i%10 == 0 {
					srv.monitorPaths.forget()
				}
			}
			done <- nil
		}(g)
	}
	go func() {
		for i := 0; i < 100; i++ {
			at := base.Add(-time.Duration(100-i) * time.Second)
			if _, err := st.IngestAgentMonitorResults("node-a", []model.MonitorResult{{MonitorID: "mon-a", At: at, Success: true, LatencyMs: 10}}, base); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	go func() {
		_, err := srv.pruneMonitorHistory(context.Background())
		done <- err
	}()
	for i := 0; i < 6; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

// forget drops every cached window, so the next read goes to the store.
func (m *monitorPathState) forget() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.windows = nil
}
