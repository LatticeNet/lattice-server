package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/metricsdb"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/store"
	"github.com/LatticeNet/lattice-server/internal/telemetry"
)

// selfMonFixture is a server with a metrics store and no background loops,
// so a test drives sampling and flushing itself.
type selfMonFixture struct {
	srv     *Server
	handler http.Handler
	st      *store.Store
	db      *metricsdb.DB
	dataDir string
	now     time.Time
}

func newSelfMonFixture(t *testing.T) *selfMonFixture {
	t.Helper()
	telemetry.ResetForTest()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "state.json")
	if err := os.WriteFile(stateFile, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &selfMonFixture{st: st, dataDir: dir, now: time.Date(2026, 10, 4, 12, 0, 30, 0, time.UTC)}
	db, err := metricsdb.Open(filepath.Join(dir, "metrics.db"), metricsdb.Options{Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	f.db = db
	srv, err := New(Options{
		Store:                   st,
		AdminPassword:           testAdminPass,
		DisableRenewalScheduler: true,
		Logger:                  log.New(io.Discard, "", 0),
		SelfMonitor: SelfMonitorOptions{
			DB:      db,
			DataDir: dir,
			Files:   []MonitoredFile{{Label: "state.json", Path: stateFile}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.now = func() time.Time { return f.now }
	srv.selfmon.now = srv.now
	srv.selfmon.minute = f.now.Truncate(time.Minute)
	f.srv = srv
	f.handler = srv.Handler()
	return f
}

func (f *selfMonFixture) advance(d time.Duration) { f.now = f.now.Add(d) }

func TestSelfMonitorRecordsBeatsAsNodeHistory(t *testing.T) {
	f := newSelfMonFixture(t)
	cookies, csrf := loginSession(t, f.handler)
	nodeID, token := enrollNode(t, f.handler, cookies, csrf)
	beat := func(cpu float64) {
		t.Helper()
		body := fmt.Sprintf(`{"node_id":%q,"version":"0.3.10","metrics":{"cpu_percent":%v,"memory_used":250,"memory_total":1000,"disk_used":30,"disk_total":120,"load1":0.5,"net_rx_speed":2048,"net_tx_speed":1024,"collected_at":%q}}`,
			nodeID, cpu, f.now.Format(time.RFC3339))
		if rec := doAgentRaw(t, f.handler, http.MethodPost, "/api/agent/metrics", body, token); rec.Code != http.StatusOK {
			t.Fatalf("beat = %d %s", rec.Code, rec.Body.String())
		}
	}
	beat(10)
	f.advance(15 * time.Second)
	beat(30)
	f.advance(20 * time.Second) // into the next minute
	f.srv.selfmon.flushDue(f.now, false)

	res, err := f.db.Query(selfMonOwnerNodePrefix+nodeID, nil, f.now.Add(-time.Hour), f.now, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]metricsdb.Point{}
	for _, sp := range res.Series {
		if len(sp.Points) != 1 {
			t.Fatalf("%s has %d points, want 1", sp.Name, len(sp.Points))
		}
		got[sp.Name] = sp.Points[0].Point
	}
	if g := got[seriesNodeCPU].Gauge; g.Count != 2 || g.Min != 10 || g.Max != 30 {
		t.Fatalf("cpu = %+v, want two beats from 10 to 30", g)
	}
	if g := got[seriesNodeMem].Gauge; g.Avg() != 25 {
		t.Fatalf("mem = %v%%, want 25", g.Avg())
	}
	if g := got[seriesNodeDisk].Gauge; g.Avg() != 25 {
		t.Fatalf("disk = %v%%, want 25", g.Avg())
	}
	if g := got[seriesNodeRx].Gauge; g.Avg() != 2048 {
		t.Fatalf("rx = %v", g.Avg())
	}
	// The first beat this process heard has no gap; the second is 15 s after it.
	if g := got[seriesNodeBeatGap].Gauge; g.Count != 1 || g.Max != 15 {
		t.Fatalf("beat gap = %+v, want one gap of 15 s", g)
	}

	// The node page reads it back through the API.
	res2 := doJSON(t, f.handler, http.MethodGet, "/api/nodes/history?node_id="+nodeID+"&range=24h", "", cookies, csrf)
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("history = %d", res2.StatusCode)
	}
	var view metricsQueryView
	if err := json.NewDecoder(res2.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	if view.Tier != "1m" || len(view.Series) != 7 {
		t.Fatalf("history view = %+v", view)
	}
	for _, s := range view.Series {
		if s.Name == seriesNodeCPU && (s.Unit != "percent" || len(s.T) != 1 || s.Max[0] != 30) {
			t.Fatalf("cpu series view = %+v", s)
		}
	}

	// Deleting the node takes its history with it.
	del := doJSON(t, f.handler, http.MethodPost, "/api/nodes/delete", `{"node_id":"`+nodeID+`"}`, cookies, csrf)
	summary := decodeNodeDeleteSummary(t, del)
	if summary.MetricsSeriesPurged != 7 {
		t.Fatalf("metrics_series_purged = %d, want 7", summary.MetricsSeriesPurged)
	}
	owners, err := f.db.Owners()
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range owners {
		if o.Owner == selfMonOwnerNodePrefix+nodeID {
			t.Fatal("deleted node's history survived")
		}
	}
}

func TestSelfMonitorFlushWritesProcessHostStoreRoutesAndPlugins(t *testing.T) {
	f := newSelfMonFixture(t)
	m := f.srv.selfmon
	m.sample(f.now)
	f.advance(10 * time.Second)
	s := m.sample(f.now)
	if s.Goroutines <= 0 || s.Heap == 0 {
		t.Fatalf("sample = %+v, want goroutines and heap", s)
	}
	if !s.HaveDisk || s.DiskTotal == 0 {
		t.Fatalf("data volume not read: %+v", s)
	}
	telemetry.ObserveRoute("/api/nodes", http.StatusOK, 12*time.Millisecond)
	telemetry.ObserveRoute("/api/nodes", http.StatusBadGateway, 40*time.Millisecond)
	telemetry.ObserveRoute("/api/nodes", http.StatusNotFound, 2*time.Millisecond)
	telemetry.ObservePluginCall("latticenet.vpn-core", "subscription/fetch", 80*time.Millisecond, nil)
	telemetry.ObservePluginCall("latticenet.vpn-core", "subscription/fetch", 200*time.Millisecond, errors.New("timeout"))
	telemetry.ObservePluginProcess("latticenet.vpn-core", 1500*time.Millisecond, 48<<20)
	telemetry.ObserveStoreSave("UpdateMetrics", 3*time.Millisecond, nil)
	f.advance(25 * time.Second) // 12:01:05
	m.flushDue(f.now, false)

	agg := func(owner string) map[string]metricsdb.Point {
		t.Helper()
		out, _, err := f.db.Aggregate(owner, nil, f.now.Add(-time.Hour), f.now)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	cp := agg(selfMonOwnerCP)
	if cp[seriesProcHeap].Gauge.Count != 2 || cp[seriesProcGoroutines].Gauge.Count != 2 {
		t.Fatalf("process gauges = %+v", cp)
	}
	if cp[seriesHostDiskTotal].Gauge.Count != 2 {
		t.Fatalf("disk gauge = %+v", cp[seriesHostDiskTotal])
	}
	if cp[seriesFilePrefix+"state.json"].Gauge.Max != 4096 {
		t.Fatalf("state.json size = %+v", cp[seriesFilePrefix+"state.json"])
	}
	if _, ok := cp[seriesFilePrefix+"metrics.db"]; !ok {
		t.Fatal("the metrics store's own size is not recorded")
	}
	route := agg(selfMonOwnerHTTP)["/api/nodes"].Event
	if route == nil || route.Count != 3 || route.Errors != 1 {
		t.Fatalf("route group = %+v, want 3 requests and the 502 counted as the one failure", route)
	}
	vpn := agg(selfMonOwnerPluginPrefix + "latticenet.vpn-core")
	if e := vpn["subscription/fetch"].Event; e == nil || e.Count != 2 || e.Errors != 1 {
		t.Fatalf("plugin method = %+v", e)
	}
	if g := vpn[seriesPluginProcessCPU].Gauge; g.Count != 1 || g.Sum != 1.5 {
		t.Fatalf("plugin process cpu = %+v", g)
	}
	if g := vpn[seriesPluginProcessRSS].Gauge; g.Max != 48<<20 {
		t.Fatalf("plugin process rss = %+v", g)
	}
	if e := agg(selfMonOwnerStore)["UpdateMetrics"].Event; e == nil || e.Count != 1 {
		t.Fatalf("store caller = %+v", e)
	}

	// The second flush records the first write's duration: the metrics
	// store watches its own write path.
	f.advance(time.Minute)
	m.flushDue(f.now, false)
	if g := agg(selfMonOwnerCP)[seriesMetricsWrite].Gauge; g.Count != 1 || g.Max <= 0 {
		t.Fatalf("metrics store write gauge = %+v", g)
	}
	// Nothing new happened: no flush inside the same minute.
	before, _ := f.db.Stats()
	m.flushDue(f.now.Add(10*time.Second), false)
	after, _ := f.db.Stats()
	if after.LastWrite.At != before.LastWrite.At {
		t.Fatal("flushed twice inside one minute")
	}
}

func TestSelfMonitorFinalFlushWritesTheMinuteInProgress(t *testing.T) {
	f := newSelfMonFixture(t)
	m := f.srv.selfmon
	m.sample(f.now)
	f.advance(5 * time.Second)
	m.flushDue(f.now, true)
	agg, _, err := f.db.Aggregate(selfMonOwnerCP, []string{seriesProcGoroutines}, f.now.Add(-time.Hour), f.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if agg[seriesProcGoroutines].Gauge.Count != 1 {
		t.Fatalf("final flush lost the minute in progress: %+v", agg)
	}
}

func TestSelfMonitorPrunesGoneOwners(t *testing.T) {
	f := newSelfMonFixture(t)
	if err := f.st.UpsertNode(model.Node{ID: "kept-node", Name: "kept"}); err != nil {
		t.Fatal(err)
	}
	old := f.now.Add(-40 * 24 * time.Hour)
	recent := f.now.Add(-time.Hour)
	gauge := func(owner, name string) metricsdb.Sample {
		var g metricsdb.Gauge
		g.Observe(1)
		return metricsdb.Sample{Owner: owner, Name: name, Kind: metricsdb.KindGauge, Gauge: g}
	}
	if _, err := f.db.Write(old, []metricsdb.Sample{gauge("plugin/old-gone", "process.cpu")}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Write(recent, []metricsdb.Sample{
		gauge("plugin/recent-gone", "process.cpu"),
		gauge("node/kept-node", "cpu"),
		gauge("node/deleted-node", "cpu"),
		gauge("cp", "proc.heap"),
	}); err != nil {
		t.Fatal(err)
	}
	f.srv.selfmon.prune(f.now, false)
	owners, err := f.db.Owners()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, o := range owners {
		names = append(names, o.Owner)
	}
	want := []string{"cp", "node/kept-node", "plugin/recent-gone"}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("owners after prune = %v, want %v (a deleted node goes at once, a plugin after 30 days unloaded)", names, want)
	}
}

func TestSelfMonitorAPIAccess(t *testing.T) {
	f := newSelfMonFixture(t)
	cookies, csrf := loginSession(t, f.handler)
	nodeID, _ := enrollNode(t, f.handler, cookies, csrf)

	get := func(path, token string) int {
		t.Helper()
		var res *http.Response
		if token == "" {
			res = doJSON(t, f.handler, http.MethodGet, path, "", cookies, csrf)
		} else {
			res = doBearerJSON(t, f.handler, http.MethodGet, path, "", token)
		}
		res.Body.Close()
		return res.StatusCode
	}
	admin := createPAT(t, f.handler, cookies, csrf, []string{"*"}, nil)
	confinedAdmin := createPAT(t, f.handler, cookies, csrf, []string{"*"}, []string{nodeID})
	nodeReader := createPAT(t, f.handler, cookies, csrf, []string{"node:read", "plugin:admin", "audit:read"}, nil)
	otherNode := createPAT(t, f.handler, cookies, csrf, []string{"node:read"}, []string{"some-other-node"})

	for _, path := range []string{"/api/system/health", "/api/system/series?owner=cp&series=proc.heap"} {
		if got := get(path, ""); got != http.StatusOK {
			t.Errorf("%s as the admin session = %d", path, got)
		}
		if got := get(path, admin); got != http.StatusOK {
			t.Errorf("%s with a * token = %d", path, got)
		}
		if got := get(path, confinedAdmin); got != http.StatusForbidden {
			t.Errorf("%s with a node-restricted * token = %d, want 403", path, got)
		}
		if got := get(path, nodeReader); got != http.StatusForbidden {
			t.Errorf("%s with node, plugin and audit scopes = %d, want 403", path, got)
		}
	}
	history := "/api/nodes/history?node_id=" + nodeID
	if got := get(history, nodeReader); got != http.StatusOK {
		t.Errorf("history with node:read = %d", got)
	}
	if got := get(history, confinedAdmin); got != http.StatusOK {
		t.Errorf("history inside the allowlist = %d", got)
	}
	if got := get(history, otherNode); got != http.StatusForbidden {
		t.Errorf("history outside the allowlist = %d, want 403", got)
	}
	if got := get("/api/nodes/history?node_id=nope", ""); got != http.StatusNotFound {
		t.Errorf("history of an unknown node = %d, want 404", got)
	}
	if got := get(history+"&range=2w", ""); got != http.StatusBadRequest {
		t.Errorf("unknown range = %d, want 400", got)
	}
	if got := get(history+"&points=5000", ""); got != http.StatusBadRequest {
		t.Errorf("too many points = %d, want 400", got)
	}
}

func TestSelfMonitorHealthView(t *testing.T) {
	f := newSelfMonFixture(t)
	m := f.srv.selfmon
	m.sample(f.now)
	telemetry.ObservePluginCall("latticenet.netguard", "zones/list", 30*time.Millisecond, nil)
	telemetry.ObserveRoute("/api/agent/metrics", http.StatusOK, 4*time.Millisecond)
	f.advance(40 * time.Second)
	m.sample(f.now)
	m.flushDue(f.now, false)
	cookies, csrf := loginSession(t, f.handler)
	res := doJSON(t, f.handler, http.MethodGet, "/api/system/health?range=1h", "", cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("health = %d", res.StatusCode)
	}
	var view systemHealthView
	if err := json.NewDecoder(res.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	if view.Range != "1h" || view.Process.Goroutines == 0 || view.Process.GoVersion == "" {
		t.Fatalf("process = %+v", view.Process)
	}
	if view.Host.DiskTotalBytes == nil || *view.Host.DiskTotalBytes == 0 {
		t.Fatalf("host = %+v", view.Host)
	}
	if len(view.Plugins) != 1 || view.Plugins[0].Plugin != "latticenet.netguard" || view.Plugins[0].Name != "zones/list" || view.Plugins[0].Calls != 1 {
		t.Fatalf("plugins = %+v", view.Plugins)
	}
	if view.Plugins[0].P95Seconds <= 0 || len(view.Plugins[0].Spark.T) != 1 {
		t.Fatalf("plugin row = %+v", view.Plugins[0])
	}
	var agentRow *systemEventRow
	for i := range view.HTTP {
		if view.HTTP[i].Name == "/api/agent/metrics" {
			agentRow = &view.HTTP[i]
		}
	}
	if agentRow == nil || agentRow.Calls < 1 {
		t.Fatalf("http rows = %+v", view.HTTP)
	}
	if len(view.Files) != 2 || view.Files[0].Label != "state.json" || view.Files[0].SizeBytes == nil || *view.Files[0].SizeBytes != 4096 {
		t.Fatalf("files = %+v", view.Files)
	}
	ms := view.MetricsStore
	if ms.Series == 0 || ms.MaxSeries != metricsdb.DefaultMaxSeries || len(ms.Tiers) != 4 || ms.LastWriteAt.IsZero() || ms.SampleSeconds != 10 {
		t.Fatalf("metrics store = %+v", ms)
	}
}

func TestSelfMonitorDisabledAnswers503(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	for _, path := range []string{"/api/system/health", "/api/system/series"} {
		res := doJSON(t, handler, http.MethodGet, path, "", cookies, csrf)
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), `"code":"`+apiErrorMetricsDisabled+`"`) {
			t.Errorf("%s without a metrics store = %d %s, want 503 with code %s", path, res.StatusCode, body, apiErrorMetricsDisabled)
		}
	}
}

func TestRouteGroups(t *testing.T) {
	cases := map[string]string{
		"/":                              "/",
		"/api/nodes":                     "/api/nodes",
		"/api/nodes/delete/plan":         "/api/nodes",
		"/api/agent/metrics":             "/api/agent/metrics",
		"/api/agent/terminal/sessions/x": "/api/agent/terminal",
		"/sub/:token":                    "/sub",
		"/tools/knock/lattice-knock.tar": "/tools",
		"/install.sh":                    "/install.sh",
		"/api":                           "/api",
	}
	for path, want := range cases {
		if got := routeGroupOf(path); got != want {
			t.Errorf("routeGroupOf(%q) = %q, want %q", path, got, want)
		}
	}
	mux := newRouteGroupMux()
	mux.HandleFunc("/api/nodes", func(http.ResponseWriter, *http.Request) {})
	mux.Handle("/", http.NotFoundHandler())
	for path, want := range map[string]string{
		"/api/nodes/abc":    "/api/nodes",
		"/api/wp-login.php": routeGroupUnmatched,
		"/monitoring":       "/",
		"/.env":             "/",
		"/api":              routeGroupUnmatched,
	} {
		if got := mux.groups.group(path); got != want {
			t.Errorf("group(%q) = %q, want %q", path, got, want)
		}
	}
}

// TestRequestsAreRecordedByRouteGroup drives real requests through the
// handler: a scanner's /api guess lands in the unmatched group, never in a
// group of its own.
func TestRequestsAreRecordedByRouteGroup(t *testing.T) {
	telemetry.ResetForTest()
	handler, _ := newTestServer(t)
	for _, path := range []string{"/api/version", "/api/version", "/api/xyz-scanner-guess", "/readyz"} {
		res := doJSON(t, handler, http.MethodGet, path, "", nil, "")
		res.Body.Close()
	}
	w := telemetry.TakeInterval()
	if e := w.Routes["/api/version"]; e == nil || e.Count != 2 {
		t.Fatalf("/api/version = %+v", e)
	}
	if e := w.Routes[routeGroupUnmatched]; e == nil || e.Count != 1 {
		t.Fatalf("unmatched = %+v (routes %v)", e, w.Routes)
	}
	if _, ok := w.Routes["/api/xyz-scanner-guess"]; ok {
		t.Fatal("an unregistered path made its own group")
	}
}

func TestPluginMethodLabelAndFailure(t *testing.T) {
	if got := pluginMethodLabel("latticenet.vpn-core", "latticenet.vpn-core/subscription", "fetch"); got != "subscription/fetch" {
		t.Fatalf("label = %q", got)
	}
	if got := pluginMethodLabel("p", "other.service", "m"); got != "other.service/m" {
		t.Fatalf("foreign service label = %q", got)
	}
	if got := pluginMethodLabel("p", "", "m"); got != "m" {
		t.Fatalf("service-less label = %q", got)
	}
	if pluginCallFailure(plugin.InvokeResponse{OK: true}, nil) != nil {
		t.Fatal("a successful call counted as a failure")
	}
	if pluginCallFailure(plugin.InvokeResponse{OK: false}, nil) == nil {
		t.Fatal("a refusal did not count as a failure")
	}
	if pluginCallFailure(plugin.InvokeResponse{}, errors.New("spawn")) == nil {
		t.Fatal("a runtime error did not count as a failure")
	}
}

// TestSelfMonitorDeletedNodeStaysGoneAfterTheNextFlush deletes a node whose
// beat is still being collected this minute: the next flush must not bring
// its history back.
func TestSelfMonitorDeletedNodeStaysGoneAfterTheNextFlush(t *testing.T) {
	f := newSelfMonFixture(t)
	m := f.srv.selfmon
	if err := f.st.UpsertNode(model.Node{ID: "gone-node", Name: "gone"}); err != nil {
		t.Fatal(err)
	}
	m.observeBeat("gone-node", model.Metrics{CPUPercent: 12, Load1: 0.4, CollectedAt: f.now}, f.now)
	f.advance(time.Minute)
	m.flushDue(f.now, false)
	// A second beat lands in the minute now being collected, then the node
	// is deleted before that minute is flushed.
	m.observeBeat("gone-node", model.Metrics{CPUPercent: 14, Load1: 0.5, CollectedAt: f.now}, f.now)
	if n, err := m.forgetNode("gone-node"); err != nil || n == 0 {
		t.Fatalf("forgetNode = %d, %v; want the node's series deleted", n, err)
	}
	f.advance(time.Minute)
	m.flushDue(f.now, false)
	owners, err := f.db.Owners()
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range owners {
		if o.Owner == selfMonOwnerNodePrefix+"gone-node" {
			t.Fatalf("the deleted node's history came back with %d series", o.Series)
		}
	}
}

// TestHijackedStreamsAreNotRouteLatency: a terminal or control stream takes
// over its connection and lives for hours. Its duration is a session length,
// and counting it as a request latency would wreck its route group's p95.
func TestHijackedStreamsAreNotRouteLatency(t *testing.T) {
	telemetry.ResetForTest()
	s := &Server{logger: log.New(io.Discard, "", 0)}
	mux := newRouteGroupMux()
	mux.HandleFunc("/api/agent/terminal/", func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: close\r\n\r\n")
		_ = buf.Flush()
		_ = conn.Close()
	})
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	logged := s.withRequestLog(mux, mux.groups)
	served := make(chan struct{}, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logged.ServeHTTP(w, r)
		served <- struct{}{}
	}))
	defer srv.Close()
	for _, path := range []string{"/api/agent/terminal/session-1", "/api/version"} {
		if res, err := http.Get(srv.URL + path); err == nil {
			res.Body.Close()
		}
		select {
		case <-served:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s was not served", path)
		}
	}
	w := telemetry.TakeInterval()
	if e := w.Routes["/api/version"]; e == nil || e.Count != 1 {
		t.Fatalf("/api/version = %+v, want one request recorded", e)
	}
	if e, ok := w.Routes["/api/agent/terminal"]; ok {
		t.Fatalf("the hijacked stream was recorded as route latency: %+v", e)
	}
}

// TestSelfMonitorLogsARefusedSeriesOnce: a series over the cap is logged the
// first time, not every minute it stays refused, with the cap that refused
// it.
func TestSelfMonitorLogsARefusedSeriesOnce(t *testing.T) {
	telemetry.ResetForTest()
	now := time.Date(2026, 10, 4, 12, 0, 30, 0, time.UTC)
	db, err := metricsdb.Open(filepath.Join(t.TempDir(), "metrics.db"), metricsdb.Options{MaxSeries: 1, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var logs strings.Builder
	m := newSelfMonitor(SelfMonitorOptions{DB: db}, log.New(&logs, "", 0), func() time.Time { return now }, nil, nil)
	for i := 0; i < 5; i++ {
		m.mu.Lock()
		m.observeLocked(selfMonOwnerCP, "a", 1)
		m.observeLocked(selfMonOwnerCP, "b", 1)
		m.mu.Unlock()
		now = now.Add(time.Minute)
		m.flushDue(now, false)
	}
	// The cap of one leaves room for one of the series this minute holds;
	// every other is refused, and each is logged once.
	perSeries := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if strings.Contains(line, "is not stored") {
			perSeries[line]++
		}
	}
	if len(perSeries) == 0 {
		t.Fatalf("nothing logged for the refused series:\n%s", logs.String())
	}
	for line, n := range perSeries {
		if n != 1 {
			t.Fatalf("logged %d times over five flushes, want once: %s", n, line)
		}
	}
	if !strings.Contains(logs.String(), "LATTICE_METRICS_MAX_SERIES") {
		t.Fatalf("the log does not name the cap that refused it:\n%s", logs.String())
	}
}

func TestSelfMonitorUnavailableAnswersWithItsCode(t *testing.T) {
	telemetry.ResetForTest()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	const reason = "metrics.db could not be opened, so this server keeps no history until it restarts with a usable file: boom"
	srv, err := New(Options{
		Store:                   st,
		AdminPassword:           testAdminPass,
		DisableRenewalScheduler: true,
		Logger:                  log.New(io.Discard, "", 0),
		SelfMonitor:             SelfMonitorOptions{Unavailable: reason},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodGet, "/api/system/health", "", cookies, csrf)
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	// The 5xx message is scrubbed like every other; the code says which case
	// it is, and the detail is in the log.
	if res.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), `"code":"`+apiErrorMetricsUnavailable+`"`) || strings.Contains(string(body), "boom") {
		t.Fatalf("health = %d %s, want 503 with code %s and no detail", res.StatusCode, body, apiErrorMetricsUnavailable)
	}
}

// TestCompactFloatsNeverBreakTheJSON: a value JSON cannot carry becomes null
// rather than an encoder error after the 200 has gone out.
func TestCompactFloatsNeverBreakTheJSON(t *testing.T) {
	b, err := json.Marshal(metricsSeriesView{Avg: compactFloats{1.5, math.Inf(1), math.NaN(), math.Inf(-1), 2}})
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		Avg []*float64 `json:"avg"`
	}
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("%s does not decode: %v", b, err)
	}
	if len(back.Avg) != 5 || back.Avg[0] == nil || *back.Avg[0] != 1.5 || back.Avg[1] != nil || back.Avg[2] != nil || back.Avg[3] != nil || *back.Avg[4] != 2 {
		t.Fatalf("avg = %s, want 1.5,null,null,null,2", b)
	}
}
