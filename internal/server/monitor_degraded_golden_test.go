package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// Golden responses for the M3 console (design 29 D13).
//
// A small real fleet is built on the production store layout, the degraded
// evaluator runs on it minute by minute, and the real HTTP handlers answer
// the reads the console makes. Their bodies are written to
// testdata/m3-golden/, which the console copies its fixtures from, so a
// fixture can never again say something the server does not serialise (a
// hand-written fixture once missed that a Go zero time goes out as
// 0001-01-01T00:00:00Z).
//
// The test clock is fixed, so every time the handlers derive from it is
// stable. The few stamps the store takes from the wall clock are replaced
// by goldenWallClock in place, keeping each field's shape on the wire.
//
// Regenerate after a deliberate wire change with
//
//	LATTICE_UPDATE_M3_GOLDEN=1 go test ./internal/server -run '^TestM3GoldenResponses$'
//
// and review the diff; without the variable the test fails when a fresh run
// differs from the files.

const goldenUpdateEnv = "LATTICE_UPDATE_M3_GOLDEN"

// goldenBase is the instant the golden fleet's history ends and the
// evaluator first runs: 35 minutes into an hour, so the dozen evaluations
// that follow stay inside it and the baseline window does not move.
var goldenBase = time.Date(2026, 9, 14, 9, 35, 0, 0, time.UTC)

// goldenWallClock replaces stamps the store takes from the wall clock.
var goldenWallClock = time.Date(2026, 9, 14, 9, 0, 0, 0, time.UTC)

var goldenDir = filepath.Join("testdata", "m3-golden")

func steadyRuns(ms float64) func(int) (bool, float64) {
	return func(int) (bool, float64) { return true, ms }
}

// lossyRunsAt lose one run in eight among the first fifty and answer the
// rest in ms.
func lossyRunsAt(ms float64) func(int) (bool, float64) {
	return func(i int) (bool, float64) { return !(i < 50 && i%8 == 0), ms }
}

// goldenWeek is a pair's history from the hour a week and an hour before at
// up to an hour before at: one run a minute, as the golden checks' 60 s
// interval expects, each answered in ms, so the long windows read as fully
// heard. windowRuns adds the last hour.
func goldenWeek(monitorID, nodeID string, at time.Time, ms float64) []store.MonitorResultRecord {
	first := at.Add(-model.PathBaselineSpan - time.Hour).Truncate(time.Hour)
	last := at.Add(-time.Hour)
	out := make([]store.MonitorResultRecord, 0, int(last.Sub(first)/time.Minute)+1)
	for ts := first; !ts.After(last); ts = ts.Add(time.Minute) {
		out = append(out, store.MonitorResultRecord{
			MonitorResult: model.MonitorResult{MonitorID: monitorID, NodeID: nodeID, At: ts, Success: true, LatencyMs: ms},
			ReceivedAt:    ts,
		})
	}
	return out
}

// icmpWindowRuns is an icmp check's hour up to at, five echoes a run, every
// one answered in ms.
func icmpWindowRuns(monitorID, nodeID string, at time.Time, ms float64) []store.MonitorResultRecord {
	recs := windowRuns(monitorID, nodeID, at, steadyRuns(ms))
	for i := range recs {
		recs[i].Sent, recs[i].RTTsMs = 5, []float64{ms, ms, ms, ms, ms}
	}
	return recs
}

// tlsHistory is a tls check's week of hourly readings from the control
// plane, the newest twenty minutes before at.
func tlsHistory(monitorID string, at time.Time) []store.MonitorResultRecord {
	notAfter := time.Date(2026, 10, 25, 23, 59, 59, 0, time.UTC)
	var out []store.MonitorResultRecord
	for h := 0; h < 168; h++ {
		ts := at.Add(-20*time.Minute - time.Duration(h)*time.Hour)
		out = append(out, store.MonitorResultRecord{
			MonitorResult: model.MonitorResult{MonitorID: monitorID, At: ts, Success: true, LatencyMs: 85, CertNotAfter: notAfter},
			ReceivedAt:    ts,
		})
	}
	return out
}

// goldenFleet is the fleet the golden responses are read from.
type goldenFleet struct {
	*degradedFixture
	handler http.Handler
	cookies []*http.Cookie
	csrf    string
}

// The pairs of the golden fleet and what each is made to read by the end.
var (
	goldenLossPair     = store.MonitorPair{MonitorID: latencyMonitorID("node-jp"), NodeID: "node-sh"}  // degraded on loss
	goldenLatencyPair  = store.MonitorPair{MonitorID: latencyMonitorID("node-jp"), NodeID: "node-hk"}  // degraded on latency
	goldenClearingPair = store.MonitorPair{MonitorID: latencyMonitorID("node-jp"), NodeID: "node-fra"} // degraded, clearing
	goldenDownPair     = store.MonitorPair{MonitorID: latencyMonitorID("node-hk"), NodeID: "node-sh"}  // down
	goldenWebSH        = store.MonitorPair{MonitorID: "mon-web", NodeID: "node-sh"}                    // degraded on both, own thresholds
	goldenWebHK        = store.MonitorPair{MonitorID: "mon-web", NodeID: "node-hk"}
	goldenPingHK       = store.MonitorPair{MonitorID: "mon-ping-jp", NodeID: "node-hk"}
	// mon-ping-jp on node-fra reads unknown, icmp_not_permitted; mon-cert
	// is a tls check read from the control plane.
)

// goldenInventories hands every target a current line inventory, so the
// plan picks each one's tcp endpoint as production does.
func (g *goldenFleet) goldenInventories() {
	now := g.now()
	g.srv.singboxInvMu.Lock()
	defer g.srv.singboxInvMu.Unlock()
	g.srv.singboxInv = map[string]model.SingBoxInventory{}
	for id, ip := range map[string]string{"node-hk": "203.0.113.2", "node-jp": "203.0.113.3", "node-fra": "203.0.113.4"} {
		g.srv.singboxInv[id] = model.SingBoxInventory{NodeID: id, At: now, Status: "ok", Nodes: []model.SingBoxNode{
			{Name: "vless-reality-443", Protocol: "vless", Network: "reality", Port: "443", ListenHost: "::", Address: ip, PortBound: boolPtr(true)},
		}}
	}
}

func openGoldenFleet(t *testing.T) *goldenFleet {
	t.Helper()
	gen := latencyMonitorID
	var history []store.MonitorResultRecord
	for _, p := range []struct {
		pair store.MonitorPair
		base float64
		run  func(int) (bool, float64)
	}{
		{goldenLossPair, 40, lossyRunsAt(40)},
		{goldenLatencyPair, 52, steadyRuns(140)},
		{goldenClearingPair, 40, steadyRuns(140)},
		{goldenDownPair, 38, steadyRuns(38)},
		{store.MonitorPair{MonitorID: gen("node-fra"), NodeID: "node-sh"}, 210, steadyRuns(212)},
		{store.MonitorPair{MonitorID: gen("node-fra"), NodeID: "node-hk"}, 160, steadyRuns(158)},
		{store.MonitorPair{MonitorID: gen("node-hk"), NodeID: "node-fra"}, 162, steadyRuns(163)},
		{goldenWebSH, 40, lossyRunsAt(140)},
		{goldenWebHK, 52, steadyRuns(51)},
	} {
		history = append(history, goldenWeek(p.pair.MonitorID, p.pair.NodeID, goldenBase, p.base)...)
		history = append(history, windowRuns(p.pair.MonitorID, p.pair.NodeID, goldenBase, p.run)...)
	}
	pingBase := goldenWeek(goldenPingHK.MonitorID, goldenPingHK.NodeID, goldenBase, 50)
	for i := range pingBase {
		pingBase[i].Sent, pingBase[i].RTTsMs = 5, []float64{50, 50, 50, 50, 50}
	}
	history = append(history, pingBase...)
	history = append(history, icmpWindowRuns(goldenPingHK.MonitorID, goldenPingHK.NodeID, goldenBase, 50)...)
	history = append(history, tlsHistory("mon-cert", goldenBase)...)

	f := openDegradedFixture(t, t.TempDir(), history)
	f.clock.at = goldenBase
	g := &goldenFleet{degradedFixture: f}
	st := f.st
	for _, n := range []model.Node{
		{ID: "node-hk", Name: "hk-edge", Online: true, PublicIP: "203.0.113.2", Geo: &model.NodeGeo{Country: "HK"},
			ProbeMethods: []string{model.MonitorTypeTCP, model.MonitorTypeHTTP, model.MonitorTypeICMP}},
		{ID: "node-fra", Name: "fra-2", Online: true, PublicIP: "203.0.113.4", Geo: &model.NodeGeo{Country: "DE"},
			ProbeMethods: []string{model.MonitorTypeTCP, model.MonitorTypeHTTP}, ProbeRefusals: map[string]string{model.MonitorTypeICMP: model.PathReasonICMPNotPermitted}},
	} {
		if err := st.UpsertNode(n); err != nil {
			t.Fatal(err)
		}
	}
	for _, mon := range []model.Monitor{
		{ID: "mon-web", Name: "tyo-3 web", Type: model.MonitorTypeTCP, Target: "203.0.113.3:443", IntervalSec: 60, TimeoutSec: 5,
			NodeIDs: []string{"node-sh", "node-hk"}, Enabled: true, Alert: model.MonitorAlertDownAndDegraded,
			Degraded: &model.MonitorDegradedRule{LossPercent: 5, LatencyMarginMs: 50}, Version: 1, CreatedAt: time.Date(2026, 8, 3, 10, 12, 0, 0, time.UTC)},
		{ID: "mon-ping-jp", Name: "Ping tyo-3", Type: model.MonitorTypeICMP, Target: "203.0.113.3", Packets: 5, IntervalSec: 60, TimeoutSec: 5,
			NodeIDs: []string{"node-hk", "node-fra"}, Enabled: true, Version: 1, CreatedAt: time.Date(2026, 8, 20, 7, 41, 0, 0, time.UTC)},
		{ID: "mon-cert", Name: "lattice.example.net certificate", Type: model.MonitorTypeTLS, Target: "lattice.example.net:443",
			IntervalSec: 3600, TimeoutSec: 10, ThresholdDays: 14, Enabled: true, Version: 1, CreatedAt: time.Date(2026, 8, 20, 7, 45, 0, 0, time.UTC)},
	} {
		if err := st.UpsertMonitor(mon); err != nil {
			t.Fatal(err)
		}
	}
	g.goldenInventories()
	g.handler = f.srv.Handler()
	g.cookies, g.csrf = loginSession(t, g.handler)
	// The path set is saved through its route, so it is normalised and
	// stored as an operator's save is, and its generated checks are synced.
	status, _, body := putLatencyConfig(t, g.handler, g.cookies, g.csrf, model.LatencyProbeConfig{
		Enabled: true, IntervalSec: 60, TimeoutSec: 5, Sources: []string{"node-sh", "node-hk", "node-fra"}, AutoTargets: true,
		Alert: model.MonitorAlertDownAndDegraded, AlertAfter: 3, Degraded: &model.MonitorDegradedRule{LossPercent: 3, LatencyFactor: 2.5},
	})
	if status != http.StatusOK {
		t.Fatalf("path set save = %d %s", status, body)
	}
	for _, id := range []string{gen("node-jp"), gen("node-hk"), gen("node-fra")} {
		if mon, ok := st.Monitor(id); !ok || !mon.Enabled || len(mon.NodeIDs) == 0 {
			t.Fatalf("generated check %s = %+v", id, mon)
		}
	}
	return g
}

// minute moves the fleet one minute: every source reports its run for each
// pair it probes, then the evaluator runs.
func (g *goldenFleet) minute(fraFast, shFails bool) pathDegradedPass {
	g.t.Helper()
	gen := latencyMonitorID
	runs := map[store.MonitorPair]model.MonitorResult{
		goldenLossPair:    okRun(40),
		goldenLatencyPair: okRun(140),
		goldenDownPair:    okRun(38),
		{MonitorID: gen("node-fra"), NodeID: "node-sh"}: okRun(212),
		{MonitorID: gen("node-fra"), NodeID: "node-hk"}: okRun(158),
		{MonitorID: gen("node-hk"), NodeID: "node-fra"}: okRun(163),
		goldenWebSH:  okRun(140),
		goldenWebHK:  okRun(51),
		goldenPingHK: {Success: true, LatencyMs: 50, Sent: 5, RTTsMs: []float64{50, 50, 50, 50, 50}},
	}
	runs[goldenClearingPair] = okRun(140)
	if fraFast {
		runs[goldenClearingPair] = okRun(40)
	}
	if shFails {
		runs[goldenDownPair] = failedRun
	}
	return g.tick(runs)
}

// get reads path through the real handler and returns its body as sent.
func (g *goldenFleet) get(path string) []byte {
	g.t.Helper()
	res := doJSON(g.t, g.handler, http.MethodGet, path, "", g.cookies, g.csrf)
	body := readBody(g.t, res)
	if res.StatusCode != http.StatusOK {
		g.t.Fatalf("GET %s = %d %s", path, res.StatusCode, body)
	}
	return []byte(body)
}

// goldenWallClockFields are the fields the store may stamp from the wall
// clock (UpsertMonitor stamps updated_at with time.Now). A value in one of
// them later than the fixture's last minute came from the wall clock and
// is replaced with goldenWallClock; every earlier one came from the test
// clock and is kept.
var goldenWallClockFields = []string{"created_at", "updated_at"}

// normalizeGolden replaces wall-clock stamps and indents body for review,
// keeping the handler's key order. Every other byte is the handler's.
func normalizeGolden(t *testing.T, body []byte, end time.Time) []byte {
	t.Helper()
	for _, key := range goldenWallClockFields {
		re := regexp.MustCompile(`("` + regexp.QuoteMeta(key) + `":")([^"]*)(")`)
		body = re.ReplaceAllFunc(body, func(m []byte) []byte {
			parts := re.FindSubmatch(m)
			at, err := time.Parse(time.RFC3339Nano, string(parts[2]))
			if err != nil || !at.After(end) {
				return m
			}
			return []byte(string(parts[1]) + goldenWallClock.Format(time.RFC3339Nano) + string(parts[3]))
		})
	}
	var out bytes.Buffer
	if err := json.Indent(&out, bytes.TrimSpace(body), "", "  "); err != nil {
		t.Fatalf("indent %s: %v", body, err)
	}
	out.WriteByte('\n')
	return out.Bytes()
}

// catalogueEntries keeps the catalogue's entries for types, as the handler
// serialised them.
func catalogueEntries(t *testing.T, body []byte, types ...string) []byte {
	t.Helper()
	var cat struct {
		Types []json.RawMessage `json:"types"`
	}
	if err := json.Unmarshal(body, &cat); err != nil {
		t.Fatal(err)
	}
	var keep []json.RawMessage
	for _, want := range types {
		for _, raw := range cat.Types {
			var e struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(raw, &e); err != nil {
				t.Fatal(err)
			}
			if e.Type == want {
				keep = append(keep, raw)
			}
		}
	}
	if len(keep) != len(types) {
		t.Fatalf("catalogue entries for %v = %d", types, len(keep))
	}
	out, err := json.Marshal(keep)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestM3GoldenResponses(t *testing.T) {
	g := openGoldenFleet(t)
	// t0: one finding each. t0+1: the degraded pairs enter. From t0+2 the
	// clearing pair answers fast, and its 15-minute median falls under the
	// trigger at t0+10, when it starts clearing. node-sh fails its last
	// three runs to hk-edge, the path set's alert_after, and reads down.
	g.evaluate()
	if pass := g.minute(false, false); pass.entered != 4 {
		t.Fatalf("t0+1 = %+v, want the loss, latency, clearing and web paths entering", pass)
	}
	cleared := 0
	for k := 2; k <= 12; k++ {
		cleared += g.minute(true, k >= 10).cleared
	}
	if cleared != 1 {
		t.Fatalf("%d paths started clearing, want 1", cleared)
	}
	g.goldenInventories()

	m := g.matrix()
	for _, want := range []struct {
		pair          store.MonitorPair
		state, reason string
	}{
		{goldenLossPair, model.PathStateDegraded, model.PathReasonDegradedLoss},
		{goldenLatencyPair, model.PathStateDegraded, model.PathReasonDegradedLatency},
		{goldenClearingPair, model.PathStateDegraded, model.PathReasonDegradedLatency},
		{goldenDownPair, model.PathStateDown, ""},
		{goldenWebSH, model.PathStateDegraded, model.PathReasonDegradedLossLatency},
		{goldenWebHK, model.PathStateUp, ""},
		{goldenPingHK, model.PathStateUp, ""},
		{store.MonitorPair{MonitorID: "mon-ping-jp", NodeID: "node-fra"}, model.PathStateUnknown, model.PathReasonICMPNotPermitted},
		{store.MonitorPair{MonitorID: "mon-cert"}, model.PathStateUp, ""},
	} {
		c := pathCellFor(t, m, want.pair.NodeID, want.pair.MonitorID)
		if c.State != want.state || c.Reason != want.reason {
			t.Errorf("%s/%s = %s %q, want %s %q", want.pair.MonitorID, want.pair.NodeID, c.State, c.Reason, want.state, want.reason)
		}
	}
	if c := pathCellFor(t, m, goldenClearingPair.NodeID, goldenClearingPair.MonitorID); c.Degraded == nil || c.Degraded.ClearingSince == nil {
		t.Errorf("clearing path = %+v", c.Degraded)
	}
	if t.Failed() {
		t.FailNow()
	}

	files := []struct {
		name string
		body []byte
	}{
		{"paths-1h.json", g.get("/api/monitors/paths?window=1h")},
		{"paths-7d.json", g.get("/api/monitors/paths?window=7d")},
		{"series-degraded-latency-1h-previous.json", g.get("/api/monitors/series?source=node-hk&target_node=node-jp&window=1h&compare=previous")},
		{"monitors.json", g.get("/api/monitors")},
		{"path-set.json", g.get("/api/monitors/latency")},
		{"notify-catalogue-path-entries.json", catalogueEntries(t, g.get("/api/notify/catalogue"), EventPathDegraded, EventPathRecovered)},
	}
	update := os.Getenv(goldenUpdateEnv) != ""
	if update {
		if err := os.MkdirAll(goldenDir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range files {
		got := normalizeGolden(t, file.body, g.now())
		path := filepath.Join(goldenDir, file.name)
		if update {
			if err := os.WriteFile(path, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v; regenerate with %s=1", err, goldenUpdateEnv)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from a fresh run (%s); if the change is deliberate, regenerate with %s=1 and review the diff", path, firstDifference(got, want), goldenUpdateEnv)
		}
	}
}

// firstDifference names the first line where got and want differ.
func firstDifference(got, want []byte) string {
	g, w := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
	for i := 0; i < len(g) || i < len(w); i++ {
		var gl, wl string
		if i < len(g) {
			gl = g[i]
		}
		if i < len(w) {
			wl = w[i]
		}
		if gl != wl {
			return fmt.Sprintf("line %d: got %q, file has %q", i+1, gl, wl)
		}
	}
	return "same lines"
}
