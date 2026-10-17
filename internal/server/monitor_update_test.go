package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/store"
)

func decodeMonitorView(t *testing.T, res *http.Response) monitorView {
	t.Helper()
	defer res.Body.Close()
	var v monitorView
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// An edit names the version it was read at and changes only what it names;
// a stale version is refused, a generated check answers 409 as a delete
// does, and a new method or target is refused with what to do instead.
func TestMonitorUpdateVersionAndRefusals(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	upsertNodes(t, st, model.Node{ID: "node-a", Name: "a"}, model.Node{ID: "node-b", Name: "b"})
	create := doJSON(t, handler, http.MethodPost, "/api/monitors", `{"name":"web","type":"tcp","target":"203.0.113.9:443","node_ids":["node-a"]}`, cookies, csrf)
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create = %d", create.StatusCode)
	}
	var created model.Monitor
	if err := json.NewDecoder(create.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	create.Body.Close()
	if created.Version != 1 || created.Alert != model.MonitorAlertDown {
		t.Fatalf("created = %+v", created)
	}
	edit := func(body string) *http.Response {
		return doJSON(t, handler, http.MethodPost, "/api/monitors/update", body, cookies, csrf)
	}
	res := edit(`{"id":"` + created.ID + `","version":1,"name":"web front","interval_sec":20,"alert":"off","node_ids":["node-a","node-b"],"paused_node_ids":["node-b"]}`)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("edit = %d", res.StatusCode)
	}
	view := decodeMonitorView(t, res)
	if view.Version != 2 || view.Name != "web front" || view.IntervalSec != 20 || view.TimeoutSec != 5 || view.Alert != "off" ||
		len(view.NodeIDs) != 2 || len(view.PausedNodeIDs) != 1 || view.Target != "203.0.113.9:443" {
		t.Fatalf("after the edit = %+v", view)
	}
	stale := edit(`{"id":"` + created.ID + `","version":1,"name":"again"}`)
	stale.Body.Close()
	if stale.StatusCode != http.StatusConflict {
		t.Fatalf("stale edit = %d", stale.StatusCode)
	}
	for body, want := range map[string]string{
		`{"id":"` + created.ID + `","version":2,"type":"http"}`:                                                "create a new check",
		`{"id":"` + created.ID + `","version":2,"target":"203.0.113.10:443"}`:                                  "create a new check",
		`{"id":"` + created.ID + `","version":2,"interval_sec":9}`:                                             "interval_sec must be 10",
		`{"id":"` + created.ID + `","version":2,"paused_node_ids":["node-c"]}`:                                 "not one of the check's sources",
		`{"id":"` + created.ID + `","version":2,"alert":"loud"}`:                                               "alert must be",
		`{"id":"` + created.ID + `","version":2,"threshold_days":3}`:                                           "tls checks only",
		`{"id":"` + created.ID + `","version":2,"node_ids":[]}`:                                                "assign_all or provide node_ids",
		`{"id":"` + created.ID + `","version":2,"timeout_sec":20}`:                                             "shorter than interval_sec",
		`{"id":"` + created.ID + `","version":2,"node_ids":["node-a","node-gone"]}`:                            "not a node",
		`{"id":"` + created.ID + `","version":2,"type":"tcp","target":"203.0.113.9:443","name":"same method"}`: "",
	} {
		res := edit(body)
		var answer model.APIErrorResponse
		_ = json.NewDecoder(res.Body).Decode(&answer)
		res.Body.Close()
		if want == "" {
			if res.StatusCode != http.StatusOK {
				t.Fatalf("%s = %d", body, res.StatusCode)
			}
			continue
		}
		if res.StatusCode != http.StatusBadRequest || !strings.Contains(answer.Error.Message, want) {
			t.Fatalf("%s = %d %q, want 400 naming %q", body, res.StatusCode, answer.Error.Message, want)
		}
	}
	mon, _ := st.Monitor(created.ID)
	if mon.Version != 3 || mon.Name != "same method" {
		t.Fatalf("stored = %+v", mon)
	}
	// The refusal text names the way forward.
	res = edit(`{"id":"` + created.ID + `","version":3,"target":"203.0.113.10:443"}`)
	var apiErr model.APIErrorResponse
	_ = json.NewDecoder(res.Body).Decode(&apiErr)
	res.Body.Close()
	if !strings.Contains(apiErr.Error.Message, "create a new check") || !strings.Contains(apiErr.Error.Message, "pause this one") {
		t.Fatalf("target change refusal = %q", apiErr.Error.Message)
	}
	if _, _, err := srv.syncLatencyProbes(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertMonitor(model.Monitor{ID: latencyMonitorID("node-b"), Name: "Latency to b", Type: model.MonitorTypeTCP, Target: "203.0.113.2:443", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-a"}, Enabled: true, ManagedBy: model.MonitorManagedLatency}); err != nil {
		t.Fatal(err)
	}
	generated := edit(`{"id":"` + latencyMonitorID("node-b") + `","version":0,"name":"mine now"}`)
	generated.Body.Close()
	if generated.StatusCode != http.StatusConflict {
		t.Fatalf("edit of a generated check = %d", generated.StatusCode)
	}
	missing := edit(`{"id":"mon-nope","version":0}`)
	missing.Body.Close()
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("edit of a missing check = %d", missing.StatusCode)
	}
	if !auditHasAction(t, st, "monitor.update") {
		t.Fatal("the edit was not audited")
	}
}

func auditHasAction(t *testing.T, st *store.Store, action string) bool {
	t.Helper()
	for _, ev := range st.AuditEvents() {
		if ev.Action == action {
			return true
		}
	}
	return false
}

// A paused source is not handed the check and its results are refused; the
// other sources carry on, and resuming hands it back.
func TestMonitorUpdatePausesOneSource(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	upsertNodes(t, st, model.Node{ID: "node-a", Name: "a"}, model.Node{ID: "node-b", Name: "b"})
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-x", Name: "x", Type: model.MonitorTypeTCP, Target: "203.0.113.9:443", IntervalSec: 30, TimeoutSec: 5, NodeIDs: []string{"node-a", "node-b"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	res := doJSON(t, handler, http.MethodPost, "/api/monitors/update", `{"id":"mon-x","version":0,"paused_node_ids":["node-b"]}`, cookies, csrf)
	view := decodeMonitorView(t, res)
	if res.StatusCode != http.StatusOK || view.Version != 1 {
		t.Fatalf("pause = %d %+v", res.StatusCode, view)
	}
	if got := st.MonitorsForNode("node-b"); len(got) != 0 {
		t.Fatalf("paused source handed %+v", got)
	}
	if got := st.MonitorsForNode("node-a"); len(got) != 1 {
		t.Fatalf("running source handed %+v", got)
	}
	now := time.Now().UTC()
	out, err := st.IngestAgentMonitorResults("node-b", []model.MonitorResult{{MonitorID: "mon-x", At: now, Success: true}}, now)
	if err != nil || out[0].Dropped != store.MonitorResultDropNotAssigned {
		t.Fatalf("paused source result = %+v %v", out, err)
	}
	// Taking node-b off the check drops it from the paused list too.
	res = doJSON(t, handler, http.MethodPost, "/api/monitors/update", `{"id":"mon-x","version":1,"node_ids":["node-a"]}`, cookies, csrf)
	view = decodeMonitorView(t, res)
	if len(view.PausedNodeIDs) != 0 || len(view.NodeIDs) != 1 {
		t.Fatalf("after unassigning = %+v", view)
	}
}

// A token confined to some nodes edits only checks on its nodes and cannot
// add a source outside them.
func TestMonitorUpdateIsNodeScoped(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	upsertNodes(t, st, model.Node{ID: "node-a", Name: "a"}, model.Node{ID: "node-b", Name: "b"})
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-x", Name: "x", Type: model.MonitorTypeTCP, Target: "203.0.113.9:443", IntervalSec: 30, TimeoutSec: 5, NodeIDs: []string{"node-a"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-b", Name: "b", Type: model.MonitorTypeTCP, Target: "203.0.113.9:443", IntervalSec: 30, TimeoutSec: 5, NodeIDs: []string{"node-b"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	confined := createPAT(t, handler, cookies, csrf, []string{"monitor:admin", "monitor:read"}, []string{"node-a"})
	for body, want := range map[string]int{
		`{"id":"mon-x","version":0,"name":"renamed"}`:               http.StatusOK,
		`{"id":"mon-x","version":1,"node_ids":["node-a","node-b"]}`: http.StatusForbidden,
		`{"id":"mon-x","version":1,"assign_all":true}`:              http.StatusForbidden,
		`{"id":"mon-b","version":0,"name":"not mine"}`:              http.StatusForbidden,
	} {
		res := doBearerJSON(t, handler, http.MethodPost, "/api/monitors/update", body, confined)
		res.Body.Close()
		if res.StatusCode != want {
			t.Errorf("%s = %d, want %d", body, res.StatusCode, want)
		}
	}
}

// Generated latency checks and checks whose alert policy is off never page,
// so the incidents list shows no pending incident for them, the legacy
// adoption opens none, and an incident opened before alerts were turned off
// is closed by the sweep.
func TestNonPagingMonitorsOpenNoIncidents(t *testing.T) {
	srv, _, st := newPathsServer(t)
	now := time.Now().UTC()
	srv.now = func() time.Time { return now }
	upsertNodes(t, st, model.Node{ID: "node-a", Name: "a", Online: true, LastSeen: now})
	for _, mon := range []model.Monitor{
		{ID: latencyMonitorID("node-t"), Name: "Latency to t", Type: model.MonitorTypeTCP, Target: "203.0.113.2:443", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-a"}, Enabled: true, ManagedBy: model.MonitorManagedLatency},
		{ID: "mon-quiet", Name: "quiet", Type: model.MonitorTypeTCP, Target: "203.0.113.3:443", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-a"}, Enabled: true, Alert: model.MonitorAlertOff},
		{ID: "mon-loud", Name: "loud", Type: model.MonitorTypeTCP, Target: "203.0.113.4:443", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-a"}, Enabled: true},
	} {
		if err := st.UpsertMonitor(mon); err != nil {
			t.Fatal(err)
		}
	}
	fail := func(monitorID string, at time.Time) {
		out, err := st.IngestAgentMonitorResults("node-a", []model.MonitorResult{{MonitorID: monitorID, At: at, Success: false, Error: "refused"}}, now)
		if err != nil || !out[0].Stored() {
			t.Fatalf("ingest %s = %+v %v", monitorID, out, err)
		}
		srv.notifyMonitorTransition("node-a", out[0].Result.MonitorResult, out[0].PriorFailStreak)
	}
	for _, id := range []string{latencyMonitorID("node-t"), "mon-quiet", "mon-loud"} {
		fail(id, now.Add(-2*time.Minute))
	}
	pending := map[string]bool{}
	for _, inc := range srv.pendingIncidents(now) {
		pending[inc.MonitorID] = true
	}
	if pending[latencyMonitorID("node-t")] || pending["mon-quiet"] || !pending["mon-loud"] {
		t.Fatalf("pending incidents by monitor = %v", pending)
	}
	for _, id := range []string{latencyMonitorID("node-t"), "mon-quiet", "mon-loud"} {
		fail(id, now.Add(-time.Minute))
	}
	open := func(monitorID string) bool {
		_, ok := st.ActiveIncident(incidentKey(EventMonitorDown, "node-a", monitorID))
		return ok
	}
	if open(latencyMonitorID("node-t")) || open("mon-quiet") || !open("mon-loud") {
		t.Fatalf("open after two failures: latency %v quiet %v loud %v", open(latencyMonitorID("node-t")), open("mon-quiet"), open("mon-loud"))
	}
	// Adoption of pre-incident pages skips the pairs that could not page.
	inc, _ := st.ActiveIncident(incidentKey(EventMonitorDown, "node-a", "mon-loud"))
	if err := st.DeleteIncidentsWhere(func(store.Incident) bool { return true }); err != nil {
		t.Fatal(err)
	}
	srv.adoptLegacyAlerts(now)
	if open(latencyMonitorID("node-t")) || open("mon-quiet") || !open("mon-loud") {
		t.Fatalf("adopted: latency %v quiet %v loud %v (was %s)", open(latencyMonitorID("node-t")), open("mon-quiet"), open("mon-loud"), inc.ID)
	}
	// Turning alerts off closes what is open at the next sweep.
	loud, _ := st.Monitor("mon-loud")
	loud.Alert = model.MonitorAlertOff
	if _, err := st.UpdateMonitor(loud, loud.Version, now); err != nil {
		t.Fatal(err)
	}
	srv.evaluateIncidents(now)
	if open("mon-loud") {
		t.Fatal("an incident of a check whose alerts are off stayed open")
	}
}

// No generated check with history is deleted while its target node exists,
// whatever the configuration does to it; deleting the target node deletes
// it. SyncManagedMonitors deletes history with a monitor, so this is what
// keeps a path's week of history across configuration changes.
func TestGeneratedCheckWithHistoryOutlivesConfigurationChanges(t *testing.T) {
	srv, _, st := latencyFleet(t)
	if _, _, err := srv.syncLatencyProbes(time.Now()); err != nil {
		t.Fatal(err)
	}
	id := latencyMonitorID("node-jp")
	now := time.Now().UTC()
	if out, err := st.IngestAgentMonitorResults("node-sh", []model.MonitorResult{{MonitorID: id, At: now, Success: true, LatencyMs: 40}}, now); err != nil || !out[0].Stored() {
		t.Fatalf("seed = %+v %v", out, err)
	}
	cfg := model.LatencyProbeConfig{Enabled: true, IntervalSec: 60, TimeoutSec: 5, Sources: []string{"node-sh"}, AutoTargets: true}
	version := int64(0)
	save := func(c model.LatencyProbeConfig) {
		t.Helper()
		stored, err := st.SetLatencyProbeConfig(c, version, "admin", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		version = stored.Version
		if _, _, err := srv.syncLatencyProbes(time.Now()); err != nil {
			t.Fatal(err)
		}
		mon, ok := st.Monitor(id)
		if !ok {
			t.Fatalf("config %+v deleted the generated check", c)
		}
		if _, ok, _ := st.MonitorLatest(id, "node-sh"); !ok || mon.ManagedBy != model.MonitorManagedLatency {
			t.Fatalf("config %+v lost the check's history", c)
		}
	}
	excluded := cfg
	excluded.ExcludeTargets = []string{"node-jp"}
	off := cfg
	off.Enabled = false
	noAuto := cfg
	noAuto.AutoTargets = false
	noSource := cfg
	noSource.Sources = []string{"node-bj"}
	pairOff := cfg
	pairOff.DisabledPairs = []model.LatencyPair{{Source: "node-sh", Target: "node-jp"}}
	for _, c := range []model.LatencyProbeConfig{excluded, off, noAuto, noSource, pairOff, cfg} {
		save(c)
	}
	// The target loses its lines: not probeable, still kept.
	srv.singboxInvMu.Lock()
	srv.singboxInv["node-jp"] = model.SingBoxInventory{NodeID: "node-jp", At: time.Now(), Status: "ok"}
	srv.singboxInvMu.Unlock()
	save(cfg)
	n, _ := st.Node("node-jp")
	n.Disabled = true
	upsertNodes(t, st, n)
	save(cfg)
	if _, _, err := st.DeleteNode("node-jp"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := srv.syncLatencyProbes(time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Monitor(id); ok {
		t.Fatal("the generated check survived its target node")
	}
}

// History taken before this release keeps its check ids and stays readable
// through the new reads: a sync with the new code keeps the generated
// check, its rows and rollups answer the series and the matrix, and the
// first sweep under the new tiers deletes none of it.
func TestLatencyHistoryKeepsItsIDsUnderTheNewTiers(t *testing.T) {
	srv, _, st := newPathsServer(t)
	now := time.Now().UTC()
	srv.now = func() time.Time { return now }
	upsertNodes(t, st,
		model.Node{ID: "node-sh", Name: "cd-hs-sh", Online: true, Geo: &model.NodeGeo{Country: "CN"}},
		model.Node{ID: "node-jp", Name: "jp", PublicIP: "203.0.113.3", Online: true, Geo: &model.NodeGeo{Country: "JP"}},
	)
	id := latencyMonitorID("node-jp")
	prior := model.Monitor{ID: id, Name: "Latency to jp", Type: model.MonitorTypeTCP, Target: "203.0.113.3:443", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-sh"}, Enabled: true, ManagedBy: model.MonitorManagedLatency}
	if err := st.UpsertMonitor(prior); err != nil {
		t.Fatal(err)
	}
	created, _ := st.Monitor(id)
	// Two days of hourly results, then the last hour every minute, as the
	// previous release stored them (48 h fine, 8 d coarse).
	var batch []model.MonitorResult
	for h := 47; h >= 2; h-- {
		batch = append(batch, model.MonitorResult{MonitorID: id, At: now.Add(-time.Duration(h) * time.Hour), Success: true, LatencyMs: 60})
	}
	for m := 60; m >= 1; m-- {
		batch = append(batch, model.MonitorResult{MonitorID: id, At: now.Add(-time.Duration(m) * time.Minute), Success: m%15 != 0, LatencyMs: 55})
	}
	for _, r := range batch {
		if _, err := st.IngestAgentMonitorResults("node-sh", []model.MonitorResult{r}, r.At); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := srv.syncLatencyProbes(now); err != nil {
		t.Fatal(err)
	}
	mon, ok := st.Monitor(id)
	if !ok || mon.ID != id || !mon.CreatedAt.Equal(created.CreatedAt) {
		t.Fatalf("after the sync = %+v %v", mon, ok)
	}
	report, err := srv.pruneMonitorHistory(t.Context())
	if err != nil || report.Rows+report.Fine+report.Coarse != 0 {
		t.Fatalf("first sweep = %+v %v", report, err)
	}
	day, err := srv.pathSeriesFor(srv.generatedPathChecks("node-jp"), "node-sh", model.PathWindowDay, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	runs := 0
	for _, b := range day.Buckets {
		runs += b.N
	}
	// The window is the 288 five-minute steps up to the one holding now, so
	// it starts after now minus 24 h and the hourly result taken exactly
	// then is outside it.
	if runs != 22+60 {
		t.Fatalf("24h series holds %d runs, want the 22 hourly and 60 recent ones", runs)
	}
	m, err := srv.pathMatrixFor(principal{Principal: adminPrincipalForTest()}, model.PathWindowThreeDays, now)
	if err != nil {
		t.Fatal(err)
	}
	// The 3d matrix counts the whole hours before the one in progress.
	inWindow := 0
	for _, r := range batch {
		if hour := now.Truncate(time.Hour); r.At.Before(hour) && !r.At.Before(hour.Add(-72*time.Hour)) {
			inWindow++
		}
	}
	cell := pathCellTo(t, m, "node-sh", "node-jp")
	if cell.MonitorID != id || cell.Samples != inWindow || cell.State != model.PathStateUp {
		t.Fatalf("3d matrix cell = %+v, want %d samples", cell, inWindow)
	}
	// The latency reads of the previous release still answer.
	rollups, err := srv.latencyRollupsFor(srv.planLatencyProbes(now).plan, now)
	if err != nil || len(rollups.Pairs) != 1 || rollups.Pairs[0].Windows[model.LatencyWindowWeek].Samples != len(batch) {
		t.Fatalf("latency rollups = %+v %v", rollups, err)
	}
}
