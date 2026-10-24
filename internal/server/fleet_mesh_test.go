package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/store"
)

var meshT0 = time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)

// meshFleet is a fleet shaped like production's on 2026-10-24: the default
// source cd-hs-sh in mainland China; six nodes outside it serving a TCP
// line; three outside it that have reported no line inventory, so TCP has
// nothing to dial (not_probeable, no_inventory); one more mainland node; and
// five nodes the operator excluded.
func meshFleet(t *testing.T, dir string) (*Server, http.Handler, *store.Store) {
	t.Helper()
	srv, handler, st := newPathsServerAt(t, dir)
	serverClock(t, srv).set(meshT0)
	all := []string{"beacon", "http", "icmp", "tcp"}
	node := func(id, country, ip string) model.Node {
		return model.Node{ID: id, Name: id, PublicIP: ip, Online: true, ProbeMethods: all, Geo: &model.NodeGeo{Country: country}}
	}
	nodes := []model.Node{
		node("cd-hs-sh", "CN", "203.0.113.1"),
		node("node-bj", "CN", "203.0.113.2"),
	}
	lined := []string{"node-jp", "node-us", "node-de", "node-sg", "node-hk", "node-uk"}
	for _, id := range lined {
		nodes = append(nodes, node(id, "JP", ""))
	}
	for _, id := range []string{"node-bare1", "node-bare2", "node-bare3"} {
		nodes = append(nodes, node(id, "US", ""))
	}
	for _, id := range []string{"node-x1", "node-x2", "node-x3", "node-x4", "node-x5"} {
		nodes = append(nodes, node(id, "DE", ""))
	}
	for i := range nodes {
		// A public test address for each node, which icmp and the port
		// rule both accept.
		nodes[i].PublicIP = "203.0.113." + strconv.Itoa(10+i)
	}
	upsertNodes(t, st, nodes...)
	srv.singboxInvMu.Lock()
	if srv.singboxInv == nil {
		srv.singboxInv = map[string]model.SingBoxInventory{}
	}
	for _, id := range append(slices.Clone(lined), "cd-hs-sh", "node-bj", "node-x1", "node-x2", "node-x3", "node-x4", "node-x5") {
		n, _ := st.Node(id)
		srv.singboxInv[id] = model.SingBoxInventory{NodeID: id, At: meshT0, Status: "ok", Nodes: []model.SingBoxNode{
			{Name: "vless-443", Protocol: "vless", Network: "reality", Port: "443", ListenHost: "::", Address: n.PublicIP},
		}}
	}
	srv.singboxInvMu.Unlock()
	srv.monitorPaths.forget()
	return srv, handler, st
}

// meshConfig is production's path set: enabled, every 60 s, timeout 5 s,
// one source, tcp, the region rule, five excluded targets, alerts on down.
func meshConfig() model.LatencyProbeConfig {
	return model.LatencyProbeConfig{
		Enabled: true, IntervalSec: 60, TimeoutSec: 5,
		Sources:        []string{"cd-hs-sh"},
		AutoTargets:    true,
		ExcludeTargets: []string{"node-x1", "node-x2", "node-x3", "node-x4", "node-x5"},
		Alert:          model.MonitorAlertDown,
	}
}

func storePathSet(t *testing.T, st *store.Store, cfg model.LatencyProbeConfig) {
	t.Helper()
	if _, err := st.SetLatencyProbeConfig(cfg, 0, "admin", meshT0); err != nil {
		t.Fatal(err)
	}
}

// pairState is one pair as the path set plan or the matrix states it.
type pairState struct {
	method, monitorID, measure, reason string
}

func pathSetPairs(t *testing.T, srv *Server) map[string]pairState {
	t.Helper()
	srv.monitorPaths.forget()
	out := map[string]pairState{}
	for _, pair := range srv.planLatencyProbes(srv.now()).plan.Pairs {
		ps := pairState{method: pair.Method, monitorID: pair.MonitorID}
		switch {
		case pair.Active:
			ps.measure = model.PathMeasured
		case pair.Reason != "":
			ps.measure, ps.reason = model.PathSkipped, pair.Reason
		default:
			ps.measure = model.PathPaused
		}
		if !pair.Active {
			ps.monitorID = ""
		}
		out[pair.Source+"~"+pair.Target] = ps
	}
	return out
}

func matrixPairs(t *testing.T, srv *Server) map[string]pairState {
	t.Helper()
	srv.monitorPaths.forget()
	m, err := srv.pathMatrixFor(principal{Principal: adminPrincipalForTest()}, model.PathWindowHour, srv.now())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]pairState{}
	for _, cell := range m.Paths {
		if cell.TargetNode == "" {
			continue
		}
		ps := pairState{method: cell.Method, monitorID: cell.MonitorID, measure: model.PathMeasurement(cell.State, cell.Reason)}
		if ps.measure != model.PathMeasured {
			ps.reason, ps.monitorID = cell.Reason, ""
		}
		key := cell.Source + "~" + cell.TargetNode
		if _, dup := out[key]; dup {
			t.Fatalf("pair %s has two cells", key)
		}
		out[key] = ps
	}
	return out
}

// runsOf counts the stored results of every (monitor, source) pair named.
func runsOf(t *testing.T, st *store.Store, pairs map[string]pairState) map[string]int {
	t.Helper()
	out := map[string]int{}
	for key, ps := range pairs {
		if ps.monitorID == "" {
			continue
		}
		source := strings.SplitN(key, "~", 2)[0]
		rows, err := st.MonitorPairResultsBetween(ps.monitorID, source, meshT0.Add(-time.Hour), meshT0.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		out[ps.monitorID+"/"+source] = len(rows)
	}
	return out
}

// Design 32 R1 and its test list: a path set shaped like production's
// migrates to one definition whose expansion equals the path set's plan
// pair for pair, with every monitor id and run history unchanged; the
// region rule becomes the fleet minus what it left out; running the
// migration again changes nothing.
func TestFleetMeshMigrationMatchesThePathSet(t *testing.T) {
	srv, _, st := meshFleet(t, t.TempDir())
	storePathSet(t, st, meshConfig())
	if _, _, err := srv.syncLatencyProbes(meshT0); err != nil {
		t.Fatal(err)
	}
	before := pathSetPairs(t, srv)
	measured, skipped := 0, 0
	for key, ps := range before {
		switch ps.measure {
		case model.PathMeasured:
			measured++
			source := strings.SplitN(key, "~", 2)[0]
			for i := range 3 {
				if _, err := st.AddMonitorResult(model.MonitorResult{MonitorID: ps.monitorID, NodeID: source, At: meshT0.Add(-time.Duration(i+1) * time.Minute), Success: true, LatencyMs: 40}); err != nil {
					t.Fatal(err)
				}
			}
		case model.PathSkipped:
			skipped++
		}
	}
	if measured != 6 || skipped != 3 {
		t.Fatalf("the fixture's path set measures %d and skips %d pairs, want 6 and 3: %+v", measured, skipped, before)
	}
	runsBefore := runsOf(t, st, before)

	migrated, err := srv.migratePathSet(meshT0)
	if err != nil || !migrated {
		t.Fatalf("migrate = %v %v", migrated, err)
	}
	defs := st.CheckDefinitions()
	if len(defs) != 1 {
		t.Fatalf("definitions = %+v", defs)
	}
	def := defs[0]
	wantTargets := model.TargetSelector{All: true, Exclude: []string{"cd-hs-sh", "node-bj", "node-x1", "node-x2", "node-x3", "node-x4", "node-x5"}}
	if def.ID != model.CheckFleetMeshID || def.Name != model.CheckFleetMeshName || def.Type != model.MonitorTypeTCP || !def.Enabled ||
		!slices.Equal(def.Sources.Nodes, []string{"cd-hs-sh"}) || def.Targets.All != wantTargets.All || !slices.Equal(def.Targets.Exclude, wantTargets.Exclude) ||
		def.IntervalSec != 60 || def.TimeoutSec != 5 || def.Alert != model.MonitorAlertDown || len(def.ExcludedPairs) != 0 {
		t.Fatalf("Fleet mesh = %+v", def)
	}
	var adopted []string
	for _, a := range def.Adopted {
		adopted = append(adopted, a.MonitorID)
	}
	sort.Strings(adopted)
	var pathSetIDs []string
	for _, ps := range before {
		if ps.monitorID != "" {
			pathSetIDs = append(pathSetIDs, ps.monitorID)
		}
	}
	sort.Strings(pathSetIDs)
	if !slices.Equal(adopted, pathSetIDs) {
		t.Fatalf("adopted %v, the path set's monitors %v", adopted, pathSetIDs)
	}
	cfg, _ := st.LatencyProbeConfig()
	if cfg.Migrated == nil || !slices.Equal(cfg.Migrated.Definitions, []string{model.CheckFleetMeshID}) || cfg.Sources[0] != "cd-hs-sh" {
		t.Fatalf("the stored path set = %+v", cfg)
	}
	ev := lastAudit(t, st, "monitor.latency.migrate")
	if ev.Metadata["left_out"] != "cd-hs-sh,node-bj" || !strings.Contains(ev.Metadata["note"], "joins later") {
		t.Fatalf("migration audit = %+v", ev.Metadata)
	}

	after := matrixPairs(t, srv)
	if len(after) != len(before) {
		t.Fatalf("pairs before %d, after %d:\n%+v\n%+v", len(before), len(after), before, after)
	}
	for key, want := range before {
		got, ok := after[key]
		if !ok || got.method != want.method || got.measure != want.measure || got.monitorID != want.monitorID || got.reason != want.reason {
			t.Fatalf("pair %s: path set %+v, definition %+v", key, want, got)
		}
	}
	if runsAfter := runsOf(t, st, before); !mapsEqual(runsBefore, runsAfter) {
		t.Fatalf("runs before %v, after %v", runsBefore, runsAfter)
	}
	for _, id := range pathSetIDs {
		mon, _ := st.Monitor(id)
		if mon.ManagedBy != model.MonitorManagedLatency || mon.CheckDefinitionID != model.CheckFleetMeshID || store.MonitorOwnerOf(mon) != store.MonitorOwnerDefinition {
			t.Fatalf("adopted %s = managed_by %q definition %q", id, mon.ManagedBy, mon.CheckDefinitionID)
		}
	}

	// Again: the marker holds, and a sweep has nothing left to write.
	if again, err := srv.migratePathSet(meshT0.Add(time.Minute)); err != nil || again {
		t.Fatalf("second migration = %v %v", again, err)
	}
	if _, _, err := srv.syncLatencyProbes(meshT0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	changes, err := srv.syncCheckDefinitions(meshT0.Add(time.Minute), "sweep")
	if err != nil {
		t.Fatal(err)
	}
	for owner, c := range changes {
		if c.Changed() {
			t.Fatalf("a sweep after the migration rewrote %s: %+v", owner, c)
		}
	}
	if got := st.CheckDefinitions(); len(got) != 1 || got[0].Version != def.Version {
		t.Fatalf("definitions after the second run = %+v", got)
	}
}

func mapsEqual(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// The same inputs always migrate to the same definitions and adoption:
// what lets a roll-forward after a rollback, which migrates again from the
// path set the older release ran, land on the same ids.
func TestFleetMeshMigrationIsDeterministic(t *testing.T) {
	srv, _, st := meshFleet(t, t.TempDir())
	cfg := meshConfig()
	cfg.DisabledPairs = []model.LatencyPair{{Source: "cd-hs-sh", Target: "node-us"}}
	storePathSet(t, st, cfg)
	if _, _, err := srv.syncLatencyProbes(meshT0); err != nil {
		t.Fatal(err)
	}
	var pathSet []model.Monitor
	for _, mon := range st.Monitors() {
		if store.MonitorOwnerOf(mon) == store.MonitorOwnerPathSet {
			pathSet = append(pathSet, mon)
		}
	}
	a := planFleetMeshMigration(cfg, st.Nodes(), pathSet, nil, meshT0)
	b := planFleetMeshMigration(cfg, st.Nodes(), slices.Clone(pathSet), nil, meshT0)
	ja, _ := json.Marshal(a.defs)
	jb, _ := json.Marshal(b.defs)
	if string(ja) != string(jb) || !mapsEqualString(a.adopt, b.adopt) {
		t.Fatalf("two migrations of the same path set differ:\n%s\n%s", ja, jb)
	}
	if got := a.defs[0].ExcludedPairs; len(got) != 1 || got[0] != (model.LatencyPair{Source: "cd-hs-sh", Target: "node-us"}) {
		t.Fatalf("disabled pairs became %+v", got)
	}
	// A re-migration keeps the stored definition's creation and moves its
	// version on.
	prior := a.defs[0]
	prior.Version = 7
	c := planFleetMeshMigration(cfg, st.Nodes(), pathSet, map[string]model.CheckDefinition{prior.ID: prior}, meshT0.Add(time.Hour))
	if c.defs[0].Version != 8 || !c.defs[0].CreatedAt.Equal(prior.CreatedAt) || !mapsEqualString(a.adopt, c.adopt) {
		t.Fatalf("re-migration = version %d created %v", c.defs[0].Version, c.defs[0].CreatedAt)
	}
}

func mapsEqualString(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// For one release the path set API reads as migrated, names the
// definitions, and refuses writes with that pointer; the store refuses a
// save that would drop the marker too.
func TestMigratedPathSetIsReadOnly(t *testing.T) {
	srv, handler, st := meshFleet(t, t.TempDir())
	storePathSet(t, st, meshConfig())
	if _, err := srv.migratePathSet(meshT0); err != nil {
		t.Fatal(err)
	}
	c := newCheckClient(t, handler)
	code, raw := c.do(http.MethodGet, "/api/monitors/latency", nil)
	var plan model.LatencyProbePlan
	if code != http.StatusOK || json.Unmarshal([]byte(raw), &plan) != nil || plan.Config.Migrated == nil || len(plan.Pairs) != 0 {
		t.Fatalf("read = %d %s", code, raw)
	}
	for _, n := range plan.Nodes {
		if n.Target != model.LatencyTargetNone || n.TargetReason != model.LatencyReasonMigrated {
			t.Fatalf("a migrated plan's node = %+v", n)
		}
	}
	jp := slices.IndexFunc(plan.Nodes, func(n model.LatencyProbeNode) bool { return n.NodeID == "node-jp" })
	if jp < 0 || plan.Nodes[jp].Endpoint == "" {
		t.Fatalf("a migrated plan still reports endpoints: %+v", plan.Nodes)
	}
	next := meshConfig()
	next.Version = plan.Config.Version
	code, raw = c.do(http.MethodPut, "/api/monitors/latency", next)
	if code != http.StatusConflict || apiErrorOf(t, raw).Code != model.APIErrorPathSetMigrated || !strings.Contains(raw, model.CheckFleetMeshID) {
		t.Fatalf("write = %d %s", code, raw)
	}
	if _, err := st.SetLatencyProbeConfig(next, next.Version, "admin", meshT0); err != store.ErrPathSetMigrated {
		t.Fatalf("store save = %v", err)
	}
	code, raw = c.do(http.MethodGet, "/api/monitors/definitions", nil)
	var list model.CheckDefinitionList
	if code != http.StatusOK || json.Unmarshal([]byte(raw), &list) != nil || !list.FleetMesh.Migrated || !slices.Equal(list.FleetMesh.Definitions, []string{model.CheckFleetMeshID}) || len(list.Definitions) != 1 {
		t.Fatalf("list = %d %s", code, raw)
	}
}

// A fresh install seeds the same definition from today's defaults, and an
// operator who deletes it does not get it back at the next start.
func TestFreshInstallSeedsFleetMesh(t *testing.T) {
	dir := t.TempDir()
	srv, handler, st := meshFleet(t, dir)
	if migrated, err := srv.migratePathSet(meshT0); err != nil || !migrated {
		t.Fatalf("seed = %v %v", migrated, err)
	}
	def, ok := st.CheckDefinition(model.CheckFleetMeshID)
	if !ok || def.Type != model.MonitorTypeTCP || !slices.Equal(def.Sources.Nodes, []string{"cd-hs-sh"}) || !def.Targets.All || def.Alert != model.MonitorAlertOff || len(def.Adopted) != 0 {
		t.Fatalf("seeded = %+v", def)
	}
	cfg, stored := st.LatencyProbeConfig()
	if !stored || cfg.Migrated == nil {
		t.Fatalf("the defaults are stored as migrated: %+v %v", cfg, stored)
	}
	c := newCheckClient(t, handler)
	view := c.get(model.CheckFleetMeshID)
	var ids []string
	for _, m := range view.Monitors {
		ids = append(ids, m.MonitorID)
	}
	code, raw := c.do(http.MethodPost, "/api/monitors/definitions/delete", model.CheckDefinitionDelete{ID: view.ID, Version: view.Version, MonitorIDs: ids})
	if code != http.StatusOK {
		t.Fatalf("delete = %d %s", code, raw)
	}
	if again, err := srv.migratePathSet(meshT0.Add(time.Hour)); err != nil || again {
		t.Fatalf("after a delete = %v %v", again, err)
	}
	if _, ok := st.CheckDefinition(model.CheckFleetMeshID); ok {
		t.Fatal("Fleet mesh came back after the operator deleted it")
	}
}

// Per-source method pins become one definition per distinct method, and
// auto keeps choosing per pair: beacon is not enabled here, icmp wins where
// the source runs it and tcp where the agent is too old for icmp.
func TestFleetMeshMigrationOfMethodsAndPins(t *testing.T) {
	srv, _, st := meshFleet(t, t.TempDir())
	old, _ := st.Node("node-bj")
	old.ProbeMethods = []string{"tcp"}
	upsertNodes(t, st, old)
	cfg := meshConfig()
	cfg.Method = model.LatencyMethodAuto
	cfg.Sources = []string{"cd-hs-sh", "node-bj", "node-jp"}
	cfg.SourceMethods = map[string]string{"node-jp": model.LatencyMethodTCP}
	cfg.ExcludeTargets = nil
	storePathSet(t, st, cfg)
	if _, _, err := srv.syncLatencyProbes(meshT0); err != nil {
		t.Fatal(err)
	}
	before := pathSetPairs(t, srv)
	if _, err := srv.migratePathSet(meshT0); err != nil {
		t.Fatal(err)
	}
	defs := st.CheckDefinitions()
	byID := map[string]model.CheckDefinition{}
	for _, d := range defs {
		byID[d.ID] = d
	}
	auto, tcp := byID[model.CheckFleetMeshID], byID[model.CheckFleetMeshID+"_tcp"]
	if len(defs) != 2 || auto.Type != model.CheckMethodAuto || !slices.Equal(auto.Sources.Nodes, []string{"cd-hs-sh", "node-bj"}) ||
		tcp.Type != model.MonitorTypeTCP || !slices.Equal(tcp.Sources.Nodes, []string{"node-jp"}) || tcp.Name != "Fleet mesh (TCP)" || auto.Packets != model.MonitorPacketsDefault {
		t.Fatalf("definitions = %+v", defs)
	}
	after := matrixPairs(t, srv)
	for key, want := range before {
		got := after[key]
		if want.measure == model.PathMeasured && (got.method != want.method || got.measure != want.measure) {
			t.Fatalf("pair %s: path set %+v, definitions %+v", key, want, got)
		}
	}
	sawICMP, sawTCP := false, false
	for key, ps := range after {
		if strings.HasPrefix(key, "cd-hs-sh~") && ps.method == model.MonitorTypeICMP {
			sawICMP = true
		}
		if strings.HasPrefix(key, "node-bj~") && ps.method == model.MonitorTypeTCP {
			sawTCP = true
		}
	}
	if !sawICMP || !sawTCP {
		t.Fatalf("auto chose icmp from cd-hs-sh %v and tcp from the old agent %v: %+v", sawICMP, sawTCP, after)
	}
}

// The state file holds a definition that adopted path set monitors as
// paused, with its own setting beside it, so the release before the
// migration plans it paused; this release reads it back as it was.
func TestAdoptingDefinitionPersistsPausedForTheOlderRelease(t *testing.T) {
	dir := t.TempDir()
	srv, _, st := meshFleet(t, dir)
	storePathSet(t, st, meshConfig())
	if _, _, err := srv.syncLatencyProbes(meshT0); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.migratePathSet(meshT0); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var onDisk struct {
		CheckDefinitions        map[string]model.CheckDefinition `json:"check_definitions"`
		CheckDefinitionsEnabled map[string]bool                  `json:"check_definitions_enabled"`
	}
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatal(err)
	}
	if d := onDisk.CheckDefinitions[model.CheckFleetMeshID]; d.Enabled || !onDisk.CheckDefinitionsEnabled[model.CheckFleetMeshID] {
		t.Fatalf("on disk: enabled %v, kept %v", d.Enabled, onDisk.CheckDefinitionsEnabled)
	}
	if def, _ := st.CheckDefinition(model.CheckFleetMeshID); !def.Enabled {
		t.Fatal("in memory the definition stays enabled")
	}
	srv.Close(t.Context())
	st.Close()
	reopened, err := store.OpenWithCipher(filepath.Join(dir, "state.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if def, _ := reopened.CheckDefinition(model.CheckFleetMeshID); !def.Enabled || len(def.Adopted) == 0 {
		t.Fatalf("reopened = %+v", def)
	}
}

// The migration runs at start, before any agent has reported its lines
// again: an adopted check keeps what it dialled and keeps measuring, and
// once the lines are back the sweep changes nothing.
func TestFleetMeshMigrationAtStartBeforeTheLinesReturn(t *testing.T) {
	srv, _, st := meshFleet(t, t.TempDir())
	storePathSet(t, st, meshConfig())
	if _, _, err := srv.syncLatencyProbes(meshT0); err != nil {
		t.Fatal(err)
	}
	before := pathSetPairs(t, srv)
	targets := map[string]string{}
	for _, mon := range st.Monitors() {
		targets[mon.ID] = mon.Target
	}
	srv.singboxInvMu.Lock()
	srv.singboxInv = map[string]model.SingBoxInventory{}
	srv.singboxInvMu.Unlock()
	srv.monitorPaths.dropPlan()
	at := meshT0.Add(time.Minute)
	if migrated, err := srv.migratePathSet(at); err != nil || !migrated {
		t.Fatalf("migrate = %v %v", migrated, err)
	}
	for key, ps := range before {
		if ps.measure != model.PathMeasured {
			continue
		}
		mon, ok := st.Monitor(ps.monitorID)
		if !ok || !mon.Enabled || mon.Target != targets[ps.monitorID] || !slices.Contains(mon.NodeIDs, strings.SplitN(key, "~", 2)[0]) {
			t.Fatalf("at start %s reads %+v, before it dialled %q", ps.monitorID, mon, targets[ps.monitorID])
		}
	}
	meshInventory(srv, st, at)
	srv.monitorPaths.dropPlan()
	changes, err := srv.syncCheckDefinitions(at.Add(time.Minute), "sweep")
	if err != nil {
		t.Fatal(err)
	}
	for owner, c := range changes {
		if c.Changed() {
			t.Fatalf("the sweep after the lines returned rewrote %s: %+v", owner, c)
		}
	}
}
