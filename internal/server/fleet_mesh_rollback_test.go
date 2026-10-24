package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// The rollback proof of design 32 R1, run by hand across two releases:
//
//	LATTICE_ROLLBACK_DIR=<dir> LATTICE_ROLLBACK_STEP=produce go test -run TestFleetMeshRollbackHarness ./internal/server/
//	(LATTICE_ROLLBACK_SHAPE=auto produces an auto path set with a pinned source;
//	auto-split adds an auto source that shares the pin's tcp monitors)
//	(in a checkout of the release before the migration, the resume step of
//	the same harness over <dir>)
//	LATTICE_ROLLBACK_DIR=<dir> LATTICE_ROLLBACK_STEP=forward go test -run TestFleetMeshRollbackHarness ./internal/server/
//
// produce migrates a production-shaped path set with run history and writes
// what it measures to <dir>/produce.json; forward opens the state the older
// release left, migrates it again and checks that the definitions, the
// adopted ids and every pair are what produce wrote, with the runs the older
// release added kept on the same ids, and that a second start changes
// nothing. Skipped unless LATTICE_ROLLBACK_DIR is set.

// rollbackSnapshot is what one release measured over the shared state.
type rollbackSnapshot struct {
	Pairs       map[string]pairStateJSON `json:"pairs"`
	Runs        map[string]int           `json:"runs"`
	Definitions []rollbackDefinition     `json:"definitions,omitempty"`
	Monitors    []string                 `json:"monitors"`
}

type pairStateJSON struct {
	Method    string `json:"method"`
	MonitorID string `json:"monitor_id"`
	Measure   string `json:"measure"`
	Reason    string `json:"reason"`
}

type rollbackDefinition struct {
	ID      string                `json:"id"`
	Type    string                `json:"type"`
	Enabled bool                  `json:"enabled"`
	Targets model.TargetSelector  `json:"targets"`
	Sources model.TargetSelector  `json:"sources"`
	Adopted []model.CheckAdoption `json:"adopted"`
}

var rollbackRunsFrom, rollbackRunsTo = meshT0.Add(-24 * time.Hour), meshT0.Add(24 * time.Hour)

func rollbackSnapshotOf(t *testing.T, srv *Server, st *store.Store) rollbackSnapshot {
	t.Helper()
	snap := rollbackSnapshot{Pairs: map[string]pairStateJSON{}, Runs: map[string]int{}}
	for key, ps := range matrixPairs(t, srv) {
		snap.Pairs[key] = pairStateJSON{Method: ps.method, MonitorID: ps.monitorID, Measure: ps.measure, Reason: ps.reason}
		if ps.monitorID == "" {
			continue
		}
		source := strings.SplitN(key, "~", 2)[0]
		rows, err := st.MonitorPairResultsBetween(ps.monitorID, source, rollbackRunsFrom, rollbackRunsTo)
		if err != nil {
			t.Fatal(err)
		}
		snap.Runs[ps.monitorID+"/"+source] = len(rows)
	}
	for _, def := range st.CheckDefinitions() {
		snap.Definitions = append(snap.Definitions, rollbackDefinition{ID: def.ID, Type: def.Type, Enabled: def.Enabled, Targets: def.Targets, Sources: def.Sources, Adopted: def.Adopted})
	}
	for _, mon := range st.Monitors() {
		snap.Monitors = append(snap.Monitors, mon.ID)
	}
	sort.Strings(snap.Monitors)
	return snap
}

func writeRollbackSnapshot(t *testing.T, path string, snap rollbackSnapshot) {
	t.Helper()
	raw, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readRollbackSnapshot(t *testing.T, path string) rollbackSnapshot {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var snap rollbackSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatal(err)
	}
	return snap
}

// meshInventory hands the fixture's nodes the lines meshFleet gives them, as
// their agents would report after a start.
func meshInventory(srv *Server, st *store.Store, at time.Time) {
	srv.singboxInvMu.Lock()
	defer srv.singboxInvMu.Unlock()
	srv.singboxInv = map[string]model.SingBoxInventory{}
	for _, id := range []string{"node-jp", "node-us", "node-de", "node-sg", "node-hk", "node-uk", "cd-hs-sh", "node-bj", "node-x1", "node-x2", "node-x3", "node-x4", "node-x5"} {
		n, _ := st.Node(id)
		srv.singboxInv[id] = model.SingBoxInventory{NodeID: id, At: at, Status: "ok", Nodes: []model.SingBoxNode{
			{Name: "vless-443", Protocol: "vless", Network: "reality", Port: "443", ListenHost: "::", Address: n.PublicIP},
		}}
	}
}

func TestFleetMeshRollbackHarness(t *testing.T) {
	dir := os.Getenv("LATTICE_ROLLBACK_DIR")
	if dir == "" {
		t.Skip("LATTICE_ROLLBACK_DIR is not set")
	}
	switch step := os.Getenv("LATTICE_ROLLBACK_STEP"); step {
	case "produce":
		rollbackProduce(t, dir)
	case "forward":
		rollbackForward(t, dir)
	default:
		t.Fatalf("LATTICE_ROLLBACK_STEP = %q, want produce or forward", step)
	}
}

func rollbackProduce(t *testing.T, dir string) {
	if _, err := os.Stat(filepath.Join(dir, "state.json")); err == nil {
		t.Fatalf("%s already holds a state", dir)
	}
	srv, _, st := meshFleet(t, dir)
	cfg := meshConfig()
	switch shape := os.Getenv("LATTICE_ROLLBACK_SHAPE"); shape {
	case "auto", "auto-split":
		// The other shape a path set takes: method auto with a source
		// pinned to tcp, which migrates to an auto chk_fleet_mesh, a type
		// the older release does not know, and chk_fleet_mesh_tcp. The
		// auto sources choose icmp, so the pin's tcp monitors are its own.
		cfg.Method = model.LatencyMethodAuto
		cfg.Sources = []string{"cd-hs-sh", "node-bj", "node-jp"}
		cfg.SourceMethods = map[string]string{"node-jp": model.LatencyMethodTCP}
		if shape == "auto-split" {
			// An auto source whose agent runs tcp only shares the pin's
			// tcp monitors, which one definition adopts and the other
			// cannot.
			old, _ := st.Node("node-bj")
			old.ProbeMethods = []string{"tcp"}
			upsertNodes(t, st, old)
		}
	}
	storePathSet(t, st, cfg)
	if _, _, err := srv.syncLatencyProbes(meshT0); err != nil {
		t.Fatal(err)
	}
	for key, ps := range pathSetPairs(t, srv) {
		if ps.measure != model.PathMeasured {
			continue
		}
		source := strings.SplitN(key, "~", 2)[0]
		for i := range 3 {
			if _, err := st.AddMonitorResult(model.MonitorResult{MonitorID: ps.monitorID, NodeID: source, At: meshT0.Add(-time.Duration(i+1) * time.Minute), Success: true, LatencyMs: 40}); err != nil {
				t.Fatal(err)
			}
		}
	}
	before := rollbackSnapshotOf(t, srv, st)
	writeRollbackSnapshot(t, filepath.Join(dir, "pathset.json"), before)
	if migrated, err := srv.migratePathSet(meshT0); err != nil || !migrated {
		t.Fatalf("migrate = %v %v", migrated, err)
	}
	after := rollbackSnapshotOf(t, srv, st)
	for key, want := range before.Pairs {
		if got := after.Pairs[key]; got.Measure == model.PathMeasured && got != want {
			t.Fatalf("pair %s: path set %+v, Fleet mesh %+v", key, want, got)
		}
	}
	writeRollbackSnapshot(t, filepath.Join(dir, "produce.json"), after)
	t.Logf("produced: %d pairs, %d monitors, definitions %+v", len(after.Pairs), len(after.Monitors), after.Definitions)
}

func rollbackForward(t *testing.T, dir string) {
	produced := readRollbackSnapshot(t, filepath.Join(dir, "produce.json"))
	resumed := readRollbackSnapshot(t, filepath.Join(dir, "a146.json"))
	srv, _, st := newPathsServerAt(t, dir)
	at := meshT0.Add(30 * time.Minute)
	serverClock(t, srv).set(at)
	meshInventory(srv, st, at)

	migrated, err := srv.migratePathSet(at)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("migrated again: %v", migrated)
	forward := rollbackSnapshotOf(t, srv, st)
	if len(forward.Definitions) != len(produced.Definitions) {
		t.Fatalf("definitions: produced %+v, forward %+v", produced.Definitions, forward.Definitions)
	}
	for i, want := range produced.Definitions {
		got := forward.Definitions[i]
		if got.ID != want.ID || got.Type != want.Type || got.Enabled != want.Enabled || !slices.Equal(got.Adopted, want.Adopted) ||
			!slices.Equal(got.Targets.Exclude, want.Targets.Exclude) || !slices.Equal(got.Sources.Nodes, want.Sources.Nodes) {
			t.Fatalf("definition %s: produced %+v, forward %+v", want.ID, want, got)
		}
	}
	for key, want := range produced.Pairs {
		got, ok := forward.Pairs[key]
		if !ok || got != want {
			t.Fatalf("pair %s: produced %+v, forward %+v", key, want, got)
		}
	}
	if len(forward.Pairs) != len(produced.Pairs) {
		t.Fatalf("pairs: produced %d, forward %d", len(produced.Pairs), len(forward.Pairs))
	}
	for pair, n := range resumed.Runs {
		if forward.Runs[pair] != n {
			t.Fatalf("runs of %s: the older release left %d, forward reads %d", pair, n, forward.Runs[pair])
		}
		if n <= produced.Runs[pair] {
			t.Fatalf("runs of %s: %d at migration, %d after the older release ran; the rollback recorded nothing", pair, produced.Runs[pair], n)
		}
	}
	if !slices.Equal(forward.Monitors, produced.Monitors) {
		t.Fatalf("monitors: produced %v, forward %v", produced.Monitors, forward.Monitors)
	}

	// A second start: the marker holds and nothing is written.
	if again, err := srv.migratePathSet(at.Add(time.Minute)); err != nil || again {
		t.Fatalf("second start = %v %v", again, err)
	}
	changes, err := srv.syncCheckDefinitions(at.Add(time.Minute), "sweep")
	if err != nil {
		t.Fatal(err)
	}
	for owner, c := range changes {
		if c.Changed() {
			t.Fatalf("a sweep after the roll-forward rewrote %s: %+v", owner, c)
		}
	}
	writeRollbackSnapshot(t, filepath.Join(dir, "forward.json"), forward)
	t.Logf("forward: %d pairs, %d monitors, runs %v", len(forward.Pairs), len(forward.Monitors), forward.Runs)
}
