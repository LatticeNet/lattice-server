package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// Design 32 R1 and R3: an excluded pair is a pair both sets hold that the
// definition never measures ("Stop measuring this pair" writes one through
// the normal save). Its monitor keeps its id and the pair's history, and
// including the pair again resumes it on the same id.
func TestExcludedPairStopsMeasuringAndKeepsHistory(t *testing.T) {
	srv, handler, st := checkFleet(t)
	c := newCheckClient(t, handler)
	view := c.create(tcpMesh([]string{"node-sh", "node-bj"}, []string{"node-jp", "node-us"}))
	jp := monitorTo(t, definitionMonitors(st, view.ID), "node-jp", "")
	if !slices.Equal(jp.NodeIDs, []string{"node-bj", "node-sh"}) {
		t.Fatalf("before = %v", jp.NodeIDs)
	}
	reportRun(t, st, jp.ID, "node-sh", checkT0.Add(-time.Minute))

	save := saveOf(view)
	save.ExcludedPairs = []model.LatencyPair{{Source: " node-sh ", Target: "node-jp"}, {Source: "node-sh", Target: "node-jp"}}
	view = c.update(save)
	if want := []model.LatencyPair{{Source: "node-sh", Target: "node-jp"}}; !slices.Equal(view.ExcludedPairs, want) {
		t.Fatalf("stored excluded pairs = %+v, want trimmed and without repeats", view.ExcludedPairs)
	}
	after := monitorTo(t, definitionMonitors(st, view.ID), "node-jp", "")
	if after.ID != jp.ID || !slices.Equal(after.NodeIDs, []string{"node-bj"}) {
		t.Fatalf("excluded = %s %v, want %s run from node-bj only", after.ID, after.NodeIDs, jp.ID)
	}
	if us := monitorTo(t, definitionMonitors(st, view.ID), "node-us", ""); !slices.Equal(us.NodeIDs, []string{"node-bj", "node-sh"}) {
		t.Fatalf("another target of the source is still measured: %v", us.NodeIDs)
	}
	if cells := pairCells(t, srv, "node-sh", "node-jp", view.ID); len(cells) != 0 {
		t.Fatalf("the excluded pair is still a path: %+v", cells)
	}
	if view.Summary.Paths != 3 {
		t.Fatalf("paths = %d, want 3 of the 4 pairs", view.Summary.Paths)
	}
	rows, err := st.MonitorPairResultsBetween(jp.ID, "node-sh", checkT0.Add(-time.Hour), checkT0)
	if err != nil || len(rows) != 1 {
		t.Fatalf("the pair's history while excluded = %d %v", len(rows), err)
	}

	save = saveOf(view)
	save.ExcludedPairs = nil
	view = c.update(save)
	again := monitorTo(t, definitionMonitors(st, view.ID), "node-jp", "")
	if again.ID != jp.ID || !slices.Equal(again.NodeIDs, []string{"node-bj", "node-sh"}) {
		t.Fatalf("included again = %s %v", again.ID, again.NodeIDs)
	}
	if rows, err := st.MonitorPairResultsBetween(jp.ID, "node-sh", checkT0.Add(-time.Hour), checkT0); err != nil || len(rows) != 1 {
		t.Fatalf("the pair's history after including it again = %d %v", len(rows), err)
	}
}

// A refused excluded pair names its place in the request (design 32 R6),
// and a token confined to some nodes may name only pairs of nodes it reads.
func TestExcludedPairRefusals(t *testing.T) {
	_, handler, _ := checkFleet(t)
	admin := newCheckClient(t, handler)
	refused := func(c *checkClient, save model.CheckDefinitionSave, status int, field string) {
		t.Helper()
		code, raw := c.do(http.MethodPost, "/api/monitors/definitions", save)
		if code != status || apiErrorOf(t, raw).Field != field {
			t.Fatalf("save = %d %s, want %d on %s", code, raw, status, field)
		}
	}
	pairs := func(p ...model.LatencyPair) model.CheckDefinitionSave {
		save := tcpMesh([]string{"node-sh"}, []string{"node-jp", "node-us"})
		save.ExcludedPairs = p
		return save
	}
	refused(admin, pairs(model.LatencyPair{Source: "node-bj", Target: "node-jp"}), http.StatusBadRequest, "excluded_pairs[0]")
	refused(admin, pairs(model.LatencyPair{Source: "node-sh", Target: "node-us"}, model.LatencyPair{Source: "node-sh", Target: "node-sh"}), http.StatusBadRequest, "excluded_pairs[1]")
	refused(admin, pairs(model.LatencyPair{Source: "node-sh", Target: "node-gone"}), http.StatusBadRequest, "excluded_pairs[0]")
	refused(admin, pairs(model.LatencyPair{Source: "node-sh"}), http.StatusBadRequest, "excluded_pairs[0]")
	web := model.CheckDefinitionSave{CheckDefinitionSpec: model.CheckDefinitionSpec{
		Name: "web", Type: model.MonitorTypeHTTP, IntervalSec: 60, TimeoutSec: 5, Enabled: true,
		Sources: model.TargetSelector{Nodes: []string{"node-sh"}}, Addresses: []string{"https://status.example.net/"},
		ExcludedPairs: []model.LatencyPair{{Source: "node-sh", Target: "node-jp"}},
	}}
	refused(admin, web, http.StatusBadRequest, "excluded_pairs")
	// A pair whose source a group or the whole fleet holds is any source of the set.
	fleet := pairs(model.LatencyPair{Source: "node-bj", Target: "node-jp"})
	fleet.Sources = model.TargetSelector{All: true}
	if code, raw := admin.do(http.MethodPost, "/api/monitors/definitions", fleet); code != http.StatusOK {
		t.Fatalf("a whole-fleet source's pair = %d %s", code, raw)
	}

	confined := &checkClient{t: t, handler: handler, token: createPAT(t, handler, admin.cookies, admin.csrf, []string{"monitor:read", "monitor:admin"}, []string{"node-sh", "node-jp"})}
	own := tcpMesh([]string{"node-sh"}, []string{"node-jp"})
	own.ExcludedPairs = []model.LatencyPair{{Source: "node-sh", Target: "node-us"}}
	refused(confined, own, http.StatusForbidden, "excluded_pairs[0]")
}

// Excluded pairs and the adoption name nodes as the selectors do: a token
// confined to some nodes reads a definition only when every node named
// there is one it reads too (a target that left a migrated definition stays
// in its adoption).
func TestDefinitionNamesNoNodeAConfinedReaderCannotRead(t *testing.T) {
	p := principal{Principal: rbac.Principal{ActorID: "token", Scopes: []string{"monitor:read"}, ServerAllowlist: []string{"node-sh", "node-jp"}}}
	def := model.CheckDefinition{CheckDefinitionSpec: model.CheckDefinitionSpec{
		Type: model.MonitorTypeTCP, Sources: model.TargetSelector{Nodes: []string{"node-sh"}}, Targets: model.TargetSelector{Nodes: []string{"node-jp"}},
	}}
	if !checkDefinitionVisible(p, def) {
		t.Fatal("a definition of the token's own nodes is hidden from it")
	}
	excluded, adopted := def, def
	excluded.ExcludedPairs = []model.LatencyPair{{Source: "node-sh", Target: "node-us"}}
	adopted.Adopted = []model.CheckAdoption{{Method: model.MonitorTypeTCP, TargetNode: "node-us", MonitorID: "mon_lat_node-us"}}
	for name, d := range map[string]model.CheckDefinition{"an excluded pair": excluded, "an adoption": adopted} {
		if checkDefinitionVisible(p, d) {
			t.Fatalf("%s naming node-us leaves the definition readable to a token confined to node-sh and node-jp", name)
		}
	}
}

// Design 32 R2: a skipped pair is not a path, so a definition counts the
// pairs it measures, as the matrix and the dry run do, not every source its
// monitors name.
func TestDefinitionCountsOnlyThePairsItMeasures(t *testing.T) {
	_, handler, st := checkFleet(t)
	old, _ := st.Node("node-bj")
	old.ProbeMethods = []string{"tcp"}
	upsertNodes(t, st, old)
	c := newCheckClient(t, handler)
	save := tcpMesh([]string{"node-sh", "node-bj"}, []string{"node-jp"})
	save.Type = model.MonitorTypeICMP
	view := c.create(save)
	if view.Summary.Paths != 1 {
		t.Fatalf("saved: paths = %d, want 1: node-bj's agent cannot run icmp", view.Summary.Paths)
	}
	if got := c.get(view.ID); got.Summary.Paths != 1 {
		t.Fatalf("read: paths = %d, want 1", got.Summary.Paths)
	}
}

// Auto takes target nodes only, and the adoption the migration wrote is
// never a save's to write: a body that carries one changes nothing.
func TestAutoDefinitionSaveRules(t *testing.T) {
	_, handler, st := checkFleet(t)
	c := newCheckClient(t, handler)
	auto := tcpMesh([]string{"node-sh"}, []string{"node-jp"})
	auto.Type = model.CheckMethodAuto
	auto.Addresses = []string{"203.0.113.9:443"}
	code, raw := c.do(http.MethodPost, "/api/monitors/definitions", auto)
	if code != http.StatusBadRequest || apiErrorOf(t, raw).Field != "addresses[0]" || !strings.Contains(raw, "an auto check") {
		t.Fatalf("auto with an address = %d %s", code, raw)
	}
	auto.Addresses = nil
	view := c.create(auto)
	if view.Type != model.CheckMethodAuto || view.Packets != model.MonitorPacketsDefault {
		t.Fatalf("auto = %+v", view.CheckDefinitionSpec)
	}

	var body map[string]any
	raw0, _ := json.Marshal(saveOf(view))
	if err := json.Unmarshal(raw0, &body); err != nil {
		t.Fatal(err)
	}
	body["adopted"] = []model.CheckAdoption{{Method: "tcp", TargetNode: "node-jp", MonitorID: "mon_lat_node-jp"}}
	if code, raw := c.do(http.MethodPost, "/api/monitors/definitions/update", body); code != http.StatusOK && code != http.StatusBadRequest {
		t.Fatalf("a save carrying an adoption = %d %s", code, raw)
	}
	if stored, _ := st.CheckDefinition(view.ID); len(stored.Adopted) != 0 {
		t.Fatalf("a save wrote an adoption: %+v", stored.Adopted)
	}
}
