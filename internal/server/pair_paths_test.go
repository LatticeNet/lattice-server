package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// pairCells are the matrix's cells from source to targetNode, only those of
// definition when it is named.
func pairCells(t *testing.T, srv *Server, source, targetNode string, definition ...string) []model.PathCell {
	t.Helper()
	srv.monitorPaths.forget()
	m, err := srv.pathMatrixFor(principal{Principal: adminPrincipalForTest()}, model.PathWindowHour, srv.now())
	if err != nil {
		t.Fatal(err)
	}
	var out []model.PathCell
	for _, cell := range m.Paths {
		if cell.Source == source && cell.TargetNode == targetNode && (len(definition) == 0 || cell.CheckDefinitionID == definition[0]) {
			out = append(out, cell)
		}
	}
	return out
}

func pairSeries(t *testing.T, c *checkClient, source, targetNode, check string) (int, model.PathSeries, string) {
	t.Helper()
	q := url.Values{"source": {source}, "target_node": {targetNode}, "window": {model.PathWindowHour}}
	if check != "" {
		q.Set("check", check)
	}
	code, raw := c.do(http.MethodGet, "/api/monitors/series?"+q.Encode(), nil)
	var series model.PathSeries
	if code == http.StatusOK {
		if err := json.Unmarshal([]byte(raw), &series); err != nil {
			t.Fatal(err)
		}
	}
	return code, series, raw
}

// seriesP50 is the p50 of the series' newest bucket that heard a run.
func seriesP50(series model.PathSeries) float64 {
	for i := len(series.Buckets) - 1; i >= 0; i-- {
		if b := series.Buckets[i]; b.N > 0 && b.P50Ms != nil {
			return *b.P50Ms
		}
	}
	return -1
}

// Design 32 R1: a path is a (source, target) pair whichever check measures
// it. Fleet mesh and an operator's icmp check both measure cd-hs-sh to
// node-jp: the matrix has a cell for each, both keyed by the target node,
// Fleet mesh's naming its definition (and still marked managed for one
// release), and the series route answers for the pair with the first check
// by default and with any check on it by ?check=.
func TestNodePairIsKeyedByItsNodesWhicheverCheckMeasuresIt(t *testing.T) {
	srv, handler, st := meshFleet(t, t.TempDir())
	storePathSet(t, st, meshConfig())
	if _, _, err := srv.syncLatencyProbes(meshT0); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.migratePathSet(meshT0); err != nil {
		t.Fatal(err)
	}
	icmp := model.Monitor{ID: "mon_jp_icmp", Name: "ICMP to Tokyo", Type: model.MonitorTypeICMP, Target: "203.0.113.12", TargetNode: "node-jp", NodeIDs: []string{"cd-hs-sh"}, IntervalSec: 60, TimeoutSec: 5, Packets: 3, Enabled: true}
	if err := st.UpsertMonitor(icmp); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		at := meshT0.Add(-time.Duration(i+1) * time.Minute)
		for _, r := range []model.MonitorResult{
			{MonitorID: "mon_lat_node-jp", NodeID: "cd-hs-sh", At: at, Success: true, LatencyMs: 40},
			{MonitorID: icmp.ID, NodeID: "cd-hs-sh", At: at, Success: true, LatencyMs: 80},
		} {
			if _, err := st.AddMonitorResult(r); err != nil {
				t.Fatal(err)
			}
		}
	}

	cells := pairCells(t, srv, "cd-hs-sh", "node-jp")
	if len(cells) != 2 {
		t.Fatalf("cells on the pair = %+v", cells)
	}
	byMonitor := map[string]model.PathCell{}
	for _, cell := range cells {
		byMonitor[cell.MonitorID] = cell
	}
	mesh, single := byMonitor["mon_lat_node-jp"], byMonitor[icmp.ID]
	if mesh.CheckDefinitionID != model.CheckFleetMeshID || !mesh.Managed || single.CheckDefinitionID != "" || single.Managed || single.TargetNode != "node-jp" {
		t.Fatalf("Fleet mesh cell %+v, single check cell %+v", mesh, single)
	}

	c := newCheckClient(t, handler)
	code, series, raw := pairSeries(t, c, "cd-hs-sh", "node-jp", "")
	if code != http.StatusOK || series.Check != model.CheckFleetMeshID || seriesP50(series) != 40 {
		t.Fatalf("the pair's default series = %d check %q p50 %v: %s", code, series.Check, seriesP50(series), raw)
	}
	code, series, raw = pairSeries(t, c, "cd-hs-sh", "node-jp", icmp.ID)
	if code != http.StatusOK || series.Check != icmp.ID || seriesP50(series) != 80 {
		t.Fatalf("the icmp check's series on the pair = %d check %q p50 %v: %s", code, series.Check, seriesP50(series), raw)
	}
	code, series, _ = pairSeries(t, c, "cd-hs-sh", "node-jp", model.CheckFleetMeshID)
	if code != http.StatusOK || series.Check != model.CheckFleetMeshID {
		t.Fatalf("Fleet mesh by name = %d %q", code, series.Check)
	}
	if code, _, raw := pairSeries(t, c, "cd-hs-sh", "node-jp", "chk_nothing"); code != http.StatusNotFound {
		t.Fatalf("a check not on the pair = %d %s", code, raw)
	}
	// The old spelling of a Fleet mesh path, by its monitor, still answers.
	code, raw = c.do(http.MethodGet, "/api/monitors/series?source=cd-hs-sh&monitor=mon_lat_node-jp&window=1h", nil)
	if code != http.StatusOK {
		t.Fatalf("by monitor = %d %s", code, raw)
	}
}

// An auto definition keeps one path per pair: when a source's method
// switches, the monitor of the method it left is that pair's history, the
// matrix shows only the method it uses now, and the pair's series joins
// both.
func TestAutoDefinitionKeepsOnePathPerPairAcrossAMethodSwitch(t *testing.T) {
	srv, handler, st := meshFleet(t, t.TempDir())
	src, _ := st.Node("cd-hs-sh")
	src.ProbeMethods = []string{"tcp"}
	upsertNodes(t, st, src)
	c := newCheckClient(t, handler)
	view := c.create(model.CheckDefinitionSave{CheckDefinitionSpec: model.CheckDefinitionSpec{
		Name: "Mesh", Type: model.CheckMethodAuto, Enabled: true, IntervalSec: 60, TimeoutSec: 5,
		Sources: model.TargetSelector{Nodes: []string{"cd-hs-sh"}}, Targets: model.TargetSelector{Nodes: []string{"node-jp"}},
	}})
	cells := pairCells(t, srv, "cd-hs-sh", "node-jp", view.ID)
	if len(cells) != 1 || cells[0].Method != model.MonitorTypeTCP || cells[0].CheckDefinitionID != view.ID {
		t.Fatalf("an agent without icmp = %+v", cells)
	}
	tcpID := cells[0].MonitorID
	reportRun(t, st, tcpID, "cd-hs-sh", meshT0.Add(-2*time.Minute))

	src.ProbeMethods = []string{"beacon", "http", "icmp", "tcp"}
	upsertNodes(t, st, src)
	srv.monitorPaths.dropPlan()
	if _, err := srv.syncCheckDefinitions(meshT0, "sweep"); err != nil {
		t.Fatal(err)
	}
	cells = pairCells(t, srv, "cd-hs-sh", "node-jp", view.ID)
	if len(cells) != 1 || cells[0].Method != model.MonitorTypeICMP || cells[0].MonitorID == tcpID {
		t.Fatalf("after the agent learned icmp = %+v", cells)
	}
	reportRun(t, st, cells[0].MonitorID, "cd-hs-sh", meshT0.Add(-time.Minute))
	if tcp, ok := st.Monitor(tcpID); !ok || tcp.Enabled {
		t.Fatalf("the tcp monitor is kept, not run: %+v %v", tcp, ok)
	}
	if got := c.get(view.ID); got.Summary.PausedTargets != 0 || got.Summary.Paths != 1 {
		t.Fatalf("summary = %+v; the earlier method is history, not a paused target", got.Summary)
	}
	code, series, raw := pairSeries(t, c, "cd-hs-sh", "node-jp", view.ID)
	heard := 0
	for _, b := range series.Buckets {
		heard += b.N
	}
	if code != http.StatusOK || series.Check != view.ID || heard != 2 {
		t.Fatalf("the pair's series = %d check %q heard %d: %s", code, series.Check, heard, raw)
	}
}

// When an auto source and a pinned source shared one path set monitor, one
// definition adopts it and the other measures its pairs on a monitor of its
// own. The pair's series still reads its history: from the pair's source,
// the rows of any monitor an adoption map recorded for the same method and
// target. A check of the operator's own on the pair never picks them up.
func TestSplitPairReadsTheHistoryItsAdoptionRecorded(t *testing.T) {
	srv, handler, st := meshFleet(t, t.TempDir())
	old, _ := st.Node("node-bj")
	old.ProbeMethods = []string{"tcp"}
	upsertNodes(t, st, old)
	cfg := meshConfig()
	cfg.Method = model.LatencyMethodAuto
	cfg.Sources = []string{"cd-hs-sh", "node-bj", "node-jp"}
	cfg.SourceMethods = map[string]string{"node-jp": model.LatencyMethodTCP}
	storePathSet(t, st, cfg)
	if _, _, err := srv.syncLatencyProbes(meshT0); err != nil {
		t.Fatal(err)
	}
	shared, ok := st.Monitor("mon_lat_node-hk")
	if !ok || !slices.Contains(shared.NodeIDs, "node-bj") || !slices.Contains(shared.NodeIDs, "node-jp") {
		t.Fatalf("the fixture needs both sources on one tcp monitor: %+v", shared)
	}
	for _, source := range []string{"node-bj", "node-jp"} {
		for i := range 3 {
			reportRun(t, st, shared.ID, source, meshT0.Add(-time.Duration(i+1)*time.Minute))
		}
	}
	if _, err := srv.migratePathSet(meshT0); err != nil {
		t.Fatal(err)
	}

	c := newCheckClient(t, handler)
	split := 0
	for _, source := range []string{"node-bj", "node-jp"} {
		cells := pairCells(t, srv, source, "node-hk")
		if len(cells) != 1 || cells[0].Method != model.MonitorTypeTCP {
			t.Fatalf("%s to node-hk after the migration = %+v", source, cells)
		}
		if cells[0].MonitorID != shared.ID {
			split++
		}
		code, series, raw := pairSeries(t, c, source, "node-hk", cells[0].CheckDefinitionID)
		heard := 0
		for _, b := range series.Buckets {
			heard += b.N
		}
		if code != http.StatusOK || heard != 3 {
			t.Fatalf("%s to node-hk by %s heard %d runs, want its 3 from before the migration: %s", source, cells[0].CheckDefinitionID, heard, raw)
		}
	}
	if split != 1 {
		t.Fatalf("%d pairs moved to a new monitor; the fixture needs exactly one", split)
	}

	// An operator's own tcp check on a split pair reads its own runs only.
	own := model.Monitor{ID: "mon_bj_hk_tcp", Name: "TCP to Hong Kong", Type: model.MonitorTypeTCP, Target: "203.0.113.14:443", TargetNode: "node-hk", NodeIDs: []string{"node-bj"}, IntervalSec: 60, TimeoutSec: 5, Enabled: true}
	if err := st.UpsertMonitor(own); err != nil {
		t.Fatal(err)
	}
	reportRun(t, st, own.ID, "node-bj", meshT0.Add(-30*time.Second))
	code, series, raw := pairSeries(t, c, "node-bj", "node-hk", own.ID)
	heard := 0
	for _, b := range series.Buckets {
		heard += b.N
	}
	if code != http.StatusOK || heard != 1 {
		t.Fatalf("the operator's check heard %d runs, want its own 1: %s", heard, raw)
	}
}
