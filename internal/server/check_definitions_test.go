package server

import (
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/store"
)

var checkT0 = time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)

// checkFleet is a server with two domestic sources and three targets:
// node-jp and node-us serve a TCP line, node-hk only UDP (nothing TCP can
// dial). Every agent runs every method and is online.
func checkFleet(t *testing.T) (*Server, http.Handler, *store.Store) {
	t.Helper()
	srv, handler, st := newPathsServer(t)
	serverClock(t, srv).set(checkT0)
	all := []string{"beacon", "http", "icmp", "tcp"}
	upsertNodes(t, st,
		model.Node{ID: "node-sh", Name: "sh", PublicIP: "203.0.113.1", Online: true, ProbeMethods: all, Geo: &model.NodeGeo{Country: "CN"}, Tags: []string{"domestic"}},
		model.Node{ID: "node-bj", Name: "bj", PublicIP: "203.0.113.2", Online: true, ProbeMethods: all, Geo: &model.NodeGeo{Country: "CN"}},
		model.Node{ID: "node-jp", Name: "jp", PublicIP: "203.0.113.3", Online: true, ProbeMethods: all, Geo: &model.NodeGeo{Country: "JP"}},
		model.Node{ID: "node-us", Name: "us", PublicIP: "198.51.100.9", Online: true, ProbeMethods: all, Geo: &model.NodeGeo{Country: "US"}},
		model.Node{ID: "node-hk", Name: "hk", PublicIP: "203.0.113.4", Online: true, ProbeMethods: all, Geo: &model.NodeGeo{Country: "HK"}},
	)
	srv.singboxInvMu.Lock()
	if srv.singboxInv == nil {
		srv.singboxInv = map[string]model.SingBoxInventory{}
	}
	srv.singboxInv["node-jp"] = model.SingBoxInventory{NodeID: "node-jp", At: checkT0, Status: "ok", Nodes: []model.SingBoxNode{
		{Name: "vless-443", Protocol: "vless", Network: "reality", Port: "443", ListenHost: "::", Address: "203.0.113.3"},
	}}
	srv.singboxInv["node-us"] = model.SingBoxInventory{NodeID: "node-us", At: checkT0, Status: "ok", Nodes: []model.SingBoxNode{
		{Name: "trojan-8443", Protocol: "trojan", Network: "trojan", Port: "8443", ListenHost: "::", Address: "198.51.100.9"},
	}}
	srv.singboxInv["node-hk"] = model.SingBoxInventory{NodeID: "node-hk", At: checkT0, Status: "ok", Nodes: []model.SingBoxNode{
		{Name: "hy2", Protocol: "hysteria2", Network: "hysteria2", Port: "8443", Address: "203.0.113.4"},
	}}
	srv.singboxInvMu.Unlock()
	// A path set nobody saved would probe from cd-hs-sh; none is here, and
	// the defaults with no source generate nothing.
	srv.monitorPaths.forget()
	return srv, handler, st
}

type checkClient struct {
	t       *testing.T
	handler http.Handler
	cookies []*http.Cookie
	csrf    string
	token   string
}

func newCheckClient(t *testing.T, handler http.Handler) *checkClient {
	cookies, csrf := loginSession(t, handler)
	return &checkClient{t: t, handler: handler, cookies: cookies, csrf: csrf}
}

func (c *checkClient) do(method, path string, body any) (int, string) {
	c.t.Helper()
	raw := ""
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		raw = string(b)
	}
	var res *http.Response
	if c.token != "" {
		res = doBearerJSON(c.t, c.handler, method, path, raw, c.token)
	} else {
		res = doJSON(c.t, c.handler, method, path, raw, c.cookies, c.csrf)
	}
	return res.StatusCode, readBody(c.t, res)
}

func (c *checkClient) create(save model.CheckDefinitionSave) model.CheckDefinitionView {
	c.t.Helper()
	code, raw := c.do(http.MethodPost, "/api/monitors/definitions", save)
	if code != http.StatusOK {
		c.t.Fatalf("create = %d %s", code, raw)
	}
	var view model.CheckDefinitionView
	if err := json.Unmarshal([]byte(raw), &view); err != nil {
		c.t.Fatal(err)
	}
	return view
}

func (c *checkClient) update(save model.CheckDefinitionSave) model.CheckDefinitionView {
	c.t.Helper()
	code, raw := c.do(http.MethodPost, "/api/monitors/definitions/update", save)
	if code != http.StatusOK {
		c.t.Fatalf("update = %d %s", code, raw)
	}
	var view model.CheckDefinitionView
	if err := json.Unmarshal([]byte(raw), &view); err != nil {
		c.t.Fatal(err)
	}
	return view
}

func (c *checkClient) preview(save model.CheckDefinitionSave) model.CheckDefinitionPreview {
	c.t.Helper()
	code, raw := c.do(http.MethodPost, "/api/monitors/definitions/preview", save)
	if code != http.StatusOK {
		c.t.Fatalf("preview = %d %s", code, raw)
	}
	var out model.CheckDefinitionPreview
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		c.t.Fatal(err)
	}
	return out
}

func (c *checkClient) get(id string) model.CheckDefinitionView {
	c.t.Helper()
	code, raw := c.do(http.MethodGet, "/api/monitors/definitions?id="+id, nil)
	if code != http.StatusOK {
		c.t.Fatalf("get = %d %s", code, raw)
	}
	var view model.CheckDefinitionView
	if err := json.Unmarshal([]byte(raw), &view); err != nil {
		c.t.Fatal(err)
	}
	return view
}

// saveOf is the edit body that echoes a stored definition.
func saveOf(view model.CheckDefinitionView) model.CheckDefinitionSave {
	return model.CheckDefinitionSave{ID: view.ID, Version: view.Version, CheckDefinitionSpec: view.CheckDefinitionSpec}
}

func tcpMesh(sources, targets []string) model.CheckDefinitionSave {
	return model.CheckDefinitionSave{CheckDefinitionSpec: model.CheckDefinitionSpec{
		Name: "edge tcp", Type: model.MonitorTypeTCP, IntervalSec: 60, TimeoutSec: 5, Enabled: true,
		Sources: model.TargetSelector{Nodes: sources}, Targets: model.TargetSelector{Nodes: targets},
	}}
}

// definitionMonitors are the stored monitors of a definition, by id.
func definitionMonitors(st *store.Store, definitionID string) []model.Monitor {
	var out []model.Monitor
	for _, mon := range st.Monitors() {
		if mon.ManagedBy == store.CheckDefinitionOwner(definitionID) {
			out = append(out, mon)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func monitorTo(t *testing.T, mons []model.Monitor, targetNode, address string) model.Monitor {
	t.Helper()
	for _, mon := range mons {
		if (targetNode != "" && mon.TargetNode == targetNode) || (address != "" && mon.Target == address && mon.TargetNode == "") {
			return mon
		}
	}
	t.Fatalf("no monitor to %q%q in %+v", targetNode, address, mons)
	return model.Monitor{}
}

// reportRun stores one result from source for monitorID, as the agent would.
func reportRun(t *testing.T, st *store.Store, monitorID, source string, at time.Time) {
	t.Helper()
	outcomes, err := st.IngestAgentMonitorResults(source, []model.MonitorResult{{MonitorID: monitorID, NodeID: source, At: at, Success: true, LatencyMs: 30}}, at)
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 1 || outcomes[0].Dropped != "" {
		t.Fatalf("result for %s from %s refused: %+v", monitorID, source, outcomes)
	}
}

func heldRuns(t *testing.T, st *store.Store, monitorID, source string) int {
	t.Helper()
	latest, ok, err := st.MonitorLatest(monitorID, source)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		return 0
	}
	return latest.Held
}

// D1 / S2b: a definition with two sources and three targets yields three
// monitors and six paths, which the matrix lists as an operator's check
// lists them (keyed by monitor, never managed) and which page by the
// definition's own policy. A target TCP cannot dial keeps its monitor and
// reads unknown with the reason.
func TestCheckDefinitionExpandsSourcesTimesTargets(t *testing.T) {
	srv, handler, st := checkFleet(t)
	c := newCheckClient(t, handler)
	view := c.create(tcpMesh([]string{"node-sh", "node-bj"}, []string{"node-jp", "node-us", "node-hk"}))
	if !strings.HasPrefix(view.ID, model.CheckDefinitionIDPrefix) || view.Version != 1 {
		t.Fatalf("created = %+v", view.CheckDefinition)
	}
	mons := definitionMonitors(st, view.ID)
	if len(mons) != 3 || view.Summary.Monitors != 3 || view.Summary.Paths != 6 {
		t.Fatalf("monitors = %d, summary = %+v", len(mons), view.Summary)
	}
	for _, mon := range mons {
		if !strings.HasPrefix(mon.ID, "mon_"+view.ID+"_") || !slices.Equal(mon.NodeIDs, []string{"node-bj", "node-sh"}) || !mon.Enabled || mon.Alert != model.MonitorAlertDown {
			t.Fatalf("expanded monitor = %+v", mon)
		}
		if store.MonitorOwnerOf(mon) != store.MonitorOwnerDefinition {
			t.Fatalf("owner of %s = %v", mon.ID, store.MonitorOwnerOf(mon))
		}
	}
	jp := monitorTo(t, mons, "node-jp", "")
	if jp.Target != "203.0.113.3:443" {
		t.Fatalf("node target resolved to %q, want the port rule's pick", jp.Target)
	}

	m, err := srv.pathMatrixFor(beaconAdmin(), model.PathWindowHour, checkT0)
	if err != nil {
		t.Fatal(err)
	}
	cells := 0
	for _, cell := range m.Paths {
		if !strings.HasPrefix(cell.MonitorID, "mon_"+view.ID) {
			continue
		}
		cells++
		if cell.Managed {
			t.Fatalf("a definition path is marked managed: %+v", cell)
		}
	}
	if cells != 6 {
		t.Fatalf("matrix lists %d definition paths, want 6: %+v", cells, m.Paths)
	}
	hk := monitorTo(t, mons, "node-hk", "")
	if cell := pathCellFor(t, m, "node-sh", hk.ID); cell.State != model.PathStateUnknown || cell.Reason != model.PathReasonNotProbeable {
		t.Fatalf("UDP-only target cell = %+v, want unknown not_probeable", cell)
	}
	if policy := srv.monitorPolicy(jp); policy.alert != model.MonitorAlertDown {
		t.Fatalf("definition monitor pages by %q, want its own down policy", policy.alert)
	}
	// The agent of a source is handed the expanded checks, resolved.
	handed := map[string]bool{}
	for _, mon := range agentMonitorList(t, srv, st, "node-sh") {
		handed[mon.ID] = true
	}
	if !handed[jp.ID] || handed[hk.ID] {
		t.Fatalf("node-sh is handed %v; want jp's check and not hk's (nothing to dial)", handed)
	}
}

// D1: a selector is stored, not resolved, so a node joining a target group
// gets a monitor within one sync (here the group edit's own), and a node
// leaving it pauses its monitor and keeps its runs.
func TestCheckDefinitionFollowsGroupMembership(t *testing.T) {
	_, handler, st := checkFleet(t)
	c := newCheckClient(t, handler)
	if err := st.UpsertGroup(model.Group{ID: "grp_edge", Name: "edge", Slug: "edge", Color: "sky", Members: []string{"node-jp"}}); err != nil {
		t.Fatal(err)
	}
	save := tcpMesh([]string{"node-sh"}, nil)
	save.Targets = model.TargetSelector{Groups: []string{"grp_edge"}}
	view := c.create(save)
	if mons := definitionMonitors(st, view.ID); len(mons) != 1 || mons[0].TargetNode != "node-jp" {
		t.Fatalf("monitors before the join = %+v", mons)
	}
	if code, raw := c.do(http.MethodPost, "/api/groups/members", map[string]any{"group_id": "grp_edge", "add": []string{"node-us"}}); code != http.StatusOK {
		t.Fatalf("add member = %d %s", code, raw)
	}
	mons := definitionMonitors(st, view.ID)
	us := monitorTo(t, mons, "node-us", "")
	if len(mons) != 2 || !us.Enabled {
		t.Fatalf("after the join = %+v", mons)
	}
	reportRun(t, st, us.ID, "node-sh", checkT0)
	if code, raw := c.do(http.MethodPost, "/api/groups/members", map[string]any{"group_id": "grp_edge", "remove": []string{"node-us"}}); code != http.StatusOK {
		t.Fatalf("remove member = %d %s", code, raw)
	}
	left, ok := st.Monitor(us.ID)
	if !ok || left.Enabled {
		t.Fatalf("the departed target's monitor = %+v %v, want it kept paused", left, ok)
	}
	if held := heldRuns(t, st, us.ID, "node-sh"); held != 1 {
		t.Fatalf("the paused target kept %d runs, want 1", held)
	}
	got := c.get(view.ID)
	if got.Summary.PausedTargets != 1 || got.Summary.PausedRuns != 1 || got.Summary.Paths != 1 {
		t.Fatalf("summary after the leave = %+v", got.Summary)
	}
}

// D1: monitor ids hash the method and the normalized target, so removing
// the second of three addresses leaves the third's id and history alone,
// and a method change starts new ids.
func TestCheckDefinitionIdentityIsHashedNotPositional(t *testing.T) {
	_, handler, st := checkFleet(t)
	c := newCheckClient(t, handler)
	urls := []string{"https://a.example.com/health", "https://b.example.com/health", "https://c.example.com/health"}
	view := c.create(model.CheckDefinitionSave{CheckDefinitionSpec: model.CheckDefinitionSpec{
		Name: "web", Type: model.MonitorTypeHTTP, IntervalSec: 60, TimeoutSec: 5, Enabled: true,
		Sources: model.TargetSelector{Nodes: []string{"node-sh"}}, Addresses: urls,
	}})
	mons := definitionMonitors(st, view.ID)
	if len(mons) != 3 {
		t.Fatalf("monitors = %+v", mons)
	}
	third := monitorTo(t, mons, "", urls[2])
	reportRun(t, st, third.ID, "node-sh", checkT0)

	next := saveOf(view)
	next.Addresses = []string{urls[0], urls[2]}
	view = c.update(next)
	after, ok := st.Monitor(third.ID)
	if !ok || !after.Enabled || after.Target != urls[2] {
		t.Fatalf("third address after removing the second = %+v %v", after, ok)
	}
	if held := heldRuns(t, st, third.ID, "node-sh"); held != 1 {
		t.Fatalf("third address kept %d runs, want 1", held)
	}
	second := monitorTo(t, mons, "", urls[1])
	if kept, ok := st.Monitor(second.ID); !ok || kept.Enabled {
		t.Fatalf("removed address = %+v %v, want it paused", kept, ok)
	}

	// tcp to icmp on node targets: new ids, the old ones paused.
	tcp := c.create(tcpMesh([]string{"node-sh"}, []string{"node-jp"}))
	oldID := definitionMonitors(st, tcp.ID)[0].ID
	icmp := saveOf(tcp)
	icmp.Type = model.MonitorTypeICMP
	c.update(icmp)
	var live []string
	for _, mon := range definitionMonitors(st, tcp.ID) {
		switch {
		case mon.ID == oldID && mon.Enabled:
			t.Fatalf("the tcp monitor still runs after the method change: %+v", mon)
		case mon.ID != oldID && mon.Enabled:
			live = append(live, mon.ID)
			if mon.Type != model.MonitorTypeICMP || mon.Target != "203.0.113.3" {
				t.Fatalf("new icmp monitor = %+v", mon)
			}
		}
	}
	if len(live) != 1 || live[0] == oldID {
		t.Fatalf("live monitors after the method change = %v (old %s)", live, oldID)
	}
}

// D1: an expanded monitor is changed only through its definition.
func TestCheckDefinitionMonitorsRefuseDirectEdits(t *testing.T) {
	_, handler, st := checkFleet(t)
	c := newCheckClient(t, handler)
	view := c.create(tcpMesh([]string{"node-sh"}, []string{"node-jp"}))
	mon := definitionMonitors(st, view.ID)[0]
	if code, raw := c.do(http.MethodPost, "/api/monitors/update", map[string]any{"id": mon.ID, "version": mon.Version, "interval_sec": 120}); code != http.StatusConflict || !strings.Contains(raw, view.ID) {
		t.Fatalf("direct edit = %d %s, want 409 naming the definition", code, raw)
	}
	if code, raw := c.do(http.MethodPost, "/api/monitors/delete", map[string]any{"id": mon.ID}); code != http.StatusConflict || !strings.Contains(raw, view.ID) {
		t.Fatalf("direct delete = %d %s, want 409 naming the definition", code, raw)
	}
}

// D1: a group or whole-fleet selector needs an unrestricted principal; a
// restricted one may name explicit nodes it can read and administer.
func TestCheckDefinitionSelectorScope(t *testing.T) {
	_, handler, st := checkFleet(t)
	admin := newCheckClient(t, handler)
	if err := st.UpsertGroup(model.Group{ID: "grp_edge", Name: "edge", Slug: "edge", Color: "sky", Members: []string{"node-jp"}}); err != nil {
		t.Fatal(err)
	}
	confined := &checkClient{t: t, handler: handler, token: createPAT(t, handler, admin.cookies, admin.csrf, []string{"monitor:read", "monitor:admin"}, []string{"node-sh", "node-jp"})}

	group := tcpMesh([]string{"node-sh"}, nil)
	group.Targets = model.TargetSelector{Groups: []string{"grp_edge"}}
	if code, raw := confined.do(http.MethodPost, "/api/monitors/definitions", group); code != http.StatusForbidden {
		t.Fatalf("restricted group selector = %d %s", code, raw)
	}
	fleet := tcpMesh(nil, []string{"node-jp"})
	fleet.Sources = model.TargetSelector{All: true}
	if code, raw := confined.do(http.MethodPost, "/api/monitors/definitions", fleet); code != http.StatusForbidden {
		t.Fatalf("restricted whole-fleet selector = %d %s", code, raw)
	}
	if code, raw := confined.do(http.MethodPost, "/api/monitors/definitions/preview", group); code != http.StatusForbidden {
		t.Fatalf("restricted group preview = %d %s", code, raw)
	}
	if code, raw := confined.do(http.MethodPost, "/api/monitors/definitions", tcpMesh([]string{"node-sh"}, []string{"node-us"})); code != http.StatusForbidden {
		t.Fatalf("restricted target outside scope = %d %s", code, raw)
	}
	confined.create(tcpMesh([]string{"node-sh"}, []string{"node-jp"}))
	// The same principal does not see a definition with a group selector.
	broad := admin.create(group)
	code, raw := confined.do(http.MethodGet, "/api/monitors/definitions", nil)
	if code != http.StatusOK || strings.Contains(raw, broad.ID) {
		t.Fatalf("restricted list = %d %s, want the group definition hidden", code, raw)
	}
	if code, _ := confined.do(http.MethodPost, "/api/monitors/definitions/update", saveOf(broad)); code != http.StatusNotFound {
		t.Fatalf("restricted edit of a hidden definition = %d", code)
	}
}

// D1 and design 29 D1: secret headers need explicit source nodes, are never
// read back, and stay bound to the origins they were saved for.
func TestCheckDefinitionSecretHeaders(t *testing.T) {
	_, handler, st := checkFleet(t)
	c := newCheckClient(t, handler)
	if err := st.UpsertGroup(model.Group{ID: "grp_dom", Name: "dom", Slug: "dom", Color: "sky", Members: []string{"node-sh"}}); err != nil {
		t.Fatal(err)
	}
	save := model.CheckDefinitionSave{
		CheckDefinitionSpec: model.CheckDefinitionSpec{
			Name: "api", Type: model.MonitorTypeHTTP, IntervalSec: 60, TimeoutSec: 5, Enabled: true,
			Sources: model.TargetSelector{Groups: []string{"grp_dom"}}, Addresses: []string{"https://api.example.com/health"},
		},
		Headers: []model.MonitorHeaderEdit{{Name: "X-Api-Key", Op: model.MonitorHeaderSet, Value: "s3cret", Secret: true}},
	}
	if code, raw := c.do(http.MethodPost, "/api/monitors/definitions", save); code != http.StatusBadRequest || !strings.Contains(raw, "secret") {
		t.Fatalf("secret headers with a group source = %d %s", code, raw)
	}
	save.Sources = model.TargetSelector{Nodes: []string{"node-sh"}}
	view := c.create(save)
	if len(view.Headers) != 1 || view.Headers[0].Value != "" || !view.Headers[0].Set || !view.Headers[0].Secret {
		t.Fatalf("read headers = %+v, want the secret redacted", view.Headers)
	}
	if !slices.Equal(view.SecretsOrigins, []string{"https://api.example.com:443"}) && !slices.Equal(view.SecretsOrigins, []string{"https://api.example.com"}) {
		t.Fatalf("secrets origins = %v", view.SecretsOrigins)
	}
	mon := definitionMonitors(st, view.ID)[0]
	if len(mon.Headers) != 1 || mon.Headers[0].Value != "s3cret" || mon.SecretsOrigin == "" {
		t.Fatalf("expanded monitor carries %+v / %q, want the secret bound to its origin", mon.Headers, mon.SecretsOrigin)
	}
	// An edit that adds another origin must set the secret again.
	next := saveOf(view)
	next.Addresses = append(next.Addresses, "https://other.example.net/health")
	next.Headers = []model.MonitorHeaderEdit{{Name: "X-Api-Key", Op: model.MonitorHeaderKeep}}
	if code, raw := c.do(http.MethodPost, "/api/monitors/definitions/update", next); code != http.StatusBadRequest || !strings.Contains(raw, "set again") {
		t.Fatalf("adding an origin without re-setting the secret = %d %s", code, raw)
	}
	next.Headers = []model.MonitorHeaderEdit{{Name: "X-Api-Key", Op: model.MonitorHeaderSet, Value: "s3cret2", Secret: true}}
	c.update(next)
	// The audit records name the header, never its value.
	for _, ev := range st.AuditEvents() {
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), "s3cret") {
			t.Fatalf("an audit record carries the secret: %s", raw)
		}
	}
}

// D1: the packet budget is judged at every sync. A source group that grows
// so one source would send more than two packets a second to one address
// pauses the pair over budget with that reason, in the dry run and in the
// matrix, and the pair resumes when the group shrinks again.
func TestCheckDefinitionPacketBudgetPausesTheExcess(t *testing.T) {
	srv, handler, st := checkFleet(t)
	c := newCheckClient(t, handler)
	// node-sh already sends one packet a second to node-jp's address
	// through an operator's check.
	if code, raw := c.do(http.MethodPost, "/api/monitors", map[string]any{
		"name": "op ping", "type": "icmp", "target_node": "node-jp", "packets": 10, "interval_sec": 10, "timeout_sec": 5, "node_ids": []string{"node-sh"},
	}); code != http.StatusOK {
		t.Fatalf("operator check = %d %s", code, raw)
	}
	ping := func(name string, sources model.TargetSelector) model.CheckDefinitionSave {
		return model.CheckDefinitionSave{CheckDefinitionSpec: model.CheckDefinitionSpec{
			Name: name, Type: model.MonitorTypeICMP, IntervalSec: 10, TimeoutSec: 5, Packets: 10, Enabled: true,
			Sources: sources, Targets: model.TargetSelector{Nodes: []string{"node-jp"}},
		}}
	}
	first := c.create(ping("first", model.TargetSelector{Nodes: []string{"node-sh"}}))
	if mon := definitionMonitors(st, first.ID)[0]; len(mon.PausedNodeIDs) != 0 {
		t.Fatalf("two packets a second is within the budget: %+v", mon)
	}
	if err := st.UpsertGroup(model.Group{ID: "grp_src", Name: "src", Slug: "src", Color: "sky", Members: []string{"node-bj"}}); err != nil {
		t.Fatal(err)
	}
	second := c.create(ping("second", model.TargetSelector{Groups: []string{"grp_src"}}))
	if mon := definitionMonitors(st, second.ID)[0]; len(mon.PausedNodeIDs) != 0 {
		t.Fatalf("node-bj has its own budget: %+v", mon)
	}
	// The group grows to node-sh, which is already at two packets a second.
	if code, raw := c.do(http.MethodPost, "/api/groups/members", map[string]any{"group_id": "grp_src", "add": []string{"node-sh"}}); code != http.StatusOK {
		t.Fatalf("grow group = %d %s", code, raw)
	}
	mon := definitionMonitors(st, second.ID)[0]
	if !slices.Equal(mon.NodeIDs, []string{"node-bj", "node-sh"}) || !slices.Equal(mon.PausedNodeIDs, []string{"node-sh"}) {
		t.Fatalf("after the group grew = sources %v paused %v, want node-sh paused", mon.NodeIDs, mon.PausedNodeIDs)
	}
	if first := definitionMonitors(st, first.ID)[0]; len(first.PausedNodeIDs) != 0 {
		t.Fatalf("the older definition keeps its budget: %+v", first)
	}
	preview := c.preview(saveOf(c.get(second.ID)))
	reasons := map[string]string{}
	for _, pair := range preview.Pairs {
		reasons[pair.Source] = pair.Reason
	}
	if reasons["node-sh"] != model.PathReasonPacketBudget || reasons["node-bj"] != "" {
		t.Fatalf("dry run reasons = %v", reasons)
	}
	srv.monitorPaths.forget()
	m, err := srv.pathMatrixFor(beaconAdmin(), model.PathWindowHour, checkT0)
	if err != nil {
		t.Fatal(err)
	}
	if cell := pathCellFor(t, m, "node-sh", mon.ID); cell.State != model.PathStateUnknown || cell.Reason != model.PathReasonPacketBudget {
		t.Fatalf("over-budget cell = %+v", cell)
	}
	for _, handed := range agentMonitorList(t, srv, st, "node-sh") {
		if handed.ID == mon.ID {
			t.Fatalf("node-sh is handed the paused pair %s", mon.ID)
		}
	}
	if code, raw := c.do(http.MethodPost, "/api/groups/members", map[string]any{"group_id": "grp_src", "remove": []string{"node-sh"}}); code != http.StatusOK {
		t.Fatalf("shrink group = %d %s", code, raw)
	}
	if mon := definitionMonitors(st, second.ID)[0]; len(mon.PausedNodeIDs) != 0 {
		t.Fatalf("after the group shrank = %+v, want no budget pause", mon)
	}
}

// D1: the dry run returns exactly what the save produces: the same paths,
// targets and reasons for a create, and the same monitor ids and writes
// for an edit.
func TestCheckDefinitionDryRunEqualsSave(t *testing.T) {
	_, handler, st := checkFleet(t)
	c := newCheckClient(t, handler)
	body := tcpMesh([]string{"node-sh", "node-bj"}, []string{"node-jp", "node-us", "node-hk"})
	pre := c.preview(body)
	if pre.Paths != 6 || len(pre.Targets) != 3 || len(pre.Writes.Created) != 3 {
		t.Fatalf("dry run = %+v", pre)
	}
	notDialable := 0
	for _, target := range pre.Targets {
		if target.Reason == model.PathReasonNotProbeable {
			notDialable++
			if target.TargetNode != "node-hk" || target.Note != model.LatencyEndpointUDPOnly || target.Target != "" {
				t.Fatalf("not dialable target = %+v", target)
			}
		}
	}
	if notDialable != 1 {
		t.Fatalf("dry run targets = %+v", pre.Targets)
	}
	view := c.create(body)
	// Monitor ids differ only by the definition id a create mints.
	key := func(monitorID, definitionID string) string {
		return strings.TrimPrefix(monitorID, "mon_"+definitionID+"_")
	}
	type pairKey struct{ source, target, reason string }
	got := map[pairKey]bool{}
	for _, mon := range definitionMonitors(st, view.ID) {
		for _, source := range mon.NodeIDs {
			got[pairKey{source, key(mon.ID, view.ID), ""}] = true
		}
	}
	want := map[pairKey]bool{}
	for _, pair := range pre.Pairs {
		want[pairKey{pair.Source, key(pair.MonitorID, checkDefinitionPreviewID), ""}] = true
	}
	if len(got) != len(want) {
		t.Fatalf("saved pairs %v, dry run pairs %v", got, want)
	}
	for k := range want {
		if !got[k] {
			t.Fatalf("dry run pair %v was not saved; saved %v", k, got)
		}
	}

	// An edit's dry run names the very ids and writes the save makes.
	edit := saveOf(view)
	edit.Targets = model.TargetSelector{Nodes: []string{"node-jp", "node-us"}}
	edit.Alert = model.MonitorAlertOff
	pre = c.preview(edit)
	before := map[string]model.Monitor{}
	for _, mon := range definitionMonitors(st, view.ID) {
		before[mon.ID] = mon
	}
	c.update(edit)
	var updated, paused []string
	for _, mon := range definitionMonitors(st, view.ID) {
		if mon.UpdatedAt.Equal(before[mon.ID].UpdatedAt) && mon.Version == before[mon.ID].Version && managedMonitorFieldsEqual(mon, before[mon.ID]) {
			continue
		}
		if mon.Enabled {
			updated = append(updated, mon.ID)
		} else {
			paused = append(paused, mon.ID)
		}
	}
	sort.Strings(updated)
	sort.Strings(paused)
	if !slices.Equal(updated, pre.Writes.Updated) || !slices.Equal(paused, pre.Writes.Paused) || len(pre.Writes.Created) != 0 {
		t.Fatalf("save wrote updated %v paused %v; dry run said %+v", updated, paused, pre.Writes)
	}
}

// managedMonitorFieldsEqual compares what an edit can change on a
// definition monitor.
func managedMonitorFieldsEqual(a, b model.Monitor) bool {
	return a.Enabled == b.Enabled && a.Alert == b.Alert && a.Target == b.Target && slices.Equal(a.NodeIDs, b.NodeIDs)
}

// D1: an edit of a shared field rewrites every expanded monitor.
func TestCheckDefinitionSharedFieldEditReachesEveryMonitor(t *testing.T) {
	_, handler, st := checkFleet(t)
	c := newCheckClient(t, handler)
	view := c.create(tcpMesh([]string{"node-sh"}, []string{"node-jp", "node-us"}))
	edit := saveOf(view)
	edit.AlertAfter = 4
	edit.Degraded = &model.MonitorDegradedRule{LossPercent: 25}
	edit.IntervalSec = 120
	c.update(edit)
	for _, mon := range definitionMonitors(st, view.ID) {
		if mon.AlertAfter != 4 || mon.Degraded == nil || mon.Degraded.LossPercent != 25 || mon.IntervalSec != 120 {
			t.Fatalf("monitor after the edit = %+v", mon)
		}
	}
}

// D1: a beacon definition's new source reads beacon_source_pending, in the
// dry run and in the matrix, until the target's node.beacon plan approves
// it; the approved source runs.
func TestCheckDefinitionBeaconSourcePending(t *testing.T) {
	srv, handler, st := beaconFleet(t)
	enableBeacon(t, srv, handler, model.BeaconPlanRequest{})
	listenAsPlanned(t, srv, st)
	upsertNodes(t, st, model.Node{ID: "node-d", Name: "delta", PublicIP: "203.0.113.24", Online: true, ProbeMethods: []string{"beacon", "http", "icmp", "tcp"}})
	cookies, csrf := beaconLogin(t, handler)
	c := &checkClient{t: t, handler: handler, cookies: cookies, csrf: csrf}
	save := model.CheckDefinitionSave{CheckDefinitionSpec: model.CheckDefinitionSpec{
		Name: "beacon", Type: model.MonitorTypeBeacon, IntervalSec: 60, TimeoutSec: 5, Enabled: true,
		Sources: model.TargetSelector{Nodes: []string{"node-a", "node-d"}}, Targets: model.TargetSelector{Nodes: []string{"node-t"}},
	}}
	pre := c.preview(save)
	reasons := map[string]string{}
	for _, pair := range pre.Pairs {
		reasons[pair.Source] = pair.Reason
	}
	if reasons["node-a"] != "" || reasons["node-d"] != model.PathReasonBeaconSourcePending {
		t.Fatalf("dry run reasons = %v", reasons)
	}
	view := c.create(save)
	mon := definitionMonitors(st, view.ID)[0]
	srv.monitorPaths.forget()
	m, err := srv.pathMatrixFor(beaconAdmin(), model.PathWindowHour, srv.now())
	if err != nil {
		t.Fatal(err)
	}
	if cell := pathCellFor(t, m, "node-d", mon.ID); cell.Reason != model.PathReasonBeaconSourcePending {
		t.Fatalf("unapproved source cell = %+v", cell)
	}
	for _, handed := range agentMonitorList(t, srv, st, "node-d") {
		if handed.ID == mon.ID {
			t.Fatalf("node-d, not approved, is handed %s", mon.ID)
		}
	}
	// The definition's new source counts toward the beacon's re-plan.
	found := false
	for _, replan := range m.BeaconReplans {
		found = found || (replan.NodeID == "node-t" && slices.Contains(replan.Added, "node-d"))
	}
	if !found {
		t.Fatalf("beacon re-plans = %+v, want node-d named for node-t", m.BeaconReplans)
	}
}

// D1: deleting a definition or forgetting its paused targets names the
// monitors first and goes only when the confirmation matches; a target
// still in the set cannot be forgotten.
func TestCheckDefinitionDeleteAndForgetNameTheirMonitors(t *testing.T) {
	_, handler, st := checkFleet(t)
	c := newCheckClient(t, handler)
	view := c.create(tcpMesh([]string{"node-sh"}, []string{"node-jp", "node-us"}))
	mons := definitionMonitors(st, view.ID)
	us := monitorTo(t, mons, "node-us", "")
	jp := monitorTo(t, mons, "node-jp", "")
	reportRun(t, st, us.ID, "node-sh", checkT0)
	edit := saveOf(view)
	edit.Targets = model.TargetSelector{Nodes: []string{"node-jp"}}
	view = c.update(edit)

	if code, raw := c.do(http.MethodPost, "/api/monitors/definitions/forget", model.CheckDefinitionForget{ID: view.ID, MonitorIDs: []string{jp.ID}}); code != http.StatusConflict {
		t.Fatalf("forget a target in the set = %d %s", code, raw)
	}
	detail := c.get(view.ID)
	var paused []model.CheckDefinitionMonitor
	for _, mon := range detail.Monitors {
		if !mon.InSet {
			paused = append(paused, mon)
		}
	}
	if len(paused) != 1 || paused[0].MonitorID != us.ID || paused[0].Runs != 1 {
		t.Fatalf("paused targets in the read = %+v", detail.Monitors)
	}
	code, raw := c.do(http.MethodPost, "/api/monitors/definitions/forget", model.CheckDefinitionForget{ID: view.ID, MonitorIDs: []string{us.ID}})
	if code != http.StatusOK || !strings.Contains(raw, `"runs":1`) {
		t.Fatalf("forget = %d %s", code, raw)
	}
	if _, ok := st.Monitor(us.ID); ok || heldRuns(t, st, us.ID, "node-sh") != 0 {
		t.Fatalf("the forgotten target's monitor or history survived")
	}

	if code, raw := c.do(http.MethodPost, "/api/monitors/definitions/delete", model.CheckDefinitionDelete{ID: view.ID, Version: view.Version, MonitorIDs: []string{"mon_other"}}); code != http.StatusConflict {
		t.Fatalf("delete with a stale confirmation = %d %s", code, raw)
	}
	if code, raw := c.do(http.MethodPost, "/api/monitors/definitions/delete", model.CheckDefinitionDelete{ID: view.ID, Version: view.Version, MonitorIDs: []string{jp.ID}}); code != http.StatusOK {
		t.Fatalf("delete = %d %s", code, raw)
	}
	if _, ok := st.CheckDefinition(view.ID); ok || len(definitionMonitors(st, view.ID)) != 0 {
		t.Fatalf("the definition or its monitors survived the delete")
	}
	actions := map[string]bool{}
	for _, ev := range st.AuditEvents() {
		actions[ev.Action] = true
	}
	for _, want := range []string{"monitor.check.create", "monitor.check.update", "monitor.check.forget", "monitor.check.delete"} {
		if !actions[want] {
			t.Fatalf("no %s audit record in %v", want, actions)
		}
	}
}

// D1: a node removed from the fleet takes its monitors with it, and a group
// a definition names cannot be deleted under it.
func TestCheckDefinitionNodeRemovalAndGroupDelete(t *testing.T) {
	srv, handler, st := checkFleet(t)
	c := newCheckClient(t, handler)
	if err := st.UpsertGroup(model.Group{ID: "grp_edge", Name: "edge", Slug: "edge", Color: "sky", Members: []string{"node-jp", "node-us"}}); err != nil {
		t.Fatal(err)
	}
	save := tcpMesh([]string{"node-sh"}, nil)
	save.Targets = model.TargetSelector{Groups: []string{"grp_edge"}}
	view := c.create(save)
	if code, raw := c.do(http.MethodPost, "/api/groups/delete", map[string]string{"id": "grp_edge"}); code != http.StatusConflict || !strings.Contains(raw, view.ID) {
		t.Fatalf("delete a group a definition names = %d %s", code, raw)
	}
	us := monitorTo(t, definitionMonitors(st, view.ID), "node-us", "")
	if code, raw := c.do(http.MethodPost, "/api/nodes/delete", map[string]string{"node_id": "node-us"}); code != http.StatusOK {
		t.Fatalf("delete node = %d %s", code, raw)
	}
	if _, ok := st.Monitor(us.ID); ok {
		t.Fatalf("the removed node's monitor survived")
	}
	_ = srv
}

// D1: the sweep writes every changed definition in one store write and is
// audited like monitor.latency.sync; a sweep with nothing to change writes
// and records nothing.
func TestCheckDefinitionSweepIsBatchedAndAudited(t *testing.T) {
	srv, handler, st := checkFleet(t)
	c := newCheckClient(t, handler)
	first := c.create(tcpMesh([]string{"node-sh"}, []string{"node-jp"}))
	second := c.create(tcpMesh([]string{"node-bj"}, []string{"node-jp"}))
	// Both definitions follow node-us once it joins the whole fleet... by
	// a tag: make node-us part of both target sets through a group.
	if err := st.UpsertGroup(model.Group{ID: "grp_t", Name: "t", Slug: "t", Color: "sky", Selector: &model.GroupSelector{MatchTagsAny: []string{"target"}}}); err != nil {
		t.Fatal(err)
	}
	for _, view := range []model.CheckDefinitionView{first, second} {
		edit := saveOf(c.get(view.ID))
		edit.Targets = model.TargetSelector{Nodes: []string{"node-jp"}, Groups: []string{"grp_t"}}
		c.update(edit)
	}
	us, _ := st.Node("node-us")
	us.Tags = []string{"target"}
	if err := st.UpsertNode(us); err != nil {
		t.Fatal(err)
	}
	changes, err := srv.syncCheckDefinitions(checkT0, "sweep")
	if err != nil {
		t.Fatal(err)
	}
	changed := 0
	for _, ch := range changes {
		if ch.Changed() {
			changed++
		}
	}
	if changed != 2 {
		t.Fatalf("one sweep changed %d definitions, want both: %+v", changed, changes)
	}
	var sync *model.AuditEvent
	for _, ev := range st.AuditEvents() {
		if ev.Action == "monitor.check.sync" {
			ev := ev
			sync = &ev
		}
	}
	if sync == nil || sync.ActorID != systemActorID || sync.Metadata["trigger"] != "sweep" || !strings.Contains(sync.Metadata["definitions"], first.ID) || !strings.Contains(sync.Metadata["definitions"], second.ID) {
		t.Fatalf("sync audit = %+v", sync)
	}
	audits := len(st.AuditEvents())
	for i := range 3 {
		changes, err := srv.syncCheckDefinitions(checkT0, "sweep")
		if err != nil {
			t.Fatal(err)
		}
		for _, ch := range changes {
			if ch.Changed() {
				t.Fatalf("sweep %d wrote %+v", i, changes)
			}
		}
	}
	if len(st.AuditEvents()) != audits {
		t.Fatalf("a sweep without a change was audited")
	}
}

// D1: Fleet mesh is listed beside the definitions, and its ids and history
// do not change when definitions arrive.
// A node target's address comes from the path set planner's endpoint choice
// (design 32 D1), so it is as sticky as the path set's: a stale inventory
// keeps the address it dialled, a better-ranked line does not move a working
// monitor, and losing the chosen line does.
func TestCheckDefinitionNodeTargetIsSticky(t *testing.T) {
	srv, handler, st := checkFleet(t)
	c := newCheckClient(t, handler)
	view := c.create(model.CheckDefinitionSave{CheckDefinitionSpec: model.CheckDefinitionSpec{
		Name: "tcp jp", Type: model.MonitorTypeTCP, IntervalSec: 60, TimeoutSec: 5, Enabled: true,
		Sources: model.TargetSelector{Nodes: []string{"node-sh"}}, Targets: model.TargetSelector{Nodes: []string{"node-jp"}},
	}})
	clock := serverClock(t, srv)
	target := func(step string) string {
		t.Helper()
		// Past the planner's cache, so each sweep plans the fleet as it is now.
		clock.advance(pathPlanFresh + time.Second)
		if _, err := srv.syncCheckDefinitions(srv.now(), "sweep"); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		mons := definitionMonitors(st, view.ID)
		if len(mons) != 1 {
			t.Fatalf("%s: monitors = %+v", step, mons)
		}
		return mons[0].Target
	}
	if got := target("first plan"); got != "203.0.113.3:443" {
		t.Fatalf("first plan dials %q", got)
	}
	srv.removeSingBoxInventory("node-jp")
	if got := target("stale inventory"); got != "203.0.113.3:443" {
		t.Fatalf("a stale inventory moved the target to %q", got)
	}
	setLines := func(lines ...model.SingBoxNode) {
		srv.singboxInvMu.Lock()
		srv.singboxInv["node-jp"] = model.SingBoxInventory{NodeID: "node-jp", At: srv.now(), Status: "ok", Nodes: lines}
		srv.singboxInvMu.Unlock()
	}
	trojan := model.SingBoxNode{Name: "aaa-trojan-80", Protocol: "trojan", Network: "trojan", Port: "80", ListenHost: "::", Address: "203.0.113.3"}
	vless := model.SingBoxNode{Name: "vless-443", Protocol: "vless", Network: "reality", Port: "443", ListenHost: "::", Address: "203.0.113.3"}
	setLines(trojan, vless)
	if got := target("better-ranked line"); got != "203.0.113.3:443" {
		t.Fatalf("a better-ranked line moved a working target to %q", got)
	}
	setLines(trojan)
	if got := target("chosen line gone"); got != "203.0.113.3:80" {
		t.Fatalf("the chosen line went away and the target is %q", got)
	}
}

func TestFleetMeshListedAndUntouched(t *testing.T) {
	srv, handler, st := checkFleet(t)
	c := newCheckClient(t, handler)
	cfg := model.LatencyProbeConfig{Enabled: true, IntervalSec: 60, TimeoutSec: 5, Sources: []string{"node-sh"}, IncludeTargets: []string{"node-jp"}}
	if code, _, raw := putLatencyConfig(t, handler, c.cookies, c.csrf, cfg); code != http.StatusOK {
		t.Fatalf("path set save = %d %s", code, raw)
	}
	meshID := latencyMonitorID("node-jp")
	reportRun(t, st, meshID, "node-sh", checkT0)
	before, ok := st.Monitor(meshID)
	if !ok {
		t.Fatal("no path set check")
	}
	view := c.create(tcpMesh([]string{"node-sh"}, []string{"node-jp"}))
	if _, err := srv.syncCheckDefinitions(checkT0, "sweep"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := srv.syncLatencyProbes(checkT0); err != nil {
		t.Fatal(err)
	}
	after, ok := st.Monitor(meshID)
	if !ok || after.ManagedBy != model.MonitorManagedLatency || !after.UpdatedAt.Equal(before.UpdatedAt) || heldRuns(t, st, meshID, "node-sh") != 1 {
		t.Fatalf("path set check after definitions = %+v %v", after, ok)
	}
	code, raw := c.do(http.MethodGet, "/api/monitors/definitions", nil)
	if code != http.StatusOK {
		t.Fatalf("list = %d %s", code, raw)
	}
	var list model.CheckDefinitionList
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		t.Fatal(err)
	}
	if list.FleetMesh.Name != model.CheckFleetMeshName || !list.FleetMesh.Stored || list.FleetMesh.Paths != 1 || len(list.Definitions) != 1 || list.Definitions[0].ID != view.ID {
		t.Fatalf("list = %+v", list)
	}
	// The monitors list names the definition of an expanded monitor.
	code, raw = c.do(http.MethodGet, "/api/monitors", nil)
	if code != http.StatusOK || !strings.Contains(raw, `"check_definition_id":"`+view.ID+`"`) {
		t.Fatalf("monitors list = %d, want check_definition_id %s", code, view.ID)
	}
}

// A save validates the method's shape.
// A selector is stored in one canonical form that resolves to the same
// nodes as what was sent (design 32 D5): the whole fleet needs no named
// nodes or groups, an excluded node is never also named (an exclusion wins),
// and an exclusion with no group or whole fleet to subtract from says
// nothing. So the console, which edits that form, never changes what a
// definition made through the API measures.
func TestCheckDefinitionSelectorIsStoredCanonical(t *testing.T) {
	_, handler, st := checkFleet(t)
	if err := st.UpsertGroup(model.Group{ID: "grp_far", Name: "far", Slug: "far", Color: "sky", Members: []string{"node-jp", "node-us"}}); err != nil {
		t.Fatal(err)
	}
	c := newCheckClient(t, handler)
	cases := []struct {
		name     string
		sent     model.TargetSelector
		stored   model.TargetSelector
		resolves []string
	}{
		{"whole fleet drops named nodes and groups", model.TargetSelector{All: true, Nodes: []string{"node-jp"}, Groups: []string{"grp_far"}, Exclude: []string{"node-hk"}}, model.TargetSelector{All: true, Exclude: []string{"node-hk"}}, []string{"node-bj", "node-jp", "node-us"}},
		{"an excluded node leaves the named list", model.TargetSelector{Nodes: []string{"node-jp", "node-us"}, Exclude: []string{"node-jp"}}, model.TargetSelector{Nodes: []string{"node-us"}}, []string{"node-us"}},
		{"exclusions stay beside a group", model.TargetSelector{Groups: []string{"grp_far"}, Nodes: []string{"node-us", "node-hk"}, Exclude: []string{"node-us"}}, model.TargetSelector{Nodes: []string{"node-hk"}, Groups: []string{"grp_far"}, Exclude: []string{"node-us"}}, []string{"node-hk", "node-jp"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			view := c.create(model.CheckDefinitionSave{CheckDefinitionSpec: model.CheckDefinitionSpec{
				Name: tc.name, Type: model.MonitorTypeICMP, IntervalSec: 60, TimeoutSec: 5, Packets: 1, Enabled: true,
				Sources: model.TargetSelector{Nodes: []string{"node-sh"}}, Targets: tc.sent,
			}})
			if !reflect.DeepEqual(view.Targets, tc.stored) {
				t.Fatalf("stored %+v, want %+v", view.Targets, tc.stored)
			}
			var got []string
			for _, mon := range definitionMonitors(st, view.ID) {
				if mon.Enabled {
					got = append(got, mon.TargetNode)
				}
			}
			slices.Sort(got)
			if !slices.Equal(got, tc.resolves) {
				t.Fatalf("measures %v, want %v (the canonical form must resolve as the sent one did)", got, tc.resolves)
			}
		})
	}
}

func TestCheckDefinitionValidation(t *testing.T) {
	_, handler, _ := checkFleet(t)
	c := newCheckClient(t, handler)
	cases := []struct {
		name string
		save model.CheckDefinitionSave
		want string
	}{
		{"no name", model.CheckDefinitionSave{CheckDefinitionSpec: model.CheckDefinitionSpec{Type: "tcp", Sources: model.TargetSelector{Nodes: []string{"node-sh"}}, Targets: model.TargetSelector{Nodes: []string{"node-jp"}}}}, "name"},
		{"no sources", tcpMesh(nil, []string{"node-jp"}), "sources"},
		{"no targets", tcpMesh([]string{"node-sh"}, nil), "no target"},
		{"unknown node", tcpMesh([]string{"node-sh"}, []string{"node-zz"}), "not a node"},
		{"beacon address", model.CheckDefinitionSave{CheckDefinitionSpec: model.CheckDefinitionSpec{Name: "b", Type: "beacon", Sources: model.TargetSelector{Nodes: []string{"node-sh"}}, Addresses: []string{"203.0.113.9"}}}, "beacon"},
		{"http node target", model.CheckDefinitionSave{CheckDefinitionSpec: model.CheckDefinitionSpec{Name: "h", Type: "http", Sources: model.TargetSelector{Nodes: []string{"node-sh"}}, Targets: model.TargetSelector{Nodes: []string{"node-jp"}}}}, "addresses"},
		{"private address", model.CheckDefinitionSave{CheckDefinitionSpec: model.CheckDefinitionSpec{Name: "p", Type: "icmp", Sources: model.TargetSelector{Nodes: []string{"node-sh"}}, Addresses: []string{"10.0.0.1"}}}, "private"},
		{"tls sources", model.CheckDefinitionSave{CheckDefinitionSpec: model.CheckDefinitionSpec{Name: "t", Type: "tls", Sources: model.TargetSelector{Nodes: []string{"node-sh"}}, Addresses: []string{"example.com:443"}}}, "control plane"},
	}
	for _, tc := range cases {
		code, raw := c.do(http.MethodPost, "/api/monitors/definitions", tc.save)
		if code != http.StatusBadRequest || !strings.Contains(raw, tc.want) {
			t.Fatalf("%s: %d %s, want 400 mentioning %q", tc.name, code, raw, tc.want)
		}
	}
	// A tls definition runs on the control plane, one path per address.
	view := c.create(model.CheckDefinitionSave{CheckDefinitionSpec: model.CheckDefinitionSpec{Name: "certs", Type: "tls", Enabled: true, Addresses: []string{"Example.com:443", "example.org:8443"}}})
	if view.Summary.Monitors != 2 || view.Summary.Paths != 2 || view.Addresses[0] != "example.com:443" {
		t.Fatalf("tls definition = %+v", view)
	}
}

// The budget never takes a share from a pair that runs: when an older
// definition's source group grows into a source already at the budget, the
// older definition's new pair is the one paused, and the newer definition's
// running pair keeps going.
func TestCheckDefinitionPacketBudgetKeepsRunningPairs(t *testing.T) {
	srv, handler, st := checkFleet(t)
	c := newCheckClient(t, handler)
	if code, raw := c.do(http.MethodPost, "/api/monitors", map[string]any{
		"name": "op ping", "type": "icmp", "target_node": "node-jp", "packets": 10, "interval_sec": 10, "timeout_sec": 5, "node_ids": []string{"node-sh"},
	}); code != http.StatusOK {
		t.Fatalf("operator check = %d %s", code, raw)
	}
	if err := st.UpsertGroup(model.Group{ID: "grp_src", Name: "src", Slug: "src", Color: "sky", Members: []string{"node-bj"}}); err != nil {
		t.Fatal(err)
	}
	ping := func(name string, sources model.TargetSelector) model.CheckDefinitionSave {
		return model.CheckDefinitionSave{CheckDefinitionSpec: model.CheckDefinitionSpec{
			Name: name, Type: model.MonitorTypeICMP, IntervalSec: 10, TimeoutSec: 5, Packets: 10, Enabled: true,
			Sources: sources, Targets: model.TargetSelector{Nodes: []string{"node-jp"}},
		}}
	}
	older := c.create(ping("older", model.TargetSelector{Groups: []string{"grp_src"}}))
	serverClock(t, srv).set(checkT0.Add(time.Minute))
	newer := c.create(ping("newer", model.TargetSelector{Nodes: []string{"node-sh"}}))
	if mon := definitionMonitors(st, newer.ID)[0]; len(mon.PausedNodeIDs) != 0 {
		t.Fatalf("newer definition within the budget: %+v", mon)
	}
	if code, raw := c.do(http.MethodPost, "/api/groups/members", map[string]any{"group_id": "grp_src", "add": []string{"node-sh"}}); code != http.StatusOK {
		t.Fatalf("grow group = %d %s", code, raw)
	}
	if mon := definitionMonitors(st, older.ID)[0]; !slices.Equal(mon.PausedNodeIDs, []string{"node-sh"}) {
		t.Fatalf("older definition after its group grew = paused %v, want node-sh", mon.PausedNodeIDs)
	}
	if mon := definitionMonitors(st, newer.ID)[0]; len(mon.PausedNodeIDs) != 0 {
		t.Fatalf("the newer definition's running pair lost its share: %+v", mon)
	}
	// Further sweeps keep the same allocation.
	for range 3 {
		if _, err := srv.syncCheckDefinitions(srv.now(), "sweep"); err != nil {
			t.Fatal(err)
		}
	}
	if mon := definitionMonitors(st, newer.ID)[0]; len(mon.PausedNodeIDs) != 0 {
		t.Fatalf("the allocation flapped: %+v", mon)
	}
}

// A restricted token sees a definition that names only nodes it can read,
// but never the monitors of targets that left the set while the selector
// was broad, which name nodes it may not read; and the monitors list never
// shows it a broad definition's other sources or its id.
func TestCheckDefinitionRestrictedViewsNameOnlyReadableNodes(t *testing.T) {
	_, handler, _ := checkFleet(t)
	admin := newCheckClient(t, handler)
	confined := &checkClient{t: t, handler: handler, token: createPAT(t, handler, admin.cookies, admin.csrf, []string{"monitor:read", "monitor:admin"}, []string{"node-sh", "node-jp"})}

	broad := tcpMesh(nil, []string{"node-jp", "node-us"})
	broad.Sources = model.TargetSelector{All: true}
	view := admin.create(broad)
	code, raw := confined.do(http.MethodGet, "/api/monitors", nil)
	if code != http.StatusOK {
		t.Fatalf("monitors list = %d %s", code, raw)
	}
	var listed []map[string]any
	if err := json.Unmarshal([]byte(raw), &listed); err != nil {
		t.Fatal(err)
	}
	for _, mon := range listed {
		if strings.HasPrefix(mon["id"].(string), "mon_"+view.ID) {
			if mon["check_definition_id"] != nil {
				t.Fatalf("a restricted token learns the id of a definition it cannot read: %v", mon)
			}
			for _, nodeID := range mon["node_ids"].([]any) {
				if nodeID != "node-sh" && nodeID != "node-jp" {
					t.Fatalf("a restricted token sees source %v of a broad definition", nodeID)
				}
			}
		}
	}

	// Narrowed to nodes the token can read: the definition shows, its
	// paused target to node-us (whole-fleet sources) does not.
	edit := saveOf(view)
	edit.Sources = model.TargetSelector{Nodes: []string{"node-sh"}}
	edit.Targets = model.TargetSelector{Nodes: []string{"node-jp"}}
	admin.update(edit)
	got := confined.get(view.ID)
	for _, mon := range got.Monitors {
		if mon.TargetNode == "node-us" {
			t.Fatalf("a restricted token sees a paused target it cannot read: %+v", mon)
		}
		for _, source := range mon.Sources {
			if source != "node-sh" && source != "node-jp" {
				t.Fatalf("a restricted token sees source %s of a paused target", source)
			}
		}
	}
	if got.Summary.PausedTargets != 0 {
		t.Fatalf("restricted summary counts unreadable paused targets: %+v", got.Summary)
	}
	if full := admin.get(view.ID); full.Summary.PausedTargets != 1 {
		t.Fatalf("admin summary = %+v, want the paused target counted", full.Summary)
	}
}

// Scope is judged before existence: a restricted token naming an id it
// cannot read gets 403 whether or not the node exists.
func TestCheckDefinitionScopeBeforeExistence(t *testing.T) {
	_, handler, _ := checkFleet(t)
	admin := newCheckClient(t, handler)
	confined := &checkClient{t: t, handler: handler, token: createPAT(t, handler, admin.cookies, admin.csrf, []string{"monitor:read", "monitor:admin"}, []string{"node-sh", "node-jp"})}
	for _, target := range []string{"node-us", "node-does-not-exist"} {
		if code, raw := confined.do(http.MethodPost, "/api/monitors/definitions/preview", tcpMesh([]string{"node-sh"}, []string{target})); code != http.StatusForbidden {
			t.Fatalf("restricted target %s = %d %s, want 403 either way", target, code, raw)
		}
	}
}

// An edit that adds an origin may delete a secret header instead of
// setting it again; the one it keeps must be set again.
func TestCheckDefinitionSecretDeleteSettlesANewOrigin(t *testing.T) {
	_, handler, _ := checkFleet(t)
	c := newCheckClient(t, handler)
	view := c.create(model.CheckDefinitionSave{
		CheckDefinitionSpec: model.CheckDefinitionSpec{
			Name: "api", Type: model.MonitorTypeHTTP, IntervalSec: 60, TimeoutSec: 5, Enabled: true,
			Sources: model.TargetSelector{Nodes: []string{"node-sh"}}, Addresses: []string{"https://api.example.com/health"},
		},
		Headers: []model.MonitorHeaderEdit{
			{Name: "X-Api-Key", Op: model.MonitorHeaderSet, Value: "s3cret", Secret: true},
			{Name: "X-Old-Token", Op: model.MonitorHeaderSet, Value: "old", Secret: true},
		},
	})
	next := saveOf(view)
	next.Addresses = append(next.Addresses, "https://other.example.net/health")
	next.Headers = []model.MonitorHeaderEdit{
		{Name: "X-Old-Token", Op: model.MonitorHeaderDelete},
		{Name: "X-Api-Key", Op: model.MonitorHeaderSet, Value: "s3cret2", Secret: true},
	}
	got := c.update(next)
	if len(got.Headers) != 1 || got.Headers[0].Name != "X-Api-Key" || len(got.SecretsOrigins) != 2 {
		t.Fatalf("after deleting one secret and setting the other = headers %+v origins %v", got.Headers, got.SecretsOrigins)
	}
}

// The bounds a save may leave: paths, paused targets and the number of
// definitions.
func TestCheckDefinitionBounds(t *testing.T) {
	plan := checkDefinitionPlan{def: model.CheckDefinition{CheckDefinitionSpec: model.CheckDefinitionSpec{Type: model.MonitorTypeTCP}}}
	for i := range model.CheckDefinitionPausedMax + 1 {
		plan.desired = append(plan.desired, model.Monitor{ID: "mon_paused_" + strconv.Itoa(i)})
	}
	if err := checkPlanBounds(plan); err == nil || !strings.Contains(err.Error(), "forget") {
		t.Fatalf("too many paused targets = %v", err)
	}
	plan.desired = nil
	for i := range 65 {
		plan.sources = append(plan.sources, "src-"+strconv.Itoa(i))
		plan.entries = append(plan.entries, checkPlanEntry{key: "t-" + strconv.Itoa(i), targetNode: "t-" + strconv.Itoa(i)})
	}
	if err := checkPlanBounds(plan); err == nil || !strings.Contains(err.Error(), "paths") {
		t.Fatalf("65 by 65 = %v, want the path bound", err)
	}

	_, handler, st := checkFleet(t)
	c := newCheckClient(t, handler)
	for i := range model.CheckDefinitionsMax {
		id := "chk_fill" + strconv.Itoa(i)
		if _, _, err := st.SaveCheckDefinition(model.CheckDefinition{ID: id, CheckDefinitionSpec: model.CheckDefinitionSpec{Name: id, Type: model.MonitorTypeTCP}}, 0, "admin", nil, checkT0); err != nil {
			t.Fatal(err)
		}
	}
	if code, raw := c.do(http.MethodPost, "/api/monitors/definitions", tcpMesh([]string{"node-sh"}, []string{"node-jp"})); code != http.StatusBadRequest || !strings.Contains(raw, "at most") {
		t.Fatalf("create past the definition bound = %d %s", code, raw)
	}
}

// The dry run of an edit that frees packet budget names the other
// definition whose paused pair the save would resume.
func TestCheckDefinitionPreviewNamesOtherDefinitionsItRewrites(t *testing.T) {
	_, handler, st := checkFleet(t)
	c := newCheckClient(t, handler)
	ping := func(name string) model.CheckDefinitionSave {
		return model.CheckDefinitionSave{CheckDefinitionSpec: model.CheckDefinitionSpec{
			Name: name, Type: model.MonitorTypeICMP, IntervalSec: 10, TimeoutSec: 5, Packets: 10, Enabled: true,
			Sources: model.TargetSelector{Nodes: []string{"node-sh"}}, Targets: model.TargetSelector{Nodes: []string{"node-jp"}},
		}}
	}
	first := c.create(ping("first"))
	second := c.create(ping("second"))
	third := c.create(ping("third"))
	if mon := definitionMonitors(st, third.ID)[0]; len(mon.PausedNodeIDs) != 1 {
		t.Fatalf("the third definition should be over the budget: %+v", mon)
	}
	off := saveOf(first)
	off.Enabled = false
	pre := c.preview(off)
	if !slices.Contains(pre.AlsoChanges, third.ID) || slices.Contains(pre.AlsoChanges, second.ID) {
		t.Fatalf("also_changes = %v, want %s (resumed) and not %s", pre.AlsoChanges, third.ID, second.ID)
	}
}

// Saves, previews and sweeps run at once without a race or a lost write.
func TestCheckDefinitionSavesAndSweepsConcurrently(t *testing.T) {
	srv, handler, st := checkFleet(t)
	c := newCheckClient(t, handler)
	view := c.create(tcpMesh([]string{"node-sh"}, []string{"node-jp"}))
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 20 {
			if _, err := srv.syncCheckDefinitions(checkT0, "sweep"); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for i := range 10 {
		edit := saveOf(c.get(view.ID))
		edit.IntervalSec = 60 + 10*(i+1)
		c.update(edit)
		c.preview(edit)
	}
	<-done
	if def, _ := st.CheckDefinition(view.ID); def.IntervalSec != 160 {
		t.Fatalf("final interval = %d, want the last edit's 160", def.IntervalSec)
	}
	for _, mon := range definitionMonitors(st, view.ID) {
		if mon.IntervalSec != 160 {
			t.Fatalf("monitor after concurrent saves = %+v", mon)
		}
	}
}
