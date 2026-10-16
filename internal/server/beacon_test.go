package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/beacon"
	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/netguard"
	"github.com/LatticeNet/lattice-server/internal/network"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// beaconT0 is the clock every beacon test starts from.
var beaconT0 = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func beaconAdmin() principal {
	return principal{Principal: rbac.Principal{ActorID: "admin", Scopes: []string{"*"}}}
}

// beaconFleet is a server whose path set probes node-t from node-a and
// node-b (agents with the beacon client) and node-c (an older agent), all
// on auto. node-t reports a responder that is not listening yet.
func beaconFleet(t *testing.T) (*Server, http.Handler, *store.Store) {
	t.Helper()
	srv, handler, st := newPathsServer(t)
	srv.now = func() time.Time { return beaconT0 }
	all := []string{"beacon", "http", "icmp", "tcp"}
	upsertNodes(t, st,
		model.Node{ID: "node-t", Name: "target", PublicIP: "198.51.100.30", InternalIP: "10.1.0.5", WireGuardIP: "10.66.0.30", WireGuardPort: 51820, Online: true, ProbeMethods: all,
			Geo: &model.NodeGeo{Country: "JP"}, Beacon: &model.BeaconFacts{Responder: true, State: model.BeaconAgentOff}},
		model.Node{ID: "node-a", Name: "alpha", PublicIP: "203.0.113.21", WireGuardIP: "10.66.0.21", Online: true, ProbeMethods: all},
		model.Node{ID: "node-b", Name: "bravo", PublicIP: "203.0.113.22", Online: true, ProbeMethods: all},
		model.Node{ID: "node-c", Name: "charlie", PublicIP: "203.0.113.23", Online: true, ProbeMethods: []string{"http", "icmp", "tcp"}},
	)
	srv.singboxInvMu.Lock()
	if srv.singboxInv == nil {
		srv.singboxInv = map[string]model.SingBoxInventory{}
	}
	srv.singboxInv["node-t"] = model.SingBoxInventory{NodeID: "node-t", At: beaconT0, Status: "ok", Nodes: []model.SingBoxNode{
		{Name: "vless-443", Protocol: "vless", Network: "reality", Port: "443", ListenHost: "::", Address: "198.51.100.30"},
	}}
	srv.singboxInvMu.Unlock()
	saveBeaconPathSet(t, srv, st, model.LatencyProbeConfig{
		Enabled: true, Sources: []string{"node-a", "node-b", "node-c"}, IncludeTargets: []string{"node-t"}, Method: model.LatencyMethodAuto,
	})
	return srv, handler, st
}

func saveBeaconPathSet(t *testing.T, srv *Server, st *store.Store, cfg model.LatencyProbeConfig) {
	t.Helper()
	prior, _ := st.LatencyProbeConfig()
	cfg.IntervalSec, cfg.TimeoutSec = 60, 5
	if _, err := st.SetLatencyProbeConfig(cfg, prior.Version, "admin", srv.now()); err != nil {
		t.Fatal(err)
	}
	srv.monitorPaths.notePlan(latencyPlan{}, time.Time{})
	if _, _, err := srv.syncLatencyProbes(srv.now()); err != nil {
		t.Fatal(err)
	}
}

// setBeaconFacts makes nodeID's agent report facts.
func setBeaconFacts(t *testing.T, srv *Server, st *store.Store, nodeID string, facts model.BeaconFacts) {
	t.Helper()
	n, _ := st.Node(nodeID)
	srv.noteBeaconFacts(nodeID, n.Beacon, &facts)
}

// listenAsPlanned makes node-t report listening where its applied plan put
// the beacon.
func listenAsPlanned(t *testing.T, srv *Server, st *store.Store) {
	t.Helper()
	bt, ok := st.BeaconTarget("node-t")
	if !ok {
		t.Fatal("no beacon state for node-t")
	}
	setBeaconFacts(t, srv, st, "node-t", model.BeaconFacts{Responder: true, State: model.BeaconAgentListening, Bind: bt.Settings.Bind, Port: bt.Settings.Port})
	srv.monitorPaths.notePlan(latencyPlan{}, time.Time{})
	if _, _, err := srv.syncLatencyProbes(srv.now()); err != nil {
		t.Fatal(err)
	}
}

// beaconSessions keeps one login per test (each builds its own server), so
// a test that plans many times stays under the login rate limit.
var beaconSessions sync.Map

type beaconSession struct {
	cookies []*http.Cookie
	csrf    string
}

func beaconLogin(t *testing.T, handler http.Handler) ([]*http.Cookie, string) {
	t.Helper()
	if v, ok := beaconSessions.Load(t); ok {
		s := v.(beaconSession)
		return s.cookies, s.csrf
	}
	cookies, csrf := loginSession(t, handler)
	beaconSessions.Store(t, beaconSession{cookies: cookies, csrf: csrf})
	t.Cleanup(func() { beaconSessions.Delete(t) })
	return cookies, csrf
}

func planBeacon(t *testing.T, handler http.Handler, req model.BeaconPlanRequest) (int, model.BeaconPlanResponse, string) {
	t.Helper()
	cookies, csrf := beaconLogin(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/nodes/beacon/plan", string(mustJSON(t, req)), cookies, csrf)
	raw := readBody(t, res)
	var out model.BeaconPlanResponse
	if res.StatusCode == http.StatusOK {
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			t.Fatal(err)
		}
	}
	return res.StatusCode, out, raw
}

func decideBeacon(srv *Server, approval model.Approval, p principal) (model.Approval, error) {
	sum := sha256.Sum256([]byte(approval.Plan))
	return srv.approveApprovalCore(context.Background(), p, approval, true, fmt.Sprintf("%x", sum))
}

// enableBeacon plans and approves an enable on node-t.
func enableBeacon(t *testing.T, srv *Server, handler http.Handler, req model.BeaconPlanRequest) model.BeaconPlanResponse {
	t.Helper()
	req.NodeID, req.Action = "node-t", model.BeaconActionEnable
	code, out, raw := planBeacon(t, handler, req)
	if code != http.StatusOK {
		t.Fatalf("plan = %d %s", code, raw)
	}
	if _, err := decideBeacon(srv, out.Approval, beaconAdmin()); err != nil {
		t.Fatalf("approve: %v", err)
	}
	return out
}

func targetKeyOf(t *testing.T, st *store.Store, nodeID string) beacon.Key {
	t.Helper()
	bt, ok := st.BeaconTarget(nodeID)
	if !ok {
		t.Fatalf("no beacon state for %s", nodeID)
	}
	key, ok := beaconTargetKey(bt)
	if !ok {
		t.Fatalf("node %s holds no target key", nodeID)
	}
	return key
}

func nodeOf(t *testing.T, st *store.Store, nodeID string) model.Node {
	t.Helper()
	n, ok := st.Node(nodeID)
	if !ok {
		t.Fatalf("no node %s", nodeID)
	}
	return n
}

// A source only ever receives its own path key, and a target only its own
// table: every key on the wire is the derivation for that (source, epoch),
// and a request one side signs is one the other side's table answers.
func TestBeaconKeyTablesGoOnlyToTheirOwners(t *testing.T) {
	srv, handler, st := beaconFleet(t)
	plan := enableBeacon(t, srv, handler, model.BeaconPlanRequest{})
	listenAsPlanned(t, srv, st)
	if got := len(plan.Plan.Sources); got != 2 {
		t.Fatalf("approved sources = %+v, want node-a and node-b (node-c runs no beacon client)", plan.Plan.Sources)
	}
	now := srv.now()
	key := targetKeyOf(t, st, "node-t")
	ids := st.BeaconSourceIDs()
	if ids["node-a"] == 0 || ids["node-b"] == 0 || ids["node-a"] == ids["node-b"] {
		t.Fatalf("source ids = %v", ids)
	}

	target := srv.agentBeaconConfig(nodeOf(t, st, "node-t"), now)
	if target == nil || target.Responder == nil {
		t.Fatalf("target config = %+v", target)
	}
	if len(target.Keys) != 0 {
		t.Fatalf("the target received source keys: %+v", target.Keys)
	}
	bt, _ := st.BeaconTarget("node-t")
	var tableIDs []uint32
	for _, e := range target.Responder.Table {
		want := beacon.DerivePathKey(&key, e.SourceID, e.Epoch)
		if string(e.Key) != string(want[:]) || e.Epoch != bt.Epoch || e.Retired {
			t.Fatalf("table entry %+v is not the derivation for its source and epoch %d", e, bt.Epoch)
		}
		tableIDs = append(tableIDs, e.SourceID)
	}
	slices.Sort(tableIDs)
	wantIDs := []uint32{ids["node-a"], ids["node-b"]}
	slices.Sort(wantIDs)
	if !slices.Equal(tableIDs, wantIDs) {
		t.Fatalf("table holds sources %v, want %v", tableIDs, wantIDs)
	}
	if target.Responder.Bind != "10.1.0.5" || target.Responder.Port < beacon.PortRandomMin || target.Responder.Port > beacon.PortRandomMax {
		t.Fatalf("responder = %+v; want the primary interface address and a random port", target.Responder)
	}

	var keyA []byte
	for _, nodeID := range []string{"node-a", "node-b"} {
		cfg := srv.agentBeaconConfig(nodeOf(t, st, nodeID), now)
		if cfg == nil || cfg.Responder != nil || len(cfg.Keys) != 1 || cfg.SourceID != ids[nodeID] {
			t.Fatalf("%s config = %+v", nodeID, cfg)
		}
		k := cfg.Keys[0]
		want := beacon.DerivePathKey(&key, ids[nodeID], k.Epoch)
		if k.TargetNode != "node-t" || string(k.Key) != string(want[:]) {
			t.Fatalf("%s holds %+v, not its own path key", nodeID, k)
		}
		if nodeID == "node-a" {
			keyA = k.Key
		} else if string(keyA) == string(k.Key) {
			t.Fatal("two sources hold the same path key")
		}
	}
	if cfg := srv.agentBeaconConfig(nodeOf(t, st, "node-c"), now); cfg != nil && len(cfg.Keys) > 0 {
		t.Fatalf("an agent without the beacon client got keys: %+v", cfg)
	}

	// End to end through the SDK: node-a signs, node-t's table answers.
	r := beacon.NewResponder(now.Add(-time.Hour))
	var entries []beacon.TableEntry
	for _, e := range target.Responder.Table {
		var k beacon.Key
		copy(k[:], e.Key)
		entries = append(entries, beacon.TableEntry{SourceID: e.SourceID, Epoch: e.Epoch, Key: k, Retired: e.Retired})
	}
	if err := r.SetTable(entries); err != nil {
		t.Fatal(err)
	}
	var pathKey beacon.Key
	copy(pathKey[:], keyA)
	req := beacon.Request{Epoch: srv.agentBeaconConfig(nodeOf(t, st, "node-a"), now).Keys[0].Epoch, SourceID: ids["node-a"], Seq: 1, SentUnixNano: now.UnixNano()}
	req.Nonce[0] = 7
	pkt := make([]byte, beacon.RequestLen)
	if _, err := beacon.EncodeRequest(pkt, &pathKey, &req); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, beacon.ReplyLen)
	if n, v := r.Handle(now, pkt, out); v != beacon.ReplyOK || n != beacon.ReplyLen {
		t.Fatalf("the target's table did not answer the source's request: %v", v)
	}
}

// Epochs N and N-1 are both accepted across a rotation: sources keep
// signing with N-1 until the target has held N for the switch delay, N-1
// stays accepted for the overlap, then answers only as retired, then goes.
func TestBeaconRotationKeepsTwoEpochs(t *testing.T) {
	srv, handler, st := beaconFleet(t)
	enableBeacon(t, srv, handler, model.BeaconPlanRequest{})
	listenAsPlanned(t, srv, st)
	t0 := srv.now()
	srv.agentBeaconConfig(nodeOf(t, st, "node-t"), t0)
	first, _ := st.BeaconTarget("node-t")

	cookies, csrf := beaconLogin(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/nodes/beacon/rotate", `{"node_id":"node-t"}`, cookies, csrf)
	var rotated model.BeaconRotateResponse
	if raw := readBody(t, res); res.StatusCode != http.StatusOK || json.Unmarshal([]byte(raw), &rotated) != nil || rotated.Epoch != first.Epoch+1 {
		t.Fatalf("rotate = %d %s", res.StatusCode, raw)
	}
	n, o := rotated.Epoch, first.Epoch
	epochOf := func(at time.Time) uint32 {
		cfg := srv.agentBeaconConfig(nodeOf(t, st, "node-a"), at)
		if cfg == nil || len(cfg.Keys) != 1 {
			t.Fatalf("node-a config at %v = %+v", at, cfg)
		}
		return cfg.Keys[0].Epoch
	}
	tableAt := func(at time.Time) map[uint32]bool {
		cfg := srv.agentBeaconConfig(nodeOf(t, st, "node-t"), at)
		out := map[uint32]bool{}
		for _, e := range cfg.Responder.Table {
			out[e.Epoch] = e.Retired
		}
		return out
	}
	if got := epochOf(t0); got != o {
		t.Fatalf("before the target pulls the new epoch a source signs with %d, want %d", got, o)
	}
	acked := t0.Add(time.Second)
	if table := tableAt(acked); len(table) != 2 || table[n] || table[o] {
		t.Fatalf("table after the rotation = %v; want both epochs accepted", table)
	}
	if got := epochOf(acked.Add(model.BeaconSourceSwitchDelay - time.Second)); got != o {
		t.Fatalf("inside the switch delay a source signs with %d, want %d", got, o)
	}
	if got := epochOf(acked.Add(model.BeaconSourceSwitchDelay)); got != n {
		t.Fatalf("after the switch delay a source signs with %d, want %d", got, n)
	}
	if table := tableAt(acked.Add(model.BeaconEpochOverlap - time.Second)); table[o] {
		t.Fatalf("inside the overlap the old epoch is retired: %v", table)
	}
	afterOverlap := tableAt(acked.Add(model.BeaconEpochOverlap + time.Second))
	if retired, ok := afterOverlap[o]; !ok || !retired {
		t.Fatalf("after the overlap the old epoch should be retired: %v", afterOverlap)
	}
	afterGrace := tableAt(acked.Add(model.BeaconEpochOverlap + model.BeaconRetiredGrace + time.Second))
	if _, ok := afterGrace[n]; len(afterGrace) != 1 || !ok {
		t.Fatalf("after the grace only the new epoch is held: %v", afterGrace)
	}
	audit := beaconAuditActions(st)
	if !slices.Contains(audit, "beacon.rotate") {
		t.Fatalf("rotation was not audited: %v", audit)
	}
}

func beaconAuditActions(st *store.Store) []string {
	var out []string
	for _, e := range st.AuditEvents() {
		out = append(out, e.Action)
	}
	return out
}

// A source leaving the target's table rotates the epoch and takes its key
// with it.
func TestBeaconRotatesWhenASourceLeaves(t *testing.T) {
	srv, handler, st := beaconFleet(t)
	enableBeacon(t, srv, handler, model.BeaconPlanRequest{})
	listenAsPlanned(t, srv, st)
	now := srv.now()
	srv.agentBeaconConfig(nodeOf(t, st, "node-t"), now)
	before, _ := st.BeaconTarget("node-t")
	saveBeaconPathSet(t, srv, st, model.LatencyProbeConfig{
		Enabled: true, Sources: []string{"node-a", "node-b", "node-c"}, IncludeTargets: []string{"node-t"}, Method: model.LatencyMethodAuto,
		DisabledPairs: []model.LatencyPair{{Source: "node-b", Target: "node-t"}},
	})
	cfg := srv.agentBeaconConfig(nodeOf(t, st, "node-t"), now.Add(time.Second))
	after, _ := st.BeaconTarget("node-t")
	if after.Epoch != before.Epoch+1 || after.PrevEpoch != before.Epoch {
		t.Fatalf("epoch %d -> %d (prev %d); a source leaving must rotate", before.Epoch, after.Epoch, after.PrevEpoch)
	}
	idB := st.BeaconSourceIDs()["node-b"]
	for _, e := range cfg.Responder.Table {
		if e.SourceID == idB {
			t.Fatalf("the table still holds the source that left: %+v", e)
		}
	}
	if b := srv.agentBeaconConfig(nodeOf(t, st, "node-b"), now.Add(time.Second)); b != nil && len(b.Keys) > 0 {
		t.Fatalf("the source that left still gets a key: %+v", b.Keys)
	}
}

// The plan's hash covers the port, the bind address, the endpoint, the
// source set and the limits: changing any of them changes the document,
// and a decision against a document live state no longer renders is
// refused as stale.
func TestBeaconPlanHashCoversEveryField(t *testing.T) {
	srv, handler, st := beaconFleet(t)
	code, out, raw := planBeacon(t, handler, model.BeaconPlanRequest{NodeID: "node-t", Action: model.BeaconActionEnable})
	if code != http.StatusOK {
		t.Fatalf("plan = %d %s", code, raw)
	}
	for _, field := range []string{`"port":`, `"bind": "10.1.0.5"`, `"endpoint": "198.51.100.30:`, `"limits":`, `"source_rate_per_second": 20`, `"min_interval_sec": 10`, `"packets_per_second_max": 2`, `"node_id": "node-a"`, `"node_id": "node-b"`, `"exposure": "internet"`} {
		if !strings.Contains(out.Approval.Plan, field) {
			t.Fatalf("plan document lacks %s:\n%s", field, out.Approval.Plan)
		}
	}
	node := nodeOf(t, st, "node-t")
	bt, _ := st.BeaconTarget("node-t")
	base := out.Plan.Beacon
	render := func(s model.BeaconSettings) string {
		_, doc, err := srv.buildBeaconPlan(node, model.BeaconActionEnable, s, bt, srv.now(), srv.compileInputForSystem)
		if err != nil {
			t.Fatal(err)
		}
		return doc
	}
	if render(base) != out.Approval.Plan {
		t.Fatal("rendering the same settings again does not reproduce the document")
	}
	for name, mutate := range map[string]func(*model.BeaconSettings){
		"port":     func(s *model.BeaconSettings) { s.Port++ },
		"bind":     func(s *model.BeaconSettings) { s.Bind = "198.51.100.30" },
		"endpoint": func(s *model.BeaconSettings) { s.Endpoint = "203.0.113.99:40001" },
		"limits":   func(s *model.BeaconSettings) { s.Limits.PacketsPerSecondMax = 1 },
		"enabled":  func(s *model.BeaconSettings) { s.Enabled = false },
	} {
		changed := base
		mutate(&changed)
		if render(changed) == out.Approval.Plan {
			t.Errorf("changing the %s leaves the document, and so its hash, unchanged", name)
		}
	}

	// The source set moves under a pending approval: the decision refuses it.
	saveBeaconPathSet(t, srv, st, model.LatencyProbeConfig{
		Enabled: true, Sources: []string{"node-a", "node-c"}, IncludeTargets: []string{"node-t"}, Method: model.LatencyMethodAuto,
	})
	if _, err := decideBeacon(srv, out.Approval, beaconAdmin()); err == nil || !strings.Contains(err.Error(), "re-plan") {
		t.Fatalf("a plan whose source set changed was approved: %v", err)
	}
	if got, _ := st.Approval(out.Approval.ID); got.Status != model.ApprovalPending {
		t.Fatalf("a refused decision changed the approval: %+v", got)
	}
	// A hash that is not the document's is refused before anything else.
	if _, err := srv.approveApprovalCore(context.Background(), beaconAdmin(), out.Approval, true, strings.Repeat("0", 64)); err == nil {
		t.Fatal("a decision naming another hash was accepted")
	}
	if _, ok := st.BeaconTarget("node-t"); ok {
		if bt, _ := st.BeaconTarget("node-t"); bt.Settings.Enabled {
			t.Fatal("a refused plan enabled the beacon")
		}
	}
}

// With NetGuard managing the node, the plan carries the companion: UDP to
// the port from exactly the approved sources' /32s (pinned public and
// WireGuard addresses, plus a different egress), notrack both ways, the
// whole ruleset under the hash, and an apply task in the same approval.
// Every later NetGuard compile keeps the companion, and a source added
// later reads firewall pending until a change plan applies.
func TestBeaconNetGuardCompanion(t *testing.T) {
	srv, handler, st := beaconFleet(t)
	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "node-t", Managed: true}); err != nil {
		t.Fatal(err)
	}
	srv.replaceAgentCapabilities("node-t", []string{netGuardManagedSHACapability})
	srv.beacon.noteEgress("node-a", "10.66.0.21")    // over WireGuard: says nothing about egress
	srv.beacon.noteEgress("node-b", "203.0.113.122") // a NAT source's real egress
	srv.beacon.noteEgress("node-b", "10.9.9.9")      // a private hop is never kept as egress
	code, out, raw := planBeacon(t, handler, model.BeaconPlanRequest{NodeID: "node-t", Action: model.BeaconActionEnable})
	if code != http.StatusOK {
		t.Fatalf("plan = %d %s", code, raw)
	}
	ng := out.Plan.NetGuard
	if out.Plan.Exposure != model.BeaconExposureNetGuard || ng == nil || !ng.Notrack {
		t.Fatalf("plan = %+v", out.Plan)
	}
	wantAllow := []string{"10.66.0.21/32", "203.0.113.122/32", "203.0.113.21/32", "203.0.113.22/32"}
	if !slices.Equal(ng.Allow, wantAllow) {
		t.Fatalf("allow = %v, want %v", ng.Allow, wantAllow)
	}
	port := out.Plan.Beacon.Port
	for _, want := range []string{
		fmt.Sprintf("udp dport { %d } accept comment \"lattice beacon\"", port),
		fmt.Sprintf("udp dport { %d } notrack", port),
		fmt.Sprintf("udp sport { %d } notrack", port),
		"type filter hook prerouting priority raw",
		"type filter hook output priority raw",
	} {
		if !strings.Contains(ng.Ruleset, want) {
			t.Fatalf("ruleset lacks %q:\n%s", want, ng.Ruleset)
		}
	}
	if sum := sha256.Sum256([]byte(ng.Ruleset)); fmt.Sprintf("%x", sum) != ng.RulesetSHA256 {
		t.Fatal("ruleset_sha256 is not the ruleset's")
	}
	if doc, err := beaconPlanOf(out.Approval); err != nil || doc.NetGuard == nil || doc.NetGuard.Ruleset != ng.Ruleset {
		t.Fatal("the ruleset is not inside the hashed document")
	}

	// Deciding without netguard:admin is refused.
	limited := principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"network:apply", "monitor:admin", "node:admin"}}}
	if _, err := decideBeacon(srv, out.Approval, limited); err == nil {
		t.Fatal("a decider without netguard:admin approved NetGuard rules")
	}
	approved, err := decideBeacon(srv, out.Approval, beaconAdmin())
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != model.ApprovalApproved {
		t.Fatalf("approval = %s; the companion still has to run", approved.Status)
	}
	tasks := tasksFor(srv, approved.ID)
	if len(tasks) != 1 || !strings.Contains(tasks[0].Script, fmt.Sprintf("udp dport { %d } notrack", port)) || tasks[0].Targets[0] != "node-t" {
		t.Fatalf("tasks = %+v", tasks)
	}
	binding, _ := st.NodeGuardBinding("node-t")
	if binding.LastPlanSHA != ng.RulesetSHA256 {
		t.Fatal("the binding does not record the companion ruleset as its latest plan")
	}
	if current, err := srv.currentNetGuardPlanSHA("node-t"); err != nil || current != ng.RulesetSHA256 {
		t.Fatalf("a NetGuard compile after the apply drops the companion: %v", err)
	}

	// The apply reports the managed table hash: the approval applies.
	managed := strings.Repeat("ab", 32)
	if err := srv.handleBeaconTaskResult(httptestRequest(), approved, tasks[0], model.TaskResult{TaskID: tasks[0].ID, NodeID: "node-t", Stdout: netGuardManagedSHAResultPrefix + managed + "\n", FinishedAt: srv.now()}); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Approval(approved.ID); got.Status != model.ApprovalApplied {
		t.Fatalf("approval after a good apply = %s", got.Status)
	}
	if binding, _ := st.NodeGuardBinding("node-t"); binding.AppliedTableSHA != managed {
		t.Fatalf("binding applied sha = %q", binding.AppliedTableSHA)
	}

	// A source pinned to the beacon that the plan did not approve reads
	// firewall pending, and so does the beacon view.
	upsertNodes(t, st, model.Node{ID: "node-d", Name: "delta", PublicIP: "203.0.113.24", Online: true, ProbeMethods: []string{"beacon", "http", "icmp", "tcp"}})
	listenAsPlanned(t, srv, st)
	saveBeaconPathSet(t, srv, st, model.LatencyProbeConfig{
		Enabled: true, Sources: []string{"node-a", "node-b", "node-c", "node-d"}, IncludeTargets: []string{"node-t"}, Method: model.LatencyMethodAuto,
		SourceMethods: map[string]string{"node-d": model.LatencyMethodBeacon},
	})
	plan := srv.pathPlan(srv.now())
	found := false
	for _, pair := range plan.Pairs {
		if pair.Source == "node-d" && pair.Target == "node-t" {
			found = true
			if pair.Active || pair.Reason != model.PathReasonFirewallPending {
				t.Fatalf("an unapproved pinned source = %+v", pair)
			}
		}
	}
	if !found {
		t.Fatal("no node-d pair")
	}
	view := srv.beaconView(beaconAdmin(), nodeOf(t, st, "node-t"), srv.now())
	if !view.FirewallPending {
		t.Fatalf("view = %+v; want firewall pending", view)
	}
	var d model.BeaconSourceView
	for _, sv := range view.Sources {
		if sv.NodeID == "node-d" {
			d = sv
		}
	}
	if d.Approved || !d.Current || d.Reason != model.PathReasonFirewallPending {
		t.Fatalf("node-d in the view = %+v", d)
	}
	if cfg := srv.agentBeaconConfig(nodeOf(t, st, "node-d"), srv.now()); cfg != nil && len(cfg.Keys) > 0 {
		t.Fatalf("an unapproved source holds a key: %+v", cfg.Keys)
	}
	for _, mon := range agentMonitorList(t, srv, st, "node-d") {
		if mon.Type == model.MonitorTypeBeacon {
			t.Fatalf("an unapproved source was handed a beacon check: %+v", mon)
		}
	}
}

// The companion's ruleset is byte for byte the old one with nothing to
// notrack, and adds both raw chains when there is.
func TestBeaconNotrackRendering(t *testing.T) {
	srv, _, st := beaconFleet(t)
	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "node-t", Managed: true}); err != nil {
		t.Fatal(err)
	}
	input, err := srv.compileInputForSystem("node-t")
	if err != nil {
		t.Fatal(err)
	}
	if input.Beacon != nil {
		t.Fatal("a node without an applied beacon compiles with a companion")
	}
	plain, err := netguardRuleset(input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain, "notrack") || strings.Contains(plain, "beacon") {
		t.Fatalf("a ruleset without a beacon mentions it:\n%s", plain)
	}
}

func httptestRequest() *http.Request {
	r, _ := http.NewRequest(http.MethodPost, "/api/agent/task-result", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	return r
}

// netguardRuleset renders a compile input's ruleset.
func netguardRuleset(input netguard.CompileInput) (string, error) {
	compiled, err := netguard.Compile(input)
	if err != nil {
		return "", err
	}
	return network.GenerateNFTPlan(compiled)
}
