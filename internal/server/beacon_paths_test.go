package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/beacon"
	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func pairOf(t *testing.T, plan model.LatencyProbePlan, source, target string) model.LatencyProbePairState {
	t.Helper()
	for _, pair := range plan.Pairs {
		if pair.Source == source && pair.Target == target {
			return pair
		}
	}
	t.Fatalf("no pair %s to %s in %+v", source, target, plan.Pairs)
	return model.LatencyProbePairState{}
}

// D2's preference on auto: the beacon for approved sources of a listening
// target, icmp for a source without the beacon client, and back to icmp
// while the target is not listening. The generated beacon check carries
// the beacon's endpoint and the target node, and the path series joins it.
func TestBeaconMethodPreference(t *testing.T) {
	srv, handler, st := beaconFleet(t)
	plan := srv.pathPlan(srv.now())
	if got := pairOf(t, plan, "node-a", "node-t").Method; got != model.MonitorTypeICMP {
		t.Fatalf("without a beacon auto took %s, want icmp", got)
	}
	enabled := enableBeacon(t, srv, handler, model.BeaconPlanRequest{})
	srv.monitorPaths.notePlan(latencyPlan{}, time.Time{})
	if _, _, err := srv.syncLatencyProbes(srv.now()); err != nil {
		t.Fatal(err)
	}
	if got := pairOf(t, srv.pathPlan(srv.now()), "node-a", "node-t").Method; got != model.MonitorTypeICMP {
		t.Fatalf("before the target listens auto took %s, want icmp", got)
	}
	listenAsPlanned(t, srv, st)
	plan = srv.pathPlan(srv.now())
	for _, source := range []string{"node-a", "node-b"} {
		pair := pairOf(t, plan, source, "node-t")
		if pair.Method != model.MonitorTypeBeacon || !pair.Active || pair.MonitorID != model.LatencyMonitorPrefixBeacon+"node-t" {
			t.Fatalf("%s pair = %+v, want an active beacon pair", source, pair)
		}
	}
	if pair := pairOf(t, plan, "node-c", "node-t"); pair.Method != model.MonitorTypeICMP {
		t.Fatalf("an agent without the beacon client = %+v, want icmp", pair)
	}
	mon, ok := st.Monitor(model.LatencyMonitorPrefixBeacon + "node-t")
	if !ok || mon.Type != model.MonitorTypeBeacon || mon.TargetNode != "node-t" || mon.Target != enabled.Plan.Beacon.Endpoint ||
		mon.Packets != model.MonitorPacketsDefault || !slices.Equal(mon.NodeIDs, []string{"node-a", "node-b"}) || !mon.Enabled {
		t.Fatalf("generated beacon check = %+v", mon)
	}
	tn := latencyNodeOf(t, plan, "node-t")
	if tn.BeaconTarget != enabled.Plan.Beacon.Endpoint || tn.BeaconMonitorID != mon.ID {
		t.Fatalf("plan node = %+v", tn)
	}
	checks := srv.generatedPathChecks("node-t")
	var methods []string
	for _, c := range checks {
		methods = append(methods, c.method)
	}
	if !slices.Contains(methods, model.MonitorTypeBeacon) || !slices.Contains(methods, model.MonitorTypeICMP) {
		t.Fatalf("the path series joins %v; want beacon beside icmp", methods)
	}
	// The icmp check those sources used keeps its history, paused.
	if icmp, ok := st.Monitor(latencyICMPMonitorID("node-t")); !ok || slices.Contains(icmp.NodeIDs, "node-a") && icmp.Enabled && len(icmp.NodeIDs) > 1 {
		t.Fatalf("icmp check after the switch = %+v", icmp)
	}
	// Each source is handed the beacon check only while it holds a key.
	list := agentMonitorList(t, srv, st, "node-a")
	if !slices.Contains(monitorIDs(list), mon.ID) {
		t.Fatalf("node-a was not handed the beacon check: %v", monitorIDs(list))
	}
	// A listening state that is not where the plan put it reads as not
	// listening; auto falls back.
	setBeaconFacts(t, srv, st, "node-t", model.BeaconFacts{Responder: true, State: model.BeaconAgentBindFailed, Error: "bind: address already in use"})
	srv.monitorPaths.notePlan(latencyPlan{}, time.Time{})
	if _, _, err := srv.syncLatencyProbes(srv.now()); err != nil {
		t.Fatal(err)
	}
	if got := pairOf(t, srv.pathPlan(srv.now()), "node-a", "node-t").Method; got != model.MonitorTypeICMP {
		t.Fatalf("with the target's bind failed auto took %s, want icmp", got)
	}
	view := srv.beaconView(beaconAdmin(), nodeOf(t, st, "node-t"), srv.now())
	if view.State != model.BeaconStateNotListening || view.Reason != model.PathReasonBeaconNotListening || view.Agent == nil || view.Agent.Error == "" {
		t.Fatalf("view of a failed bind = %+v", view)
	}
}

// The console design review decision of 2026-10-16: auto falls back to tcp
// for a pair whose icmp reads icmp_filtered, and stays there; a pair whose
// icmp has succeeded before keeps icmp, so a node that dies still reads down.
func TestAutoFallsBackToTCPWhenICMPReadsFiltered(t *testing.T) {
	srv, _, st := beaconFleet(t)
	plan := srv.pathPlan(srv.now())
	if pairOf(t, plan, "node-a", "node-t").Method != model.MonitorTypeICMP || pairOf(t, plan, "node-b", "node-t").Method != model.MonitorTypeICMP {
		t.Fatal("auto did not start on icmp")
	}
	icmpID := latencyICMPMonitorID("node-t")
	at := srv.now().Add(-time.Minute)
	ingest := func(source string, ok bool, when time.Time) {
		t.Helper()
		r := model.MonitorResult{MonitorID: icmpID, NodeID: source, At: when, Success: ok, Sent: 5}
		if ok {
			r.Lost, r.LatencyMs, r.RTTsMs = 0, 12, []float64{12, 12, 12, 12, 12}
		} else {
			r.Lost, r.Error = 5, "all echoes lost"
		}
		resp, err := srv.ingestAgentMonitorResults(source, []model.MonitorResult{r})
		if err != nil || resp.Accepted != 1 {
			t.Fatalf("ingest %s: %+v %v", source, resp, err)
		}
	}
	ingest("node-a", false, at)                  // never had an echo: icmp_filtered
	ingest("node-b", true, at)                   // had one ...
	ingest("node-b", false, at.Add(time.Second)) // ... so a loss is a failure
	srv.monitorPaths.notePlan(latencyPlan{}, time.Time{})
	if _, _, err := srv.syncLatencyProbes(srv.now()); err != nil {
		t.Fatal(err)
	}
	plan = srv.pathPlan(srv.now())
	if pair := pairOf(t, plan, "node-a", "node-t"); pair.Method != model.MonitorTypeTCP || !pair.Active {
		t.Fatalf("a filtered pair on auto = %+v, want tcp", pair)
	}
	if pair := pairOf(t, plan, "node-b", "node-t"); pair.Method != model.MonitorTypeICMP {
		t.Fatalf("a pair whose icmp succeeded before = %+v, want icmp", pair)
	}
	// Sticky: the next sweep keeps tcp while icmp's latest still reads
	// filtered.
	srv.monitorPaths.notePlan(latencyPlan{}, time.Time{})
	if _, _, err := srv.syncLatencyProbes(srv.now()); err != nil {
		t.Fatal(err)
	}
	if pair := pairOf(t, srv.pathPlan(srv.now()), "node-a", "node-t"); pair.Method != model.MonitorTypeTCP {
		t.Fatalf("the fallback flapped back: %+v", pair)
	}
	// A pin never falls back.
	saveBeaconPathSet(t, srv, st, model.LatencyProbeConfig{
		Enabled: true, Sources: []string{"node-a", "node-b", "node-c"}, IncludeTargets: []string{"node-t"}, Method: model.LatencyMethodAuto,
		SourceMethods: map[string]string{"node-a": model.LatencyMethodICMP},
	})
	if pair := pairOf(t, srv.pathPlan(srv.now()), "node-a", "node-t"); pair.Method != model.MonitorTypeICMP {
		t.Fatalf("a pinned icmp pair fell back: %+v", pair)
	}
}

// The plan's lint refuses a port another listener on the node holds, and a
// bind address inside WireGuard; it warns about a NAT mapping and a node
// NetGuard does not manage.
func TestBeaconPortLintAndAddresses(t *testing.T) {
	srv, handler, _ := beaconFleet(t)
	_ = srv
	for _, c := range []struct {
		name string
		req  model.BeaconPlanRequest
		code int
		want string
	}{
		{"a sing-box inbound's port", model.BeaconPlanRequest{Port: 1443}, http.StatusOK, ""},
		{"port 443 is the vless inbound", model.BeaconPlanRequest{Port: 443}, http.StatusBadRequest, "port must be 1024"},
		{"the WireGuard port", model.BeaconPlanRequest{Port: 51820}, http.StatusConflict, model.BeaconLintPortWireGuard},
		{"a bind inside WireGuard", model.BeaconPlanRequest{Bind: "10.66.0.30"}, http.StatusConflict, model.BeaconLintBindWireGuard},
		{"the wildcard bind", model.BeaconPlanRequest{Bind: "0.0.0.0"}, http.StatusBadRequest, "refused"},
		{"a loopback bind", model.BeaconPlanRequest{Bind: "127.0.0.1"}, http.StatusBadRequest, "refused"},
		{"a host name endpoint", model.BeaconPlanRequest{Endpoint: "beacon.example.com:45000"}, http.StatusBadRequest, "IPv4 literal"},
		{"a loopback endpoint", model.BeaconPlanRequest{Endpoint: "127.0.0.1:45000"}, http.StatusBadRequest, "refused"},
		{"a link-local endpoint", model.BeaconPlanRequest{Endpoint: "169.254.169.254:80"}, http.StatusBadRequest, "refused"},
		{"a multicast endpoint", model.BeaconPlanRequest{Endpoint: "239.1.1.1:45000"}, http.StatusBadRequest, "refused"},
		{"an IPv6 endpoint", model.BeaconPlanRequest{Endpoint: "[2001:db8::1]:45000"}, http.StatusBadRequest, "IPv4 literal"},
		{"a privileged port", model.BeaconPlanRequest{Port: 1000}, http.StatusBadRequest, "port must be 1024"},
	} {
		req := c.req
		req.NodeID, req.Action = "node-t", model.BeaconActionEnable
		code, _, raw := planBeacon(t, handler, req)
		if code != c.code || (c.want != "" && !strings.Contains(raw, c.want)) {
			t.Errorf("%s: %d %s; want %d with %q", c.name, code, raw, c.code, c.want)
		}
	}
	// A sing-box inbound on an allowed port blocks.
	srv.singboxInvMu.Lock()
	inv := srv.singboxInv["node-t"]
	inv.Nodes = append(inv.Nodes, model.SingBoxNode{Name: "hy2", Protocol: "hysteria2", Port: "45123", ListenHost: "::"})
	srv.singboxInv["node-t"] = inv
	srv.singboxInvMu.Unlock()
	if code, _, raw := planBeacon(t, handler, model.BeaconPlanRequest{NodeID: "node-t", Action: model.BeaconActionEnable, Port: 45123}); code != http.StatusConflict || !strings.Contains(raw, model.BeaconLintPortSingBox) {
		t.Fatalf("a sing-box port: %d %s", code, raw)
	}
	// A NAT mapping is allowed, with a warning, and so is a private bind.
	code, out, raw := planBeacon(t, handler, model.BeaconPlanRequest{NodeID: "node-t", Action: model.BeaconActionEnable, Port: 45000, Bind: "10.1.0.5", Endpoint: "203.0.113.200:52000"})
	if code != http.StatusOK {
		t.Fatalf("a NAT mapping: %d %s", code, raw)
	}
	codes := map[string]string{}
	for _, f := range out.Findings {
		codes[f.Code] = f.Severity
	}
	if codes[model.BeaconLintEndpointMapped] != model.BeaconFindingWarn || codes[model.BeaconLintOpenToInternet] != model.BeaconFindingWarn {
		t.Fatalf("findings = %+v", out.Findings)
	}
	if out.Plan.Beacon.Endpoint != "203.0.113.200:52000" || out.Plan.Beacon.Bind != "10.1.0.5" || out.Plan.Beacon.Port != 45000 {
		t.Fatalf("settings = %+v", out.Plan.Beacon)
	}
}

// The beacon check: node targets only, the interval floor, and the packet
// budget per (source, target) counting generated and operator checks.
func TestBeaconCheckBudgetAndTargets(t *testing.T) {
	srv, handler, st := beaconFleet(t)
	enableBeacon(t, srv, handler, model.BeaconPlanRequest{})
	listenAsPlanned(t, srv, st)
	cookies, csrf := beaconLogin(t, handler)
	post := func(body string) (int, string) {
		res := doJSON(t, handler, http.MethodPost, "/api/monitors", body, cookies, csrf)
		return res.StatusCode, readBody(t, res)
	}
	if code, raw := post(`{"name":"b","type":"beacon","target_node":"node-t","interval_sec":5,"timeout_sec":2,"node_ids":["node-a"]}`); code != http.StatusBadRequest || !strings.Contains(raw, "interval_sec must be 10") && !strings.Contains(raw, "at most every 10") {
		t.Fatalf("under the floor: %d %s", code, raw)
	}
	code, raw := post(`{"name":"b","type":"beacon","target_node":"node-t","packets":10,"interval_sec":10,"timeout_sec":2,"node_ids":["node-a"]}`)
	if code != http.StatusOK {
		t.Fatalf("one packet a second: %d %s", code, raw)
	}
	var created model.Monitor
	_ = json.Unmarshal([]byte(raw), &created)
	bt, _ := st.BeaconTarget("node-t")
	if created.Target != bt.Settings.Endpoint || created.TargetNode != "node-t" {
		t.Fatalf("created = %+v; want the advertised endpoint", created)
	}
	// One more packet a second on top of the generated check's 5/60 goes
	// over 2.
	if code, raw := post(`{"name":"b2","type":"beacon","target_node":"node-t","packets":10,"interval_sec":10,"timeout_sec":2,"node_ids":["node-a"]}`); code != http.StatusBadRequest || !strings.Contains(raw, "packets a second") {
		t.Fatalf("over the budget: %d %s", code, raw)
	}
	// A different source has its own budget.
	if code, raw := post(`{"name":"b3","type":"beacon","target_node":"node-t","packets":10,"interval_sec":10,"timeout_sec":2,"node_ids":["node-b"]}`); code != http.StatusOK {
		t.Fatalf("another source: %d %s", code, raw)
	}
	// An operator check from a source the plan did not approve is not
	// handed out, and its path reads beacon_source_pending.
	if code, raw := post(`{"name":"b4","type":"beacon","target_node":"node-t","node_ids":["node-c"],"interval_sec":60}`); code != http.StatusOK {
		t.Fatalf("an unapproved source: %d %s", code, raw)
	}
	for _, mon := range agentMonitorList(t, srv, st, "node-c") {
		if mon.Type == model.MonitorTypeBeacon {
			t.Fatalf("node-c, which runs no beacon client and was not approved, got %+v", mon)
		}
	}
}

// Scopes: planning needs monitor:admin and node:admin on the node (and
// network:plan); deciding needs them too; reading needs monitor:read.
func TestBeaconScopes(t *testing.T) {
	srv, handler, _ := beaconFleet(t)
	cookies, csrf := beaconLogin(t, handler)
	body := string(mustJSON(t, model.BeaconPlanRequest{NodeID: "node-t", Action: model.BeaconActionEnable}))
	for _, scopes := range [][]string{
		{"monitor:admin", "network:plan"},
		{"node:admin", "network:plan"},
		{"monitor:admin", "node:admin"},
	} {
		token := createPAT(t, handler, cookies, csrf, scopes, nil)
		res := doBearerJSON(t, handler, http.MethodPost, "/api/nodes/beacon/plan", body, token)
		if raw := readBody(t, res); res.StatusCode != http.StatusForbidden {
			t.Errorf("scopes %v planned a beacon: %d %s", scopes, res.StatusCode, raw)
		}
	}
	other := createPAT(t, handler, cookies, csrf, []string{"monitor:admin", "node:admin", "network:plan"}, []string{"node-a"})
	if res := doBearerJSON(t, handler, http.MethodPost, "/api/nodes/beacon/plan", body, other); res.StatusCode != http.StatusForbidden {
		t.Errorf("a token confined to another node planned node-t's beacon: %d", res.StatusCode)
	}
	// The plan names the sources and their addresses, so its author reads
	// them too.
	full := createPAT(t, handler, cookies, csrf, []string{"monitor:admin", "monitor:read", "node:admin", "network:plan"}, nil)
	res := doBearerJSON(t, handler, http.MethodPost, "/api/nodes/beacon/plan", body, full)
	raw := readBody(t, res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("a token with every scope: %d %s", res.StatusCode, raw)
	}
	var out model.BeaconPlanResponse
	_ = json.Unmarshal([]byte(raw), &out)
	decider := createPAT(t, handler, cookies, csrf, []string{"network:apply", "monitor:admin"}, nil)
	approve := doBearerJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": out.Approval.ID, "queue_apply": true, "plan_sha256": planSHA256(out.Approval.Plan)})), decider)
	if raw := readBody(t, approve); approve.StatusCode != http.StatusForbidden {
		t.Fatalf("a decider without node:admin: %d %s", approve.StatusCode, raw)
	}
	reader := createPAT(t, handler, cookies, csrf, []string{"node:read"}, nil)
	if res := doBearerJSON(t, handler, http.MethodGet, "/api/nodes/beacon?node_id=node-t", "", reader); res.StatusCode != http.StatusForbidden {
		t.Fatalf("a reader without monitor:read: %d", res.StatusCode)
	}
	monitorReader := createPAT(t, handler, cookies, csrf, []string{"monitor:read"}, nil)
	if res := doBearerJSON(t, handler, http.MethodGet, "/api/nodes/beacon?node_id=node-t", "", monitorReader); res.StatusCode != http.StatusOK {
		t.Fatalf("a monitor reader: %d", res.StatusCode)
	}
	_ = srv
}

// No key ever leaves the beacon code: not in the beacon view, the node
// list, the monitors, the approvals, the plan document or the audit log.
func TestBeaconSecretsNeverInReadsOrAudit(t *testing.T) {
	srv, handler, st := beaconFleet(t)
	enableBeacon(t, srv, handler, model.BeaconPlanRequest{})
	listenAsPlanned(t, srv, st)
	if _, err := srv.beaconRotate("node-t", srv.now()); err != nil {
		t.Fatal(err)
	}
	now := srv.now()
	key := targetKeyOf(t, st, "node-t")
	bt, _ := st.BeaconTarget("node-t")
	ids := st.BeaconSourceIDs()
	secrets := []string{base64.StdEncoding.EncodeToString(key[:])}
	for _, epoch := range []uint32{bt.Epoch, bt.PrevEpoch} {
		for _, id := range ids {
			k := beacon.DerivePathKey(&key, id, epoch)
			secrets = append(secrets, base64.StdEncoding.EncodeToString(k[:]))
		}
	}
	cookies, csrf := beaconLogin(t, handler)
	var reads []string
	for _, path := range []string{"/api/nodes/beacon?node_id=node-t", "/api/nodes", "/api/monitors", "/api/network/approvals", "/api/audit", "/api/monitors/latency", "/api/monitors/paths?window=1h"} {
		res := doJSON(t, handler, http.MethodGet, path, "", cookies, csrf)
		reads = append(reads, path+" "+readBody(t, res))
	}
	for _, e := range st.AuditEvents() {
		raw, _ := json.Marshal(e)
		reads = append(reads, "audit "+string(raw))
	}
	for _, a := range st.Approvals() {
		reads = append(reads, "approval "+a.Plan)
	}
	for _, read := range reads {
		for _, secret := range secrets {
			if strings.Contains(read, secret) {
				t.Fatalf("a key leaked into %s", read[:min(len(read), 80)])
			}
		}
	}
	// The agent config is the one place keys travel, to their owners.
	if cfg := srv.agentBeaconConfig(nodeOf(t, st, "node-a"), now); cfg == nil || len(cfg.Keys) != 1 {
		t.Fatalf("node-a config = %+v", cfg)
	}
}

// The agent's report: -no-beacon reads refused by node everywhere, and a
// node whose agent refuses gets no responder and no source a beacon check.
func TestBeaconRefusedByNode(t *testing.T) {
	srv, handler, st := beaconFleet(t)
	enableBeacon(t, srv, handler, model.BeaconPlanRequest{})
	setBeaconFacts(t, srv, st, "node-t", model.BeaconFacts{Responder: true, Refusal: model.PathReasonRefusedByNode, State: "whatever"})
	if facts := nodeOf(t, st, "node-t").Beacon; facts == nil || facts.State != model.BeaconAgentRefused {
		t.Fatalf("stored facts = %+v", facts)
	}
	view := srv.beaconView(beaconAdmin(), nodeOf(t, st, "node-t"), srv.now())
	if view.State != model.BeaconStateRefusedByNode || view.Reason != model.PathReasonRefusedByNode {
		t.Fatalf("view = %+v", view)
	}
	if cfg := srv.agentBeaconConfig(nodeOf(t, st, "node-t"), srv.now()); cfg != nil && cfg.Responder != nil {
		t.Fatalf("a refusing node got a responder: %+v", cfg.Responder)
	}
	saveBeaconPathSet(t, srv, st, model.LatencyProbeConfig{
		Enabled: true, Sources: []string{"node-a", "node-b", "node-c"}, IncludeTargets: []string{"node-t"}, Method: model.LatencyMethodAuto,
		SourceMethods: map[string]string{"node-a": model.LatencyMethodBeacon},
	})
	if pair := pairOf(t, srv.pathPlan(srv.now()), "node-a", "node-t"); pair.Active || pair.Reason != model.PathReasonRefusedByNode {
		t.Fatalf("a pinned beacon pair to a refusing node = %+v", pair)
	}
	if got := normalizeBeaconFacts(&model.BeaconFacts{Responder: true, Bind: "0.0.0.0", Port: 70000, Error: strings.Repeat("x", 500), State: "listening"}, srv.now()); got.Bind != "" || got.Port != 0 || len(got.Error) != beaconErrorMax {
		t.Fatalf("an out-of-bounds report was kept: %+v", got)
	}
}

// After a plan applies and the target listens, one approved source runs the
// reachability check; its first telling result is the verdict, and the
// check goes away.
func TestBeaconReachability(t *testing.T) {
	for _, c := range []struct {
		name   string
		result model.MonitorResult
		want   string
	}{
		{"a reply", model.MonitorResult{Success: true, Sent: 3, Lost: 0, LatencyMs: 20, RTTsMs: []float64{20, 20, 20}}, model.BeaconReachReachable},
		{"refused", model.MonitorResult{Reason: model.PathReasonBeaconNotListening}, model.BeaconReachNotListening},
		{"all lost", model.MonitorResult{Sent: 3, Lost: 3, Error: "no reply"}, model.BeaconReachFiltered},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv, handler, st := beaconFleet(t)
			enableBeacon(t, srv, handler, model.BeaconPlanRequest{})
			if bt, _ := st.BeaconTarget("node-t"); !bt.ReachArmed || bt.Reach.State != model.BeaconReachPending {
				t.Fatalf("after the apply reach = %+v armed=%v", bt.Reach, bt.ReachArmed)
			}
			if _, ok := st.Monitor(model.BeaconReachMonitorPrefix + "node-t"); ok {
				t.Fatal("the reachability check started before the target listened")
			}
			listenAsPlanned(t, srv, st)
			srv.syncBeaconReach(srv.now())
			mon, ok := st.Monitor(model.BeaconReachMonitorPrefix + "node-t")
			if !ok || mon.ManagedBy != model.MonitorManagedBeacon || len(mon.NodeIDs) != 1 || mon.Packets != beaconReachPackets || mon.Type != model.MonitorTypeBeacon {
				t.Fatalf("reachability check = %+v %v", mon, ok)
			}
			source := mon.NodeIDs[0]
			if source != "node-a" && source != "node-b" {
				t.Fatalf("the check runs from %s, not an approved source", source)
			}
			r := c.result
			r.MonitorID, r.NodeID, r.At = mon.ID, source, srv.now().Add(-time.Second)
			if resp, err := srv.ingestAgentMonitorResults(source, []model.MonitorResult{r}); err != nil || resp.Accepted != 1 {
				t.Fatalf("ingest: %+v %v", resp, err)
			}
			bt, _ := st.BeaconTarget("node-t")
			if bt.ReachArmed || bt.Reach.State != c.want || bt.Reach.Source != source {
				t.Fatalf("reach = %+v armed=%v; want %s", bt.Reach, bt.ReachArmed, c.want)
			}
			if _, ok := st.Monitor(mon.ID); ok {
				t.Fatal("the reachability check outlived its verdict")
			}
			view := srv.beaconView(beaconAdmin(), nodeOf(t, st, "node-t"), srv.now())
			if view.Reachability.State != c.want {
				t.Fatalf("view reachability = %+v", view.Reachability)
			}
			// It is not a path.
			for _, e := range srv.pathEntries(srv.now(), map[string]model.Node{}) {
				if e.cell.MonitorID == mon.ID {
					t.Fatal("the reachability check shows as a path")
				}
			}
		})
	}
}

// Disabling drops the key and the responder; the epoch never goes back, so
// a later enable signs with keys no earlier holder had.
func TestBeaconDisableDropsTheKey(t *testing.T) {
	srv, handler, st := beaconFleet(t)
	enableBeacon(t, srv, handler, model.BeaconPlanRequest{})
	first, _ := st.BeaconTarget("node-t")
	cookies, csrf := beaconLogin(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/monitors", `{"name":"op","type":"beacon","target_node":"node-t","node_ids":["node-a"],"interval_sec":60}`, cookies, csrf)
	var opCheck model.Monitor
	if raw := readBody(t, res); res.StatusCode != http.StatusOK || json.Unmarshal([]byte(raw), &opCheck) != nil {
		t.Fatalf("operator beacon check: %d %s", res.StatusCode, raw)
	}
	code, out, raw := planBeacon(t, handler, model.BeaconPlanRequest{NodeID: "node-t", Action: model.BeaconActionDisable})
	if code != http.StatusOK {
		t.Fatalf("disable plan: %d %s", code, raw)
	}
	if _, err := decideBeacon(srv, out.Approval, beaconAdmin()); err != nil {
		t.Fatal(err)
	}
	off, _ := st.BeaconTarget("node-t")
	if off.Settings.Enabled || off.Key != "" || off.Epoch != first.Epoch {
		t.Fatalf("after disable = %+v", off)
	}
	if cfg := srv.agentBeaconConfig(nodeOf(t, st, "node-t"), srv.now()); cfg != nil && cfg.Responder != nil {
		t.Fatal("a disabled beacon still gets a responder")
	}
	nodes := map[string]model.Node{}
	for _, n := range st.Nodes() {
		nodes[n.ID] = n
	}
	read := false
	for _, e := range srv.pathEntries(srv.now(), nodes) {
		if e.cell.MonitorID == opCheck.ID {
			read = true
			if state, reason := pathStateOf(e, nil, nodes, srv.now()); state != model.PathStateUnknown || reason != model.PathReasonBeaconNotEnabled {
				t.Fatalf("an operator check to a disabled beacon reads %s %s", state, reason)
			}
		}
	}
	if !read {
		t.Fatal("the operator check has no path")
	}
	for _, mon := range agentMonitorList(t, srv, st, "node-a") {
		if mon.ID == opCheck.ID {
			t.Fatal("a check to a disabled beacon is still handed out")
		}
	}
	enableBeacon(t, srv, handler, model.BeaconPlanRequest{})
	again, _ := st.BeaconTarget("node-t")
	if again.Epoch <= first.Epoch || again.Key == first.Key {
		t.Fatalf("re-enable reused epoch %d or the old key", again.Epoch)
	}
	if again.Settings.Port != first.Settings.Port {
		t.Fatalf("re-enable moved the port %d -> %d; the assigned random port is kept", first.Settings.Port, again.Settings.Port)
	}
}

// The store side: the target key is encrypted at rest, survives a reload,
// and a deleted node's source id is never given to another node.
func TestBeaconStateAtRest(t *testing.T) {
	dir := t.TempDir()
	cipher := testCipher(t)
	st, err := store.OpenWithCipher(dir+"/state.json", cipher)
	if err != nil {
		t.Fatal(err)
	}
	upsertNodes(t, st, model.Node{ID: "n1", Name: "one"}, model.Node{ID: "n2", Name: "two"})
	ids, err := st.EnsureBeaconSourceIDs([]string{"n1", "n2"})
	if err != nil || ids["n1"] != 1 || ids["n2"] != 2 {
		t.Fatalf("ids = %v %v", ids, err)
	}
	key, _ := newBeaconTargetKey()
	if _, err := st.UpdateBeaconTarget("n1", func(next *store.BeaconTarget, _ bool) (bool, error) {
		next.Key, next.Epoch, next.Settings.Enabled = key, 1, true
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := readFileString(dir + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, key) {
		t.Fatal("the target key is stored in plaintext")
	}
	if _, _, err := st.DeleteNode("n2"); err != nil {
		t.Fatal(err)
	}
	upsertNodes(t, st, model.Node{ID: "n3", Name: "three"})
	ids, _ = st.EnsureBeaconSourceIDs([]string{"n3"})
	if ids["n3"] != 3 {
		t.Fatalf("a new node got source id %d; ids are never reused", ids["n3"])
	}
	st.Close()
	reopened, err := store.OpenWithCipher(dir+"/state.json", cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	bt, ok := reopened.BeaconTarget("n1")
	if !ok || bt.Key != key {
		t.Fatal("the key did not survive a reload")
	}
}

func testCipher(t *testing.T) secret.Cipher {
	t.Helper()
	cipher, err := secret.NewAESGCM(bytes.Repeat([]byte{0x7b}, secret.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func readFileString(path string) (string, error) {
	raw, err := os.ReadFile(path)
	return string(raw), err
}
