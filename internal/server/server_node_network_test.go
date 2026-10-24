package server

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Design 32 S3b: the node's effective network (D4). The endpoint lists every
// owner of every table, every outbound policy that reaches the node in
// priority order and the orphans, writes nothing, and refuses a node outside
// the caller's scope.

type nodeNetworkOut struct {
	NodeID  string `json:"node_id"`
	Inbound struct {
		State                 string                     `json:"state"`
		Scope                 string                     `json:"scope"`
		Firewall              string                     `json:"firewall"`
		Binding               string                     `json:"binding"`
		SecurityGroups        []nodeNetworkSecurityGroup `json:"security_groups"`
		DerivedSecurityGroups []nodeNetworkSecurityGroup `json:"derived_security_groups"`
		ExtraPorts            []nodeNetworkPort          `json:"extra_ports"`
		LegacyIngress         *nodeNetworkLegacyIngress  `json:"legacy_ingress"`
	} `json:"inbound"`
	Outbound struct {
		State    string                 `json:"state"`
		Scope    string                 `json:"scope"`
		Source   string                 `json:"source"`
		Policies []nodeNetworkPolicy    `json:"policies"`
		Manual   *nodeNetworkNodePolicy `json:"manual"`
		Orphan   *nodeNetworkNodePolicy `json:"orphan"`
	} `json:"outbound"`
	Access struct {
		State         string `json:"state"`
		Scope         string `json:"scope"`
		KnockRequired bool   `json:"knock_required"`
		Stage         string `json:"stage"`
	} `json:"access"`
	Mesh struct {
		State        string   `json:"state"`
		Scope        string   `json:"scope"`
		Ready        bool     `json:"ready"`
		Missing      []string `json:"missing"`
		Peers        int      `json:"peers"`
		PeersRefused string   `json:"peers_refused"`
		NotReported  []string `json:"not_reported"`
	} `json:"mesh"`
	Groups struct {
		State string             `json:"state"`
		Scope string             `json:"scope"`
		Items []nodeNetworkGroup `json:"items"`
	} `json:"groups"`
	Tables []struct {
		State      string             `json:"state"`
		Scope      string             `json:"scope"`
		Table      string             `json:"table"`
		Owners     []nodeNetworkOwner `json:"owners"`
		LastWriter *struct {
			Kind       string `json:"kind"`
			ApprovalID string `json:"approval_id"`
		} `json:"last_writer"`
		CompileNow    nodeNetworkRuleset `json:"compile_now"`
		LastApplied   nodeNetworkRuleset `json:"last_applied"`
		ReplanPending bool               `json:"replan_pending"`
		RulesWithheld string             `json:"rules_withheld"`
	} `json:"tables"`
}

func (v nodeNetworkOut) table(t *testing.T, name string) int {
	t.Helper()
	for i, table := range v.Tables {
		if table.Table == name {
			return i
		}
	}
	t.Fatalf("no table %s in %+v", name, v.Tables)
	return -1
}

// nodeNetworkFleet is n1 (tokyo-1, adopted by NetGuard with the web security
// group), n2 (la-1, on the legacy route) and n3 (sg-1), with node group web
// holding n1 and n2 and five outbound policies:
//
//	gnp_d  priority 1, disabled, names n1
//	gnp_b  priority 5, names n1, allows ssh to n2
//	gnp_a  priority 10, group web, allows https anywhere
//	gnp_c  priority 20, whole fleet, excludes n1 and n3
//	gnp_e  priority 30, names n2
func nodeNetworkFleet(t *testing.T) (*Server, http.Handler, *store.Store, []*http.Cookie, string) {
	t.Helper()
	srv, handler, st := newDNSServerWithOptions(t, Options{PublicURL: "https://203.0.113.99"})
	cookies, csrf := loginSession(t, handler)
	if err := st.UpsertNode(model.Node{ID: "n3", Name: "sg-1", WireGuardIP: "10.66.0.3/32", PublicIP: "192.0.2.33"}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"n1", "n2"} {
		node, _ := st.Node(id)
		node.WireGuardPublicKey = strings.Repeat(id[1:], 43) + "="
		if err := st.UpsertNode(node); err != nil {
			t.Fatal(err)
		}
	}
	adoptNodeWithWebGroup(t, handler, st, cookies, csrf)
	if err := st.UpsertGroup(model.Group{ID: "grp_web", Name: "web", Slug: "web", Color: "blue", Members: []string{"n1", "n2"}}); err != nil {
		t.Fatal(err)
	}
	https := []model.GroupNetRule{{ID: "https", Action: model.NetRuleAllow, Direction: model.NetDirEgress, Protocol: "tcp", Ports: []int{443}, Remote: model.NetEndpoint{Kind: model.NetRefAny}}}
	ssh := []model.GroupNetRule{{ID: "ssh", Action: model.NetRuleAllow, Direction: model.NetDirEgress, Protocol: "tcp", Ports: []int{22}, Remote: model.NetEndpoint{Kind: model.NetRefNode, NodeID: "n2"}}}
	for _, gp := range []model.GroupNetPolicy{
		{ID: "gnp_d", Priority: 1, Enabled: false, Scope: &model.TargetSelector{Nodes: []string{"n1"}}, Rules: https},
		{ID: "gnp_b", Priority: 5, Enabled: true, Scope: &model.TargetSelector{Nodes: []string{"n1"}}, Rules: ssh},
		{ID: "gnp_a", Name: "egress-web", Priority: 10, Enabled: true, Scope: &model.TargetSelector{Groups: []string{"grp_web"}}, Rules: https},
		{ID: "gnp_c", Priority: 20, Enabled: true, Scope: &model.TargetSelector{All: true, Exclude: []string{"n1", "n3"}}, Rules: https},
		{ID: "gnp_e", Priority: 30, Enabled: true, Scope: &model.TargetSelector{Nodes: []string{"n2"}}, Rules: https},
	} {
		if err := st.UpsertGroupPolicy(gp); err != nil {
			t.Fatal(err)
		}
	}
	return srv, handler, st, cookies, csrf
}

func getNodeNetwork(t *testing.T, handler http.Handler, cookies []*http.Cookie, query string) (int, nodeNetworkOut, string) {
	t.Helper()
	res := doJSON(t, handler, http.MethodGet, "/api/nodes/network?"+query, "", cookies, "")
	raw := readBody(t, res)
	var out nodeNetworkOut
	if res.StatusCode == http.StatusOK {
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			t.Fatal(err)
		}
	}
	return res.StatusCode, out, raw
}

func bearerNodeNetwork(t *testing.T, handler http.Handler, token, query string) (int, nodeNetworkOut, string) {
	t.Helper()
	res := doBearerJSON(t, handler, http.MethodGet, "/api/nodes/network?"+query, "", token)
	raw := readBody(t, res)
	var out nodeNetworkOut
	if res.StatusCode == http.StatusOK {
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			t.Fatal(err)
		}
	}
	return res.StatusCode, out, raw
}

func ownerStates(owners []nodeNetworkOwner) map[string]string {
	out := map[string]string{}
	for _, o := range owners {
		out[o.Kind] = o.State
	}
	return out
}

// Every outbound policy whose target names the node is listed in the order
// expansion merges them, each with how it reaches the node and what it does
// there; the tables name every owner.
func TestNodeNetworkListsEveryOwnerAndPolicyInPriorityOrder(t *testing.T) {
	_, handler, _, cookies, csrf := nodeNetworkFleet(t)
	code, view, raw := getNodeNetwork(t, handler, cookies, "node_id=n1")
	if code != http.StatusOK {
		t.Fatalf("GET = %d %s", code, raw)
	}

	type row struct{ id, reach, state string }
	got := make([]row, 0, len(view.Outbound.Policies))
	for _, p := range view.Outbound.Policies {
		got = append(got, row{p.ID, p.Reach, p.State})
	}
	want := []row{
		{"gnp_d", "named", "disabled"},
		{"gnp_b", "named", "applies"},
		{"gnp_a", "group", "applies"},
		{"gnp_c", "excluded", "excluded"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("policies = %+v, want %+v", got, want)
	}
	if via := view.Outbound.Policies[2].ViaGroups; len(via) != 1 || via[0].ID != "grp_web" || via[0].Name != "web" {
		t.Fatalf("gnp_a must reach n1 through group web: %+v", via)
	}
	if p := view.Outbound.Policies[0]; p.Rules != 1 || p.Allow != 1 {
		t.Fatalf("a disabled policy still says what it would add: %+v", p)
	}
	if view.Outbound.Source != "policies" || view.Outbound.Manual != nil || view.Outbound.Orphan != nil {
		t.Fatalf("outbound source = %q manual=%v orphan=%v", view.Outbound.Source, view.Outbound.Manual, view.Outbound.Orphan)
	}

	if view.Inbound.Firewall != "netguard" || view.Inbound.Binding != "managed" ||
		len(view.Inbound.SecurityGroups) != 1 || view.Inbound.SecurityGroups[0].ID != "sg-web" || view.Inbound.SecurityGroups[0].Rules != 3 {
		t.Fatalf("inbound = %+v", view.Inbound)
	}
	if view.Inbound.DerivedSecurityGroups == nil || len(view.Inbound.DerivedSecurityGroups) != 0 {
		t.Fatalf("derived security groups are an empty list until S4: %v", view.Inbound.DerivedSecurityGroups)
	}
	if len(view.Groups.Items) != 1 || view.Groups.Items[0].ID != "grp_web" {
		t.Fatalf("groups = %+v", view.Groups)
	}

	order := make([]string, 0, len(view.Tables))
	for _, table := range view.Tables {
		order = append(order, table.Table)
	}
	if !reflect.DeepEqual(order, []string{"inet lattice_guard", "inet lattice_policy", "inet lattice_knock"}) {
		t.Fatalf("tables = %v", order)
	}
	guard := view.Tables[view.table(t, "inet lattice_guard")]
	if !reflect.DeepEqual(ownerStates(guard.Owners), map[string]string{
		"netguard": "writes", "beacon": "idle", "selfdns": "refused", "legacy_firewall": "refused",
	}) {
		t.Fatalf("guard owners on a managed node = %+v", guard.Owners)
	}
	if guard.CompileNow.State != "ok" || guard.CompileNow.Composer != "netguard" || guard.CompileNow.SHA256 == "" || guard.CompileNow.Ruleset != "" {
		t.Fatalf("guard compile now without rules=1 is a digest: %+v", guard.CompileNow)
	}
	if guard.LastApplied.State != "none" || guard.LastWriter != nil || guard.ReplanPending {
		t.Fatalf("nothing applied yet: %+v %+v", guard.LastApplied, guard.LastWriter)
	}
	policy := view.Tables[view.table(t, "inet lattice_policy")]
	if !reflect.DeepEqual(ownerStates(policy.Owners), map[string]string{"outbound_policy": "writes"}) || policy.CompileNow.State != "ok" {
		t.Fatalf("policy table = %+v", policy)
	}
	knock := view.Tables[view.table(t, "inet lattice_knock")]
	if !reflect.DeepEqual(ownerStates(knock.Owners), map[string]string{"sshguard": "idle"}) || knock.RulesWithheld != "knock" {
		t.Fatalf("knock table = %+v", knock)
	}

	// n2 has a manual document: it blocks every policy, which the clobber
	// guard of the group plan would skip.
	doNetPolicyUpsert(t, handler, cookies, csrf, "n2")
	_, view2, raw2 := getNodeNetwork(t, handler, cookies, "node_id=n2")
	if view2.Outbound.Source != "manual" || view2.Outbound.Manual == nil {
		t.Fatalf("n2 outbound = %s", raw2)
	}
	for _, p := range view2.Outbound.Policies {
		if p.ID == "gnp_c" || p.ID == "gnp_a" || p.ID == "gnp_e" {
			if p.State != "blocked" {
				t.Fatalf("%s on a node with a manual policy = %q, want blocked", p.ID, p.State)
			}
		}
	}
	if owners := ownerStates(view2.Tables[view2.table(t, "inet lattice_policy")].Owners); !reflect.DeepEqual(owners, map[string]string{"manual_policy": "writes", "outbound_policy": "refused"}) {
		t.Fatalf("n2 policy owners = %+v", owners)
	}
	if owners := ownerStates(view2.Tables[view2.table(t, "inet lattice_guard")].Owners); owners["legacy_firewall"] != "idle" || owners["netguard"] != "idle" {
		t.Fatalf("n2 guard owners = %+v", owners)
	}
}

func doNetPolicyUpsert(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, nodeID string) {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/netpolicy", `{"target_node_id":"`+nodeID+`","enabled":true,"rules":[{"id":"dns","action":"allow","direction":"egress","protocol":"udp","ports":[53],"remote":{"kind":"any"}}]}`, cookies, csrf)
	raw := readBody(t, res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("manual policy = %d %s", res.StatusCode, raw)
	}
}

// A group-derived document still on a node that every policy has left is an
// orphan: listed, with the policy that excludes the node.
func TestNodeNetworkListsOrphans(t *testing.T) {
	_, handler, st, cookies, _ := nodeNetworkFleet(t)
	applied := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	if err := st.UpsertNetPolicy(model.NetPolicy{
		ID: "n3", TargetNodeID: "n3", Enabled: true, GroupDerived: true, LastAppliedAt: applied,
		Rules: []model.NetRule{{ID: "https", Action: model.NetRuleAllow, Direction: model.NetDirEgress, Protocol: "tcp", Ports: []int{443}, Remote: model.NetEndpoint{Kind: model.NetRefAny}}},
	}); err != nil {
		t.Fatal(err)
	}
	_, view, raw := getNodeNetwork(t, handler, cookies, "node_id=n3")
	if view.Outbound.Source != "orphan" || view.Outbound.Orphan == nil || view.Outbound.Orphan.Rules != 1 || !view.Outbound.Orphan.LastAppliedAt.Equal(applied) {
		t.Fatalf("n3 outbound = %s", raw)
	}
	if len(view.Outbound.Policies) != 1 || view.Outbound.Policies[0].ID != "gnp_c" || view.Outbound.Policies[0].State != "excluded" {
		t.Fatalf("the fleet policy that excludes n3 is listed: %+v", view.Outbound.Policies)
	}
	policy := view.Tables[view.table(t, "inet lattice_policy")]
	if !reflect.DeepEqual(ownerStates(policy.Owners), map[string]string{"outbound_policy": "orphan"}) || policy.CompileNow.State != "none" {
		t.Fatalf("orphan policy table = %+v", policy)
	}
}

// Show rules: what would compile now beside what was last applied, the last
// writer of lattice_guard named from the newest applied approval, and
// re-plan pending when another composer rebuilt the table.
func TestNodeNetworkShowRulesNamesTheLastWriterAndDrift(t *testing.T) {
	_, handler, st, cookies, _ := nodeNetworkFleet(t)
	_, view, _ := getNodeNetwork(t, handler, cookies, "node_id=n1&rules=1")
	guard := view.Tables[view.table(t, "inet lattice_guard")]
	preview := guard.CompileNow.Ruleset
	if guard.CompileNow.State != "ok" || !strings.Contains(preview, "table inet lattice_guard") {
		t.Fatalf("compile now with rules=1 = %+v", guard.CompileNow)
	}

	// UpsertApproval stamps UpdatedAt with the wall clock, so the times here
	// are relative to it.
	t0 := time.Now().UTC().Add(-time.Hour)
	// The legacy route never marks its approval applied; the finished apply
	// task is the record.
	legacy := model.Approval{ID: "approval_legacy", NodeID: "n1", Plugin: "nft", Action: "apply-ruleset", Plan: "table inet lattice_guard {\n\tchain input { type filter hook input priority 0; policy drop; }\n}\n", Status: model.ApprovalApproved, CreatedAt: t0}
	if err := st.UpsertApproval(legacy); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTask(model.Task{ID: "task_legacy", ApprovalID: legacy.ID, Targets: []string{"n1"}, Status: model.TaskFinished, CreatedAt: t0, FinishedAt: t0.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	netguardApplied := model.Approval{ID: "approval_ng", NodeID: "n1", Plugin: "nft", Action: netGuardApprovalAction, Plan: preview, Status: model.ApprovalApplied, CreatedAt: t0.Add(2 * time.Minute), UpdatedAt: t0.Add(3 * time.Minute)}
	if err := st.UpsertApproval(netguardApplied); err != nil {
		t.Fatal(err)
	}
	_, view, raw := getNodeNetwork(t, handler, cookies, "node_id=n1&rules=1")
	guard = view.Tables[view.table(t, "inet lattice_guard")]
	if guard.LastWriter == nil || guard.LastWriter.Kind != "netguard" || guard.LastWriter.ApprovalID != "approval_ng" {
		t.Fatalf("last writer = %s", raw)
	}
	if guard.ReplanPending || guard.LastApplied.Ruleset != preview || guard.LastApplied.SHA256 != guard.CompileNow.SHA256 {
		t.Fatalf("NetGuard applied what it compiles now; nothing is pending: %+v", guard)
	}

	// A legacy plan applied after NetGuard rebuilt the table without the
	// security groups: the view names it and says a re-plan is pending.
	late := legacy
	late.ID, late.CreatedAt = "approval_legacy_late", t0.Add(4*time.Minute)
	if err := st.UpsertApproval(late); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTask(model.Task{ID: "task_legacy_late", ApprovalID: late.ID, Targets: []string{"n1"}, Status: model.TaskFinished, CreatedAt: late.CreatedAt, FinishedAt: time.Now().UTC().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	// A rejected approval never counts, even with a finished task.
	rejected := legacy
	rejected.ID, rejected.Status, rejected.CreatedAt = "approval_rejected", model.ApprovalRejected, t0.Add(6*time.Minute)
	if err := st.UpsertApproval(rejected); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTask(model.Task{ID: "task_rejected", ApprovalID: rejected.ID, Targets: []string{"n1"}, Status: model.TaskFinished, CreatedAt: rejected.CreatedAt, FinishedAt: time.Now().UTC().Add(2 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	_, view, raw = getNodeNetwork(t, handler, cookies, "node_id=n1&rules=1")
	guard = view.Tables[view.table(t, "inet lattice_guard")]
	if guard.LastWriter == nil || guard.LastWriter.Kind != "legacy_firewall" || guard.LastWriter.ApprovalID != "approval_legacy_late" {
		t.Fatalf("last writer after the late legacy apply = %s", raw)
	}
	if !guard.ReplanPending || guard.LastApplied.Ruleset != legacy.Plan || guard.CompileNow.Composer != "netguard" {
		t.Fatalf("drift must read re-plan pending: %+v", guard)
	}

	// The outbound table compares the same way: an applied plan that is not
	// what the policies compile to now is pending.
	policy := view.Tables[view.table(t, "inet lattice_policy")]
	if policy.LastApplied.State != "none" || policy.ReplanPending {
		t.Fatalf("no outbound plan applied yet: %+v", policy)
	}
	stale := model.Approval{ID: "approval_pol", NodeID: "n1", Plugin: "nftpolicy", Action: "apply-ruleset", Plan: "add table inet lattice_policy\n", Status: model.ApprovalApplied, CreatedAt: t0, UpdatedAt: t0}
	if err := st.UpsertApproval(stale); err != nil {
		t.Fatal(err)
	}
	_, view, _ = getNodeNetwork(t, handler, cookies, "node_id=n1&rules=1")
	policy = view.Tables[view.table(t, "inet lattice_policy")]
	if !policy.ReplanPending || policy.LastWriter == nil || policy.LastWriter.Kind != "outbound_policy" || !strings.Contains(policy.CompileNow.Ruleset, "table inet lattice_policy") {
		t.Fatalf("policy drift = %+v", policy)
	}
	current := stale
	current.ID, current.Plan, current.UpdatedAt = "approval_pol_now", policy.CompileNow.Ruleset, t0.Add(time.Hour)
	if err := st.UpsertApproval(current); err != nil {
		t.Fatal(err)
	}
	_, view, _ = getNodeNetwork(t, handler, cookies, "node_id=n1")
	if policy = view.Tables[view.table(t, "inet lattice_policy")]; policy.ReplanPending || policy.LastApplied.Ruleset != "" {
		t.Fatalf("applied what compiles now, and no text without rules=1: %+v", policy)
	}
}

// On a node NetGuard does not manage, the self-host DNS composer is the last
// writer once its plan applied, and what would compile now is that composer's
// output, so an unchanged deployment reads in sync.
func TestNodeNetworkSelfDNSLastWriterOnTheLegacyRoute(t *testing.T) {
	_, handler, st, cookies, csrf := nodeNetworkFleet(t)
	inputs := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs", `{"node_id":"n2","interface_name":"eth0","wireguard_cidr":"10.66.0.0/24","public_tcp":[22]}`, cookies, csrf)
	inputs.Body.Close()
	create := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{"name":"mesh dns","node_id":"n2","zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]}`, cookies, csrf)
	var dep struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(readBody(t, create)), &dep); err != nil || dep.ID == "" {
		t.Fatalf("create deployment: %v", err)
	}
	plan := doJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+dep.ID+`","accept_lockout_risk":true}`, cookies, csrf)
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("dns plan = %d %s", plan.StatusCode, readBody(t, plan))
	}
	approval := decodeDNSPlan(t, plan)
	if _, _, err := st.MutateApproval(approval.ID, func(a *model.Approval) bool {
		a.Status, a.UpdatedAt = model.ApprovalApplied, time.Now().UTC()
		return true
	}); err != nil {
		t.Fatal(err)
	}
	_, view, raw := getNodeNetwork(t, handler, cookies, "node_id=n2&rules=1")
	guard := view.Tables[view.table(t, "inet lattice_guard")]
	if guard.LastWriter == nil || guard.LastWriter.Kind != "selfdns" {
		t.Fatalf("last writer = %s", raw)
	}
	if guard.CompileNow.Composer != "selfdns" || guard.ReplanPending || !strings.Contains(guard.CompileNow.Ruleset, "53") {
		t.Fatalf("selfdns compiles what it applied: compile=%+v applied=%+v", guard.CompileNow, guard.LastApplied)
	}
	if owners := ownerStates(guard.Owners); owners["selfdns"] != "writes" || owners["legacy_firewall"] != "writes" {
		t.Fatalf("legacy-route owners = %+v", owners)
	}
	found := false
	for _, port := range view.Inbound.ExtraPorts {
		if port.Source == "selfdns" && port.Port == 53 && port.Label == "mesh dns" {
			found = true
		}
	}
	if !found {
		t.Fatalf("extra ports = %+v", view.Inbound.ExtraPorts)
	}
}

// The read writes nothing: no state write, no approval, no change to any
// policy document, whatever the node and with the rules requested.
func TestNodeNetworkWritesNothing(t *testing.T) {
	_, handler, st, cookies, _ := nodeNetworkFleet(t)
	if err := st.UpsertNetPolicy(model.NetPolicy{ID: "n3", TargetNodeID: "n3", Enabled: true, GroupDerived: true}); err != nil {
		t.Fatal(err)
	}
	before := st.PersistCallsForTest()
	approvals, netPolicies, groupPolicies, bindings := len(st.Approvals()), st.NetPolicies(), st.GroupPolicies(), st.NodeGuardBindings()
	for _, q := range []string{"node_id=n1", "node_id=n1&rules=1", "node_id=n2&rules=1", "node_id=n3&rules=1"} {
		if code, _, raw := getNodeNetwork(t, handler, cookies, q); code != http.StatusOK {
			t.Fatalf("%s = %d %s", q, code, raw)
		}
	}
	if after := st.PersistCallsForTest(); after != before {
		t.Fatalf("the read wrote the state %d times", after-before)
	}
	if len(st.Approvals()) != approvals {
		t.Fatal("the read created an approval")
	}
	if !reflect.DeepEqual(st.NetPolicies(), netPolicies) || !reflect.DeepEqual(st.GroupPolicies(), groupPolicies) || !reflect.DeepEqual(st.NodeGuardBindings(), bindings) {
		t.Fatal("the read changed a policy document or a binding")
	}
}

// A node outside the caller's scope is refused; a section the caller has no
// scope for is refused whole and names the scope; a ruleset that needs a
// remote the caller cannot read is refused, never shown without its rules.
func TestNodeNetworkRefusesOutsideTheCallersScope(t *testing.T) {
	_, handler, st, cookies, csrf := nodeNetworkFleet(t)

	other := createPAT(t, handler, cookies, csrf, []string{"node:read", "netguard:read", "netpolicy:read"}, []string{"n2"})
	for _, q := range []string{"node_id=n1", "node_id=ghost"} {
		if code, _, raw := bearerNodeNetwork(t, handler, other, q); code != http.StatusForbidden {
			t.Fatalf("%s outside the allowlist = %d %s, want 403", q, code, raw)
		}
	}
	if code, _, _ := getNodeNetwork(t, handler, cookies, "node_id=ghost"); code != http.StatusNotFound {
		t.Fatalf("an unknown node for an unrestricted session = %d, want 404", code)
	}

	bare := createPAT(t, handler, cookies, csrf, []string{"node:read"}, []string{"n1"})
	code, view, raw := bearerNodeNetwork(t, handler, bare, "node_id=n1&rules=1")
	if code != http.StatusOK {
		t.Fatalf("node:read alone = %d %s", code, raw)
	}
	sections := map[string][2]string{
		"inbound":  {view.Inbound.State, view.Inbound.Scope},
		"outbound": {view.Outbound.State, view.Outbound.Scope},
		"access":   {view.Access.State, view.Access.Scope},
		"mesh":     {view.Mesh.State, view.Mesh.Scope},
		"groups":   {view.Groups.State, view.Groups.Scope},
	}
	wantScope := map[string]string{"inbound": "netguard:read", "outbound": "netpolicy:read", "access": "sshguard:read", "mesh": "wireguard:read", "groups": "group:read"}
	for name, got := range sections {
		if got[0] != "refused" || got[1] != wantScope[name] {
			t.Errorf("%s = %v, want refused naming %s", name, got, wantScope[name])
		}
	}
	if view.Outbound.Policies != nil || view.Inbound.SecurityGroups != nil {
		t.Fatalf("a refused section carries nothing: %s", raw)
	}
	for _, table := range view.Tables {
		if table.State != "refused" || table.CompileNow.Ruleset != "" || len(table.Owners) != 0 {
			t.Fatalf("table %s for node:read alone = %+v", table.Table, table)
		}
	}

	// netpolicy:read on n1 only: gnp_b's rule names n2, so the outbound
	// compile is refused rather than shown without that rule, and nothing
	// of n2 or n3 reaches the body.
	confined := createPAT(t, handler, cookies, csrf, []string{"node:read", "netpolicy:read", "netguard:read"}, []string{"n1"})
	code, view, raw = bearerNodeNetwork(t, handler, confined, "node_id=n1&rules=1")
	if code != http.StatusOK {
		t.Fatalf("confined = %d %s", code, raw)
	}
	policy := view.Tables[view.table(t, "inet lattice_policy")]
	if policy.CompileNow.State != "refused" || policy.CompileNow.Ruleset != "" || policy.CompileNow.SHA256 != "" {
		t.Fatalf("an unreadable remote refuses the compile: %+v", policy.CompileNow)
	}
	for _, leak := range []string{"198.51.100.9", "10.66.0.2", "192.0.2.33", "10.66.0.3", "sg-1", "la-1"} {
		if strings.Contains(raw, leak) {
			t.Fatalf("confined body leaks %q: %s", leak, raw)
		}
	}
	for _, p := range view.Outbound.Policies {
		if p.ID == "gnp_c" && p.HiddenTargetNodes != 1 {
			t.Fatalf("the fleet policy counts the excluded node it hides: %+v", p)
		}
	}
	if len(st.Approvals()) != 0 {
		t.Fatal("refusals must not create approvals")
	}
}

// A manual document is compiled as it is stored, without the normalisation
// that refuses a group-derived one, so the compile itself must refuse a rule
// naming a node the caller cannot read rather than drop the rule.
func TestNodeNetworkRefusesAManualPolicyNamingAnUnreadableNode(t *testing.T) {
	_, handler, _, cookies, csrf := nodeNetworkFleet(t)
	res := doJSON(t, handler, http.MethodPost, "/api/netpolicy", `{"target_node_id":"n1","enabled":true,"rules":[{"id":"ssh","action":"allow","direction":"egress","protocol":"tcp","ports":[22],"remote":{"kind":"node","node_id":"n2"}}]}`, cookies, csrf)
	if raw := readBody(t, res); res.StatusCode != http.StatusOK {
		t.Fatalf("manual policy = %d %s", res.StatusCode, raw)
	}
	if _, view, raw := getNodeNetwork(t, handler, cookies, "node_id=n1&rules=1"); view.Outbound.Source != "manual" || !strings.Contains(view.Tables[view.table(t, "inet lattice_policy")].CompileNow.Ruleset, "10.66.0.2") {
		t.Fatalf("an unrestricted reader sees the manual compile with its remote: %s", raw)
	}

	confined := createPAT(t, handler, cookies, csrf, []string{"node:read", "netpolicy:read"}, []string{"n1"})
	code, view, raw := bearerNodeNetwork(t, handler, confined, "node_id=n1&rules=1")
	if code != http.StatusOK || view.Outbound.Source != "manual" {
		t.Fatalf("confined = %d %s", code, raw)
	}
	policy := view.Tables[view.table(t, "inet lattice_policy")]
	if policy.CompileNow.State != "refused" || policy.CompileNow.Scope != "netpolicy:read" || policy.CompileNow.Ruleset != "" || policy.CompileNow.SHA256 != "" {
		t.Fatalf("a manual rule naming an unreadable node refuses the compile: %+v", policy.CompileNow)
	}
	for _, leak := range []string{"10.66.0.2", "198.51.100.9", "la-1"} {
		if strings.Contains(raw, leak) {
			t.Fatalf("confined body leaks %q: %s", leak, raw)
		}
	}
}

// A confined token learns nothing countable about nodes outside its reach:
// the mesh peer count is refused unless every member is readable, a group
// remote counts once whatever the group's size, the beacon source count is
// sent only when every source is readable, and the manual document's ingress
// rules need the scope that reads that document.
func TestNodeNetworkCountsNothingOutsideTheCallersScope(t *testing.T) {
	_, handler, st, cookies, csrf := nodeNetworkFleet(t)
	if err := st.UpsertGroup(model.Group{ID: "grp_all", Name: "all", Slug: "all", Members: []string{"n1", "n2", "n3"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertGroupPolicy(model.GroupNetPolicy{ID: "gnp_mesh", Priority: 40, Enabled: true, Scope: &model.TargetSelector{Nodes: []string{"n1"}},
		Rules: []model.GroupNetRule{{ID: "all", Action: model.NetRuleAllow, Direction: model.NetDirEgress, Protocol: "tcp", Ports: []int{22}, Remote: model.NetEndpoint{Kind: model.NetRefGroup, GroupID: "grp_all"}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateBeaconTarget("n1", func(target *store.BeaconTarget, _ bool) (bool, error) {
		target.Settings = model.BeaconSettings{Enabled: true, Port: 47000}
		target.Approved = []model.BeaconPlanSource{{NodeID: "n2", Name: "la-1"}}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNetPolicy(model.NetPolicy{ID: "n2", TargetNodeID: "n2", Enabled: true,
		Rules: []model.NetRule{{ID: "in", Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: "tcp", Ports: []int{8080}, Remote: model.NetEndpoint{Kind: model.NetRefAny}}}}); err != nil {
		t.Fatal(err)
	}

	beaconSources := func(view nodeNetworkOut) int {
		for _, port := range view.Inbound.ExtraPorts {
			if port.Source == "beacon" {
				return port.Sources
			}
		}
		t.Fatalf("no beacon port in %+v", view.Inbound.ExtraPorts)
		return -1
	}
	policyRules := func(view nodeNetworkOut, id string) int {
		for _, p := range view.Outbound.Policies {
			if p.ID == id {
				return p.Rules
			}
		}
		t.Fatalf("no policy %s in %+v", id, view.Outbound.Policies)
		return -1
	}

	_, full, raw := getNodeNetwork(t, handler, cookies, "node_id=n1")
	if full.Mesh.Peers != 1 || full.Mesh.PeersRefused != "" || beaconSources(full) != 1 || policyRules(full, "gnp_mesh") != 1 {
		t.Fatalf("unrestricted view = %s", raw)
	}
	if _, legacy, raw := getNodeNetwork(t, handler, cookies, "node_id=n2"); legacy.Inbound.LegacyIngress == nil || legacy.Inbound.LegacyIngress.Rules != 1 {
		t.Fatalf("an unrestricted reader sees the manual document's ingress rules: %s", raw)
	}

	confined := createPAT(t, handler, cookies, csrf, []string{"node:read", "netguard:read", "netpolicy:read", "wireguard:read", "monitor:read"}, []string{"n1"})
	_, view, raw := bearerNodeNetwork(t, handler, confined, "node_id=n1")
	if view.Mesh.State != "ok" || view.Mesh.PeersRefused != "wireguard:read" || view.Mesh.Peers != 0 || !view.Mesh.Ready {
		t.Fatalf("a confined mesh keeps the node's own facts and refuses the peer count: %+v", view.Mesh)
	}
	if beaconSources(view) != 0 {
		t.Fatalf("the beacon source count names an unreadable source: %s", raw)
	}
	if policyRules(view, "gnp_mesh") != 1 {
		t.Fatalf("a group remote counts once, not once per member: %s", raw)
	}
	n2Only := createPAT(t, handler, cookies, csrf, []string{"node:read", "netguard:read"}, []string{"n2"})
	if _, view, raw := bearerNodeNetwork(t, handler, n2Only, "node_id=n2"); view.Inbound.State != "ok" || view.Inbound.LegacyIngress != nil {
		t.Fatalf("the manual document's ingress rules need netpolicy:read: %s", raw)
	}
}

// Access says whether a knock is required and the stage, never the sequence;
// the knock table serves no rules at all.
func TestNodeNetworkNeverServesTheKnockSequence(t *testing.T) {
	_, handler, st, cookies, _ := nodeNetworkFleet(t)
	at := time.Date(2026, 10, 24, 2, 0, 0, 0, time.UTC)
	if err := st.UpsertApproval(model.Approval{
		ID: "approval_knock", NodeID: "n1", Plugin: sshGuardPlugin, Action: sshGuardArmAction,
		Plan: "knockd sequence = 47011:udp,47213:tcp,47415:udp", Status: model.ApprovalApplied, CreatedAt: at, UpdatedAt: at,
	}); err != nil {
		t.Fatal(err)
	}
	_, view, raw := getNodeNetwork(t, handler, cookies, "node_id=n1&rules=1")
	for _, secret := range []string{"47011", "47213", "47415", "knockd"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("the view carries knock material %q: %s", secret, raw)
		}
	}
	knock := view.Tables[view.table(t, "inet lattice_knock")]
	if knock.LastWriter == nil || knock.LastWriter.Kind != "sshguard" || knock.RulesWithheld != "knock" || knock.LastApplied.Ruleset != "" {
		t.Fatalf("knock table = %+v", knock)
	}
	if view.Access.State != "ok" || view.Access.Stage == "" {
		t.Fatalf("access = %+v", view.Access)
	}
}

// The mesh section shows what the server holds and names what only the node
// knows.
func TestNodeNetworkMeshShowsWhatTheServerHolds(t *testing.T) {
	_, handler, _, cookies, _ := nodeNetworkFleet(t)
	_, view, _ := getNodeNetwork(t, handler, cookies, "node_id=n1")
	if !view.Mesh.Ready || view.Mesh.Peers != 1 || len(view.Mesh.Missing) != 0 || len(view.Mesh.NotReported) == 0 {
		t.Fatalf("n1 mesh = %+v", view.Mesh)
	}
	_, view, _ = getNodeNetwork(t, handler, cookies, "node_id=n3")
	if view.Mesh.Ready || !reflect.DeepEqual(view.Mesh.Missing, []string{"public_key"}) || view.Mesh.Peers != 2 {
		t.Fatalf("n3 mesh = %+v", view.Mesh)
	}
}
