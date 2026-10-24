package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Design 32 S4: security groups bound to node groups.

// webSecurityGroup allows tcp/8443 from the public zone. The rule takes the
// fast path into the public port list, so a compiled table shows it as 8443.
var webSecurityGroup = model.SecurityGroup{ID: "sg-web", Name: "web", Rules: []model.GuardRule{{
	ID: "web-8443", Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: model.NetProtoTCP,
	Ports: []model.GuardPortRange{{From: 8443, To: 8443}}, Remote: model.NetEndpoint{Kind: model.NetRefZone, ZoneID: model.GuardZonePublic},
}}}

// adoptGuardNode enrolls a node, gives it a legacy baseline allowing tcp/22
// on ens3, adopts it in NetGuard and seeds the reality the lint reads.
func adoptGuardNode(t *testing.T, handler http.Handler, st *store.Store, cookies []*http.Cookie, csrf, nodeID, name string) string {
	t.Helper()
	token := enrollNamedNodeToken(t, handler, cookies, csrf, nodeID, name)
	inputs := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
		`{"node_id":"`+nodeID+`","interface_name":"ens3","public_tcp":[22]}`, cookies, csrf)
	if body := readBody(t, inputs); inputs.StatusCode != http.StatusOK {
		t.Fatalf("save nft inputs for %s: %d %s", nodeID, inputs.StatusCode, body)
	}
	adopt := doJSON(t, handler, http.MethodPost, "/api/netguard/nodes/adopt", `{"node_id":"`+nodeID+`"}`, cookies, csrf)
	if body := readBody(t, adopt); adopt.StatusCode != http.StatusOK {
		t.Fatalf("adopt %s: %d %s", nodeID, adopt.StatusCode, body)
	}
	seedNodeReality(t, st, nodeID, 22, "ens3")
	return token
}

func bindNodeGroup(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, groupID string, version int64, securityGroupIDs ...string) model.NodeGroupGuardBinding {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/netguard/node-group-bindings", string(mustJSON(t, map[string]any{
		"group_id": groupID, "security_group_ids": securityGroupIDs, "version": version,
	})), cookies, csrf)
	body := readBody(t, res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("bind %s: %d %s", groupID, res.StatusCode, body)
	}
	var out model.NodeGroupGuardBinding
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

type nodeGroupPlanOut struct {
	Affected  []nodeGroupPlanNode    `json:"affected"`
	Unchanged []nodeGroupPlanSkipped `json:"unchanged"`
	Conflicts []nodeGroupPlanSkipped `json:"conflicts"`
	Inactive  []nodeGroupPlanSkipped `json:"inactive"`
}

func (o nodeGroupPlanOut) affected(nodeID string) (nodeGroupPlanNode, bool) {
	for _, n := range o.Affected {
		if n.NodeID == nodeID {
			return n, true
		}
	}
	return nodeGroupPlanNode{}, false
}

func planNodeGroups(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, body string) nodeGroupPlanOut {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/netguard/node-group-bindings/plan", body, cookies, csrf)
	raw := readBody(t, res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("node group plan: %d %s", res.StatusCode, raw)
	}
	var out nodeGroupPlanOut
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Conflicts) > 0 {
		t.Fatalf("node group plan conflicts: %+v", out.Conflicts)
	}
	return out
}

// applyNetGuardApproval approves an approval with its task, leases it as the
// node's agent and reports a successful apply.
func applyNetGuardApproval(t *testing.T, srv *Server, handler http.Handler, st *store.Store, cookies []*http.Cookie, csrf, token, approvalID string) model.Approval {
	t.Helper()
	approval, ok := st.Approval(approvalID)
	if !ok {
		t.Fatalf("approval %s not found", approvalID)
	}
	srv.replaceAgentCapabilities(approval.NodeID, []string{netGuardManagedSHACapability})
	if status, body := approveStatus(t, handler, cookies, csrf, approval); status != http.StatusOK {
		t.Fatalf("approve %s: %d %s", approvalID, status, body)
	}
	leased, err := st.LeaseTasks(approval.NodeID, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range leased {
		if task.ApprovalID != approvalID {
			continue
		}
		res := postNetGuardTaskResult(t, handler, token, task, model.TaskResult{ExitCode: 0,
			Stdout: "lattice nft: applied\n" + netGuardManagedSHAResultPrefix + strings.Repeat("d", 64) + "\n"})
		if res.Code != http.StatusOK {
			t.Fatalf("post result for %s: %d %s", approvalID, res.Code, res.Body.String())
		}
		applied, _ := st.Approval(approvalID)
		if applied.Status != model.ApprovalApplied {
			t.Fatalf("approval %s = %s after its apply, want applied (%s)", approvalID, applied.Status, applied.Reason)
		}
		return applied
	}
	t.Fatalf("no leased task for %s: %+v", approvalID, leased)
	return model.Approval{}
}

func approvalsFor(st *store.Store, nodeID string) int {
	n := 0
	for _, a := range st.Approvals() {
		if a.NodeID == nodeID {
			n++
		}
	}
	return n
}

// A security group bound to a node group reaches a managed member only
// through a plan the operator approves: a member that joins after the
// binding's batch plan gets the group through the next one, and a member
// that leaves loses it the same way. An unmanaged member reads inactive and
// is never adopted.
func TestNodeGroupBindingReachesAMemberOnlyThroughAnApprovedPlan(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	tokenA := adoptGuardNode(t, handler, st, cookies, csrf, "node-a", "Node A")
	tokenB := adoptGuardNode(t, handler, st, cookies, csrf, "node-b", "Node B")
	enrollNamedNodeToken(t, handler, cookies, csrf, "node-c", "Node C")
	if _, err := st.UpsertSecurityGroup(webSecurityGroup); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertGroup(model.Group{ID: "grp_web", Name: "web", Members: []string{"node-a", "node-c"}}); err != nil {
		t.Fatal(err)
	}
	bindNodeGroup(t, handler, cookies, csrf, "grp_web", 0, "sg-web")
	if n := len(st.Approvals()); n != 0 {
		t.Fatalf("a binding queued %d approvals by itself", n)
	}

	plan := planNodeGroups(t, handler, cookies, csrf, `{}`)
	a, ok := plan.affected("node-a")
	if !ok || len(plan.Affected) != 1 {
		t.Fatalf("the batch plan should plan node-a alone: %+v", plan)
	}
	if len(a.Added) != 1 || a.Added[0].ID != "sg-web" || a.Added[0].ViaNodeGroup == nil || a.Added[0].ViaNodeGroup.Name != "web" ||
		!strings.Contains(a.Change, "adds web (via node group web)") {
		t.Fatalf("node-a's plan must name what it adds: %+v", a)
	}
	if len(a.Order) != 2 || a.Order[0].ID != "sg-legacy-node-a" || a.Order[1].ID != "sg-web" {
		t.Fatalf("the preview order must be the node's own groups, then the derived one: %+v", a.Order)
	}
	if len(plan.Inactive) != 1 || plan.Inactive[0].NodeID != "node-c" || plan.Inactive[0].Reason != "group binding inactive: node not managed" {
		t.Fatalf("node-c must read inactive: %+v", plan.Inactive)
	}
	if binding, ok := st.NodeGuardBinding("node-c"); ok && binding.Managed {
		t.Fatalf("a group binding adopted node-c: %+v", binding)
	}
	applied := applyNetGuardApproval(t, srv, handler, st, cookies, csrf, tokenA, a.ApprovalID)
	if !strings.Contains(applied.Plan, "8443") {
		t.Fatalf("node-a's applied table lacks the derived group's rule:\n%s", applied.Plan)
	}
	if binding, _ := st.NodeGuardBinding("node-a"); !slices.Equal(binding.AppliedDerived, []model.DerivedSecurityGroup{{SecurityGroupID: "sg-web", NodeGroupID: "grp_web"}}) {
		t.Fatalf("node-a's apply must record what it derived: %+v", binding.AppliedDerived)
	}

	// node-b joins: nothing reaches it until a plan is approved.
	if err := st.UpsertGroup(model.Group{ID: "grp_web", Name: "web", Members: []string{"node-a", "node-b", "node-c"}}); err != nil {
		t.Fatal(err)
	}
	if n := approvalsFor(st, "node-b"); n != 0 {
		t.Fatalf("joining a bound group queued %d approvals for node-b", n)
	}
	plan = planNodeGroups(t, handler, cookies, csrf, `{"group_id":"grp_web"}`)
	b, ok := plan.affected("node-b")
	if !ok || len(plan.Affected) != 1 || len(b.Added) != 1 || b.Added[0].ID != "sg-web" {
		t.Fatalf("the batch plan after the join should plan node-b alone, adding web: %+v", plan)
	}
	if len(plan.Unchanged) != 1 || plan.Unchanged[0].NodeID != "node-a" {
		t.Fatalf("node-a is in sync and must be listed unchanged: %+v", plan.Unchanged)
	}
	applied = applyNetGuardApproval(t, srv, handler, st, cookies, csrf, tokenB, b.ApprovalID)
	if !strings.Contains(applied.Plan, "8443") {
		t.Fatalf("node-b's applied table lacks the derived group's rule:\n%s", applied.Plan)
	}

	// node-b leaves: the next plan removes the group.
	if err := st.UpsertGroup(model.Group{ID: "grp_web", Name: "web", Members: []string{"node-a", "node-c"}}); err != nil {
		t.Fatal(err)
	}
	plan = planNodeGroups(t, handler, cookies, csrf, `{"group_id":"grp_web"}`)
	b, ok = plan.affected("node-b")
	if !ok || len(b.Removed) != 1 || b.Removed[0].ID != "sg-web" || !strings.Contains(b.Change, "removes web (via node group web)") {
		t.Fatalf("the batch plan after the leave should remove web from node-b: %+v", plan)
	}
	applied = applyNetGuardApproval(t, srv, handler, st, cookies, csrf, tokenB, b.ApprovalID)
	if strings.Contains(applied.Plan, "8443") {
		t.Fatalf("node-b's table still carries the group it left:\n%s", applied.Plan)
	}
	if binding, _ := st.NodeGuardBinding("node-b"); len(binding.AppliedDerived) != 0 {
		t.Fatalf("node-b's apply must record that it derives nothing: %+v", binding.AppliedDerived)
	}
	if plan = planNodeGroups(t, handler, cookies, csrf, `{}`); len(plan.Affected) != 0 {
		t.Fatalf("nothing is left to plan: %+v", plan.Affected)
	}
}

// The node page and the NetGuard views show derived groups after the node's
// own, active on a managed member and inactive, with why, on an unmanaged one.
func TestDerivedGroupsShowActiveAndInactive(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	adoptGuardNode(t, handler, st, cookies, csrf, "node-a", "Node A")
	enrollNamedNodeToken(t, handler, cookies, csrf, "node-c", "Node C")
	if _, err := st.UpsertSecurityGroup(webSecurityGroup); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertGroup(model.Group{ID: "grp_web", Name: "web", Members: []string{"node-a", "node-c"}}); err != nil {
		t.Fatal(err)
	}
	bindNodeGroup(t, handler, cookies, csrf, "grp_web", 0, "sg-web")

	_, managed, raw := getNodeNetwork(t, handler, cookies, "node_id=node-a")
	derived := managed.Inbound.DerivedSecurityGroups
	if len(derived) != 1 || derived[0].ID != "sg-web" || derived[0].Via == nil || derived[0].Via.Name != "web" || derived[0].State != "" {
		t.Fatalf("node-a's network must list web via node group web as active: %s", raw)
	}
	_, unmanaged, raw := getNodeNetwork(t, handler, cookies, "node_id=node-c")
	derived = unmanaged.Inbound.DerivedSecurityGroups
	if len(derived) != 1 || derived[0].State != "inactive" || derived[0].Reason != "group binding inactive: node not managed" {
		t.Fatalf("node-c's network must list web as inactive: %s", raw)
	}

	review := doJSON(t, handler, http.MethodGet, "/api/netguard/review?node_id=node-a", "", cookies, csrf)
	var reviewed netGuardReviewResponse
	if err := json.Unmarshal([]byte(readBody(t, review)), &reviewed); err != nil {
		t.Fatal(err)
	}
	view := reviewed.Review.Node
	if len(view.Groups) != 1 || len(view.DerivedGroups) != 1 || view.DerivedGroups[0].ID != "sg-web" || view.DerivedGroups[0].Inactive {
		t.Fatalf("the review must keep own and derived groups apart: %+v", view)
	}
	if !strings.Contains(reviewed.Review.Ruleset, "8443") {
		t.Fatalf("the review's preview must compile the derived group:\n%s", reviewed.Review.Ruleset)
	}
}

// The beacon approve re-renders the plan through the system compile path, so
// it is correct only if that path includes derived groups. A companion
// planned on a member of a bound group carries the group's rules and is
// approved; one whose member left the group in between is refused as stale.
func TestBeaconApproveRerenderIncludesDerivedGroups(t *testing.T) {
	srv, handler, st := beaconFleet(t)
	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "node-t", Managed: true}); err != nil {
		t.Fatal(err)
	}
	srv.replaceAgentCapabilities("node-t", []string{netGuardManagedSHACapability})
	if _, err := st.UpsertSecurityGroup(webSecurityGroup); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertGroup(model.Group{ID: "grp_edge", Name: "edge", Members: []string{"node-t"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertNodeGroupGuardBinding(model.NodeGroupGuardBinding{GroupID: "grp_edge", SecurityGroupIDs: []string{"sg-web"}}); err != nil {
		t.Fatal(err)
	}
	code, out, raw := planBeacon(t, handler, model.BeaconPlanRequest{NodeID: "node-t", Action: model.BeaconActionEnable})
	if code != http.StatusOK {
		t.Fatalf("plan = %d %s", code, raw)
	}
	if out.Plan.NetGuard == nil || !strings.Contains(out.Plan.NetGuard.Ruleset, "8443") {
		t.Fatalf("the companion must carry the derived group's rules: %+v", out.Plan.NetGuard)
	}
	approved, err := decideBeacon(srv, out.Approval, beaconAdmin())
	if err != nil {
		t.Fatalf("approving a companion with derived groups: %v", err)
	}
	if tasks := tasksFor(srv, approved.ID); len(tasks) != 1 || !strings.Contains(tasks[0].Script, "8443") {
		t.Fatalf("the companion task must apply the derived group: %+v", tasks)
	}

	code, out, raw = planBeacon(t, handler, model.BeaconPlanRequest{NodeID: "node-t", Action: model.BeaconActionDisable})
	if code != http.StatusOK {
		t.Fatalf("disable plan = %d %s", code, raw)
	}
	if err := st.UpsertGroup(model.Group{ID: "grp_edge", Name: "edge"}); err != nil {
		t.Fatal(err)
	}
	if _, err := decideBeacon(srv, out.Approval, beaconAdmin()); err == nil || !strings.Contains(err.Error(), "changed since this plan was made") {
		t.Fatalf("a companion planned before the node left the group must be stale: %v", err)
	}
}

// D7 with S4: a node covered only through a group binding (NetGuard does not
// manage it yet) is NetGuard's to write. The legacy route and a DNS ruleset
// are refused there at plan and at approve, naming the group, and the node
// is not adopted by any of it.
func TestLegacyRouteRefusedOnANodeCoveredOnlyThroughAGroupBinding(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	seedNodeReality(t, st, "n1", 22, "eth0")
	early := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan", `{"node_id":"n1","public_tcp":[22]}`, cookies, csrf)
	if early.StatusCode != http.StatusOK {
		t.Fatalf("legacy plan before the binding: %d %s", early.StatusCode, readBody(t, early))
	}
	legacy := decodeNFTPlan(t, early)
	depID := createDNSDeployment(t, handler, cookies, csrf)

	if _, err := st.UpsertSecurityGroup(webSecurityGroup); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertGroup(model.Group{ID: "grp_web", Name: "web", Members: []string{"n1"}}); err != nil {
		t.Fatal(err)
	}
	bindNodeGroup(t, handler, cookies, csrf, "grp_web", 0, "sg-web")

	plan := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan", `{"node_id":"n1","public_tcp":[22]}`, cookies, csrf)
	if body := readBody(t, plan); plan.StatusCode != http.StatusConflict || !strings.Contains(body, `node group \"web\"`) {
		t.Fatalf("legacy plan on a node covered through a group = %d %s, want 409 naming the group", plan.StatusCode, body)
	}
	if status, body := approveStatus(t, handler, cookies, csrf, legacy); status != http.StatusConflict || !strings.Contains(body, `node group \"web\"`) {
		t.Fatalf("approving a legacy plan made before the binding = %d %s, want 409", status, body)
	}
	dns := doJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+depID+`","accept_lockout_risk":true}`, cookies, csrf)
	if body := readBody(t, dns); dns.StatusCode != http.StatusConflict || !strings.Contains(body, `node group \"web\"`) {
		t.Fatalf("DNS plan with a ruleset on a node covered through a group = %d %s, want 409", dns.StatusCode, body)
	}
	if binding, ok := st.NodeGuardBinding("n1"); ok && binding.Managed {
		t.Fatalf("a group binding adopted n1: %+v", binding)
	}
	// Leaving the group gives the legacy route back.
	if err := st.UpsertGroup(model.Group{ID: "grp_web", Name: "web"}); err != nil {
		t.Fatal(err)
	}
	again := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan", `{"node_id":"n1","public_tcp":[22]}`, cookies, csrf)
	if body := readBody(t, again); again.StatusCode != http.StatusOK {
		t.Fatalf("legacy plan after the node left the group = %d %s", again.StatusCode, body)
	}
}

// A guard rule whose remote is a node group compiles to every member's
// addresses. A token confined to some nodes may not write one into a node
// binding, the group's Used by lists the binding and the rule, and the group
// cannot be deleted while either names it.
func TestGroupRemoteExpandsAndIsGuarded(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	adoptNodeWithWebGroup(t, handler, st, cookies, csrf)
	if err := st.UpsertGroup(model.Group{ID: "grp_peers", Name: "peers", Members: []string{"n2"}}); err != nil {
		t.Fatal(err)
	}
	group, _ := st.SecurityGroup("sg-web")
	group.Rules = append(group.Rules, model.GuardRule{ID: "from-peers", Action: model.NetRuleAllow, Direction: model.NetDirIngress,
		Protocol: model.NetProtoTCP, Ports: []model.GuardPortRange{{From: 9100, To: 9100}},
		Remote: model.NetEndpoint{Kind: model.NetRefGroup, GroupID: "grp_peers"}})
	save := doJSON(t, handler, http.MethodPost, "/api/netguard/groups", string(mustJSON(t, group)), cookies, csrf)
	if body := readBody(t, save); save.StatusCode != http.StatusOK {
		t.Fatalf("save a security group with a group remote: %d %s", save.StatusCode, body)
	}
	status, body, approval := netGuardPlanStatus(t, handler, cookies, csrf, "n1")
	if status != http.StatusOK {
		t.Fatalf("netguard plan: %d %s", status, body)
	}
	if !strings.Contains(approval.Plan, "ip saddr { 10.66.0.2, 198.51.100.9 } tcp dport { 9100 } accept") {
		t.Fatalf("the group remote must expand to la-1's addresses:\n%s", approval.Plan)
	}

	confined := createPAT(t, handler, cookies, csrf, []string{"netguard:admin", "netguard:read"}, []string{"n2"})
	override := doBearerJSON(t, handler, http.MethodPost, "/api/netguard/bindings", string(mustJSON(t, map[string]any{
		"node_id": "n2", "group_ids": []string{}, "managed": false,
		"overrides": []model.GuardRule{{ID: "o", Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: model.NetProtoTCP,
			Ports: []model.GuardPortRange{{From: 1, To: 1}}, Remote: model.NetEndpoint{Kind: model.NetRefGroup, GroupID: "grp_peers"}}},
	})), confined)
	if body := readBody(t, override); override.StatusCode != http.StatusForbidden {
		t.Fatalf("a confined token wrote a group remote override: %d %s", override.StatusCode, body)
	}

	if err := st.UpsertGroup(model.Group{ID: "grp_web", Name: "web", Members: []string{"n1"}}); err != nil {
		t.Fatal(err)
	}
	bindNodeGroup(t, handler, cookies, csrf, "grp_web", 0, "sg-web")
	for groupID, want := range map[string]string{"grp_web": "target", "grp_peers": "remote"} {
		res := doJSON(t, handler, http.MethodGet, "/api/groups/used-by?id="+groupID, "", cookies, csrf)
		var used struct {
			UsedBy []groupUse `json:"used_by"`
		}
		if err := json.Unmarshal([]byte(readBody(t, res)), &used); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, use := range used.UsedBy {
			if use.Kind == groupUseSecurityGroupBinding && use.ID == "sg-web" && use.Role == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s's Used by must list sg-web as %s: %+v", groupID, want, used.UsedBy)
		}
		del := doJSON(t, handler, http.MethodPost, "/api/groups/delete", `{"id":"`+groupID+`"}`, cookies, csrf)
		if body := readBody(t, del); del.StatusCode != http.StatusConflict || !strings.Contains(body, "security-group binding") {
			t.Fatalf("deleting %s while NetGuard names it = %d %s, want 409", groupID, del.StatusCode, body)
		}
	}
	del := doJSON(t, handler, http.MethodPost, "/api/netguard/groups/delete", `{"id":"sg-web"}`, cookies, csrf)
	if body := readBody(t, del); del.StatusCode != http.StatusConflict {
		t.Fatalf("deleting a security group a node group binds = %d %s, want 409", del.StatusCode, body)
	}
}

// The approvals list hid a plan only by its own node and, for a few plugins,
// the nodes it reaches. A NetGuard or legacy firewall plan pins other nodes'
// addresses into its text too, so a token confined to the plan's node must
// not read it when it cannot read those nodes.
func TestApprovalsListHidesFirewallPlansThatReachUnreadableNodes(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	adoptNodeWithWebGroup(t, handler, st, cookies, csrf)
	group, _ := st.SecurityGroup("sg-web")
	group.Rules = append(group.Rules, model.GuardRule{ID: "from-la", Action: model.NetRuleAllow, Direction: model.NetDirIngress,
		Protocol: model.NetProtoTCP, Ports: []model.GuardPortRange{{From: 9100, To: 9100}},
		Remote: model.NetEndpoint{Kind: model.NetRefNode, NodeID: "n2"}})
	if _, err := st.UpsertSecurityGroup(group); err != nil {
		t.Fatal(err)
	}
	status, body, netGuard := netGuardPlanStatus(t, handler, cookies, csrf, "n1")
	if status != http.StatusOK || !strings.Contains(netGuard.Plan, "198.51.100.9") {
		t.Fatalf("netguard plan naming la-1: %d %s", status, body)
	}

	// A legacy plan on la-1 whose outbound document admits tokyo-1 inbound.
	if err := st.UpsertNetPolicy(model.NetPolicy{ID: "n2", TargetNodeID: "n2", Enabled: true, Rules: []model.NetRule{{
		ID: "from-tokyo", Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: model.NetProtoTCP, Ports: []int{9200},
		Remote: model.NetEndpoint{Kind: model.NetRefNode, NodeID: "n1"},
	}}}); err != nil {
		t.Fatal(err)
	}
	seedNodeReality(t, st, "n2", 22, "eth0")
	legacyRes := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan", `{"node_id":"n2","public_tcp":[22]}`, cookies, csrf)
	if legacyRes.StatusCode != http.StatusOK {
		t.Fatalf("legacy plan on la-1: %d %s", legacyRes.StatusCode, readBody(t, legacyRes))
	}
	legacy := decodeNFTPlan(t, legacyRes)
	if !strings.Contains(legacy.Plan, "203.0.113.7") {
		t.Fatalf("the legacy plan should carry tokyo-1's address:\n%s", legacy.Plan)
	}

	for _, tc := range []struct {
		approval model.Approval
		own      string
		scopes   []string
	}{
		{netGuard, "n1", []string{"network:plan", "netguard:read", "netguard:admin"}},
		{legacy, "n2", []string{"network:plan", "netpolicy:read"}},
	} {
		confined := createPAT(t, handler, cookies, csrf, tc.scopes, []string{tc.own})
		res := doBearerJSON(t, handler, http.MethodGet, "/api/network/approvals", "", confined)
		for _, view := range decodeApprovalViews(t, res) {
			if view.ID == tc.approval.ID {
				t.Fatalf("a token confined to %s read approval %s, whose plan carries another node's addresses", tc.own, tc.approval.ID)
			}
		}
		wide := createPAT(t, handler, cookies, csrf, tc.scopes, []string{"n1", "n2"})
		seen := false
		for _, view := range decodeApprovalViews(t, doBearerJSON(t, handler, http.MethodGet, "/api/network/approvals", "", wide)) {
			seen = seen || view.ID == tc.approval.ID
		}
		if !seen {
			t.Fatalf("a token that reads both nodes must still see approval %s", tc.approval.ID)
		}
	}
}
