package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// A beacon companion is NetGuard's table; on a node NetGuard let go of
// after the approve, the lease supersedes it rather than write a NetGuard
// compile over the legacy route's table.
func TestLeaseSupersedesABeaconCompanionOnceNetGuardLetGo(t *testing.T) {
	srv, handler, st := beaconFleet(t)
	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "node-t", Managed: true}); err != nil {
		t.Fatal(err)
	}
	srv.replaceAgentCapabilities("node-t", []string{netGuardManagedSHACapability})
	approved := enableBeacon(t, srv, handler, model.BeaconPlanRequest{})
	binding, _ := st.NodeGuardBinding("node-t")
	binding.Managed = false
	if _, err := st.UpsertNodeGuardBinding(binding); err != nil {
		t.Fatal(err)
	}
	leased, err := st.LeaseTasks("node-t", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(leased) != 0 {
		t.Fatalf("a beacon companion leased on a node NetGuard no longer manages: %+v", leased)
	}
	stored, _ := st.Approval(approved.Approval.ID)
	if stored.StaleCode != store.ApprovalStaleGuardOwnerChanged || !strings.Contains(stored.Reason, "no longer manages") {
		t.Fatalf("companion approval = %+v, want superseded", stored)
	}
}

// A NetGuard apply is applied again by planning it: its stored script is a
// whole table compiled once, and a rerun would replace the node's table with
// it, on a node NetGuard may no longer manage or beside a running legacy
// apply. The rerun is refused.
func TestNetGuardApplyIsNotRerun(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	setupAdoptedNetGuardNode(t, handler, st, cookies, csrf)
	seedNodeReality(t, st, "node-a", 22, "ens3")
	_, task := planApproveAndLeaseNetGuard(t, srv, handler, st, cookies, csrf)
	before := len(st.Tasks())
	rerun := doJSON(t, handler, http.MethodPost, "/api/tasks/rerun", `{"id":"`+task.ID+`"}`, cookies, csrf)
	if body := readBody(t, rerun); rerun.StatusCode != http.StatusConflict || !strings.Contains(body, "not rerun from its stored script") {
		t.Fatalf("rerun of a NetGuard apply = %d %s, want 409", rerun.StatusCode, body)
	}
	if len(st.Tasks()) != before {
		t.Fatal("a refused rerun queued a task")
	}
}

// Reach is what the plan's bytes carry, not only what the rules name now: a
// node that left a group remote after the plan was made is still pinned in
// it, so a token that cannot read that node still cannot read the plan.
func TestApprovalReachFollowsThePlanBytes(t *testing.T) {
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
	if _, err := st.UpsertSecurityGroup(group); err != nil {
		t.Fatal(err)
	}
	status, body, approval := netGuardPlanStatus(t, handler, cookies, csrf, "n1")
	if status != http.StatusOK || !strings.Contains(approval.Plan, "198.51.100.9") {
		t.Fatalf("netguard plan naming la-1 through the group: %d %s", status, body)
	}
	// la-1 leaves the group; the pending plan still carries its address.
	if err := st.UpsertGroup(model.Group{ID: "grp_peers", Name: "peers"}); err != nil {
		t.Fatal(err)
	}
	confined := createPAT(t, handler, cookies, csrf, []string{"network:plan", "netguard:read", "netguard:admin"}, []string{"n1"})
	for _, view := range decodeApprovalViews(t, doBearerJSON(t, handler, http.MethodGet, "/api/network/approvals", "", confined)) {
		if view.ID == approval.ID {
			t.Fatal("a token confined to tokyo-1 read a plan that still carries la-1's address")
		}
	}
}

// The batch plan refuses a node whose compile would close a running
// CoreDNS's ports, naming the deployment, and plans the others.
func TestNodeGroupPlanRefusesANodeThatWouldCloseDNSPorts(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	adoptNodeWithWebGroup(t, handler, st, cookies, csrf)
	depID := createDNSDeployment(t, handler, cookies, csrf)
	markDNSApplied(t, st, depID)
	if _, err := st.UpsertSecurityGroup(webSecurityGroup); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertGroup(model.Group{ID: "grp_web", Name: "web", Members: []string{"n1"}}); err != nil {
		t.Fatal(err)
	}
	bindNodeGroup(t, handler, cookies, csrf, "grp_web", 0, "sg-web")
	res := doJSON(t, handler, http.MethodPost, "/api/netguard/node-group-bindings/plan", `{"accept_lockout_risk":true}`, cookies, csrf)
	var out nodeGroupPlanOut
	if err := json.Unmarshal([]byte(readBody(t, res)), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Affected) != 0 || len(out.Conflicts) != 1 || out.Conflicts[0].NodeID != "n1" || !strings.Contains(out.Conflicts[0].Reason, `"private dns"`) {
		t.Fatalf("batch plan = %+v, want n1 refused naming the deployment", out)
	}
	if len(out.Conflicts[0].Findings) != 1 || out.Conflicts[0].Findings[0].Code != "dns_listener_closed" {
		t.Fatalf("the refusal must carry the finding: %+v", out.Conflicts[0].Findings)
	}
}

// A refusal through a group binding names the node group only to a caller
// who may read node groups; a caller confined to a node sees the derived
// group's name and rule count, never its rules or the group's identity.
func TestNodeGroupIdentityIsShownOnlyToGroupReaders(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	if _, err := st.UpsertSecurityGroup(webSecurityGroup); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertGroup(model.Group{ID: "grp_web", Name: "web", Members: []string{"n1"}}); err != nil {
		t.Fatal(err)
	}
	bindNodeGroup(t, handler, cookies, csrf, "grp_web", 0, "sg-web")
	planner := createPAT(t, handler, cookies, csrf, []string{"network:plan", "netguard:read"}, []string{"n1"})
	plan := doBearerJSON(t, handler, http.MethodPost, "/api/network/nft/plan", `{"node_id":"n1","public_tcp":[22]}`, planner)
	body := readBody(t, plan)
	if plan.StatusCode != http.StatusConflict || !strings.Contains(body, "a node group whose security groups NetGuard applies") || strings.Contains(body, "web") {
		t.Fatalf("refusal to a caller without group:read = %d %s, want the group unnamed", plan.StatusCode, body)
	}

	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "n1", Managed: true}); err != nil {
		t.Fatal(err)
	}
	nodes := doBearerJSON(t, handler, http.MethodGet, "/api/netguard/nodes", "", planner)
	var listed netGuardNodesWithDerived
	if err := json.Unmarshal([]byte(readBody(t, nodes)), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Nodes) != 1 || len(listed.Nodes[0].DerivedGroups) != 1 {
		t.Fatalf("the confined reader should see n1 with one derived group: %+v", listed)
	}
	derived := listed.Nodes[0].DerivedGroups[0]
	if derived.Name != "web" || derived.RuleCount != 1 || len(derived.Rules) != 0 || derived.ViaNodeGroup != nil {
		t.Fatalf("a confined reader's derived group = %+v, want name and count only", derived)
	}
}

type netGuardNodesWithDerived struct {
	Nodes []struct {
		NodeID        string `json:"node_id"`
		DerivedGroups []struct {
			ID           string            `json:"id"`
			Name         string            `json:"name"`
			Rules        []model.GuardRule `json:"rules"`
			RuleCount    int               `json:"rule_count"`
			ViaNodeGroup *nodeNetworkRef   `json:"via_node_group"`
		} `json:"derived_groups"`
	} `json:"nodes"`
}
