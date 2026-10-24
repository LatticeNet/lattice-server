package store

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func guardTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []model.Node{
		{ID: "n", Name: "tokyo", Tags: []string{"edge"}, PublicIP: "203.0.113.7"},
		{ID: "m", Name: "osaka", PublicIP: "203.0.113.8"},
	} {
		if err := st.UpsertNode(n); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"sg1", "sg2", "sg3"} {
		if _, err := st.UpsertSecurityGroup(model.SecurityGroup{ID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

func groupIDsOf(groups []model.SecurityGroup) []string {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		out = append(out, g.ID)
	}
	return out
}

// Derived groups follow the node's own, by node group name (not id), each
// node group's list in its order, a group already in force not repeated.
// They join the compile only on a managed binding, and are listed either way.
func TestDerivedGroupsOrderDedupAndAdoption(t *testing.T) {
	st := guardTestStore(t)
	for _, g := range []model.Group{
		{ID: "grp_1", Name: "beta", Members: []string{"n"}},
		{ID: "grp_2", Name: "alpha", Members: []string{"n"}},
	} {
		if err := st.UpsertGroup(g); err != nil {
			t.Fatal(err)
		}
	}
	for groupID, sgs := range map[string][]string{"grp_2": {"sg2", "sg1"}, "grp_1": {"sg1", "sg3"}} {
		if _, err := st.UpsertNodeGroupGuardBinding(model.NodeGroupGuardBinding{GroupID: groupID, SecurityGroupIDs: sgs}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "n", GroupIDs: []string{"sg3"}}); err != nil {
		t.Fatal(err)
	}
	snap, err := st.NetGuardCompileSnapshot("n")
	if err != nil {
		t.Fatal(err)
	}
	if got := groupIDsOf(snap.Groups); strings.Join(got, ",") != "sg3" {
		t.Fatalf("an unmanaged binding compiles only its own groups, got %v", got)
	}
	var derived []string
	for _, d := range snap.Derived {
		derived = append(derived, d.SecurityGroupID+"@"+d.NodeGroupName)
	}
	if strings.Join(derived, ",") != "sg2@alpha,sg1@alpha" {
		t.Fatalf("derived = %v, want sg2 then sg1 via alpha, beta adding nothing new", derived)
	}

	binding, _ := st.NodeGuardBinding("n")
	binding.Managed = true
	if _, err := st.UpsertNodeGuardBinding(binding); err != nil {
		t.Fatal(err)
	}
	snap, err = st.NetGuardCompileSnapshot("n")
	if err != nil {
		t.Fatal(err)
	}
	if got := groupIDsOf(snap.Groups); strings.Join(got, ",") != "sg3,sg2,sg1" {
		t.Fatalf("a managed binding compiles own then derived, got %v", got)
	}
}

func anchoredBinding(t *testing.T, st *Store, nodeID string, groups ...string) {
	t.Helper()
	binding, ok := st.NodeGuardBinding(nodeID)
	binding.NodeID, binding.Managed, binding.LastPlanSHA = nodeID, true, "anchor"
	if !ok {
		binding.GroupIDs = groups
	}
	if _, err := st.UpsertNodeGuardBinding(binding); err != nil {
		t.Fatal(err)
	}
}

func anchor(st *Store, nodeID string) string {
	binding, _ := st.NodeGuardBinding(nodeID)
	return binding.LastPlanSHA
}

// A plan made for one membership must not lease after the membership
// moved: a tag edit that moves a node in or out of a bound selector group,
// a geo edit, or a group edit clears the plan anchors of the compiles that
// change, and an edit that moves nothing leaves them.
func TestMembershipChangesClearPlanAnchors(t *testing.T) {
	st := guardTestStore(t)
	if err := st.UpsertGroup(model.Group{ID: "grp_edge", Name: "edge", Selector: &model.GroupSelector{MatchTagsAny: []string{"edge"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertNodeGroupGuardBinding(model.NodeGroupGuardBinding{GroupID: "grp_edge", SecurityGroupIDs: []string{"sg1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertSecurityGroup(model.SecurityGroup{ID: "from-edge", Name: "from-edge", Rules: []model.GuardRule{{
		ID: "r", Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: model.NetProtoTCP,
		Remote: model.NetEndpoint{Kind: model.NetRefGroup, GroupID: "grp_edge"},
	}}}); err != nil {
		t.Fatal(err)
	}
	anchoredBinding(t, st, "n")
	anchoredBinding(t, st, "m", "from-edge")

	if _, _, err := st.UpdateNodeMeta("n", "tokyo", "", "", []string{"edge", "prod"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if anchor(st, "n") != "anchor" || anchor(st, "m") != "anchor" {
		t.Fatal("a tag edit that moves no membership cleared an anchor")
	}
	if _, _, err := st.UpdateNodeMeta("n", "tokyo", "", "", []string{"prod"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if anchor(st, "n") != "" {
		t.Fatal("n left the bound group and its plan anchor stayed")
	}
	if anchor(st, "m") != "" {
		t.Fatal("n left a group m's rules take as a remote and m's plan anchor stayed")
	}

	anchoredBinding(t, st, "n")
	if err := st.UpsertGroup(model.Group{ID: "grp_edge", Name: "edge", Members: []string{"n"}, Selector: &model.GroupSelector{MatchTagsAny: []string{"edge"}}}); err != nil {
		t.Fatal(err)
	}
	if anchor(st, "n") != "" {
		t.Fatal("a group edit that added n kept n's plan anchor")
	}
}

// The in-use refusal happens under the lock that deletes, so a binding
// written between a caller's check and the delete cannot dangle.
func TestDeleteSecurityGroupRefusesWhileBound(t *testing.T) {
	st := guardTestStore(t)
	if err := st.UpsertGroup(model.Group{ID: "grp_web", Name: "web"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertNodeGroupGuardBinding(model.NodeGroupGuardBinding{GroupID: "grp_web", SecurityGroupIDs: []string{"sg1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "n", GroupIDs: []string{"sg2"}}); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{"sg1": "node group grp_web", "sg2": "node n"} {
		var inUse *SecurityGroupInUseError
		if err := st.DeleteSecurityGroup(id); !errors.As(err, &inUse) || !strings.Contains(err.Error(), want) {
			t.Fatalf("delete %s = %v, want in use by %s", id, err, want)
		}
		if _, ok := st.SecurityGroup(id); !ok {
			t.Fatalf("a refused delete removed %s", id)
		}
	}
	if err := st.DeleteSecurityGroup("sg3"); err != nil {
		t.Fatalf("an unbound group must delete: %v", err)
	}
}

func approvedTask(t *testing.T, st *Store, approval model.Approval, taskID string) {
	t.Helper()
	approval.Status = model.ApprovalApproved
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTask(model.Task{ID: taskID, ApprovalID: approval.ID, Targets: []string{approval.NodeID}, Interpreter: "sh",
		Script: "true", TimeoutSec: 60, OutputLimit: 1024, Status: model.TaskQueued, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
}

const coreDNSOnlyPlan = "## CoreDNS Corefile\n\n```coredns\n.:53 {\n  forward . 1.1.1.1\n}\n```\n"

// A superseded self-host DNS apply leaves its deployment failed with the
// reason, as a failed apply would, rather than applying forever; a rerun is
// cancelled without touching the decided approval it replays; a writer of
// the other side that is only queued, not running, holds nothing.
func TestLeaseSupersessionEffects(t *testing.T) {
	st := guardTestStore(t)
	dep := model.DNSDeployment{ID: "dns_1", Name: "private dns", NodeID: "n", Status: model.DNSStatusApplying}
	if err := st.UpsertDNSDeployment(dep); err != nil {
		t.Fatal(err)
	}
	ruleset := "\n## nftables lattice_guard candidate\n\n```nft\ntable inet lattice_guard {}\n```\n"
	dnsApproval := model.Approval{ID: "apr_dns", NodeID: "n", Plugin: "selfdns", Action: "apply-config:ZG5zXzE", Plan: coreDNSOnlyPlan + ruleset}
	approvedTask(t, st, dnsApproval, "task_dns")
	legacy := model.Approval{ID: "apr_legacy", NodeID: "n", Plugin: "nft", Action: "apply-ruleset", Plan: "table inet lattice_guard {}"}
	approvedTask(t, st, legacy, "task_legacy")
	rerun := model.Task{ID: "task_rerun", RerunOfTaskID: "task_legacy", Targets: []string{"n"}, Interpreter: "sh", Script: "true",
		TimeoutSec: 60, OutputLimit: 1024, Status: model.TaskQueued, CreatedAt: time.Now().UTC().Add(time.Second)}
	if err := st.CreateTask(rerun); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "n", Managed: true}); err != nil {
		t.Fatal(err)
	}
	leased, err := st.LeaseTasks("n", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(leased) != 0 {
		t.Fatalf("legacy writers on a managed node were leased: %+v", leased)
	}
	if got, _ := st.DNSDeployment("dns_1"); got.Status != model.DNSStatusFailed || !strings.Contains(got.LastError, "NetGuard took over") {
		t.Fatalf("deployment = %+v, want failed with the reason", got)
	}
	if got, _ := st.Approval("apr_legacy"); got.StaleCode != ApprovalStaleGuardOwnerChanged {
		t.Fatalf("legacy approval = %+v, want superseded", got)
	}
	if got, _ := st.Task("task_rerun"); got.Status != model.TaskCancelled {
		t.Fatalf("rerun = %s, want cancelled", got.Status)
	}
	if len(st.TakeGuardSupersessions()) != 3 {
		t.Fatal("each supersession is kept for the audit")
	}

	// m, unmanaged: a queued NetGuard apply that has not started holds no
	// legacy apply, and a running legacy apply holds the NetGuard one.
	other := model.Approval{ID: "apr_legacy_m", NodeID: "m", Plugin: "nft", Action: "apply-ruleset", Plan: "table inet lattice_guard { }"}
	approvedTask(t, st, other, "task_legacy_m")
	netguard := model.Approval{ID: "apr_ng", NodeID: "m", Plugin: "nft", Action: NetGuardApplyAction, Plan: "table inet lattice_guard {}"}
	approvedTask(t, st, netguard, "task_ng")
	leased, err = st.LeaseTasks("m", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(leased) != 1 || leased[0].ID != "task_legacy_m" {
		t.Fatalf("a queued NetGuard apply held the legacy one: %+v", leased)
	}
	if leased, _ = st.LeaseTasks("m", 1); len(leased) != 0 {
		t.Fatalf("a NetGuard apply leased while a legacy apply was running: %+v", leased)
	}
}
