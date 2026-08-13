package store

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// seedNodeCascade enrolls a target node plus a bystander node, then attaches one
// of every node-owned and node-shared resource the cascade is expected to
// touch. It returns the store ready for DeleteNode/PlanDeleteNode assertions.
func seedNodeCascade(t *testing.T) *Store {
	t.Helper()
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	const node = "node-target"
	const other = "node-other"
	if err := s.UpsertNode(model.Node{ID: node, LatticeIdentityUUID: "generation-target", Name: "target"}); err != nil {
		t.Fatalf("upsert node: %v", err)
	}
	if err := s.UpsertNode(model.Node{ID: other, LatticeIdentityUUID: "generation-other", Name: "other"}); err != nil {
		t.Fatalf("upsert other: %v", err)
	}
	collectedAt := time.Date(2026, 7, 31, 13, 0, 0, 0, time.UTC)
	for nodeID, generation := range map[string]string{node: "generation-target", other: "generation-other"} {
		if _, _, err := s.UpsertGuardRealitySnapshot(generation, GuardRealitySnapshot{
			Reality:    model.GuardNodeReality{NodeID: nodeID, CollectedAt: collectedAt},
			ReceivedAt: collectedAt.Add(time.Second),
		}); err != nil {
			t.Fatalf("guard reality %s: %v", nodeID, err)
		}
	}

	// Step 1/2: a sole-target task (deleted) and a multi-target task (stripped),
	// each with a result for the target node.
	if err := s.CreateTask(model.Task{ID: "task-sole", Targets: []string{node}, Status: model.TaskFinished}); err != nil {
		t.Fatalf("task-sole: %v", err)
	}
	if err := s.CreateTask(model.Task{ID: "task-multi", Targets: []string{node, other}, Status: model.TaskFinished}); err != nil {
		t.Fatalf("task-multi: %v", err)
	}
	if err := s.AddTaskResult(model.TaskResult{TaskID: "task-sole", NodeID: node}); err != nil {
		t.Fatalf("result sole: %v", err)
	}
	if err := s.AddTaskResult(model.TaskResult{TaskID: "task-multi", NodeID: node}); err != nil {
		t.Fatalf("result multi node: %v", err)
	}
	if err := s.AddTaskResult(model.TaskResult{TaskID: "task-multi", NodeID: other}); err != nil {
		t.Fatalf("result multi other: %v", err)
	}

	// Step 3: DDNS.
	if err := s.UpsertDDNSProfile(model.DDNSProfile{ID: "ddns-1", NodeID: node, Provider: model.DDNSProviderCloudflare}); err != nil {
		t.Fatalf("ddns: %v", err)
	}
	// Step 4: machine profile.
	if err := s.UpsertMachineProfile(model.MachineProfile{ID: "mp-1", NodeID: node}); err != nil {
		t.Fatalf("machine profile: %v", err)
	}
	// Step 5: nft inputs (keyed by node).
	if err := s.UpsertNFTInputs(model.NFTInputs{NodeID: node}); err != nil {
		t.Fatalf("nft: %v", err)
	}
	// Step 6: dns deployment.
	if err := s.UpsertDNSDeployment(model.DNSDeployment{ID: "dns-1", NodeID: node}); err != nil {
		t.Fatalf("dns deployment: %v", err)
	}
	// Step 7: net policy (keyed by target node).
	if err := s.UpsertNetPolicy(model.NetPolicy{TargetNodeID: node, Enabled: true}); err != nil {
		t.Fatalf("net policy: %v", err)
	}
	// Step 7b: the bystander node's policy references the target as a peer (one
	// node-ref rule, stripped) plus a CIDR rule (kept). Deleting the target must
	// prune the dangling peer rule but keep the bystander's policy + its other rule.
	if err := s.UpsertNetPolicy(model.NetPolicy{TargetNodeID: other, Enabled: true, Rules: []model.NetRule{
		{ID: "peer-to-target", Action: model.NetRuleAllow, Direction: model.NetDirEgress, Protocol: model.NetProtoTCP, Ports: []int{22}, Remote: model.NetEndpoint{Kind: model.NetRefNode, NodeID: node}},
		{ID: "keep-cidr", Action: model.NetRuleAllow, Direction: model.NetDirEgress, Protocol: model.NetProtoUDP, Ports: []int{53}, Remote: model.NetEndpoint{Kind: model.NetRefCIDR, CIDR: "1.1.1.1/32"}},
	}}); err != nil {
		t.Fatalf("bystander net policy: %v", err)
	}
	// A group policy with a node-ref rule pointing at the target (stripped) plus an
	// any-rule (kept), so future expansions never re-materialize the gone node.
	if err := s.UpsertGroupPolicy(model.GroupNetPolicy{ID: "gnp-1", ScopeGroupID: "grp-1", Enabled: true, Rules: []model.GroupNetRule{
		{ID: "grp-peer-target", Action: model.NetRuleDeny, Direction: model.NetDirEgress, Protocol: model.NetProtoTCP, Ports: []int{3306}, Remote: model.NetEndpoint{Kind: model.NetRefNode, NodeID: node}},
		{ID: "grp-keep", Action: model.NetRuleAllow, Direction: model.NetDirEgress, Protocol: model.NetProtoTCP, Ports: []int{443}, Remote: model.NetEndpoint{Kind: model.NetRefAny}},
	}}); err != nil {
		t.Fatalf("group policy: %v", err)
	}
	// Step 8: geo routing - one shared (kept, stripped) and one sole (deleted).
	if err := s.UpsertGeoRouting(model.GeoRouting{ID: "geo-shared", NodeIDs: []string{node, other}, DNSNodeIDs: []string{other}}); err != nil {
		t.Fatalf("geo shared: %v", err)
	}
	if err := s.UpsertGeoRouting(model.GeoRouting{ID: "geo-sole", NodeIDs: []string{node}}); err != nil {
		t.Fatalf("geo sole: %v", err)
	}
	// Step 9: agent update policy (keyed by node).
	if err := s.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{NodeID: node}); err != nil {
		t.Fatalf("agent update: %v", err)
	}
	// Step 10/11: proxy profile + usage (keyed by node).
	if err := s.UpsertProxyNodeProfile(model.ProxyNodeProfile{NodeID: node}); err != nil {
		t.Fatalf("proxy profile: %v", err)
	}
	if err := s.UpsertProxyUsageSnapshot(model.ProxyUsageSnapshot{NodeID: node}); err != nil {
		t.Fatalf("proxy usage: %v", err)
	}
	// Step 12: monitor assignment (shared, stripped) + results for two nodes.
	if err := s.UpsertMonitor(model.Monitor{ID: "mon-1", Type: model.MonitorTypeTCP, NodeIDs: []string{node, other}}); err != nil {
		t.Fatalf("monitor: %v", err)
	}
	if err := s.AddMonitorResult(model.MonitorResult{MonitorID: "mon-1", NodeID: node}); err != nil {
		t.Fatalf("mon result node: %v", err)
	}
	if err := s.AddMonitorResult(model.MonitorResult{MonitorID: "mon-1", NodeID: other}); err != nil {
		t.Fatalf("mon result other: %v", err)
	}
	// Step 13: log source.
	if err := s.UpsertLogSource(model.LogSource{ID: "log-1", NodeID: node, Path: "/var/log/x"}); err != nil {
		t.Fatalf("log source: %v", err)
	}
	// Step 14: group with target as member + leader.
	if err := s.UpsertGroup(model.Group{ID: "grp-1", Name: "g", Slug: "g", Color: "sky", Members: []string{node, other}, LeaderID: node}); err != nil {
		t.Fatalf("group: %v", err)
	}
	// Step 15: approval.
	if err := s.UpsertApproval(model.Approval{ID: "appr-1", NodeID: node, Status: "pending"}); err != nil {
		t.Fatalf("approval: %v", err)
	}
	// Step 16: tunnel.
	if err := s.UpsertTunnel(model.TunnelProfile{ID: "tun-1", NodeID: node, TunnelID: "t"}); err != nil {
		t.Fatalf("tunnel: %v", err)
	}
	return s
}

// expectedCascade is the report both PlanDeleteNode and DeleteNode must produce
// for the seedNodeCascade fixture.
func expectedCascade() NodeCascadeReport {
	return NodeCascadeReport{
		NodeID:                   "node-target",
		TasksStripped:            1,
		TasksDeleted:             1,
		TaskResults:              2, // target's own result + the deleted sole task's result
		DDNSProfiles:             1,
		MachineProfiles:          1,
		NFTInputs:                1,
		DNSDeployments:           1,
		NetPolicies:              1,
		NetPeerRulesStripped:     1,
		GroupPolicyRulesStripped: 1,
		GeoRoutingStripped:       1,
		GeoRoutingDeleted:        1,
		AgentUpdatePolicies:      1,
		ProxyNodeProfiles:        1,
		ProxyUsageSnapshots:      1,
		MonitorsStripped:         1,
		MonitorResults:           1,
		LogSources:               1,
		Groups:                   1,
		Approvals:                1,
		Tunnels:                  1,
		GuardRealitySnapshots:    1,
	}
}

func assertReportCounts(t *testing.T, got, want NodeCascadeReport) {
	t.Helper()
	got.RemovedLogSourceIDs = nil
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cascade report mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}

// TestPlanDeleteNodeMatchesDelete asserts the dry-run plan reports identical
// counts to a real delete and that the plan mutates nothing.
func TestPlanDeleteNodeMatchesDelete(t *testing.T) {
	s := seedNodeCascade(t)

	plan, ok := s.PlanDeleteNode("node-target")
	if !ok {
		t.Fatal("plan: node not found")
	}
	assertReportCounts(t, plan, expectedCascade())

	// Plan must not have mutated anything: the node and its resources survive.
	if _, ok := s.Node("node-target"); !ok {
		t.Fatal("plan deleted the node")
	}
	if _, ok := s.NFTInputs("node-target"); !ok {
		t.Fatal("plan deleted nft inputs")
	}
	if _, ok := s.GuardRealitySnapshot("node-target"); !ok {
		t.Fatal("plan deleted guard reality snapshot")
	}

	del, ok, err := s.DeleteNode("node-target")
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !ok {
		t.Fatal("delete: node not found")
	}
	assertReportCounts(t, del, expectedCascade())

	// Plan and delete must agree on log-source IDs to purge.
	if len(del.RemovedLogSourceIDs) != 1 || del.RemovedLogSourceIDs[0] != "log-1" {
		t.Fatalf("RemovedLogSourceIDs = %v want [log-1]", del.RemovedLogSourceIDs)
	}
}

// TestDeleteNodeCascade asserts every node-owned resource is gone, shared
// resources are stripped (not deleted), bystander data is untouched, and the
// audit chain remains intact and verifiable.
func TestDeleteNodeCascade(t *testing.T) {
	s := seedNodeCascade(t)

	// An audit row predating the delete: it must survive (audit is append-only).
	if err := s.AppendAudit(model.AuditEvent{ID: "audit-pre", Action: "node.enroll", NodeID: "node-target"}); err != nil {
		t.Fatalf("append pre audit: %v", err)
	}

	if _, ok, err := s.DeleteNode("node-target"); err != nil || !ok {
		t.Fatalf("delete: ok=%v err=%v", ok, err)
	}

	// Node-owned resources are gone.
	if _, ok := s.Node("node-target"); ok {
		t.Fatal("node still present")
	}
	if _, ok := s.NFTInputs("node-target"); ok {
		t.Fatal("nft inputs survived")
	}
	if _, ok := s.NetPolicy("node-target"); ok {
		t.Fatal("net policy survived")
	}
	if _, ok := s.GuardRealitySnapshot("node-target"); ok {
		t.Fatal("guard reality snapshot survived")
	}
	if _, ok := s.GuardRealitySnapshot("node-other"); !ok {
		t.Fatal("bystander guard reality snapshot was deleted")
	}
	if _, ok := s.AgentUpdatePolicy("node-target"); ok {
		t.Fatal("agent update policy survived")
	}
	if _, ok := s.ProxyNodeProfile("node-target"); ok {
		t.Fatal("proxy profile survived")
	}
	if len(s.DDNSProfilesForNode("node-target")) != 0 {
		t.Fatal("ddns survived")
	}
	if _, ok := s.Task("task-sole"); ok {
		t.Fatal("sole-target task survived")
	}

	// Shared task kept, stripped of the gone node.
	multi, ok := s.Task("task-multi")
	if !ok {
		t.Fatal("multi-target task was deleted")
	}
	if contains(multi.Targets, "node-target") {
		t.Fatalf("multi-target task still targets deleted node: %v", multi.Targets)
	}
	if !contains(multi.Targets, "node-other") {
		t.Fatalf("multi-target task lost bystander target: %v", multi.Targets)
	}

	// Results: only the bystander's multi-task result remains.
	results := s.Results()
	if len(results) != 1 || results[0].NodeID != "node-other" {
		t.Fatalf("results after delete = %+v want one for node-other", results)
	}

	// Shared geo routing: shared kept+stripped, sole deleted.
	if shared, ok := s.GeoRouting("geo-shared"); !ok {
		t.Fatal("shared geo routing was deleted")
	} else if contains(shared.NodeIDs, "node-target") {
		t.Fatalf("shared geo still references node: %v", shared.NodeIDs)
	}
	if _, ok := s.GeoRouting("geo-sole"); ok {
		t.Fatal("sole geo routing survived")
	}

	// Shared monitor kept+stripped; only bystander's result remains.
	if mon, ok := s.Monitor("mon-1"); !ok {
		t.Fatal("monitor was deleted")
	} else if contains(mon.NodeIDs, "node-target") {
		t.Fatalf("monitor still assigned to node: %v", mon.NodeIDs)
	}
	monResults := s.MonitorResults("mon-1")
	if len(monResults) != 1 || monResults[0].NodeID != "node-other" {
		t.Fatalf("monitor results = %+v want one for node-other", monResults)
	}

	// Group kept; membership + leadership stripped.
	if g, ok := s.Group("grp-1"); !ok {
		t.Fatal("group was deleted")
	} else {
		if contains(g.Members, "node-target") {
			t.Fatalf("group still lists node as member: %v", g.Members)
		}
		if !contains(g.Members, "node-other") {
			t.Fatalf("group lost bystander member: %v", g.Members)
		}
		if g.LeaderID == "node-target" {
			t.Fatal("group still leads with deleted node")
		}
	}

	// Bystander node survives intact.
	if _, ok := s.Node("node-other"); !ok {
		t.Fatal("bystander node was deleted")
	}

	// Bystander's net policy kept; the dangling peer rule pointing at the deleted
	// node is pruned, the unrelated CIDR rule remains (no orphaned firewall ref).
	if np, ok := s.NetPolicy("node-other"); !ok {
		t.Fatal("bystander net policy was deleted")
	} else {
		for _, r := range np.Rules {
			if r.Remote.Kind == model.NetRefNode && r.Remote.NodeID == "node-target" {
				t.Fatalf("bystander policy still references deleted node: %+v", r)
			}
		}
		if len(np.Rules) != 1 || np.Rules[0].ID != "keep-cidr" {
			t.Fatalf("bystander policy rules = %+v want only keep-cidr", np.Rules)
		}
	}

	// Group policy kept; the node-ref rule is pruned so it can't re-materialize on
	// the next expansion, the any-rule remains.
	if gp, ok := s.GroupPolicy("gnp-1"); !ok {
		t.Fatal("group policy was deleted")
	} else {
		for _, r := range gp.Rules {
			if r.Remote.Kind == model.NetRefNode && r.Remote.NodeID == "node-target" {
				t.Fatalf("group policy still references deleted node: %+v", r)
			}
		}
		if len(gp.Rules) != 1 || gp.Rules[0].ID != "grp-keep" {
			t.Fatalf("group policy rules = %+v want only grp-keep", gp.Rules)
		}
	}

	// Audit preserved and chain still verifies.
	foundPre := false
	for _, ev := range s.AuditEvents() {
		if ev.ID == "audit-pre" {
			foundPre = true
		}
	}
	if !foundPre {
		t.Fatal("pre-delete audit row was removed")
	}
	// AuditWALVerify returns a non-nil error if the hash chain is broken; a clean
	// return means the chain still validates after the delete.
	if _, _, err := s.AuditWALVerify(); err != nil {
		t.Fatalf("audit wal chain broken: %v", err)
	}

	// disable still works on the surviving bystander node.
	if ok, err := s.SetNodeDisabled("node-other", true); err != nil || !ok {
		t.Fatalf("disable bystander: ok=%v err=%v", ok, err)
	}
}

// TestDeleteNodeUnknownIsIdempotent asserts deleting/planning a missing node is
// a no-op that reports not-found rather than erroring.
func TestDeleteNodeUnknownIsIdempotent(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, ok := s.PlanDeleteNode("ghost"); ok {
		t.Fatal("plan reported found for unknown node")
	}
	report, ok, err := s.DeleteNode("ghost")
	if err != nil {
		t.Fatalf("delete unknown err: %v", err)
	}
	if ok {
		t.Fatal("delete reported found for unknown node")
	}
	if report.NodeID != "ghost" {
		t.Fatalf("report.NodeID = %q want ghost", report.NodeID)
	}
}

func seedLineChainCascade(t *testing.T, lease bool) (*Store, model.Approval, model.Task, string) {
	t.Helper()
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, nodeID := range []string{"source-node", "target-node"} {
		if err := s.UpsertNode(model.Node{ID: nodeID, Name: nodeID}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PutManagedLineRecord(ManagedLinePublicRecord{LineUUID: "target-line", NodeID: "target-node", Status: "applied"}, ManagedLineSecretRecord{RealityPrivateKey: "private"}); err != nil {
		t.Fatal(err)
	}
	approval := model.Approval{ID: "approval-chain-cascade", NodeID: "source-node", Plugin: "singbox-linechain", PluginVersion: "1", Service: "network/lines", Method: "chain_set_apply",
		Action: "apply-line-chain:artifact", ArtifactDigest: "artifact", RequestSHA256: "request", Status: model.ApprovalPending, Targets: []string{"source-node"}}
	attempt := LineChainAttempt{ApprovalID: approval.ID, Operation: LineChainOperationSet, SourceLineUUID: "source-line", SourceNodeID: "source-node",
		CandidateTargetLineUUID: "target-line", CandidateTargetNodeID: "target-node", CandidateArtifactSHA256: "artifact", RequestSHA256: "request",
		CandidateDefinition: LineChainDefinition{SourceLineUUID: "source-line", SourceNodeID: "source-node", TargetLineUUID: "target-line", TargetNodeID: "target-node", ArtifactSHA256: "artifact"}}
	if _, _, err := s.PlanLineChainApproval(attempt, approval); err != nil {
		t.Fatal(err)
	}
	approval.Status = model.ApprovalApproved
	task := model.Task{ID: "task-chain-cascade", ApprovalID: approval.ID, Targets: []string{"source-node"}, Script: "script", Status: model.TaskQueued}
	if _, committed, err := s.ApproveLineChain(approval, task); err != nil || !committed {
		t.Fatalf("approve committed=%v err=%v", committed, err)
	}
	leaseID := ""
	if lease {
		deliveries, err := s.LeaseTaskDeliveriesWithLineChainValidator("source-node", 1, false, true, func(LineChainCompileStateSnapshot, model.Approval, LineChainAttempt, model.Task) error { return nil })
		if err != nil || len(deliveries) != 1 {
			t.Fatalf("lease=%+v err=%v", deliveries, err)
		}
		leaseID = deliveries[0].Task.LeaseID
	}
	return s, approval, task, leaseID
}

func TestDeleteNodeCancelsUnissuedLineChainAndPlanMatches(t *testing.T) {
	s, approval, task, _ := seedLineChainCascade(t, false)
	plan, ok := s.PlanDeleteNode("source-node")
	if !ok || plan.LineChainAttemptsReleased != 1 || plan.LineChainLeaseConflicts != 0 {
		t.Fatalf("unexpected plan: %+v ok=%v", plan, ok)
	}
	report, ok, err := s.DeleteNode("source-node")
	if err != nil || !ok || report.LineChainAttemptsReleased != plan.LineChainAttemptsReleased {
		t.Fatalf("delete report=%+v ok=%v err=%v", report, ok, err)
	}
	gotTask, _ := s.Task(task.ID)
	gotApproval, _ := s.Approval(approval.ID)
	snapshot := s.LineChainSnapshot()
	if gotTask.Status != model.TaskCancelled || gotApproval.Status != model.ApprovalRejected || len(snapshot.Attempts) != 0 || snapshot.Revision != 2 {
		t.Fatalf("cascade did not cancel/release atomically: task=%+v approval=%+v snapshot=%+v", gotTask, gotApproval, snapshot)
	}
}

func TestDeleteSourceNodeConflictsWithIssuedLineChainLease(t *testing.T) {
	s, _, _, _ := seedLineChainCascade(t, true)
	before := s.LineChainSnapshot()
	report, ok, err := s.DeleteNode("source-node")
	if !ok || !errors.Is(err, ErrLineChainDeleteConflict) || report.LineChainLeaseConflicts != 1 {
		t.Fatalf("delete report=%+v ok=%v err=%v", report, ok, err)
	}
	if _, found := s.Node("source-node"); !found || !reflect.DeepEqual(before, s.LineChainSnapshot()) {
		t.Fatalf("conflicting delete mutated state: before=%+v after=%+v", before, s.LineChainSnapshot())
	}
}

func TestDeleteSourceNodeAfterTerminalFailureDoesNotRetainLeaseConflict(t *testing.T) {
	s, approval, task, leaseID := seedLineChainCascade(t, true)
	result := model.TaskResult{TaskID: task.ID, NodeID: "source-node", LeaseID: leaseID, ExitCode: 1, Error: "host failed", FinishedAt: time.Now().UTC()}
	if committed, err := s.CompleteLineChainTaskResult(result, approval, LineChainStatusAppliedUnobserved, "host_apply_failed", "host failed"); err != nil || !committed {
		t.Fatalf("complete failure committed=%v err=%v", committed, err)
	}
	plan, ok := s.PlanDeleteNode("source-node")
	if !ok || plan.LineChainLeaseConflicts != 0 || plan.LineChainAttemptsReleased != 1 {
		t.Fatalf("terminal failure still blocks dry-run: ok=%v plan=%+v", ok, plan)
	}
	report, ok, err := s.DeleteNode("source-node")
	if err != nil || !ok || report.LineChainLeaseConflicts != 0 || report.LineChainAttemptsReleased != 1 {
		t.Fatalf("delete report=%+v ok=%v err=%v", report, ok, err)
	}
	if _, found := s.Node("source-node"); found || len(s.LineChainSnapshot().Attempts) != 0 {
		t.Fatalf("terminal failed source authority survived deletion: %+v", s.LineChainSnapshot())
	}
}

func TestDeleteTargetNodePreservesIssuedCandidateAndPromotesTargetMissing(t *testing.T) {
	s, approval, task, leaseID := seedLineChainCascade(t, true)
	report, ok, err := s.DeleteNode("target-node")
	if err != nil || !ok || report.ManagedLines != 1 || report.LineChainTargetsDrifted != 1 {
		t.Fatalf("delete report=%+v ok=%v err=%v", report, ok, err)
	}
	if _, _, found := s.ManagedLineRecord("target-line"); found {
		t.Fatal("target managed-line definition survived node deletion")
	}
	result := model.TaskResult{TaskID: task.ID, NodeID: "source-node", LeaseID: leaseID, ExitCode: 0, FinishedAt: time.Now().UTC()}
	if committed, err := s.CompleteLineChainTaskResult(result, approval, LineChainStatusDrifted, "target_missing", ""); err != nil || !committed {
		t.Fatalf("complete committed=%v err=%v", committed, err)
	}
	definition := s.LineChainSnapshot().Definitions["source-line"]
	if definition.TargetLineUUID != "target-line" || definition.Status != LineChainStatusDrifted || definition.DriftCode != "target_missing" || s.LineChainSnapshot().Revision != 3 {
		t.Fatalf("frozen target authority was not retained: %+v snapshot=%+v", definition, s.LineChainSnapshot())
	}
}

func TestDeleteNodeLineChainCascadePersistenceBoundaries(t *testing.T) {
	t.Run("source_before_lease_pre_rename_failure_publishes_nothing", func(t *testing.T) {
		s, approval, task, _ := seedLineChainCascade(t, false)
		before := s.LineChainSnapshot()
		if err := os.Mkdir(s.path+".tmp", 0o700); err != nil {
			t.Fatal(err)
		}
		report, ok, err := s.DeleteNode("source-node")
		if !ok || err == nil || report.LineChainAttemptsReleased != 1 {
			t.Fatalf("delete report=%+v ok=%v err=%v", report, ok, err)
		}
		gotApproval, _ := s.Approval(approval.ID)
		gotTask, _ := s.Task(task.ID)
		if _, found := s.Node("source-node"); !found || !reflect.DeepEqual(before, s.LineChainSnapshot()) || gotApproval.Status != model.ApprovalApproved || gotTask.Status != model.TaskQueued {
			t.Fatalf("pre-rename cascade published state: approval=%+v task=%+v before=%+v after=%+v", gotApproval, gotTask, before, s.LineChainSnapshot())
		}
		if _, ok, err := s.DeleteNode("source-node"); err != nil || !ok {
			t.Fatalf("retry did not commit cleanly: ok=%v err=%v", ok, err)
		}
	})

	t.Run("target_after_lease_post_rename_failure_publishes_once", func(t *testing.T) {
		s, _, _, _ := seedLineChainCascade(t, true)
		s.syncParentDir = func(string) error { return errors.New("forced post-rename sync failure") }
		report, ok, err := s.DeleteNode("target-node")
		if !ok || err == nil || report.LineChainTargetsDrifted != 1 || report.ManagedLines != 1 {
			t.Fatalf("delete report=%+v ok=%v err=%v", report, ok, err)
		}
		if _, found := s.Node("target-node"); found || s.LineChainSnapshot().Revision != 2 {
			t.Fatalf("post-rename cascade was not published exactly once: %+v", s.LineChainSnapshot())
		}
		s.syncParentDir = syncDir
		if retry, ok, err := s.DeleteNode("target-node"); err != nil || ok || retry.NodeID != "target-node" || s.LineChainSnapshot().Revision != 2 {
			t.Fatalf("retry was not idempotent: report=%+v ok=%v err=%v snapshot=%+v", retry, ok, err, s.LineChainSnapshot())
		}
	})
}
