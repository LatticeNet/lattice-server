package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// KI-29 race 1: a lattice_guard apply is decided at one time and executed at
// another, and each apply replaces the whole table. These tests put an apply
// of one side (the legacy firewall route, self-host DNS with a ruleset)
// behind or beside an apply of the other (NetGuard), and check that the
// later decision is refused while the earlier one is unfinished, and that an
// apply whose writer lost the table by the time the agent asks for it is
// superseded with a sentence instead of handed out.

// legacyApprovedAndQueued plans node-a's firewall on the legacy route and
// approves it with its apply task, leaving the task queued.
func legacyApprovedAndQueued(t *testing.T, handler http.Handler, st *store.Store, cookies []*http.Cookie, csrf string) (model.Approval, string) {
	t.Helper()
	token := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")
	inputs := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
		`{"node_id":"node-a","interface_name":"ens3","public_tcp":[22]}`, cookies, csrf)
	inputs.Body.Close()
	if inputs.StatusCode != http.StatusOK {
		t.Fatalf("save nft inputs: %d", inputs.StatusCode)
	}
	seedNodeReality(t, st, "node-a", 22, "ens3")
	plan := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan", `{"node_id":"node-a"}`, cookies, csrf)
	defer plan.Body.Close()
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("legacy nft plan: %d", plan.StatusCode)
	}
	approval := decodeNFTPlan(t, plan)
	if status, body := approveStatus(t, handler, cookies, csrf, approval); status != http.StatusOK {
		t.Fatalf("approve legacy plan: %d %s", status, body)
	}
	return approval, token
}

// taskFor returns the task an approval queued.
func taskFor(t *testing.T, st *store.Store, approvalID string) model.Task {
	t.Helper()
	for _, task := range st.Tasks() {
		if task.ApprovalID == approvalID {
			return task
		}
	}
	t.Fatalf("approval %s has no task", approvalID)
	return model.Task{}
}

// agentPoll asks for tasks as node-a's agent does, NetGuard capable.
func agentPoll(t *testing.T, handler http.Handler, token string) []agentTaskView {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/agent/tasks?node_id=node-a", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(agentCapabilitiesHeader, netGuardManagedSHACapability)
	res := serveReq(handler, req)
	if res.Code != http.StatusOK {
		t.Fatalf("agent poll: %d %s", res.Code, res.Body.String())
	}
	var views []agentTaskView
	if err := json.Unmarshal(res.Body.Bytes(), &views); err != nil {
		t.Fatal(err)
	}
	return views
}

func polled(views []agentTaskView, taskID string) bool {
	for _, v := range views {
		if v.ID == taskID {
			return true
		}
	}
	return false
}

func postTaskResult(t *testing.T, handler http.Handler, token string, view agentTaskView, result model.TaskResult) {
	t.Helper()
	result.TaskID, result.LeaseID = view.ID, view.LeaseID
	if result.FinishedAt.IsZero() {
		result.FinishedAt = time.Now().UTC()
	}
	payload := mustJSON(t, map[string]any{"node_id": "node-a", "result": result})
	res := doAgentRaw(t, handler, http.MethodPost, "/api/agent/task-result", string(payload), token)
	if res.Code != http.StatusOK {
		t.Fatalf("post task result: %d %s", res.Code, res.Body.String())
	}
}

// Adopting a node, or turning its binding to managed, while a legacy
// firewall apply for it is queued would let that apply land after
// NetGuard's own and replace it. Both wait for the legacy apply to finish.
func TestNetGuardAdoptWaitsForAnUnfinishedLegacyFirewallApply(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	legacy, token := legacyApprovedAndQueued(t, handler, st, cookies, csrf)

	adopt := doJSON(t, handler, http.MethodPost, "/api/netguard/nodes/adopt", `{"node_id":"node-a"}`, cookies, csrf)
	body := readBody(t, adopt)
	if adopt.StatusCode != http.StatusConflict || !strings.Contains(body, "legacy firewall plan") || !strings.Contains(body, legacy.ID) || !strings.Contains(body, "is queued") {
		t.Fatalf("adopt with a queued legacy apply = %d %s, want 409 naming the approval", adopt.StatusCode, body)
	}
	manage := doJSON(t, handler, http.MethodPost, "/api/netguard/bindings", `{"node_id":"node-a","group_ids":[],"managed":true}`, cookies, csrf)
	body = readBody(t, manage)
	if manage.StatusCode != http.StatusConflict || !strings.Contains(body, legacy.ID) {
		t.Fatalf("managed binding with a queued legacy apply = %d %s, want 409", manage.StatusCode, body)
	}
	if binding, ok := st.NodeGuardBinding("node-a"); ok && binding.Managed {
		t.Fatalf("a refused adoption left a managed binding: %+v", binding)
	}

	// Once the legacy apply has reported, NetGuard may take the node.
	views := agentPoll(t, handler, token)
	if len(views) != 1 {
		t.Fatalf("the legacy apply should be handed out: %+v", views)
	}
	postTaskResult(t, handler, token, views[0], model.TaskResult{ExitCode: 0, Stdout: "lattice nft: applied\n"})
	adopt = doJSON(t, handler, http.MethodPost, "/api/netguard/nodes/adopt", `{"node_id":"node-a"}`, cookies, csrf)
	if body := readBody(t, adopt); adopt.StatusCode != http.StatusOK {
		t.Fatalf("adopt after the legacy apply finished = %d %s", adopt.StatusCode, body)
	}
}

// The decisions above read and act in separate lock sections, so two of
// them racing can both pass. The lease is the backstop: a legacy apply
// whose node NetGuard took meanwhile is superseded, with a sentence and an
// audit line, and never reaches the agent.
func TestLeaseSupersedesALegacyFirewallApplyOnceNetGuardTookTheNode(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	legacy, token := legacyApprovedAndQueued(t, handler, st, cookies, csrf)
	task := taskFor(t, st, legacy.ID)

	// The adoption that won the race, written past the server's refusal.
	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "node-a", Managed: true}); err != nil {
		t.Fatal(err)
	}
	if views := agentPoll(t, handler, token); polled(views, task.ID) {
		t.Fatalf("a legacy apply on a node NetGuard manages was handed out: %+v", views)
	}
	stored, _ := st.Approval(legacy.ID)
	if stored.Status != model.ApprovalRejected || !stored.Stale || stored.StaleCode != store.ApprovalStaleGuardOwnerChanged ||
		!strings.Contains(stored.Reason, "NetGuard took over this node's firewall") {
		t.Fatalf("superseded approval = %+v, want rejected, stale guard_owner_changed with the reason", stored)
	}
	if storedTask, _ := st.Task(task.ID); storedTask.Status != model.TaskCancelled {
		t.Fatalf("superseded task status = %q, want cancelled", storedTask.Status)
	}
	audited := false
	for _, ev := range st.AuditEvents() {
		if ev.Action == "network.guard.superseded" && ev.Metadata["approval_id"] == legacy.ID && ev.Decision == "deny" {
			audited = true
		}
	}
	if !audited {
		t.Fatal("the supersession was not audited")
	}
}

// A self-host DNS plan made on the legacy path carries a ruleset and is a
// legacy writer like the firewall route: the lease supersedes it the same way.
func TestLeaseSupersedesASelfDNSRulesetOnceNetGuardTookTheNode(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	depID := createDNSDeployment(t, handler, cookies, csrf)
	seedNodeReality(t, st, "n1", 22, "eth0")
	plan := doJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+depID+`","accept_lockout_risk":true}`, cookies, csrf)
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("dns plan on the legacy path: %d %s", plan.StatusCode, readBody(t, plan))
	}
	approval := decodeDNSPlan(t, plan)
	if status, body := approveStatus(t, handler, cookies, csrf, approval); status != http.StatusOK {
		t.Fatalf("approve dns plan: %d %s", status, body)
	}
	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "n1", Managed: true}); err != nil {
		t.Fatal(err)
	}
	leased, err := st.LeaseTasks("n1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(leased) != 0 {
		t.Fatalf("a DNS ruleset on a node NetGuard manages was leased: %+v", leased)
	}
	if stored, _ := st.Approval(approval.ID); stored.StaleCode != store.ApprovalStaleGuardOwnerChanged {
		t.Fatalf("DNS approval = %+v, want superseded", stored)
	}
}

// A node that joins a node group whose security groups NetGuard applies is
// NetGuard's to write even before it is adopted (design 32 D7 with S4), so a
// legacy apply approved before the join is superseded too, naming the group.
func TestLeaseSupersedesALegacyApplyOnANodeCoveredThroughANodeGroup(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	legacy, token := legacyApprovedAndQueued(t, handler, st, cookies, csrf)
	task := taskFor(t, st, legacy.ID)

	if err := st.UpsertGroup(model.Group{ID: "grp_web", Name: "web", Members: []string{"node-a"}}); err != nil {
		t.Fatal(err)
	}
	sg, err := st.UpsertSecurityGroup(model.SecurityGroup{ID: "sg-ssh", Name: "ssh", Rules: []model.GuardRule{{
		ID: "ssh", Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: model.NetProtoTCP,
		Ports: []model.GuardPortRange{{From: 22, To: 22}}, Remote: model.NetEndpoint{Kind: model.NetRefZone, ZoneID: model.GuardZonePublic},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertNodeGroupGuardBinding(model.NodeGroupGuardBinding{GroupID: "grp_web", SecurityGroupIDs: []string{sg.ID}}); err != nil {
		t.Fatal(err)
	}
	if views := agentPoll(t, handler, token); polled(views, task.ID) {
		t.Fatalf("a legacy apply on a node covered through a node group was handed out: %+v", views)
	}
	stored, _ := st.Approval(legacy.ID)
	if stored.StaleCode != store.ApprovalStaleGuardOwnerChanged || !strings.Contains(stored.Reason, `node group "web"`) {
		t.Fatalf("superseded approval = %+v, want the reason naming the node group", stored)
	}
	if binding, ok := st.NodeGuardBinding("node-a"); ok && binding.Managed {
		t.Fatalf("a group binding adopted the node: %+v", binding)
	}
}

// The reverse: with a NetGuard apply running, a legacy plan approved for the
// same node (NetGuard let go of it in between) would race it on the node. The
// approve waits for the NetGuard apply, and the lease holds a legacy task
// that got past it until the NetGuard apply reports.
func TestLegacyApplyWaitsForARunningNetGuardApply(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	token := setupAdoptedNetGuardNode(t, handler, st, cookies, csrf)
	seedNodeReality(t, st, "node-a", 22, "ens3")
	netGuard, netGuardTask := planApproveAndLeaseNetGuard(t, srv, handler, st, cookies, csrf)

	binding, _ := st.NodeGuardBinding("node-a")
	release := doJSON(t, handler, http.MethodPost, "/api/netguard/bindings", string(mustJSON(t, map[string]any{
		"node_id": "node-a", "group_ids": binding.GroupIDs, "managed": false, "version": binding.Version,
	})), cookies, csrf)
	if body := readBody(t, release); release.StatusCode != http.StatusOK {
		t.Fatalf("unmanage: %d %s", release.StatusCode, body)
	}
	plan := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan", `{"node_id":"node-a"}`, cookies, csrf)
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("legacy plan on the released node: %d %s", plan.StatusCode, readBody(t, plan))
	}
	legacy := decodeNFTPlan(t, plan)
	status, body := approveStatus(t, handler, cookies, csrf, legacy)
	if status != http.StatusConflict || !strings.Contains(body, "NetGuard plan") || !strings.Contains(body, netGuard.ID) || !strings.Contains(body, "is running") {
		t.Fatalf("approve legacy beside a running NetGuard apply = %d %s, want 409 naming it", status, body)
	}

	// A legacy task that got past the approve, as a race would leave it.
	legacy.Status, legacy.ApprovedBy = model.ApprovalApproved, "admin"
	if err := st.UpsertApproval(legacy); err != nil {
		t.Fatal(err)
	}
	legacyTask := model.Task{ID: "task_legacy_race", ApprovalID: legacy.ID, Targets: []string{"node-a"}, Interpreter: "sh",
		Script: "true", TimeoutSec: 60, OutputLimit: 1024, Status: model.TaskQueued, CreatedAt: time.Now().UTC()}
	if err := st.CreateTask(legacyTask); err != nil {
		t.Fatal(err)
	}
	if views := agentPoll(t, handler, token); polled(views, legacyTask.ID) {
		t.Fatalf("a legacy apply was handed out while a NetGuard apply was running: %+v", views)
	}
	if stored, _ := st.Approval(legacy.ID); stored.Status != model.ApprovalApproved {
		t.Fatalf("a held legacy apply must stay approved, not be superseded: %+v", stored)
	}

	// The NetGuard apply reports (stale now, since the node was released);
	// the legacy apply is handed out on the next poll.
	res := postNetGuardTaskResult(t, handler, token, netGuardTask, model.TaskResult{ExitCode: 0,
		Stdout: "lattice nft: applied\n" + netGuardManagedSHAResultPrefix + strings.Repeat("c", 64) + "\n"})
	if res.Code != http.StatusOK {
		t.Fatalf("post netguard result: %d %s", res.Code, res.Body.String())
	}
	if views := agentPoll(t, handler, token); !polled(views, legacyTask.ID) {
		t.Fatalf("the legacy apply should be handed out once NetGuard's reported: %+v", views)
	}
}

// With a legacy apply running, approving a NetGuard plan for the node would
// queue NetGuard's table behind or beside it. The approve waits.
func TestNetGuardApproveWaitsForARunningLegacyApply(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	legacy, token := legacyApprovedAndQueued(t, handler, st, cookies, csrf)
	views := agentPoll(t, handler, token)
	if !polled(views, taskFor(t, st, legacy.ID).ID) {
		t.Fatalf("the legacy apply should be running: %+v", views)
	}
	// NetGuard took the node in a race with the lease above.
	if _, err := st.UpsertSecurityGroup(model.SecurityGroup{ID: "sg-ssh", Name: "ssh", Rules: []model.GuardRule{{
		ID: "ssh", Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: model.NetProtoTCP,
		Ports: []model.GuardPortRange{{From: 22, To: 22}}, Remote: model.NetEndpoint{Kind: model.NetRefZone, ZoneID: model.GuardZonePublic},
	}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "node-a", GroupIDs: []string{"sg-ssh"}, Managed: true}); err != nil {
		t.Fatal(err)
	}
	netGuard := planNetGuardApproval(t, handler, cookies, csrf)
	srv.replaceAgentCapabilities("node-a", []string{netGuardManagedSHACapability})
	status, body := approveStatus(t, handler, cookies, csrf, netGuard)
	if status != http.StatusConflict || !strings.Contains(body, "legacy firewall plan") || !strings.Contains(body, legacy.ID) || !strings.Contains(body, "is running") {
		t.Fatalf("approve NetGuard beside a running legacy apply = %d %s, want 409 naming it", status, body)
	}
	postTaskResult(t, handler, token, views[0], model.TaskResult{ExitCode: 0, Stdout: "lattice nft: applied\n"})
	if status, body := approveStatus(t, handler, cookies, csrf, netGuard); status != http.StatusOK {
		t.Fatalf("approve NetGuard after the legacy apply reported = %d %s", status, body)
	}
}
