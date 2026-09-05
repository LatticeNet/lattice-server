package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func newWaitingTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	return srv, st
}

func approvedTestApproval(id, nodeID, plugin, action string, created time.Time) model.Approval {
	return model.Approval{
		ID:        id,
		NodeID:    nodeID,
		Plugin:    plugin,
		Action:    action,
		Plan:      "plan",
		Status:    model.ApprovalApproved,
		ActorID:   "operator",
		CreatedAt: created,
	}
}

func waitFor(t *testing.T, srv *Server, approval model.Approval) *approvalWaitView {
	t.Helper()
	approvals := srv.store.Approvals()
	ctx := srv.newApprovalWaitContext(approvals)
	if ctx == nil {
		t.Fatal("expected a waiting context for a listing that contains an approved approval")
	}
	wait := srv.approvalWait(approval, ctx)
	if wait == nil {
		t.Fatal("expected an explanation for an approved approval")
	}
	return wait
}

// The production case: approved, nothing queued, and the target node has been
// out of contact for days. The page has to name the machine and the instant.
func TestApprovalWaitOfflineNodeNamesMachineAndInstant(t *testing.T) {
	srv, st := newWaitingTestServer(t)
	lastSeen := time.Now().UTC().Add(-72 * time.Hour)
	if err := st.UpsertNode(model.Node{ID: "node-1", Name: "[OpenJobs-Data]-tmp", Online: false, LastSeen: lastSeen, CreatedAt: lastSeen.Add(-24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	approval := approvedTestApproval("approval-1", "node-1", agentUpdatePlugin, agentUpdateAction, time.Now().UTC().Add(-time.Hour))
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	wait := waitFor(t, srv, approval)
	if wait.Code != ApprovalWaitNodeOffline {
		t.Fatalf("code = %q, want %q", wait.Code, ApprovalWaitNodeOffline)
	}
	if !wait.Blocked {
		t.Fatal("an approval waiting on an offline node is blocked")
	}
	if wait.NodeStatus != NodeStatusOffline {
		t.Fatalf("node_status = %q, want %q", wait.NodeStatus, NodeStatusOffline)
	}
	if !wait.NodeStatusSince.Equal(lastSeen) {
		t.Fatalf("node_status_since = %v, want %v", wait.NodeStatusSince, lastSeen)
	}
	if !strings.Contains(wait.Reason, "[OpenJobs-Data]-tmp") {
		t.Fatalf("reason does not name the node: %q", wait.Reason)
	}
	if !strings.Contains(wait.Reason, stamp(lastSeen)) {
		t.Fatalf("reason does not carry the instant: %q", wait.Reason)
	}
	if !wait.Dismissible {
		t.Fatal("an agent update approved against an unreachable node with no task must offer dismissal")
	}
}

func TestApprovalWaitNeverReportedNode(t *testing.T) {
	srv, st := newWaitingTestServer(t)
	enrolled := time.Now().UTC().Add(-30 * time.Hour)
	if err := st.UpsertNode(model.Node{ID: "node-2", Name: "fresh-box", CreatedAt: enrolled}); err != nil {
		t.Fatal(err)
	}
	approval := approvedTestApproval("approval-2", "node-2", agentUpdatePlugin, agentUpdateAction, time.Now().UTC())
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	wait := waitFor(t, srv, approval)
	if wait.Code != ApprovalWaitNodeNeverReported {
		t.Fatalf("code = %q, want %q", wait.Code, ApprovalWaitNodeNeverReported)
	}
	if wait.NodeStatus != NodeStatusNeverReported {
		t.Fatalf("node_status = %q, want %q", wait.NodeStatus, NodeStatusNeverReported)
	}
	if !strings.Contains(wait.Reason, "never reported") {
		t.Fatalf("reason does not say the node never reported: %q", wait.Reason)
	}
}

func TestApprovalWaitDisabledNode(t *testing.T) {
	srv, st := newWaitingTestServer(t)
	disabledAt := time.Now().UTC().Add(-2 * time.Hour)
	if err := st.UpsertNode(model.Node{ID: "node-3", Name: "parked", Disabled: true, DisabledAt: disabledAt, LastSeen: time.Now().UTC(), Online: true}); err != nil {
		t.Fatal(err)
	}
	approval := approvedTestApproval("approval-3", "node-3", agentUpdatePlugin, agentUpdateAction, time.Now().UTC())
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	wait := waitFor(t, srv, approval)
	if wait.Code != ApprovalWaitNodeDisabled {
		t.Fatalf("code = %q, want %q", wait.Code, ApprovalWaitNodeDisabled)
	}
	if !strings.Contains(wait.Reason, "parked") {
		t.Fatalf("reason does not name the node: %q", wait.Reason)
	}
}

func TestApprovalWaitNotQueuedOnHealthyNode(t *testing.T) {
	srv, st := newWaitingTestServer(t)
	if err := st.UpsertNode(model.Node{ID: "node-4", Name: "edge-4", Online: true, LastSeen: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	approval := approvedTestApproval("approval-4", "node-4", agentUpdatePlugin, agentUpdateAction, time.Now().UTC())
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	wait := waitFor(t, srv, approval)
	if wait.Code != ApprovalWaitNotQueued {
		t.Fatalf("code = %q, want %q", wait.Code, ApprovalWaitNotQueued)
	}
	if !wait.Blocked {
		t.Fatal("an approval with no apply task will not proceed on its own")
	}
}

func TestApprovalWaitQueuedTaskIsNotBlocked(t *testing.T) {
	srv, st := newWaitingTestServer(t)
	if err := st.UpsertNode(model.Node{ID: "node-5", Name: "edge-5", Online: true, LastSeen: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	approval := approvedTestApproval("approval-5", "node-5", agentUpdatePlugin, agentUpdateAction, time.Now().UTC())
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTask(model.Task{ID: "task-5", ApprovalID: approval.ID, Targets: []string{"node-5"}, Interpreter: "sh", Script: "true", Status: model.TaskQueued, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	wait := waitFor(t, srv, approval)
	if wait.Code != ApprovalWaitTaskQueued {
		t.Fatalf("code = %q, want %q", wait.Code, ApprovalWaitTaskQueued)
	}
	if wait.Blocked {
		t.Fatal("a queued task on a reporting node clears itself and is not blocked")
	}
	if wait.Dismissible {
		t.Fatal("an approval with a queued apply task must not offer dismissal")
	}
}

// A queued task on a node that cannot receive it is still blocked, and the
// node is the reason, not the queue.
func TestApprovalWaitQueuedTaskOnOfflineNodeReportsTheNode(t *testing.T) {
	srv, st := newWaitingTestServer(t)
	lastSeen := time.Now().UTC().Add(-48 * time.Hour)
	if err := st.UpsertNode(model.Node{ID: "node-6", Name: "quiet", LastSeen: lastSeen}); err != nil {
		t.Fatal(err)
	}
	approval := approvedTestApproval("approval-6", "node-6", agentUpdatePlugin, agentUpdateAction, time.Now().UTC())
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTask(model.Task{ID: "task-6", ApprovalID: approval.ID, Targets: []string{"node-6"}, Interpreter: "sh", Script: "true", Status: model.TaskQueued, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	wait := waitFor(t, srv, approval)
	if wait.Code != ApprovalWaitNodeOffline {
		t.Fatalf("code = %q, want %q", wait.Code, ApprovalWaitNodeOffline)
	}
	if wait.TaskID != "task-6" || wait.TaskStatus != model.TaskQueued {
		t.Fatalf("task evidence lost: %+v", wait)
	}
	if wait.Dismissible {
		t.Fatal("an approval that already queued work must not be retired behind that work")
	}
}

func TestApprovalWaitFailedTaskOutranksNodeState(t *testing.T) {
	srv, st := newWaitingTestServer(t)
	if err := st.UpsertNode(model.Node{ID: "node-7", Name: "edge-7", LastSeen: time.Now().UTC().Add(-48 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	approval := approvedTestApproval("approval-7", "node-7", agentUpdatePlugin, agentUpdateAction, time.Now().UTC())
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTask(model.Task{ID: "task-7", ApprovalID: approval.ID, Targets: []string{"node-7"}, Interpreter: "sh", Script: "true", Status: model.TaskFailed, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	wait := waitFor(t, srv, approval)
	if wait.Code != ApprovalWaitTaskFailed {
		t.Fatalf("code = %q, want %q", wait.Code, ApprovalWaitTaskFailed)
	}
	if !strings.Contains(wait.Reason, "task-7") {
		t.Fatalf("reason does not name the task: %q", wait.Reason)
	}
}

func TestApprovalWaitSupersededByNewerPlan(t *testing.T) {
	srv, st := newWaitingTestServer(t)
	if err := st.UpsertNode(model.Node{ID: "node-8", Name: "edge-8", Online: true, LastSeen: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	older := approvedTestApproval("approval-old", "node-8", agentUpdatePlugin, agentUpdateAction+":0.3.6", time.Now().UTC().Add(-2*time.Hour))
	newer := approvedTestApproval("approval-new", "node-8", agentUpdatePlugin, agentUpdateAction+":0.3.9", time.Now().UTC())
	newer.Status = model.ApprovalPending
	for _, a := range []model.Approval{older, newer} {
		if err := st.UpsertApproval(a); err != nil {
			t.Fatal(err)
		}
	}
	wait := waitFor(t, srv, older)
	if wait.Code != ApprovalWaitPlanSuperseded {
		t.Fatalf("code = %q, want %q", wait.Code, ApprovalWaitPlanSuperseded)
	}
	if wait.SupersededBy != "approval-new" {
		t.Fatalf("superseded_by = %q, want approval-new", wait.SupersededBy)
	}
}

// A rejected successor retires nothing, so the older approval must keep its
// own reason instead of being declared replaced.
func TestApprovalWaitRejectedSuccessorDoesNotSupersede(t *testing.T) {
	srv, st := newWaitingTestServer(t)
	if err := st.UpsertNode(model.Node{ID: "node-9", Name: "edge-9", Online: true, LastSeen: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	older := approvedTestApproval("approval-keep", "node-9", agentUpdatePlugin, agentUpdateAction, time.Now().UTC().Add(-2*time.Hour))
	rejected := approvedTestApproval("approval-dead", "node-9", agentUpdatePlugin, agentUpdateAction, time.Now().UTC())
	rejected.Status = model.ApprovalRejected
	for _, a := range []model.Approval{older, rejected} {
		if err := st.UpsertApproval(a); err != nil {
			t.Fatal(err)
		}
	}
	wait := waitFor(t, srv, older)
	if wait.Code == ApprovalWaitPlanSuperseded {
		t.Fatalf("a rejected successor must not supersede: %+v", wait)
	}
	if wait.Code != ApprovalWaitNotQueued {
		t.Fatalf("code = %q, want %q", wait.Code, ApprovalWaitNotQueued)
	}
}

func TestApprovalWaitMissingNode(t *testing.T) {
	srv, st := newWaitingTestServer(t)
	approval := approvedTestApproval("approval-10", "node-gone", agentUpdatePlugin, agentUpdateAction, time.Now().UTC())
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	wait := waitFor(t, srv, approval)
	if wait.Code != ApprovalWaitNodeUnknown {
		t.Fatalf("code = %q, want %q", wait.Code, ApprovalWaitNodeUnknown)
	}
	if !strings.Contains(wait.Reason, "node-gone") {
		t.Fatalf("reason does not name the missing node: %q", wait.Reason)
	}
}

func TestApprovalWaitTaskExecutionDisabled(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, TaskExecutionDisabled: true, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNode(model.Node{ID: "node-11", Name: "edge-11", Online: true, LastSeen: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	approval := approvedTestApproval("approval-11", "node-11", agentUpdatePlugin, agentUpdateAction, time.Now().UTC())
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	wait := waitFor(t, srv, approval)
	if wait.Code != ApprovalWaitTaskExecutionDisabled {
		t.Fatalf("code = %q, want %q", wait.Code, ApprovalWaitTaskExecutionDisabled)
	}
}

// Only approved approvals carry the field, and a listing with none of them
// never builds the index.
func TestApprovalWaitOnlyForApproved(t *testing.T) {
	srv, st := newWaitingTestServer(t)
	if err := st.UpsertNode(model.Node{ID: "node-12", Name: "edge-12", Online: true, LastSeen: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{model.ApprovalPending, model.ApprovalApplied, model.ApprovalRejected} {
		approval := approvedTestApproval("approval-"+status, "node-12", agentUpdatePlugin, agentUpdateAction, time.Now().UTC())
		approval.Status = status
		if err := st.UpsertApproval(approval); err != nil {
			t.Fatal(err)
		}
	}
	approvals := srv.store.Approvals()
	if ctx := srv.newApprovalWaitContext(approvals); ctx != nil {
		t.Fatal("a listing with no approved approval must not build the index")
	}
	views := srv.annotateApprovalWaiting(toApprovalViews(approvals), approvals)
	for _, view := range views {
		if view.Waiting != nil {
			t.Fatalf("%s (%s) carries an explanation it should not", view.ID, view.Status)
		}
	}
}

func TestAnnotateApprovalWaitingAlignsWithViews(t *testing.T) {
	srv, st := newWaitingTestServer(t)
	if err := st.UpsertNode(model.Node{ID: "node-13", Name: "edge-13", LastSeen: time.Now().UTC().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	approved := approvedTestApproval("approval-13", "node-13", agentUpdatePlugin, agentUpdateAction, time.Now().UTC())
	pending := approvedTestApproval("approval-14", "node-13", "nft", "apply-ruleset", time.Now().UTC())
	pending.Status = model.ApprovalPending
	for _, a := range []model.Approval{approved, pending} {
		if err := st.UpsertApproval(a); err != nil {
			t.Fatal(err)
		}
	}
	ordered := []model.Approval{approved, pending}
	views := srv.annotateApprovalWaiting(toApprovalViews(ordered), ordered)
	if views[0].Waiting == nil || views[0].Waiting.Code != ApprovalWaitNodeOffline {
		t.Fatalf("approved view lost its explanation: %+v", views[0].Waiting)
	}
	if views[1].Waiting != nil {
		t.Fatal("a pending approval explains itself and must not carry a waiting reason")
	}
}

// End to end: the one item that never clears. It is listed with the sentence
// that explains it, and the exit the sentence offers is one the server takes.
func TestApprovedApprovalOnOfflineNodeIsExplainedAndDismissible(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	cookies, csrf := loginSession(t, handler)

	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.2.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    agentUpdateTestSHA, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	approval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "auto", time.Now().UTC().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	approval.Status = model.ApprovalApproved
	approval.ApprovedBy = "admin"
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	// The node goes quiet after the decision, which is the shape of the case.
	lastSeen := time.Now().UTC().Add(-96 * time.Hour)
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "[OpenJobs-Data]-tmp", AgentVersion: "0.1.0", LastSeen: lastSeen}); err != nil {
		t.Fatal(err)
	}

	list := doJSON(t, handler, http.MethodGet, "/api/network/approvals", "", cookies, csrf)
	defer list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list approvals failed: %d", list.StatusCode)
	}
	var views []approvalView
	if err := json.NewDecoder(list.Body).Decode(&views); err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 {
		t.Fatalf("expected one approval, got %+v", views)
	}
	wait := views[0].Waiting
	if wait == nil {
		t.Fatal("an approved approval must carry the reason it has not applied")
	}
	if wait.Code != ApprovalWaitNodeOffline || !wait.Blocked {
		t.Fatalf("unexpected explanation: %+v", wait)
	}
	if !strings.Contains(wait.Reason, "[OpenJobs-Data]-tmp") {
		t.Fatalf("reason does not name the machine: %q", wait.Reason)
	}
	if !wait.Dismissible {
		t.Fatal("the console is told this can be dismissed; the server must honour that")
	}

	dismiss := doJSON(t, handler, http.MethodPost, "/api/network/approvals/dismiss",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "note": "node retired."})), cookies, csrf)
	defer dismiss.Body.Close()
	if dismiss.StatusCode != http.StatusOK {
		t.Fatalf("dismissing a blocked approved approval should succeed, got %d", dismiss.StatusCode)
	}
	stored, ok := st.Approval(approval.ID)
	if !ok || stored.Status != approvalStatusDismissed {
		t.Fatalf("dismissal should persist: ok=%v approval=%+v", ok, stored)
	}
	if !strings.Contains(stored.Reason, "offline") || !strings.Contains(stored.Reason, "node retired.") {
		t.Fatalf("the tombstone must record why and the operator's note, got %q", stored.Reason)
	}
}

// A healthy node with a queued apply is not a dead end, and dismissing it
// would hide work that is about to run.
func TestQueuedApprovalIsNotDismissible(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	cookies, csrf := loginSession(t, handler)

	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.2.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    agentUpdateTestSHA, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	approval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "auto", time.Now().UTC().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	approval.Status = model.ApprovalApproved
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTask(model.Task{
		ID: "task-live", ApprovalID: approval.ID, Targets: []string{"node-a"},
		Interpreter: "sh", Script: "true", Status: model.TaskQueued, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	dismiss := doJSON(t, handler, http.MethodPost, "/api/network/approvals/dismiss",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID})), cookies, csrf)
	defer dismiss.Body.Close()
	if dismiss.StatusCode == http.StatusOK {
		t.Fatal("an approval with a live apply task must not be dismissible")
	}
}

// awaitingUpdateApproval is an agent update whose apply task finished and
// whose approval is waiting for the node to report the target version. The
// plan is the real one, so the target can be read back out of it.
func awaitingUpdateApproval(t *testing.T, srv *Server, st *store.Store, nodeID string, updatedAt time.Time) model.Approval {
	t.Helper()
	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: nodeID, Enabled: true, TargetVersion: "0.2.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    agentUpdateTestSHA, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	approval, err := srv.createAgentUpdateApproval(context.Background(), nodeID, "operator", false, "manual", updatedAt.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	approval.Status = model.ApprovalApproved
	approval.Reason = agentUpdateAwaitingConfirmationReason("0.2.0")
	approval.UpdatedAt = updatedAt
	if _, _, err := st.MutateApproval(approval.ID, func(a *model.Approval) bool { *a = approval; return true }); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTask(model.Task{ID: "task-" + nodeID, ApprovalID: approval.ID, Targets: []string{nodeID}, Interpreter: "sh", Script: "true", Status: model.TaskFinished, CreatedAt: updatedAt.Add(-30 * time.Second), FinishedAt: updatedAt}); err != nil {
		t.Fatal(err)
	}
	stored, ok := st.Approval(approval.ID)
	if !ok {
		t.Fatal("approval vanished")
	}
	return stored
}

// The window the operator saw as "approved and stuck": the apply task has
// finished, the node is restarting onto the new binary, and its report has
// not arrived yet. Nothing is wrong and the console must not say it is.
func TestApprovalWaitAgentUpdateAwaitingConfirmationIsNotBlocked(t *testing.T) {
	srv, st := newWaitingTestServer(t)
	now := time.Now().UTC()
	if err := st.UpsertNode(model.Node{ID: "node-u1", Name: "edge-u1", AgentVersion: "0.1.0", Online: true, LastSeen: now.Add(-5 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	approval := awaitingUpdateApproval(t, srv, st, "node-u1", now.Add(-10*time.Second))
	wait := waitFor(t, srv, approval)
	if wait.Code != ApprovalWaitAwaitingConfirmation {
		t.Fatalf("code = %q, want %q (reason %q)", wait.Code, ApprovalWaitAwaitingConfirmation, wait.Reason)
	}
	if wait.Blocked {
		t.Fatal("an update waiting for the node's version report is proceeding, not stuck")
	}
	if !strings.Contains(wait.Reason, "0.2.0") || !strings.Contains(wait.Reason, "task-node-u1") {
		t.Fatalf("reason should name the task and the version awaited: %q", wait.Reason)
	}
	if wait.Dismissible {
		t.Fatal("an update about to confirm must not offer dismissal")
	}
}

// The old agent may report once more in the 3 s before its restart. That is
// not evidence the restart failed.
func TestApprovalWaitAgentUpdateToleratesOneLateOldVersionReport(t *testing.T) {
	srv, st := newWaitingTestServer(t)
	now := time.Now().UTC()
	if err := st.UpsertNode(model.Node{ID: "node-u2", Name: "edge-u2", AgentVersion: "0.1.0", Online: true, LastSeen: now.Add(-8 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	approval := awaitingUpdateApproval(t, srv, st, "node-u2", now.Add(-10*time.Second))
	wait := waitFor(t, srv, approval)
	if wait.Code != ApprovalWaitAwaitingConfirmation || wait.Blocked {
		t.Fatalf("a report inside the restart grace is still awaiting: %+v", wait)
	}
}

// Past the grace the node is still reporting and still on the old version:
// the restart did not bring up the new agent, and that is a real block.
func TestApprovalWaitAgentUpdateVersionMismatchIsBlocked(t *testing.T) {
	srv, st := newWaitingTestServer(t)
	now := time.Now().UTC()
	if err := st.UpsertNode(model.Node{ID: "node-u3", Name: "edge-u3", AgentVersion: "0.1.0", Online: true, LastSeen: now.Add(-10 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	approval := awaitingUpdateApproval(t, srv, st, "node-u3", now.Add(-10*time.Minute))
	wait := waitFor(t, srv, approval)
	if wait.Code != ApprovalWaitVersionMismatch {
		t.Fatalf("code = %q, want %q (reason %q)", wait.Code, ApprovalWaitVersionMismatch, wait.Reason)
	}
	if !wait.Blocked {
		t.Fatal("a node that keeps reporting the old version after the restart window is stuck")
	}
	if !strings.Contains(wait.Reason, "0.1.0") || !strings.Contains(wait.Reason, "0.2.0") {
		t.Fatalf("reason should name both versions: %q", wait.Reason)
	}
}

// A node that went silent after the task is not "awaiting"; the existing
// precedence keeps its honest answer.
func TestApprovalWaitAgentUpdateAwaitingOnOfflineNodeFallsThrough(t *testing.T) {
	srv, st := newWaitingTestServer(t)
	now := time.Now().UTC()
	if err := st.UpsertNode(model.Node{ID: "node-u4", Name: "edge-u4", AgentVersion: "0.1.0", LastSeen: now.Add(-48 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	approval := awaitingUpdateApproval(t, srv, st, "node-u4", now.Add(-47*time.Hour))
	wait := waitFor(t, srv, approval)
	if wait.Code != ApprovalWaitTaskFinished || !wait.Blocked {
		t.Fatalf("offline node after a finished task keeps the task_finished answer: %+v", wait)
	}
}
