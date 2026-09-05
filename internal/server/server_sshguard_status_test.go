package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/sshguard"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// keyOnlySSHD is what the fleet's eighteen target nodes report: passwords
// off, root by key only, pubkey on.
func keyOnlySSHD(at time.Time) *model.GuardSSHDFacts {
	return &model.GuardSSHDFacts{
		PasswordAuthentication: false, PubkeyAuthentication: true,
		PermitRootLogin: "without-password", Ports: []int{22}, ObservedAt: at,
	}
}

func seedSSHGuardReality(t *testing.T, st *store.Store, nodeID string, sshd *model.GuardSSHDFacts, foreign []string, collectedAt time.Time) {
	t.Helper()
	if _, _, err := st.UpsertGuardRealitySnapshot("", store.GuardRealitySnapshot{
		Reality: model.GuardNodeReality{
			NodeID:        nodeID,
			Listeners:     []model.GuardListener{{Protocol: "tcp", Port: 22, Process: "sshd"}},
			ForeignTables: foreign,
			SSHD:          sshd,
			CollectedAt:   collectedAt,
		},
		ReceivedAt: collectedAt,
	}); err != nil {
		t.Fatalf("seed reality: %v", err)
	}
}

// seedHardeningArm stores a hardening-only arm (no firewall, no knock) whose
// plan is rendered by the real renderer with the observed-key flag the
// server would have set.
func seedHardeningArm(t *testing.T, st *store.Store, a model.Approval, keyObserved bool) {
	t.Helper()
	profile := sshguard.Profile{
		NodeID: a.NodeID, KeepLegacyPort: true, Hardening: sshguard.DefaultHardening(),
		KeyAccessObserved: keyObserved, ConfirmWindowSec: 900,
	}
	plan, err := sshguard.RenderArmPlan(profile, "Node A")
	if err != nil {
		t.Fatal(err)
	}
	a.Plugin, a.Action, a.Plan = sshGuardPlugin, sshGuardArmAction, plan
	if a.ActorID == "" {
		a.ActorID = "admin"
	}
	if err := st.UpsertApproval(a); err != nil {
		t.Fatal(err)
	}
}

func sshGuardStatusRow(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, nodeID string) map[string]any {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/sshguard/status", `{"node_id":"`+nodeID+`"}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("status: want 200, got %d (%s)", res.StatusCode, raw)
	}
	out := knockBody(t, res)
	row, _ := out["node"].(map[string]any)
	if row == nil {
		t.Fatalf("status carries no node row: %v", out)
	}
	return row
}

// sshGuardStatusRowAt reads the row through the derivation with an injected
// clock. The store stamps UpdatedAt on every write, so an "applied two hours
// ago" fixture cannot be seeded; moving the clock forward instead is the
// same test. The row goes through JSON so the assertions use wire names.
func sshGuardStatusRowAt(t *testing.T, srv *Server, nodeID string, now time.Time) map[string]any {
	t.Helper()
	raw, err := json.Marshal(srv.sshGuardNodeStatusFor(nodeID, now))
	if err != nil {
		t.Fatal(err)
	}
	var row map[string]any
	if err := json.Unmarshal(raw, &row); err != nil {
		t.Fatal(err)
	}
	return row
}

func postureOf(row map[string]any) map[string]any {
	p, _ := row["posture"].(map[string]any)
	return p
}

// The row is coloured by the node, not by the approval. A key-only node
// whose last arm reverted, and one whose last arm was rejected, both read
// secured, with the arm outcome carried as history.
func TestSSHGuardStatusPostureIsTheNodesNotTheApprovals(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	now := time.Now().UTC()
	seedSSHGuardReality(t, st, "node-a", keyOnlySSHD(now), nil, now)
	cookies, csrf := loginSession(t, handler)

	// Applied with a 900s window and never confirmed; two hours later the
	// timer has fired.
	seedHardeningArm(t, st, model.Approval{
		ID: "arm_reverted", NodeID: "node-a", Status: model.ApprovalApplied,
		CreatedAt: now.Add(-2 * time.Hour),
	}, false)
	row := sshGuardStatusRowAt(t, srv, "node-a", now.Add(2*time.Hour))
	if postureOf(row)["state"] != string(sshguard.PostureSecured) {
		t.Fatalf("a key-only node is secured whatever the approvals say: %v", row["posture"])
	}
	if row["stage"] != string(sshGuardStageReverted) {
		t.Fatalf("the history is still told: want reverted, got %v", row["stage"])
	}
	if row["stage_is_history"] != true {
		t.Fatal("on a secured node a reverted arm is history, not the row's state")
	}
	if row["revert_armed"] != false || row["revert_deadline"] != nil {
		t.Fatalf("past the window nothing is armed: %v %v", row["revert_armed"], row["revert_deadline"])
	}
	lastArm, _ := row["last_arm"].(map[string]any)
	if lastArm["outcome"] != "applied" || lastArm["approval_id"] != "arm_reverted" {
		t.Fatalf("last_arm must name the record: %v", lastArm)
	}
	if row["knock_gate"] != false {
		t.Fatal("no lattice_knock table in the report means no gate")
	}

	// A newer arm the operator rejected.
	seedHardeningArm(t, st, model.Approval{
		ID: "arm_rejected", NodeID: "node-a", Status: model.ApprovalRejected, Reason: "not today",
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour),
	}, false)
	row = sshGuardStatusRow(t, handler, cookies, csrf, "node-a")
	if row["stage"] != string(sshGuardStageArmFailed) || row["stage_is_history"] != true {
		t.Fatalf("a rejected arm on a secured node is history: stage=%v history=%v", row["stage"], row["stage_is_history"])
	}
	if postureOf(row)["state"] != string(sshguard.PostureSecured) {
		t.Fatalf("posture must not move with the approval: %v", row["posture"])
	}
	lastArm, _ = row["last_arm"].(map[string]any)
	if lastArm["outcome"] != "rejected" || lastArm["reason"] != "not today" {
		t.Fatalf("the rejection is reported as history with its reason: %v", lastArm)
	}
}

// The other two postures, and the fact that neither demotes a failed arm to
// history: a node that accepts passwords needs attention, and a node that
// has said nothing gets no claim.
func TestSSHGuardStatusPasswordOpenAndUnknown(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	cookies, csrf := loginSession(t, handler)
	now := time.Now().UTC()
	seedHardeningArm(t, st, model.Approval{
		ID: "arm_rejected", NodeID: "node-a", Status: model.ApprovalRejected,
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour),
	}, false)

	row := sshGuardStatusRow(t, handler, cookies, csrf, "node-a")
	if postureOf(row)["state"] != string(sshguard.PostureUnknown) {
		t.Fatalf("no report means unknown, got %v", row["posture"])
	}
	if row["stage_is_history"] != false {
		t.Fatal("a failed arm is only history once the node is known to be secured")
	}
	if row["sshd"] != nil {
		t.Fatal("no facts, no sshd block")
	}

	seedSSHGuardReality(t, st, "node-a", &model.GuardSSHDFacts{
		PasswordAuthentication: true, PubkeyAuthentication: true, PermitRootLogin: "yes", Ports: []int{22}, ObservedAt: now,
	}, nil, now)
	row = sshGuardStatusRow(t, handler, cookies, csrf, "node-a")
	if postureOf(row)["state"] != string(sshguard.PosturePasswordOpen) {
		t.Fatalf("passwords on is password_open, got %v", row["posture"])
	}
	if row["stage_is_history"] != false {
		t.Fatal("on an open node the failed arm is the row's state")
	}
	sshd, _ := row["sshd"].(map[string]any)
	if sshd["password_authentication"] != true || sshd["permit_root_login"] != "yes" {
		t.Fatalf("the evidence behind the verdict travels with it: %v", sshd)
	}
}

// A node whose report lists the knock table has a gate, and the reveal must
// be offered for it even when the arm that installed the gate was never
// confirmed and its window has long closed: the report says the gate is
// there, so the timer did not take it.
func TestSSHGuardStatusKnockGateComesFromRealityAndStaysRevealable(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	now := time.Now().UTC()
	seedArmApproval(t, st, "arm_knock", "node-a", model.ApprovalApplied, knockTestPorts, now)
	// The report is collected after the window closed and still lists the
	// table.
	seedSSHGuardReality(t, st, "node-a", keyOnlySSHD(now), []string{"inet lattice_guard", "inet lattice_knock"}, now.Add(2*time.Hour))
	cookies, csrf := loginSession(t, handler)

	row := sshGuardStatusRowAt(t, srv, "node-a", now.Add(3*time.Hour))
	if row["knock_gate"] != true {
		t.Fatalf("the report lists inet lattice_knock: %v", row)
	}
	if row["stage"] != string(sshGuardStageInForce) {
		t.Fatalf("a gate the node still shows after the window is in force, not reverted: %v", row["stage"])
	}
	if row["stage_is_history"] != false {
		t.Fatal("in_force is the row's state")
	}
	knock, _ := row["knock"].(map[string]any)
	if knock["revealable"] != true || knock["requires_step_up"] != true {
		t.Fatalf("the sequence is known and must be offered behind the step-up: %v", knock)
	}
	if note, _ := knock["note"].(string); !strings.Contains(note, "table in place") {
		t.Fatalf("the note must say the node shows the gate rather than that the timer may have removed it: %q", note)
	}
	for _, port := range knockTestPorts {
		raw, _ := json.Marshal(row)
		if strings.Contains(string(raw), strconv.Itoa(port)) {
			t.Fatalf("the status row leaked knock port %d", port)
		}
	}

	// The knock state endpoint says the same, and the reveal still works.
	state := doJSON(t, handler, http.MethodPost, "/api/sshguard/knock", `{"node_id":"node-a"}`, cookies, csrf)
	stateOut := knockBody(t, state)
	state.Body.Close()
	if stateOut["gate_present"] != true {
		t.Fatalf("knock state must carry the node's own word on the gate: %v", stateOut)
	}
	grant := issueStepUpGrant(t, handler, cookies, csrf)
	reveal := doJSON(t, handler, http.MethodPost, "/api/sshguard/knock/reveal",
		`{"node_id":"node-a","step_up_grant":"`+grant+`"}`, cookies, csrf)
	defer reveal.Body.Close()
	if reveal.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(reveal.Body)
		t.Fatalf("reveal: want 200, got %d (%s)", reveal.StatusCode, raw)
	}
	revealOut := knockBody(t, reveal)
	if ports, _ := revealOut["ports"].([]any); len(ports) != len(knockTestPorts) {
		t.Fatalf("reveal must hand over the sequence: %v", revealOut["ports"])
	}
	if revealOut["gate_present"] != true {
		t.Fatal("the reveal carries the gate evidence too")
	}
}

// A gated node whose report was collected after the window closed and no
// longer lists the table did revert. The clock alone is not the verdict; the
// report is.
func TestSSHGuardStatusRevertedWhenTheGateIsGone(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	now := time.Now().UTC()
	seedArmApproval(t, st, "arm_knock", "node-a", model.ApprovalApplied, knockTestPorts, now)
	seedSSHGuardReality(t, st, "node-a", keyOnlySSHD(now), []string{"inet lattice_guard"}, now.Add(2*time.Hour))
	row := sshGuardStatusRowAt(t, srv, "node-a", now.Add(3*time.Hour))
	if row["knock_gate"] != false || row["stage"] != string(sshGuardStageReverted) {
		t.Fatalf("no table after the window means reverted: gate=%v stage=%v", row["knock_gate"], row["stage"])
	}
	if row["stage_is_history"] != true {
		t.Fatal("the node is key-only, so the reverted gate is history")
	}
}

// Inside the window the stage is the live countdown, whatever the posture.
func TestSSHGuardStatusCountsDownInsideTheWindow(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	now := time.Now().UTC()
	seedArmApproval(t, st, "arm_knock", "node-a", model.ApprovalApplied, knockTestPorts, now.Add(-time.Minute))
	seedSSHGuardReality(t, st, "node-a", keyOnlySSHD(now), []string{"inet lattice_knock"}, now)
	cookies, csrf := loginSession(t, handler)
	row := sshGuardStatusRow(t, handler, cookies, csrf, "node-a")
	if row["stage"] != string(sshGuardStageAwaitingConfirm) || row["revert_armed"] != true || row["revert_deadline"] == nil {
		t.Fatalf("a fresh unconfirmed firewall arm is awaiting confirm with a deadline: %v", row)
	}
	if row["stage_is_history"] != false {
		t.Fatal("a running timer is never history")
	}
}

// Planning a hardening-only profile for a node that already shows a key
// produces a durable plan: no timer, no confirm. Applying it lands the node
// in "hardened", and a confirm request for it is refused with the reason.
func TestSSHGuardHardeningOnlyPlanIsDurableOnAKeyOnlyNode(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	now := time.Now().UTC()
	seedSSHGuardReality(t, st, "node-a", keyOnlySSHD(now), nil, now)
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"network:plan", "sshguard:admin"}, []string{"node-a"})

	res := doBearerJSON(t, handler, http.MethodPost, "/api/sshguard/plan",
		`{"node_id":"node-a","enable_knock":false}`, token)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("plan: want 200, got %d (%s)", res.StatusCode, raw)
	}
	var out struct {
		Approval model.Approval `json:"approval"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	art, err := sshguard.ParseApprovalPlan(out.Approval.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if !art.Durable || art.KnockNFT != "" {
		t.Fatalf("hardening only on a key-only node must be durable and install no firewall: durable=%v nft=%q", art.Durable, art.KnockNFT)
	}
	script := srv.applyScriptFor(out.Approval)
	if !strings.Contains(script, "sshguard_key_found") {
		t.Fatal("the apply must ask the host about the key before skipping the timer")
	}

	// Apply it, then the row and the confirm gate.
	task := model.Task{ID: id.New("task"), ApprovalID: out.Approval.ID, Targets: []string{"node-a"}}
	if err := srv.handleSSHGuardTaskResult(httptest.NewRequest(http.MethodPost, "/api/agent/task-results", nil), out.Approval, task,
		model.TaskResult{ExitCode: 0, Stdout: "lattice sshguard: authorized key present and no firewall in this plan; the change is durable, no revert timer armed\n"}); err != nil {
		t.Fatal(err)
	}
	row := sshGuardStatusRow(t, handler, cookies, csrf, "node-a")
	if row["stage"] != string(sshGuardStageHardened) || row["revert_armed"] != false || row["revert_deadline"] != nil {
		t.Fatalf("a durable arm that applied is hardened, with nothing counting down: %v", row)
	}
	if lastArm, _ := row["last_arm"].(map[string]any); lastArm["durable"] != true {
		t.Fatalf("last_arm must say the arm was durable: %v", lastArm)
	}
	confirm := doBearerJSON(t, handler, http.MethodPost, "/api/sshguard/confirm", `{"node_id":"node-a"}`, token)
	defer confirm.Body.Close()
	raw, _ := io.ReadAll(confirm.Body)
	if confirm.StatusCode != http.StatusConflict || !strings.Contains(string(raw), "durable") {
		t.Fatalf("confirming a durable arm must be refused with the reason: %d %s", confirm.StatusCode, raw)
	}
}

// The same request for a node that has not shown a key keeps the timer, and
// a knock request keeps it whatever the node shows.
func TestSSHGuardPlanKeepsTheTimerWithoutAKeyOrWithAFirewall(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"network:plan", "sshguard:admin"}, []string{"node-a"})

	plan := func(body string) sshguard.Artifacts {
		t.Helper()
		res := doBearerJSON(t, handler, http.MethodPost, "/api/sshguard/plan", body, token)
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(res.Body)
			t.Fatalf("plan: want 200, got %d (%s)", res.StatusCode, raw)
		}
		var out struct {
			Approval model.Approval `json:"approval"`
		}
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		art, err := sshguard.ParseApprovalPlan(out.Approval.Plan)
		if err != nil {
			t.Fatal(err)
		}
		return art
	}
	if art := plan(`{"node_id":"node-a","enable_knock":false}`); art.Durable {
		t.Fatal("no report, no key evidence, no durable arm")
	}
	now := time.Now().UTC()
	seedSSHGuardReality(t, st, "node-a", keyOnlySSHD(now), nil, now)
	if art := plan(sshGuardPlanBody("node-a", nil)); art.Durable || art.KnockNFT == "" {
		t.Fatal("a knock plan installs the gate and keeps the confirm-or-revert dance, key or no key")
	}
	if art := plan(sshGuardPlanBody("node-a", map[string]any{"enable_knock": false})); art.Durable || art.KnockNFT == "" {
		t.Fatal("a management-source gate is a firewall too, and is never durable")
	}
	// A port migration with no firewall on the same key-only node. The key
	// proves nothing about the new port being reachable from outside, and
	// with 22 dropped a wrong guess has no way back but the timer.
	if art := plan(`{"node_id":"node-a","ssh_port":2222,"keep_legacy_port":false,"enable_knock":false}`); art.Durable || art.KnockNFT != "" || art.SSHPort != 2222 {
		t.Fatalf("a port migration keeps the timer even on a key-only node: durable=%v nft=%q port=%d", art.Durable, art.KnockNFT, art.SSHPort)
	}
	if art := plan(`{"node_id":"node-a","ssh_port":2222,"keep_legacy_port":true,"enable_knock":false}`); art.Durable || art.KnockNFT != "" {
		t.Fatalf("adding a port is still a port change and keeps the timer: durable=%v nft=%q", art.Durable, art.KnockNFT)
	}
}

// When the host disagreed with the plan about the key, the script armed the
// timer and said so. The result handler has to keep that, or the view
// reports a permanent change on a node that is counting down.
func TestSSHGuardDurableArmThatFellBackToTheTimerIsNotHardened(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	now := time.Now().UTC()
	seedSSHGuardReality(t, st, "node-a", keyOnlySSHD(now), nil, now)
	cookies, csrf := loginSession(t, handler)
	approval := model.Approval{ID: "arm_durable", NodeID: "node-a", Status: model.ApprovalApproved, CreatedAt: now, UpdatedAt: now}
	seedHardeningArm(t, st, approval, true)
	approval, _ = st.Approval(approval.ID)
	task := model.Task{ID: id.New("task"), ApprovalID: approval.ID, Targets: []string{"node-a"}}
	if err := srv.handleSSHGuardTaskResult(httptest.NewRequest(http.MethodPost, "/api/agent/task-results", nil), approval, task,
		model.TaskResult{ExitCode: 0, Stderr: sshguard.TimerArmedAfterAllLine + "\n", Stdout: "lattice sshguard: automatic revert armed\n"}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Approval(approval.ID)
	if got.Status != model.ApprovalApplied || got.Reason != sshGuardTimerArmedMark {
		t.Fatalf("the arm applied and the record must say the timer is running: status=%q reason=%q", got.Status, got.Reason)
	}
	row := sshGuardStatusRow(t, handler, cookies, csrf, "node-a")
	if row["stage"] != string(sshGuardStageAwaitingConfirm) || row["revert_armed"] != true {
		t.Fatalf("a durable arm whose host armed the timer is awaiting confirm: %v", row)
	}
}

// The fleet shape: no node_id returns every node the principal may read, and
// a node outside the token's allowlist is not in it.
func TestSSHGuardStatusListsOnlyVisibleNodes(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	if err := st.UpsertNode(model.Node{ID: "node-b", Name: "Node B", Online: true, LastSeen: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"network:plan", "sshguard:read"}, []string{"node-a"})
	res := doBearerJSON(t, handler, http.MethodPost, "/api/sshguard/status", `{}`, token)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("status: want 200, got %d (%s)", res.StatusCode, raw)
	}
	out := knockBody(t, res)
	rows, _ := out["nodes"].([]any)
	if len(rows) != 1 {
		t.Fatalf("want only node-a, got %v", out["nodes"])
	}
	first, _ := rows[0].(map[string]any)
	if first["node_id"] != "node-a" || first["stage"] != string(sshGuardStageIdle) || postureOf(first)["state"] != string(sshguard.PostureUnknown) {
		t.Fatalf("an untouched, unreported node is idle and unknown: %v", first)
	}
}
