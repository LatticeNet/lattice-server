package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/sshguard"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// enrolSSHGuard opts a node into SSH Guard, which planning now requires.
//
// Hardening decides who can reach a machine over SSH, so it is opt-in per node
// rather than available to whatever id a caller passes. Every plan test states
// that precondition explicitly instead of inheriting it from a shared fixture,
// because "this node is in scope" is exactly the thing the gate exists to make
// deliberate.
func enrolSSHGuard(t *testing.T, st interface {
	SetNodeCapability(store.NodeCapability) error
}, nodeID string) {
	t.Helper()
	if err := st.SetNodeCapability(store.NodeCapability{
		NodeID: nodeID, Capability: sshGuardPlugin, State: store.CapabilityEnrolled,
	}); err != nil {
		t.Fatal(err)
	}
}

func sshGuardPlanBody(nodeID string, extra map[string]any) string {
	body := map[string]any{
		"node_id":      nodeID,
		"ssh_port":     58394,
		"mgmt_sources": []string{"154.17.12.165"},
	}
	for k, v := range extra {
		body[k] = v
	}
	raw, _ := json.Marshal(body)
	return string(raw)
}

// Authoring an SSH Guard plan can take a node off the network for its
// operator, so it is gated on its own admin scope rather than on the generic
// planning scope.
func TestSSHGuardPlanRequiresItsOwnAdminScope(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	cookies, csrf := loginSession(t, handler)

	planOnly := createPAT(t, handler, cookies, csrf, []string{"network:plan"}, []string{"node-a"})
	denied := doBearerJSON(t, handler, http.MethodPost, "/api/sshguard/plan", sshGuardPlanBody("node-a", nil), planOnly)
	defer denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("network:plan alone must not author an SSH Guard plan, got %d", denied.StatusCode)
	}

	guardAdmin := createPAT(t, handler, cookies, csrf, []string{"network:plan", "sshguard:admin"}, []string{"node-a"})
	ok := doBearerJSON(t, handler, http.MethodPost, "/api/sshguard/plan", sshGuardPlanBody("node-a", nil), guardAdmin)
	defer ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("sshguard:admin must author a plan, got %d", ok.StatusCode)
	}
}

// The standing decision that NAT nodes get no SSH Guard until port forwarding
// exists lived in a note. Recorded as an exclusion, it has to refuse the plan
// with that reason, gate on or off; otherwise the console files the refusal
// under "arm failed" and the decision stays folklore.
func TestSSHGuardPlanRefusesAnExcludedNodeWithItsReason(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	if err := st.SetNodeCapability(store.NodeCapability{
		NodeID: "node-a", Capability: sshGuardPlugin, State: store.CapabilityExcluded,
		Reason: "NAT, port forwarding first",
	}); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/sshguard/plan", sshGuardPlanBody("node-a", nil), cookies, csrf)
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a plan on an excluded node must be refused, got %d (%s)", res.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "port forwarding first") {
		t.Fatalf("the refusal must carry the exclusion reason: %s", raw)
	}
}

// The whole document is the contract, so what comes back must parse into the
// artifacts the apply will write, and the apply must dispatch to this plugin
// rather than falling through to the generic nft branch.
func TestSSHGuardPlanProducesAnApplicableApproval(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"network:plan", "sshguard:admin"}, []string{"node-a"})

	resp := doBearerJSON(t, handler, http.MethodPost, "/api/sshguard/plan", sshGuardPlanBody("node-a", nil), token)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("plan failed: %d", resp.StatusCode)
	}
	var out struct {
		Approval model.Approval     `json:"approval"`
		Findings []sshguard.Finding `json:"findings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Approval.Plugin != sshGuardPlugin || out.Approval.Action != sshGuardArmAction {
		t.Fatalf("unexpected approval identity: %+v", out.Approval)
	}
	art, err := sshguard.ParseApprovalPlan(out.Approval.Plan)
	if err != nil {
		t.Fatalf("the returned plan must parse back into artifacts: %v", err)
	}
	if art.SSHPort != 58394 || !art.KeepLegacyPort {
		t.Fatalf("plan header did not carry the request: %+v", art)
	}
	if art.KnockdConf == "" {
		t.Fatal("an ssh_port request enables knocking by default")
	}

	script := srv.applyScriptFor(out.Approval)
	if !strings.Contains(script, "lattice sshguard:") {
		t.Fatalf("apply did not dispatch to the sshguard renderer:\n%s", firstLines(script, 5))
	}
	if strings.Contains(script, "/tmp/lattice-nft-plan.nft") {
		t.Fatal("apply fell through to the generic nft branch, which would only syntax-check the plan and change nothing")
	}
	if !strings.Contains(script, "--on-active=") {
		t.Fatal("the arm script must schedule the automatic revert")
	}
}

// sshd -t does not catch a port that is already bound, because binding happens
// at reload rather than at parse. Catching it at plan time turns a failed apply
// into a refused plan, and the blocking finding is overridable only through an
// explicit flag that the audit trail records.
func TestSSHGuardPlanBlocksAPortThatIsAlreadyBound(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	if _, _, err := st.UpsertGuardRealitySnapshot("", store.GuardRealitySnapshot{
		Reality: model.GuardNodeReality{
			NodeID:      "node-a",
			Listeners:   []model.GuardListener{{Protocol: "tcp", Port: 58394, Process: "some-other-daemon"}},
			CollectedAt: time.Now().UTC(),
		},
		ReceivedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed reality: %v", err)
	}
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"network:plan", "sshguard:admin"}, []string{"node-a"})

	blocked := doBearerJSON(t, handler, http.MethodPost, "/api/sshguard/plan", sshGuardPlanBody("node-a", nil), token)
	defer blocked.Body.Close()
	if blocked.StatusCode != http.StatusConflict {
		t.Fatalf("a port already in use must block the plan, got %d", blocked.StatusCode)
	}

	accepted := doBearerJSON(t, handler, http.MethodPost, "/api/sshguard/plan",
		sshGuardPlanBody("node-a", map[string]any{"accept_findings": true}), token)
	defer accepted.Body.Close()
	if accepted.StatusCode != http.StatusOK {
		t.Fatalf("an explicit override must be allowed and recorded, got %d", accepted.StatusCode)
	}
}

// A profile that cannot be applied safely is refused at the door rather than
// producing an approval nobody should approve.
func TestSSHGuardPlanRefusesAProfileWithNoFallback(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"network:plan", "sshguard:admin"}, []string{"node-a"})

	body := sshGuardPlanBody("node-a", map[string]any{"mgmt_sources": []string{}})
	resp := doBearerJSON(t, handler, http.MethodPost, "/api/sshguard/plan", body, token)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a knock profile with no non-knock fallback must be refused, got %d", resp.StatusCode)
	}
}

// Deciding is gated the same way authoring is, end to end. Without this the
// scope on the plan endpoint is decoration: a bare network:apply holder could
// dispatch the change anyway.
func TestSSHGuardApprovalDecisionRequiresItsOwnAdminScope(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	cookies, csrf := loginSession(t, handler)

	plan, err := sshguard.RenderConfirmPlan("node-a", "Node A")
	if err != nil {
		t.Fatal(err)
	}
	approval := model.Approval{
		ID: "approval_sshguard_gate", NodeID: "node-a",
		Plugin: sshGuardPlugin, Action: sshGuardConfirmAction,
		Plan: plan, Status: model.ApprovalPending, ActorID: "admin",
	}
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	networkOnly := createPAT(t, handler, cookies, csrf, []string{"network:apply"}, []string{"node-a"})
	resp := doBearerJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{
			"approval_id": approval.ID, "queue_apply": false, "plan_sha256": planSHA256(approval.Plan),
		})), networkOnly)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("network-only must fail closed on an SSH Guard approval, got %d", resp.StatusCode)
	}
	if stored, ok := st.Approval(approval.ID); !ok || stored.Status != model.ApprovalPending {
		t.Fatalf("a refused decision must not mutate the approval: ok=%v %+v", ok, stored)
	}
}

// Two plans for the same node must not share a knock sequence. A sequence is a
// credential, and reusing one across the fleet would mean a single capture
// opens every node.
func TestKnockSequencesAreNotSharedBetweenPlans(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"network:plan", "sshguard:admin"}, []string{"node-a"})

	sequences := map[string]bool{}
	for i := 0; i < 3; i++ {
		resp := doBearerJSON(t, handler, http.MethodPost, "/api/sshguard/plan", sshGuardPlanBody("node-a", nil), token)
		var out struct {
			Approval model.Approval `json:"approval"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		art, err := sshguard.ParseApprovalPlan(out.Approval.Plan)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, line := range strings.Split(art.KnockdConf, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "sequence") {
				sequences[trimmed] = true
				found = true
			}
		}
		if !found {
			t.Fatal("the plan carries no knock sequence")
		}
	}
	if len(sequences) != 3 {
		t.Fatalf("expected three distinct sequences, got %d: %v", len(sequences), sequences)
	}
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// A knock profile may stand on the node's Lattice terminal instead of an
// address allowlist, and the claim is checked against the node rather than
// believed. An address allowlist goes stale silently; a terminal that is
// switched off is visible at plan time.
func TestKnockOnOutOfBandFallbackIsCheckedAgainstTheNode(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"network:plan", "sshguard:admin"}, []string{"node-a"})

	body := func() string {
		return sshGuardPlanBody("node-a", map[string]any{
			"mgmt_sources": []string{}, "out_of_band_fallback": true,
		})
	}

	// The seeded node is not online, so it cannot give a shell without SSH.
	// Gating it now would leave nothing but knocking.
	blocked := doBearerJSON(t, handler, http.MethodPost, "/api/sshguard/plan", body(), token)
	defer blocked.Body.Close()
	if blocked.StatusCode != http.StatusConflict {
		t.Fatalf("a fallback the node cannot provide must block, got %d", blocked.StatusCode)
	}
	var out struct {
		Findings []sshguard.Finding `json:"findings"`
	}
	_ = json.NewDecoder(blocked.Body).Decode(&out)
	found := false
	for _, f := range out.Findings {
		if f.Code == sshguard.FindingFallbackUnavailable {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected %s, got %+v", sshguard.FindingFallbackUnavailable, out.Findings)
	}

	// Bring the node online with the terminal reported and the same plan is fine.
	node, _ := st.Node("node-a")
	node.Online = true
	node.AgentLaunch = &model.AgentLaunchConfig{AllowTerminal: true}
	if err := st.UpsertNode(node); err != nil {
		t.Fatal(err)
	}
	ok := doBearerJSON(t, handler, http.MethodPost, "/api/sshguard/plan", body(), token)
	defer ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("a node that can give a shell without SSH must be plannable, got %d", ok.StatusCode)
	}
	if _, err := srv.store.Node("node-a"); err == false {
		t.Fatal("node vanished")
	}
}

// The knock sequence is a credential and it lives in the plan text, so reading
// the approval must require the domain the way authoring and deciding do.
// Without this, bare network:plan on the node was enough to read the secret.
func TestReadingAnSSHGuardPlanRequiresTheDomainScope(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	cookies, csrf := loginSession(t, handler)

	plan, err := sshguard.RenderArmPlan(sshguard.Profile{
		NodeID: "node-a", SSHPort: 58394, KeepLegacyPort: true,
		Hardening: sshguard.DefaultHardening(), MgmtSources: []string{"203.0.113.5"},
		Knock:            &sshguard.KnockPolicy{Ports: []int{23853, 36932, 24556}, SeqTimeoutSec: 15, OpenFor: "12h"},
		ConfirmWindowSec: 900,
	}, "Node A")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, "23853:udp") {
		t.Fatal("this test is only meaningful if the plan really carries the sequence")
	}
	if err := st.UpsertApproval(model.Approval{
		ID: "approval_sshguard_secret", NodeID: "node-a",
		Plugin: sshGuardPlugin, Action: sshGuardArmAction,
		Plan: plan, Status: model.ApprovalPending, ActorID: "admin",
	}); err != nil {
		t.Fatal(err)
	}

	planOnly := createPAT(t, handler, cookies, csrf, []string{"network:plan"}, []string{"node-a"})
	resp := doBearerJSON(t, handler, http.MethodGet, "/api/network/approvals", "", planOnly)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "23853") {
		t.Fatal("bare network:plan must not be able to read a node's knock sequence")
	}

	// The domain scope sees it, and sshguard:admin implies sshguard:read so an
	// operator who can author a plan can list the approval they just created.
	for _, scopes := range [][]string{
		{"network:plan", "sshguard:read"},
		{"network:plan", "sshguard:admin"},
	} {
		token := createPAT(t, handler, cookies, csrf, scopes, []string{"node-a"})
		ok := doBearerJSON(t, handler, http.MethodGet, "/api/network/approvals", "", token)
		raw, _ := io.ReadAll(ok.Body)
		ok.Body.Close()
		if !strings.Contains(string(raw), "23853") {
			t.Fatalf("%v must be able to read the plan it is entitled to", scopes)
		}
	}
}

// An arm may install knockd, which is an apt-get on the node's own uplink, and
// it waits for sshd to bind the new port before gating anything. The 30 second
// default cannot cover that.
func TestSSHGuardApplyGetsATimeoutThatCoversInstallingKnockd(t *testing.T) {
	got := approvalApplyTaskTimeoutSec(sshGuardPlugin)
	if got <= networkApplyTaskTimeoutSec {
		t.Fatalf("an apply that may run apt needs more than the network default, got %ds", got)
	}
	// The agent treats a timeout over ten minutes as out of range and falls
	// back to 30 seconds rather than clamping, so asking for more asks for less.
	if got > 600 {
		t.Fatalf("over ten minutes silently becomes 30 seconds on the agent, got %ds", got)
	}
}

// The approval has to advance when its apply task reports, and it did not.
// Sixty approvals across twenty-four nodes sat at `approved` a week after their
// tasks had finished, so the control plane could not say whether the hardening
// was live. `applied` on the arm is also what marks the revert timer as
// running, which is the one state on this capability with a deadline.
func TestSSHGuardApprovalAdvancesOnItsTaskResult(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result model.TaskResult
		want   string
	}{
		{"applied on success", model.TaskResult{ExitCode: 0}, model.ApprovalApplied},
		{"rejected on a non-zero exit", model.TaskResult{ExitCode: 1, Stderr: "nft: syntax error"}, model.ApprovalRejected},
		{"rejected when the agent reports an error", model.TaskResult{Error: "timed out"}, model.ApprovalRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, st := newInventoryServer(t)
			seedAgentUpdateNode(t, st)
			enrolSSHGuard(t, st, "node-a")
			approval := model.Approval{
				ID: id.New("approval"), NodeID: "node-a", Plugin: sshGuardPlugin,
				Action: sshGuardArmAction, Plan: "plugin: sshguard\n", Status: model.ApprovalApproved,
				CreatedAt: time.Now().UTC(),
			}
			if err := st.UpsertApproval(approval); err != nil {
				t.Fatal(err)
			}
			task := model.Task{ID: id.New("task"), ApprovalID: approval.ID, Targets: []string{"node-a"}}
			if err := srv.handleSSHGuardTaskResult(httptest.NewRequest(http.MethodPost, "/api/agent/task-results", nil), approval, task, tc.result); err != nil {
				t.Fatalf("result handling: %v", err)
			}
			got, ok := st.Approval(approval.ID)
			if !ok {
				t.Fatal("approval vanished")
			}
			if got.Status != tc.want {
				t.Fatalf("status = %q, want %q", got.Status, tc.want)
			}
			if tc.want == model.ApprovalRejected && got.Reason == "" {
				t.Fatal("a failed apply must say why, so the operator is not left guessing")
			}
		})
	}
}

// The confirm stage goes through the same path: its whole effect is cancelling
// the revert, and an approval stuck at `approved` cannot express that it did.
func TestSSHGuardConfirmApprovalAlsoAdvances(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	approval := model.Approval{
		ID: id.New("approval"), NodeID: "node-a", Plugin: sshGuardPlugin,
		Action: sshGuardConfirmAction, Plan: "plugin: sshguard\n", Status: model.ApprovalApproved,
		CreatedAt: time.Now().UTC(),
	}
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	task := model.Task{ID: id.New("task"), ApprovalID: approval.ID, Targets: []string{"node-a"}}
	if err := srv.handleSSHGuardTaskResult(httptest.NewRequest(http.MethodPost, "/api/agent/task-results", nil), approval, task, model.TaskResult{ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Approval(approval.ID)
	if got.Status != model.ApprovalApplied {
		t.Fatalf("confirm status = %q, want applied", got.Status)
	}
}

// An SSH Guard approval that was approved but never applied is a dead end:
// approve is idempotent so it dispatches nothing, and reject only acts on a
// pending approval. Sixty such records sat on this fleet looking like pending
// work with no way to clear them. Dismiss is that way, and it has to stay
// narrow enough that it cannot be used to skip a real decision.
func TestSSHGuardApprovalsCanBeRetiredOnlyWhenTheyAreADeadEnd(t *testing.T) {
	s := &Server{}
	base := model.Approval{Plugin: sshGuardPlugin, Action: sshGuardArmAction, NodeID: "n1"}

	for _, status := range []string{model.ApprovalPending, model.ApprovalRejected, model.ApprovalApplied} {
		a := base
		a.Status = status
		if _, ok := s.dismissibleSSHGuardApprovalReason(a, ""); ok {
			t.Fatalf("status %q must not be dismissible", status)
		}
	}

	a := base
	a.Status = model.ApprovalApproved
	reason, ok := s.dismissibleSSHGuardApprovalReason(a, "")
	if !ok {
		t.Fatal("an approved, never-applied approval must be dismissible")
	}
	if !strings.Contains(reason, "never applied") || !strings.Contains(reason, "arm") {
		t.Fatalf("the record must say what was retired and why: %q", reason)
	}

	confirm := base
	confirm.Action = sshGuardConfirmAction
	confirm.Status = model.ApprovalApproved
	reason, ok = s.dismissibleSSHGuardApprovalReason(confirm, "fleet re-armed under the new drop-in path")
	if !ok {
		t.Fatal("a confirm approval must be dismissible on the same terms")
	}
	if !strings.Contains(reason, "confirm") {
		t.Fatalf("the stage must be named: %q", reason)
	}
	if !strings.Contains(reason, "fleet re-armed under the new drop-in path") {
		t.Fatalf("the operator's note must survive into the record: %q", reason)
	}
}
