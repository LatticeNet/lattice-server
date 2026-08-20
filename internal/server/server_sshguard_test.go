package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/sshguard"
	"github.com/LatticeNet/lattice-server/internal/store"
)

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

// The whole document is the contract, so what comes back must parse into the
// artifacts the apply will write, and the apply must dispatch to this plugin
// rather than falling through to the generic nft branch.
func TestSSHGuardPlanProducesAnApplicableApproval(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
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
