package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/sshguard"
)

var knockTestPorts = []int{23853, 36932, 24556}

// seedArmApproval stores an SSH Guard arm approval carrying a known sequence.
// The plan text is rendered by the real renderer rather than hand-written, so
// these tests fail if the document format moves under the reader.
func seedArmApproval(t *testing.T, st interface {
	UpsertApproval(model.Approval) error
}, id, nodeID, status string, ports []int, updatedAt time.Time) {
	t.Helper()
	profile := sshguard.Profile{
		NodeID: nodeID, SSHPort: 58394, KeepLegacyPort: true,
		Hardening: sshguard.DefaultHardening(), MgmtSources: []string{"203.0.113.5"},
		ConfirmWindowSec: 900,
	}
	if len(ports) > 0 {
		profile.Knock = &sshguard.KnockPolicy{Ports: ports, SeqTimeoutSec: 15, OpenFor: "12h"}
	}
	plan, err := sshguard.RenderArmPlan(profile, "Node A")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertApproval(model.Approval{
		ID: id, NodeID: nodeID, Plugin: sshGuardPlugin, Action: sshGuardArmAction,
		Plan: plan, Status: status, ActorID: "admin",
		CreatedAt: updatedAt, UpdatedAt: updatedAt,
	}); err != nil {
		t.Fatal(err)
	}
}

func knockBody(t *testing.T, res *http.Response) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// The reveal is the second check the operator asked for. Without a grant it
// must refuse, and with one it must produce the sequence that was applied.
func TestKnockRevealRequiresStepUp(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	seedArmApproval(t, st, "approval_arm", "node-a", model.ApprovalApplied, knockTestPorts, time.Now().UTC())
	cookies, csrf := loginSession(t, handler)

	denied := doJSON(t, handler, http.MethodPost, "/api/sshguard/knock/reveal", `{"node_id":"node-a"}`, cookies, csrf)
	body, _ := io.ReadAll(denied.Body)
	denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("reveal without step-up: want 403, got %d (%s)", denied.StatusCode, body)
	}
	if strings.Contains(string(body), "23853") {
		t.Fatal("a refused reveal must not carry the sequence")
	}

	grant := issueStepUpGrant(t, handler, cookies, csrf)
	ok := doJSON(t, handler, http.MethodPost, "/api/sshguard/knock/reveal",
		`{"node_id":"node-a","step_up_grant":"`+grant+`"}`, cookies, csrf)
	defer ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(ok.Body)
		t.Fatalf("reveal with step-up: want 200, got %d (%s)", ok.StatusCode, raw)
	}
	out := knockBody(t, ok)
	ports, _ := out["ports"].([]any)
	if len(ports) != len(knockTestPorts) {
		t.Fatalf("want %d ports, got %v", len(knockTestPorts), out["ports"])
	}
	for i, want := range knockTestPorts {
		if int(ports[i].(float64)) != want {
			t.Fatalf("port %d: want %d, got %v (order is part of the secret)", i, want, ports[i])
		}
	}
	cmd, _ := out["command"].(string)
	if !strings.Contains(cmd, "printf k") {
		t.Fatalf("the reveal must hand over a command that actually opens the gate: %q", cmd)
	}
}

// The fourth axiom says a person's reach is an agent's reach. This is the
// deliberate exception, so the refusal has to name itself rather than read as
// a generic authorization failure an agent would retry.
func TestKnockRevealRefusesABearerTokenAndSaysWhy(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	seedArmApproval(t, st, "approval_arm", "node-a", model.ApprovalApplied, knockTestPorts, time.Now().UTC())
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"network:plan", "sshguard:admin"}, []string{"node-a"})

	res := doBearerJSON(t, handler, http.MethodPost, "/api/sshguard/knock/reveal", `{"node_id":"node-a"}`, token)
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("bearer reveal: want 403, got %d", res.StatusCode)
	}
	if strings.Contains(string(raw), "23853") {
		t.Fatal("a bearer token must never receive the sequence")
	}
	// The message has to point at the half an agent can have, or the agent
	// learns only that it failed.
	if !strings.Contains(string(raw), "/api/sshguard/knock") {
		t.Fatalf("the refusal must name what an agent can call instead: %s", raw)
	}
}

// The state endpoint is the half an agent gets, so it must work from a bearer
// token and must never carry the ports.
func TestKnockStateIsAgentReachableAndCarriesNoPorts(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	seedArmApproval(t, st, "approval_arm", "node-a", model.ApprovalApplied, knockTestPorts, time.Now().UTC())
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"network:plan", "sshguard:read"}, []string{"node-a"})

	res := doBearerJSON(t, handler, http.MethodPost, "/api/sshguard/knock", `{"node_id":"node-a"}`, token)
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("state from a bearer token: want 200, got %d (%s)", res.StatusCode, raw)
	}
	for _, port := range knockTestPorts {
		if strings.Contains(string(raw), strconv.Itoa(port)) {
			t.Fatalf("the state endpoint leaked port %d: %s", port, raw)
		}
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out["knowledge"] != string(knockInstalled) {
		t.Fatalf("an applied arm is installed, got %v", out["knowledge"])
	}
	if out["revealable"] != true {
		t.Fatal("a node whose sequence is known must offer the reveal")
	}
	if n, _ := out["port_count"].(float64); int(n) != len(knockTestPorts) {
		t.Fatalf("port_count: want %d, got %v", len(knockTestPorts), out["port_count"])
	}
}

// The page that said nothing is what produced the question. When there is no
// plan, the API must say that in words rather than return an empty object the
// console can render as silence.
func TestKnockStateSaysPlainlyWhenTheSequenceIsUnknown(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	cookies, csrf := loginSession(t, handler)

	res := doJSON(t, handler, http.MethodPost, "/api/sshguard/knock", `{"node_id":"node-a"}`, cookies, csrf)
	defer res.Body.Close()
	out := knockBody(t, res)
	if out["knowledge"] != string(knockUnknown) {
		t.Fatalf("no plan means unknown, got %v", out["knowledge"])
	}
	if out["revealable"] != false {
		t.Fatal("nothing to reveal must not offer a reveal")
	}
	note, _ := out["note"].(string)
	if !strings.Contains(note, "does not know") {
		t.Fatalf("the note must state the absence plainly, got %q", note)
	}

	// And the reveal must agree rather than returning an empty sequence.
	grant := issueStepUpGrant(t, handler, cookies, csrf)
	missing := doJSON(t, handler, http.MethodPost, "/api/sshguard/knock/reveal",
		`{"node_id":"node-a","step_up_grant":"`+grant+`"}`, cookies, csrf)
	defer missing.Body.Close()
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("revealing an unknown sequence: want 404, got %d", missing.StatusCode)
	}
}

// A node re-armed since is running the newest sequence that actually reached
// it. Handing back a pending plan's sequence would send the operator to knock
// ports the node is not listening for.
func TestKnockRevealPrefersTheAppliedArmOverAPendingOne(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	applied := []int{21111, 22222, 23333}
	pending := []int{41111, 42222, 43333}
	base := time.Now().UTC().Add(-time.Hour)
	seedArmApproval(t, st, "approval_applied", "node-a", model.ApprovalApplied, applied, base)
	seedArmApproval(t, st, "approval_pending", "node-a", model.ApprovalPending, pending, base.Add(time.Minute*30))
	cookies, csrf := loginSession(t, handler)

	grant := issueStepUpGrant(t, handler, cookies, csrf)
	res := doJSON(t, handler, http.MethodPost, "/api/sshguard/knock/reveal",
		`{"node_id":"node-a","step_up_grant":"`+grant+`"}`, cookies, csrf)
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(raw), "21111") {
		t.Fatalf("the applied arm is what the node is running: %s", raw)
	}
	if strings.Contains(string(raw), "41111") {
		t.Fatalf("a pending arm has not reached the node: %s", raw)
	}
}

// A rejected arm's sequence was never written to the node and never will be.
// Reporting it as planned would send an operator to knock ports nothing is
// listening for, and that failure looks exactly like a wrong sequence.
func TestKnockStateDoesNotOfferARejectedArmsSequence(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	seedArmApproval(t, st, "approval_arm", "node-a", "rejected", knockTestPorts, time.Now().UTC())
	cookies, csrf := loginSession(t, handler)

	res := doJSON(t, handler, http.MethodPost, "/api/sshguard/knock", `{"node_id":"node-a"}`, cookies, csrf)
	defer res.Body.Close()
	out := knockBody(t, res)
	if out["knowledge"] != string(knockUnknown) {
		t.Fatalf("a rejected arm governs nothing, got %v", out["knowledge"])
	}
	if out["revealable"] != false {
		t.Fatal("a rejected arm must not offer a reveal")
	}
	// "there was never a plan" and "the plans there were all died" are
	// different things to tell someone who cannot get in.
	note, _ := out["note"].(string)
	if !strings.Contains(note, "rejected or dismissed") {
		t.Fatalf("the note must say the plans died rather than claiming none existed, got %q", note)
	}

	grant := issueStepUpGrant(t, handler, cookies, csrf)
	reveal := doJSON(t, handler, http.MethodPost, "/api/sshguard/knock/reveal",
		`{"node_id":"node-a","step_up_grant":"`+grant+`"}`, cookies, csrf)
	defer reveal.Body.Close()
	raw, _ := io.ReadAll(reveal.Body)
	if reveal.StatusCode != http.StatusNotFound {
		t.Fatalf("revealing a rejected arm: want 404, got %d", reveal.StatusCode)
	}
	if strings.Contains(string(raw), "23853") {
		t.Fatalf("a rejected arm's sequence must not be handed over: %s", raw)
	}
}

// A pending arm is different: it is a live decision, and saying so lets the
// page explain why knocking does not work yet instead of going silent.
func TestKnockStateReportsAPendingArmAsPlanned(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	seedArmApproval(t, st, "approval_arm", "node-a", model.ApprovalPending, knockTestPorts, time.Now().UTC())
	cookies, csrf := loginSession(t, handler)

	res := doJSON(t, handler, http.MethodPost, "/api/sshguard/knock", `{"node_id":"node-a"}`, cookies, csrf)
	defer res.Body.Close()
	out := knockBody(t, res)
	if out["knowledge"] != string(knockPlanned) {
		t.Fatalf("a pending arm is planned, got %v", out["knowledge"])
	}
	note, _ := out["note"].(string)
	if !strings.Contains(note, "not knocking on it yet") {
		t.Fatalf("the note must say the node is not knocking yet, got %q", note)
	}
}

// A profile applied with knocking off has no sequence, and saying "unknown"
// there would send an operator hunting for a secret that does not exist.
func TestKnockStateDistinguishesNoKnockFromUnknown(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	seedArmApproval(t, st, "approval_arm", "node-a", model.ApprovalApplied, nil, time.Now().UTC())
	cookies, csrf := loginSession(t, handler)

	res := doJSON(t, handler, http.MethodPost, "/api/sshguard/knock", `{"node_id":"node-a"}`, cookies, csrf)
	defer res.Body.Close()
	out := knockBody(t, res)
	if out["knowledge"] != string(knockNoKnock) {
		t.Fatalf("knocking off is not the same as unknown, got %v", out["knowledge"])
	}
	note, _ := out["note"].(string)
	if !strings.Contains(note, "without port knocking") {
		t.Fatalf("the note must say knocking is off, got %q", note)
	}
}

// An arm that applied but was never confirmed may have been undone by its own
// revert timer, which the control plane does not observe. The page must not
// claim the sequence is in force.
func TestKnockStateDoesNotClaimAnUnconfirmedArmIsInForce(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	seedArmApproval(t, st, "approval_arm", "node-a", model.ApprovalApplied, knockTestPorts, time.Now().UTC())
	cookies, csrf := loginSession(t, handler)

	res := doJSON(t, handler, http.MethodPost, "/api/sshguard/knock", `{"node_id":"node-a"}`, cookies, csrf)
	defer res.Body.Close()
	out := knockBody(t, res)
	if out["confirmed"] != false {
		t.Fatalf("no confirm approval means unconfirmed, got %v", out["confirmed"])
	}
	note, _ := out["note"].(string)
	if !strings.Contains(note, "never confirmed") {
		t.Fatalf("the note must flag the revert risk, got %q", note)
	}
}

// The audit trail records that a sequence was revealed and by whom. It must
// not record the sequence: an audit row is read by more people, kept longer,
// and shipped further than the reveal response.
func TestKnockRevealAuditNeverCarriesTheSequence(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	seedArmApproval(t, st, "approval_arm", "node-a", model.ApprovalApplied, knockTestPorts, time.Now().UTC())
	cookies, csrf := loginSession(t, handler)

	grant := issueStepUpGrant(t, handler, cookies, csrf)
	res := doJSON(t, handler, http.MethodPost, "/api/sshguard/knock/reveal",
		`{"node_id":"node-a","step_up_grant":"`+grant+`"}`, cookies, csrf)
	res.Body.Close()

	found := false
	for _, event := range srv.store.AuditEvents() {
		if event.Action != "sshguard.knock.reveal" {
			continue
		}
		found = true
		raw, _ := json.Marshal(event)
		for _, port := range knockTestPorts {
			if strings.Contains(string(raw), strconv.Itoa(port)) {
				t.Fatalf("the audit row carries the sequence: %s", raw)
			}
		}
		if event.Metadata["approval_id"] != "approval_arm" {
			t.Fatalf("the audit row must name the plan it read: %v", event.Metadata)
		}
	}
	if !found {
		t.Fatal("a reveal must leave an audit row")
	}
}
