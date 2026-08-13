package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

type countingRejectTransport struct{ calls int }

func (t *countingRejectTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	return nil, errors.New("unexpected external transport call")
}

func seedLineChainFixture(t *testing.T) (*Server, string, string, VpnUser, managedLineDef) {
	t.Helper()
	srv := newManagedLineTestServer(t)
	seedManagedLineNode(t, srv, "node-a", realityInventoryLines())
	user := seedManagedLineUser(t, srv)
	_, def := compileApproval(t, srv)
	def.Status = managedLineStatusApplied
	if err := srv.putManagedLineDef(def); err != nil {
		t.Fatal(err)
	}
	seedManagedLineNode(t, srv, "node-a", []model.SingBoxNode{{
		Name: def.Tag, Protocol: "vless", Network: "tcp", Address: "203.0.113.10", Port: fmt.Sprint(def.Port),
		SNI: def.SNI, LineUUID: def.LineUUID,
	}})
	const sourceUUID = "22222222-2222-4222-8222-222222222222"
	seedManagedLineNode(t, srv, "node-b", []model.SingBoxNode{{
		Name: "source-b", Protocol: "vless", Network: "tcp", Address: "198.51.100.20", Port: "1443",
		LineUUID: sourceUUID,
	}})
	_ = srv.buildLineGroups() // test setup establishes persistent UUID authority before pure compile
	srv.replaceAgentCapabilities("node-b", []string{lineChainDurableCapability})
	if !srv.agentHasCapability("node-b", lineChainDurableCapability) {
		t.Fatal("fixture failed to record durable capability")
	}
	return srv, sourceUUID, def.LineUUID, user, def
}

func TestLineChainPublicViewsMatchHTTPAndRPCContract(t *testing.T) {
	srv := newManagedLineTestServer(t)
	const sourceUUID = "22222222-2222-4222-8222-222222222222"
	approval := model.Approval{ID: "approval-public", NodeID: "node-b", Plugin: lineChainPlugin, Service: lineChainService,
		Method: lineChainSetMethod, Action: lineChainActionPrefix + "artifact", RequestSHA256: "request", Plan: `{"private":"credential-canary"}`, Status: model.ApprovalPending}
	attempt := store.LineChainAttempt{ApprovalID: approval.ID, Operation: store.LineChainOperationSet, SourceLineUUID: sourceUUID,
		SourceNodeID: "node-b", CandidateTargetLineUUID: "11111111-1111-4111-8111-111111111111", CandidateTargetNodeID: "node-a",
		CandidateArtifactSHA256: "artifact", RequestSHA256: "request", PlanGraphRevision: 0}
	if _, _, err := srv.store.PlanLineChainApproval(attempt, approval); err != nil {
		t.Fatal(err)
	}
	view, err := srv.lineChainViews()
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Chains) != 1 || view.Chains[0].Current != nil || view.Chains[0].Attempt == nil ||
		view.Chains[0].Status != store.LineChainStatusPlanned || view.Chains[0].Attempt.Operation != store.LineChainOperationSet {
		t.Fatalf("unexpected public chain projection: %+v", view)
	}
	rpcJSON, err := srv.vpnCoreLineChainsRPC(context.Background(), "chains", nil)
	if err != nil {
		t.Fatal(err)
	}
	var rpcView lineChainListView
	if err := json.Unmarshal(rpcJSON, &rpcView); err != nil || !reflect.DeepEqual(view, rpcView) {
		t.Fatalf("RPC view mismatch: view=%+v rpc=%+v err=%v", view, rpcView, err)
	}
	handler := srv.Handler()
	cookies, _ := loginSession(t, handler)
	req, rec := httptest.NewRequest(http.MethodGet, "/api/network/lines/chains", nil), httptest.NewRecorder()
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP chains status=%d body=%s", rec.Code, rec.Body.String())
	}
	var httpShape map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &httpShape); err != nil {
		t.Fatal(err)
	}
	if len(httpShape) != 1 || httpShape["chains"] == nil || httpShape["definitions"] != nil || httpShape["attempts"] != nil || httpShape["graph_revision"] != nil {
		t.Fatalf("HTTP exposed internal shape: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "credential-canary") || strings.Contains(string(rpcJSON), "credential-canary") {
		t.Fatalf("public view leaked approval secret: http=%s rpc=%s", rec.Body.String(), rpcJSON)
	}
}

func TestLineChainHTTPReadScopeDenialDoesNotMutate(t *testing.T) {
	srv := newManagedLineTestServer(t)
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"network:plan"}, nil)
	before := srv.store.LineChainSnapshot()
	response := doBearerJSON(t, handler, http.MethodGet, "/api/network/lines/chains", "", token)
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected proxy:read denial, got %d", response.StatusCode)
	}
	after := srv.store.LineChainSnapshot()
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("denied read mutated chain state: before=%+v after=%+v", before, after)
	}
}

func TestLineChainHTTPPlanScopeDenialHasNoDomainSideEffects(t *testing.T) {
	srv, sourceUUID, targetUUID, _, _ := seedLineChainFixture(t)
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"proxy:read"}, nil)
	transport := &countingRejectTransport{}
	previousTransport := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previousTransport })
	before, tasksBefore, approvalsBefore := srv.store.LineChainSnapshot(), len(srv.store.Tasks()), len(srv.store.Approvals())
	body := fmt.Sprintf(`{"source_line_uuid":%q,"target_line_uuid":%q}`, sourceUUID, targetUUID)
	response := doBearerJSON(t, handler, http.MethodPost, "/api/network/lines/chains/plan", body, token)
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected network:plan denial, got %d", response.StatusCode)
	}
	if after := srv.store.LineChainSnapshot(); !reflect.DeepEqual(before, after) || len(srv.store.Tasks()) != tasksBefore || len(srv.store.Approvals()) != approvalsBefore {
		t.Fatalf("denied plan mutated domain state: before=%+v after=%+v", before, after)
	}
	if transport.calls != 0 {
		t.Fatalf("denied plan made %d external transport calls", transport.calls)
	}
}

func TestLineChainPublicOperationProjectsReplace(t *testing.T) {
	if got := publicLineChainOperation(store.LineChainAttempt{Operation: store.LineChainOperationSet, BaseGeneration: 2}); got != "replace" {
		t.Fatalf("set over committed generation projected as %q", got)
	}
}

func TestLineChainAgentTaskViewCarriesExactDurableProtocol(t *testing.T) {
	view := toAgentTaskView(model.Task{ID: "task-1", LeaseID: "lease-1"}, true, store.DurableProtocolLineChainV2)
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"durable_protocol":"linechain-e3-v2"`) {
		t.Fatalf("linechain response protocol mismatch: %s", raw)
	}
}

func TestLineChainHTTPPollRecoveryRedeliveryAndResultReplay(t *testing.T) {
	srv, sourceUUID, targetUUID, _, _ := seedLineChainFixture(t)
	compiled, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
	if err != nil {
		t.Fatal(err)
	}
	approval, err := srv.persistLineChainPlan(lineUserTestPrincipal(), compiled)
	if err != nil {
		t.Fatal(err)
	}
	planSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(approval.Plan)))
	if _, err := srv.approveApprovalCore(context.Background(), lineUserTestPrincipal(), approval, true, planSHA); err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)
	originalNode, _ := srv.store.Node("node-b")
	nodeToken := enrollNamedNodeToken(t, handler, cookies, csrf, "node-b", "Node B")
	enrolledNode, _ := srv.store.Node("node-b")
	originalNode.TokenHash = enrolledNode.TokenHash
	if err := srv.store.UpsertNode(originalNode); err != nil {
		t.Fatal(err)
	}
	poll := func(capable bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/agent/tasks?node_id=node-b", nil)
		req.Header.Set("Authorization", "Bearer "+nodeToken)
		if capable {
			req.Header.Set(agentCapabilitiesHeader, lineChainDurableCapability)
		}
		return serveReq(handler, req)
	}
	blocked := poll(false)
	var blockedTasks []agentTaskView
	if blocked.Code != http.StatusOK || json.Unmarshal(blocked.Body.Bytes(), &blockedTasks) != nil || len(blockedTasks) != 0 {
		t.Fatalf("capability downgrade exposed task: code=%d body=%s", blocked.Code, blocked.Body.String())
	}
	first := poll(true)
	var firstTasks []agentTaskView
	if first.Code != http.StatusOK || json.Unmarshal(first.Body.Bytes(), &firstTasks) != nil || len(firstTasks) != 1 || firstTasks[0].DurableProtocol != store.DurableProtocolLineChainV2 {
		t.Fatalf("capability recovery did not lease E3 task: code=%d body=%s snapshot=%+v", first.Code, first.Body.String(), srv.store.LineChainSnapshot())
	}
	second := poll(true)
	var secondTasks []agentTaskView
	if second.Code != http.StatusOK || json.Unmarshal(second.Body.Bytes(), &secondTasks) != nil || len(secondTasks) != 1 || secondTasks[0].LeaseID != firstTasks[0].LeaseID {
		t.Fatalf("same-lease redelivery mismatch: first=%+v second=%s", firstTasks, second.Body.String())
	}
	finishedAt := time.Unix(1_700_000_100, 0).UTC().Format(time.RFC3339Nano)
	body := fmt.Sprintf(`{"node_id":"node-b","result":{"task_id":%q,"lease_id":%q,"exit_code":0,"finished_at":%q}}`, firstTasks[0].ID, firstTasks[0].LeaseID, finishedAt)
	for attempt := 1; attempt <= 2; attempt++ {
		result := doAgentRaw(t, handler, http.MethodPost, "/api/agent/task-result", body, nodeToken)
		if result.Code != http.StatusOK {
			t.Fatalf("exact result attempt %d code=%d body=%s", attempt, result.Code, result.Body.String())
		}
	}
	conflictBody := strings.Replace(body, `"exit_code":0`, `"exit_code":1`, 1)
	conflict := doAgentRaw(t, handler, http.MethodPost, "/api/agent/task-result", conflictBody, nodeToken)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("conflicting replay code=%d body=%s", conflict.Code, conflict.Body.String())
	}
	if snapshot := srv.store.LineChainSnapshot(); snapshot.Revision != 2 || snapshot.Definitions[sourceUUID].Status != store.LineChainStatusAppliedUnobserved {
		t.Fatalf("HTTP result did not promote exactly once: %+v", snapshot)
	}
}

func TestLineChainApprovalQueuesExecutableV2DocumentAtomically(t *testing.T) {
	srv, sourceUUID, targetUUID, _, _ := seedLineChainFixture(t)
	fixturePath := strings.TrimSpace(os.Getenv("LATTICE_LINECHAIN_FIXTURE_OUT"))
	if fixturePath == "" {
		fixturePath = filepath.Join(t.TempDir(), "server-issued-linechain-v2.json")
		t.Setenv("LATTICE_LINECHAIN_FIXTURE_OUT", fixturePath)
	}
	compiled, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
	if err != nil {
		t.Fatal(err)
	}
	approval, err := srv.persistLineChainPlan(lineUserTestPrincipal(), compiled)
	if err != nil {
		t.Fatal(err)
	}
	planSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(approval.Plan)))
	approved, err := srv.approveApprovalCore(context.Background(), lineUserTestPrincipal(), approval, true, planSHA)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != model.ApprovalApproved {
		t.Fatalf("approval not approved: %+v", approved)
	}
	retryPrincipal := principal{Principal: rbac.Principal{ActorID: "op-retry", TokenID: "token-retry"}, CorrelationID: "retry-correlation"}
	if _, err := srv.approveApprovalCore(context.Background(), retryPrincipal, approved, true, planSHA); err != nil {
		t.Fatalf("approved retry with a different principal did not repair immutable evidence: %v", err)
	}
	tasks := srv.store.Tasks()
	if len(tasks) != 1 || !strings.HasPrefix(tasks[0].Script, "# lattice-linechain-e3-v2\n") {
		t.Fatalf("expected one E3 task: %+v", tasks)
	}
	tmp := t.TempDir()
	capture := filepath.Join(tmp, "document.json")
	helper := filepath.Join(tmp, "agent")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\ntest \"$1\" = -linechain-apply\ncat > \"$CAPTURE\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", tasks[0].Script)
	cmd.Env = append(os.Environ(), "LATTICE_AGENT_BIN="+helper, "LATTICE_LINECHAIN_TXN_DIR="+tmp, "CAPTURE="+capture)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("execute task script: %v: %s", err, out)
	}
	raw, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	var doc lineChainAgentDocumentV2
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile(fixturePath)
	var fixtureEnvelope lineChainCrossContractFixtureV2
	if err != nil || json.Unmarshal(fixture, &fixtureEnvelope) != nil {
		t.Fatalf("decode production fixture: err=%v fixture=%s", err, fixture)
	}
	fixtureDocument, _ := json.Marshal(fixtureEnvelope.Document)
	if !bytes.Equal(bytes.TrimSpace(fixtureDocument), bytes.TrimSpace(raw)) ||
		fixtureEnvelope.Schema != "lattice.linechain.cross-contract-fixture.v2" ||
		fixtureEnvelope.ApprovalArtifactSHA256 != compiled.Plan.ArtifactSHA256 || fixtureEnvelope.RequestSHA256 != compiled.Plan.RequestSHA256 ||
		fixtureEnvelope.TaskScriptSHA256 != digestText(tasks[0].Script) || fixtureEnvelope.TaskID == "" || fixtureEnvelope.LeaseID == "" {
		t.Fatalf("production fixture does not bind queued server authority: fixture=%+v queued=%s", fixtureEnvelope, raw)
	}
	if info, err := os.Stat(fixturePath); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("production fixture permissions=%v", info.Mode().Perm())
	}
	if doc.Version != 2 || doc.DurableProtocol != lineChainDurableProtocol || doc.Operation != "create" || doc.FragmentBasename != compiled.Plan.FragmentPath ||
		doc.Fragment == nil || doc.SidecarPatch.Schema != lineChainPatchSchema || doc.SidecarPatch.SourceLineUUID != sourceUUID ||
		doc.SidecarPatch.DesiredDownstreamLineUUID == nil || *doc.SidecarPatch.DesiredDownstreamLineUUID != targetUUID ||
		doc.ArtifactSHA256 != compiled.Plan.ArtifactSHA256 || doc.SidecarPatchSHA256 != compiled.Plan.SidecarPatchSHA256 {
		t.Fatalf("unexpected v2 document: %+v", doc)
	}
	for _, forbidden := range []string{"config_dir", "fragment_path", "sidecar_path", `"sidecar"`, "combined_sha256"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("v2 document contains forbidden %s: %s", forbidden, raw)
		}
	}
	snapshot := srv.store.LineChainSnapshot()
	if snapshot.Revision != 1 || snapshot.Attempts[approval.ID].Status != store.LineChainStatusApplying {
		t.Fatalf("approval/task/reservation not atomic: %+v", snapshot)
	}
	actions := map[string]int{}
	for _, event := range srv.store.AuditEvents() {
		actions[event.Action]++
		raw, _ := json.Marshal(event)
		if strings.Contains(string(raw), "credential-canary") || strings.Contains(string(raw), compiled.FragmentJSON) {
			t.Fatalf("line-chain audit leaked execution material: %s", raw)
		}
	}
	if actions["linechain.plan"] != 1 || actions["linechain.approve"] != 1 || actions["network.singbox-linechain.approve"] != 0 {
		t.Fatalf("unexpected approval audit actions: %+v", actions)
	}
	approveEvent, ok := srv.store.AuditEventByID(lineChainAuditID("approve", approval.ID, tasks[0].ID))
	if !ok || approveEvent.ActorID != lineUserTestPrincipal().ActorID || approveEvent.ActorID == retryPrincipal.ActorID {
		t.Fatalf("approval retry rewrote immutable audit attribution: %+v", approveEvent)
	}
}

func TestGenericTaskHTTPMutationCannotBypassLineChainProtocol(t *testing.T) {
	for _, leased := range []bool{false, true} {
		t.Run(fmt.Sprintf("leased=%t", leased), func(t *testing.T) {
			srv, sourceUUID, targetUUID, _, _ := seedLineChainFixture(t)
			compiled, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
			if err != nil {
				t.Fatal(err)
			}
			approval, err := srv.persistLineChainPlan(lineUserTestPrincipal(), compiled)
			if err != nil {
				t.Fatal(err)
			}
			planSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(approval.Plan)))
			if _, err := srv.approveApprovalCore(context.Background(), lineUserTestPrincipal(), approval, true, planSHA); err != nil {
				t.Fatal(err)
			}
			if leased {
				deliveries, err := srv.store.LeaseTaskDeliveriesWithLineChainValidator("node-b", 1, false, true, srv.validateLineChainFirstLease)
				if err != nil || len(deliveries) != 1 {
					t.Fatalf("lease=%+v err=%v", deliveries, err)
				}
			}
			beforeChains, beforeTasks := srv.store.LineChainSnapshot(), srv.store.Tasks()
			handler := srv.Handler()
			cookies, csrf := loginSession(t, handler)
			for _, request := range []struct {
				path string
				body string
			}{
				{path: "/api/tasks/cancel", body: fmt.Sprintf(`{"id":%q}`, beforeTasks[0].ID)},
				{path: "/api/tasks/delete", body: fmt.Sprintf(`{"id":%q}`, beforeTasks[0].ID)},
				{path: "/api/tasks/rerun", body: fmt.Sprintf(`{"id":%q}`, beforeTasks[0].ID)},
				{path: "/api/tasks/rerun-node", body: fmt.Sprintf(`{"id":%q,"node_id":"node-b"}`, beforeTasks[0].ID)},
			} {
				response := doJSON(t, handler, http.MethodPost, request.path, request.body, cookies, csrf)
				response.Body.Close()
				if response.StatusCode != http.StatusConflict {
					t.Fatalf("%s status=%d want 409", request.path, response.StatusCode)
				}
			}
			if afterChains, afterTasks := srv.store.LineChainSnapshot(), srv.store.Tasks(); !reflect.DeepEqual(beforeChains, afterChains) || !reflect.DeepEqual(beforeTasks, afterTasks) || len(afterTasks) != 1 {
				t.Fatalf("generic endpoints mutated E3 state: before=%+v/%+v after=%+v/%+v", beforeChains, beforeTasks, afterChains, afterTasks)
			}
		})
	}
}

func TestLineChainManualRejectRetiresCandidateAndAllowsFreshPlan(t *testing.T) {
	srv, sourceUUID, targetUUID, _, _ := seedLineChainFixture(t)
	compiled, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
	if err != nil {
		t.Fatal(err)
	}
	approval, err := srv.persistLineChainPlan(lineUserTestPrincipal(), compiled)
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)
	response := doJSON(t, handler, http.MethodPost, "/api/network/approvals/reject", fmt.Sprintf(`{"approval_id":%q}`, approval.ID), cookies, csrf)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("reject status=%d", response.StatusCode)
	}
	stored, _ := srv.store.Approval(approval.ID)
	attempt := srv.store.LineChainSnapshot().Attempts[approval.ID]
	if stored.Status != model.ApprovalRejected || stored.Stale || attempt.Status != store.LineChainStatusFailed || len(srv.store.Tasks()) != 0 {
		t.Fatalf("manual rejection did not retire candidate: approval=%+v attempt=%+v tasks=%+v", stored, attempt, srv.store.Tasks())
	}
	if _, err := srv.persistLineChainPlan(lineUserTestPrincipal(), compiled); err != nil {
		t.Fatalf("fresh plan blocked after rejection: %v", err)
	}
}

func TestLineChainTaskScriptRevealIsDeniedBeforeStepUp(t *testing.T) {
	srv := newManagedLineTestServer(t)
	approval := model.Approval{ID: "approval-secret", NodeID: "node-a", Plugin: lineChainPlugin, Service: lineChainService,
		Method: lineChainSetMethod, Action: lineChainActionPrefix + "digest", Status: model.ApprovalApproved}
	if err := srv.store.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.CreateTask(model.Task{ID: "task-secret", ApprovalID: approval.ID, Targets: []string{"node-a"}, Script: "credential-canary", Status: model.TaskQueued}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/tasks/reveal-script", strings.NewReader(`{"id":"task-secret","step_up_grant":"otherwise-valid"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.handleRevealTaskScript(rec, req, principal{Principal: rbac.Principal{ActorID: "admin", Scopes: []string{"task:read"}}})
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "credential-canary") {
		t.Fatalf("E3 reveal status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestLineChainReconciliationAuditFreezesActionReasonAndTaskMetadata(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	drift := lineChainReconciliationAudit(store.LineChainDefinition{SourceLineUUID: "22222222-2222-4222-8222-222222222222", SourceNodeID: "node-a",
		TargetLineUUID: "11111111-1111-4111-8111-111111111111", AuditTargetLineUUID: "11111111-1111-4111-8111-111111111111",
		ApprovalID: "approval-observe", TaskID: "task-observe", ActorID: "planner", ArtifactSHA256: "artifact",
		Status: store.LineChainStatusDrifted, DriftCode: "observed_mismatch", UpdatedAt: at})
	if drift.Action != "linechain.drift" || drift.Decision != "deny" || drift.Reason != "observed_mismatch" ||
		drift.Metadata["task_id"] != "task-observe" || drift.Metadata["target_line_uuid"] != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("drift evidence lost frozen metadata: %+v", drift)
	}
	remove := lineChainReconciliationAudit(store.LineChainDefinition{SourceLineUUID: "22222222-2222-4222-8222-222222222222", SourceNodeID: "node-a",
		AuditTargetLineUUID: "11111111-1111-4111-8111-111111111111", ApprovalID: "approval-observe", TaskID: "task-observe", ActorID: "planner",
		Status: store.LineChainStatusConverged, UpdatedAt: at})
	if remove.Action != "linechain.remove" || remove.Decision != "allow" || remove.Metadata["target_line_uuid"] == "" {
		t.Fatalf("remove evidence lost prior target metadata: %+v", remove)
	}
}

func TestLineChainReconciliationAuditIDsDistinguishRepeatedStatusCycles(t *testing.T) {
	base := store.LineChainDefinition{SourceLineUUID: "22222222-2222-4222-8222-222222222222", SourceNodeID: "node-a", ApprovalID: "approval-a", TaskID: "task-a", Status: store.LineChainStatusConverged}
	first := base
	first.ObservationRevision = 1
	drift := base
	drift.Status, drift.DriftCode, drift.ObservationRevision = store.LineChainStatusDrifted, "observed_mismatch", 2
	second := base
	second.ObservationRevision = 3
	firstAudit, driftAudit, secondAudit := lineChainReconciliationAudit(first), lineChainReconciliationAudit(drift), lineChainReconciliationAudit(second)
	if firstAudit.ID == driftAudit.ID || driftAudit.ID == secondAudit.ID || firstAudit.ID == secondAudit.ID {
		t.Fatalf("repeated reconciliation transitions reused audit ids: first=%s drift=%s second=%s", firstAudit.ID, driftAudit.ID, secondAudit.ID)
	}
	if retry := lineChainReconciliationAudit(second); !reflect.DeepEqual(secondAudit, retry) {
		t.Fatalf("same transition is not idempotent: first=%+v retry=%+v", secondAudit, retry)
	}
}

func TestLineChainCompilerProducesDeterministicRedactedArtifact(t *testing.T) {
	srv, sourceUUID, targetUUID, user, def := seedLineChainFixture(t)
	first, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
	if err != nil {
		t.Fatal(err)
	}
	second, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
	if err != nil {
		t.Fatal(err)
	}
	if first.Plan.FragmentSHA256 != second.Plan.FragmentSHA256 || first.Plan.SidecarPatchSHA256 != second.Plan.SidecarPatchSHA256 || first.Plan.ArtifactSHA256 != second.Plan.ArtifactSHA256 {
		t.Fatalf("compile is not deterministic: first=%+v second=%+v", first.Plan, second.Plan)
	}
	planJSON, err := json.Marshal(first.Plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{user.Credentials[0].UUID, def.RealityPrivateKey, first.FragmentJSON, first.SidecarPatchJSON} {
		if strings.Contains(string(planJSON), secret) {
			t.Fatalf("redacted plan leaked secret/artifact %q: %s", secret, planJSON)
		}
	}
	if first.Plan.SourceNodeID != "node-b" || first.Plan.TargetNodeID != "node-a" || first.Plan.SourceInboundTag != "source-b" {
		t.Fatalf("edge direction is wrong: %+v", first.Plan)
	}
	if !strings.Contains(first.FragmentJSON, `"outbounds"`) || !strings.Contains(first.SidecarPatchJSON, targetUUID) {
		t.Fatalf("compiled pair does not describe the same edge: fragment=%s sidecar=%s", first.FragmentJSON, first.SidecarPatchJSON)
	}
}

func TestLineChainSemanticPatchAndArtifactCanonicalVector(t *testing.T) {
	const (
		sourceUUID   = "22222222-2222-4222-8222-222222222222"
		targetUUID   = "11111111-1111-4111-8111-111111111111"
		patchJSON    = `{"schema":"lattice.singbox-linechain-sidecar-patch.v1","source_line_uuid":"22222222-2222-4222-8222-222222222222","source_inbound_tag":"source-b","expected_downstream_line_uuid":null,"desired_downstream_line_uuid":"11111111-1111-4111-8111-111111111111"}`
		patchSHA     = "7394c9367aa36d0e37e1e6bb70d3de70afc1d6792f56754741ba118ca2137188"
		artifactJSON = `{"schema":"lattice.singbox-linechain-artifact.v2","operation":"create","fragment_basename":"lattice-linechain-0123456789abcdef0123.json","previous_fragment_sha256":null,"fragment_sha256":"0000000000000000000000000000000000000000000000000000000000000000","sidecar_patch_sha256":"7394c9367aa36d0e37e1e6bb70d3de70afc1d6792f56754741ba118ca2137188"}`
		artifactSHA  = "bb59094488756276a385921951eaac3e36dc604eb4a03c4cb2e1a52797aee261"
	)
	patch, raw, gotPatchSHA, err := canonicalLineChainSidecarPatch(strings.ToUpper(sourceUUID), "source-b", "", strings.ToUpper(targetUUID))
	if err != nil {
		t.Fatal(err)
	}
	if raw != patchJSON || gotPatchSHA != patchSHA || patch.ExpectedDownstreamLineUUID != nil ||
		patch.DesiredDownstreamLineUUID == nil || *patch.DesiredDownstreamLineUUID != targetUUID {
		t.Fatalf("canonical patch mismatch: raw=%s sha=%s patch=%+v", raw, gotPatchSHA, patch)
	}
	artifactRaw, gotArtifactSHA, err := canonicalLineChainArtifactJSON("create", "lattice-linechain-0123456789abcdef0123.json", "", strings.Repeat("0", 64), patchSHA)
	if err != nil || artifactRaw != artifactJSON || gotArtifactSHA != artifactSHA {
		t.Fatalf("canonical artifact mismatch: raw=%s sha=%s err=%v", artifactRaw, gotArtifactSHA, err)
	}
	_, removeRaw, _, err := canonicalLineChainSidecarPatch(sourceUUID, "source-b", targetUUID, "")
	if err != nil || !strings.Contains(removeRaw, `"expected_downstream_line_uuid":"`+targetUUID+`"`) ||
		!strings.Contains(removeRaw, `"desired_downstream_line_uuid":null`) {
		t.Fatalf("remove patch did not preserve explicit nullable CAS fields: raw=%s err=%v", removeRaw, err)
	}
}

func TestLineChainArtifactOperationShapeMatchesAgent(t *testing.T) {
	sha := strings.Repeat("a", 64)
	tests := []struct {
		name, operation, previous, fragment string
		valid                               bool
	}{
		{name: "create", operation: "create", fragment: sha, valid: true},
		{name: "create_with_previous", operation: "create", previous: sha, fragment: sha},
		{name: "create_without_fragment", operation: "create"},
		{name: "replace", operation: "replace", previous: sha, fragment: sha, valid: true},
		{name: "replace_without_previous", operation: "replace", fragment: sha},
		{name: "replace_without_fragment", operation: "replace", previous: sha},
		{name: "remove", operation: "remove", previous: sha, valid: true},
		{name: "remove_without_previous", operation: "remove"},
		{name: "remove_with_fragment", operation: "remove", previous: sha, fragment: sha},
		{name: "plan_operation", operation: "set", fragment: sha},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := canonicalLineChainArtifact(tc.operation, "lattice-linechain-0123456789abcdef0123.json", tc.previous, tc.fragment, sha)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}

func TestLineChainCompilerUsesImmutableCapturedSnapshot(t *testing.T) {
	srv, sourceUUID, targetUUID, _, _ := seedLineChainFixture(t)
	snapshot, err := srv.captureLineChainCompileSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	first, err := srv.compileLineChainSnapshot(snapshot, lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
	if err != nil {
		t.Fatal(err)
	}
	srv.replaceAgentCapabilities("node-b", nil)
	srv.now = func() time.Time { return time.Unix(2_000_000_000, 0).UTC() }
	second, err := srv.compileLineChainSnapshot(snapshot, lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
	if err != nil {
		t.Fatalf("captured snapshot changed after live capability mutation: %v", err)
	}
	if first.SidecarPatchJSON != second.SidecarPatchJSON || first.Plan.ArtifactSHA256 != second.Plan.ArtifactSHA256 || first.Plan.RequestSHA256 != second.Plan.RequestSHA256 {
		t.Fatalf("captured snapshot changed across wall clock: first=%+v second=%+v", first.Plan, second.Plan)
	}
}

func TestLineChainCompilerTenThousandProjectedLinesIsPure(t *testing.T) {
	srv, sourceUUID, targetUUID, _, _ := seedLineChainFixture(t)
	snapshot, err := srv.captureLineChainCompileSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	sourceNodeID := snapshot.Lines[sourceUUID][0].NodeID
	existing := 0
	for _, matches := range snapshot.Lines {
		for _, line := range matches {
			if line.NodeID == sourceNodeID {
				existing++
			}
		}
	}
	for i := existing; i < 10_000; i++ {
		uuid := fmt.Sprintf("00000000-0000-4000-8000-%012x", i)
		if _, collision := snapshot.Lines[uuid]; collision {
			continue
		}
		snapshot.Lines[uuid] = []Line{{LineUUID: uuid, NodeID: sourceNodeID, LineHashID: "hash-" + uuid, Tag: "tag-" + uuid, Status: "ok"}}
	}
	before := srv.store.LineChainSnapshot()
	var compileErr error
	allocs := testing.AllocsPerRun(3, func() {
		compiled, err := srv.compileLineChainSnapshot(snapshot, lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
		compileErr = err
		var patch lineChainSidecarPatch
		if err == nil {
			compileErr = json.Unmarshal([]byte(compiled.SidecarPatchJSON), &patch)
		}
		if compileErr == nil && (patch.SourceLineUUID != sourceUUID || patch.DesiredDownstreamLineUUID == nil || *patch.DesiredDownstreamLineUUID != targetUUID) {
			compileErr = fmt.Errorf("semantic patch does not bind source/target: %+v", patch)
		}
	})
	if compileErr != nil {
		t.Fatal(compileErr)
	}
	if after := srv.store.LineChainSnapshot(); !reflect.DeepEqual(before, after) {
		t.Fatalf("10k compile mutated store: before=%+v after=%+v", before, after)
	}
	t.Logf("10k projected-line compile allocations/run: %.0f", allocs)
}

func benchmarkLineChainSnapshot() (lineChainCompileSnapshot, string, string) {
	const sourceUUID = "22222222-2222-4222-8222-222222222222"
	const targetUUID = "11111111-1111-4111-8111-111111111111"
	const userID = "vpn-benchmark"
	snapshot := lineChainCompileSnapshot{
		Lines: map[string][]Line{
			sourceUUID: {{LineUUID: sourceUUID, NodeID: "node-b", LineHashID: "source-hash", Name: "source", Tag: "source", Core: model.ProxyCoreSingbox, Status: "ok"}},
			targetUUID: {{LineUUID: targetUUID, NodeID: "node-a", LineHashID: "target-hash", Name: "target", Tag: "target", Core: model.ProxyCoreSingbox,
				Type: model.ProxyProtocolVLESS, Security: model.ProxySecurityReality, Transport: model.ProxyTransportTCP, Overlay: true,
				OverlayStatus: managedLineStatusApplied, Status: "ok", PublicHost: "203.0.113.10"}},
		},
		Definitions: map[string]managedLineDef{targetUUID: {LineUUID: targetUUID, NodeID: "node-a", LineHashID: "target-hash", Tag: "target",
			Port: 443, SNI: "example.com", RealityPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", RealityPrivateKey: "private-key", ShortID: "abcdef12", UserID: userID, Status: managedLineStatusApplied}},
		Users:        map[string]VpnUser{userID: {ID: userID, Enabled: true, Credentials: []VpnCredential{{Protocol: model.ProxyProtocolVLESS, UUID: "33333333-3333-4333-8333-333333333333"}}}},
		Nodes:        map[string]model.Node{"node-a": {ID: "node-a", PublicIP: "203.0.113.10"}, "node-b": {ID: "node-b", Name: "source-node"}},
		Chains:       store.LineChainSnapshot{Definitions: map[string]store.LineChainDefinition{}, Attempts: map[string]store.LineChainAttempt{}},
		Capabilities: map[string]bool{"node-b": true},
	}
	for i := 1; i < 10_000; i++ {
		uuid := fmt.Sprintf("00000000-0000-4000-8000-%012x", i)
		snapshot.Lines[uuid] = []Line{{LineUUID: uuid, NodeID: "node-b", LineHashID: "hash-" + uuid, Tag: "tag-" + uuid, Status: "ok"}}
	}
	return snapshot, sourceUUID, targetUUID
}

func BenchmarkLineChainCompilerTenThousandProjectedLines(b *testing.B) {
	snapshot, sourceUUID, targetUUID := benchmarkLineChainSnapshot()
	srv := &Server{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compiled, err := srv.compileLineChainSnapshot(snapshot, lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
		if err != nil {
			b.Fatal(err)
		}
		if i == 0 {
			var patch lineChainSidecarPatch
			if err := json.Unmarshal([]byte(compiled.SidecarPatchJSON), &patch); err != nil || patch.SourceLineUUID != sourceUUID {
				b.Fatalf("benchmark patch=%+v err=%v", patch, err)
			}
		}
	}
}

func TestLineChainTerminalAcceptsIssuedSuccessWhenLiveDescriptorDrifts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *Server, string)
	}{
		{name: "managed_definition_missing", mutate: func(t *testing.T, srv *Server, targetUUID string) {
			vpnPublic, vpnPrivate := srv.store.VpnUserRecords()
			managedPublic, managedPrivate := srv.store.ManagedLineRecords()
			delete(managedPublic, targetUUID)
			delete(managedPrivate, targetUUID)
			if err := srv.store.ReplaceLineSecretRecords(vpnPublic, vpnPrivate, managedPublic, managedPrivate, nil); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "credential_changed", mutate: func(t *testing.T, srv *Server, _ string) {
			vpnPublic, vpnPrivate := srv.store.VpnUserRecords()
			for id, record := range vpnPrivate {
				if len(record.Credentials) > 0 {
					record.Credentials[0].UUID = "33333333-3333-4333-8333-333333333333"
					vpnPrivate[id] = record
					break
				}
			}
			managedPublic, managedPrivate := srv.store.ManagedLineRecords()
			if err := srv.store.ReplaceLineSecretRecords(vpnPublic, vpnPrivate, managedPublic, managedPrivate, nil); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, sourceUUID, targetUUID, _, _ := seedLineChainFixture(t)
			compiled, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
			if err != nil {
				t.Fatal(err)
			}
			approval, err := srv.persistLineChainPlan(lineUserTestPrincipal(), compiled)
			if err != nil {
				t.Fatal(err)
			}
			planSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(approval.Plan)))
			approval, err = srv.approveApprovalCore(context.Background(), lineUserTestPrincipal(), approval, true, planSHA)
			if err != nil {
				t.Fatal(err)
			}
			deliveries, err := srv.store.LeaseTaskDeliveriesWithLineChainValidator("node-b", 1, false, true, srv.validateLineChainFirstLease)
			if err != nil || len(deliveries) != 1 {
				t.Fatalf("lease=%+v err=%v", deliveries, err)
			}
			tc.mutate(t, srv, targetUUID)
			status, driftCode, err := srv.classifyLineChainTerminal(approval.ID)
			if err != nil || status != store.LineChainStatusDrifted || driftCode != "inputs_changed" {
				t.Fatalf("classification status=%q code=%q err=%v", status, driftCode, err)
			}
			result := model.TaskResult{TaskID: deliveries[0].Task.ID, NodeID: "node-b", LeaseID: deliveries[0].Task.LeaseID, ExitCode: 0, FinishedAt: time.Now().UTC()}
			terminalAudit := srv.lineChainTerminalAudit(approval, deliveries[0].Task, result, status, driftCode)
			if committed, err := srv.store.CompleteLineChainTaskResult(result, approval, status, driftCode, "", terminalAudit); err != nil || !committed {
				t.Fatalf("complete committed=%v err=%v", committed, err)
			}
			if matches, found, err := srv.store.ConfirmTaskResultReplay(result); err != nil || !found || !matches {
				t.Fatalf("exact replay matches=%v found=%v err=%v", matches, found, err)
			}
			if err := srv.ensureLineChainTerminalAudit(approval, deliveries[0].Task, result); err != nil {
				t.Fatal(err)
			}
			if err := srv.ensureLineChainTerminalAudit(approval, deliveries[0].Task, result); err != nil {
				t.Fatal(err)
			}
			terminalID := lineChainAuditID("terminal", approval.ID, deliveries[0].Task.ID+"\x00"+result.NodeID)
			event, ok := srv.store.AuditEventByID(terminalID)
			if !ok || event.Action != "linechain.drift" {
				t.Fatalf("missing drift audit: %+v ok=%v", event, ok)
			}
			count := 0
			for _, candidate := range srv.store.AuditEvents() {
				if candidate.ID == terminalID {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("exact replay duplicated terminal audit %d times", count)
			}
		})
	}
}

func TestLineChainTerminalConcurrentLiveMutationCommitsConsistentDrift(t *testing.T) {
	srv, sourceUUID, targetUUID, _, _ := seedLineChainFixture(t)
	compiled, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
	if err != nil {
		t.Fatal(err)
	}
	approval, err := srv.persistLineChainPlan(lineUserTestPrincipal(), compiled)
	if err != nil {
		t.Fatal(err)
	}
	planSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(approval.Plan)))
	approval, err = srv.approveApprovalCore(context.Background(), lineUserTestPrincipal(), approval, true, planSHA)
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err := srv.store.LeaseTaskDeliveriesWithLineChainValidator("node-b", 1, false, true, srv.validateLineChainFirstLease)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("lease=%+v err=%v", deliveries, err)
	}
	result := model.TaskResult{TaskID: deliveries[0].Task.ID, NodeID: "node-b", LeaseID: deliveries[0].Task.LeaseID, FinishedAt: time.Now().UTC()}

	// Hold the live-input write lock while the result path starts. The result
	// transaction holds its persistent snapshot lock, waits for this mutation,
	// then retains the live read locks through receipt/definition commit.
	srv.singboxInvMu.Lock()
	inventory := srv.singboxInv["node-a"]
	inventory.Nodes[0].Address = "203.0.113.99"
	srv.singboxInv["node-a"] = inventory
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		done <- srv.handleLineChainTaskResult(approval, deliveries[0].Task, result)
	}()
	<-started
	srv.singboxInvMu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	definition := srv.store.LineChainSnapshot().Definitions[sourceUUID]
	if definition.Status != store.LineChainStatusDrifted || definition.DriftCode != "inputs_changed" {
		t.Fatalf("concurrent target mutation committed inconsistent status: %+v", definition)
	}
	if matches, found, err := srv.store.ConfirmTaskResultReplay(result); err != nil || !found || !matches {
		t.Fatalf("concurrent result was not exactly replayable: matches=%v found=%v err=%v", matches, found, err)
	}
}

func TestLineChainFailedAndRemoveAuditsAreIdempotent(t *testing.T) {
	srv := newManagedLineTestServer(t)
	base := model.Approval{ID: "approval-audit", NodeID: "node-a", ActorID: "actor", Plugin: lineChainPlugin, Service: lineChainService,
		Method: lineChainSetMethod, ArtifactDigest: "artifact", Plan: `{"source_line_uuid":"source","target_line_uuid":"target","private":"secret-canary"}`}
	task := model.Task{ID: "task-audit", TokenID: "token"}
	failed := model.TaskResult{TaskID: task.ID, NodeID: "node-a", ExitCode: 1, Error: "host failed", FinishedAt: time.Unix(1_700_000_000, 0).UTC()}
	failedAudit := srv.lineChainTerminalAudit(base, task, failed, store.LineChainStatusFailed, "host_apply_failed")
	if _, err := srv.store.AppendAuditIdempotent(failedAudit); err != nil {
		t.Fatal(err)
	}
	if err := srv.ensureLineChainTerminalAudit(base, task, failed); err != nil {
		t.Fatal(err)
	}
	remove := base
	remove.ID, remove.Method = "approval-remove-audit", lineChainRemoveMethod
	removed := model.TaskResult{TaskID: task.ID, NodeID: "node-a", FinishedAt: time.Unix(1_700_000_001, 0).UTC()}
	removeAudit := srv.lineChainTerminalAudit(remove, task, removed, store.LineChainStatusAppliedUnobserved, "")
	if _, err := srv.store.AppendAuditIdempotent(removeAudit); err != nil {
		t.Fatal(err)
	}
	if err := srv.ensureLineChainTerminalAudit(remove, task, removed); err != nil {
		t.Fatal(err)
	}
	actions := map[string]int{}
	for _, event := range srv.store.AuditEvents() {
		actions[event.Action]++
		raw, _ := json.Marshal(event)
		if strings.Contains(string(raw), "secret-canary") {
			t.Fatalf("audit leaked approval plan: %s", raw)
		}
	}
	if actions["linechain.failed"] != 1 || actions["linechain.remove"] != 1 {
		t.Fatalf("missing audit actions: %+v", actions)
	}
}

func TestLineChainCompilerRejectsMissingConsumerCapability(t *testing.T) {
	srv, sourceUUID, targetUUID, _, _ := seedLineChainFixture(t)
	srv.replaceAgentCapabilities("node-b", nil)
	if _, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID}); err == nil || !strings.Contains(err.Error(), lineChainDurableCapability) {
		t.Fatalf("missing capability error=%v", err)
	}
}

func TestLineChainApprovalAndFirstLeaseRejectBoundDependencyMutationsAtomically(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *Server, string, string, VpnUser, managedLineDef)
	}{
		{name: "source_tag_and_hash", mutate: func(t *testing.T, srv *Server, sourceUUID, _ string, _ VpnUser, _ managedLineDef) {
			seedManagedLineNode(t, srv, "node-b", []model.SingBoxNode{{Name: "source-mutated", Protocol: "vless", Network: "tcp", Address: "198.51.100.20", Port: "1443", LineUUID: sourceUUID}})
		}},
		{name: "target_host", mutate: func(t *testing.T, srv *Server, _, targetUUID string, _ VpnUser, def managedLineDef) {
			seedManagedLineNode(t, srv, "node-a", []model.SingBoxNode{{Name: def.Tag, Protocol: "vless", Network: "tcp", Address: "203.0.113.99", Port: fmt.Sprint(def.Port), SNI: def.SNI, LineUUID: targetUUID}})
		}},
		{name: "target_port", mutate: func(t *testing.T, srv *Server, _, _ string, _ VpnUser, def managedLineDef) {
			def.Port++
			if err := srv.putManagedLineDef(def); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "target_public_material", mutate: func(t *testing.T, srv *Server, _, _ string, _ VpnUser, def managedLineDef) {
			def.RealityPublicKey = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
			if err := srv.putManagedLineDef(def); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "target_definition", mutate: func(t *testing.T, srv *Server, _, _ string, _ VpnUser, def managedLineDef) {
			def.SNI = "changed.example.com"
			if err := srv.putManagedLineDef(def); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "target_credential", mutate: func(t *testing.T, srv *Server, _, _ string, user VpnUser, _ managedLineDef) {
			user.Credentials[0].UUID = "33333333-3333-4333-8333-333333333333"
			if err := srv.putVpnUser(user); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name+"/approval", func(t *testing.T) {
			srv, sourceUUID, targetUUID, user, def := seedLineChainFixture(t)
			compiled, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
			if err != nil {
				t.Fatal(err)
			}
			approval, err := srv.persistLineChainPlan(lineUserTestPrincipal(), compiled)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, srv, sourceUUID, targetUUID, user, def)
			planSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(approval.Plan)))
			if _, err := srv.approveApprovalCore(context.Background(), lineUserTestPrincipal(), approval, true, planSHA); err == nil {
				t.Fatal("approval accepted mutated bound dependency")
			}
			stored, _ := srv.store.Approval(approval.ID)
			attempt := srv.store.LineChainSnapshot().Attempts[approval.ID]
			if len(srv.store.Tasks()) != 0 || srv.store.LineChainSnapshot().Revision != 0 || stored.Status != model.ApprovalRejected || !stored.Stale ||
				stored.StaleCode != "line_chain_inputs_changed" || attempt.Status != store.LineChainStatusFailed || attempt.LastErrorCode != "line_chain_inputs_changed" {
				t.Fatalf("stale approval mutated queue/graph: approval=%+v tasks=%+v snapshot=%+v", stored, srv.store.Tasks(), srv.store.LineChainSnapshot())
			}
			if event, ok := srv.store.AuditEventByID(lineChainAuditID("failed", approval.ID, "\x00line_chain_inputs_changed")); !ok || event.Action != "linechain.failed" || event.Decision != "deny" {
				t.Fatalf("stale approval missing frozen failure audit: ok=%v event=%+v", ok, event)
			}
		})
		t.Run(tc.name+"/first_lease", func(t *testing.T) {
			srv, sourceUUID, targetUUID, user, def := seedLineChainFixture(t)
			compiled, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
			if err != nil {
				t.Fatal(err)
			}
			approval, err := srv.persistLineChainPlan(lineUserTestPrincipal(), compiled)
			if err != nil {
				t.Fatal(err)
			}
			planSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(approval.Plan)))
			approval, err = srv.approveApprovalCore(context.Background(), lineUserTestPrincipal(), approval, true, planSHA)
			if err != nil {
				t.Fatal(err)
			}
			task := srv.store.Tasks()[0]
			tc.mutate(t, srv, sourceUUID, targetUUID, user, def)
			deliveries, err := srv.store.LeaseTaskDeliveriesWithLineChainValidator("node-b", 1, false, true, srv.validateLineChainFirstLease)
			if err != nil || len(deliveries) != 0 {
				t.Fatalf("mutated dependency leased: deliveries=%+v err=%v", deliveries, err)
			}
			gotApproval, _ := srv.store.Approval(approval.ID)
			gotTask, _ := srv.store.Task(task.ID)
			attempt := srv.store.LineChainSnapshot().Attempts[approval.ID]
			if gotApproval.Status != model.ApprovalRejected || !gotApproval.Stale || gotTask.Status != model.TaskCancelled || attempt.Status != store.LineChainStatusFailed || srv.store.LineChainSnapshot().Revision != 2 {
				t.Fatalf("first-lease rejection was not atomic: approval=%+v task=%+v attempt=%+v snapshot=%+v", gotApproval, gotTask, attempt, srv.store.LineChainSnapshot())
			}
			if event, ok := srv.store.AuditEventByID(lineChainAuditID("failed", approval.ID, task.ID+"\x00line_chain_inputs_changed")); !ok || event.Action != "linechain.failed" || event.Metadata["task_id"] != task.ID {
				t.Fatalf("first-lease rejection missing frozen failure audit: ok=%v event=%+v", ok, event)
			}
		})
	}
}

func TestLineChainFirstLeaseRejectsTamperedQueuedScriptAtomically(t *testing.T) {
	srv, sourceUUID, targetUUID, _, _ := seedLineChainFixture(t)
	compiled, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
	if err != nil {
		t.Fatal(err)
	}
	approval, err := srv.persistLineChainPlan(lineUserTestPrincipal(), compiled)
	if err != nil {
		t.Fatal(err)
	}
	planSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(approval.Plan)))
	approval, err = srv.approveApprovalCore(context.Background(), lineUserTestPrincipal(), approval, true, planSHA)
	if err != nil {
		t.Fatal(err)
	}
	task := srv.store.Tasks()[0]
	task.Script += "\n# tampered"
	if err := srv.store.CreateTask(task); err != nil {
		t.Fatal(err)
	}
	deliveries, err := srv.store.LeaseTaskDeliveriesWithLineChainValidator("node-b", 1, false, true, srv.validateLineChainFirstLease)
	if err != nil || len(deliveries) != 0 {
		t.Fatalf("tampered task leased: deliveries=%+v err=%v", deliveries, err)
	}
	gotApproval, _ := srv.store.Approval(approval.ID)
	gotTask, _ := srv.store.Task(task.ID)
	attempt := srv.store.LineChainSnapshot().Attempts[approval.ID]
	if gotApproval.Status != model.ApprovalRejected || gotTask.Status != model.TaskCancelled || attempt.Status != store.LineChainStatusFailed || srv.store.LineChainSnapshot().Revision != 2 {
		t.Fatalf("tampered task rejection was not atomic: approval=%+v task=%+v attempt=%+v", gotApproval, gotTask, attempt)
	}
}

func TestLineChainCompilerDoesNotAllocateMissingUUIDAuthority(t *testing.T) {
	srv, sourceUUID, targetUUID, _, _ := seedLineChainFixture(t)
	snapshot, err := srv.captureLineChainCompileSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	source := snapshot.Lines[sourceUUID][0]
	if err := srv.store.DeleteKV(lineUUIDKVBucket, source.LineHashID); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID}); err == nil {
		t.Fatal("compile unexpectedly allocated missing UUID authority")
	}
	if _, ok := srv.store.KVEntry(lineUUIDKVBucket, source.LineHashID); ok {
		t.Fatal("failed compile mutated UUID authority")
	}
}

func TestLineChainCompilerRejectsUnsupportedTargetTransport(t *testing.T) {
	srv, sourceUUID, targetUUID, _, def := seedLineChainFixture(t)
	seedManagedLineNode(t, srv, "node-a", []model.SingBoxNode{{
		Name: def.Tag, Protocol: "vless", Network: "udp", Address: "203.0.113.10", Port: fmt.Sprint(def.Port),
		SNI: def.SNI, LineUUID: def.LineUUID,
	}})
	if _, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID}); err == nil || !strings.Contains(err.Error(), "VLESS+REALITY+TCP") {
		t.Fatalf("unsupported target transport error=%v", err)
	}
}

func TestLineChainCompilerRejectsCurrentGraphCycle(t *testing.T) {
	srv, sourceUUID, targetUUID, _, _ := seedLineChainFixture(t)
	if _, _, err := srv.store.PlanLineChain(store.LineChainAttempt{
		ApprovalID: "approval-existing", Operation: store.LineChainOperationSet,
		SourceLineUUID: targetUUID, SourceNodeID: "node-a", CandidateTargetLineUUID: sourceUUID,
		CandidateTargetNodeID: "node-b", RequestSHA256: "existing",
	}); err != nil {
		t.Fatal(err)
	}
	snapshot := srv.store.LineChainSnapshot()
	if _, err := srv.store.ReserveLineChain("approval-existing", snapshot.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID}); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cycle error=%v", err)
	}
}

func TestLineChainPlanPersistsTypedApprovalAndSeparateAttempt(t *testing.T) {
	srv, sourceUUID, targetUUID, user, def := seedLineChainFixture(t)
	compiled, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
	if err != nil {
		t.Fatal(err)
	}
	approval, err := srv.persistLineChainPlan(lineUserTestPrincipal(), compiled)
	if err != nil {
		t.Fatal(err)
	}
	if approval.Plugin != lineChainPlugin || approval.Service != lineChainService || approval.Method != lineChainSetMethod ||
		approval.Action != lineChainActionPrefix+compiled.Plan.ArtifactSHA256 || len(approval.Targets) != 1 || approval.Targets[0] != "node-b" {
		t.Fatalf("typed approval binding is wrong: %+v", approval)
	}
	for _, secret := range []string{user.Credentials[0].UUID, def.RealityPrivateKey, compiled.FragmentJSON, compiled.SidecarPatchJSON} {
		if strings.Contains(approval.Plan, secret) {
			t.Fatalf("approval leaked secret/artifact %q: %s", secret, approval.Plan)
		}
	}
	snapshot := srv.store.LineChainSnapshot()
	attempt, ok := snapshot.Attempts[approval.ID]
	if !ok || attempt.Status != store.LineChainStatusPlanned || attempt.PlanGraphRevision != snapshot.Revision || len(snapshot.Definitions) != 0 {
		t.Fatalf("planned state is not separate from committed definitions: %+v", snapshot)
	}
	again, err := srv.persistLineChainPlan(lineUserTestPrincipal(), compiled)
	if err != nil || again.ID != approval.ID {
		t.Fatalf("identical plan did not deduplicate: again=%+v err=%v", again, err)
	}
}

func TestLineChainPlanRejectsStaleCompiledRevision(t *testing.T) {
	srv, sourceUUID, targetUUID, _, _ := seedLineChainFixture(t)
	compiled, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
	if err != nil {
		t.Fatal(err)
	}
	other := store.LineChainAttempt{ApprovalID: "other", Operation: store.LineChainOperationSet,
		SourceLineUUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", CandidateTargetLineUUID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		RequestSHA256: "other", PlanGraphRevision: compiled.PlanGraphRevision}
	if _, _, err := srv.store.PlanLineChain(other); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.store.ReserveLineChain(other.ApprovalID, compiled.PlanGraphRevision); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.persistLineChainPlan(lineUserTestPrincipal(), compiled); !errors.Is(err, store.ErrLineChainRevisionConflict) {
		t.Fatalf("stale compiled revision error=%v", err)
	}
}

func TestLineChainEndToEndSetObserveMetadataAndRemoveTrace(t *testing.T) {
	srv, sourceUUID, targetUUID, _, def := seedLineChainFixture(t)
	planner := principal{Principal: rbac.Principal{ActorID: "planner-a", TokenID: "planner-token"}}
	approver := principal{Principal: rbac.Principal{ActorID: "approver-b", TokenID: "approver-token"}}
	apply := func(t *testing.T, compiled lineChainCompiledArtifact) model.Approval {
		t.Helper()
		beforeTasks := len(srv.store.Tasks())
		approval, err := srv.persistLineChainPlan(planner, compiled)
		if err != nil {
			t.Fatal(err)
		}
		planSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(approval.Plan)))
		approval, err = srv.approveApprovalCore(context.Background(), approver, approval, true, planSHA)
		if err != nil {
			t.Fatal(err)
		}
		if len(srv.store.Tasks()) != beforeTasks+1 {
			t.Fatalf("approval queued %d tasks, want one", len(srv.store.Tasks())-beforeTasks)
		}
		deliveries, err := srv.store.LeaseTaskDeliveriesWithLineChainValidator("node-b", 1, false, true, srv.validateLineChainFirstLease)
		if err != nil || len(deliveries) != 1 || len(deliveries[0].Task.Targets) != 1 || deliveries[0].Task.Targets[0] != "node-b" {
			t.Fatalf("source-only lease mismatch: %+v err=%v", deliveries, err)
		}
		result := model.TaskResult{TaskID: deliveries[0].Task.ID, NodeID: "node-b", LeaseID: deliveries[0].Task.LeaseID, FinishedAt: time.Now().UTC()}
		if err := srv.handleLineChainTaskResult(approval, deliveries[0].Task, result); err != nil {
			t.Fatal(err)
		}
		return approval
	}

	seedManagedLineNode(t, srv, "node-b", []model.SingBoxNode{{Name: "source-b", Protocol: "vless", Network: "tcp", Address: "198.51.100.20", Port: "1443",
		LineUUID: sourceUUID, DownstreamLineUUID: "33333333-3333-4333-8333-333333333333"}})
	if _, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID}); err == nil ||
		!strings.Contains(err.Error(), "true create requires an unclaimed source") {
		t.Fatalf("true create adopted an unrelated observed declaration: %v", err)
	}
	seedManagedLineNode(t, srv, "node-b", []model.SingBoxNode{{Name: "source-b", Protocol: "vless", Network: "tcp", Address: "198.51.100.20", Port: "1443", LineUUID: sourceUUID}})
	setArtifact, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
	if err != nil {
		t.Fatal(err)
	}
	var setPatch lineChainSidecarPatch
	if err := json.Unmarshal([]byte(setArtifact.SidecarPatchJSON), &setPatch); err != nil || setPatch.ExpectedDownstreamLineUUID != nil ||
		setPatch.DesiredDownstreamLineUUID == nil || *setPatch.DesiredDownstreamLineUUID != targetUUID {
		t.Fatalf("set patch lost semantic CAS: patch=%+v err=%v", setPatch, err)
	}
	apply(t, setArtifact)
	if got := srv.store.LineChainSnapshot().Definitions[sourceUUID]; got.Status != store.LineChainStatusAppliedUnobserved || got.TargetLineUUID != targetUUID {
		t.Fatalf("set terminal did not promote frozen definition: %+v", got)
	}
	seedManagedLineNode(t, srv, "node-b", []model.SingBoxNode{{Name: "source-b", Protocol: "vless", Network: "tcp", Address: "198.51.100.20", Port: "1443",
		LineUUID: sourceUUID, DownstreamLineUUID: "33333333-3333-4333-8333-333333333333"}})
	if _, err := srv.compileLineChainRemove(sourceUUID); err == nil || !strings.Contains(err.Error(), "conflicts with committed baseline") {
		t.Fatalf("conflicting nonempty observation did not fail closed: %v", err)
	}
	seedManagedLineNode(t, srv, "node-b", []model.SingBoxNode{{Name: "source-b", Protocol: "vless", Network: "tcp", Address: "198.51.100.20", Port: "1443", LineUUID: sourceUUID}})
	for operation, compile := range map[string]func() (lineChainCompiledArtifact, error){
		"replace": func() (lineChainCompiledArtifact, error) {
			return srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
		},
		"remove": func() (lineChainCompiledArtifact, error) { return srv.compileLineChainRemove(sourceUUID) },
	} {
		immediate, err := compile()
		if err != nil {
			t.Fatalf("immediate set->%s before inventory failed: %v", operation, err)
		}
		var patch lineChainSidecarPatch
		if err := json.Unmarshal([]byte(immediate.SidecarPatchJSON), &patch); err != nil || patch.ExpectedDownstreamLineUUID == nil ||
			*patch.ExpectedDownstreamLineUUID != targetUUID {
			t.Fatalf("immediate set->%s did not freeze committed expected target: patch=%+v err=%v", operation, patch, err)
		}
		wantArtifact, err := canonicalLineChainArtifact(operation, immediate.Plan.FragmentPath, immediate.PreviousFragmentSHA256,
			immediate.Plan.FragmentSHA256, immediate.Plan.SidecarPatchSHA256)
		if err != nil || immediate.Plan.ArtifactSHA256 != wantArtifact {
			t.Fatalf("immediate set->%s artifact=%s want=%s err=%v", operation, immediate.Plan.ArtifactSHA256, wantArtifact, err)
		}
	}
	observedHash := lineHash("node-b", model.ProxyCoreSingbox, "vless", "", 1443, "source-b", setArtifact.Plan.OutboundTag)
	if err := srv.store.PutKV(model.KVEntry{Bucket: lineUUIDKVBucket, Key: observedHash, Value: sourceUUID}); err != nil {
		t.Fatal(err)
	}
	seedManagedLineNode(t, srv, "node-b", []model.SingBoxNode{{Name: "source-b", Protocol: "vless", Network: "tcp", Address: "198.51.100.20", Port: "1443",
		LineUUID: sourceUUID, OutboundRef: setArtifact.Plan.OutboundTag, DownstreamLineUUID: targetUUID}})
	if err := srv.reconcileLineChainsForNode("node-b"); err != nil {
		t.Fatal(err)
	}
	if got := srv.store.LineChainSnapshot().Definitions[sourceUUID]; got.Status != store.LineChainStatusConverged {
		t.Fatalf("scheduled observation did not converge set: %+v", got)
	}
	for _, event := range srv.store.AuditEvents() {
		switch event.Action {
		case "linechain.plan":
			if event.ActorID != planner.ActorID {
				t.Fatalf("plan audit actor=%q want %q", event.ActorID, planner.ActorID)
			}
		case "linechain.approve", "linechain.apply", "linechain.drift", "linechain.remove":
			if event.ActorID != approver.ActorID {
				t.Fatalf("execution audit %s actor=%q want %q", event.Action, event.ActorID, approver.ActorID)
			}
		}
	}
	metadata, err := srv.renderLineMetadataJSON("node-b")
	if err != nil || !strings.Contains(string(metadata), targetUUID) {
		t.Fatalf("metadata did not retain committed chain: %s err=%v", metadata, err)
	}

	removeArtifact, err := srv.compileLineChainRemove(sourceUUID)
	if err != nil {
		t.Fatal(err)
	}
	var removePatch lineChainSidecarPatch
	if err := json.Unmarshal([]byte(removeArtifact.SidecarPatchJSON), &removePatch); err != nil || removePatch.ExpectedDownstreamLineUUID == nil ||
		*removePatch.ExpectedDownstreamLineUUID != targetUUID || removePatch.DesiredDownstreamLineUUID != nil {
		t.Fatalf("remove patch lost semantic CAS: patch=%+v err=%v", removePatch, err)
	}
	apply(t, removeArtifact)
	removed := srv.store.LineChainSnapshot().Definitions[sourceUUID]
	if removed.TargetLineUUID != "" || removed.Status != store.LineChainStatusAppliedUnobserved || removed.OutboundTag != setArtifact.Plan.OutboundTag {
		t.Fatalf("remove did not preserve authoritative tombstone: %+v", removed)
	}
	seedManagedLineNode(t, srv, "node-b", []model.SingBoxNode{{Name: "source-b", Protocol: "vless", Network: "tcp", Address: "198.51.100.20", Port: "1443", LineUUID: sourceUUID}})
	if err := srv.reconcileLineChainsForNode("node-b"); err != nil {
		t.Fatal(err)
	}
	removed = srv.store.LineChainSnapshot().Definitions[sourceUUID]
	if removed.Status != store.LineChainStatusConverged || removed.TargetLineUUID != "" || len(srv.store.Tasks()) != 2 {
		t.Fatalf("remove observation/task count mismatch: definition=%+v tasks=%+v", removed, srv.store.Tasks())
	}
	metadata, err = srv.renderLineMetadataJSON("node-b")
	if err != nil || strings.Contains(string(metadata), targetUUID) || !strings.Contains(string(metadata), sourceUUID) || def.LineUUID != targetUUID {
		t.Fatalf("metadata did not clear only the observed chain: %s err=%v", metadata, err)
	}
	recreate, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
	if err != nil {
		t.Fatal(err)
	}
	wantRecreateArtifact, err := canonicalLineChainArtifact("create", recreate.Plan.FragmentPath, "", recreate.Plan.FragmentSHA256, recreate.Plan.SidecarPatchSHA256)
	if err != nil || recreate.Plan.ArtifactSHA256 != wantRecreateArtifact || recreate.PreviousFragmentSHA256 != "" {
		t.Fatalf("set over committed remove tombstone was not create: artifact=%+v want=%s err=%v", recreate.Plan, wantRecreateArtifact, err)
	}
}
