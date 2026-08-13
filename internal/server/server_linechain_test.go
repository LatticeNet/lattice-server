package server

import (
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

func TestLineChainPublicOperationProjectsReplace(t *testing.T) {
	if got := publicLineChainOperation(store.LineChainAttempt{Operation: store.LineChainOperationSet, BaseGeneration: 2}); got != "replace" {
		t.Fatalf("set over committed generation projected as %q", got)
	}
}

func TestLineChainAgentTaskViewCarriesExactDurableProtocol(t *testing.T) {
	view := toAgentTaskView(model.Task{ID: "task-1", LeaseID: "lease-1"}, true, store.DurableProtocolLineChainV1)
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"durable_protocol":"linechain-e3-v1"`) {
		t.Fatalf("linechain response protocol mismatch: %s", raw)
	}
}

func TestLineChainApprovalQueuesExecutableV2DocumentAtomically(t *testing.T) {
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
	approved, err := srv.approveApprovalCore(context.Background(), lineUserTestPrincipal(), approval, true, planSHA)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != model.ApprovalApproved {
		t.Fatalf("approval not approved: %+v", approved)
	}
	tasks := srv.store.Tasks()
	if len(tasks) != 1 || !strings.HasPrefix(tasks[0].Script, "# lattice-linechain-e3-v1\n") {
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
	if doc.Version != 2 || doc.Operation != "create" || doc.FragmentBasename != compiled.Plan.FragmentPath ||
		doc.Fragment == nil || doc.Sidecar == nil || doc.CombinedSHA256 != compiled.Plan.ArtifactSHA256 {
		t.Fatalf("unexpected v2 document: %+v", doc)
	}
	for _, forbidden := range []string{"config_dir", "fragment_path", "sidecar_path", "previous_sidecar_sha256"} {
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
	if first.Plan.FragmentSHA256 != second.Plan.FragmentSHA256 || first.Plan.SidecarSHA256 != second.Plan.SidecarSHA256 || first.Plan.ArtifactSHA256 != second.Plan.ArtifactSHA256 {
		t.Fatalf("compile is not deterministic: first=%+v second=%+v", first.Plan, second.Plan)
	}
	planJSON, err := json.Marshal(first.Plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{user.Credentials[0].UUID, def.RealityPrivateKey, first.FragmentJSON, first.SidecarJSON} {
		if strings.Contains(string(planJSON), secret) {
			t.Fatalf("redacted plan leaked secret/artifact %q: %s", secret, planJSON)
		}
	}
	if first.Plan.SourceNodeID != "node-b" || first.Plan.TargetNodeID != "node-a" || first.Plan.SourceInboundTag != "source-b" {
		t.Fatalf("edge direction is wrong: %+v", first.Plan)
	}
	if !strings.Contains(first.FragmentJSON, `"outbounds"`) || !strings.Contains(first.SidecarJSON, targetUUID) {
		t.Fatalf("compiled pair does not describe the same edge: fragment=%s sidecar=%s", first.FragmentJSON, first.SidecarJSON)
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
	if first.SidecarJSON != second.SidecarJSON || first.Plan.ArtifactSHA256 != second.Plan.ArtifactSHA256 || first.Plan.RequestSHA256 != second.Plan.RequestSHA256 {
		t.Fatalf("captured snapshot changed across wall clock: first=%+v second=%+v", first.Plan, second.Plan)
	}
}

func TestLineChainCompilerTenThousandProjectedLinesIsPure(t *testing.T) {
	srv, sourceUUID, targetUUID, _, _ := seedLineChainFixture(t)
	snapshot, err := srv.captureLineChainCompileSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	for i := len(snapshot.Lines); i < 10_000; i++ {
		uuid := fmt.Sprintf("projected-%05d", i)
		snapshot.Lines[uuid] = []Line{{LineUUID: uuid, NodeID: "scale-node", LineHashID: "hash-" + uuid, Tag: "tag-" + uuid, Status: "ok"}}
	}
	before := srv.store.LineChainSnapshot()
	var compileErr error
	allocs := testing.AllocsPerRun(3, func() {
		_, compileErr = srv.compileLineChainSnapshot(snapshot, lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
	})
	if compileErr != nil {
		t.Fatal(compileErr)
	}
	if after := srv.store.LineChainSnapshot(); !reflect.DeepEqual(before, after) {
		t.Fatalf("10k compile mutated store: before=%+v after=%+v", before, after)
	}
	t.Logf("10k projected-line compile allocations/run: %.0f", allocs)
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
			if committed, err := srv.store.CompleteLineChainTaskResult(result, approval, status, driftCode, ""); err != nil || !committed {
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

func TestLineChainFailedAndRemoveAuditsAreIdempotent(t *testing.T) {
	srv := newManagedLineTestServer(t)
	base := model.Approval{ID: "approval-audit", NodeID: "node-a", ActorID: "actor", Plugin: lineChainPlugin, Service: lineChainService,
		Method: lineChainSetMethod, ArtifactDigest: "artifact", Plan: `{"source_line_uuid":"source","target_line_uuid":"target","private":"secret-canary"}`}
	task := model.Task{ID: "task-audit", TokenID: "token"}
	failed := model.TaskResult{TaskID: task.ID, NodeID: "node-a", ExitCode: 1, Error: "host failed", FinishedAt: time.Unix(1_700_000_000, 0).UTC()}
	if err := srv.ensureLineChainTerminalAudit(base, task, failed); err != nil {
		t.Fatal(err)
	}
	remove := base
	remove.ID, remove.Method = "approval-remove-audit", lineChainRemoveMethod
	removed := model.TaskResult{TaskID: task.ID, NodeID: "node-a", FinishedAt: time.Unix(1_700_000_001, 0).UTC()}
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
	for _, secret := range []string{user.Credentials[0].UUID, def.RealityPrivateKey, compiled.FragmentJSON, compiled.SidecarJSON} {
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
