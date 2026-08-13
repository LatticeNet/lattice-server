package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
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
