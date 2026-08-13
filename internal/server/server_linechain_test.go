package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
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

func TestLineChainCompilerRejectsMissingConsumerCapability(t *testing.T) {
	srv, sourceUUID, targetUUID, _, _ := seedLineChainFixture(t)
	srv.replaceAgentCapabilities("node-b", nil)
	if _, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID}); err == nil || !strings.Contains(err.Error(), lineChainDurableCapability) {
		t.Fatalf("missing capability error=%v", err)
	}
}
