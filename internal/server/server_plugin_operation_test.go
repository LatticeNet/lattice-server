package server

import (
	"context"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// These exercise the re-check ladder in executePluginOperation directly. Each typed
// column the approval bound must be compared to live state before the plugin is
// invoked, so a mismatch fails BEFORE reaching the runtime — which is why a nil
// pluginRuntime is enough to prove the gate: if any of these reached the invoke, the
// nil runtime would panic instead of returning the expected refusal.

func operationServer(t *testing.T, manifest plugin.Manifest, artifactDigest string) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertPluginInstallation(model.PluginInstallation{
		ID: manifest.ID, Name: manifest.Name, Type: manifest.Type, Status: model.PluginStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		store:     st,
		plugins:   []plugin.Loaded{{Manifest: manifest, ArtifactDigest: artifactDigest}},
		pluginRPC: plugin.NewRPCRegistry(),
	}
	return srv, st
}

func runtimeBackedManifest() plugin.Manifest {
	return plugin.Manifest{
		Schema: plugin.ManifestSchemaV2, ID: "latticenet.example", Name: "Example", Type: plugin.TypeSystem,
		Version: "1.0.0", Publisher: "latticenet",
		Interfaces: []plugin.InterfaceContract{{
			Service: "latticenet.example/net", Backing: plugin.BackingRuntime,
			MethodSpecs: []plugin.InterfaceMethod{{Name: "apply", Effect: plugin.InterfaceEffectPlan, Scopes: []string{"network:apply"}}},
		}},
	}
}

func boundApproval(digest string) model.Approval {
	plan, _ := plugin.CanonicalOperationPlan(plugin.PluginOperationPlan{
		Summary: "apply", Targets: []string{"node-a"},
	})
	return model.Approval{
		ID: "approval-1", Plugin: "latticenet.example", NodeID: "node-a",
		Plan: plan, Status: model.ApprovalApproved, ActorID: "op",
		PluginVersion: "1.0.0", ArtifactDigest: digest, Service: "latticenet.example/net",
		Method: "apply", Targets: []string{"node-a"},
	}
}

func applier() principal {
	return principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"network:apply"}}}
}

func TestExecuteRejectsVersionMismatch(t *testing.T) {
	const digest = "aa"
	m := runtimeBackedManifest()
	srv, _ := operationServer(t, m, digest)
	approval := boundApproval(digest)
	approval.PluginVersion = "0.9.0" // the operator approved a plan produced by an older build

	err := srv.executePluginOperation(context.Background(), applier(), approval)
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("a version drift must refuse execution, got %v", err)
	}
}

func TestExecuteRejectsArtifactDigestMismatch(t *testing.T) {
	m := runtimeBackedManifest()
	srv, _ := operationServer(t, m, "current-digest")
	approval := boundApproval("approved-digest") // artifact was re-signed since approval

	err := srv.executePluginOperation(context.Background(), applier(), approval)
	if err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("an artifact digest change must refuse execution, got %v", err)
	}
}

func TestExecuteRejectsWhenServiceIsNoLongerRuntimeBacked(t *testing.T) {
	const digest = "aa"
	m := runtimeBackedManifest()
	m.Interfaces[0].Backing = plugin.BackingCore // engine moved back into core
	srv, _ := operationServer(t, m, digest)

	err := srv.executePluginOperation(context.Background(), applier(), boundApproval(digest))
	if err == nil || !strings.Contains(err.Error(), "runtime-backed") {
		t.Fatalf("a core-backed service must not be executed as a plugin artifact, got %v", err)
	}
}

func TestExecuteRejectsWhenPluginDisabled(t *testing.T) {
	const digest = "aa"
	m := runtimeBackedManifest()
	srv, st := operationServer(t, m, digest)
	if err := st.UpsertPluginInstallation(model.PluginInstallation{
		ID: m.ID, Name: m.Name, Type: m.Type, Status: model.PluginStatusDisabled,
	}); err != nil {
		t.Fatal(err)
	}

	err := srv.executePluginOperation(context.Background(), applier(), boundApproval(digest))
	if err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("a disabled plugin must not execute, got %v", err)
	}
}

func TestExecuteRejectsUnauthorizedTarget(t *testing.T) {
	const digest = "aa"
	m := runtimeBackedManifest()
	srv, _ := operationServer(t, m, digest)
	// A principal whose allowlist excludes the approved node: they can approve nothing
	// here, so execution must refuse before invoking the plugin.
	p := principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"network:apply"}, ServerAllowlist: []string{"node-z"}}}

	err := srv.executePluginOperation(context.Background(), p, boundApproval(digest))
	if err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("an unauthorized target must refuse execution, got %v", err)
	}
}

// nft/dns/agent-update approvals set neither Service nor Method, so the generic router
// must never mistake one for a plugin operation and hand it to the plugin executor.
func TestIsPluginOperationApprovalOnlyMatchesOperations(t *testing.T) {
	if isPluginOperationApproval(model.Approval{Plugin: "nftpolicy", Plan: "nft add rule ..."}) {
		t.Fatal("an nft approval was mistaken for a plugin operation")
	}
	if !isPluginOperationApproval(boundApproval("aa")) {
		t.Fatal("a plugin operation was not recognized")
	}
}
