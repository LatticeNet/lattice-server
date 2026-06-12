package store

import (
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestPluginLifecycleTransitionsArePersistedAndValidated(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}

	initial := model.PluginInstallation{
		ID:             "ops.bundle",
		Name:           "Ops Bundle",
		Type:           "system",
		Version:        "1.0.0",
		Publisher:      "latticenet",
		Capabilities:   []string{"node:read"},
		ArtifactSHA256: "abc123",
		BundlePath:     "/plugins/ops",
		Status:         model.PluginStatusVerified,
	}
	if err := s.UpsertPluginInstallation(initial); err != nil {
		t.Fatal(err)
	}
	got, ok := s.PluginInstallation("ops.bundle")
	if !ok {
		t.Fatal("expected plugin installation to be persisted")
	}
	if got.Status != model.PluginStatusVerified || got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() || got.VerifiedAt.IsZero() {
		t.Fatalf("unexpected verified lifecycle entry: %+v", got)
	}
	if got.Capabilities[0] != "node:read" {
		t.Fatalf("expected capabilities to persist, got %+v", got.Capabilities)
	}

	for _, status := range []string{model.PluginStatusInstalled, model.PluginStatusActive, model.PluginStatusDisabled, model.PluginStatusActive} {
		if err := s.SetPluginStatus("ops.bundle", status); err != nil {
			t.Fatalf("transition to %s failed: %v", status, err)
		}
	}
	got, ok = s.PluginInstallation("ops.bundle")
	if !ok || got.Status != model.PluginStatusActive || got.InstalledAt.IsZero() || got.ActivatedAt.IsZero() || got.DisabledAt.IsZero() {
		t.Fatalf("unexpected active lifecycle entry after transitions: ok=%v %+v", ok, got)
	}

	if err := s.SetPluginStatus("ops.bundle", model.PluginStatusVerified); err == nil || !strings.Contains(err.Error(), "invalid plugin status transition") {
		t.Fatalf("expected active->verified rejection, got %v", err)
	}
	if err := s.SetPluginStatus("missing.bundle", model.PluginStatusInstalled); err == nil || !strings.Contains(err.Error(), "plugin installation not found") {
		t.Fatalf("expected missing plugin rejection, got %v", err)
	}
}

func TestPluginLifecycleRejectsSkippingInstall(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertPluginInstallation(model.PluginInstallation{
		ID:           "skip.bundle",
		Name:         "Skip Bundle",
		Type:         "system",
		Capabilities: []string{"node:read"},
		Status:       model.PluginStatusVerified,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPluginStatus("skip.bundle", model.PluginStatusActive); err == nil {
		t.Fatal("expected verified->active transition to be rejected")
	}
}

func TestPluginInstallationsSortedByIDAndCopied(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"z.plugin", "a.plugin"} {
		if err := s.UpsertPluginInstallation(model.PluginInstallation{
			ID:           id,
			Name:         id,
			Type:         "system",
			Capabilities: []string{"node:read"},
			Status:       model.PluginStatusVerified,
		}); err != nil {
			t.Fatal(err)
		}
	}
	list := s.PluginInstallations()
	if len(list) != 2 || list[0].ID != "a.plugin" || list[1].ID != "z.plugin" {
		t.Fatalf("expected sorted installations, got %+v", list)
	}
	list[0].Capabilities[0] = "mutated"
	got, _ := s.PluginInstallation("a.plugin")
	if got.Capabilities[0] != "node:read" {
		t.Fatalf("store returned mutable capability slice: %+v", got.Capabilities)
	}
}
