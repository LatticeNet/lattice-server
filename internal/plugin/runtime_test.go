package plugin

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestRuntimeManagerArmsLoadedPluginWithoutExecutingArtifact(t *testing.T) {
	m := NewRuntimeManager(HostServices{})
	loaded := Loaded{
		Manifest: Manifest{
			ID:           "ops.bundle",
			Name:         "Ops",
			Type:         TypeSystem,
			Capabilities: []string{"node:read", "log:write"},
		},
		Capabilities: []string{"log:write", "node:read"},
		BundlePath:   "/plugins/ops",
	}

	rt, err := m.Start(context.Background(), loaded)
	if err != nil {
		t.Fatal(err)
	}
	if rt.PluginID != "ops.bundle" || rt.State != RuntimeStateArmed || rt.StartedAt.IsZero() || rt.UpdatedAt.IsZero() {
		t.Fatalf("unexpected runtime state: %+v", rt)
	}
	encoded, err := json.Marshal(rt)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "bundle_path") || strings.Contains(string(encoded), "/plugins/ops") {
		t.Fatalf("runtime status must not expose bundle path: %s", encoded)
	}
	if !m.IsArmed("ops.bundle") {
		t.Fatal("expected plugin to be armed")
	}
}

func TestRuntimeManagerRejectsInvalidLoadedPlugin(t *testing.T) {
	m := NewRuntimeManager(HostServices{})
	_, err := m.Start(context.Background(), Loaded{
		Manifest: Manifest{
			ID:           "bad.bundle",
			Name:         "Bad",
			Type:         TypeWorker,
			Capabilities: []string{"network:apply"},
		},
		Capabilities: []string{"network:apply"},
	})
	if err == nil {
		t.Fatal("expected invalid loaded manifest to be rejected")
	}
	if m.IsArmed("bad.bundle") {
		t.Fatal("invalid plugin must not be armed")
	}
}

func TestRuntimeManagerStopAndSnapshotAreSafe(t *testing.T) {
	m := NewRuntimeManager(HostServices{})
	loaded := Loaded{
		Manifest: Manifest{
			ID:           "log.bundle",
			Name:         "Log",
			Type:         TypeSystem,
			Capabilities: []string{"log:write", "worker:route"},
		},
		Capabilities: []string{"log:write", "worker:route"},
	}
	if _, err := m.Start(context.Background(), loaded); err != nil {
		t.Fatal(err)
	}
	first := m.Snapshot()
	if got := first["log.bundle"]; got.State != RuntimeStateArmed {
		t.Fatalf("expected armed snapshot, got %+v", got)
	}
	delete(first, "log.bundle")
	if !m.IsArmed("log.bundle") {
		t.Fatal("mutating snapshot must not mutate manager")
	}

	stopped, err := m.Stop("log.bundle", "operator disabled plugin")
	if err != nil {
		t.Fatal(err)
	}
	if stopped.State != RuntimeStateStopped || stopped.Message != "operator disabled plugin" || stopped.StoppedAt.IsZero() {
		t.Fatalf("unexpected stopped runtime: %+v", stopped)
	}
	if m.IsArmed("log.bundle") {
		t.Fatal("stopped plugin must not remain armed")
	}
}
