package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
	"github.com/LatticeNet/lattice-server/internal/telemetry"
)

func TestExportedNameKeepsOnlyExportedIdentifiers(t *testing.T) {
	for name, want := range map[string]string{
		"UpsertNode":                 "UpsertNode",
		"UpsertNode.func1":           "UpsertNode",
		"UpsertNode.func1.2":         "UpsertNode",
		"MigrateOnce[...]":           "MigrateOnce",
		"persistState":               "",
		"replaceLineSecretsLocked":   "",
		"":                           "",
		"Weird-Name":                 "",
		"glob..func3":                "",
		"SyncLineClientTemplates":    "SyncLineClientTemplates",
		"UpsertGuardRealitySnapshot": "UpsertGuardRealitySnapshot",
	} {
		if got := exportedName(name); got != want {
			t.Errorf("exportedName(%q) = %q, want %q", name, got, want)
		}
	}
}

// Every whole-state write is counted under the store method that asked for
// it, never under Save, which most of them go through, so production can
// attribute its write rate.
func TestStateWritesAreCountedByTheStoreMethodThatAskedForThem(t *testing.T) {
	callers := func() map[string]uint64 {
		out := map[string]uint64{}
		for caller, st := range telemetry.CurrentSnapshot().StoreCallers {
			out[caller] = st.Count
		}
		return out
	}
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	before := callers()
	if err := s.UpsertNode(model.Node{ID: "node-a", Name: "a"}); err != nil {
		t.Fatal(err)
	}
	// Coming online is durable, so this beat writes.
	if _, err := s.UpdateMetrics("node-a", model.Metrics{}, "0.3.9", "", "", "", "", "", model.HostFacts{}); err != nil {
		t.Fatal(err)
	}
	if touched, err := s.TouchNodeToken("node-a", time.Now().Add(time.Hour), time.Minute); err != nil || !touched {
		t.Fatalf("token: touched=%v err=%v", touched, err)
	}
	// A quiet beat waits in memory, so Close has something to write.
	if _, err := s.UpdateMetrics("node-a", model.Metrics{}, "0.3.9", "", "", "", "", "", model.HostFacts{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	after := callers()
	for _, caller := range []string{"UpsertNode", "UpdateMetrics", "TouchNodeToken", "Close"} {
		if after[caller]-before[caller] != 1 {
			t.Errorf("writes counted under %s: %d, want 1 (all: %v)", caller, after[caller]-before[caller], after)
		}
	}
	if after["Save"] != 0 || after[telemetry.StoreCallerOther] != before[telemetry.StoreCallerOther] {
		t.Errorf("a write was counted under Save or other: %v", after)
	}
}
