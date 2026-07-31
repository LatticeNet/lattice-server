package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestGuardRealitySnapshotLatestOnlyAndCopies(t *testing.T) {
	st, err := Open("")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	collectedAt := time.Date(2026, 7, 31, 13, 0, 0, 0, time.UTC)
	first := GuardRealitySnapshot{
		Reality: model.GuardNodeReality{
			NodeID:     "node-b",
			ManagedSHA: strings.Repeat("a", 64),
			Listeners: []model.GuardListener{{
				Protocol: "tcp",
				Port:     22,
				Address:  "2001:db8::10",
				Process:  "sshd",
			}},
			Interfaces: []model.GuardInterface{{
				Name:      "ens3",
				Addresses: []string{"2001:db8::10/128"},
				Up:        true,
			}},
			ForeignTables: []string{"inet docker"},
			NFTVersion:    "nftables v1.0.9",
			CollectedAt:   collectedAt,
		},
		ReceivedAt: collectedAt.Add(time.Second),
	}

	stored, changed, err := st.UpsertGuardRealitySnapshot(first)
	if err != nil {
		t.Fatalf("upsert first snapshot: %v", err)
	}
	if !changed {
		t.Fatalf("first snapshot was not marked changed")
	}
	if stored.Reality.NodeID != "node-b" {
		t.Fatalf("stored node id = %q", stored.Reality.NodeID)
	}

	first.Reality.Listeners[0].Process = "mutated-after-upsert"
	got, ok := st.GuardRealitySnapshot("node-b")
	if !ok {
		t.Fatalf("snapshot missing after upsert")
	}
	if got.Reality.Listeners[0].Process != "sshd" {
		t.Fatalf("snapshot aliases caller memory: process = %q", got.Reality.Listeners[0].Process)
	}
	got.Reality.Listeners[0].Process = "mutated-after-read"
	gotAgain, ok := st.GuardRealitySnapshot("node-b")
	if !ok {
		t.Fatalf("snapshot missing after read")
	}
	if gotAgain.Reality.Listeners[0].Process != "sshd" {
		t.Fatalf("read snapshot aliases store memory: process = %q", gotAgain.Reality.Listeners[0].Process)
	}

	same := first
	same.Reality.Listeners[0].Process = "sshd"
	same.ReceivedAt = collectedAt.Add(2 * time.Second)
	stored, changed, err = st.UpsertGuardRealitySnapshot(same)
	if err != nil {
		t.Fatalf("idempotent upsert returned error: %v", err)
	}
	if changed {
		t.Fatalf("idempotent upsert was marked changed")
	}
	if !stored.ReceivedAt.Equal(collectedAt.Add(time.Second)) {
		t.Fatalf("idempotent upsert changed received_at to %s", stored.ReceivedAt)
	}

	older := same
	older.Reality.CollectedAt = collectedAt.Add(-time.Second)
	if _, _, err := st.UpsertGuardRealitySnapshot(older); !errors.Is(err, ErrGuardRealityStale) {
		t.Fatalf("older snapshot error = %v, want ErrGuardRealityStale", err)
	}

	diffSameTime := same
	diffSameTime.Reality.ManagedSHA = strings.Repeat("b", 64)
	if _, _, err := st.UpsertGuardRealitySnapshot(diffSameTime); !errors.Is(err, ErrGuardRealityStale) {
		t.Fatalf("same-time conflicting snapshot error = %v, want ErrGuardRealityStale", err)
	}

	newer := same
	newer.Reality.CollectedAt = collectedAt.Add(time.Minute)
	newer.Reality.ManagedSHA = strings.Repeat("c", 64)
	if _, changed, err := st.UpsertGuardRealitySnapshot(newer); err != nil || !changed {
		t.Fatalf("newer snapshot changed=%v err=%v, want changed nil-error", changed, err)
	}

	nodeA := newer
	nodeA.Reality.NodeID = "node-a"
	if _, _, err := st.UpsertGuardRealitySnapshot(nodeA); err != nil {
		t.Fatalf("upsert node-a snapshot: %v", err)
	}
	all := st.GuardRealitySnapshots()
	if len(all) != 2 {
		t.Fatalf("snapshot count = %d, want 2", len(all))
	}
	if all[0].Reality.NodeID != "node-a" || all[1].Reality.NodeID != "node-b" {
		t.Fatalf("snapshots not sorted by node_id: %q, %q", all[0].Reality.NodeID, all[1].Reality.NodeID)
	}
}

func TestGuardRealitySnapshotPersistsPlaintextOperationalFacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	cipher := testCipher(t)
	st, err := OpenWithCipher(path, cipher)
	if err != nil {
		t.Fatalf("open encrypted store: %v", err)
	}

	collectedAt := time.Date(2026, 7, 31, 13, 0, 0, 0, time.UTC)
	if _, _, err := st.UpsertGuardRealitySnapshot(GuardRealitySnapshot{
		Reality: model.GuardNodeReality{
			NodeID:     "node-a",
			ManagedSHA: strings.Repeat("a", 64),
			Listeners: []model.GuardListener{{
				Protocol: "tcp",
				Port:     443,
				Address:  "2001:db8::20",
				Process:  "edge-proxy",
			}},
			CollectedAt: collectedAt,
		},
		ReceivedAt: collectedAt.Add(time.Second),
	}); err != nil {
		t.Fatalf("upsert snapshot: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted state: %v", err)
	}
	if !strings.Contains(string(raw), "guard_reality_snapshots") {
		t.Fatalf("persisted state missing guard_reality_snapshots collection")
	}
	if !strings.Contains(string(raw), "edge-proxy") {
		t.Fatalf("operational snapshot facts were unexpectedly encrypted or omitted")
	}
	if strings.Contains(string(raw), "Bearer ") {
		t.Fatalf("persisted state contains bearer credential material")
	}

	reopened, err := OpenWithCipher(path, cipher)
	if err != nil {
		t.Fatalf("reopen encrypted store: %v", err)
	}
	got, ok := reopened.GuardRealitySnapshot("node-a")
	if !ok {
		t.Fatalf("reopened store missing guard reality snapshot")
	}
	if got.Reality.Listeners[0].Process != "edge-proxy" {
		t.Fatalf("reopened process = %q, want edge-proxy", got.Reality.Listeners[0].Process)
	}
}
