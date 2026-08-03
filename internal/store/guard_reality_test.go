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
	if err := st.UpsertNode(model.Node{ID: "node-a", LatticeIdentityUUID: "generation-a"}); err != nil {
		t.Fatalf("upsert node-a: %v", err)
	}
	if err := st.UpsertNode(model.Node{ID: "node-b", LatticeIdentityUUID: "generation-b"}); err != nil {
		t.Fatalf("upsert node-b: %v", err)
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

	stored, changed, err := st.UpsertGuardRealitySnapshot("generation-b", first)
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
	stored, changed, err = st.UpsertGuardRealitySnapshot("generation-b", same)
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
	if _, _, err := st.UpsertGuardRealitySnapshot("generation-b", older); !errors.Is(err, ErrGuardRealityStale) {
		t.Fatalf("older snapshot error = %v, want ErrGuardRealityStale", err)
	}

	diffSameTime := same
	diffSameTime.Reality.ManagedSHA = strings.Repeat("b", 64)
	if _, _, err := st.UpsertGuardRealitySnapshot("generation-b", diffSameTime); !errors.Is(err, ErrGuardRealityStale) {
		t.Fatalf("same-time conflicting snapshot error = %v, want ErrGuardRealityStale", err)
	}

	newer := same
	newer.Reality.CollectedAt = collectedAt.Add(time.Minute)
	newer.Reality.ManagedSHA = strings.Repeat("c", 64)
	if _, changed, err := st.UpsertGuardRealitySnapshot("generation-b", newer); err != nil || !changed {
		t.Fatalf("newer snapshot changed=%v err=%v, want changed nil-error", changed, err)
	}

	nodeA := newer
	nodeA.Reality.NodeID = "node-a"
	if _, _, err := st.UpsertGuardRealitySnapshot("generation-a", nodeA); err != nil {
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
	if err := st.UpsertNode(model.Node{ID: "node-a", LatticeIdentityUUID: "generation-a"}); err != nil {
		t.Fatalf("upsert node-a: %v", err)
	}

	collectedAt := time.Date(2026, 7, 31, 13, 0, 0, 0, time.UTC)
	if _, _, err := st.UpsertGuardRealitySnapshot("generation-a", GuardRealitySnapshot{
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

func TestGuardRealitySnapshotPersistFailureDoesNotPublish(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	cipher := testCipher(t)
	st, err := OpenWithCipher(path, cipher)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	for _, node := range []model.Node{
		{ID: "node-a", LatticeIdentityUUID: "generation-a"},
		{ID: "node-b", LatticeIdentityUUID: "generation-b"},
	} {
		if err := st.UpsertNode(node); err != nil {
			t.Fatalf("upsert %s: %v", node.ID, err)
		}
	}

	collectedAt := time.Date(2026, 7, 31, 13, 0, 0, 0, time.UTC)
	first := GuardRealitySnapshot{
		Reality: model.GuardNodeReality{
			NodeID:      "node-a",
			ManagedSHA:  strings.Repeat("a", 64),
			CollectedAt: collectedAt,
		},
		ReceivedAt: collectedAt.Add(time.Second),
	}
	if _, _, err := st.UpsertGuardRealitySnapshot("generation-a", first); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}

	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatalf("install save-failure fixture: %v", err)
	}
	newer := first
	newer.Reality.CollectedAt = collectedAt.Add(time.Minute)
	newer.Reality.ManagedSHA = strings.Repeat("b", 64)
	newer.ReceivedAt = collectedAt.Add(time.Minute + time.Second)
	if _, _, err := st.UpsertGuardRealitySnapshot("generation-a", newer); err == nil {
		t.Fatal("replacement unexpectedly survived forced persist failure")
	}
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatalf("reinstall save-failure fixture: %v", err)
	}
	firstInsert := newer
	firstInsert.Reality.NodeID = "node-b"
	if _, _, err := st.UpsertGuardRealitySnapshot("generation-b", firstInsert); err == nil {
		t.Fatal("first insert unexpectedly survived forced persist failure")
	}
	if err := st.ReadyCheck(); err != nil {
		t.Fatalf("pre-rename failure degraded readiness: %v", err)
	}

	got, ok := st.GuardRealitySnapshot("node-a")
	if !ok || got.Reality.ManagedSHA != strings.Repeat("a", 64) {
		t.Fatalf("live snapshot changed after failed persist: ok=%v snapshot=%+v", ok, got)
	}
	if _, ok := st.GuardRealitySnapshot("node-b"); ok {
		t.Fatal("failed first insert was published to live state")
	}
	reopened, err := OpenWithCipher(path, cipher)
	if err != nil {
		t.Fatalf("reopen after failed persists: %v", err)
	}
	got, ok = reopened.GuardRealitySnapshot("node-a")
	if !ok || got.Reality.ManagedSHA != strings.Repeat("a", 64) {
		t.Fatalf("persisted snapshot changed after failed persist: ok=%v snapshot=%+v", ok, got)
	}
	if _, ok := reopened.GuardRealitySnapshot("node-b"); ok {
		t.Fatal("failed first insert reached persisted state")
	}

	if _, changed, err := st.UpsertGuardRealitySnapshot("generation-a", newer); err != nil || !changed {
		t.Fatalf("retry replacement changed=%v err=%v", changed, err)
	}
	if _, changed, err := st.UpsertGuardRealitySnapshot("generation-b", firstInsert); err != nil || !changed {
		t.Fatalf("retry first insert changed=%v err=%v", changed, err)
	}
	reopened, err = OpenWithCipher(path, cipher)
	if err != nil {
		t.Fatalf("reopen after retries: %v", err)
	}
	for nodeID, wantSHA := range map[string]string{
		"node-a": strings.Repeat("b", 64),
		"node-b": strings.Repeat("b", 64),
	} {
		got, ok := reopened.GuardRealitySnapshot(nodeID)
		if !ok || got.Reality.ManagedSHA != wantSHA {
			t.Fatalf("retried snapshot %s: ok=%v snapshot=%+v", nodeID, ok, got)
		}
	}
}

func TestGuardRealitySnapshotPostRenameFailurePublishesCommittedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	cipher := testCipher(t)
	st, err := OpenWithCipher(path, cipher)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := st.UpsertNode(model.Node{ID: "node-a", LatticeIdentityUUID: "generation-a"}); err != nil {
		t.Fatalf("upsert node: %v", err)
	}
	collectedAt := time.Date(2026, 7, 31, 13, 0, 0, 0, time.UTC)
	first := GuardRealitySnapshot{
		Reality: model.GuardNodeReality{
			NodeID:      "node-a",
			ManagedSHA:  strings.Repeat("a", 64),
			CollectedAt: collectedAt,
		},
		ReceivedAt: collectedAt.Add(time.Second),
	}
	if _, _, err := st.UpsertGuardRealitySnapshot("generation-a", first); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}
	if err := st.ReadyCheck(); err != nil {
		t.Fatalf("healthy persistence degraded readiness: %v", err)
	}

	newer := first
	newer.Reality.CollectedAt = collectedAt.Add(time.Minute)
	newer.Reality.ManagedSHA = strings.Repeat("b", 64)
	newer.ReceivedAt = collectedAt.Add(time.Minute + time.Second)
	st.syncParentDir = func(string) error { return errors.New("forced post-rename sync failure") }
	stored, changed, err := st.UpsertGuardRealitySnapshot("generation-a", newer)
	if !errors.Is(err, ErrGuardRealityDurabilityDegraded) || !changed {
		t.Fatalf("post-rename result changed=%v err=%v", changed, err)
	}
	if err := st.ReadyCheck(); err == nil {
		t.Fatal("post-rename sync failure left readiness healthy")
	}
	if stored.Reality.ManagedSHA != strings.Repeat("b", 64) {
		t.Fatalf("returned committed snapshot = %+v", stored)
	}
	got, ok := st.GuardRealitySnapshot("node-a")
	if !ok || got.Reality.ManagedSHA != strings.Repeat("b", 64) {
		t.Fatalf("live state did not publish committed snapshot: ok=%v snapshot=%+v", ok, got)
	}
	reopened, err := OpenWithCipher(path, cipher)
	if err != nil {
		t.Fatalf("reopen committed snapshot: %v", err)
	}
	got, ok = reopened.GuardRealitySnapshot("node-a")
	if !ok || got.Reality.ManagedSHA != strings.Repeat("b", 64) {
		t.Fatalf("reopened state did not contain committed snapshot: ok=%v snapshot=%+v", ok, got)
	}

	st.syncParentDir = syncDir
	confirmed := newer
	confirmed.Reality.CollectedAt = newer.Reality.CollectedAt.Add(time.Minute)
	confirmed.Reality.ManagedSHA = strings.Repeat("c", 64)
	confirmed.ReceivedAt = newer.ReceivedAt.Add(time.Minute)
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatalf("install degraded save-failure fixture: %v", err)
	}
	if _, _, err := st.UpsertGuardRealitySnapshot("generation-a", confirmed); err == nil {
		t.Fatal("pre-rename failure unexpectedly succeeded while durability was degraded")
	}
	if err := st.ReadyCheck(); err == nil {
		t.Fatal("pre-rename failure cleared durability-degraded readiness")
	}

	stored, changed, err = st.UpsertGuardRealitySnapshot("generation-a", newer)
	if err != nil || changed {
		t.Fatalf("committed retry changed=%v err=%v", changed, err)
	}
	if !stored.ReceivedAt.Equal(newer.ReceivedAt) {
		t.Fatalf("committed retry received_at = %s, want %s", stored.ReceivedAt, newer.ReceivedAt)
	}
	if err := st.ReadyCheck(); err == nil {
		t.Fatal("idempotent retry cleared durability-degraded readiness without a parent sync")
	}

	stored, changed, err = st.UpsertGuardRealitySnapshot("generation-a", confirmed)
	if err != nil || !changed {
		t.Fatalf("confirmed durable update changed=%v err=%v", changed, err)
	}
	if err := st.ReadyCheck(); err != nil {
		t.Fatalf("successful parent sync did not clear durability-degraded readiness: %v", err)
	}
	reopened, err = OpenWithCipher(path, cipher)
	if err != nil {
		t.Fatalf("reopen confirmed durable snapshot: %v", err)
	}
	got, ok = reopened.GuardRealitySnapshot("node-a")
	if !ok || got.Reality.ManagedSHA != strings.Repeat("c", 64) {
		t.Fatalf("reopened confirmed snapshot: ok=%v snapshot=%+v", ok, got)
	}
}

func TestGuardRealitySnapshotBindsNodeIdentityGeneration(t *testing.T) {
	st, err := Open("")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := st.UpsertNode(model.Node{ID: "node-a", LatticeIdentityUUID: "generation-old"}); err != nil {
		t.Fatalf("upsert old generation: %v", err)
	}
	snapshot := GuardRealitySnapshot{
		Reality: model.GuardNodeReality{
			NodeID:      "node-a",
			CollectedAt: time.Date(2026, 7, 31, 13, 0, 0, 0, time.UTC),
		},
		ReceivedAt: time.Date(2026, 7, 31, 13, 0, 1, 0, time.UTC),
	}
	if _, _, err := st.UpsertGuardRealitySnapshot("generation-old", snapshot); err != nil {
		t.Fatalf("upsert old generation snapshot: %v", err)
	}
	if _, ok, err := st.DeleteNode("node-a"); err != nil || !ok {
		t.Fatalf("delete old generation: ok=%v err=%v", ok, err)
	}
	if err := st.UpsertNode(model.Node{ID: "node-a", LatticeIdentityUUID: "generation-new"}); err != nil {
		t.Fatalf("upsert new generation: %v", err)
	}
	if _, _, err := st.UpsertGuardRealitySnapshot("generation-old", snapshot); !errors.Is(err, ErrGuardRealityNodeChanged) {
		t.Fatalf("old generation error = %v, want ErrGuardRealityNodeChanged", err)
	}
	if _, ok := st.GuardRealitySnapshot("node-a"); ok {
		t.Fatal("old generation report attached to replacement node")
	}
	if _, changed, err := st.UpsertGuardRealitySnapshot("generation-new", snapshot); err != nil || !changed {
		t.Fatalf("new generation upsert changed=%v err=%v", changed, err)
	}
}

func TestGuardRealitySnapshotCanonicalizesEmptyAndSetOrder(t *testing.T) {
	st, err := Open("")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	for _, nodeID := range []string{"node-empty", "node-order"} {
		if err := st.UpsertNode(model.Node{ID: nodeID, LatticeIdentityUUID: nodeID + "-generation"}); err != nil {
			t.Fatalf("upsert %s: %v", nodeID, err)
		}
	}
	collectedAt := time.Date(2026, 7, 31, 13, 0, 0, 0, time.UTC)
	empty := GuardRealitySnapshot{
		Reality:    model.GuardNodeReality{NodeID: "node-empty", CollectedAt: collectedAt},
		ReceivedAt: collectedAt.Add(time.Second),
	}
	if _, _, err := st.UpsertGuardRealitySnapshot("node-empty-generation", empty); err != nil {
		t.Fatalf("upsert omitted empties: %v", err)
	}
	empty.Reality.Listeners = []model.GuardListener{}
	empty.Reality.Interfaces = []model.GuardInterface{}
	empty.Reality.ForeignTables = []string{}
	if _, changed, err := st.UpsertGuardRealitySnapshot("node-empty-generation", empty); err != nil || changed {
		t.Fatalf("explicit empty retry changed=%v err=%v", changed, err)
	}

	ordered := GuardRealitySnapshot{
		Reality: model.GuardNodeReality{
			NodeID: "node-order",
			Listeners: []model.GuardListener{
				{Protocol: "udp", Port: 53, Address: "2001:db8::2"},
				{Protocol: "tcp", Port: 22, Address: "2001:db8::1"},
			},
			Interfaces: []model.GuardInterface{
				{Name: "eth1", Addresses: []string{"2001:db8::2/128", "2001:db8::1/128"}},
				{Name: "eth0", Up: true},
			},
			ForeignTables: []string{"inet z", "inet a"},
			CollectedAt:   collectedAt,
		},
		ReceivedAt: collectedAt.Add(time.Second),
	}
	if _, _, err := st.UpsertGuardRealitySnapshot("node-order-generation", ordered); err != nil {
		t.Fatalf("upsert unordered snapshot: %v", err)
	}
	ordered.Reality.Listeners[0], ordered.Reality.Listeners[1] = ordered.Reality.Listeners[1], ordered.Reality.Listeners[0]
	ordered.Reality.Interfaces[0], ordered.Reality.Interfaces[1] = ordered.Reality.Interfaces[1], ordered.Reality.Interfaces[0]
	ordered.Reality.Interfaces[0].Addresses = []string{}
	ordered.Reality.Interfaces[1].Addresses[0], ordered.Reality.Interfaces[1].Addresses[1] = ordered.Reality.Interfaces[1].Addresses[1], ordered.Reality.Interfaces[1].Addresses[0]
	ordered.Reality.ForeignTables[0], ordered.Reality.ForeignTables[1] = ordered.Reality.ForeignTables[1], ordered.Reality.ForeignTables[0]
	if _, changed, err := st.UpsertGuardRealitySnapshot("node-order-generation", ordered); err != nil || changed {
		t.Fatalf("reordered retry changed=%v err=%v", changed, err)
	}
}
