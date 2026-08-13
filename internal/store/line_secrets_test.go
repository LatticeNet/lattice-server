package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func testVpnUserRecords(id, secretValue string) (VpnUserPublicRecord, VpnUserSecretRecord) {
	return VpnUserPublicRecord{
			ID: id, Email: id + "@example.com", Enabled: true,
			Credentials: []VpnUserCredentialPublic{{Protocol: "vless", Flow: "xtls-rprx-vision"}},
			Bindings:    []VpnUserLineBinding{}, CreatedAt: time.Unix(1_700_000_000, 0).UTC(),
		}, VpnUserSecretRecord{
			Credentials: []VpnUserCredentialSecret{{Protocol: "vless", UUID: secretValue}},
			SubID:       "sub-" + secretValue,
		}
}

func TestVpnUserPrivateRecordsAreEncryptedAndBoltParityRoundTrips(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "state.json")
	cipher := testCipher(t)
	public, private := testVpnUserRecords("vpn-1", "credential-canary")
	jsonStore, err := OpenWithCipher(jsonPath, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := jsonStore.PutVpnUserRecord(public, private); err != nil {
		t.Fatal(err)
	}
	managedPublic := ManagedLinePublicRecord{LineUUID: "line-1", NodeID: "node-1", Status: "applied"}
	managedPrivate := ManagedLineSecretRecord{RealityPrivateKey: "reality-private-canary"}
	if err := jsonStore.PutManagedLineRecord(managedPublic, managedPrivate); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "credential-canary") || strings.Contains(string(raw), "sub-credential-canary") || strings.Contains(string(raw), "reality-private-canary") {
		t.Fatalf("typed vpn user secret leaked to JSON: %s", raw)
	}
	reopened, err := OpenWithCipher(jsonPath, cipher)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reopened.VpnUserSecretRecord("vpn-1")
	if !ok || got.Credentials[0].UUID != "credential-canary" || got.SubID != "sub-credential-canary" {
		t.Fatalf("JSON round trip lost secret: %+v, ok=%v", got, ok)
	}

	boltPath := filepath.Join(dir, "state.db")
	boltStore, err := OpenBoltState(boltPath, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer boltStore.Close()
	state := emptyState()
	state.VpnUsers[public.ID] = public
	state.VpnUserSecrets[public.ID] = private
	state.ManagedLines[managedPublic.LineUUID] = managedPublic
	state.ManagedLineSecrets[managedPublic.LineUUID] = managedPrivate
	if err := boltStore.ImportState(state); err != nil {
		t.Fatal(err)
	}
	boltRaw, err := os.ReadFile(boltPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(boltRaw), "credential-canary") || strings.Contains(string(boltRaw), "reality-private-canary") {
		t.Fatal("typed vpn user secret leaked to bbolt")
	}
	exported, err := boltStore.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if exported.VpnUserSecrets[public.ID].Credentials[0].UUID != "credential-canary" {
		t.Fatalf("bbolt round trip lost secret: %+v", exported.VpnUserSecrets[public.ID])
	}
	if exported.ManagedLineSecrets[managedPublic.LineUUID].RealityPrivateKey != "reality-private-canary" {
		t.Fatalf("bbolt round trip lost managed line secret: %+v", exported.ManagedLineSecrets[managedPublic.LineUUID])
	}
}

func TestReplaceVpnUserRecordsStagesLegacyRemovalAtomically(t *testing.T) {
	store, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutKV(model.KVEntry{Bucket: "plugin:latticenet.vpn-core", Key: "vpnuser/vpn-1", Value: "credential-canary"}); err != nil {
		t.Fatal(err)
	}
	public, private := testVpnUserRecords("vpn-1", "credential-canary")
	if err := store.ReplaceVpnUserRecords(
		map[string]VpnUserPublicRecord{public.ID: public},
		map[string]VpnUserSecretRecord{public.ID: private},
		[]LegacyKVKey{{Bucket: "plugin:latticenet.vpn-core", Key: "vpnuser/vpn-1"}},
	); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.KVEntry("plugin:latticenet.vpn-core", "vpnuser/vpn-1"); ok {
		t.Fatal("secret-bearing legacy KV record survived migration")
	}
	if got, ok := store.VpnUserSecretRecord("vpn-1"); !ok || got.Credentials[0].UUID != "credential-canary" {
		t.Fatalf("typed private record missing: %+v, ok=%v", got, ok)
	}
}

func TestVpnUserSecretBoundsFailClosed(t *testing.T) {
	public, private := testVpnUserRecords("vpn-1", "credential-canary")
	private.Credentials = make([]VpnUserCredentialSecret, MaxVpnUserCredentials+1)
	for i := range private.Credentials {
		private.Credentials[i] = VpnUserCredentialSecret{Protocol: string(rune('a' + i)), UUID: "x"}
	}
	store, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutVpnUserRecord(public, private); err == nil {
		t.Fatal("seventeenth credential was accepted")
	}
	_, oversized := testVpnUserRecords("vpn-2", strings.Repeat("x", MaxLineSecretRecordBytes))
	public.ID = "vpn-2"
	public.Email = "vpn-2@example.com"
	store, err = Open("")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutVpnUserRecord(public, oversized); err == nil {
		t.Fatal("oversized private record was accepted")
	}
}

func TestVpnUserRecordMutationsSerializeWithoutLostUpdates(t *testing.T) {
	store, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	const count = 64
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("vpn-%03d", i)
			public, private := testVpnUserRecords(id, fmt.Sprintf("secret-%03d", i))
			errs <- store.PutVpnUserRecord(public, private)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	public, private := store.VpnUserRecords()
	if len(public) != count || len(private) != count {
		t.Fatalf("concurrent mutations lost updates: public=%d private=%d", len(public), len(private))
	}
}

func TestVpnUserRecordValidationRejectsOrphansAndProtocolMismatch(t *testing.T) {
	public, private := testVpnUserRecords("vpn-1", "credential-canary")
	if err := validateVpnUserCollections(map[string]VpnUserPublicRecord{}, map[string]VpnUserSecretRecord{"vpn-1": private}); err == nil {
		t.Fatal("orphan private record was accepted")
	}
	private.Credentials[0].Protocol = "trojan"
	if err := validateVpnUserCollections(map[string]VpnUserPublicRecord{"vpn-1": public}, map[string]VpnUserSecretRecord{"vpn-1": private}); err == nil {
		t.Fatal("mismatched public/private protocol sets were accepted")
	}
}

func TestReplaceVpnUserRecordsPublishesCommittedStateOnParentSyncFailure(t *testing.T) {
	store, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	public, private := testVpnUserRecords("vpn-1", "credential-canary")
	store.syncParentDir = func(string) error { return errors.New("forced parent sync failure") }
	err = store.ReplaceVpnUserRecords(
		map[string]VpnUserPublicRecord{"vpn-1": public},
		map[string]VpnUserSecretRecord{"vpn-1": private}, nil,
	)
	if err == nil || !strings.Contains(err.Error(), "forced parent sync failure") {
		t.Fatalf("expected durability warning, got %v", err)
	}
	if gotPublic, gotPrivate, ok := store.VpnUserRecord("vpn-1"); !ok || gotPublic.ID != "vpn-1" || gotPrivate.Credentials[0].UUID != "credential-canary" {
		t.Fatalf("committed state was not published: public=%+v private=%+v ok=%v", gotPublic, gotPrivate, ok)
	}
	if !errors.Is(store.ReadyCheck(), errStoreDurabilityDegraded) {
		t.Fatalf("committed durability warning did not degrade readiness: %v", store.ReadyCheck())
	}
}
