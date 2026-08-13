package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
	bolt "go.etcd.io/bbolt"
)

func testVpnUserRecords(id, secretValue string) (VpnUserPublicRecord, VpnUserSecretRecord) {
	return VpnUserPublicRecord{
			ID: id, Email: id + "@example.com", Enabled: true,
			Credentials: []VpnUserCredentialPublic{{Protocol: "trojan"}},
			Bindings:    []VpnUserLineBinding{}, CreatedAt: time.Unix(1_700_000_000, 0).UTC(),
		}, VpnUserSecretRecord{
			Credentials: []VpnUserCredentialSecret{{Protocol: "trojan", Password: secretValue}},
			SubID:       "sub-" + secretValue,
		}
}

const testRealityKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func testManagedLineRecords(i int) (ManagedLinePublicRecord, ManagedLineSecretRecord) {
	id := fmt.Sprintf("%08x-0000-4000-8000-%012x", i, i)
	return ManagedLinePublicRecord{LineUUID: id, NodeID: "node-a", RealityPublicKey: testRealityKey, Status: "applied"}, ManagedLineSecretRecord{RealityPrivateKey: testRealityKey}
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
	managedPublic, managedPrivate := testManagedLineRecords(1)
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
	if !ok || got.Credentials[0].Password != "credential-canary" || got.SubID != "sub-credential-canary" {
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
	if exported.VpnUserSecrets[public.ID].Credentials[0].Password != "credential-canary" {
		t.Fatalf("bbolt round trip lost secret: %+v", exported.VpnUserSecrets[public.ID])
	}
	if exported.ManagedLineSecrets[managedPublic.LineUUID].RealityPrivateKey != testRealityKey {
		t.Fatalf("bbolt round trip lost managed line secret: %+v", exported.ManagedLineSecrets[managedPublic.LineUUID])
	}
}

func TestLineSecretsReopen1024RecordsBeyondLegacyVaultCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	cipher := testCipher(t)
	s, err := OpenWithCipher(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	public, private := make(map[string]VpnUserPublicRecord, 1024), make(map[string]VpnUserSecretRecord, 1024)
	for i := 0; i < 1024; i++ {
		id := fmt.Sprintf("vpn-%04d", i)
		public[id], private[id] = testVpnUserRecords(id, "secret-"+id)
	}
	if err := s.ReplaceVpnUserRecords(public, private, nil); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWithCipher(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	gotPublic, gotPrivate := reopened.VpnUserRecords()
	if len(gotPublic) != 1024 || len(gotPrivate) != 1024 || gotPrivate["vpn-1023"].Credentials[0].Password != "secret-vpn-1023" {
		t.Fatalf("1024 reopen mismatch: public=%d private=%d last=%+v", len(gotPublic), len(gotPrivate), gotPrivate["vpn-1023"])
	}
}

func TestLineSecretLostKeyRestartFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenWithCipher(path, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	public, private := testVpnUserRecords("vpn-1", "credential-canary")
	if err := s.PutVpnUserRecord(public, private); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithCipher(path, testCipher(t)); err == nil {
		t.Fatal("restart with lost master key served encrypted line secrets")
	}
}

func TestLineSecretMigrationTenThousandRecordsUsesOneJSONCommit(t *testing.T) {
	for _, runtimeHot := range []bool{false, true} {
		t.Run(fmt.Sprintf("runtime_hot_%v", runtimeHot), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			s, err := OpenWithCipher(path, testCipher(t))
			if err != nil {
				t.Fatal(err)
			}
			if runtimeHot {
				if err := s.EnableRuntimeBoltHotStore(filepath.Join(t.TempDir(), "hot.db")); err != nil {
					t.Fatal(err)
				}
				defer s.Close()
			}
			before := s.testPersistCalls
			err = s.MigrateLineSecrets(func(source LineSecretMigrationSource) (LineSecretMigrationBuild, error) {
				for i := 0; i < 10_000; i++ {
					id := fmt.Sprintf("vpn-%05d", i)
					source.VpnUsers[id], source.VpnUserSecrets[id] = testVpnUserRecords(id, "secret-"+id)
					managedPublic, managedPrivate := testManagedLineRecords(i)
					source.ManagedLines[managedPublic.LineUUID], source.ManagedLineSecrets[managedPublic.LineUUID] = managedPublic, managedPrivate
				}
				return LineSecretMigrationBuild{VpnUsers: source.VpnUsers, VpnUserSecrets: source.VpnUserSecrets,
					ManagedLines: source.ManagedLines, ManagedLineSecrets: source.ManagedLineSecrets}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if calls := s.testPersistCalls - before; calls != 1 {
				t.Fatalf("migration persisted %d times, want exactly one", calls)
			}
		})
	}
}

func BenchmarkLineSecretMigrationLinear(b *testing.B) {
	for _, records := range []int{1_000, 10_000} {
		b.Run(fmt.Sprintf("records_%d", records), func(b *testing.B) {
			b.ReportAllocs()
			b.ReportMetric(float64(records*2), "typed-records/op")
			for n := 0; n < b.N; n++ {
				s, err := Open("")
				if err != nil {
					b.Fatal(err)
				}
				err = s.MigrateLineSecrets(func(source LineSecretMigrationSource) (LineSecretMigrationBuild, error) {
					for i := 0; i < records; i++ {
						id := fmt.Sprintf("vpn-%05d", i)
						source.VpnUsers[id], source.VpnUserSecrets[id] = testVpnUserRecords(id, "secret-"+id)
						managedPublic, managedPrivate := testManagedLineRecords(i)
						source.ManagedLines[managedPublic.LineUUID], source.ManagedLineSecrets[managedPublic.LineUUID] = managedPublic, managedPrivate
					}
					return LineSecretMigrationBuild{VpnUsers: source.VpnUsers, VpnUserSecrets: source.VpnUserSecrets,
						ManagedLines: source.ManagedLines, ManagedLineSecrets: source.ManagedLineSecrets}, nil
				})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestLineSecretMigrationNarrowlyPreservesPendingManagedLineApprovalBytes(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	pending := model.Approval{ID: "approval-managed-pending", NodeID: "node-a", Plugin: "singbox-managedline", Status: model.ApprovalPending, Plan: `{"private":"approval-canary"}`}
	if err := s.UpsertApproval(pending); err != nil {
		t.Fatal(err)
	}
	pending, _ = s.Approval(pending.ID)
	if err := s.MigrateLineSecrets(func(source LineSecretMigrationSource) (LineSecretMigrationBuild, error) {
		public, private := testVpnUserRecords("vpn-1", "credential-canary")
		source.VpnUsers[public.ID], source.VpnUserSecrets[public.ID] = public, private
		return LineSecretMigrationBuild{VpnUsers: source.VpnUsers, VpnUserSecrets: source.VpnUserSecrets,
			ManagedLines: source.ManagedLines, ManagedLineSecrets: source.ManagedLineSecrets}, nil
	}); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Approval(pending.ID)
	if !ok || !reflect.DeepEqual(got, pending) {
		t.Fatalf("pending managed-line approval changed during migration: got=%+v ok=%v", got, ok)
	}
}

func TestLineSecretMigrationFullBoltUsesExactlyOneUpdate(t *testing.T) {
	bs, err := OpenBoltState(filepath.Join(t.TempDir(), "state.db"), testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()
	state := emptyState()
	for i := 0; i < 10_000; i++ {
		id := fmt.Sprintf("vpn-%05d", i)
		state.VpnUsers[id], state.VpnUserSecrets[id] = testVpnUserRecords(id, "secret-"+id)
		managedPublic, managedPrivate := testManagedLineRecords(i)
		state.ManagedLines[managedPublic.LineUUID], state.ManagedLineSecrets[managedPublic.LineUUID] = managedPublic, managedPrivate
	}
	before := bs.testUpdateCalls
	if err := bs.ImportState(state); err != nil {
		t.Fatal(err)
	}
	if calls := bs.testUpdateCalls - before; calls != 1 {
		t.Fatalf("full Bolt migration used %d write transactions, want exactly one", calls)
	}
}

func TestRuntimeHotBoltContainsNoTypedLineSecretCanaries(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenWithCipher(filepath.Join(dir, "state.json"), testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	hotPath := filepath.Join(dir, "runtime.db")
	if err := s.EnableRuntimeBoltHotStore(hotPath); err != nil {
		t.Fatal(err)
	}
	public, private := testVpnUserRecords("public-canary", "private-canary")
	if err := s.PutVpnUserRecord(public, private); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(hotPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "public-canary") || strings.Contains(string(raw), "private-canary") {
		t.Fatal("runtime-hot Bolt contained typed line public/private canary")
	}
}

func TestLineSecretBoundsRejectRecord100001AndAggregate256MiB(t *testing.T) {
	tooMany := make(map[string]VpnUserPublicRecord, MaxVpnUserRecords+1)
	for i := 0; i <= MaxVpnUserRecords; i++ {
		id := fmt.Sprintf("vpn-%06d", i)
		tooMany[id] = VpnUserPublicRecord{ID: id}
	}
	if err := validateVpnUserCollections(tooMany, nil); err == nil || !strings.Contains(err.Error(), "more than 100000") {
		t.Fatalf("record 100001 was not rejected: %v", err)
	}

	const records = 17_000
	payload := strings.Repeat("x", 16_200)
	public := make(map[string]VpnUserPublicRecord, records)
	private := make(map[string]VpnUserSecretRecord, records)
	for i := 0; i < records; i++ {
		id := fmt.Sprintf("vpn-%05d", i)
		public[id] = VpnUserPublicRecord{ID: id, Credentials: []VpnUserCredentialPublic{{Protocol: "trojan"}}}
		private[id] = VpnUserSecretRecord{Credentials: []VpnUserCredentialSecret{{Protocol: "trojan", Password: "x"}}, SubID: payload}
	}
	if err := validateVpnUserCollections(public, private); err == nil || !strings.Contains(err.Error(), "aggregate encoded bytes") {
		t.Fatalf("aggregate secret collection beyond 256 MiB was not rejected: %v", err)
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
	if got, ok := store.VpnUserSecretRecord("vpn-1"); !ok || got.Credentials[0].Password != "credential-canary" {
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
	private.Credentials[0].Protocol = "vless"
	private.Credentials[0].Password = ""
	private.Credentials[0].UUID = "11111111-1111-4111-8111-111111111111"
	if err := validateVpnUserCollections(map[string]VpnUserPublicRecord{"vpn-1": public}, map[string]VpnUserSecretRecord{"vpn-1": private}); err == nil {
		t.Fatal("mismatched public/private protocol sets were accepted")
	}
	public, private = testVpnUserRecords("vpn-1", "credential-canary")
	public.Credentials[0].Protocol = " VLESS "
	private.Credentials[0].Protocol = " VLESS "
	if err := validateVpnUserCollections(map[string]VpnUserPublicRecord{"vpn-1": public}, map[string]VpnUserSecretRecord{"vpn-1": private}); err == nil {
		t.Fatal("noncanonical public/private protocols were accepted")
	}
}

func TestLineSecretValidationRejectsMalformedCredentialAndRealityMaterial(t *testing.T) {
	public, private := testVpnUserRecords("vpn-1", "credential-canary")
	cases := []struct {
		name   string
		mutate func(*VpnUserPublicRecord, *VpnUserSecretRecord)
	}{
		{name: "unsupported_protocol", mutate: func(p *VpnUserPublicRecord, s *VpnUserSecretRecord) {
			p.Credentials[0].Protocol, s.Credentials[0].Protocol = "unknown", "unknown"
		}},
		{name: "invalid_vless_uuid", mutate: func(p *VpnUserPublicRecord, s *VpnUserSecretRecord) {
			p.Credentials[0].Protocol, s.Credentials[0] = "vless", VpnUserCredentialSecret{Protocol: "vless", UUID: "not-a-uuid"}
		}},
		{name: "password_protocol_with_uuid", mutate: func(_ *VpnUserPublicRecord, s *VpnUserSecretRecord) {
			s.Credentials[0].UUID = "11111111-1111-4111-8111-111111111111"
		}},
		{name: "tuic_missing_password", mutate: func(p *VpnUserPublicRecord, s *VpnUserSecretRecord) {
			p.Credentials[0].Protocol = "tuic"
			s.Credentials[0] = VpnUserCredentialSecret{Protocol: "tuic", UUID: "11111111-1111-4111-8111-111111111111"}
		}},
		{name: "tuic_missing_uuid", mutate: func(p *VpnUserPublicRecord, s *VpnUserSecretRecord) {
			p.Credentials[0].Protocol = "tuic"
			s.Credentials[0] = VpnUserCredentialSecret{Protocol: "tuic", Password: "secret"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotPublic, gotPrivate := public, private
			gotPublic.Credentials = append([]VpnUserCredentialPublic(nil), public.Credentials...)
			gotPrivate.Credentials = append([]VpnUserCredentialSecret(nil), private.Credentials...)
			tc.mutate(&gotPublic, &gotPrivate)
			if err := validateVpnUserCollections(map[string]VpnUserPublicRecord{gotPublic.ID: gotPublic}, map[string]VpnUserSecretRecord{gotPublic.ID: gotPrivate}); err == nil {
				t.Fatal("malformed credential material was accepted")
			}
		})
	}
	managedPublic, managedPrivate := testManagedLineRecords(1)
	for _, tc := range []struct {
		name string
		pub  ManagedLinePublicRecord
		priv ManagedLineSecretRecord
	}{
		{name: "invalid_uuid", pub: func() ManagedLinePublicRecord { p := managedPublic; p.LineUUID = "not-a-uuid"; return p }(), priv: managedPrivate},
		{name: "invalid_public_key", pub: func() ManagedLinePublicRecord { p := managedPublic; p.RealityPublicKey = "bad"; return p }(), priv: managedPrivate},
		{name: "invalid_private_key", pub: managedPublic, priv: ManagedLineSecretRecord{RealityPrivateKey: "bad"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateManagedLineCollections(map[string]ManagedLinePublicRecord{tc.pub.LineUUID: tc.pub}, map[string]ManagedLineSecretRecord{tc.pub.LineUUID: tc.priv}); err == nil {
				t.Fatal("malformed managed line material was accepted")
			}
		})
	}
}

func TestFullBoltImportExportValidatesTypedSecretDomains(t *testing.T) {
	bs, err := OpenBoltState(filepath.Join(t.TempDir(), "state.db"), secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()
	invalid := emptyState()
	_, orphan := testVpnUserRecords("vpn-1", "secret")
	invalid.VpnUserSecrets["vpn-1"] = orphan
	before := bs.testUpdateCalls
	if err := bs.ImportState(invalid); err == nil || bs.testUpdateCalls != before {
		t.Fatalf("invalid import reached write transaction: err=%v calls=%d", err, bs.testUpdateCalls-before)
	}
	valid := emptyState()
	public, private := testVpnUserRecords("vpn-1", "secret")
	valid.VpnUsers[public.ID], valid.VpnUserSecrets[public.ID] = public, private
	if err := bs.ImportState(valid); err != nil {
		t.Fatal(err)
	}
	key, _ := boltStringKey(public.ID)
	if err := bs.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(boltBucketVpnUsers).Delete(key) }); err != nil {
		t.Fatal(err)
	}
	if _, err := bs.ExportState(); err == nil || !strings.Contains(err.Error(), "invalid vpn user secret collections") {
		t.Fatalf("corrupt full-Bolt export was accepted: %v", err)
	}
}

func TestTUICCredentialPreservesUUIDAndPasswordAcrossFullBolt(t *testing.T) {
	bs, err := OpenBoltState(filepath.Join(t.TempDir(), "state.db"), secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()
	state := emptyState()
	public := VpnUserPublicRecord{ID: "vpn-tuic", Credentials: []VpnUserCredentialPublic{{Protocol: "tuic"}}}
	private := VpnUserSecretRecord{Credentials: []VpnUserCredentialSecret{{Protocol: "tuic", UUID: "11111111-1111-4111-8111-111111111111", Password: "tuic-secret"}}}
	state.VpnUsers[public.ID], state.VpnUserSecrets[public.ID] = public, private
	if err := bs.ImportState(state); err != nil {
		t.Fatal(err)
	}
	exported, err := bs.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	got := exported.VpnUserSecrets[public.ID].Credentials[0]
	if got.UUID != private.Credentials[0].UUID || got.Password != private.Credentials[0].Password {
		t.Fatalf("TUIC full-Bolt round trip lost dual secrets: %+v", got)
	}
}

func TestOpenRejectsOrphanLineSecretCollections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	state := emptyState()
	_, private := testVpnUserRecords("vpn-1", "credential-canary")
	state.VpnUserSecrets["vpn-1"] = private
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithCipher(path, secret.Disabled()); err == nil || !strings.Contains(err.Error(), "invalid vpn user secret collections") {
		t.Fatalf("expected fail-closed startup validation, got %v", err)
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
	if gotPublic, gotPrivate, ok := store.VpnUserRecord("vpn-1"); !ok || gotPublic.ID != "vpn-1" || gotPrivate.Credentials[0].Password != "credential-canary" {
		t.Fatalf("committed state was not published: public=%+v private=%+v ok=%v", gotPublic, gotPrivate, ok)
	}
	if !errors.Is(store.ReadyCheck(), errStoreDurabilityDegraded) {
		t.Fatalf("committed durability warning did not degrade readiness: %v", store.ReadyCheck())
	}
}

func TestPutVpnUserRecordOwnsMonotonicSubscriptionGeneration(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	public, private := testVpnUserRecords("vpn-generation", "secret")
	public.SubscriptionGeneration = 99
	if err := s.PutVpnUserRecord(public, private); err != nil {
		t.Fatal(err)
	}
	got, gotSecret, ok := s.VpnUserRecord(public.ID)
	if !ok || got.SubscriptionGeneration != 1 {
		t.Fatalf("create generation = %d, want 1", got.SubscriptionGeneration)
	}

	got.Comment = "display-only change"
	got.SubscriptionGeneration = 500
	if err := s.PutVpnUserRecord(got, gotSecret); err != nil {
		t.Fatal(err)
	}
	unchanged, unchangedSecret, _ := s.VpnUserRecord(public.ID)
	if unchanged.SubscriptionGeneration != 1 {
		t.Fatalf("display-only write advanced generation to %d", unchanged.SubscriptionGeneration)
	}

	unchanged.Bindings = append(unchanged.Bindings, VpnUserLineBinding{LineHashID: "line-b", Enabled: true})
	if err := s.PutVpnUserRecord(unchanged, unchangedSecret); err != nil {
		t.Fatal(err)
	}
	bound, boundSecret, _ := s.VpnUserRecord(public.ID)
	if bound.SubscriptionGeneration != 2 {
		t.Fatalf("binding generation = %d, want 2", bound.SubscriptionGeneration)
	}

	boundSecret.Credentials[0].Password = "rotated-secret"
	if err := s.PutVpnUserRecord(bound, boundSecret); err != nil {
		t.Fatal(err)
	}
	rotated, _, _ := s.VpnUserRecord(public.ID)
	if rotated.SubscriptionGeneration != 3 {
		t.Fatalf("credential generation = %d, want 3", rotated.SubscriptionGeneration)
	}
}
