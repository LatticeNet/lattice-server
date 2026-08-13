package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestVpnUserMigrationIdempotent(t *testing.T) {
	srv := newLinesTestServer(t)
	if err := srv.store.UpsertProxyUser(model.ProxyUser{
		ID: "pu-1", Name: "alice@example.com", Enabled: true,
		UUID: "11111111-1111-4111-8111-111111111111", SubToken: "tok-alice",
	}); err != nil {
		t.Fatal(err)
	}
	srv.migrateProxyUsersToVpnUsers()
	srv.migrateProxyUsersToVpnUsers() // second run must not duplicate

	users := srv.listVpnUsers()
	if len(users) != 1 {
		t.Fatalf("want 1 migrated user, got %d", len(users))
	}
	u := users[0]
	if u.ID != "vu_pu-1" || u.Email != "alice@example.com" || u.MigratedFromProxyUser != "pu-1" {
		t.Fatalf("migrated identity wrong: %+v", u)
	}
	if len(u.Credentials) != 1 || u.Credentials[0].Protocol != "vless" ||
		u.Credentials[0].UUID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("migrated credential wrong: %+v", u.Credentials)
	}
}

func TestTUICCredentialPreservesUUIDAndPasswordAcrossNormalizeMigrationAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := store.OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	const uuid = "11111111-1111-4111-8111-111111111111"
	credentials, err := srv.normalizeCredentials([]VpnCredential{{Protocol: "tuic", UUID: uuid, Password: "created-secret"}})
	if err != nil || len(credentials) != 1 || credentials[0].UUID != uuid || credentials[0].Password != "created-secret" {
		t.Fatalf("normalize lost TUIC dual secret: %+v err=%v", credentials, err)
	}
	user := VpnUser{ID: "vpn-tuic", Email: "tuic@example.com", Enabled: true, Credentials: credentials}
	if err := srv.putVpnUser(user); err != nil {
		t.Fatal(err)
	}
	credentials, err = srv.normalizeCredentials([]VpnCredential{{Protocol: "tuic", UUID: uuid, Password: "updated-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	user.Credentials = credentials
	if err := srv.putVpnUser(user); err != nil {
		t.Fatal(err)
	}
	legacy := VpnUser{ID: "vpn-tuic-legacy", Email: "legacy-tuic@example.com", Enabled: true,
		Credentials: []VpnCredential{{Protocol: "tuic", UUID: "22222222-2222-4222-8222-222222222222", Password: "legacy-secret"}}}
	raw, _ := json.Marshal(legacy)
	if err := st.PutKV(model.KVEntry{Bucket: vpnCoreKVBucket, Key: vpnUserKey(legacy.ID), Value: string(raw)}); err != nil {
		t.Fatal(err)
	}
	if err := srv.migrateProxyUsersToVpnUsers(); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	srv, err = New(Options{Store: reopened, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]VpnCredential{
		user.ID:   {UUID: uuid, Password: "updated-secret"},
		legacy.ID: {UUID: "22222222-2222-4222-8222-222222222222", Password: "legacy-secret"},
	} {
		got, ok := srv.getVpnUser(id)
		if !ok || len(got.Credentials) != 1 || got.Credentials[0].UUID != want.UUID || got.Credentials[0].Password != want.Password {
			t.Fatalf("TUIC reopen lost %s dual secret: %+v ok=%v", id, got, ok)
		}
		payload, err := lineUserCredential(got, "tuic", "user-tuic")
		if err != nil || payload.UUID != want.UUID || payload.Password != want.Password {
			t.Fatalf("line-user TUIC payload lost %s dual secret: %+v err=%v", id, payload, err)
		}
	}
	for _, missing := range []VpnCredential{{Protocol: "tuic", UUID: uuid}, {Protocol: "tuic", Password: "secret"}} {
		if _, err := srv.normalizeCredentials([]VpnCredential{missing}); err == nil {
			t.Fatalf("normalize accepted incomplete TUIC credential: %+v", missing)
		}
	}
}

func TestLineSecretMigrationPreservesPendingManagedLineApproval(t *testing.T) {
	key := make([]byte, secret.KeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cipher, err := secret.NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := store.OpenWithCipher(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	legacy := VpnUser{ID: "vpn-restart", Email: "restart@example.com", Enabled: true,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: "11111111-1111-4111-8111-111111111111"}}, SubID: "restart-sub", Bindings: []LineBinding{}}
	approvalID := "approval-managed-pre-migration"
	managed := managedLineDef{LineUUID: "22222222-2222-4222-8222-222222222222", NodeID: "node-migration", Tag: "managed-restart",
		Port: 24443, SNI: "example.com", HandshakeServer: "example.com", HandshakePort: 443, RealityPrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		RealityPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ShortID: "abcdef12", UserID: legacy.ID, Status: managedLineStatusPlanned, ApprovalID: approvalID}
	managed.LineHashID = managedLinePlannedHash(managed.NodeID, managed.Tag, managed.Port)
	managed.UserName = userLineName(legacy.ID, managed.LineUUID)
	managed.FragmentSHA256, err = managedLineFragmentSHA(managed, lineUserCredentialPayload{
		Name: managed.UserName, UUID: legacy.Credentials[0].UUID,
	})
	if err != nil {
		t.Fatal(err)
	}
	planJSON, err := json.Marshal(managedLinePlan{
		NodeID: managed.NodeID, LineUUID: managed.LineUUID, LineHashID: managed.LineHashID,
		Tag: managed.Tag, Port: managed.Port, SNI: managed.SNI,
		HandshakeServer: managed.HandshakeServer, HandshakePort: managed.HandshakePort,
		RealityPublicKey: managed.RealityPublicKey, ShortID: managed.ShortID,
		UserID: managed.UserID, UserName: managed.UserName, FragmentSHA256: managed.FragmentSHA256,
		Summary: "pre-migration pending managed-line approval",
	})
	if err != nil {
		t.Fatal(err)
	}
	pending := model.Approval{
		ID: approvalID, NodeID: managed.NodeID, Plugin: singBoxManagedLinePlugin,
		Action: managedLineActionPrefix + managed.FragmentSHA256, Plan: string(planJSON), Status: model.ApprovalPending,
		ActorID: "pre-migration-planner", PluginVersion: managedLinePluginVersion,
		Service: managedLineService, Method: managedLineMethod,
		RequestSHA256: managedLineRequestSHA(legacy.ID, managed.NodeID, managed.Port),
		Targets:       []string{managed.NodeID}, ArtifactDigest: managed.FragmentSHA256,
	}
	userJSON, _ := json.Marshal(legacy)
	managedJSON, _ := json.Marshal(managed)
	if err := st.PutKV(model.KVEntry{Bucket: vpnCoreKVBucket, Key: vpnUserKey(legacy.ID), Value: string(userJSON)}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutKV(model.KVEntry{Bucket: managedLineDefBucket, Key: managed.LineUUID, Value: string(managedJSON)}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertApproval(pending); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.migrateProxyUsersToVpnUsers(); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.OpenWithCipher(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	srv, err = New(Options{Store: reopened, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	preserved, ok := srv.store.Approval(approvalID)
	if !ok || preserved.Status != model.ApprovalPending || preserved.Plan != pending.Plan || preserved.ArtifactDigest != pending.ArtifactDigest {
		t.Fatalf("migration/restart changed pending managed-line approval: %+v ok=%v", preserved, ok)
	}
	seedManagedLineNode(t, srv, managed.NodeID, realityInventoryLines())
	planSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(preserved.Plan)))
	approved, err := srv.approveApprovalCore(context.Background(), lineUserTestPrincipal(), preserved, true, planSHA)
	if err != nil || approved.Status != model.ApprovalApproved {
		t.Fatalf("pre-migration pending managed-line approval could not execute after restart: approval=%+v err=%v", approved, err)
	}
	managedTaskFound := false
	for _, task := range srv.store.Tasks() {
		if task.ApprovalID == approvalID && strings.Contains(task.Script, "systemctl restart sing-box") {
			managedTaskFound = true
		}
	}
	if !managedTaskFound {
		t.Fatal("pre-migration managed-line approval did not queue its executable apply task")
	}

	seedLinesFixture(t, srv)
	groups := srv.buildLineGroups()
	lineHash := groups[0].Lines[0].LineHashID
	if _, err := srv.vpnCoreUsersAdminRPC(context.Background(), "bind", []byte(`{"user_id":"`+legacy.ID+`","line_hash_id":"`+lineHash+`"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.vpnUserRotateCredential(lineUserTestPrincipal(), []byte(`{"user_id":"`+legacy.ID+`","protocol":"vless"}`)); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := srv.managedLineDefByUUID(managed.LineUUID); err != nil || !ok || got.RealityPrivateKey != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("managed definition after restart: %+v ok=%v err=%v", got, ok, err)
	}
	if subscriptions := srv.buildSubscriptions(); len(subscriptions) == 0 {
		t.Fatal("migrated user could not render a subscription summary after restart")
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	secondRestart, err := store.OpenWithCipher(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer secondRestart.Close()
	srv, err = New(Options{Store: secondRestart, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	userAfter, ok := srv.getVpnUser(legacy.ID)
	if !ok || len(userAfter.Credentials) == 0 || userAfter.Credentials[0].UUID == legacy.Credentials[0].UUID || len(userAfter.Bindings) == 0 {
		t.Fatalf("second restart lost rotated credential/binding: %+v ok=%v", userAfter, ok)
	}
	approvedAfter, ok := srv.store.Approval(approvalID)
	if !ok || approvedAfter.Status != model.ApprovalApproved {
		t.Fatalf("second restart lost managed-line approval: %+v ok=%v", approvedAfter, ok)
	}
	if subscriptions := srv.buildSubscriptions(); len(subscriptions) == 0 {
		t.Fatal("second restart could not render migrated subscription")
	}
}

func TestVpnUserLegacyKVSecretMigrationIsFailClosedAndIdempotent(t *testing.T) {
	srv := newLinesTestServer(t)
	legacy := VpnUser{
		ID: "vpn-legacy", Email: "legacy@example.com", Enabled: true,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: "33333333-3333-4333-8333-333333333333"}},
		Bindings:    []LineBinding{}, SubID: "subscription-canary",
	}
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.store.PutKV(model.KVEntry{Bucket: vpnCoreKVBucket, Key: vpnUserKey(legacy.ID), Value: string(raw)}); err != nil {
		t.Fatal(err)
	}
	if err := srv.migrateProxyUsersToVpnUsers(); err != nil {
		t.Fatal(err)
	}
	if err := srv.migrateProxyUsersToVpnUsers(); err != nil {
		t.Fatalf("second migration was not idempotent: %v", err)
	}
	if _, ok := srv.store.KVEntry(vpnCoreKVBucket, vpnUserKey(legacy.ID)); ok {
		t.Fatal("secret-bearing legacy KV entry survived migration")
	}
	got, ok := srv.getVpnUser(legacy.ID)
	if !ok || got.Credentials[0].UUID != "33333333-3333-4333-8333-333333333333" || got.SubID != "subscription-canary" {
		t.Fatalf("typed migration lost secret material: %+v, ok=%v", got, ok)
	}
	public, ok := srv.store.VpnUserPublicRecord(legacy.ID)
	if !ok {
		t.Fatal("typed public record missing")
	}
	publicJSON, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(publicJSON), "credential-canary") || strings.Contains(string(publicJSON), "subscription-canary") {
		t.Fatalf("public record contains secret material: %s", publicJSON)
	}
}

func TestLineSecretMigrationMovesVpnUserAndManagedLineInOneTypedTransition(t *testing.T) {
	srv := newLinesTestServer(t)
	user := VpnUser{
		ID: "vpn-legacy-pair", Email: "pair@example.com", Enabled: true,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: "44444444-4444-4444-8444-444444444444"}},
		Bindings:    []LineBinding{},
	}
	managed := managedLineDef{
		LineUUID: "11111111-1111-4111-8111-111111111111", NodeID: "node-a", Tag: "managed-pair",
		RealityPrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", RealityPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Status: managedLineStatusApplied,
	}
	userJSON, _ := json.Marshal(user)
	managedJSON, _ := json.Marshal(managed)
	if err := srv.store.PutKV(model.KVEntry{Bucket: vpnCoreKVBucket, Key: vpnUserKey(user.ID), Value: string(userJSON)}); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.PutKV(model.KVEntry{Bucket: managedLineDefBucket, Key: managed.LineUUID, Value: string(managedJSON)}); err != nil {
		t.Fatal(err)
	}
	if err := srv.migrateProxyUsersToVpnUsers(); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.store.KVEntry(vpnCoreKVBucket, vpnUserKey(user.ID)); ok {
		t.Fatal("legacy vpn user survived unified migration")
	}
	if _, ok := srv.store.KVEntry(managedLineDefBucket, managed.LineUUID); ok {
		t.Fatal("legacy managed line survived unified migration")
	}
	gotUser, ok := srv.getVpnUser(user.ID)
	if !ok || gotUser.Credentials[0].UUID != "44444444-4444-4444-8444-444444444444" {
		t.Fatalf("vpn user secret missing after unified migration: %+v", gotUser)
	}
	gotManaged, ok, err := srv.managedLineDefByUUID(managed.LineUUID)
	if err != nil || !ok || gotManaged.RealityPrivateKey != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("managed line secret missing after unified migration: %+v ok=%v err=%v", gotManaged, ok, err)
	}
}

func TestVpnUserAdminRPCCRUDAndBind(t *testing.T) {
	srv := newLinesTestServer(t)
	seedLinesFixture(t, srv) // node-a + managed vless:443 line to bind against
	ctx := context.Background()

	// create — vless uuid auto-generated, trojan password provided
	raw, err := srv.vpnCoreUsersAdminRPC(ctx, "create",
		[]byte(`{"email":"bob@example.com","name":"Bob","credentials":[{"protocol":"vless"},{"protocol":"trojan","password":"s3cret"}]}`))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var created struct {
		User vpnUserView `json:"user"`
	}
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatalf("create decode: %v", err)
	}
	uid := created.User.ID
	if uid == "" || created.User.Email != "bob@example.com" || len(created.User.Credentials) != 2 {
		t.Fatalf("create result wrong: %+v", created.User)
	}
	for _, c := range created.User.Credentials {
		if !c.HasSecret {
			t.Fatalf("credential %q should report has_secret", c.Protocol)
		}
	}

	// stored credential actually carries the secret (redaction is only at the boundary)
	stored, ok := srv.getVpnUser(uid)
	if !ok {
		t.Fatal("user not persisted")
	}
	var vlessUUID string
	for _, c := range stored.Credentials {
		if c.Protocol == "vless" {
			vlessUUID = c.UUID
		}
	}
	if vlessUUID == "" {
		t.Fatal("vless uuid was not auto-generated/stored")
	}

	// list — redacted: the generated uuid and the trojan password must NOT leak
	rawList, err := srv.vpnCoreUsersRPC(ctx, "list", nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if strings.Contains(string(rawList), vlessUUID) || strings.Contains(string(rawList), "s3cret") {
		t.Fatalf("read RPC leaked secret material:\n%s", rawList)
	}

	// bind to a real line
	lineHash := srv.buildLineGroups()[0].Lines[0].LineHashID
	if _, err := srv.vpnCoreUsersAdminRPC(ctx, "bind",
		[]byte(`{"user_id":"`+uid+`","line_hash_id":"`+lineHash+`"}`)); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if u, _ := srv.getVpnUser(uid); len(u.Bindings) != 1 || u.Bindings[0].LineHashID != lineHash {
		t.Fatalf("bind not stored: %+v", u.Bindings)
	}

	// bind to an unknown line -> error
	if _, err := srv.vpnCoreUsersAdminRPC(ctx, "bind",
		[]byte(`{"user_id":"`+uid+`","line_hash_id":"line_does_not_exist"}`)); err == nil {
		t.Fatal("bind to unknown line should error")
	}

	// unbind
	if _, err := srv.vpnCoreUsersAdminRPC(ctx, "unbind",
		[]byte(`{"user_id":"`+uid+`","line_hash_id":"`+lineHash+`"}`)); err != nil {
		t.Fatalf("unbind: %v", err)
	}
	if u, _ := srv.getVpnUser(uid); len(u.Bindings) != 0 {
		t.Fatalf("unbind left bindings: %+v", u.Bindings)
	}

	// duplicate email -> error
	if _, err := srv.vpnCoreUsersAdminRPC(ctx, "create", []byte(`{"email":"bob@example.com"}`)); err == nil {
		t.Fatal("duplicate email should error")
	}
	// bad protocol -> error
	if _, err := srv.vpnCoreUsersAdminRPC(ctx, "create",
		[]byte(`{"email":"c@example.com","credentials":[{"protocol":"telnet"}]}`)); err == nil {
		t.Fatal("unsupported protocol should error")
	}
	// invalid email -> error
	if _, err := srv.vpnCoreUsersAdminRPC(ctx, "create", []byte(`{"email":"not-an-email"}`)); err == nil {
		t.Fatal("invalid email should error")
	}

	// delete
	if _, err := srv.vpnCoreUsersAdminRPC(ctx, "delete", []byte(`{"id":"`+uid+`"}`)); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := srv.getVpnUser(uid); ok {
		t.Fatal("user not deleted")
	}
}
