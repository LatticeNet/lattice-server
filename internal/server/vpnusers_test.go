package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestVpnUserMigrationIdempotent(t *testing.T) {
	srv := newLinesTestServer(t)
	if err := srv.store.UpsertProxyUser(model.ProxyUser{
		ID: "pu-1", Name: "alice@example.com", Enabled: true,
		UUID: "11111111-1111-1111-1111-111111111111", SubToken: "tok-alice",
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
		u.Credentials[0].UUID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("migrated credential wrong: %+v", u.Credentials)
	}
}

func TestVpnUserLegacyKVSecretMigrationIsFailClosedAndIdempotent(t *testing.T) {
	srv := newLinesTestServer(t)
	legacy := VpnUser{
		ID: "vpn-legacy", Email: "legacy@example.com", Enabled: true,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: "credential-canary"}},
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
	if !ok || got.Credentials[0].UUID != "credential-canary" || got.SubID != "subscription-canary" {
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
		Credentials: []VpnCredential{{Protocol: "vless", UUID: "credential-pair-canary"}},
		Bindings:    []LineBinding{},
	}
	managed := managedLineDef{
		LineUUID: "11111111-1111-4111-8111-111111111111", NodeID: "node-a", Tag: "managed-pair",
		RealityPrivateKey: "reality-pair-canary", RealityPublicKey: "public", Status: managedLineStatusApplied,
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
	if !ok || gotUser.Credentials[0].UUID != "credential-pair-canary" {
		t.Fatalf("vpn user secret missing after unified migration: %+v", gotUser)
	}
	gotManaged, ok, err := srv.managedLineDefByUUID(managed.LineUUID)
	if err != nil || !ok || gotManaged.RealityPrivateKey != "reality-pair-canary" {
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
