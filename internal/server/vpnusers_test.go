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
