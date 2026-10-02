package server

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Every boot runs migrateProxyUsersToVpnUsers, which derives vu_<id> for each
// legacy proxy user that has no identity yet and copies its sub token into
// SubID. Deleting a migrated identity removed only the identity record and
// left the legacy proxy user behind, so the next boot found a legacy user
// with no identity and created it again, old token and all. Delete has to
// survive a restart.
func TestADeletedMigratedIdentityStaysDeletedAcrossARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	const legacyToken = "legacy-sub-token-alice-0123456789"
	boot := func(t *testing.T) (*Server, *store.Store) {
		t.Helper()
		st, err := store.OpenWithCipher(path, secret.Disabled())
		if err != nil {
			t.Fatal(err)
		}
		srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
		if err != nil {
			t.Fatal(err)
		}
		return srv, st
	}

	srv, st := boot(t)
	if err := st.UpsertProxyUser(model.ProxyUser{
		ID: "pu-alice", Name: "alice@example.com", Enabled: true,
		UUID: "11111111-1111-4111-8111-111111111111", SubToken: legacyToken,
	}); err != nil {
		t.Fatal(err)
	}
	if err := srv.migrateProxyUsersToVpnUsers(); err != nil {
		t.Fatal(err)
	}
	migrated, ok := srv.getVpnUser("vu_pu-alice")
	if !ok || migrated.MigratedFromProxyUser != "pu-alice" || migrated.SubID != legacyToken {
		t.Fatalf("fixture: want vu_pu-alice migrated with the legacy token, got %+v ok=%v", migrated, ok)
	}
	if _, err := srv.vpnCoreUsersAdminDispatch(context.Background(), "delete", mustJSON(t, map[string]string{"id": "vu_pu-alice"})); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := st.ProxyUser("pu-alice"); ok {
		t.Fatal("deleting the migrated identity must delete the legacy proxy user it was derived from")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// The restart: a new server on the same state runs the boot migration.
	srv, st = boot(t)
	defer st.Close()
	if u, ok := srv.getVpnUser("vu_pu-alice"); ok {
		t.Fatalf("the deleted identity came back at boot: %+v", u)
	}
	for _, u := range srv.listVpnUsers() {
		if u.SubID == legacyToken {
			t.Fatalf("identity %s carries the deleted identity's old token", u.ID)
		}
	}
	for _, pu := range st.ProxyUsers() {
		if pu.SubToken == legacyToken {
			t.Fatalf("proxy user %s still holds the deleted identity's old token", pu.ID)
		}
	}
}

// A native identity's delete already removed its usage projection, the proxy
// user stored under the identity's own id. That stays true, and a migrated
// identity's delete removes such a projection too: left behind, the boot
// migration would read it as a legacy user and derive vu_<identity id>.
func TestDeletingAnIdentityLeavesNoProxyUserForTheMigrationToRevive(t *testing.T) {
	for _, tc := range []struct {
		name     string
		identity VpnUser
		legacy   []string
	}{
		{"native", VpnUser{ID: "vpnuser_native00000001", Email: "n@example.com", Enabled: true,
			Credentials: []VpnCredential{{Protocol: "vless", UUID: "22222222-2222-4222-8222-222222222222"}}}, []string{"vpnuser_native00000001"}},
		{"migrated", VpnUser{ID: "vu_pu-bob", Email: "b@example.com", Enabled: true, MigratedFromProxyUser: "pu-bob",
			Credentials: []VpnCredential{{Protocol: "vless", UUID: "33333333-3333-4333-8333-333333333333"}}}, []string{"pu-bob", "vu_pu-bob"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newLinemetaTestServer(t, mustOpenStore(t))
			if err := srv.putVpnUser(tc.identity); err != nil {
				t.Fatal(err)
			}
			for _, id := range tc.legacy {
				if err := srv.store.UpsertProxyUser(model.ProxyUser{ID: id, Name: id, Enabled: true, UUID: tc.identity.Credentials[0].UUID}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := srv.vpnCoreUsersAdminDispatch(context.Background(), "delete", mustJSON(t, map[string]string{"id": tc.identity.ID})); err != nil {
				t.Fatalf("delete: %v", err)
			}
			for _, id := range tc.legacy {
				if _, ok := srv.store.ProxyUser(id); ok {
					t.Fatalf("proxy user %s survived the delete", id)
				}
			}
			if err := srv.migrateProxyUsersToVpnUsers(); err != nil {
				t.Fatal(err)
			}
			if users := srv.listVpnUsers(); len(users) != 0 {
				t.Fatalf("the migration revived %d identities after the delete: %+v", len(users), users)
			}
		})
	}
}
