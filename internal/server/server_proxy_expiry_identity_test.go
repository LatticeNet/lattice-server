package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// proxyNotifyCapture records the untyped notifications the proxy user alerts
// are sent through.
func proxyNotifyCapture(srv *Server) *[]string {
	sent := &[]string{}
	srv.emitNotify = func(title, body string) { *sent = append(*sent, title) }
	return sent
}

// An expiry set through the vpn-core editor drives proxy.expiry for a
// migrated identity, whose legacy record still carries no expiry, at each
// threshold, and /api/expiring reads the same date.
func TestProxyExpiryFollowsVPNCoreEdits(t *testing.T) {
	now := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	if err := srv.store.UpsertProxyUser(model.ProxyUser{ID: "pu-1", Name: "alice@example.com", Enabled: true, UUID: "1b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"}); err != nil {
		t.Fatal(err)
	}
	if err := srv.migrateProxyUsersToVpnUsers(); err != nil {
		t.Fatal(err)
	}
	identity, ok := srv.vpnUsersByAccounting()["pu-1"]
	if !ok {
		t.Fatal("migration did not derive an identity for pu-1")
	}
	sent := proxyNotifyCapture(srv)

	expires := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	if _, err := srv.vpnCoreUsersAdminRPC(context.Background(), "update", []byte(`{"id":"`+identity.ID+`","email":"alice@example.com","expires_at":"2026-10-04T00:00:00Z"}`)); err != nil {
		t.Fatal(err)
	}
	if legacy, _ := srv.store.ProxyUser("pu-1"); !legacy.ExpiresAt.IsZero() {
		t.Fatalf("precondition: the legacy record is not the one the editor writes: %+v", legacy)
	}

	steps := []struct {
		at    time.Time
		title string
	}{
		{now, "Lattice proxy expiry due in 7d: alice@example.com"},
		{now.Add(6 * time.Hour), ""}, // the same threshold does not repeat
		{time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC), "Lattice proxy expiry due in 1d: alice@example.com"},
		{time.Date(2026, 10, 4, 0, 0, 1, 0, time.UTC), "Lattice proxy expiry expired: alice@example.com"},
	}
	for _, step := range steps {
		before := len(*sent)
		fired, err := srv.evaluateProxyUserNotifications(step.at, "")
		if err != nil {
			t.Fatal(err)
		}
		if step.title == "" {
			if len(fired) != 0 || len(*sent) != before {
				t.Fatalf("%v: repeated alert %+v", step.at, fired)
			}
			continue
		}
		if len(fired) != 1 || !fired[0].ExpiresAt.Equal(expires) || len(*sent) != before+1 || (*sent)[before] != step.title {
			t.Fatalf("%v: fired=%+v sent=%v, want %q", step.at, fired, *sent, step.title)
		}
	}
	if legacy, _ := srv.store.ProxyUser("pu-1"); legacy.Status != model.ProxyUserStatusExpired {
		t.Fatalf("status should follow the identity's expiry: %q", legacy.Status)
	}

	admin := principal{Principal: rbac.Principal{Scopes: []string{"*"}}}
	listed := srv.expiringFor(admin, now, 60)
	if len(listed.Items) != 1 || listed.Items[0].ID != identity.ID || !listed.Items[0].DueAt.Equal(expires) {
		t.Fatalf("/api/expiring disagrees with the notification: %+v", listed.Items)
	}

	// Turning the identity off in vpn-core silences it, as /api/expiring
	// leaves it out.
	if _, err := srv.vpnCoreUsersAdminRPC(context.Background(), "update", []byte(`{"id":"`+identity.ID+`","email":"alice@example.com","enabled":false,"expires_at":"2026-12-01T00:00:00Z"}`)); err != nil {
		t.Fatal(err)
	}
	if fired, _ := srv.evaluateProxyUserNotifications(time.Date(2026, 11, 28, 0, 0, 0, 0, time.UTC), ""); len(fired) != 0 {
		t.Fatalf("a disabled identity alerted: %+v", fired)
	}
}

// A vpn-core user created with an expiry and no traffic yet has no stored
// projection; its expiry still alerts, and the projection that holds the
// cursor is written only then.
func TestProxyExpiryForVPNCoreUserWithoutTraffic(t *testing.T) {
	now := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	sent := proxyNotifyCapture(srv)
	raw, err := srv.vpnCoreUsersAdminRPC(context.Background(), "create", []byte(`{"email":"frank@example.com","credentials":[{"protocol":"vless"}],"expires_at":"2026-12-31T00:00:00Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	var created struct {
		User vpnUserView `json:"user"`
	}
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatal(err)
	}
	if fired, _ := srv.evaluateProxyUserNotifications(now, ""); len(fired) != 0 {
		t.Fatalf("nothing is due yet: %+v", fired)
	}
	if _, ok := srv.store.ProxyUser(created.User.ID); ok {
		t.Fatal("no projection should be written while nothing fires")
	}
	at := time.Date(2026, 12, 26, 8, 0, 0, 0, time.UTC)
	fired, err := srv.evaluateProxyUserNotifications(at, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(fired) != 1 || fired[0].UserID != created.User.ID || len(*sent) != 1 || (*sent)[0] != "Lattice proxy expiry due in 7d: frank@example.com" {
		t.Fatalf("fired=%+v sent=%v", fired, *sent)
	}
	stored, ok := srv.store.ProxyUser(created.User.ID)
	if !ok || stored.LastExpiryNotifiedKey != "expiry:2026-12-31:7" {
		t.Fatalf("cursor projection: %+v ok=%v", stored, ok)
	}
	if again, _ := srv.evaluateProxyUserNotifications(at.Add(time.Hour), ""); len(again) != 0 {
		t.Fatalf("repeated: %+v", again)
	}
}

// Evaluating every identity must not announce expiries that are long gone. An
// identity expired 30 days ago with no stored record stays silent and writes
// nothing; a migrated identity whose vpn-core date is long past (and differs
// from its legacy record's) stays silent and has the cursor seeded instead.
func TestProxyExpiryLongPastIsSilent(t *testing.T) {
	now := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	sent := proxyNotifyCapture(srv)
	if err := srv.store.UpsertProxyUser(model.ProxyUser{ID: "pu-legacy", Name: "bob@example.com", Enabled: true, UUID: "2b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
		ExpiresAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), LastExpiryNotifiedKey: "expiry:2026-01-01:expired"}); err != nil {
		t.Fatal(err)
	}
	if err := srv.migrateProxyUsersToVpnUsers(); err != nil {
		t.Fatal(err)
	}
	bob := srv.vpnUsersByAccounting()["pu-legacy"]
	if _, err := srv.vpnCoreUsersAdminRPC(context.Background(), "update", []byte(`{"id":"`+bob.ID+`","email":"bob@example.com","expires_at":"2026-08-01T00:00:00Z"}`)); err != nil {
		t.Fatal(err)
	}
	raw, err := srv.vpnCoreUsersAdminRPC(context.Background(), "create", []byte(`{"email":"old@example.com","credentials":[{"protocol":"vless"}],"expires_at":"2026-08-30T00:00:00Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	var created struct {
		User vpnUserView `json:"user"`
	}
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatal(err)
	}

	fired, err := srv.evaluateProxyUserNotifications(now, "")
	if err != nil || len(fired) != 0 || len(*sent) != 0 {
		t.Fatalf("long-past expiries announced: fired=%+v sent=%v err=%v", fired, *sent, err)
	}
	if _, ok := srv.store.ProxyUser(created.User.ID); ok {
		t.Fatal("a silent identity without a record must not get one")
	}
	if legacy, _ := srv.store.ProxyUser("pu-legacy"); legacy.LastExpiryNotifiedKey != "expiry:2026-08-01:expired" {
		t.Fatalf("cursor not seeded for the identity's date: %q", legacy.LastExpiryNotifiedKey)
	}
}

// Several users reaching an expiry threshold in one run arrive as one
// message, still routed as proxy.expiry.
func TestProxyExpiryDigestIsOneMessagePerRun(t *testing.T) {
	now := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	var sent []sentNotification
	srv.emitNotify = func(title, body string) {
		sent = append(sent, sentNotification{eventType: classifyNotifyEvent(title), title: title, body: body})
	}
	for _, u := range []struct{ email, expires string }{
		{"carol@example.com", "2026-10-04T00:00:00Z"},
		{"alice@example.com", "2026-09-30T00:00:00Z"},
		{"dave@example.com", "2026-09-25T00:00:00Z"},
	} {
		if _, err := srv.vpnCoreUsersAdminRPC(context.Background(), "create", []byte(`{"email":"`+u.email+`","credentials":[{"protocol":"vless"}],"expires_at":"`+u.expires+`"}`)); err != nil {
			t.Fatal(err)
		}
	}
	fired, err := srv.evaluateProxyUserNotifications(now, "")
	if err != nil || len(fired) != 3 {
		t.Fatalf("fired=%+v err=%v", fired, err)
	}
	if len(sent) != 1 {
		t.Fatalf("one run must send one message, sent %d: %+v", len(sent), sent)
	}
	want := sentNotification{
		eventType: "proxy.expiry",
		title:     "Lattice proxy expiry digest: 3 users",
		body:      "09-25  dave@example.com  expired\n09-30  alice@example.com  within 1d\n10-04  carol@example.com  within 7d",
	}
	if sent[0] != want {
		t.Fatalf("digest:\n got %+v\nwant %+v", sent[0], want)
	}
	if again, _ := srv.evaluateProxyUserNotifications(now.Add(time.Hour), ""); len(again) != 0 {
		t.Fatalf("repeated: %+v", again)
	}
}
