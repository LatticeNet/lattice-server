package server

import (
	"context"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

type sentProxyAlert struct{ title, body string }

func captureProxyAlerts(srv *Server) *[]sentProxyAlert {
	sent := &[]sentProxyAlert{}
	srv.emitNotify = func(title, body string) { *sent = append(*sent, sentProxyAlert{title, body}) }
	return sent
}

// emitQuotaAlert evaluates a lifetime quota of 1000 bytes fully used for the
// identity and sends what fires, returning the one message.
func emitQuotaAlert(t *testing.T, srv *Server, u VpnUser, now time.Time) (proxyUserNotificationFire, sentProxyAlert) {
	t.Helper()
	sent := captureProxyAlerts(srv)
	u.QuotaBytes = 1000
	projection := vpnUserUsageProjection(u)
	projection.UsedBytes = 1000
	_, alerts := srv.quotaEvaluate(projection, &u, now, usageCounter{})
	if len(alerts) != 1 {
		t.Fatalf("want one quota alert, got %+v", alerts)
	}
	srv.emitProxyUserNotifications(alerts, now)
	if len(*sent) != 1 {
		t.Fatalf("want one message, got %+v", *sent)
	}
	return alerts[0], (*sent)[0]
}

// A quota or expiry alert about an identity outside the managed render, one
// on adopted lines only or on no line at all, says that no managed line
// carries the user and that the message is an alert only. An identity the
// managed render carries, through a managed binding or through its legacy
// record, keeps the plain text.
func TestProxyAlertTextSaysWhenItIsAlertOnly(t *testing.T) {
	now := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)

	t.Run("expiry, no lines", func(t *testing.T) {
		srv := usageTestServer(t, now)
		sent := captureProxyAlerts(srv)
		if _, err := srv.vpnCoreUsersAdminRPC(context.Background(), "create", []byte(`{"email":"frank@example.com","credentials":[{"protocol":"vless"}],"expires_at":"2026-10-04T00:00:00Z"}`)); err != nil {
			t.Fatal(err)
		}
		fired, err := srv.evaluateProxyUserNotifications(now, "")
		if err != nil || len(fired) != 1 || !fired[0].AlertOnly {
			t.Fatalf("fired=%+v err=%v", fired, err)
		}
		want := sentProxyAlert{
			title: "Lattice proxy expiry due in 7d: frank@example.com",
			body:  "frank@example.com subscription expires on 2026-10-04. Status: active. No managed line carries this user, so Lattice will not remove it and this message is an alert only.",
		}
		if len(*sent) != 1 || (*sent)[0] != want {
			t.Fatalf("sent %+v\nwant %+v", *sent, want)
		}
	})

	t.Run("quota, adopted line", func(t *testing.T) {
		srv := usageTestServer(t, now)
		_, user := seedLineUserFixture(t, srv)
		if srv.vpnUserInManagedRender(user) {
			t.Fatal("an identity bound to a discovered line is outside the managed render")
		}
		alert, msg := emitQuotaAlert(t, srv, user, now)
		want := sentProxyAlert{
			title: "Lattice proxy quota 100%: alice@example.com",
			body:  "alice@example.com used 1000 B of 1000 B (100.0%). Status: over_quota. No managed line carries this user, so Lattice will not remove it and this message is an alert only.",
		}
		if !alert.AlertOnly || msg != want {
			t.Fatalf("alert=%+v sent %+v\nwant %+v", alert, msg, want)
		}
	})

	t.Run("quota, managed line", func(t *testing.T) {
		srv := usageTestServer(t, now)
		line, user := seedManagedLineUserFixture(t, srv)
		user.Bindings = []LineBinding{{LineHashID: line.LineHashID, Enabled: true}}
		if err := srv.putVpnUser(user); err != nil {
			t.Fatal(err)
		}
		if !srv.vpnUserInManagedRender(user) {
			t.Fatal("an identity bound to a managed line is in the managed render")
		}
		if _, ok := renderRow(t, srv.proxyUsersForManagedRender(nil, now), userLineName(user.ID, line.LineUUID)); !ok {
			t.Fatal("the render must agree: the identity has a row")
		}
		alert, msg := emitQuotaAlert(t, srv, user, now)
		if alert.AlertOnly || msg.body != "managed@example.com used 1000 B of 1000 B (100.0%). Status: over_quota." {
			t.Fatalf("alert=%+v sent %+v", alert, msg)
		}
	})

	t.Run("expiry, legacy record on a managed line", func(t *testing.T) {
		srv := usageTestServer(t, now)
		_, user := seedManagedLineUserFixture(t, srv)
		user.ExpiresAt = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
		if err := srv.putVpnUser(user); err != nil {
			t.Fatal(err)
		}
		if _, ok := renderRow(t, srv.proxyUsersForManagedRender(nil, now), "legacy-keepalive"); !ok || !srv.vpnUserInManagedRender(user) {
			t.Fatal("a migrated identity without a managed binding is rendered through its legacy record")
		}
		sent := captureProxyAlerts(srv)
		fired, err := srv.evaluateProxyUserNotifications(now, "legacy-keepalive")
		if err != nil || len(fired) != 1 || fired[0].AlertOnly || len(*sent) != 1 || (*sent)[0].body != "Legacy subscription expires on 2026-10-04. Status: active." {
			t.Fatalf("fired=%+v sent=%+v err=%v", fired, *sent, err)
		}

		// The same identity once its legacy record covers no managed inbound.
		legacy, _ := srv.store.ProxyUser("legacy-keepalive")
		legacy.InboundIDs = []string{"in-elsewhere"}
		legacy.LastExpiryNotifiedKey = ""
		if err := srv.store.UpsertProxyUser(legacy); err != nil {
			t.Fatal(err)
		}
		if srv.vpnUserInManagedRender(user) {
			t.Fatal("a legacy record on no managed inbound puts the identity in no render")
		}
		fired, err = srv.evaluateProxyUserNotifications(now, "legacy-keepalive")
		if err != nil || len(fired) != 1 || !fired[0].AlertOnly {
			t.Fatalf("fired=%+v err=%v", fired, err)
		}
	})

	t.Run("legacy record without an identity", func(t *testing.T) {
		srv := usageTestServer(t, now)
		user := model.ProxyUser{ID: "legacy-only", Name: "legacy-only", Enabled: true, TrafficLimitBytes: 1000, UsedBytes: 1000}
		_, alerts := srv.quotaEvaluate(user, nil, now, usageCounter{})
		if len(alerts) != 1 || alerts[0].AlertOnly {
			t.Fatalf("a legacy record is the managed render substrate, not an adopted line: %+v", alerts)
		}
	})
}

// A digest says which users the message is an alert only for: the whole
// message when it is every user, each marked line otherwise.
func TestProxyDigestMarksAlertOnlyUsers(t *testing.T) {
	now := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	quota := func(name string, used int64, alertOnly bool) proxyUserNotificationFire {
		return proxyUserNotificationFire{UserID: name, UserName: name, Kind: proxyUserAlertQuota, UsedBytes: used, TrafficLimitBytes: 1000, AlertOnly: alertOnly}
	}
	_, mixed := proxyUserDigestMessage(proxyUserAlertQuota, []proxyUserNotificationFire{quota("bob", 900, true), quota("amy", 1000, false)}, now)
	wantMixed := "amy  1000 B of 1000 B (100.0%)\n" +
		"bob  900 B of 1000 B (90.0%)  alert only\n" +
		"No managed line carries the users marked alert only, so Lattice will not remove them and for them this message is an alert only."
	if mixed != wantMixed {
		t.Fatalf("mixed digest:\n got %q\nwant %q", mixed, wantMixed)
	}
	_, all := proxyUserDigestMessage(proxyUserAlertQuota, []proxyUserNotificationFire{quota("bob", 900, true), quota("amy", 1000, true)}, now)
	if want := "amy  1000 B of 1000 B (100.0%)\nbob  900 B of 1000 B (90.0%)\nNo managed line carries these users, so Lattice will not remove them and this message is an alert only."; all != want {
		t.Fatalf("all alert only:\n got %q\nwant %q", all, want)
	}
	_, none := proxyUserDigestMessage(proxyUserAlertQuota, []proxyUserNotificationFire{quota("bob", 900, false), quota("amy", 1000, false)}, now)
	if want := "amy  1000 B of 1000 B (100.0%)\nbob  900 B of 1000 B (90.0%)"; none != want {
		t.Fatalf("none alert only:\n got %q\nwant %q", none, want)
	}
}
