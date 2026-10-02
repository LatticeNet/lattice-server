package server

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// renderRow finds one row of the managed render user list by id.
func renderRow(t *testing.T, users []model.ProxyUser, id string) (model.ProxyUser, bool) {
	t.Helper()
	for _, user := range users {
		if user.ID == id {
			return user, true
		}
	}
	return model.ProxyUser{}, false
}

// pinManagedApply records the current render of node managed-a as applied,
// the state a reviewed apply leaves behind.
func pinManagedApply(t *testing.T, srv *Server) string {
	t.Helper()
	_, _, artifact, err := srv.renderProxyCoreArtifact("managed-a")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	profile, _ := srv.store.ProxyNodeProfile("managed-a")
	profile.AppliedSHA256 = artifact.ConfigSHA256
	if err := srv.store.UpsertProxyNodeProfile(profile); err != nil {
		t.Fatal(err)
	}
	return artifact.ConfigSHA256
}

// managedRenderHas reports whether the current render of node managed-a
// serves the given VLESS uuid.
func managedRenderHas(t *testing.T, srv *Server, uuid string) bool {
	t.Helper()
	_, _, artifact, err := srv.renderProxyCoreArtifact("managed-a")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return strings.Contains(artifact.ConfigJSON, uuid)
}

func managedDrift(t *testing.T, srv *Server, now time.Time) proxyDriftState {
	t.Helper()
	srv.evaluateProxyConfigDrift(now)
	state, ok := srv.proxyDriftFor("managed-a")
	if !ok {
		t.Fatal("no drift state for managed-a")
	}
	return state
}

// An identity bound to a managed line is rendered with its live quota
// figure: crossing its monthly quota drops it from the render and the drift
// banner counts it, the same status quotaEvaluate alerts with; a raised quota
// or the next period brings it back. A legacy record with no identity behind
// it is passed through as stored.
func TestManagedRenderFollowsIdentityQuota(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	line, identity := seedManagedLineUserFixture(t, srv)
	identity.Bindings = []LineBinding{{LineHashID: line.LineHashID, Enabled: true}}
	identity.QuotaBytes, identity.QuotaPeriod, identity.QuotaResetDay = 1000, vpnQuotaPeriodMonthly, 15
	if err := srv.putVpnUser(identity); err != nil {
		t.Fatal(err)
	}
	uuid := identity.Credentials[0].UUID
	rowID := userLineName(identity.ID, line.LineUUID)

	users := srv.proxyUsersForManagedRender(nil, now)
	if row, ok := renderRow(t, users, rowID); !ok || row.Status != model.ProxyUserStatusActive || row.TrafficLimitBytes != 1000 || row.UsedBytes != 0 {
		t.Fatalf("bound identity under quota: row=%+v ok=%v", row, ok)
	}
	if _, ok := renderRow(t, users, "legacy-keepalive"); ok {
		t.Fatal("an identity with a managed binding replaces its legacy record")
	}
	other, _ := srv.store.ProxyUser("other-keepalive")
	if row, ok := renderRow(t, users, "other-keepalive"); !ok || !reflect.DeepEqual(row, other) {
		t.Fatalf("a legacy record without an identity must render as stored:\n got %+v\nwant %+v", row, other)
	}
	applied := pinManagedApply(t, srv)
	if !managedRenderHas(t, srv, uuid) {
		t.Fatal("the identity under its quota must be served")
	}
	if state := managedDrift(t, srv, now); state.Stale {
		t.Fatalf("no drift right after the apply: %+v", state)
	}

	// This period's day rows reach the quota.
	if err := srv.store.ApplyProxyUsage(store.ProxyUsageUpdate{DayUsers: []store.UsageDayUser{
		{UserID: identity.ID, Day: "20260910", Uplink: 5000, Downlink: 5000}, // previous period
		{UserID: identity.ID, Day: "20260916", Uplink: 600, Downlink: 500},
	}}); err != nil {
		t.Fatal(err)
	}
	row, ok := renderRow(t, srv.proxyUsersForManagedRender(nil, now), rowID)
	if !ok || row.Status != model.ProxyUserStatusOverQuota || row.UsedBytes != 1100 {
		t.Fatalf("over its monthly quota: row=%+v ok=%v", row, ok)
	}
	legacy, _ := srv.store.ProxyUser("legacy-keepalive")
	if evaluated, _ := srv.quotaEvaluate(legacy, &identity, now, usageCounter{}); evaluated.Status != row.Status {
		t.Fatalf("the alert path and the render disagree: alert status %q, render status %q", evaluated.Status, row.Status)
	}
	if managedRenderHas(t, srv, uuid) {
		t.Fatal("an identity over its quota must be dropped from the managed render")
	}
	state := managedDrift(t, srv, now)
	if !state.Stale || state.IneligibleUsers != 1 || state.Reason != "1 user is no longer eligible; review and apply to enforce" {
		t.Fatalf("drift must name the over-quota identity: %+v", state)
	}

	// A raised quota brings it back, to the config that is already applied.
	identity.QuotaBytes = 2000
	if err := srv.putVpnUser(identity); err != nil {
		t.Fatal(err)
	}
	if !managedRenderHas(t, srv, uuid) {
		t.Fatal("a raised quota must bring the identity back")
	}
	if state := managedDrift(t, srv, now); state.Stale || state.PendingSHA256 != applied {
		t.Fatalf("the render is back to the applied config: %+v", state)
	}

	// Back under the old quota, the next period starts from zero.
	identity.QuotaBytes = 1000
	if err := srv.putVpnUser(identity); err != nil {
		t.Fatal(err)
	}
	if managedRenderHas(t, srv, uuid) {
		t.Fatal("precondition: over the quota again")
	}
	next := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	srv.now = func() time.Time { return next }
	if !managedRenderHas(t, srv, uuid) {
		t.Fatal("a new quota period must bring the identity back")
	}
	if state := managedDrift(t, srv, next); state.Stale {
		t.Fatalf("no drift in the new period: %+v", state)
	}
}

// A migrated identity without a managed binding is rendered through its
// legacy record, and that record carries the identity's live policy, not what
// it held at migration: an expiry or a lifetime quota set on the identity
// drops it, a renewal or a raised quota brings it back. The stored record is
// never written by the render.
func TestManagedRenderOverlaysIdentityOnLegacyRecord(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	_, identity := seedManagedLineUserFixture(t, srv)
	legacy, _ := srv.store.ProxyUser("legacy-keepalive")
	legacy.UsedBytes = 800
	if err := srv.store.UpsertProxyUser(legacy); err != nil {
		t.Fatal(err)
	}
	legacy, _ = srv.store.ProxyUser("legacy-keepalive")
	const legacyUUID = "11111111-1111-4111-8111-111111111111"

	pinManagedApply(t, srv)
	if !managedRenderHas(t, srv, legacyUUID) {
		t.Fatal("the migrated identity's legacy record must be served")
	}

	steps := []struct {
		name    string
		edit    func(u *VpnUser)
		status  string
		served  bool
		drifted bool
	}{
		{"expired on the identity", func(u *VpnUser) { u.ExpiresAt = now.Add(-time.Hour) }, model.ProxyUserStatusExpired, false, true},
		{"renewed", func(u *VpnUser) { u.ExpiresAt = now.Add(30 * 24 * time.Hour) }, model.ProxyUserStatusActive, true, false},
		{"lifetime quota below the running total", func(u *VpnUser) { u.QuotaBytes = 500 }, model.ProxyUserStatusOverQuota, false, true},
		{"quota raised", func(u *VpnUser) { u.QuotaBytes = 5000 }, model.ProxyUserStatusActive, true, false},
		{"disabled on the identity", func(u *VpnUser) { u.Enabled = false }, model.ProxyUserStatusDisabled, false, true},
	}
	for _, step := range steps {
		step.edit(&identity)
		if err := srv.putVpnUser(identity); err != nil {
			t.Fatal(err)
		}
		row, ok := renderRow(t, srv.proxyUsersForManagedRender(nil, now), "legacy-keepalive")
		if !ok || row.Status != step.status || row.UUID != legacyUUID {
			t.Fatalf("%s: row=%+v ok=%v, want status %q", step.name, row, ok, step.status)
		}
		if evaluated, _ := srv.quotaEvaluate(legacy, &identity, now, usageCounter{}); evaluated.Status != row.Status {
			t.Fatalf("%s: alert status %q, render status %q", step.name, evaluated.Status, row.Status)
		}
		if got := managedRenderHas(t, srv, legacyUUID); got != step.served {
			t.Fatalf("%s: served=%v, want %v", step.name, got, step.served)
		}
		state := managedDrift(t, srv, now)
		if state.Stale != step.drifted || (step.drifted && state.IneligibleUsers != 1) {
			t.Fatalf("%s: drift %+v", step.name, state)
		}
	}
	if stored, _ := srv.store.ProxyUser("legacy-keepalive"); !reflect.DeepEqual(stored, legacy) {
		t.Fatalf("the render wrote the legacy record:\n got %+v\nwant %+v", stored, legacy)
	}
}
