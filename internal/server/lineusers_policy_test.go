package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// planLineUser calls plan_add, plan_update or plan_remove with an optional
// quota in the same request.
func planLineUser(t *testing.T, srv *Server, op, userID, lineHashID string, quota *int64) error {
	t.Helper()
	req := map[string]any{"user_id": userID, "line_hash_id": lineHashID}
	if quota != nil {
		req["quota_bytes"] = *quota
	}
	_, err := srv.vpnUserLinePlan(lineUserTestPrincipal(), mustJSON(t, req), op)
	return err
}

func storedQuota(t *testing.T, srv *Server, userID string) int64 {
	t.Helper()
	u, ok := srv.getVpnUser(userID)
	if !ok {
		t.Fatalf("user %q is gone", userID)
	}
	return u.QuotaBytes
}

// plan_add refuses an identity over its quota or past its expiry, as it
// refuses a disabled one: the managed render would leave it out while the
// task result marked the binding enabled. The quota in the request counts,
// a refused call writes nothing and files no approval, and the usage is
// written in the quota's unit. plan_update and plan_remove stay open: the
// first adds nobody and is how a leaked credential is rotated.
func TestLinePlanRefusesIdentityOutsideItsPolicy(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	line, identity := seedManagedLineUserFixture(t, srv)
	identity.QuotaBytes, identity.QuotaPeriod, identity.QuotaResetDay = 1000, vpnQuotaPeriodMonthly, 15
	if err := srv.putVpnUser(identity); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.ApplyProxyUsage(store.ProxyUsageUpdate{DayUsers: []store.UsageDayUser{
		{UserID: identity.ID, Day: "20260916", Uplink: 600, Downlink: 500},
	}}); err != nil {
		t.Fatal(err)
	}
	approvals := len(srv.store.Approvals())

	err := planLineUser(t, srv, lineUserOpAdd, identity.ID, line.LineHashID, nil)
	if err == nil || !strings.Contains(err.Error(), "has used 1100 B of its 1000 B quota; raise the quota or wait for the next period before planning a line") {
		t.Fatalf("over quota: %v", err)
	}
	short := int64(1050)
	if err := planLineUser(t, srv, lineUserOpAdd, identity.ID, line.LineHashID, &short); err == nil {
		t.Fatal("a raise still under the usage must be refused")
	}
	if got := storedQuota(t, srv, identity.ID); got != 1000 {
		t.Fatalf("a refused plan wrote the quota: %d", got)
	}
	if got := len(srv.store.Approvals()); got != approvals {
		t.Fatalf("a refused plan filed an approval: %d, want %d", got, approvals)
	}
	raised := int64(2000)
	if err := planLineUser(t, srv, lineUserOpAdd, identity.ID, line.LineHashID, &raised); err != nil {
		t.Fatalf("a raise in the same call must be enough: %v", err)
	}
	if got := storedQuota(t, srv, identity.ID); got != 2000 {
		t.Fatalf("the accepted plan did not write the quota: %d", got)
	}

	identity, _ = srv.getVpnUser(identity.ID)
	identity.ExpiresAt = now.Add(-time.Hour)
	if err := srv.putVpnUser(identity); err != nil {
		t.Fatal(err)
	}
	err = planLineUser(t, srv, lineUserOpAdd, identity.ID, line.LineHashID, nil)
	if err == nil || !strings.Contains(err.Error(), "expired on 2026-09-20; renew it before planning a line") {
		t.Fatalf("expired: %v", err)
	}

	// Bound already: plan_update and plan_remove are both accepted.
	identity.Bindings = []LineBinding{{LineHashID: line.LineHashID, Enabled: true}}
	if err := srv.putVpnUser(identity); err != nil {
		t.Fatal(err)
	}
	if err := planLineUser(t, srv, lineUserOpUpdate, identity.ID, line.LineHashID, nil); err != nil {
		t.Fatalf("plan_update must stay open to an expired identity: %v", err)
	}
	if err := planLineUser(t, srv, lineUserOpRemove, identity.ID, line.LineHashID, nil); err != nil {
		t.Fatalf("plan_remove must stay open to an expired identity: %v", err)
	}
}

// The refusal is not limited to managed lines: on an adopted line sb would
// add a user Lattice's own alerts call expired. A bound user's credential
// can still be rotated there, since Lattice does not remove it.
func TestAdoptedLinePlanRefusesExpiredIdentity(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	line, u := seedLineUserFixture(t, srv)
	u.ExpiresAt = time.Now().Add(-48 * time.Hour)
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	if err := planLineUser(t, srv, lineUserOpUpdate, u.ID, line.LineHashID, nil); err != nil {
		t.Fatalf("adopted plan_update for an expired identity must rotate: %v", err)
	}
	if err := planLineUser(t, srv, lineUserOpRemove, u.ID, line.LineHashID, nil); err != nil {
		t.Fatalf("adopted plan_remove: %v", err)
	}
	u.Bindings = nil
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	if err := planLineUser(t, srv, lineUserOpAdd, u.ID, line.LineHashID, nil); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("adopted plan_add for an expired identity: %v", err)
	}
}

// A managed-line rollout puts the user in the fragment it plans, so it is
// refused for the same identities.
func TestManagedLineRolloutRefusesIdentityOutsideItsPolicy(t *testing.T) {
	srv := newManagedLineTestServer(t)
	seedManagedLineNode(t, srv, "node-a", realityInventoryLines())
	u := seedManagedLineUser(t, srv)
	u.ExpiresAt = time.Now().Add(-48 * time.Hour)
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	_, _, err := srv.compileManagedLineRollout(context.Background(), rolloutTestPrincipal(), managedLineRolloutRequest{UserID: u.ID})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("rollout for an expired identity: %v", err)
	}
	if defs, _ := srv.managedLineDefs(); len(defs) != 0 {
		t.Fatalf("a refused rollout stored definitions: %+v", defs)
	}
}

// A refusal compares the usage with the quota, so both are written in the
// quota's unit; formatProxyBytes alone still picks each figure's own unit.
func TestFormatProxyBytesInUsesTheReferenceUnit(t *testing.T) {
	const gib = int64(1) << 30
	cases := []struct {
		v, ref int64
		want   string
	}{
		{v: 1100, ref: 1000, want: "1100 B"},
		{v: 1536, ref: 1536, want: "1.5 KiB"},
		{v: 11 * gib, ref: 10 * gib, want: "11.0 GiB"},
		{v: 2048 * gib, ref: 10 * gib, want: "2048.0 GiB"},
	}
	for _, tc := range cases {
		if got := formatProxyBytesIn(tc.v, tc.ref); got != tc.want {
			t.Fatalf("formatProxyBytesIn(%d, %d) = %q, want %q", tc.v, tc.ref, got, tc.want)
		}
	}
	if got := formatProxyBytes(1000); got != "1000 B" {
		t.Fatalf("formatProxyBytes(1000) = %q", got)
	}
	if got := formatProxyBytes(1100); got != "1.1 KiB" {
		t.Fatalf("formatProxyBytes(1100) = %q", got)
	}
}
