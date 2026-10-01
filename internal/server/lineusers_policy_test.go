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

// plan_add and plan_update refuse an identity over its quota or past its
// expiry, as they refuse a disabled one: the managed render would leave it
// out while the task result marked the binding enabled. The quota in the
// request counts, a refused call writes nothing and files no approval, and
// plan_remove is always allowed.
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
	if err == nil || !strings.Contains(err.Error(), "has used 1.1 KiB of its 1000 B quota; raise the quota or wait for the next period") {
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

	// Bound already: plan_update is refused, plan_remove is not.
	identity.Bindings = []LineBinding{{LineHashID: line.LineHashID, Enabled: true}}
	if err := srv.putVpnUser(identity); err != nil {
		t.Fatal(err)
	}
	if err := planLineUser(t, srv, lineUserOpUpdate, identity.ID, line.LineHashID, nil); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("plan_update for an expired identity: %v", err)
	}
	if err := planLineUser(t, srv, lineUserOpRemove, identity.ID, line.LineHashID, nil); err != nil {
		t.Fatalf("plan_remove must stay open to an expired identity: %v", err)
	}
}

// The refusal is not limited to managed lines: on an adopted line sb would
// add a user Lattice's own alerts call expired.
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
	if err := planLineUser(t, srv, lineUserOpUpdate, u.ID, line.LineHashID, nil); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("adopted plan_update for an expired identity: %v", err)
	}
	if err := planLineUser(t, srv, lineUserOpRemove, u.ID, line.LineHashID, nil); err != nil {
		t.Fatalf("adopted plan_remove: %v", err)
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
