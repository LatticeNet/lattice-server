package server

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
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

// The plan-time gates run again when an adopted plan is approved: an
// approval filed while the user was within its policy is refused once the
// user expires, and the refusal says why. Renewing the user is enough to
// approve the same plan. The task result is not held to it, because the node
// already holds what the task wrote. plan_update stays open to an expired
// user and closes to a disabled one, as at plan time.
func TestAdoptedLineApprovalRechecksTheIdentityPolicy(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	line, u := seedLineUserFixture(t, srv)
	u.Bindings = nil
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	add := filePlan(t, srv, lineUserOpAdd, u.ID, line.LineHashID)

	u.ExpiresAt = time.Now().Add(-48 * time.Hour)
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	if script := srv.applyScriptFor(add); !strings.Contains(script, "expired on") || !strings.Contains(script, "exit 1") || strings.Contains(script, "user add") {
		t.Fatalf("an expired user's add must render the fail-closed script:\n%s", script)
	}
	err = approvePlan(t, srv, add)
	if err == nil || !strings.Contains(err.Error(), "so this plan would add a user its policy denies; renew it before approving") {
		t.Fatalf("approving an add for an expired user: %v", err)
	}
	if stored, _ := srv.store.Approval(add.ID); stored.Status != model.ApprovalPending {
		t.Fatalf("a refused approval must stay pending, got %q", stored.Status)
	}
	if tasks := tasksFor(srv, add.ID); len(tasks) != 0 {
		t.Fatalf("a refused approval queued tasks: %+v", tasks)
	}

	u.ExpiresAt = time.Time{}
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	if err := approvePlan(t, srv, add); err != nil {
		t.Fatalf("a renewed user's add must approve: %v", err)
	}
	if tasks := tasksFor(srv, add.ID); len(tasks) != 1 || !strings.Contains(tasks[0].Script, "user add") {
		t.Fatalf("the approved add must queue sb user add: %+v", tasks)
	}

	// The user expires while the task runs; the result still records the
	// binding the node now holds.
	u.ExpiresAt = time.Now().Add(-time.Hour)
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	stored, _ := srv.store.Approval(add.ID)
	request := httptest.NewRequest("POST", "/api/agent/task-result", nil)
	if err := srv.handleLineUserTaskResult(request, stored, model.Task{ID: "task-add"}, model.TaskResult{}); err != nil {
		t.Fatal(err)
	}
	u, _ = srv.getVpnUser(u.ID)
	if len(u.Bindings) != 1 || !u.Bindings[0].Enabled {
		t.Fatalf("the task result must record the binding: %+v", u.Bindings)
	}

	update := filePlan(t, srv, lineUserOpUpdate, u.ID, line.LineHashID)
	if err := approvePlan(t, srv, update); err != nil {
		t.Fatalf("an update for an expired user must approve: %v", err)
	}
	update = filePlan(t, srv, lineUserOpUpdate, u.ID, line.LineHashID)
	u.Enabled = false
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	if err := approvePlan(t, srv, update); err == nil || !strings.Contains(err.Error(), "is disabled, so this plan would grant a disabled user; enable it before approving") {
		t.Fatalf("approving an update for a disabled user: %v", err)
	}
}

// On a managed line the config hash already fails once the planned user
// crosses its quota, since the render leaves the user out. The refusal now
// names the quota instead of a changed config, and raising the quota is
// enough to approve the same plan.
func TestManagedLineApprovalNamesTheQuotaItCrossed(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	line, identity := seedManagedLineUserFixture(t, srv)
	identity.QuotaBytes, identity.QuotaPeriod, identity.QuotaResetDay = 1000, vpnQuotaPeriodMonthly, 15
	if err := srv.putVpnUser(identity); err != nil {
		t.Fatal(err)
	}
	add := filePlan(t, srv, lineUserOpAdd, identity.ID, line.LineHashID)

	if err := srv.store.ApplyProxyUsage(store.ProxyUsageUpdate{DayUsers: []store.UsageDayUser{
		{UserID: identity.ID, Day: "20260916", Uplink: 600, Downlink: 500},
	}}); err != nil {
		t.Fatal(err)
	}
	err := approvePlan(t, srv, add)
	if err == nil || !strings.Contains(err.Error(), "has used 1100 B of its 1000 B quota, so this plan would add a user its policy denies; raise the quota or wait for the next period before approving") {
		t.Fatalf("approving a managed add over quota: %v", err)
	}

	identity, _ = srv.getVpnUser(identity.ID)
	identity.QuotaBytes = 2000
	if err := srv.putVpnUser(identity); err != nil {
		t.Fatal(err)
	}
	if err := approvePlan(t, srv, add); err != nil {
		t.Fatalf("a raised quota must approve the same managed plan: %v", err)
	}
}

// A managed-line rollout puts the user in its fragment, so its approval is
// held to the same gate, at approve time and in the script. The task result
// still validates without it.
func TestManagedLineRolloutApprovalRechecksTheIdentityPolicy(t *testing.T) {
	srv := newManagedLineTestServer(t)
	seedManagedLineNode(t, srv, "node-a", realityInventoryLines())
	u := seedManagedLineUser(t, srv)
	approval, _ := compileApproval(t, srv)

	u.ExpiresAt = time.Now().Add(-48 * time.Hour)
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := srv.validateManagedLineApproval(approval, true); err == nil || !strings.Contains(err.Error(), "expired on") {
		t.Fatalf("validating a rollout for an expired user: %v", err)
	}
	if script := srv.managedLineApplyScript(approval); !strings.Contains(script, "expired on") || strings.Contains(script, "base64 -d") {
		t.Fatalf("an expired user's rollout must render the fail-closed script:\n%s", script)
	}
	if err := approvePlan(t, srv, approval); err == nil || !strings.Contains(err.Error(), "renew it before approving") {
		t.Fatalf("approving a rollout for an expired user: %v", err)
	}
	if _, _, _, err := srv.validateManagedLineApproval(approval, false); err != nil {
		t.Fatalf("the task-result validation must not apply the policy: %v", err)
	}
}
