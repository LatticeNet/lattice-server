package server

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

const policyGiB = int64(1) << 30

// One decision, every reason: what the identity's status is, why it is not
// active, who decided, since when, and for a quota what the crossing rests
// on. The row the policy writes reads back as the same status through
// derivedProxyUserStatusAt, which the managed render, the drift check and the
// alerts use, so no reader of a row can disagree with the policy.
func TestDecideVpnUserPolicy(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	disabledAt := now.Add(-48 * time.Hour)
	past, future := now.Add(-time.Hour), now.Add(240*time.Hour)
	over := vpnUserQuotaUsage{Used: 2 * policyGiB, Proof: 2 * policyGiB, ProofKnown: true}
	for _, tc := range []struct {
		name                      string
		user                      VpnUser
		usage                     vpnUserQuotaUsage
		status, reason, by        string
		since                     time.Time
		evidence                  string
		rowEnabled, wantsInRender bool
	}{
		{name: "active", user: VpnUser{Enabled: true, QuotaBytes: 10 * policyGiB, ExpiresAt: future},
			usage: vpnUserQuotaUsage{Used: policyGiB}, status: model.ProxyUserStatusActive, rowEnabled: true, wantsInRender: true},
		{name: "unlimited and no expiry", user: VpnUser{Enabled: true}, usage: over,
			status: model.ProxyUserStatusActive, rowEnabled: true, wantsInRender: true},
		{name: "disabled, recorded", user: VpnUser{Enabled: false, Suspension: &VpnSuspension{Reason: vpnSuspendReasonDisabled, By: "op-7", Since: disabledAt}},
			status: model.ProxyUserStatusDisabled, reason: vpnSuspendReasonDisabled, by: "op-7", since: disabledAt},
		{name: "disabled before suspensions were recorded", user: VpnUser{Enabled: false},
			status: model.ProxyUserStatusDisabled, reason: vpnSuspendReasonDisabled},
		{name: "disabled outranks expiry and quota", user: VpnUser{Enabled: false, ExpiresAt: past, QuotaBytes: policyGiB}, usage: over,
			status: model.ProxyUserStatusDisabled, reason: vpnSuspendReasonDisabled},
		{name: "operator suspension leaves the flag on", user: VpnUser{Enabled: true, ExpiresAt: past,
			Suspension: &VpnSuspension{Reason: vpnSuspendReasonOperator, By: "op-9", Since: disabledAt}},
			status: model.ProxyUserStatusDisabled, reason: vpnSuspendReasonOperator, by: "op-9", since: disabledAt},
		{name: "a stale disabled record on an enabled identity is ignored", user: VpnUser{Enabled: true,
			Suspension: &VpnSuspension{Reason: vpnSuspendReasonDisabled, By: "op-7"}},
			status: model.ProxyUserStatusActive, rowEnabled: true, wantsInRender: true},
		{name: "expired", user: VpnUser{Enabled: true, ExpiresAt: past, QuotaBytes: policyGiB}, usage: over,
			status: model.ProxyUserStatusExpired, reason: vpnSuspendReasonExpiry, by: vpnPolicyActor, since: past, rowEnabled: true},
		{name: "expires exactly now", user: VpnUser{Enabled: true, ExpiresAt: now},
			status: model.ProxyUserStatusExpired, reason: vpnSuspendReasonExpiry, by: vpnPolicyActor, since: now, rowEnabled: true},
		{name: "quota reached on proof", user: VpnUser{Enabled: true, QuotaBytes: policyGiB}, usage: over,
			status: model.ProxyUserStatusOverQuota, reason: vpnSuspendReasonQuota, by: vpnPolicyActor, evidence: vpnQuotaEvidenceProof, rowEnabled: true},
		{name: "quota reached exactly", user: VpnUser{Enabled: true, QuotaBytes: policyGiB},
			usage:  vpnUserQuotaUsage{Used: policyGiB, Proof: policyGiB, ProofKnown: true},
			status: model.ProxyUserStatusOverQuota, reason: vpnSuspendReasonQuota, by: vpnPolicyActor, evidence: vpnQuotaEvidenceProof, rowEnabled: true},
		{name: "quota reached only with inferred bytes", user: VpnUser{Enabled: true, QuotaBytes: policyGiB},
			usage:  vpnUserQuotaUsage{Used: 2 * policyGiB, Proof: policyGiB / 2, ProofKnown: true},
			status: model.ProxyUserStatusOverQuota, reason: vpnSuspendReasonQuota, by: vpnPolicyActor, evidence: vpnQuotaEvidenceInferred, rowEnabled: true},
		{name: "quota reached with the proof split unknown", user: VpnUser{Enabled: true, QuotaBytes: policyGiB},
			usage:  vpnUserQuotaUsage{Used: 2 * policyGiB, Proof: 2 * policyGiB},
			status: model.ProxyUserStatusOverQuota, reason: vpnSuspendReasonQuota, by: vpnPolicyActor, evidence: vpnQuotaEvidenceInferred, rowEnabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := decideVpnUserPolicy(tc.user, tc.usage, now)
			if p.Status != tc.status || p.Reason != tc.reason || p.By != tc.by || !p.Since.Equal(tc.since) || p.Evidence != tc.evidence {
				t.Fatalf("policy = %+v, want status=%s reason=%s by=%s since=%s evidence=%s", p, tc.status, tc.reason, tc.by, tc.since, tc.evidence)
			}
			if p.Active() != (tc.status == model.ProxyUserStatusActive) {
				t.Fatalf("Active() = %v for status %s", p.Active(), p.Status)
			}
			row := p.applyTo(model.ProxyUser{ID: "row", UsedBytes: 5})
			if got := derivedProxyUserStatusAt(row, now); got != p.Status {
				t.Fatalf("the row the policy writes reads back as %q, the policy said %q (row %+v)", got, p.Status, row)
			}
			if row.Enabled != tc.rowEnabled {
				t.Fatalf("row enabled = %v, want %v", row.Enabled, tc.rowEnabled)
			}
			if kept := proxycoreKeeps(row, now); kept != tc.wantsInRender {
				t.Fatalf("the renderer keeps the row = %v, want %v", kept, tc.wantsInRender)
			}
		})
	}
}

// proxycoreKeeps is whether the managed renderer would serve the row: the
// same three checks proxycore's skipProxyUserReason makes.
func proxycoreKeeps(row model.ProxyUser, now time.Time) bool {
	return row.Enabled && (row.Status == "" || row.Status == model.ProxyUserStatusActive) &&
		!proxyUserExpiredAt(row.ExpiresAt, now) && !proxyQuotaExhausted(row.UsedBytes, row.TrafficLimitBytes)
}

// Turning an identity off records who did it and when; an edit that leaves it
// off keeps that record; turning it on clears it. The record survives a
// reopen of the store, and the policy names the actor.
func TestDisablingAnIdentityRecordsWhoDidIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	t0 := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	srv.now = func() time.Time { return t0 }
	ctx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, principal{Principal: rbac.Principal{ActorID: "op-7"}})
	raw, err := srv.vpnCoreUsersAdminDispatch(ctx, "create", mustJSON(t, map[string]any{"email": "dora@example.com"}))
	if err != nil {
		t.Fatal(err)
	}
	userID := decodeCreatedUserID(t, raw)
	if u, _ := srv.getVpnUser(userID); u.Suspension != nil {
		t.Fatalf("an enabled identity must carry no suspension: %+v", u.Suspension)
	}

	update := func(actor string, body map[string]any) {
		t.Helper()
		body["id"] = userID
		ctx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, principal{Principal: rbac.Principal{ActorID: actor}})
		if _, err := srv.vpnCoreUsersAdminDispatch(ctx, "update", mustJSON(t, body)); err != nil {
			t.Fatal(err)
		}
	}
	update("op-7", map[string]any{"email": "dora@example.com", "enabled": false})
	srv.now = func() time.Time { return t0.Add(time.Hour) }
	update("op-8", map[string]any{"email": "dora@example.com", "enabled": false, "comment": "still off"})
	u, _ := srv.getVpnUser(userID)
	if u.Suspension == nil || u.Suspension.Reason != vpnSuspendReasonDisabled || u.Suspension.By != "op-7" || !u.Suspension.Since.Equal(t0) {
		t.Fatalf("suspension = %+v, want disabled by op-7 at %s", u.Suspension, t0)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	srv = newLinemetaTestServer(t, reopened)
	u, _ = srv.getVpnUser(userID)
	p := srv.vpnUserPolicyAt(u, t0.Add(2*time.Hour))
	if p.Reason != vpnSuspendReasonDisabled || p.By != "op-7" || !p.Since.Equal(t0) {
		t.Fatalf("policy after reopen = %+v", p)
	}
	update("op-8", map[string]any{"email": "dora@example.com", "enabled": true})
	if u, _ := srv.getVpnUser(userID); u.Suspension != nil {
		t.Fatalf("enabling must clear the disabled record: %+v", u.Suspension)
	}
}

// The store refuses a suspension it cannot interpret, so a bad write cannot
// leave the policy guessing.
func TestStoreRefusesAnUnknownSuspensionReason(t *testing.T) {
	srv := newLinemetaTestServer(t, mustOpenStore(t))
	u := VpnUser{ID: "vpnuser_bad", Email: "bad@example.com", Enabled: true, Suspension: &VpnSuspension{Reason: "quota"}}
	if err := srv.putVpnUser(u); err == nil || !strings.Contains(err.Error(), "suspension reason") {
		t.Fatalf("a stored quota suspension must be refused, the policy derives quota: %v", err)
	}
	u.Suspension = &VpnSuspension{Reason: vpnSuspendReasonOperator, By: "op\x00"}
	if err := srv.putVpnUser(u); err == nil {
		t.Fatal("a control character in the actor must be refused")
	}
}

// adopted-suspend F5: for a lifetime quota the server measures the running
// total on the accounting record, which can be above the quota while the
// retained day rows sum below it. The view used to leave the client to
// decide from used_period_bytes and get it wrong. It now carries the
// server's decision, the figure it used, and what the crossing rests on.
func TestUsageViewCarriesThePolicyDecision(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	day := store.UsageDay(now)
	for _, tc := range []struct {
		name            string
		dayBytes, proof int64
		evidence        string
	}{
		{"the retained rows prove it", 3 * policyGiB / 2, 3 * policyGiB / 2, vpnQuotaEvidenceProof},
		{"the retained rows prove less than the quota", policyGiB / 2, policyGiB / 4, vpnQuotaEvidenceInferred},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := usageTestServer(t, now)
			u := VpnUser{ID: "vpnuser_life", Email: "life@example.com", Enabled: true, QuotaBytes: policyGiB, Credentials: []VpnCredential{}, Bindings: []LineBinding{}}
			if err := srv.putVpnUser(u); err != nil {
				t.Fatal(err)
			}
			if err := srv.store.UpsertProxyUser(model.ProxyUser{ID: u.ID, Name: u.Email, Enabled: true, UsedBytes: 2 * policyGiB, InboundIDs: []string{"__vpn_line_scoped__"}}); err != nil {
				t.Fatal(err)
			}
			if err := srv.store.ApplyProxyUsage(store.ProxyUsageUpdate{DayUsers: []store.UsageDayUser{{UserID: u.ID, Day: day, Downlink: tc.dayBytes, Proof: tc.proof}}}); err != nil {
				t.Fatal(err)
			}
			v := srv.vpnUserUsageViews([]VpnUser{u}, now)[0]
			q := v.Policy.Quota
			if v.Policy.Status != model.ProxyUserStatusOverQuota || v.Policy.Reason != vpnSuspendReasonQuota || v.Policy.By != vpnPolicyActor || q == nil {
				t.Fatalf("policy = %+v", v.Policy)
			}
			if q.UsedBytes != 2*policyGiB || q.LimitBytes != policyGiB || q.Period != "lifetime" || q.ProofBytes == nil || *q.ProofBytes != tc.proof || q.Evidence != tc.evidence {
				t.Fatalf("quota = %+v (proof %v), want used 2 GiB of 1 GiB, proof %d, evidence %s", q, q.ProofBytes, tc.proof, tc.evidence)
			}
			if v.UsedPeriodBytes >= policyGiB && tc.dayBytes < policyGiB {
				t.Fatalf("fixture: used_period_bytes %d should be under the quota", v.UsedPeriodBytes)
			}
			// The direct read gives the same answer the view does.
			if p := srv.vpnUserPolicyAt(u, now); p.Status != v.Policy.Status || p.Evidence != q.Evidence || p.Usage.Used != q.UsedBytes {
				t.Fatalf("vpnUserPolicyAt = %+v, view = %+v", p, q)
			}
		})
	}
}

// A monthly quota is measured over the current period's rows, proof
// included, and the view names the period.
func TestUsageViewPolicyForAMonthlyQuota(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	u := VpnUser{ID: "vpnuser_month", Email: "month@example.com", Enabled: true, QuotaBytes: policyGiB,
		QuotaPeriod: vpnQuotaPeriodMonthly, QuotaResetDay: 15, Credentials: []VpnCredential{}, Bindings: []LineBinding{}}
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	rows := []store.UsageDayUser{
		{UserID: u.ID, Day: "20261014", Downlink: 5 * policyGiB, Proof: 5 * policyGiB}, // last period
		{UserID: u.ID, Day: "20261016", Downlink: policyGiB / 2, Proof: policyGiB / 2},
		{UserID: u.ID, Day: "20261019", Downlink: policyGiB / 4},
	}
	if err := srv.store.ApplyProxyUsage(store.ProxyUsageUpdate{DayUsers: rows}); err != nil {
		t.Fatal(err)
	}
	v := srv.vpnUserUsageViews([]VpnUser{u}, now)[0]
	q := v.Policy.Quota
	if v.Policy.Status != model.ProxyUserStatusActive || q == nil || q.UsedBytes != 3*policyGiB/4 || q.ProofBytes == nil || *q.ProofBytes != policyGiB/2 ||
		q.Period != vpnQuotaPeriodMonthly || !strings.HasPrefix(q.PeriodStart, "2026-10-15") || !strings.HasPrefix(q.PeriodEnd, "2026-11-15") || q.Evidence != "" {
		t.Fatalf("policy = %+v quota = %+v", v.Policy, q)
	}
	if v.UsedPeriodBytes != q.UsedBytes {
		t.Fatalf("a monthly quota's figure must match used_period_bytes: %d vs %d", q.UsedBytes, v.UsedPeriodBytes)
	}
}

// An operator suspension refuses plan_add and plan_update, and an approval
// filed before it, because sb user add would put the identity back on the
// node. The managed render leaves its rows out.
func TestAnOperatorSuspensionRefusesGrantsAndLeavesTheRender(t *testing.T) {
	srv := newLinemetaTestServer(t, mustOpenStore(t))
	line, u := seedLineUserFixture(t, srv)
	update := filePlan(t, srv, lineUserOpUpdate, u.ID, line.LineHashID)
	u.Suspension = &VpnSuspension{Reason: vpnSuspendReasonOperator, By: "op-9", Since: srv.now()}
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	_, err := srv.vpnUserLinePlan(lineUserTestPrincipal(), mustJSON(t, map[string]string{"user_id": u.ID, "line_hash_id": line.LineHashID}), lineUserOpUpdate)
	if err == nil || !strings.Contains(err.Error(), "suspended by op-9") {
		t.Fatalf("plan_update for a suspended identity: %v", err)
	}
	if err := approvePlan(t, srv, update); err == nil || !strings.Contains(err.Error(), "suspended by op-9") {
		t.Fatalf("approving an update filed before the suspension: %v", err)
	}

	managedSrv := newLinemetaTestServer(t, mustOpenStore(t))
	managedLine, identity := seedManagedLineUserFixture(t, managedSrv)
	identity.Bindings = []LineBinding{{LineHashID: managedLine.LineHashID, Enabled: true}}
	identity.Suspension = &VpnSuspension{Reason: vpnSuspendReasonOperator, By: "op-9"}
	if err := managedSrv.putVpnUser(identity); err != nil {
		t.Fatal(err)
	}
	name := userLineName(identity.ID, managedLine.LineUUID)
	for _, row := range managedSrv.proxyUsersForManagedRender(nil, managedSrv.now()) {
		if row.ID == name && (row.Enabled || derivedProxyUserStatusAt(row, managedSrv.now()) == model.ProxyUserStatusActive) {
			t.Fatalf("the managed render must leave a suspended identity out: %+v", row)
		}
	}
}

func decodeCreatedUserID(t *testing.T, raw []byte) string {
	t.Helper()
	var out struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.User.ID == "" {
		t.Fatalf("create response %s: %v", raw, err)
	}
	return out.User.ID
}
