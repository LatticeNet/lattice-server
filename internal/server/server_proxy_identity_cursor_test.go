package server

import (
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// reportBobLine sends node-a's cumulative direct-a counter. bob is the only
// identity bound to direct-a and has no inbound membership, so every byte is
// his through the binding and his stored projection is the line-scoped one.
func reportBobLine(t *testing.T, srv *Server, uptime uint64, total int64) proxyUsageApplyResult {
	t.Helper()
	return mustApplyUsage(t, srv, model.ProxyUsageSnapshot{NodeID: "node-a", CoreUptimeSec: uptime,
		InboundTraffic: map[string]model.ProxyTrafficCounter{"direct-a": counter(total/4, total-total/4)}})
}

func alertTitles(sent []sentProxyAlert) []string {
	out := make([]string, 0, len(sent))
	for _, msg := range sent {
		out = append(out, msg.title)
	}
	return out
}

// A line-scoped identity carrying traffic on every report is alerted once per
// threshold. Its stored projection never applies to the node's profile, and
// the cursor written by one report used to be dropped by the next, so the
// 100 percent alert went out on every usage report.
func TestUsageIngestAlertsLineScopedIdentityQuotaOnce(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	f := seedUsageFleet(t, srv)
	bob := f.bob
	bob.QuotaBytes, bob.QuotaPeriod, bob.QuotaResetDay = 1000, vpnQuotaPeriodMonthly, 1
	if err := srv.putVpnUser(bob); err != nil {
		t.Fatal(err)
	}
	reportBobLine(t, srv, 100, 0)

	for i, step := range []struct {
		total int64
		want  []string
	}{
		{850, []string{"Lattice proxy quota 80%: bob@example.com"}},
		{900, nil},
		{1100, []string{"Lattice proxy quota 100%: bob@example.com"}},
		{1200, nil},
		{1300, nil},
	} {
		sent := captureProxyAlerts(srv)
		result := reportBobLine(t, srv, uint64(110+10*i), step.total)
		if got := alertTitles(*sent); result.AlertsFired != len(step.want) || strings.Join(got, "|") != strings.Join(step.want, "|") {
			t.Fatalf("report %d at %d bytes: fired %d %q, want %q", i+1, step.total, result.AlertsFired, got, step.want)
		}
	}
	stored, ok := srv.store.ProxyUser(bob.ID)
	if !ok || !strings.HasSuffix(stored.LastQuotaNotifiedKey, ":100") {
		t.Fatalf("stored cursor = %q ok=%v, want the 100 percent key", stored.LastQuotaNotifiedKey, ok)
	}
}

// The running total on a line-scoped identity's projection accumulates
// across reports. It is what a lifetime quota is measured with, so restarting
// it from each report's delta left a lifetime quota unenforced and unalerted.
// A report with no stored baseline for the node keeps the total too.
func TestUsageIngestAccumulatesLineScopedIdentityTotal(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	f := seedUsageFleet(t, srv)
	bob := f.bob
	bob.QuotaBytes = 1000
	if err := srv.putVpnUser(bob); err != nil {
		t.Fatal(err)
	}
	reportBobLine(t, srv, 100, 0)

	for i, want := range []string{"", "Lattice proxy quota 80%: bob@example.com", "Lattice proxy quota 100%: bob@example.com", ""} {
		sent := captureProxyAlerts(srv)
		total := int64(400 * (i + 1))
		reportBobLine(t, srv, uint64(110+10*i), total)
		stored, ok := srv.store.ProxyUser(bob.ID)
		if !ok || stored.UsedBytes != total {
			t.Fatalf("report %d: stored UsedBytes = %d ok=%v, want %d", i+1, stored.UsedBytes, ok, total)
		}
		if got := strings.Join(alertTitles(*sent), "|"); got != want {
			t.Fatalf("report %d at %d bytes: sent %q, want %q", i+1, total, got, want)
		}
	}
	policy := srv.vpnUserPolicyAt(bob, now)
	if policy.Usage.Used != 1600 || policy.Status != model.ProxyUserStatusOverQuota {
		t.Fatalf("lifetime policy used=%d status=%s, want 1600 over_quota", policy.Usage.Used, policy.Status)
	}

	// The node's baseline is gone: the next report is a new baseline and
	// advances nothing, and it must not overwrite the total or the cursor.
	if err := srv.store.DeleteProxyUsageSnapshot("node-a"); err != nil {
		t.Fatal(err)
	}
	sent := captureProxyAlerts(srv)
	bobName := userLineName(bob.ID, f.direct.LineUUID)
	mustApplyUsage(t, srv, model.ProxyUsageSnapshot{NodeID: "node-a", CoreUptimeSec: 5,
		UserTraffic: map[string]model.ProxyTrafficCounter{bobName: counter(3, 4)}})
	stored, _ := srv.store.ProxyUser(bob.ID)
	if stored.UsedBytes != 1600 || !strings.HasSuffix(stored.LastQuotaNotifiedKey, ":100") || len(*sent) != 0 {
		t.Fatalf("after a baseline report: UsedBytes=%d cursor=%q sent=%q", stored.UsedBytes, stored.LastQuotaNotifiedKey, alertTitles(*sent))
	}
}

// The expiry cursor of a line-scoped identity survives the same way: an
// identity due to expire is told once, not on every report it carries
// traffic in.
func TestUsageIngestAlertsLineScopedIdentityExpiryOnce(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	f := seedUsageFleet(t, srv)
	bob := f.bob
	bob.ExpiresAt = time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	if err := srv.putVpnUser(bob); err != nil {
		t.Fatal(err)
	}
	reportBobLine(t, srv, 100, 0)

	for i, want := range []string{"Lattice proxy expiry due in 7d: bob@example.com", "", ""} {
		sent := captureProxyAlerts(srv)
		reportBobLine(t, srv, uint64(110+10*i), int64(100*(i+1)))
		if got := strings.Join(alertTitles(*sent), "|"); got != want {
			t.Fatalf("report %d: sent %q, want %q", i+1, got, want)
		}
	}
	stored, ok := srv.store.ProxyUser(bob.ID)
	if !ok || stored.LastExpiryNotifiedKey != proxyExpiryNotificationKey(bob.ExpiresAt, 7) || stored.UsedBytes != 300 {
		t.Fatalf("stored expiry cursor = %q UsedBytes=%d ok=%v", stored.LastExpiryNotifiedKey, stored.UsedBytes, ok)
	}
}
