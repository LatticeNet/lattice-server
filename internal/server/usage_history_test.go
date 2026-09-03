package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestQuotaPeriodBounds(t *testing.T) {
	cases := []struct {
		now        string
		reset      int
		start, end string
	}{
		{"2026-09-02T12:00:00Z", 1, "2026-09-01", "2026-10-01"},
		{"2026-09-02T12:00:00Z", 15, "2026-08-15", "2026-09-15"},
		{"2026-09-15T00:00:00Z", 15, "2026-09-15", "2026-10-15"},
		{"2026-03-01T00:00:00Z", 28, "2026-02-28", "2026-03-28"},
		{"2026-01-10T00:00:00Z", 20, "2025-12-20", "2026-01-20"},
		{"2026-09-02T12:00:00Z", 0, "2026-09-01", "2026-10-01"},  // out of range falls back to the 1st
		{"2026-09-02T12:00:00Z", 31, "2026-09-01", "2026-10-01"}, // out of range falls back to the 1st
	}
	for _, tc := range cases {
		now, _ := time.Parse(time.RFC3339, tc.now)
		start, end := quotaPeriodBounds(now, tc.reset)
		if start.Format("2006-01-02") != tc.start || end.Format("2006-01-02") != tc.end {
			t.Fatalf("bounds(%s, %d) = %s..%s, want %s..%s", tc.now, tc.reset, start.Format("2006-01-02"), end.Format("2006-01-02"), tc.start, tc.end)
		}
	}
}

// Deltas land in the UTC day of ingestion; the day roll opens a new row and
// runs the retention sweep exactly once per day.
func TestUsageDayRollAndRetention(t *testing.T) {
	day1 := time.Date(2026, 9, 2, 23, 50, 0, 0, time.UTC)
	srv := usageTestServer(t, day1)
	f := seedUsageFleet(t, srv)
	// Rows older than the retention window, and one exactly at the edge.
	stale := store.UsageDay(day1.AddDate(0, 0, -store.UsageDayRetentionDays-1))
	edge := store.UsageDay(day1.AddDate(0, 0, 1-store.UsageDayRetentionDays))
	for _, day := range []string{stale, edge} {
		if err := srv.store.ApplyProxyUsage(store.ProxyUsageUpdate{
			DayNode:  &store.UsageDayNode{NodeID: "node-a", Day: day, Lines: map[string]store.UsageDayLine{"old": {Uplink: 1, Downlink: 1}}},
			DayUsers: []store.UsageDayUser{{UserID: f.alice.ID, Day: day, Uplink: 1, Downlink: 1}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	reportUsageFleet(t, srv, f)
	// Ten minutes later it is the next UTC day: a new delta opens day 2 and
	// the sweep removes the row past retention while keeping the edge row.
	day2 := day1.Add(10 * time.Minute)
	srv.now = func() time.Time { return day2 }
	srv.singboxInvMu.Lock()
	for id, inv := range srv.singboxInv {
		inv.At = day2
		srv.singboxInv[id] = inv
	}
	srv.singboxInvMu.Unlock()
	srv.invalidateLineReadModel()
	mustApplyUsage(t, srv, model.ProxyUsageSnapshot{NodeID: "node-a", CoreUptimeSec: 300,
		InboundTraffic: map[string]model.ProxyTrafficCounter{"hub-a": counter(1600, 2700), "direct-a": counter(41, 71)},
		UserTraffic:    map[string]model.ProxyTrafficCounter{f.aliceName: counter(410, 820)},
	})
	from, to := stale, store.UsageDay(day2)
	nodes, err := srv.store.UsageDayNodeRows("node-a", from, to)
	if err != nil {
		t.Fatal(err)
	}
	days := []string{}
	for _, row := range nodes {
		days = append(days, row.Day)
	}
	if got := strings.Join(days, ","); got != edge+",20260902,20260903" {
		t.Fatalf("node days after roll: %s", got)
	}
	if hub := nodes[2].Lines["hub-a"]; hub.Uplink != 100 || hub.Downlink != 100 || hub.Users[f.alice.ID] != (store.UsageDayBytes{Uplink: 10, Downlink: 20}) {
		t.Fatalf("day 2 hub-a: %+v", hub)
	}
	users, _ := srv.store.UsageDayUserRows(f.alice.ID, from, to)
	if len(users) != 3 || users[0].Day != edge || users[2].Day != "20260903" || users[2].Uplink != 10 {
		t.Fatalf("alice days after roll: %+v", users)
	}
	users, _ = srv.store.UsageDayUserRows(f.bob.ID, from, to)
	if len(users) != 2 || users[1].Day != "20260903" || users[1].Downlink != 1 {
		t.Fatalf("bob days after roll: %+v", users)
	}
	// A core restart makes the current counter the delta rather than a drop.
	mustApplyUsage(t, srv, model.ProxyUsageSnapshot{NodeID: "node-a", CoreUptimeSec: 5,
		InboundTraffic: map[string]model.ProxyTrafficCounter{"direct-a": counter(7, 9)}})
	nodes, _ = srv.store.UsageDayNodeRows("node-a", to, to)
	if direct := nodes[0].Lines["direct-a"]; direct.Uplink != 8 || direct.Downlink != 10 {
		t.Fatalf("restart delta: %+v", direct)
	}
	// A decrease without a restart is a new baseline and adds nothing.
	mustApplyUsage(t, srv, model.ProxyUsageSnapshot{NodeID: "node-a", CoreUptimeSec: 6,
		InboundTraffic: map[string]model.ProxyTrafficCounter{"direct-a": counter(3, 9)}})
	nodes, _ = srv.store.UsageDayNodeRows("node-a", to, to)
	if direct := nodes[0].Lines["direct-a"]; direct.Uplink != 8 || direct.Downlink != 10 {
		t.Fatalf("baseline after decrease: %+v", direct)
	}
}

// Period usage is a sum over the user-day rows from the reset day, never a
// stored counter, and the 80/100 percent alerts fire against it and again in
// the next period.
func TestQuotaPeriodSumsAndAlerts(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	f := seedUsageFleet(t, srv)
	erin := VpnUser{ID: "vpnuser_erin", Email: "erin@example.com", Enabled: true, QuotaBytes: 1000, QuotaPeriod: vpnQuotaPeriodMonthly, QuotaResetDay: 15,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: "5b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"}},
		Bindings:    []LineBinding{{LineHashID: f.direct.LineHashID, Enabled: true}}}
	if err := srv.putVpnUser(erin); err != nil {
		t.Fatal(err)
	}
	seed := func(day string, up, down int64) {
		t.Helper()
		if err := srv.store.ApplyProxyUsage(store.ProxyUsageUpdate{DayUsers: []store.UsageDayUser{{UserID: erin.ID, Day: day, Uplink: up, Downlink: down,
			ByLine: map[string]store.UsageDayUserLine{f.direct.LineHashID: {Uplink: up, Downlink: down}}}}}); err != nil {
			t.Fatal(err)
		}
	}
	seed("20260910", 400, 400) // before the reset day: previous period
	seed("20260916", 100, 200) // this period
	seed("20260919", 50, 50)   // this period, inside last_7d
	views := srv.vpnUserUsageViews([]VpnUser{erin}, now)
	v := views[0]
	if v.UsedPeriodBytes != 400 || v.PeriodStart != "2026-09-15T00:00:00Z" || v.PeriodEnd != "2026-10-15T00:00:00Z" || v.QuotaPeriod != "monthly" || v.QuotaResetDay != 15 {
		t.Fatalf("period view: %+v", v)
	}
	if v.Last7d[5] != 100 || v.Last7d[6] != 0 || v.Last7d[2] != 300 {
		t.Fatalf("last_7d: %v", v.Last7d)
	}
	if len(v.AllocatedNodes) != 1 || v.AllocatedNodes[0].Lines[0].PeriodUplink != 150 || v.AllocatedNodes[0].Lines[0].PeriodDownlink != 250 {
		t.Fatalf("allocated period bytes: %+v", v.AllocatedNodes)
	}

	// Alerts: 400 stored plus 500 pending is 90 percent of the period quota.
	projection := vpnUserUsageProjection(erin)
	projection.UsedBytes = 5000 // lifetime total is irrelevant to a period quota
	updated, alerts := srv.quotaEvaluate(projection, &erin, now, usageCounter{Downlink: 500})
	if len(alerts) != 1 || alerts[0].ThresholdPercent != 80 || alerts[0].UsedBytes != 900 || updated.LastQuotaNotifiedKey != "quota:1000:20260915:80" || updated.Status != model.ProxyUserStatusActive || updated.UsedBytes != 5000 {
		t.Fatalf("first alert: %+v key=%q status=%q", alerts, updated.LastQuotaNotifiedKey, updated.Status)
	}
	if _, again := srv.quotaEvaluate(updated, &erin, now, usageCounter{Downlink: 500}); len(again) != 0 {
		t.Fatalf("80 percent must not repeat inside the period: %+v", again)
	}
	over, alerts := srv.quotaEvaluate(updated, &erin, now, usageCounter{Downlink: 700})
	if len(alerts) != 1 || alerts[0].ThresholdPercent != 100 || over.Status != model.ProxyUserStatusOverQuota {
		t.Fatalf("100 percent: %+v status=%q", alerts, over.Status)
	}
	// Next period: the same thresholds fire again under a new key and the
	// status returns to active with nothing pending.
	next := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	fresh, alerts := srv.quotaEvaluate(over, &erin, next, usageCounter{})
	if len(alerts) != 0 || fresh.Status != model.ProxyUserStatusActive {
		t.Fatalf("new period reset: %+v status=%q", alerts, fresh.Status)
	}
	_, alerts = srv.quotaEvaluate(fresh, &erin, next, usageCounter{Downlink: 850})
	if len(alerts) != 1 || alerts[0].Key != "quota:1000:20261015:80" {
		t.Fatalf("new period alert: %+v", alerts)
	}
	// A lifetime quota keeps the old key shape and the old cursor semantics.
	lifetime := vpnUserUsageProjection(f.alice)
	lifetime.TrafficLimitBytes, lifetime.UsedBytes, lifetime.LastQuotaNotifiedKey = 1000, 900, "quota:1000:80"
	if _, alerts := srv.quotaEvaluate(lifetime, &f.alice, now, usageCounter{}); len(alerts) != 0 {
		t.Fatalf("lifetime cursor must still suppress: %+v", alerts)
	}
}

// The identity write paths validate and persist the period, and plan_add /
// plan_update set the quota before queueing the approval.
func TestQuotaPeriodWritePaths(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	f := seedUsageFleet(t, srv)
	raw, err := srv.vpnCoreUsersAdminRPC(context.Background(), "create", []byte(`{"email":"frank@example.com","credentials":[{"protocol":"vless"}],"quota_bytes":5000,"quota_period":"monthly"}`))
	if err != nil {
		t.Fatal(err)
	}
	var created struct {
		User vpnUserView `json:"user"`
	}
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatal(err)
	}
	if created.User.QuotaPeriod != "monthly" || created.User.QuotaResetDay != 1 || created.User.QuotaBytes != 5000 {
		t.Fatalf("create: %+v", created.User)
	}
	stored, _ := srv.getVpnUser(created.User.ID)
	if stored.QuotaPeriod != "monthly" || stored.QuotaResetDay != 1 {
		t.Fatalf("stored: %+v", stored)
	}
	for _, bad := range []string{`"quota_period":"weekly"`, `"quota_period":"monthly","quota_reset_day":29`, `"quota_reset_day":0`} {
		if _, err := srv.vpnCoreUsersAdminRPC(context.Background(), "update", []byte(`{"id":"`+created.User.ID+`",`+bad+`}`)); err == nil {
			t.Fatalf("update with %s must fail", bad)
		}
	}
	if _, err := srv.vpnCoreUsersAdminRPC(context.Background(), "update", []byte(`{"id":"`+created.User.ID+`","quota_period":"none"}`)); err != nil {
		t.Fatal(err)
	}
	stored, _ = srv.getVpnUser(created.User.ID)
	if stored.QuotaPeriod != "" || stored.QuotaResetDay != 0 || stored.QuotaBytes != 5000 {
		t.Fatalf("period cleared: %+v", stored)
	}

	// plan_add carries the quota; the approval is still what touches the node.
	ctx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, lineUserTestPrincipal())
	raw, err = srv.vpnCoreUsersAdminRPC(ctx, "plan_add", []byte(`{"user_id":"`+f.carol.ID+`","line_hash_id":"`+f.direct.LineHashID+`","quota_bytes":2048,"quota_period":"monthly","quota_reset_day":10}`))
	if err != nil {
		t.Fatal(err)
	}
	var planned struct {
		Approval model.Approval `json:"approval"`
	}
	if err := json.Unmarshal(raw, &planned); err != nil {
		t.Fatal(err)
	}
	if planned.Approval.Status != model.ApprovalPending {
		t.Fatalf("approval: %+v", planned.Approval)
	}
	carol, _ := srv.getVpnUser(f.carol.ID)
	if carol.QuotaBytes != 2048 || carol.QuotaPeriod != "monthly" || carol.QuotaResetDay != 10 || len(carol.Bindings) != 0 {
		t.Fatalf("carol after plan_add: %+v", carol)
	}
	if _, err := srv.vpnCoreUsersAdminRPC(ctx, "plan_update", []byte(`{"user_id":"`+f.bob.ID+`","line_hash_id":"`+f.direct.LineHashID+`","quota_reset_day":40}`)); err == nil {
		t.Fatal("plan_update with an invalid reset day must fail")
	}
	if _, err := srv.vpnCoreUsersAdminRPC(ctx, "plan_update", []byte(`{"user_id":"`+f.bob.ID+`","line_hash_id":"`+f.direct.LineHashID+`","quota_bytes":-1}`)); err == nil {
		t.Fatal("plan_update with a negative quota must fail")
	}
	bob, _ := srv.getVpnUser(f.bob.ID)
	if bob.QuotaBytes != 0 {
		t.Fatalf("rejected plan must not touch the quota: %+v", bob)
	}
}

// A Sub-Store graph record selects a line through its entry roots: with no
// binding and no credential match the substore rule reports the identity,
// and the identity's allocated nodes list the line.
func TestUsageSubStoreSelection(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	f := seedUsageFleet(t, srv)
	orphan := VpnUser{ID: "vpnuser_gina", Email: "gina@example.com", Enabled: true, Credentials: []VpnCredential{{Protocol: "vless", UUID: "6b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"}}}
	if err := srv.putVpnUser(orphan); err != nil {
		t.Fatal(err)
	}
	// Move bob off direct-a so the line has no binding at all.
	bob, _ := srv.getVpnUser(f.bob.ID)
	bob.Bindings = nil
	if err := srv.putVpnUser(bob); err != nil {
		t.Fatal(err)
	}
	doc := `{"version":1,"records":[
		{"id":"rec-1","source":"vpn-core-graph","vpn_identity":"` + orphan.ID + `","entry_roots":["` + f.direct.LineUUID + `"]},
		{"id":"rec-2","source":"vpn-core-graph","vpn_identity":"` + f.alice.ID + `","entry_roots":["` + f.hub.LineUUID + `"]},
		{"id":"rec-3","source":"url","url":"https://example/sub","vpn_identity":"` + orphan.ID + `"}]}`
	if err := srv.store.PutKV(model.KVEntry{Bucket: usageSubStoreKVBucket, Key: usageSubStoreRecordsKey, Value: doc}); err != nil {
		t.Fatal(err)
	}
	srv.invalidateLineReadModel()
	ctx := srv.usageAttributionContext()
	direct := ctx.byHash[f.direct.LineHashID]
	if len(direct.SubStore) != 1 || direct.SubStore[0].IdentityID != orphan.ID || len(direct.Bound) != 0 {
		t.Fatalf("direct-a facts: %+v", direct)
	}
	rows := ctx.attributeLine("node-a", "direct-a", direct, usageLineTraffic{Inbound: usageCounter{Uplink: 5, Downlink: 6}})
	if len(rows) != 1 || rows[0].Attribution != usageAttributionSubstore || rows[0].UserID != orphan.ID || rows[0].Counted || !strings.Contains(rows[0].AttributionReason, "rec-1") {
		t.Fatalf("substore row: %+v", rows)
	}
	views := srv.vpnUserUsageViews([]VpnUser{orphan}, now)
	if len(views[0].AllocatedNodes) != 1 || views[0].AllocatedNodes[0].Lines[0].Allocation != "substore" || views[0].AllocatedNodes[0].Lines[0].LineHashID != f.direct.LineHashID {
		t.Fatalf("substore allocation: %+v", views[0].AllocatedNodes)
	}
	// Reported only: an ingestion through the substore rule feeds no quota.
	mustApplyUsage(t, srv, model.ProxyUsageSnapshot{NodeID: "node-a", CoreUptimeSec: 1, InboundTraffic: map[string]model.ProxyTrafficCounter{"direct-a": counter(1, 1)}})
	mustApplyUsage(t, srv, model.ProxyUsageSnapshot{NodeID: "node-a", CoreUptimeSec: 2, InboundTraffic: map[string]model.ProxyTrafficCounter{"direct-a": counter(11, 21)}})
	if _, ok := srv.store.ProxyUser(orphan.ID); ok {
		t.Fatal("substore attribution must not advance a user total")
	}
	if rows, _ := srv.store.UsageDayUserRows(orphan.ID, store.UsageDay(now), store.UsageDay(now)); len(rows) != 0 {
		t.Fatalf("substore attribution must not write user-day rows: %+v", rows)
	}
	nodes, _ := srv.store.UsageDayNodeRows("node-a", store.UsageDay(now), store.UsageDay(now))
	if nodes[0].Lines["direct-a"].Uplink != 10 || len(nodes[0].Lines["direct-a"].Users) != 0 {
		t.Fatalf("node row keeps the bytes without a user: %+v", nodes[0].Lines["direct-a"])
	}
}

// A named counter is proof on its own: when discovery is stale and the read
// model has no line for it, the user-day row is still written, and the
// inbound bytes are kept as an unknown_line node row until the line is back.
func TestUsageNamedCounterSurvivesStaleDiscovery(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	f := seedUsageFleet(t, srv)
	mustApplyUsage(t, srv, model.ProxyUsageSnapshot{NodeID: "node-a", CoreUptimeSec: 1,
		InboundTraffic: map[string]model.ProxyTrafficCounter{"hub-a": counter(10, 10)}, UserTraffic: map[string]model.ProxyTrafficCounter{f.aliceName: counter(5, 5)}})
	srv.singboxInvMu.Lock()
	srv.singboxInv = map[string]model.SingBoxInventory{}
	srv.singboxInvMu.Unlock()
	srv.invalidateLineReadModel()
	result := mustApplyUsage(t, srv, model.ProxyUsageSnapshot{NodeID: "node-a", CoreUptimeSec: 2,
		InboundTraffic: map[string]model.ProxyTrafficCounter{"hub-a": counter(30, 40)}, UserTraffic: map[string]model.ProxyTrafficCounter{f.aliceName: counter(15, 25)}})
	if result.UnknownLines != 1 {
		t.Fatalf("result: %+v", result)
	}
	day := store.UsageDay(now)
	users, _ := srv.store.UsageDayUserRows(f.alice.ID, day, day)
	if len(users) != 1 || users[0].Uplink != 10 || users[0].Downlink != 20 || users[0].ByLine[f.hub.LineHashID].Downlink != 20 {
		t.Fatalf("alice row with stale discovery: %+v", users)
	}
	nodes, _ := srv.store.UsageDayNodeRows("node-a", day, day)
	if hub := nodes[0].Lines["hub-a"]; hub.Uplink != 20 || hub.Downlink != 30 || hub.LineHashID != "" {
		t.Fatalf("hub-a bytes must be kept as an unknown line: %+v", hub)
	}
	if pu, _ := srv.store.ProxyUser(f.alice.ID); pu.UsedBytes != 30 {
		t.Fatalf("alice total: %+v", pu)
	}
}

// used_total_bytes and used_period_bytes come out of one scan of one set of
// user-day rows, so the total is never below the period it contains, whatever
// mix of attribution rules produced the traffic. The cases are the ones that
// took different paths through ingestion: an identity credited only by an
// inferred binding, one credited only by its named counter, one credited both
// ways in the same report, one with nothing at all, and one whose oldest rows
// sit outside the retention window and so cannot be part of the total.
func TestVpnUserUsageViewTotalCoversPeriod(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	today := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	retained := today.AddDate(0, 0, -store.UsageDayRetentionDays)
	srv := usageTestServer(t, now)
	f := seedUsageFleet(t, srv)

	// Monthly quotas so the period is a strict subset of the total, and an
	// explicit CreatedAt so the truncation flag is not read off a zero time.
	withPeriod := func(u VpnUser, created time.Time) VpnUser {
		u.QuotaPeriod, u.QuotaResetDay, u.QuotaBytes = vpnQuotaPeriodMonthly, 1, 1<<30
		u.CreatedAt = created
		return u
	}
	erin := withPeriod(VpnUser{ID: "vpnuser_erin", Email: "erin@example.com", Enabled: true,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: "5b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"}},
		Bindings:    []LineBinding{{LineHashID: f.hub.LineHashID, Enabled: true}, {LineHashID: f.hub2.LineHashID, Enabled: true}}}, now)
	frank := withPeriod(VpnUser{ID: "vpnuser_frank", Email: "frank@example.com", Enabled: true,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: "6b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"}}}, now)
	// grace predates the retention window, so her total is a floor.
	grace := withPeriod(VpnUser{ID: "vpnuser_grace", Email: "grace@example.com", Enabled: true,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: "7b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"}}}, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	for _, u := range []VpnUser{withPeriod(f.alice, now), withPeriod(f.bob, now), erin, frank, grace} {
		if err := srv.putVpnUser(u); err != nil {
			t.Fatal(err)
		}
	}
	erinHubName := userLineName(erin.ID, f.hub.LineUUID)

	// One baseline and one delta on node-a. alice and erin are named on
	// hub-a; erin is also the only binding on hub2-a and bob the only one on
	// direct-a, so those two lines are credited by inference.
	mustApplyUsage(t, srv, model.ProxyUsageSnapshot{NodeID: "node-a", CoreUptimeSec: 100,
		InboundTraffic: map[string]model.ProxyTrafficCounter{"hub-a": counter(1000, 2000), "hub2-a": counter(100, 100), "direct-a": counter(10, 20)},
		UserTraffic:    map[string]model.ProxyTrafficCounter{f.aliceName: counter(300, 600), erinHubName: counter(50, 50)},
	})
	mustApplyUsage(t, srv, model.ProxyUsageSnapshot{NodeID: "node-a", CoreUptimeSec: 200,
		InboundTraffic: map[string]model.ProxyTrafficCounter{"hub-a": counter(1500, 2600), "hub2-a": counter(160, 240), "direct-a": counter(40, 70)},
		UserTraffic:    map[string]model.ProxyTrafficCounter{f.aliceName: counter(400, 800), erinHubName: counter(80, 110)},
	})
	// A third report, so a day holds more than one round. The legacy
	// projection keeps only this last round and falls below the period.
	mustApplyUsage(t, srv, model.ProxyUsageSnapshot{NodeID: "node-a", CoreUptimeSec: 300,
		InboundTraffic: map[string]model.ProxyTrafficCounter{"hub-a": counter(1600, 2700), "hub2-a": counter(200, 300), "direct-a": counter(60, 110)},
		UserTraffic:    map[string]model.ProxyTrafficCounter{f.aliceName: counter(450, 900), erinHubName: counter(100, 130)},
	})

	// Rows before this period but inside retention, and one day older than
	// the window, which no total may include.
	seed := func(userID, day string, up, down int64) {
		t.Helper()
		if err := srv.store.ApplyProxyUsage(store.ProxyUsageUpdate{DayUsers: []store.UsageDayUser{
			{UserID: userID, Day: day, Uplink: up, Downlink: down}}}); err != nil {
			t.Fatal(err)
		}
	}
	const beforePeriod = "20260810"
	seed(f.alice.ID, beforePeriod, 300, 400)
	seed(f.bob.ID, beforePeriod, 200, 300)
	seed(erin.ID, beforePeriod, 100, 150)
	seed(grace.ID, beforePeriod, 150, 250)
	seed(grace.ID, store.UsageDay(retained.AddDate(0, 0, -1)), 5000, 4999)

	views := map[string]vpnUserUsageView{}
	for _, v := range srv.vpnUserUsageViews(srv.listVpnUsers(), now) {
		views[v.ID] = v
	}
	cases := []struct {
		name          string
		userID        string
		total, period int64
		wantTruncated bool
	}{
		{name: "inferred binding only", userID: f.bob.ID, total: 640, period: 140},
		{name: "named counter only", userID: f.alice.ID, total: 1150, period: 450},
		{name: "named and inferred in one report", userID: erin.ID, total: 680, period: 430},
		{name: "no traffic at all", userID: frank.ID, total: 0, period: 0},
		{name: "rows older than retention are not lifetime", userID: grace.ID, total: 400, period: 0, wantTruncated: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, ok := views[tc.userID]
			if !ok {
				t.Fatalf("%s missing from the users list", tc.userID)
			}
			if v.UsedTotalBytes < v.UsedPeriodBytes {
				t.Fatalf("total %d is below the period %d it contains", v.UsedTotalBytes, v.UsedPeriodBytes)
			}
			if v.UsedTotalBytes != tc.total || v.UsedPeriodBytes != tc.period {
				t.Fatalf("total/period = %d/%d, want %d/%d", v.UsedTotalBytes, v.UsedPeriodBytes, tc.total, tc.period)
			}
			if v.UsedTotalFrom != retained.Format(usageWireTimeFmt) {
				t.Fatalf("used_total_from = %q, want %q", v.UsedTotalFrom, retained.Format(usageWireTimeFmt))
			}
			if v.UsedTotalTruncated != tc.wantTruncated {
				t.Fatalf("used_total_truncated = %v, want %v", v.UsedTotalTruncated, tc.wantTruncated)
			}
		})
	}
}

// The regression this fixes. The legacy ProxyUser projection is rebuilt from
// the identity on every report, so it holds the last delta rather than a
// lifetime, and production showed a total of 534 beside a period of 1602 for
// the same user at the same instant. The users list must read the day rows,
// which carry the same attribution decisions as the period.
func TestVpnUserUsageViewIgnoresStaleProxyUserProjection(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	f := seedUsageFleet(t, srv)
	reportUsageFleet(t, srv, f)
	// Two further reports, which is all it takes: the projection drops what
	// it held and keeps only this round's delta.
	mustApplyUsage(t, srv, model.ProxyUsageSnapshot{NodeID: "node-a", CoreUptimeSec: 300,
		InboundTraffic: map[string]model.ProxyTrafficCounter{"direct-a": counter(50, 90)}})
	mustApplyUsage(t, srv, model.ProxyUsageSnapshot{NodeID: "node-a", CoreUptimeSec: 400,
		InboundTraffic: map[string]model.ProxyTrafficCounter{"direct-a": counter(60, 110)}})

	day := store.UsageDay(now)
	rows, err := srv.store.UsageDayUserRows(f.bob.ID, day, day)
	if err != nil || len(rows) != 1 {
		t.Fatalf("bob day rows: %v %+v", err, rows)
	}
	counted := rows[0].Uplink + rows[0].Downlink
	pu, ok := srv.store.ProxyUser(f.bob.ID)
	if !ok || pu.UsedBytes >= counted {
		t.Fatalf("fixture no longer reproduces the stale projection: projection=%d counted=%d", pu.UsedBytes, counted)
	}

	bob, ok := srv.getVpnUser(f.bob.ID)
	if !ok {
		t.Fatal("bob missing")
	}
	v := srv.vpnUserUsageViews([]VpnUser{bob}, now)[0]
	if v.UsedTotalBytes != counted {
		t.Fatalf("used_total_bytes = %d, want the counted day rows %d", v.UsedTotalBytes, counted)
	}
	if v.UsedTotalBytes < v.UsedPeriodBytes {
		t.Fatalf("total %d is below the period %d", v.UsedTotalBytes, v.UsedPeriodBytes)
	}
}
