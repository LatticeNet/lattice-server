package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// seedExpiring puts one of every kind on the calendar around 2026-09-29, plus
// rows that must stay out: a date past the window, a machine with no date, a
// disabled user and a disabled share.
func seedExpiring(t *testing.T, srv *Server, st *store.Store) {
	t.Helper()
	mustUpsertNodes(t, st, "node-a", "node-b")
	mustUpsertProfiles(t, st,
		model.MachineProfile{ID: "mp-a", NodeID: "node-a", Label: "openjobs-vpn-dmit-1", Vendor: "DMIT", Region: "LAX", NextRenewal: day(2026, 10, 6), RemindDaysBefore: []int{7, 1}, RemindersEnabled: true, PriceCents: 500, Currency: "USD"},
		model.MachineProfile{ID: "mp-b", NodeID: "node-b", Label: "legend-sg", NextRenewal: day(2026, 9, 20), AutoRoll: true, RenewalCycle: model.RenewalCycleMonthly, RemindDaysBefore: []int{7}, RemindersEnabled: true, PriceCents: 1250, Currency: "USD"},
		model.MachineProfile{ID: "mp-c", NodeID: "node-b", Label: "cd-xuezhang-jp-nat", Vendor: "Xuezhang", Region: "Tokyo", NextRenewal: day(2026, 9, 25), PriceCents: 3000, Currency: "CNY"},
		model.MachineProfile{ID: "mp-d", NodeID: "node-a", Label: "far-away", NextRenewal: day(2027, 3, 1)},
		model.MachineProfile{ID: "mp-e", NodeID: "node-b", Label: "undated"},
	)
	for _, u := range []VpnUser{
		{ID: "vpnuser_alice", Email: "alice@example.com", Name: "Alice", Enabled: true, ExpiresAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)},
		{ID: "vpnuser_off", Email: "off@example.com", Enabled: false, ExpiresAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)},
	} {
		if err := srv.putVpnUser(u); err != nil {
			t.Fatal(err)
		}
	}
	shareExpiry := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	for _, share := range []model.SubscriptionShare{
		{ID: "share_cdcd", Slug: "cdcd", Enabled: true, ExpiresAt: &shareExpiry, Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: subStorePluginID, SubscriptionID: "for-cdcd-loon"}},
		{ID: "share_off", Slug: "off", Enabled: false, ExpiresAt: &shareExpiry, Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: subStorePluginID, SubscriptionID: "x"}},
	} {
		if err := st.UpsertSubscriptionShare(share); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.UpsertMonitor(model.Monitor{ID: "mon_doh", Name: "DoH certificate", Type: model.MonitorTypeTLS, Target: "dns.example.org:8443", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	for _, r := range []model.MonitorResult{
		{MonitorID: "mon_doh", At: time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC), Success: true, CertNotAfter: time.Date(2026, 10, 10, 23, 59, 59, 0, time.UTC)},
		{MonitorID: "mon_doh", At: time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC), Error: "dial tcp: i/o timeout"},
	} {
		if err := st.AddMonitorResult(r); err != nil {
			t.Fatal(err)
		}
	}
}

func getExpiring(t *testing.T, handler http.Handler, req *http.Request) expiringResponse {
	t.Helper()
	rec := serveReq(handler, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", req.URL, rec.Code, rec.Body.String())
	}
	var out expiringResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestExpiringListsEveryKindInDateOrder(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	now := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	srv.now = func() time.Time { return now }
	seedExpiring(t, srv, st)
	cookies, _ := loginSession(t, handler)
	req := httptest.NewRequest(http.MethodGet, "/api/expiring", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	out := getExpiring(t, handler, req)

	type row struct {
		kind, id, state, href string
		days                  int
	}
	want := []row{
		{expiringKindMachine, "mp-c", expiringStateOverdue, "/inventory?node=node-b", -4},
		{expiringKindVPNUser, "vpnuser_alice", expiringStateDue, "/plugins/latticenet.vpn-core/users", 2},
		{expiringKindMachine, "mp-a", expiringStateDue, "/inventory?node=node-a", 7},
		{expiringKindTLS, "mon_doh", expiringStateUpcoming, "/monitoring/mon_doh", 11},
		{expiringKindMachine, "mp-b", expiringStateAuto, "/inventory?node=node-b", 21},
		{expiringKindShare, "share_cdcd", expiringStateUpcoming, "/platform/publishing?origin=share&share=share_cdcd", 47},
	}
	if len(out.Items) != len(want) {
		t.Fatalf("items = %+v", out.Items)
	}
	for i, w := range want {
		got := out.Items[i]
		if got.Kind != w.kind || got.ID != w.id || got.State != w.state || got.Href != w.href || got.Days != w.days {
			t.Fatalf("item %d = %+v, want %+v", i, got, w)
		}
	}
	if out.WithinDays != 60 || out.Hidden != 0 || !out.GeneratedAt.Equal(now) {
		t.Fatalf("envelope: within=%d hidden=%d generated_at=%v", out.WithinDays, out.Hidden, out.GeneratedAt)
	}
	overdue, alice, dmit, cert, auto := out.Items[0], out.Items[1], out.Items[2], out.Items[3], out.Items[4]
	if overdue.Title != "cd-xuezhang-jp-nat" || overdue.Subtitle != "Xuezhang · Tokyo" || overdue.CostCents != 3000 || overdue.Currency != "CNY" ||
		overdue.Reminder == nil || overdue.Reminder.Enabled || overdue.Reminder.NextOffsetDays != nil {
		t.Fatalf("overdue machine row: %+v", overdue)
	}
	if dmit.Reminder == nil || !dmit.Reminder.Enabled || dmit.Reminder.NextOffsetDays == nil || *dmit.Reminder.NextOffsetDays != 7 || !dmit.DueAt.Equal(day(2026, 10, 6)) {
		t.Fatalf("reminded machine row: %+v %+v", dmit, dmit.Reminder)
	}
	// The auto_roll machine reads at its rolled date before the scheduler writes it.
	if !auto.DueAt.Equal(day(2026, 10, 20)) || auto.Reminder.NextOffsetDays == nil || *auto.Reminder.NextOffsetDays != 7 {
		t.Fatalf("auto_roll row: %+v %+v", auto, auto.Reminder)
	}
	if alice.Title != "alice@example.com" || alice.Subtitle != "Alice" || alice.Reminder != nil || alice.CostCents != 0 || alice.Currency != "" {
		t.Fatalf("vpn user row: %+v", alice)
	}
	if !cert.DueAt.Equal(time.Date(2026, 10, 10, 23, 59, 59, 0, time.UTC)) || cert.Subtitle != "dns.example.org:8443" {
		t.Fatalf("tls row should read the newest completed handshake: %+v", cert)
	}
	wantTotals := []expiringTotal{{Currency: "CNY", CostCents: 3000, Count: 1}, {Currency: "USD", CostCents: 1750, Count: 2}}
	if len(out.Totals) != 2 || out.Totals[0] != wantTotals[0] || out.Totals[1] != wantTotals[1] {
		t.Fatalf("totals = %+v", out.Totals)
	}

	// A shorter window keeps what is past due and drops what is further out.
	short := httptest.NewRequest(http.MethodGet, "/api/expiring?within=5", nil)
	for _, c := range cookies {
		short.AddCookie(c)
	}
	if got := getExpiring(t, handler, short); len(got.Items) != 2 || got.Items[0].ID != "mp-c" || got.Items[1].ID != "vpnuser_alice" || got.WithinDays != 5 {
		t.Fatalf("within=5: %+v", got.Items)
	}
	for _, bad := range []string{"0", "366", "soon"} {
		req := httptest.NewRequest(http.MethodGet, "/api/expiring?within="+bad, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		if rec := serveReq(handler, req); rec.Code != http.StatusBadRequest {
			t.Fatalf("within=%s: %d", bad, rec.Code)
		}
	}
}

// Each kind is read under its own list endpoint's scope, and every row the
// session cannot read is counted, not dropped.
func TestExpiringCountsRowsTheSessionCannotRead(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	now := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	srv.now = func() time.Time { return now }
	seedExpiring(t, srv, st)
	cookies, csrf := loginSession(t, handler)

	cases := []struct {
		name      string
		scopes    []string
		allowlist []string
		ids       []string
		hidden    int
	}{
		// Node-restricted inventory reader: its own node's machine only; the
		// fleet-wide kinds refuse a restricted session.
		{"inventory on node-a", []string{"inventory:read", "proxy:admin", "monitor:read"}, []string{"node-a"}, []string{"mp-a"}, 5},
		{"monitor reader", []string{"monitor:read"}, nil, []string{"mon_doh"}, 5},
		{"vpn-core reader", []string{"vpncore:read"}, nil, []string{"vpnuser_alice"}, 5},
		// proxy:admin does not imply proxy:read here, exactly as /api/proxy/users.
		{"proxy admin", []string{"proxy:admin"}, nil, []string{"share_cdcd"}, 5},
		{"proxy reader and admin", []string{"proxy:read", "proxy:admin"}, nil, []string{"vpnuser_alice", "share_cdcd"}, 4},
		{"nothing readable", []string{"audit:read"}, nil, nil, 6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := createPAT(t, handler, cookies, csrf, tc.scopes, tc.allowlist)
			req := httptest.NewRequest(http.MethodGet, "/api/expiring", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			out := getExpiring(t, handler, req)
			ids := []string{}
			for _, item := range out.Items {
				ids = append(ids, item.ID)
			}
			if len(ids) != len(tc.ids) || out.Hidden != tc.hidden {
				t.Fatalf("ids=%v hidden=%d, want %v hidden=%d", ids, out.Hidden, tc.ids, tc.hidden)
			}
			for i := range ids {
				if ids[i] != tc.ids[i] {
					t.Fatalf("ids=%v, want %v", ids, tc.ids)
				}
			}
		})
	}
}
