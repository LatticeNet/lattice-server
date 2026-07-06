package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func newInventoryServer(t *testing.T) (*Server, http.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	return srv, srv.Handler(), st
}

func TestMachineProfileCreateListHidesLinks(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "gmami-jp1", Online: true}); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)

	create := doJSON(t, handler, http.MethodPost, "/api/machines", `{
		"node_id":"node-a",
		"label":"gmami-jp1",
		"vendor":"DMIT",
		"console_url":"https://console.example.com/session/signed-secret",
		"detail_url":"https://billing.example.com/machine/private-link",
		"region":"JP-Tokyo",
		"price_cents":990,
		"currency":"usd",
		"renewal_cycle":"annual",
		"next_renewal":"2026-07-01T00:00:00Z",
		"remind_days_before":[14,7,1],
		"reminders_enabled":true,
		"auto_roll":true
	}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create failed: %d", create.StatusCode)
	}

	list := doJSON(t, handler, http.MethodGet, "/api/machines", "", cookies, "")
	defer list.Body.Close()
	body := new(bytes.Buffer)
	body.ReadFrom(list.Body)
	if strings.Contains(body.String(), "signed-secret") || strings.Contains(body.String(), "private-link") ||
		strings.Contains(body.String(), `"console_url"`) || strings.Contains(body.String(), `"detail_url"`) {
		t.Fatalf("machine list leaked secret links: %s", body.String())
	}
	if !strings.Contains(body.String(), `"has_console_url":true`) || !strings.Contains(body.String(), `"has_detail_url":true`) {
		t.Fatalf("machine list missing redacted link badges: %s", body.String())
	}
	if !strings.Contains(body.String(), `"currency":"USD"`) {
		t.Fatalf("currency should be normalized to uppercase: %s", body.String())
	}
}

func TestMachineProfileUpdateKeepsLinksWriteOnly(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)
	create := doJSON(t, handler, http.MethodPost, "/api/machines",
		`{"node_id":"node-a","vendor":"DMIT","console_url":"https://console.example.com/secret","detail_url":"https://detail.example.com/secret"}`,
		cookies, csrf)
	defer create.Body.Close()
	var created machineView
	if err := json.NewDecoder(create.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	update := doJSON(t, handler, http.MethodPost, "/api/machines/update",
		`{"id":"`+created.ID+`","vendor":"Vultr","region":"US-LAX"}`,
		cookies, csrf)
	defer update.Body.Close()
	if update.StatusCode != http.StatusOK {
		t.Fatalf("update failed: %d", update.StatusCode)
	}
	stored, ok := st.MachineProfile(created.ID)
	if !ok || stored.ConsoleURL != "https://console.example.com/secret" || stored.DetailURL != "https://detail.example.com/secret" {
		t.Fatalf("blank update should preserve write-only links: ok=%v profile=%+v", ok, stored)
	}

	clear := doJSON(t, handler, http.MethodPost, "/api/machines/update",
		`{"id":"`+created.ID+`","vendor":"Vultr","clear_console_url":true}`,
		cookies, csrf)
	defer clear.Body.Close()
	if clear.StatusCode != http.StatusOK {
		t.Fatalf("clear failed: %d", clear.StatusCode)
	}
	stored, _ = st.MachineProfile(created.ID)
	if stored.ConsoleURL != "" || stored.DetailURL == "" {
		t.Fatalf("clear_console_url should clear only console link: %+v", stored)
	}
}

func TestMachineProfileUpdatePreservesOmittedFields(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)
	create := doJSON(t, handler, http.MethodPost, "/api/machines", `{
		"node_id":"node-a",
		"label":"gmami-jp1",
		"vendor":"DMIT",
		"region":"JP-Tokyo",
		"notes":"billing owner cd",
		"price_cents":990,
		"currency":"usd",
		"renewal_cycle":"annual",
		"next_renewal":"2026-07-01T00:00:00Z",
		"remind_days_before":[14,7,1],
		"reminders_enabled":true,
		"auto_roll":true
	}`, cookies, csrf)
	defer create.Body.Close()
	var created machineView
	if err := json.NewDecoder(create.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	update := doJSON(t, handler, http.MethodPost, "/api/machines/update",
		`{"id":"`+created.ID+`","vendor":"Vultr"}`,
		cookies, csrf)
	defer update.Body.Close()
	if update.StatusCode != http.StatusOK {
		t.Fatalf("update failed: %d", update.StatusCode)
	}
	stored, ok := st.MachineProfile(created.ID)
	if !ok {
		t.Fatal("profile missing after update")
	}
	if stored.Vendor != "Vultr" || stored.Label != "gmami-jp1" || stored.Region != "JP-Tokyo" ||
		stored.Notes != "billing owner cd" || stored.PriceCents != 990 || stored.Currency != "USD" ||
		stored.RenewalCycle != model.RenewalCycleAnnual || stored.NextRenewal.IsZero() ||
		!stored.AutoRoll || !stored.RemindersEnabled || len(stored.RemindDaysBefore) != 3 {
		t.Fatalf("partial update should preserve omitted fields: %+v", stored)
	}

	clear := doJSON(t, handler, http.MethodPost, "/api/machines/update", `{
		"id":"`+created.ID+`",
		"label":"",
		"region":"",
		"notes":"",
		"price_cents":0,
		"currency":"",
		"renewal_cycle":"",
		"cycle_days":0,
		"next_renewal":null,
		"auto_roll":false,
		"remind_days_before":[],
		"reminders_enabled":false
	}`, cookies, csrf)
	defer clear.Body.Close()
	if clear.StatusCode != http.StatusOK {
		t.Fatalf("clear failed: %d", clear.StatusCode)
	}
	stored, _ = st.MachineProfile(created.ID)
	if stored.Label != "" || stored.Region != "" || stored.Notes != "" || stored.PriceCents != 0 ||
		stored.Currency != "" || stored.RenewalCycle != "" || !stored.NextRenewal.IsZero() ||
		stored.AutoRoll || stored.RemindersEnabled || len(stored.RemindDaysBefore) != 0 {
		t.Fatalf("explicit zero values should clear fields: %+v", stored)
	}
}

func TestMachineProfilesRespectNodeAllowlist(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNode(model.Node{ID: "node-b", Name: "node-b"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertMachineProfile(model.MachineProfile{ID: "mp-a", NodeID: "node-a", Vendor: "A"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertMachineProfile(model.MachineProfile{ID: "mp-b", NodeID: "node-b", Vendor: "B"}); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"inventory:read"}, []string{"node-a"})

	req := httptest.NewRequest(http.MethodGet, "/api/machines", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := serveReq(handler, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list failed: %d (%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "node-b") || !strings.Contains(rec.Body.String(), "node-a") {
		t.Fatalf("node allowlist not enforced: %s", rec.Body.String())
	}
}

func TestMachineReminderFiresOncePerOffset(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "gmami-jp1"}); err != nil {
		t.Fatal(err)
	}
	next := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if err := st.UpsertMachineProfile(model.MachineProfile{
		ID: "mp-a", NodeID: "node-a", Label: "gmami-jp1", Vendor: "DMIT", Region: "JP-Tokyo",
		PriceCents: 990, Currency: "USD", RenewalCycle: model.RenewalCycleAnnual,
		NextRenewal: next, RemindDaysBefore: []int{14, 7, 1}, RemindersEnabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	var sent []string
	srv.emitNotify = func(title, body string) { sent = append(sent, title+"|"+body) }

	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	fired, err := srv.evaluateMachineReminders(now, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fired) != 1 || fired[0].OffsetDays != 7 || len(sent) != 1 {
		t.Fatalf("expected exactly the 7-day reminder once, fired=%+v sent=%+v", fired, sent)
	}
	again, err := srv.evaluateMachineReminders(now, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 || len(sent) != 1 {
		t.Fatalf("same reminder should not fire twice, fired=%+v sent=%+v", again, sent)
	}
}

func TestMachineRenewAutoRollsAndResetsReminderCursor(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	next := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if err := st.UpsertMachineProfile(model.MachineProfile{
		ID: "mp-a", NodeID: "node-a", RenewalCycle: model.RenewalCycleMonthly,
		NextRenewal: next, AutoRoll: true, LastRemindedKey: "2026-07-01:1",
	}); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/machines/renew", `{"id":"mp-a"}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("renew failed: %d", res.StatusCode)
	}
	stored, ok := st.MachineProfile("mp-a")
	if !ok {
		t.Fatal("profile missing after renew")
	}
	if got := stored.NextRenewal.Format("2006-01-02"); got != "2026-08-01" {
		t.Fatalf("next renewal = %s, want 2026-08-01", got)
	}
	if stored.LastRemindedKey != "" {
		t.Fatalf("renew should reset reminder cursor, got %q", stored.LastRemindedKey)
	}
}

func TestMachineClientJSONIsStrict(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	if err := st.UpsertNode(model.Node{ID: "node-a"}); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/machines",
		`{"node_id":"node-a","vendor":"DMIT","unexpected":true}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown client JSON fields must be rejected, got %d", res.StatusCode)
	}
}
