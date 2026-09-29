package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

type sentNotification struct {
	eventType, title, body string
}

// captureRenewalNotifications records every typed notification the server
// emits, which is the path renewal reminders take.
func captureRenewalNotifications(t *testing.T, srv *Server) *[]sentNotification {
	t.Helper()
	sent := &[]sentNotification{}
	srv.emitNotifyTyped = func(eventType, title, body string) {
		if eventType != "inventory.renewal" {
			t.Errorf("renewal reminder sent as %q: %s", eventType, title)
		}
		*sent = append(*sent, sentNotification{eventType: eventType, title: title, body: body})
	}
	return sent
}

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

func mustUpsertNodes(t *testing.T, st *store.Store, ids ...string) {
	t.Helper()
	for _, nodeID := range ids {
		if err := st.UpsertNode(model.Node{ID: nodeID, Name: nodeID}); err != nil {
			t.Fatal(err)
		}
	}
}

func mustUpsertProfiles(t *testing.T, st *store.Store, profiles ...model.MachineProfile) {
	t.Helper()
	for _, p := range profiles {
		if err := st.UpsertMachineProfile(p); err != nil {
			t.Fatal(err)
		}
	}
}

func auditEventsWithAction(st *store.Store, action string) []model.AuditEvent {
	out := []model.AuditEvent{}
	for _, ev := range st.AuditEvents() {
		if ev.Action == action {
			out = append(out, ev)
		}
	}
	return out
}

// A profile created with a renewal date and no reminder fields is reminded
// with the default offsets; one without a date, or one the operator opted out,
// is not. The acceptance line: a machine created with defaults and a date
// inside its offsets fires.
func TestMachineCreateDefaultsRemindersOn(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	mustUpsertNodes(t, st, "node-a", "node-b", "node-c")
	cookies, csrf := loginSession(t, handler)
	create := func(body string) machineView {
		t.Helper()
		res := doJSON(t, handler, http.MethodPost, "/api/machines", body, cookies, csrf)
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("create %s: %d", body, res.StatusCode)
		}
		var view machineView
		if err := json.NewDecoder(res.Body).Decode(&view); err != nil {
			t.Fatal(err)
		}
		return view
	}
	dated := create(`{"node_id":"node-a","label":"openjobs-vpn-dmit-1","renewal_cycle":"monthly","next_renewal":"2026-10-06T00:00:00Z","price_cents":500,"currency":"USD"}`)
	if !dated.RemindersEnabled || !reflect.DeepEqual(dated.RemindDaysBefore, []int{14, 7, 3, 1, 0}) {
		t.Fatalf("dated profile should default to reminders on with 14,7,3,1,0: %+v", dated)
	}
	undated := create(`{"node_id":"node-b","label":"no-date"}`)
	if undated.RemindersEnabled || len(undated.RemindDaysBefore) != 0 {
		t.Fatalf("a profile without a date has nothing to remind about: %+v", undated)
	}
	optedOut := create(`{"node_id":"node-c","next_renewal":"2026-10-06T00:00:00Z","reminders_enabled":false}`)
	if optedOut.RemindersEnabled {
		t.Fatalf("an explicit reminders_enabled:false must stand: %+v", optedOut)
	}

	sent := captureRenewalNotifications(t, srv)
	fired, err := srv.evaluateMachineReminders(time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fired) != 1 || fired[0].MachineID != dated.ID || fired[0].OffsetDays != 7 || len(*sent) != 1 {
		t.Fatalf("default-on machine 7 days out should fire once: fired=%+v sent=%+v", fired, *sent)
	}
}

// The boot migration turns reminders on for every profile with a date, gives
// the ones with no offsets the defaults, audits the ids once, and never runs
// again: an operator who turns a machine off afterwards keeps it off.
func TestReminderDefaultsMigrationRunsOnceAndKeepsOperatorChoice(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	mustUpsertNodes(t, st, "node-a", "node-b", "node-c", "node-d")
	mustUpsertProfiles(t, st,
		model.MachineProfile{ID: "mp-a", NodeID: "node-a", NextRenewal: day(2026, 10, 6)},
		model.MachineProfile{ID: "mp-b", NodeID: "node-b", NextRenewal: day(2026, 10, 20), RemindDaysBefore: []int{7, 1}},
		model.MachineProfile{ID: "mp-c", NodeID: "node-c"},
		model.MachineProfile{ID: "mp-d", NodeID: "node-d", NextRenewal: day(2026, 11, 1), RemindersEnabled: true, RemindDaysBefore: []int{3}},
	)
	boot := func() {
		t.Helper()
		if _, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true}); err != nil {
			t.Fatal(err)
		}
	}
	boot()

	want := map[string]struct {
		enabled bool
		offsets []int
	}{
		"mp-a": {true, []int{14, 7, 3, 1, 0}},
		"mp-b": {true, []int{7, 1}},
		"mp-c": {false, nil},
		"mp-d": {true, []int{3}},
	}
	for id, w := range want {
		p, _ := st.MachineProfile(id)
		if p.RemindersEnabled != w.enabled || !reflect.DeepEqual(p.RemindDaysBefore, w.offsets) {
			t.Fatalf("%s after migration: enabled=%v offsets=%v, want %v %v", id, p.RemindersEnabled, p.RemindDaysBefore, w.enabled, w.offsets)
		}
	}
	events := auditEventsWithAction(st, "inventory.reminders.default_on")
	if len(events) != 1 || events[0].Metadata["machine_ids"] != "mp-a,mp-b" || events[0].Metadata["count"] != "2" {
		t.Fatalf("migration audit: %+v", events)
	}

	off, _ := st.MachineProfile("mp-a")
	off.RemindersEnabled = false
	mustUpsertProfiles(t, st, off)
	boot()
	if p, _ := st.MachineProfile("mp-a"); p.RemindersEnabled {
		t.Fatalf("a restart re-enabled reminders the operator turned off: %+v", p)
	}
	if events := auditEventsWithAction(st, "inventory.reminders.default_on"); len(events) != 1 {
		t.Fatalf("migration audited %d times, want once", len(events))
	}
}

// Several machines firing in one run arrive as one message, soonest first,
// with a total per currency; the run endpoint keeps its response shape.
func TestRenewalRemindersArriveAsOneDigest(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	now := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	srv.now = func() time.Time { return now }
	mustUpsertNodes(t, st, "node-a", "node-b", "node-c", "node-d")
	mustUpsertProfiles(t, st,
		model.MachineProfile{ID: "mp-a", NodeID: "node-a", Label: "openjobs-vpn-dmit-1", NextRenewal: day(2026, 10, 6), RemindDaysBefore: []int{7}, RemindersEnabled: true, PriceCents: 500, Currency: "USD"},
		model.MachineProfile{ID: "mp-b", NodeID: "node-b", Label: "cd-xuezhang-jp-nat", NextRenewal: day(2026, 9, 30), RemindDaysBefore: []int{1}, RemindersEnabled: true, PriceCents: 3000, Currency: "CNY"},
		model.MachineProfile{ID: "mp-c", NodeID: "node-c", Label: "legend-sg", NextRenewal: day(2026, 10, 2), RemindDaysBefore: []int{3}, RemindersEnabled: true, PriceCents: 1250, Currency: "USD", AutoRoll: true, RenewalCycle: model.RenewalCycleMonthly},
		model.MachineProfile{ID: "mp-d", NodeID: "node-d", Label: "no-price", NextRenewal: day(2026, 10, 6), RemindDaysBefore: []int{7}, RemindersEnabled: true},
	)
	sent := captureRenewalNotifications(t, srv)
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/machines/reminders/run", "", cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("run: %d", res.StatusCode)
	}
	var out map[string][]renewalReminderFire
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || len(out["fired"]) != 4 {
		t.Fatalf("response shape: %+v", out)
	}
	if len(*sent) != 1 {
		t.Fatalf("one run must send one message, sent %d: %+v", len(*sent), *sent)
	}
	msg := (*sent)[0]
	if msg.title != "Lattice renewal digest: 4 due" || classifyNotifyEvent(msg.title) != "inventory.renewal" {
		t.Fatalf("digest title: %q", msg.title)
	}
	wantBody := strings.Join([]string{
		"09-30  cd-xuezhang-jp-nat  in 1d  CNY 30.00",
		"10-02  legend-sg  auto-renews in 3d  USD 12.50",
		"10-06  no-price  in 7d",
		"10-06  openjobs-vpn-dmit-1  in 7d  USD 5.00",
		"",
		"Total CNY 30.00",
		"Total USD 17.50",
	}, "\n")
	if msg.body != wantBody {
		t.Fatalf("digest body:\n%s\nwant:\n%s", msg.body, wantBody)
	}
}

// An auto_roll machine whose date has passed rolls to the next cycle and is
// never reminded as overdue; its reminder names the date and the charge.
func TestAutoRollMachineRollsInsteadOfGoingOverdue(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	mustUpsertNodes(t, st, "node-a")
	mustUpsertProfiles(t, st, model.MachineProfile{
		ID: "mp-a", NodeID: "node-a", Label: "legend-sg", Vendor: "DMIT", Region: "SG",
		RenewalCycle: model.RenewalCycleMonthly, AutoRoll: true, NextRenewal: day(2026, 9, 20),
		RemindDaysBefore: []int{7, 0}, RemindersEnabled: true, LastRemindedKey: "2026-09-20:0",
		PriceCents: 500, Currency: "USD",
	})
	sent := captureRenewalNotifications(t, srv)

	fired, err := srv.evaluateMachineReminders(time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := st.MachineProfile("mp-a")
	if !stored.NextRenewal.Equal(day(2026, 10, 20)) || stored.LastRemindedKey != "" {
		t.Fatalf("auto_roll should roll to 2026-10-20 and reset the cursor: %+v", stored)
	}
	if len(fired) != 0 || len(*sent) != 0 {
		t.Fatalf("a rolled machine is not overdue: fired=%+v sent=%+v", fired, *sent)
	}
	rolls := auditEventsWithAction(st, "inventory.auto_roll")
	if len(rolls) != 1 || rolls[0].Metadata["from"] != "2026-09-20" || rolls[0].Metadata["next_renewal"] != "2026-10-20" {
		t.Fatalf("auto_roll audit: %+v", rolls)
	}

	fired, err = srv.evaluateMachineReminders(time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fired) != 1 || fired[0].OffsetDays != 7 || len(*sent) != 1 {
		t.Fatalf("7-day reminder for the rolled date: fired=%+v sent=%+v", fired, *sent)
	}
	if got := (*sent)[0]; got.title != "Lattice renewal auto-renews in 7d: legend-sg" ||
		got.body != "legend-sg (DMIT, SG) auto-renews 2026-10-20, USD 5.00. The renewal date rolls to the next cycle by itself." {
		t.Fatalf("auto-roll wording: %+v", got)
	}

	// A date several cycles stale lands on the first date not before today,
	// and a machine that cannot roll is still never reported overdue.
	stale := model.MachineProfile{AutoRoll: true, RenewalCycle: model.RenewalCycleMonthly, NextRenewal: day(2026, 6, 15), RemindersEnabled: true, RemindDaysBefore: []int{1}}
	if rolled, ok := rollAutoRenewal(stale, time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)); !ok || !rolled.Equal(day(2026, 10, 15)) {
		t.Fatalf("stale roll = %v %v, want 2026-10-15", rolled, ok)
	}
	stale.RenewalCycle = ""
	if _, ok := nextReminderFire(stale, time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)); ok {
		t.Fatal("an auto_roll machine past its date must never fire an overdue reminder")
	}
}

// A manual machine past its date is reminded once per UTC day for seven days
// and then stops, however often the scheduler runs.
func TestManualMachineOverdueRemindsDailyForSevenDays(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	mustUpsertNodes(t, st, "node-a")
	due := day(2026, 9, 20)
	mustUpsertProfiles(t, st, model.MachineProfile{
		ID: "mp-a", NodeID: "node-a", Label: "cd-xuezhang-jp-nat", NextRenewal: due,
		RemindDaysBefore: []int{1}, RemindersEnabled: true, LastRemindedKey: "2026-09-20:1",
		PriceCents: 500, Currency: "USD",
	})
	sent := captureRenewalNotifications(t, srv)
	overdue := []int{}
	for d := 1; d <= 10; d++ {
		for _, hour := range []time.Duration{0, 6, 12, 23} {
			fired, err := srv.evaluateMachineReminders(due.AddDate(0, 0, d).Add(hour*time.Hour), "", nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, fire := range fired {
				overdue = append(overdue, fire.OffsetDays)
			}
		}
	}
	if want := []int{-1, -2, -3, -4, -5, -6, -7}; !reflect.DeepEqual(overdue, want) {
		t.Fatalf("overdue fires = %v, want %v", overdue, want)
	}
	if len(*sent) != 7 || (*sent)[0].title != "Lattice renewal overdue 1d: cd-xuezhang-jp-nat" ||
		(*sent)[6].title != "Lattice renewal overdue 7d: cd-xuezhang-jp-nat" {
		t.Fatalf("overdue messages: %+v", *sent)
	}

	// A date long past, as the default-on migration can find, stays quiet.
	mustUpsertProfiles(t, st, model.MachineProfile{ID: "mp-a", NodeID: "node-a", NextRenewal: day(2026, 6, 1), RemindDaysBefore: []int{1}, RemindersEnabled: true})
	if fired, err := srv.evaluateMachineReminders(time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC), "", nil); err != nil || len(fired) != 0 {
		t.Fatalf("a date months past must not fire: fired=%+v err=%v", fired, err)
	}
}

// When the final warning was missed, the first overdue day still catches it
// up, and that is the only message that day.
func TestOverdueCatchUpIsTheDaysOneMessage(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	mustUpsertNodes(t, st, "node-a")
	mustUpsertProfiles(t, st, model.MachineProfile{
		ID: "mp-a", NodeID: "node-a", Label: "gmami-jp1", NextRenewal: day(2026, 9, 20),
		RemindDaysBefore: []int{7, 1}, RemindersEnabled: true, LastRemindedKey: "2026-09-20:7",
	})
	sent := captureRenewalNotifications(t, srv)
	morning := time.Date(2026, 9, 22, 8, 0, 0, 0, time.UTC)
	fired, err := srv.evaluateMachineReminders(morning, "", nil)
	// The missed 1-day warning is covered by the day's overdue message, and the
	// fire reports the cursor it stored.
	if err != nil || len(fired) != 1 || fired[0].OffsetDays != -2 {
		t.Fatalf("catch-up of the 1-day warning: fired=%+v err=%v", fired, err)
	}
	if stored, _ := st.MachineProfile("mp-a"); stored.LastRemindedKey != "2026-09-20:-2" {
		t.Fatalf("cursor %q disagrees with the fire", stored.LastRemindedKey)
	}
	if fired, _ := srv.evaluateMachineReminders(morning.Add(6*time.Hour), "", nil); len(fired) != 0 {
		t.Fatalf("second message on the same day: %+v", fired)
	}
	if fired, _ := srv.evaluateMachineReminders(morning.AddDate(0, 0, 1), "", nil); len(fired) != 1 || fired[0].OffsetDays != -3 {
		t.Fatalf("next day's overdue reminder: %+v", fired)
	}
	if len(*sent) != 2 || (*sent)[0].title != "Lattice renewal overdue 2d: gmami-jp1" {
		t.Fatalf("messages: %+v", *sent)
	}
}

// Marking an overdue machine renewed ends its overdue run.
func TestMachineRenewEndsOverdueReminders(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	mustUpsertNodes(t, st, "node-a")
	mustUpsertProfiles(t, st, model.MachineProfile{
		ID: "mp-a", NodeID: "node-a", NextRenewal: day(2026, 9, 20), RenewalCycle: model.RenewalCycleMonthly,
		RemindDaysBefore: []int{1}, RemindersEnabled: true, LastRemindedKey: "2026-09-20:1",
	})
	sent := captureRenewalNotifications(t, srv)
	if fired, _ := srv.evaluateMachineReminders(time.Date(2026, 9, 22, 8, 0, 0, 0, time.UTC), "", nil); len(fired) != 1 || fired[0].OffsetDays != -2 {
		t.Fatalf("overdue before renew: %+v", fired)
	}
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/machines/renew", `{"id":"mp-a","next_renewal":"2026-10-20T00:00:00Z"}`, cookies, csrf)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("renew: %d", res.StatusCode)
	}
	for d := 23; d <= 27; d++ {
		if fired, _ := srv.evaluateMachineReminders(time.Date(2026, 9, d, 8, 0, 0, 0, time.UTC), "", nil); len(fired) != 0 {
			t.Fatalf("renewed machine still reminded on 09-%d: %+v", d, fired)
		}
	}
	if len(*sent) != 1 {
		t.Fatalf("messages: %+v", *sent)
	}
}

// The evaluator decides the roll and the cursor against the profile as stored
// when it writes, not the list it read first. allow runs between the two, so
// an edit made there stands in for an operator saving the editor mid-run.
func TestReminderRunKeepsAnEditMadeAfterItReadTheList(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	mustUpsertNodes(t, st, "node-a", "node-b")
	mustUpsertProfiles(t, st,
		model.MachineProfile{ID: "mp-auto", NodeID: "node-a", Label: "legend-sg", AutoRoll: true, RenewalCycle: model.RenewalCycleMonthly, NextRenewal: day(2026, 9, 20), RemindDaysBefore: []int{7}, RemindersEnabled: true},
		model.MachineProfile{ID: "mp-manual", NodeID: "node-b", Label: "old label", NextRenewal: day(2026, 10, 6), RemindDaysBefore: []int{7}, RemindersEnabled: true},
	)
	captureRenewalNotifications(t, srv)
	edit := func(p model.MachineProfile) bool {
		current, _ := st.MachineProfile(p.ID)
		switch p.ID {
		case "mp-auto":
			// The operator moves the date forward by hand before the roll lands.
			current.NextRenewal = day(2026, 11, 5)
		case "mp-manual":
			current.Label = "new label"
		}
		mustUpsertProfiles(t, st, current)
		return true
	}
	fired, err := srv.evaluateMachineReminders(time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC), "", edit)
	if err != nil {
		t.Fatal(err)
	}
	auto, _ := st.MachineProfile("mp-auto")
	if !auto.NextRenewal.Equal(day(2026, 11, 5)) || len(auditEventsWithAction(st, "inventory.auto_roll")) != 0 {
		t.Fatalf("the roll overwrote the operator's date: %+v", auto)
	}
	manual, _ := st.MachineProfile("mp-manual")
	if manual.Label != "new label" || manual.LastRemindedKey != "2026-10-06:7" {
		t.Fatalf("the cursor write lost the operator's edit: %+v", manual)
	}
	if len(fired) != 1 || fired[0].MachineID != "mp-manual" {
		t.Fatalf("fired = %+v", fired)
	}
}

// One manual and one auto_roll machine walked from 8 days before their date to
// 15 days after, twice a day, with the server down on some days. Nothing
// repeats; a positive offset missed while down fires late; overdue days missed
// while down are not replayed; and the documented auto_roll case: a date that
// passes while the server is down rolls without its last reminders.
func TestReminderDayWalkWithServerDownGaps(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	mustUpsertNodes(t, st, "node-m", "node-a")
	renewal := day(2026, 10, 10)
	mustUpsertProfiles(t, st,
		model.MachineProfile{ID: "manual", NodeID: "node-m", Label: "manual", NextRenewal: renewal, RemindDaysBefore: []int{14, 7, 3, 1, 0}, RemindersEnabled: true},
		model.MachineProfile{ID: "auto", NodeID: "node-a", Label: "auto", NextRenewal: renewal, AutoRoll: true, RenewalCycle: model.RenewalCycleCustomDays, CycleDays: 10, RemindDaysBefore: []int{7, 1, 0}, RemindersEnabled: true},
	)
	captureRenewalNotifications(t, srv)
	down := map[int]bool{-5: true, -4: true, -3: true, -1: true, 0: true, 1: true, 3: true, 4: true}
	type fireAt struct {
		day, offset int
		renewal     string
	}
	got := map[string][]fireAt{}
	for k := -8; k <= 15; k++ {
		if down[k] {
			continue
		}
		for _, at := range []time.Duration{30 * time.Minute, 18 * time.Hour} {
			fired, err := srv.evaluateMachineReminders(renewal.AddDate(0, 0, k).Add(at), "", nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range fired {
				got[f.MachineID] = append(got[f.MachineID], fireAt{k, f.OffsetDays, f.NextRenewal})
			}
		}
	}
	want := map[string][]fireAt{
		"manual": {
			{-8, 14, "2026-10-10"}, // the walk starts inside the 14-day window
			{-7, 7, "2026-10-10"},
			{-2, 3, "2026-10-10"}, // down on -3: the 3-day warning fires late
			{2, -2, "2026-10-10"}, // down -1..1: the first overdue day covers the missed warnings
			{5, -5, "2026-10-10"}, // down 3 and 4: those overdue days are not replayed
			{6, -6, "2026-10-10"},
			{7, -7, "2026-10-10"}, // then silence
		},
		"auto": {
			{-7, 7, "2026-10-10"},
			{5, 7, "2026-10-20"}, // rolled on day 2 without the old date's 1 and 0 reminders
			{9, 1, "2026-10-20"},
			{10, 0, "2026-10-20"},
			{13, 7, "2026-10-30"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("walk:\n got %+v\nwant %+v", got, want)
	}
}

// A write that commits and then fails to sync its directory still holds the
// new cursor, so the reminder it recorded is sent, not lost. A directory the
// process may write and enter but not read lets the rename land and fails
// the fsync that follows it, which is exactly that case.
func TestReminderSentWhenItsWriteCommitsWithoutDurability(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	mustUpsertNodes(t, st, "node-a")
	mustUpsertProfiles(t, st, model.MachineProfile{ID: "mp-a", NodeID: "node-a", Label: "gmami-jp1", NextRenewal: day(2026, 10, 6), RemindDaysBefore: []int{7}, RemindersEnabled: true})
	sent := captureRenewalNotifications(t, srv)

	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if f, err := os.Open(dir); err == nil {
		f.Close()
		t.Skip("this platform lets the directory be read without the read bit")
	}
	fired, err := srv.evaluateMachineReminders(time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC), "", nil)
	if err != nil {
		t.Fatalf("a committed write must not fail the run: %v", err)
	}
	if len(fired) != 1 || len(*sent) != 1 || (*sent)[0].title != "Lattice renewal due in 7d: gmami-jp1" {
		t.Fatalf("the recorded reminder was not sent: fired=%+v sent=%+v", fired, *sent)
	}
	if stored, _ := st.MachineProfile("mp-a"); stored.LastRemindedKey != "2026-10-06:7" {
		t.Fatalf("cursor = %q", stored.LastRemindedKey)
	}
}
