package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/notify"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// incidentHarness is a server on the production layout (state.json plus
// state-hot.db) with a hand-moved clock, nodes in the store, and the typed
// notices the incident sweep sends recorded instead of routed.
type incidentHarness struct {
	t     *testing.T
	f     ingestFixture
	clock *testClock
	sent  *[]typedNotice
}

var incidentBase = time.Date(2026, 10, 3, 3, 0, 0, 0, time.UTC)

func newIncidentHarness(t *testing.T, nodeIDs ...string) *incidentHarness {
	t.Helper()
	f := openNotifyFixture(t, t.TempDir())
	h := &incidentHarness{t: t, f: f, clock: &testClock{at: incidentBase}}
	f.srv.now = h.clock.now
	h.sent = captureTypedNotices(f.srv)
	for _, nodeID := range nodeIDs {
		if err := f.st.UpsertNode(model.Node{ID: nodeID, Name: "name-" + nodeID}); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func (h *incidentHarness) now() time.Time { return h.clock.now() }

// sweep runs the incident pass at the harness clock and returns what it sent.
func (h *incidentHarness) sweep() []typedNotice {
	h.f.srv.evaluateIncidents(h.now())
	out := *h.sent
	*h.sent = nil
	return out
}

func (h *incidentHarness) openService(nodeID string) {
	h.f.srv.openIncident(incidentSignal{
		kind: EventServiceDown, nodeID: nodeID, subject: "name-" + nodeID, since: h.now(),
		sortKey: "name-" + nodeID,
		msg: incidentMessage{
			title: "sing-box down on name-" + nodeID, detail: "name-" + nodeID + ": down", line: "name-" + nodeID + ": down",
		},
	}, h.now())
}

func (h *incidentHarness) resolveService(nodeID string) {
	h.f.srv.resolveIncident(incidentKey(EventServiceDown, nodeID, ""), h.now(), incidentMessage{
		title: "sing-box recovered on name-" + nodeID, detail: "name-" + nodeID + ": up", line: "name-" + nodeID + ": up",
	})
}

func (h *incidentHarness) incident(kind, nodeID string) store.Incident {
	h.t.Helper()
	inc, ok := h.f.st.LatestIncident(incidentKey(kind, nodeID, ""))
	if !ok {
		h.t.Fatalf("no %s incident for %s", kind, nodeID)
	}
	return inc
}

func noticeTypes(got []typedNotice) []string {
	out := make([]string, len(got))
	for i, n := range got {
		out[i] = n.eventType + ": " + n.title
	}
	return out
}

func expectNotices(t *testing.T, when string, got []typedNotice, want ...string) {
	t.Helper()
	have := noticeTypes(got)
	if strings.Join(have, "|") != strings.Join(want, "|") {
		t.Fatalf("%s: sent %q, want %q", when, have, want)
	}
}

// An open sends one message, reporting the same problem again sends nothing,
// and the recovery follows because the open was sent.
func TestIncidentOpensOnceAndItsRecoveryFollows(t *testing.T) {
	h := newIncidentHarness(t, "a")
	h.openService("a")
	if inc := h.incident(EventServiceDown, "a"); inc.State != store.IncidentStateOpen || !inc.OwedOpen || inc.Severity != incidentSeverityCritical {
		t.Fatalf("opened incident = %+v", inc)
	}
	expectNotices(t, "first sweep", h.sweep(), "service.down: sing-box down on name-a")
	h.clock.advance(time.Minute)
	h.openService("a")
	expectNotices(t, "the same problem again", h.sweep())

	h.clock.advance(time.Minute)
	h.resolveService("a")
	expectNotices(t, "resolved", h.sweep(), "service.recovered: sing-box recovered on name-a")
	inc := h.incident(EventServiceDown, "a")
	if inc.State != store.IncidentStateResolved || inc.Notified != store.IncidentNotifiedResolved || inc.OwedRecovery {
		t.Fatalf("resolved incident = %+v", inc)
	}
	expectNotices(t, "after the recovery", h.sweep())
}

// Incidents of one kind that fall due together go out as one digest, in name
// order; a recovery that was never owed (its open was never sent) is silent.
func TestIncidentsDueTogetherShareOneDigest(t *testing.T) {
	h := newIncidentHarness(t, "c", "a", "b")
	for _, id := range []string{"c", "a", "b"} {
		h.openService(id)
	}
	got := h.sweep()
	if len(got) != 1 || got[0].title != "sing-box down digest: 3 nodes" || got[0].body != "name-a: down\nname-b: down\nname-c: down" {
		t.Fatalf("digest = %+v", got)
	}
	// Opened and resolved between two sweeps: nothing in either direction.
	h.f.st.UpsertNode(model.Node{ID: "d", Name: "name-d"})
	h.openService("d")
	h.resolveService("d")
	expectNotices(t, "a blip between sweeps", h.sweep())
}

// A maintenance window holds the open message, records it as suppressed with
// the reason once, and the message goes out when the window ends with the
// incident still open. One that resolves inside the window says nothing.
func TestMaintenanceWindowHoldsTheOpenUntilItEnds(t *testing.T) {
	h := newIncidentHarness(t, "a", "b")
	if err := h.f.st.PutMaintenanceWindow(store.MaintenanceWindow{
		ID: "mw-1", Name: "kernel upgrade", NodeIDs: []string{"a", "b"},
		StartsAt: h.now(), EndsAt: h.now().Add(time.Hour), CreatedAt: h.now(),
	}, h.now()); err != nil {
		t.Fatal(err)
	}
	h.clock.advance(time.Minute)
	h.openService("a")
	h.openService("b")
	expectNotices(t, "inside the window", h.sweep())
	held := deliveriesOf(h.f.st, store.NotifyDeliveryFilter{Outcome: store.NotifyOutcomeSuppressed})
	if len(held) != 2 || !strings.Contains(held[0].Reason, `maintenance window "kernel upgrade"`) {
		t.Fatalf("suppressed rows = %+v", held)
	}
	h.clock.advance(10 * time.Minute)
	h.resolveService("b")
	expectNotices(t, "later inside the window", h.sweep())
	if n := len(deliveriesOf(h.f.st, store.NotifyDeliveryFilter{Outcome: store.NotifyOutcomeSuppressed})); n != 2 {
		t.Fatalf("the hold was recorded again: %d rows", n)
	}

	h.clock.advance(50 * time.Minute)
	expectNotices(t, "the window ended", h.sweep(), "service.down: sing-box down on name-a")
	h.clock.advance(time.Minute)
	expectNotices(t, "after the window", h.sweep())
}

// A window over a group covers the group's resolved members, and a recovery
// owed from a page sent before the window is never held by it.
func TestGroupWindowCoversMembersAndNeverHoldsARecovery(t *testing.T) {
	h := newIncidentHarness(t, "a", "b")
	if err := h.f.st.UpsertGroup(model.Group{ID: "grp-edge", Name: "edge", Slug: "edge", Color: "sky", Members: []string{"a"}}); err != nil {
		t.Fatal(err)
	}
	h.openService("b")
	expectNotices(t, "b paged before any window", h.sweep(), "service.down: sing-box down on name-b")
	if err := h.f.st.PutMaintenanceWindow(store.MaintenanceWindow{
		ID: "mw-g", Name: "edge work", GroupIDs: []string{"grp-edge"}, NodeIDs: []string{"b"},
		StartsAt: h.now(), EndsAt: h.now().Add(time.Hour), CreatedAt: h.now(),
	}, h.now()); err != nil {
		t.Fatal(err)
	}
	h.openService("a")
	expectNotices(t, "a member of the covered group", h.sweep())
	h.resolveService("b")
	expectNotices(t, "b recovers inside the window", h.sweep(), "service.recovered: sing-box recovered on name-b")
}

// A snooze holds the open message, and when it runs out with the incident
// still open and unacknowledged one reminder goes out; an acknowledged one
// stays quiet.
func TestSnoozeExpirySendsOneReminder(t *testing.T) {
	h := newIncidentHarness(t, "a", "b")
	cookies, csrf := loginSession(t, h.f.handler)
	h.openService("a")
	h.openService("b")
	h.sweep()
	for _, id := range []string{"a", "b"} {
		inc := h.incident(EventServiceDown, id)
		res := doJSON(t, h.f.handler, http.MethodPost, "/api/incidents/snooze", fmt.Sprintf(`{"id":%q,"minutes":20}`, inc.ID), cookies, csrf)
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("snooze %s: %d", id, res.StatusCode)
		}
	}
	res := doJSON(t, h.f.handler, http.MethodPost, "/api/incidents/ack", fmt.Sprintf(`{"id":%q}`, h.incident(EventServiceDown, "b").ID), cookies, csrf)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("ack: %d", res.StatusCode)
	}
	h.clock.advance(19 * time.Minute)
	expectNotices(t, "inside the snooze", h.sweep())
	h.clock.advance(2 * time.Minute)
	expectNotices(t, "the snooze ran out", h.sweep(), "service.down: sing-box down on name-a")
	h.clock.advance(time.Minute)
	expectNotices(t, "after the reminder", h.sweep())
	if inc := h.incident(EventServiceDown, "a"); !inc.SnoozedUntil.IsZero() {
		t.Fatalf("snooze not cleared: %+v", inc)
	}
}

// From the third reopening within 30 minutes an incident is flapping: at
// most one message an hour, always the current state, and it settles after an
// hour resolved.
func TestFlappingIncidentSendsAtMostOneMessageAnHour(t *testing.T) {
	h := newIncidentHarness(t, "a")
	step := func(open bool) []typedNotice {
		h.clock.advance(time.Minute)
		if open {
			h.openService("a")
		} else {
			h.resolveService("a")
		}
		return h.sweep()
	}
	expectNotices(t, "open", step(true), "service.down: sing-box down on name-a")
	expectNotices(t, "resolve", step(false), "service.recovered: sing-box recovered on name-a")
	expectNotices(t, "flap 1", step(true), "service.down: sing-box down on name-a")
	expectNotices(t, "resolve", step(false), "service.recovered: sing-box recovered on name-a")
	expectNotices(t, "flap 2", step(true), "service.down: sing-box down on name-a")
	expectNotices(t, "resolve", step(false), "service.recovered: sing-box recovered on name-a")
	expectNotices(t, "flap 3 is damped", step(true))
	if inc := h.incident(EventServiceDown, "a"); !inc.Flapping || inc.Flaps != 3 {
		t.Fatalf("flap count = %+v", inc)
	}
	expectNotices(t, "resolve while the phone says up", step(false))
	expectNotices(t, "flap 4 is damped", step(true))
	if !strings.Contains(deliveriesOf(h.f.st, store.NotifyDeliveryFilter{Outcome: store.NotifyOutcomeSuppressed})[0].Reason, "flapping") {
		t.Fatal("the damped message was not recorded as suppressed")
	}

	// An hour after the last message, the current state (down) goes out once.
	h.clock.advance(57 * time.Minute)
	got := h.sweep()
	if len(got) != 1 || got[0].eventType != EventServiceDown || !strings.Contains(got[0].title, "flapping, 4 reopenings") {
		t.Fatalf("hourly flapping message = %+v", got)
	}
	expectNotices(t, "resolve right after", step(false))
	h.clock.advance(time.Hour)
	got = h.sweep()
	if len(got) != 1 || got[0].eventType != EventServiceRecovered {
		t.Fatalf("the recovery an hour later = %+v", got)
	}
	if inc := h.incident(EventServiceDown, "a"); inc.Flapping {
		t.Fatalf("still flapping after an hour resolved: %+v", inc)
	}
}

// escalationSends records sends with the Bark level the channel was given.
type escalationSends struct {
	mu   sync.Mutex
	rows []string
}

func (e *escalationSends) install(srv *Server) {
	srv.notifySend = func(_ context.Context, c model.NotifyChannel, msg notify.Message) error {
		e.mu.Lock()
		e.rows = append(e.rows, c.ID+" level="+c.Config["level"]+" "+msg.Title)
		e.mu.Unlock()
		return nil
	}
}

func (e *escalationSends) take() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.rows
	e.rows = nil
	return out
}

// An open critical incident nobody acknowledged is re-sent once per rule
// after the rule's delay at the rule's Bark level; an acknowledged one, a
// warning, and a rule with escalation off are never escalated.
func TestUnacknowledgedCriticalIncidentEscalatesOncePerRule(t *testing.T) {
	h := newIncidentHarness(t, "a", "b", "c")
	sends := &escalationSends{}
	sends.install(h.f.srv)
	addNotifyChannel(t, h.f.st, "nc-urgent", "Bark urgent")
	addNotifyChannel(t, h.f.st, "nc-ops", "Bark ops")
	addNotifyChannel(t, h.f.st, "nc-quiet", "Bark quiet")
	rule := func(id, channel string, opts store.NotifyRuleOptions) {
		if err := h.f.st.UpsertNotifyRuleWithOptions(model.NotifyRule{ID: id, Name: id, EventTypes: []string{EventServiceDown, EventNodeOffline}, ChannelIDs: []string{channel}, Enabled: true}, opts); err != nil {
			t.Fatal(err)
		}
	}
	rule("nr-default", "nc-urgent", store.NotifyRuleOptions{})
	rule("nr-fast", "nc-ops", store.NotifyRuleOptions{EscalateAfterMinutes: 10, EscalationBarkLevel: "timeSensitive"})
	rule("nr-off", "nc-quiet", store.NotifyRuleOptions{EscalationOff: true})

	h.openService("a")
	h.openService("b")
	h.f.srv.openIncident(incidentSignal{kind: EventNodeOffline, nodeID: "c", subject: "name-c", since: h.now(),
		msg: incidentMessage{title: "Lattice node offline: name-c", detail: "d", line: "l"}}, h.now())
	h.sweep()
	cookies, csrf := loginSession(t, h.f.handler)
	res := doJSON(t, h.f.handler, http.MethodPost, "/api/incidents/ack", fmt.Sprintf(`{"id":%q}`, h.incident(EventServiceDown, "b").ID), cookies, csrf)
	res.Body.Close()

	h.clock.advance(9 * time.Minute)
	h.sweep()
	waitOutboxSettled(t, h.f.srv)
	if got := sends.take(); len(got) != 0 {
		t.Fatalf("escalated before any delay: %v", got)
	}
	h.clock.advance(time.Minute)
	h.sweep()
	waitOutboxSettled(t, h.f.srv)
	if got := sends.take(); len(got) != 1 || got[0] != "nc-ops level=timeSensitive Not acknowledged after 10 min: sing-box down on name-a" {
		t.Fatalf("the 10 minute rule = %v", got)
	}
	h.clock.advance(20 * time.Minute)
	h.sweep()
	waitOutboxSettled(t, h.f.srv)
	if got := sends.take(); len(got) != 1 || got[0] != "nc-urgent level=critical Not acknowledged after 30 min: sing-box down on name-a" {
		t.Fatalf("the default rule = %v", got)
	}
	rows := deliveriesOf(h.f.st, store.NotifyDeliveryFilter{ChannelID: "nc-urgent", EventType: EventServiceDown})
	if len(rows) != 1 || rows[0].BarkLevel != "critical" {
		t.Fatalf("escalation receipt = %+v", rows)
	}
	h.clock.advance(3 * time.Hour)
	h.sweep()
	waitOutboxSettled(t, h.f.srv)
	if got := sends.take(); len(got) != 0 {
		t.Fatalf("escalated twice: %v", got)
	}
	if inc := h.incident(EventServiceDown, "a"); len(inc.Escalated) != 2 {
		t.Fatalf("escalations recorded = %+v", inc.Escalated)
	}
}

// Quiet hours hold a rule's non-critical deliveries until the window ends
// (also across a restart), and a critical event breaks through. The window is
// set around the wall clock, because the restarted process reads it.
func TestQuietHoursHoldNonCriticalDeliveries(t *testing.T) {
	dir := t.TempDir()
	f := openNotifyFixture(t, dir)
	now := time.Now().UTC().Truncate(time.Minute)
	clock := &testClock{at: now}
	f.srv.now = clock.now
	installFakeNotifySender(f.srv, nil)
	addNotifyChannel(t, f.st, "nc-a", "Bark")
	quiet := &store.NotifyQuietHours{Start: now.Add(-time.Hour).Format("15:04"), End: now.Add(2 * time.Hour).Format("15:04"), TimeZone: "UTC"}
	if err := f.st.UpsertNotifyRuleWithOptions(model.NotifyRule{ID: "nr-1", Name: "all", ChannelIDs: []string{"nc-a"}, Enabled: true},
		store.NotifyRuleOptions{QuietHours: quiet}); err != nil {
		t.Fatal(err)
	}
	f.srv.notifyEventTyped(EventNodeOffline, "Lattice node offline: alpha", "b")
	f.srv.notifyEventTyped(EventServiceDown, "sing-box down on alpha", "b")
	held := deliveriesOf(f.st, store.NotifyDeliveryFilter{EventType: EventNodeOffline})
	want := now.Add(2 * time.Hour)
	if len(held) != 1 || !held[0].HeldUntil.Equal(want) || !held[0].NextAttemptAt.Equal(want) || held[0].Settled() {
		t.Fatalf("held row = %+v (want held until %s)", held, want)
	}
	critical := deliveriesOf(f.st, store.NotifyDeliveryFilter{EventType: EventServiceDown})
	if len(critical) != 1 || !critical[0].HeldUntil.IsZero() {
		t.Fatalf("critical row = %+v", critical)
	}

	// A restart inside the window leaves the held row waiting, not failed.
	f.srv.stopNotifyOutbox()
	if _, err := New(Options{Store: f.st, AdminPassword: testAdminPass, DisableRenewalScheduler: true}); err != nil {
		t.Fatal(err)
	}
	row, _ := f.st.NotifyDelivery(held[0].ID)
	if row.Settled() || row.Redriven {
		t.Fatalf("the held row after a restart = %+v", row)
	}
}

func TestQuietHoursWindowArithmetic(t *testing.T) {
	shanghai := &store.NotifyQuietHours{Start: "22:00", End: "07:00", TimeZone: "Asia/Shanghai"}
	day := &store.NotifyQuietHours{Start: "09:00", End: "17:30", TimeZone: "UTC"}
	cases := []struct {
		name string
		qh   *store.NotifyQuietHours
		at   string
		end  string
	}{
		{"before midnight in Shanghai", shanghai, "2026-10-03T15:00:00Z", "2026-10-03T23:00:00Z"},
		{"after midnight in Shanghai", shanghai, "2026-10-03T20:00:00Z", "2026-10-03T23:00:00Z"},
		{"daytime in Shanghai", shanghai, "2026-10-03T03:00:00Z", ""},
		{"inside a same-day window", day, "2026-10-03T12:00:00Z", "2026-10-03T17:30:00Z"},
		{"at the end of a same-day window", day, "2026-10-03T17:30:00Z", ""},
		{"no quiet hours", nil, "2026-10-03T12:00:00Z", ""},
	}
	for _, tc := range cases {
		at, _ := time.Parse(time.RFC3339, tc.at)
		end, ok := quietHoursEnd(tc.qh, at)
		if tc.end == "" {
			if ok {
				t.Errorf("%s: held until %s, want not held", tc.name, end)
			}
			continue
		}
		want, _ := time.Parse(time.RFC3339, tc.end)
		if !ok || !end.Equal(want) {
			t.Errorf("%s: end %s %v, want %s", tc.name, end, ok, want)
		}
	}
}

// Open incidents keep their state across a restart on the production layout:
// an acknowledged incident stays acknowledged, a snoozed one stays snoozed,
// and the recovery the first process owed is sent by the second.
func TestOpenIncidentsKeepTheirStateAcrossARestart(t *testing.T) {
	dir := t.TempDir()
	f1 := openIngestFixture(t, dir)
	clock := &testClock{at: incidentBase}
	f1.srv.now = clock.now
	sent1 := captureTypedNotices(f1.srv)
	for _, id := range []string{"a", "b"} {
		if err := f1.st.UpsertNode(model.Node{ID: id, Name: "name-" + id}); err != nil {
			t.Fatal(err)
		}
		f1.srv.openIncident(incidentSignal{kind: EventServiceDown, nodeID: id, subject: "name-" + id, since: clock.now(),
			msg: incidentMessage{title: "sing-box down on name-" + id, detail: "d", line: "l"}}, clock.now())
	}
	f1.srv.evaluateIncidents(clock.now())
	if len(*sent1) != 1 {
		t.Fatalf("before the restart: %+v", *sent1)
	}
	cookies, csrf := loginSession(t, f1.handler)
	incA, _ := f1.st.ActiveIncident(incidentKey(EventServiceDown, "a", ""))
	incB, _ := f1.st.ActiveIncident(incidentKey(EventServiceDown, "b", ""))
	res := doJSON(t, f1.handler, http.MethodPost, "/api/incidents/ack", fmt.Sprintf(`{"id":%q}`, incA.ID), cookies, csrf)
	res.Body.Close()
	res = doJSON(t, f1.handler, http.MethodPost, "/api/incidents/snooze", fmt.Sprintf(`{"id":%q,"minutes":120}`, incB.ID), cookies, csrf)
	res.Body.Close()
	if err := f1.st.Close(); err != nil {
		t.Fatal(err)
	}

	f2 := openIngestFixture(t, dir)
	t.Cleanup(func() { _ = f2.st.Close() })
	f2.srv.now = clock.now
	sent2 := captureTypedNotices(f2.srv)
	cookies, csrf = loginSession(t, f2.handler)
	res = doJSON(t, f2.handler, http.MethodGet, "/api/incidents?state=open,acknowledged", "", cookies, csrf)
	var list incidentListResponse
	if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	states := map[string]string{}
	for _, v := range list.Incidents {
		states[v.NodeID] = v.State
		if v.NodeID == "b" && !v.Snoozed {
			t.Fatalf("b lost its snooze: %+v", v)
		}
	}
	if !list.Durable || states["a"] != store.IncidentStateAcknowledged || states["b"] != store.IncidentStateOpen {
		t.Fatalf("after the restart: durable=%v states=%v", list.Durable, states)
	}
	clock.advance(time.Minute)
	f2.srv.resolveIncident(incidentKey(EventServiceDown, "a", ""), clock.now(), incidentMessage{title: "sing-box recovered on name-a", detail: "d", line: "l"})
	f2.srv.evaluateIncidents(clock.now())
	if len(*sent2) != 1 || (*sent2)[0].eventType != EventServiceRecovered {
		t.Fatalf("the owed recovery after the restart: %+v", *sent2)
	}
}

// A node-confined token sees, acknowledges and covers with a window only its
// own nodes; a fleet-wide incident (no node) and a group window are refused.
func TestNodeConfinedTokenActsOnlyOnItsNodes(t *testing.T) {
	h := newIncidentHarness(t, "node-a", "node-b")
	cookies, csrf := loginSession(t, h.f.handler)
	h.openService("node-a")
	h.openService("node-b")
	if err := h.f.st.UpsertMonitor(model.Monitor{ID: "mon-tls", Name: "cert", Type: model.MonitorTypeTLS, Target: "example.com:443", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	h.f.srv.openIncident(incidentSignal{kind: EventMonitorDown, monitorID: "mon-tls", subject: "cert on example.com:443", since: h.now(),
		msg: incidentMessage{title: "Monitor down: cert", detail: "d", line: "l"}}, h.now())
	if err := h.f.st.UpsertGroup(model.Group{ID: "grp-1", Name: "g", Slug: "g", Color: "sky", Members: []string{"node-a"}}); err != nil {
		t.Fatal(err)
	}
	token := createPAT(t, h.f.handler, cookies, csrf, []string{"monitor:read", "monitor:admin"}, []string{"node-a"})
	readOnly := createPAT(t, h.f.handler, cookies, csrf, []string{"monitor:read"}, []string{"node-a"})

	res := doBearerJSON(t, h.f.handler, http.MethodGet, "/api/incidents", "", token)
	var list incidentListResponse
	if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if len(list.Incidents) != 1 || list.Incidents[0].NodeID != "node-a" {
		t.Fatalf("confined list = %+v", list.Incidents)
	}
	status := func(path, body, tok string) int {
		res := doBearerJSON(t, h.f.handler, http.MethodPost, path, body, tok)
		res.Body.Close()
		return res.StatusCode
	}
	ackBody := func(nodeID string) string {
		inc, _ := h.f.st.ActiveIncident(incidentKey(EventServiceDown, nodeID, ""))
		return fmt.Sprintf(`{"id":%q}`, inc.ID)
	}
	tlsInc, _ := h.f.st.ActiveIncident(incidentKey(EventMonitorDown, "", "mon-tls"))
	window := func(nodes, groups string) string {
		return fmt.Sprintf(`{"name":"w","node_ids":%s,"group_ids":%s,"ends_at":%q}`, nodes, groups, h.now().Add(time.Hour).Format(time.RFC3339))
	}
	cases := []struct {
		name, path, body, token string
		want                    int
	}{
		{"ack another node's incident", "/api/incidents/ack", ackBody("node-b"), token, http.StatusNotFound},
		{"ack a fleet-wide incident", "/api/incidents/ack", fmt.Sprintf(`{"id":%q}`, tlsInc.ID), token, http.StatusNotFound},
		{"ack without monitor:admin", "/api/incidents/ack", ackBody("node-a"), readOnly, http.StatusForbidden},
		{"window over another node", "/api/maintenance-windows", window(`["node-b"]`, `[]`), token, http.StatusForbidden},
		{"window over a group", "/api/maintenance-windows", window(`[]`, `["grp-1"]`), token, http.StatusForbidden},
		{"ack its own node's incident", "/api/incidents/ack", ackBody("node-a"), token, http.StatusOK},
		{"window over its own node", "/api/maintenance-windows", window(`["node-a"]`, `[]`), token, http.StatusOK},
	}
	for _, tc := range cases {
		if got := status(tc.path, tc.body, tc.token); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
	if inc, _ := h.f.st.ActiveIncident(incidentKey(EventServiceDown, "node-b", "")); inc.State != store.IncidentStateOpen {
		t.Fatalf("another node's incident changed: %+v", inc)
	}
	// The session (unrestricted) sees the fleet-wide incident and the window.
	res = doJSON(t, h.f.handler, http.MethodGet, "/api/incidents", "", cookies, csrf)
	list = incidentListResponse{}
	if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if len(list.Incidents) != 3 || len(list.Windows) != 1 {
		t.Fatalf("operator list: %d incidents, %d windows", len(list.Incidents), len(list.Windows))
	}

	// A window the operator set over both nodes is shown to the confined
	// token with only the node it can read, and it cannot change it.
	res = doJSON(t, h.f.handler, http.MethodPost, "/api/maintenance-windows", window(`["node-a","node-b"]`, `[]`), cookies, csrf)
	var shared store.MaintenanceWindow
	if err := json.NewDecoder(res.Body).Decode(&shared); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	for _, path := range []string{"/api/maintenance-windows", "/api/incidents"} {
		res = doBearerJSON(t, h.f.handler, http.MethodGet, path, "", token)
		var got struct {
			Windows []store.MaintenanceWindow `json:"windows"`
		}
		if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		found := false
		for _, mw := range got.Windows {
			if mw.ID != shared.ID {
				continue
			}
			found = true
			if strings.Join(mw.NodeIDs, ",") != "node-a" {
				t.Errorf("%s: the shared window's nodes = %v, want only node-a", path, mw.NodeIDs)
			}
		}
		if !found {
			t.Errorf("%s: the shared window is not shown to the confined token", path)
		}
	}
	edit := fmt.Sprintf(`{"id":%q,"name":"w","node_ids":["node-a"],"group_ids":[],"ends_at":%q}`, shared.ID, h.now().Add(time.Hour).Format(time.RFC3339))
	if got := status("/api/maintenance-windows", edit, token); got != http.StatusForbidden {
		t.Errorf("the confined token narrowed the shared window: %d", got)
	}
	if mw, _ := h.f.st.MaintenanceWindow(shared.ID); strings.Join(mw.NodeIDs, ",") != "node-a,node-b" {
		t.Errorf("the shared window changed: %v", mw.NodeIDs)
	}
}

// Window edits are validated and audited, and ending one early lets a held
// open message go out at the next sweep.
func TestMaintenanceWindowRoutes(t *testing.T) {
	h := newIncidentHarness(t, "a")
	cookies, csrf := loginSession(t, h.f.handler)
	post := func(body string) (*http.Response, store.MaintenanceWindow) {
		res := doJSON(t, h.f.handler, http.MethodPost, "/api/maintenance-windows", body, cookies, csrf)
		var mw store.MaintenanceWindow
		if res.StatusCode == http.StatusOK {
			_ = json.NewDecoder(res.Body).Decode(&mw)
		}
		res.Body.Close()
		return res, mw
	}
	end := h.now().Add(time.Hour).Format(time.RFC3339)
	for name, body := range map[string]string{
		"no name":         fmt.Sprintf(`{"node_ids":["a"],"ends_at":%q}`, end),
		"no target":       fmt.Sprintf(`{"name":"w","ends_at":%q}`, end),
		"unknown node":    fmt.Sprintf(`{"name":"w","node_ids":["zz"],"ends_at":%q}`, end),
		"already ended":   fmt.Sprintf(`{"name":"w","node_ids":["a"],"ends_at":%q}`, h.now().Add(-time.Minute).Format(time.RFC3339)),
		"longer than 30d": fmt.Sprintf(`{"name":"w","node_ids":["a"],"ends_at":%q}`, h.now().Add(31*24*time.Hour).Format(time.RFC3339)),
	} {
		if res, _ := post(body); res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, res.StatusCode)
		}
	}
	res, mw := post(fmt.Sprintf(`{"name":"reboot","reason":"kernel","node_ids":["a"],"ends_at":%q}`, end))
	if res.StatusCode != http.StatusOK || mw.ID == "" || !mw.StartsAt.Equal(h.now()) || mw.CreatedBy == "" {
		t.Fatalf("create: %d %+v", res.StatusCode, mw)
	}
	h.openService("a")
	expectNotices(t, "held", h.sweep())
	h.clock.advance(5 * time.Minute)
	res, _ = post(fmt.Sprintf(`{"id":%q,"name":"reboot","node_ids":["a"],"ends_at":%q}`, mw.ID, h.now().Format(time.RFC3339)))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("end early: %d", res.StatusCode)
	}
	expectNotices(t, "ended early", h.sweep(), "service.down: sing-box down on name-a")
	audits := h.f.st.AuditEvents()
	found := 0
	for _, ev := range audits {
		if ev.Action == "maintenance.upsert" {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("maintenance.upsert audited %d times, want 2", found)
	}
	res = doJSON(t, h.f.handler, http.MethodPost, "/api/maintenance-windows/delete", fmt.Sprintf(`{"id":%q}`, mw.ID), cookies, csrf)
	res.Body.Close()
	if _, ok := h.f.st.MaintenanceWindow(mw.ID); res.StatusCode != http.StatusOK || ok {
		t.Fatalf("delete: %d, still there %v", res.StatusCode, ok)
	}
}

// A pending incident is listed from the emitters' own evidence before its
// hold elapses, with the instant it opens.
func TestPendingIncidentsAreListed(t *testing.T) {
	h := newIncidentHarness(t)
	silent := h.now().Add(-3 * time.Minute)
	if err := h.f.st.UpsertNode(model.Node{ID: "n-quiet", Name: "quiet", LastSeen: silent}); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, h.f.handler)
	res := doJSON(t, h.f.handler, http.MethodGet, "/api/incidents?state=pending", "", cookies, csrf)
	var list incidentListResponse
	if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if len(list.Incidents) != 1 {
		t.Fatalf("pending = %+v", list.Incidents)
	}
	p := list.Incidents[0]
	if p.State != incidentStatePending || p.Kind != EventNodeOffline || !p.OpensAt.Equal(silent.Add(nodeOfflineAlertAfter)) || !strings.HasPrefix(p.ID, "pending:") {
		t.Fatalf("pending incident = %+v", p)
	}
}

// A loop that proves a paging problem opens agent.stalled on the sweep,
// and a moving loop resolves it with agent.recovered.
func TestAgentLoopHealthOpensAndResolvesAgentStalled(t *testing.T) {
	h := newIncidentHarness(t)
	clock := &testClock{at: time.Now().UTC()}
	h.f.srv.now = clock.now
	cookies, csrf := loginSession(t, h.f.handler)
	token := enrollNamedNodeToken(t, h.f.handler, cookies, csrf, "n-loop", "loop")
	agentNow := clock.now().Add(-time.Hour)
	metricsBeat(t, h.f.handler, "n-loop", token, agentNow, stalledLoopHealth(agentNow))
	h.f.srv.evaluateAgentHealthIncidents(clock.now())
	h.f.srv.evaluateIncidents(clock.now())
	got := *h.sent
	*h.sent = nil
	if len(got) != 1 || got[0].eventType != EventAgentStalled || got[0].title != "Lattice agent stalled on loop" || !strings.Contains(got[0].body, "in step inventory") {
		t.Fatalf("agent incident = %+v", got)
	}
	h.f.srv.evaluateAgentHealthIncidents(clock.now().Add(20 * time.Second))
	h.f.srv.evaluateIncidents(clock.now().Add(20 * time.Second))
	if len(*h.sent) != 0 {
		t.Fatalf("the same stall paged again: %+v", *h.sent)
	}

	moving := fmt.Sprintf(`{"started_at":%q,"cycle_completed_at":%q}`, agentNow.Add(-time.Hour).Format(time.RFC3339), agentNow.Add(10*time.Second).Format(time.RFC3339))
	metricsBeat(t, h.f.handler, "n-loop", token, agentNow.Add(12*time.Second), moving)
	clock.advance(15 * time.Second)
	h.f.srv.evaluateAgentHealthIncidents(clock.now())
	h.f.srv.evaluateIncidents(clock.now())
	if got := *h.sent; len(got) != 1 || got[0].eventType != EventAgentRecovered {
		t.Fatalf("agent recovery = %+v", got)
	}
}

// A page sent before incident records existed (the old offline alert map)
// becomes an incident at boot, is never escalated, and still gets its
// node.online.
func TestLegacyOfflinePageIsAdoptedAndAnswered(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	lastSeen := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	if err := st.UpsertNode(model.Node{ID: "n-old", Name: "old", LastSeen: lastSeen}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetNodeOfflineAlerts(map[string]time.Time{"n-old": lastSeen}); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	inc, ok := st.ActiveIncident(incidentKey(EventNodeOffline, "n-old", ""))
	if !ok || !inc.NoEscalate || inc.Notified != store.IncidentNotifiedOpen || !inc.Since.Equal(lastSeen) {
		t.Fatalf("adopted = %+v %v", inc, ok)
	}
	if left := st.NodeOfflineAlerts(); len(left) != 0 {
		t.Fatalf("the old map was kept: %v", left)
	}
	sent := captureTypedNotices(srv)
	srv.noteNodeOnline("n-old", time.Now().UTC())
	srv.evaluateIncidents(time.Now().UTC())
	if len(*sent) != 1 || (*sent)[0].eventType != EventNodeOnline || (*sent)[0].title != "Lattice node online: old" {
		t.Fatalf("the adopted page's recovery = %+v", *sent)
	}
}

// Taking a node off a monitor closes that pair's incident with a recovery,
// since the pair will never report again.
func TestUnassignedMonitorPairClosesItsIncident(t *testing.T) {
	h := newIncidentHarness(t, "a", "b")
	if err := h.f.st.UpsertMonitor(model.Monitor{ID: "mon-1", Name: "web", Type: model.MonitorTypeTCP, Target: "x:1", NodeIDs: []string{"a", "b"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	h.f.srv.openIncident(incidentSignal{kind: EventMonitorDown, nodeID: "a", monitorID: "mon-1", subject: "web on name-a", since: h.now(),
		msg: incidentMessage{title: "Monitor down: web on name-a", detail: "d", line: "l"}}, h.now())
	h.sweep()
	if err := h.f.st.UpsertMonitor(model.Monitor{ID: "mon-1", Name: "web", Type: model.MonitorTypeTCP, Target: "x:1", NodeIDs: []string{"b"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	expectNotices(t, "unassigned", h.sweep(), "monitor.recovered: Monitor no longer checks web on name-a")
	if err := h.f.st.DeleteMonitor("mon-1"); err != nil {
		t.Fatal(err)
	}
	if left := h.f.st.IncidentsWhere(func(inc store.Incident) bool { return inc.MonitorID == "mon-1" }); len(left) != 0 {
		t.Fatalf("a deleted monitor's incidents remain: %+v", left)
	}
}

// The rule route stores escalation and quiet hours, shows the effective
// defaults, and refuses values bark-server or the time zone database would
// not accept.
func TestNotifyRuleEscalationAndQuietHoursOptions(t *testing.T) {
	h := newIncidentHarness(t)
	cookies, csrf := loginSession(t, h.f.handler)
	addNotifyChannel(t, h.f.st, "nc-a", "Bark")
	post := func(body string) (int, notifyRuleView) {
		res := doJSON(t, h.f.handler, http.MethodPost, "/api/notify/rules", body, cookies, csrf)
		defer res.Body.Close()
		var v notifyRuleView
		if res.StatusCode == http.StatusOK {
			_ = json.NewDecoder(res.Body).Decode(&v)
		}
		return res.StatusCode, v
	}
	code, v := post(`{"id":"nr-1","name":"r","channel_ids":["nc-a"]}`)
	if code != http.StatusOK || v.EscalationOff || v.EscalateAfterMinutes != 30 || v.EscalationBarkLevel != "critical" || v.QuietHours != nil {
		t.Fatalf("defaults: %d %+v", code, v)
	}
	code, v = post(`{"id":"nr-1","name":"r","channel_ids":["nc-a"],"escalate_after_minutes":15,"escalation_bark_level":"timeSensitive","quiet_hours":{"start":"23:00","end":"07:30","time_zone":"Asia/Shanghai"}}`)
	if code != http.StatusOK || v.EscalateAfterMinutes != 15 || v.EscalationBarkLevel != "timeSensitive" || v.QuietHours == nil || v.QuietHours.TimeZone != "Asia/Shanghai" {
		t.Fatalf("set: %d %+v", code, v)
	}
	code, v = post(`{"id":"nr-1","name":"r","channel_ids":["nc-a"],"quiet_hours":null,"escalation_off":true}`)
	if code != http.StatusOK || v.QuietHours != nil || !v.EscalationOff || v.EscalateAfterMinutes != 15 {
		t.Fatalf("clear quiet hours, keep the rest: %d %+v", code, v)
	}
	for name, body := range map[string]string{
		"unknown Bark level":  `{"id":"nr-1","name":"r","channel_ids":["nc-a"],"escalation_bark_level":"loud"}`,
		"delay too short":     `{"id":"nr-1","name":"r","channel_ids":["nc-a"],"escalate_after_minutes":2}`,
		"unknown time zone":   `{"id":"nr-1","name":"r","channel_ids":["nc-a"],"quiet_hours":{"start":"23:00","end":"07:00","time_zone":"Mars/Olympus"}}`,
		"start equals end":    `{"id":"nr-1","name":"r","channel_ids":["nc-a"],"quiet_hours":{"start":"23:00","end":"23:00","time_zone":"UTC"}}`,
		"time not HH:MM":      `{"id":"nr-1","name":"r","channel_ids":["nc-a"],"quiet_hours":{"start":"7","end":"23:00","time_zone":"UTC"}}`,
		"quiet hours garbage": `{"id":"nr-1","name":"r","channel_ids":["nc-a"],"quiet_hours":"night"}`,
	} {
		if code, _ := post(body); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, code)
		}
	}
}

// Quiet hours and incident messages. A critical incident's recovery breaks
// through quiet hours as its open did. A warning's open and recovery are
// held, and when the window ends they go out one at a time in the order they
// were planned, except that an open whose incident was resolved or
// acknowledged meanwhile is withdrawn, and so is the recovery that answers
// it: the phone never heard "down", so it is not told "up".
func TestQuietHoursReleaseIncidentMessagesInOrderAndWithdrawTheSettled(t *testing.T) {
	h := newIncidentHarness(t, "a", "b", "c", "d")
	h.f.srv.emitIncidentNotice = h.f.srv.notifyIncidentEvent
	var mu sync.Mutex
	var order []string
	// An offline message takes a moment to send, so a recovery started beside
	// it would arrive first.
	h.f.srv.notifySend = func(_ context.Context, _ model.NotifyChannel, msg notify.Message) error {
		if strings.Contains(msg.Title, "offline") {
			time.Sleep(30 * time.Millisecond)
		}
		mu.Lock()
		order = append(order, msg.Title)
		mu.Unlock()
		return nil
	}
	sent := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), order...)
	}
	waitSent := func(n int) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for len(sent()) < n {
			if time.Now().After(deadline) {
				t.Fatalf("sent %q, want %d messages", sent(), n)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	addNotifyChannel(t, h.f.st, "nc-a", "Bark")
	start := h.now()
	quiet := &store.NotifyQuietHours{Start: start.Add(-time.Hour).Format("15:04"), End: start.Add(2 * time.Hour).Format("15:04"), TimeZone: "UTC"}
	if err := h.f.st.UpsertNotifyRuleWithOptions(model.NotifyRule{ID: "nr-1", Name: "all", ChannelIDs: []string{"nc-a"}, Enabled: true},
		store.NotifyRuleOptions{QuietHours: quiet, EscalationOff: true}); err != nil {
		t.Fatal(err)
	}
	offline := func(nodeID string) {
		h.f.srv.openIncident(incidentSignal{kind: EventNodeOffline, nodeID: nodeID, subject: "name-" + nodeID, since: h.now(),
			msg: incidentMessage{title: "Lattice node offline: name-" + nodeID, detail: "d", line: "l"}}, h.now())
	}
	online := func(nodeID string) {
		h.f.srv.resolveIncident(incidentKey(EventNodeOffline, nodeID, ""), h.now(),
			incidentMessage{title: "Lattice node online: name-" + nodeID, detail: "d", line: "l"})
	}
	step := func(do func()) {
		do()
		h.f.srv.evaluateIncidents(h.now())
		h.clock.advance(time.Minute)
	}

	step(func() { h.openService("a") })
	waitSent(1)
	step(func() { h.resolveService("a") })
	waitSent(2)
	if got := sent(); strings.Join(got, "|") != "sing-box down on name-a|sing-box recovered on name-a" {
		t.Fatalf("a critical incident inside quiet hours sent %q", got)
	}

	step(func() { offline("a") })
	step(func() { offline("b") })
	step(func() { offline("c") })
	step(func() { offline("d") })
	step(func() { online("a") })
	step(func() { online("c") })
	step(func() { offline("c") }) // reopens c's record
	cookies, csrf := loginSession(t, h.f.handler)
	res := doJSON(t, h.f.handler, http.MethodPost, "/api/incidents/ack", fmt.Sprintf(`{"id":%q}`, h.incident(EventNodeOffline, "d").ID), cookies, csrf)
	res.Body.Close()
	if got := sent(); len(got) != 2 {
		t.Fatalf("held messages went out inside quiet hours: %q", got)
	}
	held := deliveriesOf(h.f.st, store.NotifyDeliveryFilter{Outcome: store.NotifyOutcomePlanned})
	if len(held) != 7 {
		t.Fatalf("held rows = %d, want 7", len(held))
	}
	for _, row := range held {
		if row.HeldUntil.IsZero() || len(row.IncidentIDs) != 1 {
			t.Fatalf("held row = %+v", row)
		}
	}

	h.clock.at = start.Add(2*time.Hour + time.Minute)
	h.f.srv.wakeNotifyOutbox()
	waitOutboxSettled(t, h.f.srv)
	want := []string{
		"sing-box down on name-a", "sing-box recovered on name-a",
		"Lattice node offline: name-b",
		"Lattice node offline: name-c", "Lattice node online: name-c", "Lattice node offline: name-c",
	}
	if got := sent(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("after quiet hours sent %q, want %q", got, want)
	}
	withdrawn := map[string]string{}
	for _, row := range deliveriesOf(h.f.st, store.NotifyDeliveryFilter{Outcome: store.NotifyOutcomeSuppressed, ChannelID: "nc-a"}) {
		withdrawn[row.Title] = row.Reason
	}
	wantWithdrawn := map[string]string{
		"Lattice node offline: name-a": notifyWithdrawnOpen,
		"Lattice node online: name-a":  notifyWithdrawnRecovery,
		"Lattice node offline: name-d": notifyWithdrawnOpen,
	}
	if fmt.Sprint(withdrawn) != fmt.Sprint(wantWithdrawn) {
		t.Fatalf("withdrawn = %v, want %v", withdrawn, wantWithdrawn)
	}
}

// A rule's fallback that is a Bark channel carries an escalation's Bark
// level, which is stored only on the escalation's Bark rows.
func TestFallbackKeepsTheEscalationBarkLevel(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	addNotifyChannel(t, st, "nc-a", "Bark urgent")
	addNotifyChannel(t, st, "nc-fb", "Bark backup")
	rule := model.NotifyRule{ID: "r-urgent", Name: "Urgent", EventTypes: []string{EventServiceDown}, ChannelIDs: []string{"nc-a"}, Enabled: true}
	if err := st.UpsertNotifyRuleWithOptions(rule, store.NotifyRuleOptions{FallbackChannelID: "nc-fb"}); err != nil {
		t.Fatal(err)
	}
	installFakeNotifySender(srv, func(id string, _ int) error {
		if id == "nc-a" {
			return upstream(401)
		}
		return nil
	})
	srv.commitNotifyPlan(srv.planNotifyEvent(EventServiceDown, "Not acknowledged after 30 min: sing-box down", "b",
		notifyEnqueue{source: store.NotifySourceServer, onlyRule: &rule, barkLevel: "critical", incidentIDs: []string{"inc-1"}}))
	waitOutboxSettled(t, srv)
	fb := deliveriesOf(st, store.NotifyDeliveryFilter{ChannelID: "nc-fb"})
	if len(fb) != 1 || fb[0].Role != store.NotifyRoleFallback || fb[0].BarkLevel != "critical" || strings.Join(fb[0].IncidentIDs, ",") != "inc-1" {
		t.Fatalf("fallback = %+v", fb)
	}
}
