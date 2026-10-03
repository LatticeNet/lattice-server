package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/notify"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// incidentPoster posts {"id": ...} to an incident route as the operator,
// logging in once; it also returns the session for other calls.
func incidentPoster(h *incidentHarness) (func(path, incidentID string) (int, incidentView), []*http.Cookie, string) {
	cookies, csrf := loginSession(h.t, h.f.handler)
	return func(path, incidentID string) (int, incidentView) {
		h.t.Helper()
		res := doJSON(h.t, h.f.handler, http.MethodPost, path, fmt.Sprintf(`{"id":%q}`, incidentID), cookies, csrf)
		defer res.Body.Close()
		var v incidentView
		if res.StatusCode == http.StatusOK {
			if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
				h.t.Fatal(err)
			}
		}
		return res.StatusCode, v
	}, cookies, csrf
}

// waitOutboxIdle waits until no delivery is running and every unsettled one
// is held past the server's clock.
func waitOutboxIdle(t *testing.T, srv *Server) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		srv.notifyDeliveries.mu.Lock()
		running := srv.notifyDeliveries.n
		srv.notifyDeliveries.mu.Unlock()
		due := 0
		for _, row := range srv.store.UnsettledNotifyDeliveries() {
			if !row.HeldUntil.After(srv.now()) {
				due++
			}
		}
		if running == 0 && due == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("outbox did not go idle: %+v", srv.store.UnsettledNotifyDeliveries())
}

// Undoing an acknowledgement puts the incident back to open with its
// escalation clock where it was: an escalation that fell due while it was
// acknowledged goes out at the next sweep, as it would have without the
// acknowledgement, and the undo is audited.
func TestUnacknowledgeResumesTheEscalationClock(t *testing.T) {
	h := newIncidentHarness(t, "a")
	post, _, _ := incidentPoster(h)
	sends := &escalationSends{}
	sends.install(h.f.srv)
	addNotifyChannel(t, h.f.st, "nc-urgent", "Bark urgent")
	if err := h.f.st.UpsertNotifyRuleWithOptions(model.NotifyRule{ID: "nr-1", Name: "sing-box", EventTypes: []string{EventServiceDown}, ChannelIDs: []string{"nc-urgent"}, Enabled: true},
		store.NotifyRuleOptions{EscalateAfterMinutes: 10}); err != nil {
		t.Fatal(err)
	}
	h.openService("a")
	h.sweep()
	id := h.incident(EventServiceDown, "a").ID

	h.clock.advance(2 * time.Minute)
	if code, v := post("/api/incidents/ack", id); code != http.StatusOK || v.State != store.IncidentStateAcknowledged {
		t.Fatalf("ack: %d %+v", code, v)
	}
	h.clock.advance(9 * time.Minute)
	h.sweep()
	waitOutboxSettled(t, h.f.srv)
	if got := sends.take(); len(got) != 0 {
		t.Fatalf("an acknowledged incident escalated: %v", got)
	}

	code, v := post("/api/incidents/unack", id)
	if code != http.StatusOK || v.State != store.IncidentStateOpen || v.AckedBy != "" || !v.AckedAt.IsZero() {
		t.Fatalf("unack: %d %+v", code, v)
	}
	h.sweep()
	waitOutboxSettled(t, h.f.srv)
	if got := sends.take(); len(got) != 1 || got[0] != "nc-urgent level=critical Not acknowledged after 10 min: sing-box down on name-a" {
		t.Fatalf("after the undo = %v", got)
	}
	audited := false
	for _, ev := range h.f.st.AuditEvents() {
		if ev.Action == "incident.unack" && ev.Metadata["incident_id"] == id && ev.Metadata["acked_at"] != "" {
			audited = true
		}
	}
	if !audited {
		t.Fatal("the undo was not audited")
	}
}

// An open message a maintenance window held, and a snooze reminder that fell
// due, are dropped by an acknowledgement and owed again when it is undone.
func TestUnacknowledgeOwesTheCancelledOpenAgain(t *testing.T) {
	h := newIncidentHarness(t, "a", "b")
	post, cookies, csrf := incidentPoster(h)
	if err := h.f.st.PutMaintenanceWindow(store.MaintenanceWindow{
		ID: "mw-1", Name: "kernel upgrade", NodeIDs: []string{"a"},
		StartsAt: h.now(), EndsAt: h.now().Add(30 * time.Minute), CreatedAt: h.now(),
	}, h.now()); err != nil {
		t.Fatal(err)
	}
	h.openService("a")
	expectNotices(t, "held by the window", h.sweep())
	held := h.incident(EventServiceDown, "a")
	post("/api/incidents/ack", held.ID)
	if inc := h.incident(EventServiceDown, "a"); inc.OwedOpen || !inc.AckCancelledOpen {
		t.Fatalf("after the ack = %+v", inc)
	}
	h.clock.advance(31 * time.Minute)
	expectNotices(t, "the window ended on an acknowledged incident", h.sweep())
	post("/api/incidents/unack", held.ID)
	expectNotices(t, "after the undo", h.sweep(), "service.down: sing-box down on name-a")

	// A snooze reminder that fell due while acknowledged.
	h.openService("b")
	h.sweep()
	b := h.incident(EventServiceDown, "b")
	res := doJSON(t, h.f.handler, http.MethodPost, "/api/incidents/snooze", fmt.Sprintf(`{"id":%q,"minutes":20}`, b.ID), cookies, csrf)
	res.Body.Close()
	post("/api/incidents/ack", b.ID)
	h.clock.advance(21 * time.Minute)
	expectNotices(t, "the snooze ran out while acknowledged", h.sweep())
	post("/api/incidents/unack", b.ID)
	expectNotices(t, "the reminder after the undo", h.sweep(), "service.down: sing-box down on name-b")
	expectNotices(t, "once", h.sweep())
}

// An acknowledgement recorded before AckCancelledOpen existed carries no
// flag. Undoing one whose open message never went out (a window held it)
// still owes that message, exactly once, and the incident is then told open,
// which is what its escalation waits for.
func TestUnacknowledgeOwesAnOpenNeverSentWithoutTheFlag(t *testing.T) {
	h := newIncidentHarness(t, "a")
	post, _, _ := incidentPoster(h)
	if err := h.f.st.PutMaintenanceWindow(store.MaintenanceWindow{
		ID: "mw-1", Name: "kernel upgrade", NodeIDs: []string{"a"},
		StartsAt: h.now(), EndsAt: h.now().Add(30 * time.Minute), CreatedAt: h.now(),
	}, h.now()); err != nil {
		t.Fatal(err)
	}
	h.openService("a")
	expectNotices(t, "held by the window", h.sweep())
	// The record as the previous version wrote it: acknowledged, the held
	// open dropped, nothing remembered.
	inc := h.incident(EventServiceDown, "a")
	inc.State, inc.AckedBy, inc.AckedAt = store.IncidentStateAcknowledged, "user-1", h.now()
	inc.OwedOpen, inc.AckCancelledOpen = false, false
	if err := h.f.st.PutIncidents(inc); err != nil {
		t.Fatal(err)
	}
	h.clock.advance(31 * time.Minute)
	expectNotices(t, "the window ended on an acknowledged incident", h.sweep())

	if code, v := post("/api/incidents/unack", inc.ID); code != http.StatusOK || v.State != store.IncidentStateOpen {
		t.Fatalf("unack: %d %+v", code, v)
	}
	expectNotices(t, "after the undo", h.sweep(), "service.down: sing-box down on name-a")
	expectNotices(t, "once", h.sweep())
	if got := h.incident(EventServiceDown, "a"); got.Notified != store.IncidentNotifiedOpen || got.OpenNotifiedAt.IsZero() {
		t.Fatalf("the incident was not told open: %+v", got)
	}
}

// A closed incident keeps its acknowledgement; an incident that is not
// acknowledged is left as it is; the route needs monitor:admin on the node.
func TestUnacknowledgeRefusesAClosedIncident(t *testing.T) {
	h := newIncidentHarness(t, "a", "b")
	post, cookies, csrf := incidentPoster(h)
	h.openService("a")
	h.openService("b")
	h.sweep()
	a := h.incident(EventServiceDown, "a")
	post("/api/incidents/ack", a.ID)
	h.resolveService("a")
	if code, _ := post("/api/incidents/unack", a.ID); code != http.StatusConflict {
		t.Fatalf("unack a resolved incident: %d", code)
	}
	if inc := h.incident(EventServiceDown, "a"); inc.State != store.IncidentStateResolved || inc.AckedBy == "" {
		t.Fatalf("the resolved incident changed: %+v", inc)
	}
	b := h.incident(EventServiceDown, "b")
	if code, v := post("/api/incidents/unack", b.ID); code != http.StatusOK || v.State != store.IncidentStateOpen {
		t.Fatalf("unack an open incident: %d %+v", code, v)
	}
	if code, _ := post("/api/incidents/unack", "inc-missing"); code != http.StatusNotFound {
		t.Fatalf("unack a missing incident: %d", code)
	}

	post("/api/incidents/ack", b.ID)
	readOnly := createPAT(t, h.f.handler, cookies, csrf, []string{"monitor:read"}, nil)
	res := doBearerJSON(t, h.f.handler, http.MethodPost, "/api/incidents/unack", fmt.Sprintf(`{"id":%q}`, b.ID), readOnly)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("unack without monitor:admin: %d", res.StatusCode)
	}
	confined := createPAT(t, h.f.handler, cookies, csrf, []string{"monitor:read", "monitor:admin"}, []string{"a"})
	res = doBearerJSON(t, h.f.handler, http.MethodPost, "/api/incidents/unack", fmt.Sprintf(`{"id":%q}`, b.ID), confined)
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("unack another node's incident: %d", res.StatusCode)
	}
	if inc := h.incident(EventServiceDown, "b"); inc.State != store.IncidentStateAcknowledged {
		t.Fatalf("a refused undo changed the incident: %+v", inc)
	}
}

// An open message that quiet hours held and then withdrew because the
// incident was acknowledged goes out again through that rule when the
// acknowledgement is undone, and through no other.
func TestUnacknowledgeResendsAnOpenQuietHoursWithdrew(t *testing.T) {
	h := newIncidentHarness(t, "a")
	post, _, _ := incidentPoster(h)
	h.f.srv.emitIncidentNotice = h.f.srv.notifyIncidentEvent
	var mu sync.Mutex
	var got []string
	h.f.srv.notifySend = func(_ context.Context, c model.NotifyChannel, msg notify.Message) error {
		mu.Lock()
		got = append(got, c.ID+" "+msg.Title)
		mu.Unlock()
		return nil
	}
	take := func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := got
		got = nil
		return out
	}
	addNotifyChannel(t, h.f.st, "nc-night", "Bark night")
	addNotifyChannel(t, h.f.st, "nc-day", "Bark day")
	start := h.now()
	quiet := &store.NotifyQuietHours{Start: start.Add(-time.Hour).Format("15:04"), End: start.Add(time.Hour).Format("15:04"), TimeZone: "UTC"}
	if err := h.f.st.UpsertNotifyRuleWithOptions(model.NotifyRule{ID: "nr-night", Name: "night", EventTypes: []string{EventAgentStalled}, ChannelIDs: []string{"nc-night"}, Enabled: true},
		store.NotifyRuleOptions{QuietHours: quiet}); err != nil {
		t.Fatal(err)
	}
	if err := h.f.st.UpsertNotifyRuleWithOptions(model.NotifyRule{ID: "nr-day", Name: "day", EventTypes: []string{EventAgentStalled}, ChannelIDs: []string{"nc-day"}, Enabled: true},
		store.NotifyRuleOptions{}); err != nil {
		t.Fatal(err)
	}
	h.f.srv.openIncident(incidentSignal{kind: EventAgentStalled, nodeID: "a", subject: "name-a", since: h.now(),
		msg: incidentMessage{title: "Agent loop stalled: name-a", detail: "d", line: "l"}}, h.now())
	h.f.srv.evaluateIncidents(h.now())
	waitOutboxIdle(t, h.f.srv)
	if sent := take(); strings.Join(sent, "|") != "nc-day Agent loop stalled: name-a" {
		t.Fatalf("inside quiet hours sent %q", sent)
	}
	id := h.incident(EventAgentStalled, "a").ID
	post("/api/incidents/ack", id)

	h.clock.at = start.Add(time.Hour + time.Minute)
	h.f.srv.wakeNotifyOutbox()
	waitOutboxIdle(t, h.f.srv)
	if sent := take(); len(sent) != 0 {
		t.Fatalf("an acknowledged incident's held open went out: %q", sent)
	}
	if rows := deliveriesOf(h.f.st, store.NotifyDeliveryFilter{Outcome: store.NotifyOutcomeSuppressed, ChannelID: "nc-night"}); len(rows) != 1 || rows[0].Reason != notifyWithdrawnOpen {
		t.Fatalf("withdrawn rows = %+v", rows)
	}

	if code, _ := post("/api/incidents/unack", id); code != http.StatusOK {
		t.Fatalf("unack: %d", code)
	}
	waitOutboxIdle(t, h.f.srv)
	if sent := take(); strings.Join(sent, "|") != "nc-night Agent loop stalled: name-a" {
		t.Fatalf("after the undo sent %q", sent)
	}
	h.f.srv.evaluateIncidents(h.now())
	waitOutboxIdle(t, h.f.srv)
	if sent := take(); len(sent) != 0 {
		t.Fatalf("the sweep sent it again: %q", sent)
	}
}
