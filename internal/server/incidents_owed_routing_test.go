package server

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// raise opens a stalled agent on nodeID and runs the sweep that sends its
// open message, leaving the sends for the caller to check.
func (d *dayNight) raise(nodeID string) string {
	d.t.Helper()
	d.h.f.srv.openIncident(incidentSignal{kind: EventAgentStalled, nodeID: nodeID, subject: "name-" + nodeID, since: d.h.now(),
		msg: incidentMessage{title: "Agent loop stalled: name-" + nodeID, detail: "d", line: "name-" + nodeID + ": stalled"}}, d.h.now())
	d.sweep()
	return d.h.incident(EventAgentStalled, nodeID).ID
}

// resolve resolves nodeID's stalled agent.
func (d *dayNight) resolve(nodeID string) {
	d.h.f.srv.resolveIncident(incidentKey(EventAgentStalled, nodeID, ""), d.h.now(), incidentMessage{
		title: "Agent loop recovered: name-" + nodeID, detail: "d", line: "name-" + nodeID + ": recovered",
	})
}

// snooze posts a snooze of minutes (0 ends it) as the operator.
func (d *dayNight) snooze(cookies []*http.Cookie, csrf, incidentID string, minutes int) {
	d.t.Helper()
	res := doJSON(d.t, d.h.f.handler, http.MethodPost, "/api/incidents/snooze", fmt.Sprintf(`{"id":%q,"minutes":%d}`, incidentID, minutes), cookies, csrf)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		d.t.Fatalf("snooze %d: %d", minutes, res.StatusCode)
	}
}

// Ending a snooze early sends no reminder. A rule whose held copy of the
// open quiet hours withdrew because of the snooze is owed the open, and the
// next sweep sends it through that rule alone, once.
func TestEndingASnoozeEarlyOwesTheOpenToARuleThatMissedIt(t *testing.T) {
	d := newDayNight(t, "a")
	_, cookies, csrf := incidentPoster(d.h)
	id := d.open("a")
	d.snooze(cookies, csrf, id, 120)
	d.endQuietHours()
	d.expect("withdrawn while snoozed")

	d.h.clock.advance(time.Minute)
	d.snooze(cookies, csrf, id, 0)
	if inc := d.h.incident(EventAgentStalled, "a"); inc.OwedOpen || strings.Join(inc.OwedOpenRules, ",") != "nr-night" {
		t.Fatalf("owed after the snooze ended: %+v", inc)
	}
	d.sweep()
	d.expect("after the snooze ended", "nc-night Agent loop stalled: name-a")
	d.sweep()
	d.expect("the next sweep")
}

// Ending a snooze on an incident every rule heard owes nothing.
func TestEndingASnoozeEarlyOwesNothingWhenEveryRuleHeard(t *testing.T) {
	d := newDayNight(t, "a")
	_, cookies, csrf := incidentPoster(d.h)
	d.endQuietHours()
	id := d.raise("a")
	d.expect("outside quiet hours", "nc-day Agent loop stalled: name-a", "nc-night Agent loop stalled: name-a")
	d.snooze(cookies, csrf, id, 120)
	d.h.clock.advance(time.Minute)
	d.snooze(cookies, csrf, id, 0)
	if inc := d.h.incident(EventAgentStalled, "a"); inc.OwedOpen || len(inc.OwedOpenRules) != 0 {
		t.Fatalf("owed after the snooze ended: %+v", inc)
	}
	d.sweep()
	d.expect("after the snooze ended")
}

// A recovery sent outside quiet hours does not reach a rule whose copy of
// the open was withdrawn: night never heard "down", so it is not told "up".
// Day, which heard it, is.
func TestARecoveryIsNotSentToARuleThatMissedTheOpen(t *testing.T) {
	d := newDayNight(t, "a")
	post, _, _ := incidentPoster(d.h)
	id := d.open("a")
	post("/api/incidents/ack", id)
	d.endQuietHours()
	d.expect("withdrawn")

	d.h.clock.advance(time.Minute)
	d.resolve("a")
	d.sweep()
	d.expect("the recovery", "nc-day Agent loop recovered: name-a")
	if inc := d.h.incident(EventAgentStalled, "a"); inc.OwedRecovery || inc.Notified != store.IncidentNotifiedResolved {
		t.Fatalf("after the recovery: %+v", inc)
	}
	d.sweep()
	d.expect("the next sweep")
}

// An incident that resolves while a rule is still owed its open (an undone
// acknowledgement owed it to night, and the sweep had not sent it yet) owes
// that rule nothing more: neither the open, which is no longer true, nor
// the recovery, since night never heard it was down.
func TestARecoveryIsNotSentToARuleStillOwedTheOpen(t *testing.T) {
	d := newDayNight(t, "a")
	post, _, _ := incidentPoster(d.h)
	id := d.open("a")
	post("/api/incidents/ack", id)
	d.endQuietHours()
	d.expect("withdrawn")
	post("/api/incidents/unack", id)
	if inc := d.h.incident(EventAgentStalled, "a"); strings.Join(inc.OwedOpenRules, ",") != "nr-night" {
		t.Fatalf("owed after the undo: %+v", inc)
	}

	d.h.clock.advance(time.Minute)
	d.resolve("a")
	// Night is kept on the record only to be left out of the recovery.
	if inc := d.h.incident(EventAgentStalled, "a"); inc.OwedOpen || inc.AckCancelledOpen || !inc.OwedRecovery || strings.Join(inc.OwedOpenRules, ",") != "nr-night" {
		t.Fatalf("after the resolve: %+v", inc)
	}
	d.sweep()
	d.expect("the recovery", "nc-day Agent loop recovered: name-a")
	if inc := d.h.incident(EventAgentStalled, "a"); inc.OwedRecovery || len(inc.OwedOpenRules) != 0 {
		t.Fatalf("after the recovery: %+v", inc)
	}
	d.sweep()
	d.expect("the next sweep")
}

// Recoveries that go out together leave out, for each rule, the incidents it
// never heard were down: day, which heard both, gets the digest; night,
// which missed a and heard b, is told only that b recovered.
func TestARecoveryDigestLeavesOutWhatARuleMissed(t *testing.T) {
	d := newDayNight(t, "a", "b")
	post, _, _ := incidentPoster(d.h)
	a := d.open("a")
	post("/api/incidents/ack", a)
	d.endQuietHours()
	d.expect("a withdrawn for night")
	d.h.clock.advance(time.Minute)
	d.raise("b")
	d.expect("b outside quiet hours", "nc-day Agent loop stalled: name-b", "nc-night Agent loop stalled: name-b")

	d.h.clock.advance(time.Minute)
	d.resolve("a")
	d.resolve("b")
	d.sweep()
	d.expect("the recoveries", "nc-day Lattice agent recovered digest: 2 nodes", "nc-night Agent loop recovered: name-b")
}

// An incident that reopens before its recovery went out leaves the phone
// saying "down", which is true again, so nothing is owed, except to a rule
// that never heard the last open: night is owed this one and gets it alone.
func TestAReopeningOwesTheOpenToARuleThatMissedTheLastOne(t *testing.T) {
	d := newDayNight(t, "a")
	post, _, _ := incidentPoster(d.h)
	id := d.open("a")
	post("/api/incidents/ack", id)
	d.endQuietHours()
	d.expect("withdrawn")

	d.h.clock.advance(time.Minute)
	d.resolve("a")
	// Only the outbox knows night missed it: the record owes it nothing.
	if inc := d.h.incident(EventAgentStalled, "a"); len(inc.OwedOpenRules) != 0 {
		t.Fatalf("after the resolve: %+v", inc)
	}
	d.h.clock.advance(time.Second)
	if reopened := d.raise("a"); reopened != id {
		t.Fatalf("reopened as %s, want the same record %s", reopened, id)
	}
	d.expect("the reopening", "nc-night Agent loop stalled: name-a")
	if inc := d.h.incident(EventAgentStalled, "a"); inc.OwedOpen || inc.OwedRecovery || len(inc.OwedOpenRules) != 0 || inc.Flaps != 1 {
		t.Fatalf("after the reopening: %+v", inc)
	}
	d.sweep()
	d.expect("the next sweep")
}

// Acknowledging an incident already acknowledged changes nothing: the record
// keeps the first acknowledgement and only that one is audited.
func TestAcknowledgingTwiceAuditsOnce(t *testing.T) {
	h := newIncidentHarness(t, "a")
	post, _, _ := incidentPoster(h)
	h.openService("a")
	h.sweep()
	id := h.incident(EventServiceDown, "a").ID
	if code, v := post("/api/incidents/ack", id); code != http.StatusOK || v.State != store.IncidentStateAcknowledged {
		t.Fatalf("ack: %d %+v", code, v)
	}
	first := h.incident(EventServiceDown, "a")
	h.clock.advance(time.Minute)
	if code, v := post("/api/incidents/ack", id); code != http.StatusOK || v.State != store.IncidentStateAcknowledged {
		t.Fatalf("ack again: %d %+v", code, v)
	}
	if again := h.incident(EventServiceDown, "a"); !reflect.DeepEqual(again, first) {
		t.Fatalf("the record changed:\nbefore %+v\nafter  %+v", first, again)
	}
	audits := 0
	for _, ev := range h.f.st.AuditEvents() {
		if ev.Action == "incident.ack" && ev.Metadata["incident_id"] == id {
			audits++
		}
	}
	if audits != 1 {
		t.Fatalf("incident.ack audited %d times, want 1", audits)
	}
}

// splitNight gives night a second channel and opens a stalled agent on a
// inside quiet hours, acknowledges it, ends quiet hours (both night copies
// withdrawn), then marks the nc-night2 copy delivered, as when an undo lands
// between the outbox settling the two copies.
func splitNight(t *testing.T) (*dayNight, func(path, incidentID string) (int, incidentView), string) {
	t.Helper()
	d := newDayNight(t, "a")
	addNotifyChannel(t, d.h.f.st, "nc-night2", "Bark night 2")
	quiet := &store.NotifyQuietHours{Start: d.start.Add(-time.Hour).Format("15:04"), End: d.start.Add(time.Hour).Format("15:04"), TimeZone: "UTC"}
	if err := d.h.f.st.UpsertNotifyRuleWithOptions(model.NotifyRule{ID: "nr-night", Name: "night", EventTypes: []string{EventAgentStalled, EventAgentRecovered},
		ChannelIDs: []string{"nc-night", "nc-night2"}, Enabled: true}, store.NotifyRuleOptions{QuietHours: quiet}); err != nil {
		t.Fatal(err)
	}
	post, _, _ := incidentPoster(d.h)
	id := d.open("a")
	post("/api/incidents/ack", id)
	d.endQuietHours()
	d.expect("both night copies withdrawn")
	rows := deliveriesOf(d.h.f.st, store.NotifyDeliveryFilter{ChannelID: "nc-night2", Outcome: store.NotifyOutcomeSuppressed})
	if len(rows) != 1 || rows[0].Reason != notifyWithdrawnOpen {
		t.Fatalf("nc-night2 rows = %+v", rows)
	}
	row := rows[0]
	row.Outcome, row.Reason = store.NotifyOutcomeSent, ""
	if err := d.h.f.st.PutNotifyDelivery(row, nil); err != nil {
		t.Fatal(err)
	}
	d.h.clock.advance(time.Minute)
	return d, post, id
}

// When one copy of night's open was withdrawn and the other delivered, an
// undo owes night the open: one of its phones never heard it. The channel
// that did hears it twice, the side an alert errs on.
func TestUndoOwesTheOpenToARuleThatLostOneCopy(t *testing.T) {
	d, post, id := splitNight(t)
	post("/api/incidents/unack", id)
	if inc := d.h.incident(EventAgentStalled, "a"); strings.Join(inc.OwedOpenRules, ",") != "nr-night" {
		t.Fatalf("owed after the undo: %+v", inc)
	}
	d.sweep()
	d.expect("after the undo", "nc-night Agent loop stalled: name-a", "nc-night2 Agent loop stalled: name-a")
}

// When one copy of night's open was delivered, night is told the recovery:
// the channel that heard "down" must hear "up".
func TestARecoveryReachesARuleThatDeliveredOneCopy(t *testing.T) {
	d, _, _ := splitNight(t)
	d.resolve("a")
	d.sweep()
	d.expect("the recovery", "nc-day Agent loop recovered: name-a", "nc-night Agent loop recovered: name-a", "nc-night2 Agent loop recovered: name-a")
}

// A rule still owed the open when the incident resolves is left out of the
// recovery even when the outbox no longer holds the withdrawn copy that
// explains why (the outbox is bounded and evicts old rows): the record keeps
// the rule until the recovery goes out.
func TestARecoveryLeavesOutAnOwedRuleTheOutboxForgot(t *testing.T) {
	d := newDayNight(t, "a")
	post, _, _ := incidentPoster(d.h)
	id := d.open("a")
	post("/api/incidents/ack", id)
	d.endQuietHours()
	d.expect("withdrawn")
	if err := d.h.f.st.PutMaintenanceWindow(store.MaintenanceWindow{
		ID: "mw-1", Name: "kernel upgrade", NodeIDs: []string{"a"},
		StartsAt: d.h.now(), EndsAt: d.h.now().Add(time.Hour), CreatedAt: d.h.now(),
	}, d.h.now()); err != nil {
		t.Fatal(err)
	}
	post("/api/incidents/unack", id)
	d.sweep()
	d.expect("the debt held by the window")

	d.forgetWithdrawnCopy("nc-night")

	d.h.clock.advance(time.Minute)
	d.resolve("a")
	d.sweep()
	d.expect("the recovery", "nc-day Agent loop recovered: name-a")
	if inc := d.h.incident(EventAgentStalled, "a"); inc.OwedRecovery || len(inc.OwedOpenRules) != 0 {
		t.Fatalf("after the recovery: %+v", inc)
	}
}

// When no rule routes the recovery's event type, a recovery a rule missed
// the open of is still recorded as unrouted, as any unrouted event is, so
// "why was nobody told" has an answer.
func TestAnUnroutedRecoveryIsRecordedWhenARuleMissedTheOpen(t *testing.T) {
	d := newDayNight(t, "a")
	quiet := &store.NotifyQuietHours{Start: d.start.Add(-time.Hour).Format("15:04"), End: d.start.Add(time.Hour).Format("15:04"), TimeZone: "UTC"}
	for _, r := range []struct {
		id   string
		opts store.NotifyRuleOptions
	}{{"night", store.NotifyRuleOptions{QuietHours: quiet}}, {"day", store.NotifyRuleOptions{}}} {
		if err := d.h.f.st.UpsertNotifyRuleWithOptions(model.NotifyRule{ID: "nr-" + r.id, Name: r.id, EventTypes: []string{EventAgentStalled},
			ChannelIDs: []string{"nc-" + r.id}, Enabled: true}, r.opts); err != nil {
			t.Fatal(err)
		}
	}
	post, _, _ := incidentPoster(d.h)
	id := d.open("a")
	post("/api/incidents/ack", id)
	d.endQuietHours()
	d.expect("withdrawn")

	d.h.clock.advance(time.Minute)
	d.resolve("a")
	d.sweep()
	d.expect("the recovery")
	if rows := deliveriesOf(d.h.f.st, store.NotifyDeliveryFilter{Outcome: store.NotifyOutcomeNoRoute, EventType: EventAgentRecovered}); len(rows) != 1 {
		t.Fatalf("unrouted recovery rows = %+v", rows)
	}
}

// forgetWithdrawnCopy makes channelID's withdrawn copy of the open stop
// naming its incident, as if the bounded outbox had evicted it.
func (d *dayNight) forgetWithdrawnCopy(channelID string) {
	d.t.Helper()
	rows := deliveriesOf(d.h.f.st, store.NotifyDeliveryFilter{ChannelID: channelID, Outcome: store.NotifyOutcomeSuppressed})
	if len(rows) != 1 || rows[0].Reason != notifyWithdrawnOpen {
		d.t.Fatalf("withdrawn rows on %s = %+v", channelID, rows)
	}
	row := rows[0]
	row.IncidentIDs = nil
	if err := d.h.f.st.PutNotifyDelivery(row, nil); err != nil {
		d.t.Fatal(err)
	}
}

// A reopening owes the open to a rule the record still listed as owed when
// the incident resolved, even when the outbox no longer holds the withdrawn
// copy: only the record knows night never heard it.
func TestAReopeningOwesTheOpenToAnOwedRuleTheOutboxForgot(t *testing.T) {
	d := newDayNight(t, "a")
	post, _, _ := incidentPoster(d.h)
	id := d.open("a")
	post("/api/incidents/ack", id)
	d.endQuietHours()
	d.expect("withdrawn")
	post("/api/incidents/unack", id) // owes night; no sweep pays it before the resolve
	d.forgetWithdrawnCopy("nc-night")

	d.h.clock.advance(time.Minute)
	d.resolve("a")
	if inc := d.h.incident(EventAgentStalled, "a"); strings.Join(inc.OwedOpenRules, ",") != "nr-night" {
		t.Fatalf("after the resolve: %+v", inc)
	}
	d.h.clock.advance(time.Second)
	if reopened := d.raise("a"); reopened != id {
		t.Fatalf("reopened as %s, want the same record %s", reopened, id)
	}
	d.expect("the reopening", "nc-night Agent loop stalled: name-a")
	d.sweep()
	d.expect("the next sweep")
}
