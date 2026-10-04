package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

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
	if inc := d.h.incident(EventAgentStalled, "a"); inc.OwedOpen || len(inc.OwedOpenRules) != 0 || inc.AckCancelledOpen {
		t.Fatalf("an open is still owed after the resolve: %+v", inc)
	}
	d.sweep()
	d.expect("the recovery", "nc-day Agent loop recovered: name-a")
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
