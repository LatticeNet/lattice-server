package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
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
