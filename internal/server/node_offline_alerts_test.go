package server

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// liveness is a server with no scheduler running and a notice recorder.
type liveness struct {
	srv     *Server
	handler http.Handler
	st      *store.Store
	sent    *[]typedNotice
}

func newLivenessAlertServer(t *testing.T) liveness {
	t.Helper()
	srv, handler, st := newInventoryServer(t)
	return liveness{srv: srv, handler: handler, st: st, sent: captureTypedNotices(srv)}
}

// take returns what was sent since the previous call.
func (l liveness) take() []typedNotice {
	out := *l.sent
	*l.sent = nil
	return out
}

// enrollAndBeat enrolls a node and sends the hello that brings it online.
func enrollAndBeat(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, nodeID, name string) string {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/nodes/enroll-token", `{"node_id":"`+nodeID+`","name":"`+name+`"}`, cookies, csrf)
	defer res.Body.Close()
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Token == "" {
		t.Fatalf("enroll %s: no token", nodeID)
	}
	beat(t, handler, nodeID, out.Token)
	return out.Token
}

func beat(t *testing.T, handler http.Handler, nodeID, token string) {
	t.Helper()
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/hello", `{"node_id":"`+nodeID+`","version":"test"}`, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("hello %s: %d %s", nodeID, rec.Code, rec.Body.String())
	}
}

func lastSeenOf(t *testing.T, st *store.Store, nodeID string) time.Time {
	t.Helper()
	n, ok := st.Node(nodeID)
	if !ok || n.LastSeen.IsZero() {
		t.Fatalf("node %s has no heartbeat", nodeID)
	}
	return n.LastSeen
}

func expectNoNotice(t *testing.T, l liveness, when string) {
	t.Helper()
	if got := l.take(); len(got) != 0 {
		t.Fatalf("%s: expected nothing sent, got %+v", when, got)
	}
}

func expectOneNotice(t *testing.T, l liveness, eventType, title string) typedNotice {
	t.Helper()
	got := l.take()
	if len(got) != 1 || got[0].eventType != eventType || got[0].title != title {
		t.Fatalf("expected one %s %q, got %+v", eventType, title, got)
	}
	return got[0]
}

const sweepCause = store.NodeStatusCauseLivenessSweep

// A node is marked offline after 90s, but only paged after ten minutes of
// silence, once per spell, and its return is paged only because the spell was.
func TestNodeOfflineAlertWaitsAndSendsOncePerSpell(t *testing.T) {
	l := newLivenessAlertServer(t)
	srv, handler, st := l.srv, l.handler, l.st
	cookies, csrf := loginSession(t, handler)
	token := enrollAndBeat(t, handler, cookies, csrf, "n-alpha", "alpha")
	ls := lastSeenOf(t, st, "n-alpha")

	srv.sweepNodeLiveness(ls.Add(2*time.Minute), sweepCause)
	if n, _ := st.Node("n-alpha"); n.Online {
		t.Fatal("the sweep must mark a node silent for 2 minutes offline")
	}
	expectNoNotice(t, l, "offline for 2 minutes")
	srv.sweepNodeLiveness(ls.Add(9*time.Minute), sweepCause)
	expectNoNotice(t, l, "offline for 9 minutes")

	srv.sweepNodeLiveness(ls.Add(10*time.Minute+time.Second), sweepCause)
	got := expectOneNotice(t, l, EventNodeOffline, "Lattice node offline: alpha")
	if !strings.Contains(got.body, "alpha (n-alpha) has not reported for 10 min") {
		t.Fatalf("offline body: %q", got.body)
	}
	srv.sweepNodeLiveness(ls.Add(30*time.Minute), sweepCause)
	expectNoNotice(t, l, "the same spell, later")

	beat(t, handler, "n-alpha", token)
	expectNoNotice(t, l, "the beat itself (recoveries wait for the sweep)")
	srv.sweepNodeLiveness(lastSeenOf(t, st, "n-alpha"), sweepCause)
	expectOneNotice(t, l, EventNodeOnline, "Lattice node online: alpha")
	srv.sweepNodeLiveness(lastSeenOf(t, st, "n-alpha").Add(time.Second), sweepCause)
	expectNoNotice(t, l, "after the recovery was sent")
}

// The metrics beat is the other path that ends a spell, and it queues the
// recovery the same way the hello beat does.
func TestNodeOnlineFollowsAMetricsBeat(t *testing.T) {
	l := newLivenessAlertServer(t)
	srv, handler, st := l.srv, l.handler, l.st
	cookies, csrf := loginSession(t, handler)
	token := enrollAndBeat(t, handler, cookies, csrf, "n-metrics", "metrics")
	ls := lastSeenOf(t, st, "n-metrics")

	srv.sweepNodeLiveness(ls.Add(11*time.Minute), sweepCause)
	expectOneNotice(t, l, EventNodeOffline, "Lattice node offline: metrics")
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/metrics", `{"node_id":"n-metrics","version":"test","metrics":{}}`, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics: %d %s", rec.Code, rec.Body.String())
	}
	srv.sweepNodeLiveness(lastSeenOf(t, st, "n-metrics"), sweepCause)
	expectOneNotice(t, l, EventNodeOnline, "Lattice node online: metrics")
}

// A gap shorter than the delay sends nothing in either direction.
func TestNodeOfflineBlipSendsNothing(t *testing.T) {
	l := newLivenessAlertServer(t)
	srv, handler, st := l.srv, l.handler, l.st
	cookies, csrf := loginSession(t, handler)
	token := enrollAndBeat(t, handler, cookies, csrf, "n-blip", "blip")
	ls := lastSeenOf(t, st, "n-blip")

	srv.sweepNodeLiveness(ls.Add(5*time.Minute), sweepCause)
	beat(t, handler, "n-blip", token)
	back := lastSeenOf(t, st, "n-blip")
	srv.sweepNodeLiveness(back.Add(time.Second), sweepCause)
	srv.sweepNodeLiveness(back.Add(30*time.Second), sweepCause)
	expectNoNotice(t, l, "a five-minute gap")
}

// Nodes that go quiet in the same sweep share one message each way.
func TestNodeOfflineAlertsDigestOneSweep(t *testing.T) {
	l := newLivenessAlertServer(t)
	srv, handler, st := l.srv, l.handler, l.st
	cookies, csrf := loginSession(t, handler)
	tokenB := enrollAndBeat(t, handler, cookies, csrf, "n-bravo", "bravo")
	tokenA := enrollAndBeat(t, handler, cookies, csrf, "n-alpha", "alpha")
	ls := lastSeenOf(t, st, "n-alpha")

	srv.sweepNodeLiveness(ls.Add(11*time.Minute), sweepCause)
	got := expectOneNotice(t, l, EventNodeOffline, "Lattice node offline digest: 2 nodes")
	lines := strings.Split(got.body, "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "alpha: no report for ") || !strings.HasPrefix(lines[1], "bravo: no report for ") {
		t.Fatalf("digest body must list both nodes by name: %q", got.body)
	}

	beat(t, handler, "n-alpha", tokenA)
	beat(t, handler, "n-bravo", tokenB)
	srv.sweepNodeLiveness(lastSeenOf(t, st, "n-bravo"), sweepCause)
	got = expectOneNotice(t, l, EventNodeOnline, "Lattice node online digest: 2 nodes")
	if !strings.Contains(got.body, "alpha: back after ") || !strings.Contains(got.body, "bravo: back after ") {
		t.Fatalf("online digest body: %q", got.body)
	}
}

// The reserved tag keeps a node that sleeps by design off the phone, in any
// letter case.
func TestNodeTaggedNoOfflineAlertStaysSilent(t *testing.T) {
	l := newLivenessAlertServer(t)
	srv, handler, st := l.srv, l.handler, l.st
	cookies, csrf := loginSession(t, handler)
	token := enrollAndBeat(t, handler, cookies, csrf, "n-laptop", "laptop")
	res := doJSON(t, handler, http.MethodPost, "/api/nodes/update",
		`{"node_id":"n-laptop","name":"laptop","tags":["cd","No-Offline-Alert"]}`, cookies, csrf)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("tag update: %d", res.StatusCode)
	}
	res.Body.Close()
	ls := lastSeenOf(t, st, "n-laptop")

	srv.sweepNodeLiveness(ls.Add(2*time.Minute), sweepCause)
	srv.sweepNodeLiveness(ls.Add(3*time.Hour), sweepCause)
	beat(t, handler, "n-laptop", token)
	srv.sweepNodeLiveness(lastSeenOf(t, st, "n-laptop"), sweepCause)
	expectNoNotice(t, l, "a node tagged no-offline-alert")
}

// Silence before this process started is not counted, and a spell that was
// already past the delay at start is left to the process that saw it begin.
func TestNodeOfflineAlertCountsOnlySilenceThisProcessSaw(t *testing.T) {
	t.Run("long gone before start", func(t *testing.T) {
		l := newLivenessAlertServer(t)
		srv, handler, st := l.srv, l.handler, l.st
		cookies, csrf := loginSession(t, handler)
		enrollAndBeat(t, handler, cookies, csrf, "n-gone", "gone")
		ls := lastSeenOf(t, st, "n-gone")
		srv.nodeAlerts.start(ls.Add(30 * time.Minute))

		srv.sweepNodeLiveness(ls.Add(31*time.Minute), store.NodeStatusCauseServerStart)
		srv.sweepNodeLiveness(ls.Add(5*time.Hour), sweepCause)
		expectNoNotice(t, l, "a node silent for 30 minutes before start")
	})
	t.Run("went quiet during the restart", func(t *testing.T) {
		l := newLivenessAlertServer(t)
		srv, handler, st := l.srv, l.handler, l.st
		cookies, csrf := loginSession(t, handler)
		enrollAndBeat(t, handler, cookies, csrf, "n-dip", "dip")
		ls := lastSeenOf(t, st, "n-dip")
		srv.nodeAlerts.start(ls.Add(5 * time.Minute))

		srv.sweepNodeLiveness(ls.Add(5*time.Minute), store.NodeStatusCauseServerStart)
		srv.sweepNodeLiveness(ls.Add(14*time.Minute), sweepCause)
		expectNoNotice(t, l, "nine minutes after start")
		srv.sweepNodeLiveness(ls.Add(15*time.Minute+time.Second), sweepCause)
		got := expectOneNotice(t, l, EventNodeOffline, "Lattice node offline: dip")
		if !strings.Contains(got.body, "has not reported for 15 min") {
			t.Fatalf("the message states the whole silence, not the part seen here: %q", got.body)
		}
	})
}

func TestTwoFactorLimitAlertHasItsOwnEventType(t *testing.T) {
	if got := classifyNotifyEvent("🔐 2FA attempt limit"); got != "auth.2fa_limit" {
		t.Fatalf("classifyNotifyEvent: got %q", got)
	}
}

// A node with its own delay is recorded offline at 90s like any other, pages
// only after its delay, and its return still pages at the next sweep.
func TestNodeOfflineDelayTagWaitsItsOwnTime(t *testing.T) {
	l := newLivenessAlertServer(t)
	srv, handler, st := l.srv, l.handler, l.st
	cookies, csrf := loginSession(t, handler)
	token := enrollAndBeat(t, handler, cookies, csrf, "n-roam", "roam")
	res := doJSON(t, handler, http.MethodPost, "/api/nodes/update",
		`{"node_id":"n-roam","name":"roam","tags":["cd","offline-alert-after:3h"]}`, cookies, csrf)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("tag update: %d", res.StatusCode)
	}
	res.Body.Close()
	ls := lastSeenOf(t, st, "n-roam")

	srv.sweepNodeLiveness(ls.Add(11*time.Minute), sweepCause)
	if n, ok := st.Node("n-roam"); !ok || n.Online {
		t.Fatalf("a delayed node must still be marked offline at the liveness threshold (found %v, online %v)", ok, n.Online)
	}
	expectNoNotice(t, l, "past the default delay")
	srv.sweepNodeLiveness(ls.Add(3*time.Hour-time.Minute), sweepCause)
	expectNoNotice(t, l, "a minute before its own delay")
	srv.sweepNodeLiveness(ls.Add(3*time.Hour+time.Second), sweepCause)
	got := expectOneNotice(t, l, EventNodeOffline, "Lattice node offline: roam")
	if !strings.Contains(got.body, "has not reported for 3 h") {
		t.Fatalf("offline body: %q", got.body)
	}

	beat(t, handler, "n-roam", token)
	srv.sweepNodeLiveness(lastSeenOf(t, st, "n-roam"), sweepCause)
	expectOneNotice(t, l, EventNodeOnline, "Lattice node online: roam")
}

func TestNodeOfflineDelayReadsTags(t *testing.T) {
	cases := []struct {
		tags  []string
		delay time.Duration
		pages bool
	}{
		{nil, nodeOfflineAlertAfter, true},
		{[]string{"cd", "Mac"}, nodeOfflineAlertAfter, true},
		{[]string{"offline-alert-after:3h"}, 3 * time.Hour, true},
		{[]string{" Offline-Alert-After:45m "}, 45 * time.Minute, true},
		{[]string{"offline-alert-after:2m"}, 2 * time.Minute, true},
		{[]string{"offline-alert-after:168h"}, 168 * time.Hour, true},
		{[]string{"offline-alert-after:30m", "offline-alert-after:3h"}, 3 * time.Hour, true},
		{[]string{"offline-alert-after:3h", "no-offline-alert"}, 0, false},
		{[]string{"NO-OFFLINE-ALERT"}, 0, false},
		// Anything that does not parse falls back to the default, never to silence.
		{[]string{"offline-alert-after:3d"}, nodeOfflineAlertAfter, true},
		{[]string{"offline-alert-after:0h"}, nodeOfflineAlertAfter, true},
		{[]string{"offline-alert-after:1m"}, nodeOfflineAlertAfter, true},
		{[]string{"offline-alert-after:169h"}, nodeOfflineAlertAfter, true},
		{[]string{"offline-alert-after:3"}, nodeOfflineAlertAfter, true},
		{[]string{"offline-alert-after:h"}, nodeOfflineAlertAfter, true},
		{[]string{"offline-alert-after:+3h"}, nodeOfflineAlertAfter, true},
		{[]string{"offline-alert-after: 3h"}, nodeOfflineAlertAfter, true},
		{[]string{"offline-alert-after:99999999h"}, nodeOfflineAlertAfter, true},
	}
	for _, c := range cases {
		delay, pages := nodeOfflineDelay(model.Node{Tags: c.tags})
		if delay != c.delay || pages != c.pages {
			t.Errorf("tags %q: got (%v, %v), want (%v, %v)", c.tags, delay, pages, c.delay, c.pages)
		}
	}
}

func setNodeDisabled(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, nodeID string, disabled bool) {
	t.Helper()
	body := `{"node_id":"` + nodeID + `","disabled":false}`
	if disabled {
		body = `{"node_id":"` + nodeID + `","disabled":true}`
	}
	res := doJSON(t, handler, http.MethodPost, "/api/nodes/disable", body, cookies, csrf)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("disable %s=%v: %d", nodeID, disabled, res.StatusCode)
	}
}

// A disabled node's token is refused, so it goes silent and the sweep marks it
// offline, but that silence is the operator's own action and never pages. Once
// enabled again its silence counts from the enable, not from a LastSeen that
// is hours old, so the agent gets the whole delay to come back.
func TestDisabledNodeNeverPagesAndReenableRestartsTheDelay(t *testing.T) {
	l := newLivenessAlertServer(t)
	srv, handler, st := l.srv, l.handler, l.st
	cookies, csrf := loginSession(t, handler)
	enrollAndBeat(t, handler, cookies, csrf, "n-off", "off")
	ls := lastSeenOf(t, st, "n-off")
	setNodeDisabled(t, handler, cookies, csrf, "n-off", true)

	srv.sweepNodeLiveness(ls.Add(11*time.Minute), sweepCause)
	if n, _ := st.Node("n-off"); n.Online {
		t.Fatal("a silent disabled node is still marked offline by the sweep")
	}
	srv.sweepNodeLiveness(ls.Add(3*time.Hour), sweepCause)
	expectNoNotice(t, l, "a node disabled for three hours")

	setNodeDisabled(t, handler, cookies, csrf, "n-off", false)
	enabled := ls.Add(3*time.Hour + time.Second)
	srv.sweepNodeLiveness(enabled, sweepCause)
	expectNoNotice(t, l, "the sweep right after enabling")
	srv.sweepNodeLiveness(enabled.Add(9*time.Minute), sweepCause)
	expectNoNotice(t, l, "nine minutes after enabling")
	srv.sweepNodeLiveness(enabled.Add(10*time.Minute+time.Second), sweepCause)
	got := expectOneNotice(t, l, EventNodeOffline, "Lattice node offline: off")
	if !strings.Contains(got.body, "has not reported for 3 h") {
		t.Fatalf("the message states the whole silence: %q", got.body)
	}
}

// A node paged offline and then disabled keeps its page open: when it is
// enabled and reports again, node.online answers the page.
func TestNodePagedThenDisabledStillGetsItsRecovery(t *testing.T) {
	l := newLivenessAlertServer(t)
	srv, handler, st := l.srv, l.handler, l.st
	cookies, csrf := loginSession(t, handler)
	token := enrollAndBeat(t, handler, cookies, csrf, "n-paged", "paged")
	ls := lastSeenOf(t, st, "n-paged")

	srv.sweepNodeLiveness(ls.Add(11*time.Minute), sweepCause)
	expectOneNotice(t, l, EventNodeOffline, "Lattice node offline: paged")
	setNodeDisabled(t, handler, cookies, csrf, "n-paged", true)
	srv.sweepNodeLiveness(ls.Add(20*time.Minute), sweepCause)
	srv.sweepNodeLiveness(ls.Add(2*time.Hour), sweepCause)
	expectNoNotice(t, l, "while disabled")

	setNodeDisabled(t, handler, cookies, csrf, "n-paged", false)
	srv.sweepNodeLiveness(ls.Add(2*time.Hour+time.Second), sweepCause)
	srv.sweepNodeLiveness(ls.Add(2*time.Hour+11*time.Minute), sweepCause)
	expectNoNotice(t, l, "enabled, the same spell already paged")
	beat(t, handler, "n-paged", token)
	srv.sweepNodeLiveness(lastSeenOf(t, st, "n-paged"), sweepCause)
	expectOneNotice(t, l, EventNodeOnline, "Lattice node online: paged")
}

// A page sent before a control plane restart is answered after it: the paged
// spell is on disk, so the first beat after the restart queues node.online,
// and the restarted process does not page the same spell again.
func TestNodeOnlineFollowsAPageAcrossARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st1, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	srv1, err := New(Options{Store: st1, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	sent1 := captureTypedNotices(srv1)
	handler1 := srv1.Handler()
	cookies, csrf := loginSession(t, handler1)
	token := enrollAndBeat(t, handler1, cookies, csrf, "n-restart", "restart")
	ls := lastSeenOf(t, st1, "n-restart")
	srv1.sweepNodeLiveness(ls.Add(11*time.Minute), sweepCause)
	if len(*sent1) != 1 || (*sent1)[0].eventType != EventNodeOffline {
		t.Fatalf("before the restart: %+v", *sent1)
	}
	if err := st1.Close(); err != nil {
		t.Fatal(err)
	}

	st2, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st2.Close() })
	if got := st2.NodeOfflineAlerts(); !got["n-restart"].Equal(ls) {
		t.Fatalf("the paged spell was not persisted: %v (want LastSeen %s)", got, ls)
	}
	srv2, err := New(Options{Store: st2, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	l := liveness{srv: srv2, handler: srv2.Handler(), st: st2, sent: captureTypedNotices(srv2)}
	srv2.nodeAlerts.start(ls.Add(20 * time.Minute))
	srv2.sweepNodeLiveness(ls.Add(20*time.Minute), store.NodeStatusCauseServerStart)
	srv2.sweepNodeLiveness(ls.Add(40*time.Minute), sweepCause)
	expectNoNotice(t, l, "the same spell after the restart")

	beat(t, l.handler, "n-restart", token)
	srv2.sweepNodeLiveness(lastSeenOf(t, st2, "n-restart"), sweepCause)
	expectOneNotice(t, l, EventNodeOnline, "Lattice node online: restart")
	if got := st2.NodeOfflineAlerts(); len(got) != 0 {
		t.Fatalf("the answered page is still on disk: %v", got)
	}
	srv2.sweepNodeLiveness(lastSeenOf(t, st2, "n-restart").Add(time.Second), sweepCause)
	expectNoNotice(t, l, "after the recovery")
}

// Deleting a paged node drops its spell from disk, so a node enrolled again
// under the same id cannot announce a recovery from a page it never got.
func TestDeletedPagedNodeLeavesNoAlertBehind(t *testing.T) {
	l := newLivenessAlertServer(t)
	srv, handler, st := l.srv, l.handler, l.st
	cookies, csrf := loginSession(t, handler)
	enrollAndBeat(t, handler, cookies, csrf, "n-gone", "gone")
	ls := lastSeenOf(t, st, "n-gone")
	srv.sweepNodeLiveness(ls.Add(11*time.Minute), sweepCause)
	expectOneNotice(t, l, EventNodeOffline, "Lattice node offline: gone")
	if _, ok := st.NodeOfflineAlerts()["n-gone"]; !ok {
		t.Fatal("the page was not recorded")
	}

	res := doJSON(t, handler, http.MethodPost, "/api/nodes/delete", `{"node_id":"n-gone"}`, cookies, csrf)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("delete: %d", res.StatusCode)
	}
	if got := st.NodeOfflineAlerts(); len(got) != 0 {
		t.Fatalf("the deleted node's page is still on disk: %v", got)
	}
	token := enrollAndBeat(t, handler, cookies, csrf, "n-gone", "gone")
	beat(t, handler, "n-gone", token)
	srv.sweepNodeLiveness(lastSeenOf(t, st, "n-gone"), sweepCause)
	expectNoNotice(t, l, "the re-enrolled node's first beats")
}
