package server

import (
	"encoding/json"
	"net/http"
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
