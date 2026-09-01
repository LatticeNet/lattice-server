package server

import (
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestDeriveSingBoxServiceState(t *testing.T) {
	probed := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name         string
		rt           *model.SingBoxRuntime
		prevRestarts int
		hadPrev      bool
		want         string
	}{
		{"no probe at all", nil, 0, false, "unknown"},
		{"empty probe stamp", &model.SingBoxRuntime{}, 0, false, "unknown"},
		{"running clean", &model.SingBoxRuntime{Running: true, ActiveState: "active", SubState: "running", ProbedAt: probed}, 0, true, "running"},
		{"crash loop caught by counter", &model.SingBoxRuntime{Running: true, ActiveState: "active", SubState: "running", RestartCount: 221347, ProbedAt: probed}, 221340, true, "restarting"},
		{"first report never restarting by counter", &model.SingBoxRuntime{Running: true, RestartCount: 5, ProbedAt: probed}, 0, false, "running"},
		{"auto-restart substate", &model.SingBoxRuntime{Running: false, ActiveState: "activating", SubState: "auto-restart", ProbedAt: probed}, 0, true, "restarting"},
		{"unit failed, no process", &model.SingBoxRuntime{Running: false, ActiveState: "failed", SubState: "failed", ProbedAt: probed}, 0, true, "down"},
		{"no unit info, no process", &model.SingBoxRuntime{Running: false, ProbedAt: probed}, 0, true, "down"},
		{"unit active but no trusted process is a contradiction", &model.SingBoxRuntime{Running: false, ActiveState: "active", SubState: "running", ProbedAt: probed}, 0, true, "unknown"},
	}
	for _, tc := range cases {
		if got := deriveSingBoxServiceState(tc.rt, tc.prevRestarts, tc.hadPrev); got != tc.want {
			t.Fatalf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

func TestRefineLineServiceState(t *testing.T) {
	yes, no := true, false
	if got := refineLineServiceState("running", &no); got != "down" {
		t.Fatalf("running service without this port must be down for the line, got %q", got)
	}
	if got := refineLineServiceState("running", &yes); got != "running" {
		t.Fatalf("bound port must stay running, got %q", got)
	}
	if got := refineLineServiceState("running", nil); got != "running" {
		t.Fatalf("unknown port evidence must not downgrade, got %q", got)
	}
	if got := refineLineServiceState("down", &yes); got != "down" {
		t.Fatalf("a down node stays down whatever old port facts say, got %q", got)
	}
}

// TestNoteSingBoxLivenessDebounce walks the incident timeline: a service goes
// down, the notification fires exactly once after the hold, flapping through
// unknown does not reset the episode, and recovery clears it.
func TestNoteSingBoxLivenessDebounce(t *testing.T) {
	s, st := newShareTestServer(t)
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	at := base
	s.now = func() time.Time { return at }

	probe := func(running bool, active string) *model.SingBoxRuntime {
		return &model.SingBoxRuntime{Running: running, ActiveState: active, ProbedAt: at}
	}

	// Healthy baseline.
	s.noteSingBoxLiveness("node-x", probe(true, "active"))
	rec, ok := st.SingBoxLivenessRecord("node-x")
	if !ok || rec.State != "running" || !rec.ProblemSince.IsZero() {
		t.Fatalf("baseline wrong: %+v", rec)
	}

	// Goes down: recorded immediately, not yet notified (hold).
	at = base.Add(10 * time.Second)
	s.noteSingBoxLiveness("node-x", probe(false, "failed"))
	rec, _ = st.SingBoxLivenessRecord("node-x")
	if rec.State != "down" || rec.ProblemSince != at || !rec.NotifiedDownAt.IsZero() {
		t.Fatalf("fresh down wrong: %+v", rec)
	}

	// Still down within the hold: still silent.
	at = base.Add(40 * time.Second)
	s.noteSingBoxLiveness("node-x", probe(false, "failed"))
	if rec, _ = st.SingBoxLivenessRecord("node-x"); !rec.NotifiedDownAt.IsZero() {
		t.Fatalf("notified inside the hold: %+v", rec)
	}

	// Past the hold: notified exactly once.
	at = base.Add(2 * time.Minute)
	s.noteSingBoxLiveness("node-x", probe(false, "failed"))
	rec, _ = st.SingBoxLivenessRecord("node-x")
	firstNotified := rec.NotifiedDownAt
	if firstNotified.IsZero() {
		t.Fatalf("hold elapsed but not notified: %+v", rec)
	}
	at = base.Add(3 * time.Minute)
	s.noteSingBoxLiveness("node-x", probe(false, "failed"))
	if rec, _ = st.SingBoxLivenessRecord("node-x"); rec.NotifiedDownAt != firstNotified {
		t.Fatalf("second notification for one episode: %+v", rec)
	}

	// A probe outage mid-incident must not reset the episode.
	at = base.Add(4 * time.Minute)
	s.noteSingBoxLiveness("node-x", &model.SingBoxRuntime{})
	rec, _ = st.SingBoxLivenessRecord("node-x")
	if rec.State != "unknown" || rec.ProblemSince.IsZero() || rec.NotifiedDownAt != firstNotified {
		t.Fatalf("unknown flap reset the episode: %+v", rec)
	}

	// Recovery clears the episode.
	at = base.Add(5 * time.Minute)
	s.noteSingBoxLiveness("node-x", probe(true, "active"))
	rec, _ = st.SingBoxLivenessRecord("node-x")
	if rec.State != "running" || !rec.ProblemSince.IsZero() || !rec.NotifiedDownAt.IsZero() {
		t.Fatalf("recovery did not clear the episode: %+v", rec)
	}

	// The transitions left an audit trail.
	transitions := 0
	for _, ev := range st.AuditEvents() {
		if ev.Action == "singbox.service.state" && ev.NodeID == "node-x" {
			transitions++
		}
	}
	if transitions < 3 {
		t.Fatalf("expected audited transitions, got %d", transitions)
	}

	// An agent without the probe never overwrites the record.
	s.noteSingBoxLiveness("node-x", nil)
	if rec2, _ := st.SingBoxLivenessRecord("node-x"); rec2.ReceivedAt != rec.ReceivedAt {
		t.Fatalf("nil runtime overwrote the record")
	}
}
