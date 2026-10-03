package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The derivation reads every instant against the beat's own collected_at,
// so the same payload means the same thing whatever this server's clock says.
func TestAgentLoopProblemsReadTheAgentsClock(t *testing.T) {
	agent := time.Date(2026, 10, 3, 1, 0, 0, 0, time.UTC) // the agent's clock at the beat
	server := agent.Add(3 * time.Hour)                    // this server's clock at the beat
	rec := func(h model.AgentHealth) agentHealthRecord {
		if h.StartedAt.IsZero() {
			h.StartedAt = agent.Add(-time.Hour)
		}
		return agentHealthRecord{health: h, collectedAt: agent, receivedAt: server}
	}
	type want struct {
		kind              string
		status, incident  bool
		reasonContains    string
		sinceBeforeServer time.Duration
	}
	cases := []struct {
		name  string
		rec   agentHealthRecord
		after time.Duration // server time after the beat
		want  []want
	}{
		{"a moving loop", rec(model.AgentHealth{CycleCompletedAt: agent.Add(-5 * time.Second)}), 0, nil},
		{"late but not stalled", rec(model.AgentHealth{CycleCompletedAt: agent.Add(-2 * time.Minute)}), 0,
			[]want{{kind: agentProblemStalled, status: true, reasonContains: "2 min", sinceBeforeServer: 2 * time.Minute}}},
		{"stalled in a step", rec(model.AgentHealth{CycleCompletedAt: agent.Add(-4 * time.Minute), Step: "usage", StepSince: agent.Add(-3 * time.Minute)}), time.Minute,
			[]want{{kind: agentProblemStalled, status: true, incident: true, reasonContains: "in step usage for 4 min", sinceBeforeServer: 4 * time.Minute}}},
		{"no first cycle", rec(model.AgentHealth{StartedAt: agent.Add(-6 * time.Minute)}), 0,
			[]want{{kind: agentProblemStalled, status: true, incident: true, sinceBeforeServer: 6 * time.Minute}}},
		{"linechain blocked briefly", rec(model.AgentHealth{LinechainBlocked: "journal 3 unreadable", LinechainBlockedSince: agent.Add(-30 * time.Second), CycleCompletedAt: agent.Add(-10 * time.Minute)}), 0,
			[]want{{kind: agentProblemLinechainBlocked, reasonContains: "journal 3 unreadable", sinceBeforeServer: 30 * time.Second}}},
		{"linechain blocked for long", rec(model.AgentHealth{LinechainBlocked: "journal 3 unreadable", LinechainBlockedSince: agent.Add(-6 * time.Minute)}), 0,
			[]want{{kind: agentProblemLinechainBlocked, status: true, incident: true, sinceBeforeServer: 6 * time.Minute}}},
		{"a core step stale", rec(model.AgentHealth{CycleCompletedAt: agent, Steps: map[string]model.AgentLoopStep{
			model.AgentStepConfig: {LastOKAt: agent.Add(-20 * time.Minute), ConsecutiveErrors: 40, LastError: "502"},
			model.AgentStepUsage:  {ConsecutiveErrors: 400, LastError: "no collector"},
		}}), 0,
			[]want{{kind: agentProblemStepStale, status: true, incident: true, reasonContains: "step config has failed 40 times in a row and last succeeded 20 min ago (502)", sinceBeforeServer: 20 * time.Minute}}},
		{"a core step failing but recent", rec(model.AgentHealth{CycleCompletedAt: agent, Steps: map[string]model.AgentLoopStep{
			model.AgentStepTasks: {LastOKAt: agent.Add(-5 * time.Minute), ConsecutiveErrors: 30},
		}}), 0, nil},
	}
	for _, tc := range cases {
		got := agentLoopProblems(tc.rec, server.Add(tc.after))
		if len(got) != len(tc.want) {
			t.Errorf("%s: %d problems %+v, want %d", tc.name, len(got), got, len(tc.want))
			continue
		}
		for i, w := range tc.want {
			p := got[i]
			if p.kind != w.kind || p.status != w.status || p.incident != w.incident || !strings.Contains(p.reason, w.reasonContains) || !p.since.Equal(server.Add(-w.sinceBeforeServer)) {
				t.Errorf("%s: problem %d = %+v, want %+v", tc.name, i, p, w)
			}
		}
	}

	dropped := rec(model.AgentHealth{CycleCompletedAt: agent, MonitorResultsDropped: 7})
	dropped.droppedRoseAt = server
	if got := agentLoopProblems(dropped, server.Add(time.Minute)); len(got) != 1 || got[0].kind != agentProblemResultsDropped || !got[0].status || got[0].incident {
		t.Errorf("recent drops = %+v", got)
	}
	for _, p := range agentLoopProblems(dropped, server.Add(agentDropsRecentWithin)) {
		if p.kind == agentProblemResultsDropped {
			t.Errorf("drops a quarter hour old still degrade: %+v", p)
		}
	}
}

// The dropped count degrades only while it is rising: a beat that repeats the
// same count keeps the instant it last rose, and a new agent process that
// reports zero clears it.
func TestDroppedMonitorResultsDegradeOnlyWhileRising(t *testing.T) {
	srv, _, _ := newInventoryServer(t)
	clock := &testClock{at: time.Date(2026, 10, 3, 1, 0, 0, 0, time.UTC)}
	srv.now = clock.now
	started := clock.now().Add(-time.Hour)
	beatWith := func(dropped uint64, startedAt time.Time) agentHealthRecord {
		srv.noteAgentHealth("n1", &model.AgentHealth{StartedAt: startedAt, CycleCompletedAt: clock.now(), MonitorResultsDropped: dropped}, clock.now())
		rec, _ := srv.agentHealthRecord("n1")
		return rec
	}
	if rec := beatWith(3, started); !rec.droppedRoseAt.Equal(clock.now()) {
		t.Fatalf("first sight of drops: %+v", rec)
	}
	rose := clock.now()
	clock.advance(time.Minute)
	if rec := beatWith(3, started); !rec.droppedRoseAt.Equal(rose) {
		t.Fatalf("an unchanged count moved the instant: %+v", rec)
	}
	clock.advance(time.Minute)
	if rec := beatWith(5, started); !rec.droppedRoseAt.Equal(clock.now()) {
		t.Fatalf("a rising count: %+v", rec)
	}
	clock.advance(time.Minute)
	if rec := beatWith(0, clock.now()); !rec.droppedRoseAt.IsZero() {
		t.Fatalf("a restarted agent with no drops: %+v", rec)
	}
}

func metricsBeat(t *testing.T, handler http.Handler, nodeID, token string, collectedAt time.Time, health string) {
	t.Helper()
	body := fmt.Sprintf(`{"node_id":%q,"version":"0.3.10-alpha.1","metrics":{"collected_at":%q},"loop_health":%s}`, nodeID, collectedAt.Format(time.RFC3339Nano), health)
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/metrics", body, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics: %d %s", rec.Code, rec.Body.String())
	}
}

func nodeViewOf(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, nodeID string) nodeView {
	t.Helper()
	res := doJSON(t, handler, http.MethodGet, "/api/nodes", "", cookies, csrf)
	defer res.Body.Close()
	var views []nodeView
	if err := json.NewDecoder(res.Body).Decode(&views); err != nil {
		t.Fatal(err)
	}
	for _, v := range views {
		if v.ID == nodeID {
			return v
		}
	}
	t.Fatalf("node %s not listed", nodeID)
	return nodeView{}
}

// stalledLoopHealth is a payload whose loop has not completed a cycle for 7
// minutes by the agent's own clock, stuck in inventory, with a failing usage
// step and recent monitor result drops.
func stalledLoopHealth(agentNow time.Time) string {
	return fmt.Sprintf(`{"started_at":%q,"cycle_completed_at":%q,"step":"inventory","step_since":%q,
		"steps":{"config":{"last_ok_at":%q},"usage":{"consecutive_errors":9,"last_error":"502"}},"monitor_results_dropped":4}`,
		agentNow.Add(-time.Hour).Format(time.RFC3339), agentNow.Add(-7*time.Minute).Format(time.RFC3339),
		agentNow.Add(-6*time.Minute).Format(time.RFC3339), agentNow.Add(-7*time.Minute).Format(time.RFC3339))
}

// Loop health from the metrics beat is read against the agent's own clock: a
// loop with no cycle for 7 minutes degrades the node even when the agent's
// clock is an hour behind, the node view carries the payload and what was
// derived, a non-core step degrades nothing, and the record never reaches
// state.json or state-hot.db. An agent that sends no loop health (before
// 0.3.10) is unaffected.
func TestAgentLoopHealthDegradesNodeStatus(t *testing.T) {
	dir := t.TempDir()
	f := openNotifyFixture(t, dir)
	// Beats stamp LastSeen with the wall clock, so this server's clock is the
	// wall clock too; the agent's runs an hour behind.
	clock := &testClock{at: time.Now().UTC()}
	f.srv.now = clock.now
	cookies, csrf := loginSession(t, f.handler)
	token := enrollNamedNodeToken(t, f.handler, cookies, csrf, "n-loop", "loop")
	oldToken := enrollNamedNodeToken(t, f.handler, cookies, csrf, "n-old", "old")
	agentNow := clock.now().Add(-time.Hour)
	metricsBeat(t, f.handler, "n-loop", token, agentNow, stalledLoopHealth(agentNow))
	rec := doAgentRaw(t, f.handler, http.MethodPost, "/api/agent/metrics", `{"node_id":"n-old","version":"0.3.9","metrics":{}}`, oldToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("old agent metrics: %d", rec.Code)
	}

	v := nodeViewOf(t, f.handler, cookies, csrf, "n-loop")
	if v.Status != NodeStatusDegraded || !strings.Contains(v.StatusReason, "in step inventory") || !strings.Contains(v.StatusReason, "dropped 4 monitor results") {
		t.Fatalf("status = %s %q", v.Status, v.StatusReason)
	}
	if strings.Contains(v.StatusReason, "usage") {
		t.Fatalf("a non-core step degraded the node: %q", v.StatusReason)
	}
	lh := v.LoopHealth
	if lh == nil || lh.Steps["usage"].ConsecutiveErrors != 9 || !lh.CollectedAt.Equal(agentNow) || len(lh.Problems) != 2 || !lh.Problems[0].Pages {
		t.Fatalf("loop health view = %+v", lh)
	}
	if old := nodeViewOf(t, f.handler, cookies, csrf, "n-old"); old.Status != NodeStatusOnline || old.LoopHealth != nil {
		t.Fatalf("an agent without loop health = %s %+v", old.Status, old.LoopHealth)
	}

	moving := fmt.Sprintf(`{"started_at":%q,"cycle_completed_at":%q,"monitor_results_dropped":4}`, agentNow.Add(-time.Hour).Format(time.RFC3339), agentNow.Add(10*time.Second).Format(time.RFC3339))
	metricsBeat(t, f.handler, "n-loop", token, agentNow.Add(12*time.Second), moving)
	clock.advance(15 * time.Second)
	if v := nodeViewOf(t, f.handler, cookies, csrf, "n-loop"); v.Status != NodeStatusDegraded || strings.Contains(v.StatusReason, "work loop") {
		// The drop count is still recent, so the node stays degraded for it
		// alone; the stall is gone.
		t.Fatalf("after a moving beat = %s %q", v.Status, v.StatusReason)
	}
	for _, name := range []string{"state.json", "state-hot.db"} {
		data, err := os.ReadFile(filepath.Join(f.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "cycle_completed_at") {
			t.Fatalf("%s carries loop health", name)
		}
	}
}
