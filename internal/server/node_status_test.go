package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Every boundary of the precedence table in node_status.go, against the pure
// derivation. now is fixed so the threshold arithmetic is exact.
func TestDeriveNodeStatusPrecedenceAndBoundaries(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	enrolled := now.Add(-100 * time.Hour)
	cameUp := now.Add(-3 * time.Hour)
	fresh := now.Add(-5 * time.Second)
	problem := degradation{since: now.Add(-20 * time.Minute), reason: "sing-box has been down since X"}

	for _, tc := range []struct {
		name      string
		node      model.Node
		problems  []degradation
		want      string
		wantSince time.Time
		reasonHas string
	}{
		{
			name: "disabled outranks a live agent",
			node: model.Node{Disabled: true, DisabledAt: cameUp, Online: true, LastSeen: fresh, OnlineSince: cameUp},
			want: NodeStatusDisabled, wantSince: cameUp, reasonHas: "Disabled by an operator at",
		},
		{
			name: "disabled outranks never reported",
			node: model.Node{Disabled: true, CreatedAt: enrolled},
			want: NodeStatusDisabled, wantSince: time.Time{}, reasonHas: "Disabled by an operator;",
		},
		{
			name: "never reported measures from enrollment",
			node: model.Node{CreatedAt: enrolled},
			want: NodeStatusNeverReported, wantSince: enrolled, reasonHas: "since enrollment at",
		},
		{
			name: "online without a contact time is still never reported",
			node: model.Node{Online: true, CreatedAt: enrolled},
			want: NodeStatusNeverReported, wantSince: enrolled,
		},
		{
			name: "went quiet and the sweep flipped it",
			node: model.Node{LastSeen: now.Add(-2 * time.Hour), CreatedAt: enrolled},
			want: NodeStatusOffline, wantSince: now.Add(-2 * time.Hour), reasonHas: "No report since",
		},
		{
			name: "a beat exactly at the threshold is still online",
			node: model.Node{Online: true, LastSeen: now.Add(-nodeOfflineThreshold), OnlineSince: cameUp, CreatedAt: enrolled},
			want: NodeStatusOnline, wantSince: cameUp,
		},
		{
			name: "one nanosecond past the threshold is offline before the sweep runs",
			node: model.Node{Online: true, LastSeen: now.Add(-nodeOfflineThreshold - time.Nanosecond), OnlineSince: cameUp, CreatedAt: enrolled},
			want: NodeStatusOffline, wantSince: now.Add(-nodeOfflineThreshold - time.Nanosecond),
		},
		{
			name:     "a proven problem on a live agent is degraded from the problem start",
			node:     model.Node{Online: true, LastSeen: fresh, OnlineSince: cameUp, CreatedAt: enrolled},
			problems: []degradation{problem},
			want:     NodeStatusDegraded, wantSince: problem.since, reasonHas: "Reporting, but sing-box has been down",
		},
		{
			name:     "a problem does not rescue a node that went quiet",
			node:     model.Node{LastSeen: now.Add(-time.Hour), CreatedAt: enrolled},
			problems: []degradation{problem},
			want:     NodeStatusOffline, wantSince: now.Add(-time.Hour),
		},
		{
			name: "online since the first beat of this run",
			node: model.Node{Online: true, LastSeen: fresh, OnlineSince: cameUp, CreatedAt: enrolled},
			want: NodeStatusOnline, wantSince: cameUp, reasonHas: "Reporting; last report at",
		},
		{
			name: "online with no recorded start omits since rather than inventing one",
			node: model.Node{Online: true, LastSeen: fresh, CreatedAt: enrolled},
			want: NodeStatusOnline, wantSince: time.Time{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveNodeStatus(tc.node, now, tc.problems)
			if got.Status != tc.want {
				t.Fatalf("status = %q, want %q (reason %q)", got.Status, tc.want, got.Reason)
			}
			if !got.Since.Equal(tc.wantSince) {
				t.Fatalf("since = %s, want %s", got.Since, tc.wantSince)
			}
			if tc.reasonHas != "" && !strings.Contains(got.Reason, tc.reasonHas) {
				t.Fatalf("reason %q does not say %q", got.Reason, tc.reasonHas)
			}
			if got.Reason == "" || !strings.HasSuffix(got.Reason, ".") {
				t.Fatalf("reason must be one sentence, got %q", got.Reason)
			}
		})
	}
}

// The five words are the whole vocabulary; a refactor that maps two states to
// one value passes every case above individually and fails here.
func TestNodeStatusValuesAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, v := range []string{NodeStatusNeverReported, NodeStatusOnline, NodeStatusDegraded, NodeStatusOffline, NodeStatusDisabled} {
		if v == "" || seen[v] {
			t.Fatalf("status value %q is empty or repeated", v)
		}
		seen[v] = true
	}
}

func TestSingBoxDegradationNeedsAProvenCurrentProblem(t *testing.T) {
	beat := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	node := model.Node{Online: true, LastSeen: beat}
	rec := func(state string, receivedAgo time.Duration) store.SingBoxLiveness {
		return store.SingBoxLiveness{
			State:        state,
			StateSince:   beat.Add(-time.Hour),
			ProblemSince: beat.Add(-50 * time.Minute),
			ReceivedAt:   beat.Add(-receivedAgo),
			Runtime:      model.SingBoxRuntime{ActiveState: "failed", SubState: "failed", RestartCount: 3},
		}
	}

	if d, ok := singBoxDegradation(rec(serviceStateDown, 5*time.Second), node); !ok || !d.since.Equal(beat.Add(-50*time.Minute)) || !strings.Contains(d.reason, "down since") {
		t.Fatalf("a fresh down record must degrade from ProblemSince, got ok=%v %+v", ok, d)
	}
	if _, ok := singBoxDegradation(rec(serviceStateRestarting, 5*time.Second), node); !ok {
		t.Fatal("a crash loop is a problem")
	}
	if _, ok := singBoxDegradation(rec(serviceStateRunning, 5*time.Second), node); ok {
		t.Fatal("a running service is not a problem")
	}
	// Unknown is the honest answer when the probe cannot prove anything; it
	// must never colour the node amber.
	if _, ok := singBoxDegradation(rec(serviceStateUnknown, 5*time.Second), node); ok {
		t.Fatal("unknown degraded the node")
	}
	// The agent keeps beating but stopped sending the probe: the old record is
	// not evidence about now.
	if _, ok := singBoxDegradation(rec(serviceStateDown, nodeStatusEvidenceStaleAfter+time.Second), node); ok {
		t.Fatal("a record older than the node's beat by more than the window still counted")
	}
	if _, ok := singBoxDegradation(rec(serviceStateDown, nodeStatusEvidenceStaleAfter), node); !ok {
		t.Fatal("a record exactly at the window must still count")
	}
	// A down record with no ProblemSince (first probe of an incident) still
	// dates from the state change rather than from nothing.
	r := rec(serviceStateDown, time.Second)
	r.ProblemSince = time.Time{}
	if d, ok := singBoxDegradation(r, node); !ok || !d.since.Equal(r.StateSince) {
		t.Fatalf("since should fall back to StateSince, got ok=%v since=%s", ok, d.since)
	}
}

func TestGuardRealityDegradationOnlyWhenStale(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	snap := func(collectedAgo time.Duration) store.GuardRealitySnapshot {
		return store.GuardRealitySnapshot{Reality: model.GuardNodeReality{CollectedAt: now.Add(-collectedAgo)}, ReceivedAt: now.Add(-collectedAgo)}
	}
	if _, ok := guardRealityDegradation(snap(time.Hour), now); ok {
		t.Fatal("a fresh snapshot degraded the node")
	}
	if _, ok := guardRealityDegradation(snap(guardRealityStaleAfter-time.Second), now); ok {
		t.Fatal("a snapshot one second short of stale degraded the node")
	}
	// The boundary itself is stale: guardRealityFreshness compares with
	// !now.Before(staleAfter), so exactly 30h old already counts.
	boundary, ok := guardRealityDegradation(snap(guardRealityStaleAfter), now)
	if !ok {
		t.Fatalf("a snapshot exactly %s old must be stale", guardRealityStaleAfter)
	}
	if !boundary.since.Equal(now) {
		t.Fatalf("since = %s, want the stale-after instant %s", boundary.since, now)
	}
	d, ok := guardRealityDegradation(snap(guardRealityStaleAfter+time.Hour), now)
	if !ok {
		t.Fatal("a stale snapshot must degrade the node")
	}
	// The state began the moment the snapshot crossed the stale line, not when
	// this request happened to look.
	if want := now.Add(-time.Hour); !d.since.Equal(want) {
		t.Fatalf("since = %s, want the stale-after instant %s", d.since, want)
	}
	if !strings.Contains(d.reason, "older than 30h0m0s") {
		t.Fatalf("reason does not name the window: %q", d.reason)
	}
}

// The real view, the real store, the real wire: one status word per node,
// since omitted when unknown, the sing-box record folded in, and the map's
// geo view saying the same word as the nodes list.
func TestNodeViewsCarryOneStatusOnTheWire(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass})
	if err != nil {
		t.Fatal(err)
	}
	now := srv.now().UTC()
	nodes := map[string]model.Node{
		"never":    {ID: "never", Name: "never", CreatedAt: now.Add(-48 * time.Hour)},
		"online":   {ID: "online", Name: "online", Online: true, LastSeen: now.Add(-3 * time.Second), OnlineSince: now.Add(-time.Hour), CreatedAt: now.Add(-48 * time.Hour)},
		"legacy":   {ID: "legacy", Name: "legacy", Online: true, LastSeen: now.Add(-3 * time.Second), CreatedAt: now.Add(-48 * time.Hour)},
		"offline":  {ID: "offline", Name: "offline", LastSeen: now.Add(-6 * 24 * time.Hour), CreatedAt: now.Add(-48 * time.Hour)},
		"degraded": {ID: "degraded", Name: "degraded", Online: true, LastSeen: now.Add(-3 * time.Second), OnlineSince: now.Add(-time.Hour), CreatedAt: now.Add(-48 * time.Hour)},
		"disabled": {ID: "disabled", Name: "disabled", Disabled: true, DisabledAt: now.Add(-time.Hour), Online: true, LastSeen: now.Add(-3 * time.Second), CreatedAt: now.Add(-48 * time.Hour)},
	}
	for _, n := range nodes {
		if err := st.UpsertNode(n); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := st.UpsertSingBoxLiveness(store.SingBoxLiveness{
		NodeID: "degraded", State: serviceStateDown, StateSince: now.Add(-30 * time.Minute), ProblemSince: now.Add(-30 * time.Minute), ReceivedAt: now.Add(-3 * time.Second),
		Runtime: model.SingBoxRuntime{ActiveState: "failed", SubState: "failed", RestartCount: 7},
	}); err != nil {
		t.Fatal(err)
	}

	type wire struct {
		Online       bool   `json:"online"`
		Reachability string `json:"reachability"`
		Status       string `json:"status"`
		StatusSince  string `json:"status_since"`
		StatusReason string `json:"status_reason"`
	}
	decode := func(v any) wire {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var w wire
		if err := json.Unmarshal(raw, &w); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), `"status_reason"`) {
			t.Fatalf("status_reason missing from the wire: %s", raw)
		}
		return w
	}

	want := map[string]struct {
		status    string
		hasSince  bool
		reachable string
		online    bool
	}{
		"never":    {NodeStatusNeverReported, true, ReachabilityNever, false},
		"online":   {NodeStatusOnline, true, ReachabilityOnline, true},
		"legacy":   {NodeStatusOnline, false, ReachabilityOnline, true},
		"offline":  {NodeStatusOffline, true, ReachabilityOffline, false},
		"degraded": {NodeStatusDegraded, true, ReachabilityOnline, true},
		"disabled": {NodeStatusDisabled, true, ReachabilityOnline, true},
	}
	for id, w := range want {
		node, ok := st.Node(id)
		if !ok {
			t.Fatalf("node %s vanished", id)
		}
		got := decode(srv.toNodeView(node))
		if got.Status != w.status {
			t.Fatalf("%s: status = %q, want %q (%s)", id, got.Status, w.status, got.StatusReason)
		}
		if (got.StatusSince != "") != w.hasSince {
			t.Fatalf("%s: status_since present=%v, want %v (%q)", id, got.StatusSince != "", w.hasSince, got.StatusSince)
		}
		if got.StatusSince != "" && strings.HasPrefix(got.StatusSince, "0001-") {
			t.Fatalf("%s: status_since is the zero time on the wire", id)
		}
		// The old fields keep their meaning for consumers that read them.
		if got.Reachability != w.reachable || got.Online != w.online {
			t.Fatalf("%s: reachability/online = %q/%v, want %q/%v", id, got.Reachability, got.Online, w.reachable, w.online)
		}
		// The map reads the same word.
		if geo := decode(srv.toNodeGeoView(node)); geo.Status != got.Status || geo.StatusReason != got.StatusReason {
			t.Fatalf("%s: geo view says %q, nodes view says %q", id, geo.Status, got.Status)
		}
	}
	if got := decode(srv.toNodeView(mustNode(t, st, "degraded"))); !strings.Contains(got.StatusReason, "7 restarts") {
		t.Fatalf("degraded reason does not carry the evidence: %q", got.StatusReason)
	}
}

func mustNode(t *testing.T, st *store.Store, id string) model.Node {
	t.Helper()
	n, ok := st.Node(id)
	if !ok {
		t.Fatalf("node %s not found", id)
	}
	return n
}
