package server

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestNodeReachabilitySeparatesNeverReportedFromWentQuiet(t *testing.T) {
	beat := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	enrolled := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name string
		node model.Node
		want string
	}{
		{"beating", model.Node{LastSeen: beat, Online: true, CreatedAt: enrolled}, ReachabilityOnline},
		{"reported before and went quiet", model.Node{LastSeen: beat, CreatedAt: enrolled}, ReachabilityOffline},
		{"enrolled, never reported", model.Node{CreatedAt: enrolled}, ReachabilityNever},
		{"online with no contact time is still never", model.Node{Online: true, CreatedAt: enrolled}, ReachabilityNever},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nodeReachability(tc.node); got != tc.want {
				t.Fatalf("reachability = %q, want %q", got, tc.want)
			}
		})
	}
}

// The whole point is that the two states are not the same value. A refactor
// that collapses them back into one passes every case above individually while
// failing this.
func TestNeverReportedAndOfflineAreDifferentValues(t *testing.T) {
	never := nodeReachability(model.Node{CreatedAt: time.Now().UTC()})
	quiet := nodeReachability(model.Node{LastSeen: time.Now().UTC().Add(-time.Hour)})
	if never == quiet {
		t.Fatalf("a node that never reported and one that went quiet both render as %q", never)
	}
}

func TestNodeSilenceMeasuresFromEnrollmentWhenNothingEverReported(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

	// Reported before: the silence runs from the last beat.
	d, ok := nodeSilence(model.Node{
		LastSeen:  now.Add(-2 * time.Hour),
		CreatedAt: now.Add(-100 * time.Hour),
	}, now)
	if !ok || d != 2*time.Hour {
		t.Fatalf("silence for a node that reported = %v (ok=%v), want 2h", d, ok)
	}

	// Never reported: the only instant available is enrollment, and it is the
	// one the operator is asking about.
	d, ok = nodeSilence(model.Node{CreatedAt: now.Add(-72 * time.Hour)}, now)
	if !ok || d != 72*time.Hour {
		t.Fatalf("silence for a node that never reported = %v (ok=%v), want 72h", d, ok)
	}

	// Nothing to measure from: say so rather than reporting a duration counted
	// from the zero time, which renders as decades.
	if _, ok := nodeSilence(model.Node{}, now); ok {
		t.Fatal("a node with neither a beat nor a creation time reported a silence")
	}
}

// Enrollment writes the node record with neither LastSeen nor Online set, so
// this state is reached by every node that has not beaten yet, not by a corner
// case. Pin it against the real view so the console cannot go back to calling
// a node that never came up "offline".
func TestFreshlyEnrolledNodeViewSaysNeverRatherThanOffline(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass})
	if err != nil {
		t.Fatal(err)
	}
	view := srv.toNodeView(model.Node{ID: "n1", Name: "just-enrolled", CreatedAt: time.Now().UTC()})
	if view.Reachability != ReachabilityNever {
		t.Fatalf("a node that has never beaten reports %q", view.Reachability)
	}
	if view.Online {
		t.Fatal("a node that has never beaten reports online")
	}

	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Online       bool   `json:"online"`
		Reachability string `json:"reachability"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Reachability != ReachabilityNever {
		t.Fatalf("reachability did not reach the wire: %q", wire.Reachability)
	}
	// The existing field keeps its meaning for consumers that have not moved.
	if wire.Online {
		t.Fatal("online changed meaning on the wire")
	}
}
