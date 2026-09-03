package store

import (
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// OnlineSince marks the first beat of a run and survives the beats after it;
// a node that goes quiet and comes back starts a new run. This is what lets
// the console print "online since" instead of only "online".
func TestUpdateMetricsStampsOnlineSinceOncePerRun(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNode(model.Node{ID: "n1", Name: "n1"}); err != nil {
		t.Fatal(err)
	}
	beat := func() model.Node {
		if err := s.UpdateMetrics("n1", model.Metrics{}, "", "", "", "", "", "", model.HostFacts{}); err != nil {
			t.Fatal(err)
		}
		n, _ := s.Node("n1")
		return n
	}

	first := beat()
	if first.OnlineSince.IsZero() || !first.OnlineSince.Equal(first.LastSeen) {
		t.Fatalf("first beat must stamp OnlineSince = LastSeen, got %s / %s", first.OnlineSince, first.LastSeen)
	}
	time.Sleep(2 * time.Millisecond)
	second := beat()
	if !second.OnlineSince.Equal(first.OnlineSince) {
		t.Fatalf("a later beat moved OnlineSince from %s to %s", first.OnlineSince, second.OnlineSince)
	}
	if !second.LastSeen.After(first.LastSeen) {
		t.Fatal("LastSeen did not advance")
	}

	// Silence, then recovery: a new run.
	if _, err := s.MarkStaleNodesOffline(0, second.LastSeen.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Node("n1"); n.Online {
		t.Fatal("sweep did not flip the node offline")
	}
	third := beat()
	if !third.OnlineSince.After(first.OnlineSince) {
		t.Fatalf("recovery must start a new run, OnlineSince stayed %s", third.OnlineSince)
	}
}

func TestSetNodeDisabledStampsAndClearsDisabledAt(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNode(model.Node{ID: "n1", Name: "n1"}); err != nil {
		t.Fatal(err)
	}
	flip := func(disabled bool) model.Node {
		if _, err := s.SetNodeDisabled("n1", disabled); err != nil {
			t.Fatal(err)
		}
		n, _ := s.Node("n1")
		return n
	}
	off := flip(true)
	if off.DisabledAt.IsZero() {
		t.Fatal("disabling did not stamp DisabledAt")
	}
	time.Sleep(2 * time.Millisecond)
	// Disabling an already disabled node is not a new event.
	if again := flip(true); !again.DisabledAt.Equal(off.DisabledAt) {
		t.Fatalf("a repeated disable moved DisabledAt from %s to %s", off.DisabledAt, again.DisabledAt)
	}
	if on := flip(false); !on.DisabledAt.IsZero() || on.Disabled {
		t.Fatalf("enabling must clear DisabledAt, got %s disabled=%v", on.DisabledAt, on.Disabled)
	}
}
