package store

import (
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestMarkStaleNodesOffline(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	seed := func(id string, online bool, lastSeen time.Time) {
		if err := s.UpsertNode(model.Node{ID: id, Name: id, Online: online, LastSeen: lastSeen}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	seed("fresh", true, now.Add(-5*time.Second)) // recent beat -> stays online
	seed("stale", true, now.Add(-5*time.Minute)) // stale beat -> flips offline
	seed("never", false, time.Time{})            // never online -> untouched
	seed("down", false, now.Add(-9*time.Minute)) // already offline -> not a transition

	flipped, err := s.MarkStaleNodesOffline(90*time.Second, now)
	if err != nil {
		t.Fatalf("MarkStaleNodesOffline: %v", err)
	}
	if len(flipped) != 1 || flipped[0].ID != "stale" {
		t.Fatalf("expected only 'stale' to transition, got %+v", flipped)
	}

	want := map[string]bool{"fresh": true, "stale": false, "never": false, "down": false}
	for id, online := range want {
		n, ok := s.Node(id)
		if !ok {
			t.Fatalf("node %s missing", id)
		}
		if n.Online != online {
			t.Fatalf("node %s online=%v, want %v", id, n.Online, online)
		}
	}

	// Idempotent: a second sweep at the same instant flips nothing new.
	flipped2, err := s.MarkStaleNodesOffline(90*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(flipped2) != 0 {
		t.Fatalf("second sweep should be a no-op, got %+v", flipped2)
	}
}
