package store

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
)

const heartbeatFleetSize = 34

// openHeartbeatFleet opens a disk-backed store holding a fleet of online
// nodes, the shape production restarts into.
func openHeartbeatFleet(t *testing.T) (*Store, string, []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	seen := time.Now().UTC().Add(-time.Minute)
	ids := make([]string, heartbeatFleetSize)
	for i := range ids {
		ids[i] = fmt.Sprintf("node-%02d", i)
		if err := s.UpsertNode(model.Node{ID: ids[i], Name: ids[i], Online: true, LastSeen: seen, AgentVersion: "0.3.9"}); err != nil {
			t.Fatal(err)
		}
	}
	return s, path, ids
}

// beatFleet sends one heartbeat per node that changes nothing durable.
func beatFleet(t *testing.T, s *Store, ids []string) {
	t.Helper()
	for _, nodeID := range ids {
		if _, err := s.UpdateMetrics(nodeID, model.Metrics{CPUPercent: 7, CollectedAt: time.Now().UTC()}, "0.3.9", "", "", "", "", "", model.HostFacts{}); err != nil {
			t.Fatal(err)
		}
	}
}

// A restart seeds every node's heartbeat clock from the same write, so the
// fleet's clocks come due together. Each node used to force its own write
// when its clock ran out, 34 whole-state writes in one beat round and again
// every metricsPersistenceInterval, although the first of them already put
// every node's heartbeat on disk.
func TestQuietFleetHeartbeatsWriteOncePerInterval(t *testing.T) {
	s, path, ids := openHeartbeatFleet(t)
	stale := time.Now().UTC().Add(-metricsPersistenceInterval - time.Second)
	for _, nodeID := range ids {
		s.metricsPersistedAt[nodeID] = stale
	}

	before := s.testPersistCalls
	beatFleet(t, s, ids)
	if calls := s.testPersistCalls - before; calls != 1 {
		t.Fatalf("one round of due heartbeats from %d nodes wrote the state file %d times, want 1", len(ids), calls)
	}
	before = s.testPersistCalls
	beatFleet(t, s, ids)
	if calls := s.testPersistCalls - before; calls != 0 {
		t.Fatalf("a round of heartbeats inside the interval wrote %d times, want 0", calls)
	}

	want := make(map[string]time.Time, len(ids))
	for _, nodeID := range ids {
		n, _ := s.Node(nodeID)
		want[nodeID] = n.LastSeen
	}
	before = s.testPersistCalls
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if calls := s.testPersistCalls - before; calls != 1 {
		t.Fatalf("close with heartbeats only in memory wrote %d times, want 1", calls)
	}
	reopened, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	for _, nodeID := range ids {
		n, ok := reopened.Node(nodeID)
		if !ok || !n.LastSeen.Equal(want[nodeID]) {
			t.Fatalf("%s last seen after reopen = %v, want %v", nodeID, n.LastSeen, want[nodeID])
		}
	}
}

// A heartbeat that changes something durable is still written on the beat
// that reports it, whatever the fleet clock says.
func TestDurableHeartbeatChangeWritesImmediately(t *testing.T) {
	s, _, ids := openHeartbeatFleet(t)
	before := s.testPersistCalls
	if _, err := s.UpdateMetrics(ids[3], model.Metrics{CollectedAt: time.Now().UTC()}, "0.3.10", "", "", "", "", "", model.HostFacts{}); err != nil {
		t.Fatal(err)
	}
	if calls := s.testPersistCalls - before; calls != 1 {
		t.Fatalf("an agent version change wrote %d times, want 1", calls)
	}
}
