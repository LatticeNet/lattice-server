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

// heartbeatClock is the store's heartbeat clock in these tests.
type heartbeatClock struct{ at time.Time }

func (c *heartbeatClock) now() time.Time { return c.at }

// heartbeatFleet is a disk-backed store holding online nodes, every one
// written at t0, with the heartbeat clock under the test's control.
type heartbeatFleet struct {
	s     *Store
	path  string
	ids   []string
	t0    time.Time
	clock *heartbeatClock
}

func openHeartbeatFleet(t *testing.T, ids []string) heartbeatFleet {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 3, 20, 0, 0, 0, time.UTC)
	clock := &heartbeatClock{at: t0}
	s.testNow = clock.now
	for _, nodeID := range ids {
		if err := s.UpsertNode(model.Node{ID: nodeID, Name: nodeID, Online: true, LastSeen: t0, AgentVersion: "0.3.9"}); err != nil {
			t.Fatal(err)
		}
	}
	return heartbeatFleet{s: s, path: path, ids: ids, t0: t0, clock: clock}
}

func fleetIDs(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("node-%02d", i)
	}
	return ids
}

// beat sends one heartbeat from each node that changes nothing durable.
func beat(t *testing.T, s *Store, ids ...string) {
	t.Helper()
	for _, nodeID := range ids {
		if _, err := s.UpdateMetrics(nodeID, model.Metrics{CPUPercent: 7}, "0.3.9", "", "", "", "", "", model.HostFacts{}); err != nil {
			t.Fatal(err)
		}
	}
}

func reopen(t *testing.T, path string) *Store {
	t.Helper()
	s, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A quiet fleet beating every ten seconds writes once per
// metricsPersistenceInterval. Every node's clock used to be reset only by its
// own write, so every node forced a whole-state write each interval: 34 a
// round, although the first of them put every node's heartbeat on disk.
func TestQuietFleetHeartbeatsWriteOncePerInterval(t *testing.T) {
	f := openHeartbeatFleet(t, fleetIDs(heartbeatFleetSize))
	before := f.s.testPersistCalls
	for step := 1; step <= 96; step++ { // 16 minutes of beats
		f.clock.at = f.t0.Add(time.Duration(step) * 10 * time.Second)
		beat(t, f.s, f.ids...)
	}
	if calls := f.s.testPersistCalls - before; calls != 3 {
		t.Fatalf("16 minutes of quiet beats from %d nodes wrote the state file %d times, want 3 (one per %s)",
			len(f.ids), calls, metricsPersistenceInterval)
	}
}

// A heartbeat or a token use that did not write is carried by the next write
// made for any reason, so it survives a crash after that write.
func TestUnflushedHeartbeatAndTokenUseRideTheNextWrite(t *testing.T) {
	f := openHeartbeatFleet(t, fleetIDs(3))
	f.clock.at = f.t0.Add(time.Minute)
	before := f.s.testPersistCalls
	beat(t, f.s, f.ids...)
	use := f.clock.at
	if touched, err := f.s.TouchNodeToken(f.ids[1], use, 15*time.Minute); err != nil || !touched {
		t.Fatalf("token use: touched=%v err=%v", touched, err)
	}
	if calls := f.s.testPersistCalls - before; calls != 0 {
		t.Fatalf("beats and a token use inside the interval wrote %d times, want 0", calls)
	}
	if err := f.s.UpsertNode(model.Node{ID: "node-new", Name: "new"}); err != nil {
		t.Fatal(err)
	}
	crashed := reopen(t, f.path)
	for _, nodeID := range f.ids {
		if n, _ := crashed.Node(nodeID); !n.LastSeen.Equal(use) {
			t.Fatalf("%s last seen on disk = %s, want the beat at %s", nodeID, n.LastSeen, use)
		}
	}
	if n, _ := crashed.Node(f.ids[1]); !n.TokenLastUsedAt.Equal(use) {
		t.Fatalf("token last used on disk = %s, want %s", n.TokenLastUsedAt, use)
	}
}

// A heartbeat that changes something durable is still written on the beat
// that reports it, whatever the fleet clock says.
func TestDurableHeartbeatChangeWritesImmediately(t *testing.T) {
	f := openHeartbeatFleet(t, fleetIDs(4))
	f.clock.at = f.t0.Add(10 * time.Second)
	before := f.s.testPersistCalls
	if _, err := f.s.UpdateMetrics(f.ids[3], model.Metrics{}, "0.3.10", "", "", "", "", "", model.HostFacts{}); err != nil {
		t.Fatal(err)
	}
	if calls := f.s.testPersistCalls - before; calls != 1 {
		t.Fatalf("an agent version change wrote %d times, want 1", calls)
	}
}
