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

// What a crash leaves on disk is the fleet's heartbeats as the last write had
// them, at most metricsPersistenceInterval and a beat behind memory.
// NodeLastSeenSlack covers exactly that. A clean Close leaves nothing behind.
func TestCrashLeavesHeartbeatsAtMostOneIntervalStale(t *testing.T) {
	f := openHeartbeatFleet(t, fleetIDs(5))
	for step := 1; step <= 50; step++ { // 500 s: one write at 300 s, then 200 s of beats in memory only
		f.clock.at = f.t0.Add(time.Duration(step) * 10 * time.Second)
		beat(t, f.s, f.ids...)
	}
	crashed := reopen(t, f.path) // the first store is never closed
	worst := time.Duration(0)
	for _, nodeID := range f.ids {
		live, _ := f.s.Node(nodeID)
		disk, _ := crashed.Node(nodeID)
		if lag := live.LastSeen.Sub(disk.LastSeen); lag > worst {
			worst = lag
		}
	}
	if worst <= 0 || worst > NodeLastSeenDiskLag+10*time.Second {
		t.Fatalf("heartbeats on disk after a crash trail memory by %s, want more than zero and at most %s", worst, NodeLastSeenDiskLag+10*time.Second)
	}
	if slack := crashed.NodeLastSeenSlack(f.ids[0]); slack != NodeLastSeenDiskLag {
		t.Fatalf("slack before a beat after the crash = %s, want %s", slack, NodeLastSeenDiskLag)
	}
	crashed.testNow = f.clock.now
	beat(t, crashed, f.ids[0])
	if slack := crashed.NodeLastSeenSlack(f.ids[0]); slack != 0 {
		t.Fatalf("slack after the node beat in the new process = %s, want 0", slack)
	}

	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	clean := reopen(t, f.path)
	for _, nodeID := range f.ids {
		live, _ := f.s.Node(nodeID)
		disk, _ := clean.Node(nodeID)
		if !disk.LastSeen.Equal(live.LastSeen) {
			t.Fatalf("%s after a clean close: last seen %s on disk, %s in memory", nodeID, disk.LastSeen, live.LastSeen)
		}
	}
}

// After a crash the sweep that runs at start, before any agent can beat,
// must not mark a fleet that was beating offline because its heartbeats on
// disk are minutes old. A node that really stopped before the crash is
// still marked offline once its silence is past the threshold and the slack.
func TestBootSweepAfterACrashFlipsNoBeatingNode(t *testing.T) {
	live := []string{"node-a", "node-b", "node-c", "node-d"}
	f := openHeartbeatFleet(t, append(append([]string{}, live...), "node-late"))
	sweep := func(s *Store, at time.Time, cause string) []string {
		t.Helper()
		flipped, err := s.MarkStaleNodesOffline(90*time.Second, at, cause)
		if err != nil {
			t.Fatal(err)
		}
		ids := []string{}
		for _, n := range flipped {
			ids = append(ids, n.ID)
		}
		return ids
	}
	// The first process: every node beats every ten seconds and the sweep
	// runs every twenty, until node-late stops at t0+380s and the process
	// dies at t0+405s.
	for step := 1; step <= 40; step++ {
		f.clock.at = f.t0.Add(time.Duration(step) * 10 * time.Second)
		beat(t, f.s, live...)
		if f.clock.at.Sub(f.t0) <= 380*time.Second {
			beat(t, f.s, "node-late")
		}
		if step%2 == 0 {
			if got := sweep(f.s, f.clock.at, NodeStatusCauseLivenessSweep); len(got) != 0 {
				t.Fatalf("before the crash, at %s: flipped %v", f.clock.at.Sub(f.t0), got)
			}
		}
	}

	crashed := reopen(t, f.path)
	crashed.testNow = f.clock.now
	diskB, _ := crashed.Node("node-b")
	if lag := f.t0.Add(400 * time.Second).Sub(diskB.LastSeen); lag < 90*time.Second {
		t.Fatalf("the crash left node-b only %s stale on disk; the test needs more than the 90 s threshold", lag)
	}
	boot := f.t0.Add(450 * time.Second) // 45 s down
	if got := sweep(crashed, boot, NodeStatusCauseServerStart); len(got) != 0 {
		t.Fatalf("the start sweep after a crash marked %v offline", got)
	}
	// The new process: the live nodes beat from boot+10s, node-late never
	// does. Its LastSeen on disk is t0+290s, so it is judged with the slack
	// and goes offline at the first sweep past 90 s plus the slack.
	var lateFlippedAt time.Duration
	for step := 1; step <= 40; step++ {
		f.clock.at = boot.Add(time.Duration(step) * 10 * time.Second)
		beat(t, crashed, live...)
		if step%2 == 0 {
			got := sweep(crashed, f.clock.at, NodeStatusCauseLivenessSweep)
			switch {
			case len(got) == 0:
			case len(got) == 1 && got[0] == "node-late" && lateFlippedAt == 0:
				lateFlippedAt = f.clock.at.Sub(f.t0)
			default:
				t.Fatalf("at t0+%s the sweep marked %v offline", f.clock.at.Sub(f.t0), got)
			}
		}
	}
	if lateFlippedAt != 690*time.Second {
		t.Fatalf("node-late (last on disk at t0+290s) went offline at t0+%s, want t0+690s", lateFlippedAt)
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
