package store

import (
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func nodeStatusRows(t *testing.T, s *Store, id string) []NodeStatusEvent {
	t.Helper()
	rows, err := s.NodeStatusEvents(id)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// Only the two hooks write, and each writes one row per transition: a sweep
// that flips nothing and a beat on a node already online leave the history
// as it was.
func TestNodeStatusEventsRecordTransitionsOnly(t *testing.T) {
	for _, mode := range []string{"json", "bolt"} {
		t.Run(mode, func(t *testing.T) {
			s := openUsageDayStore(t, mode)
			stale := time.Now().UTC().Add(-10 * time.Minute)
			if err := s.UpsertNode(model.Node{ID: "node-a", Name: "a", Online: true, LastSeen: stale}); err != nil {
				t.Fatal(err)
			}

			// Under the threshold: no flip, no row.
			flipped, err := s.MarkStaleNodesOffline(90*time.Second, stale.Add(30*time.Second), NodeStatusCauseLivenessSweep)
			if err != nil || len(flipped) != 0 {
				t.Fatalf("sweep under threshold: flipped=%v err=%v", flipped, err)
			}
			if rows := nodeStatusRows(t, s, "node-a"); len(rows) != 0 {
				t.Fatalf("sweep under threshold wrote rows: %+v", rows)
			}

			sweepAt := time.Now().UTC()
			flipped, err = s.MarkStaleNodesOffline(90*time.Second, sweepAt, NodeStatusCauseServerStart)
			if err != nil || len(flipped) != 1 {
				t.Fatalf("sweep past threshold: flipped=%v err=%v", flipped, err)
			}
			rows := nodeStatusRows(t, s, "node-a")
			if len(rows) != 1 || rows[0].To != NodeStatusOffline || rows[0].Cause != NodeStatusCauseServerStart || !rows[0].At.Equal(sweepAt) {
				t.Fatalf("sweep flip must write exactly one offline row with its cause: %+v", rows)
			}
			if _, err := s.MarkStaleNodesOffline(90*time.Second, sweepAt, NodeStatusCauseLivenessSweep); err != nil {
				t.Fatal(err)
			}
			if rows := nodeStatusRows(t, s, "node-a"); len(rows) != 1 {
				t.Fatalf("a repeated sweep must not duplicate the row: %+v", rows)
			}

			cameOnline, err := s.UpdateMetrics("node-a", model.Metrics{}, "0.3.9", "", "", "", "", "", model.HostFacts{})
			if err != nil || !cameOnline {
				t.Fatalf("first beat: cameOnline=%v err=%v", cameOnline, err)
			}
			n, _ := s.Node("node-a")
			rows = nodeStatusRows(t, s, "node-a")
			if len(rows) != 2 || rows[1].To != NodeStatusOnline || rows[1].Cause != NodeStatusCauseBeat || !rows[1].At.Equal(n.OnlineSince) {
				t.Fatalf("the beat that ends an episode must write exactly one online row at OnlineSince: %+v since=%s", rows, n.OnlineSince)
			}
			cameOnline, err = s.UpdateMetrics("node-a", model.Metrics{}, "0.3.9", "", "", "", "", "", model.HostFacts{})
			if err != nil || cameOnline {
				t.Fatalf("second beat: cameOnline=%v err=%v", cameOnline, err)
			}
			// A short silence that never crosses the threshold is not a flap.
			n, _ = s.Node("node-a")
			if _, err := s.MarkStaleNodesOffline(90*time.Second, n.LastSeen.Add(60*time.Second), NodeStatusCauseLivenessSweep); err != nil {
				t.Fatal(err)
			}
			if rows := nodeStatusRows(t, s, "node-a"); len(rows) != 2 {
				t.Fatalf("a beat on an online node and a sub-threshold silence must add nothing: %+v", rows)
			}
		})
	}
}

// The per-id cap drops the oldest rows, and the prune drops every row older
// than the cutoff across ids while leaving newer ones alone.
func TestNodeStatusEventsCapAndPrune(t *testing.T) {
	for _, mode := range []string{"json", "bolt"} {
		t.Run(mode, func(t *testing.T) {
			s := openUsageDayStore(t, mode)
			base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
			batch := make([]nodeStatusAppend, 0, maxNodeStatusEvents+5)
			for i := 0; i < maxNodeStatusEvents+5; i++ {
				batch = append(batch, nodeStatusAppend{id: "node-a", event: NodeStatusEvent{At: base.Add(time.Duration(i) * time.Second), To: NodeStatusOffline, Cause: NodeStatusCauseLivenessSweep}})
			}
			if err := s.appendNodeStatusEventsLocked(batch); err != nil {
				t.Fatal(err)
			}
			rows := nodeStatusRows(t, s, "node-a")
			if len(rows) != maxNodeStatusEvents || !rows[0].At.Equal(base.Add(5*time.Second)) {
				t.Fatalf("cap must keep the newest %d rows: len=%d first=%s", maxNodeStatusEvents, len(rows), rows[0].At)
			}

			for _, at := range []time.Time{base, base.Add(40 * 24 * time.Hour)} {
				if err := s.AppendNodeStatusEvent("node-b", NodeStatusEvent{At: at, To: NodeStatusOnline, Cause: NodeStatusCauseBeat}); err != nil {
					t.Fatal(err)
				}
			}
			pruned, err := s.PruneNodeStatusEvents(base.Add(20 * 24 * time.Hour))
			if err != nil || pruned != maxNodeStatusEvents+1 {
				t.Fatalf("prune: pruned=%d err=%v", pruned, err)
			}
			if rows := nodeStatusRows(t, s, "node-a"); len(rows) != 0 {
				t.Fatalf("node-a rows survived the prune: %d", len(rows))
			}
			rows = nodeStatusRows(t, s, "node-b")
			if len(rows) != 1 || !rows[0].At.Equal(base.Add(40*24*time.Hour)) {
				t.Fatalf("prune must keep rows newer than the cutoff: %+v", rows)
			}
			if pruned, err := s.PruneNodeStatusEvents(base.Add(20 * 24 * time.Hour)); err != nil || pruned != 0 {
				t.Fatalf("second prune: pruned=%d err=%v", pruned, err)
			}
		})
	}
}

// The start mark closes the previous run at the newest instant it is known
// to have been alive: the freshest heartbeat, or the newest row when nothing
// beat since.
func TestRecordServerStartMarksTheGap(t *testing.T) {
	for _, mode := range []string{"json", "bolt"} {
		t.Run(mode, func(t *testing.T) {
			s := openUsageDayStore(t, mode)
			base := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
			if err := s.RecordServerStart(base.Add(-time.Hour)); err != nil {
				t.Fatal(err)
			}
			rows := nodeStatusRows(t, s, NodeStatusServerID)
			if len(rows) != 1 || rows[0].To != NodeStatusOnline || rows[0].Cause != NodeStatusCauseServerStart {
				t.Fatalf("a first start with nothing before it marks only the start: %+v", rows)
			}

			for id, seen := range map[string]time.Time{"node-a": base, "node-b": base.Add(-30 * time.Minute)} {
				if err := s.UpsertNode(model.Node{ID: id, Name: id, Online: true, LastSeen: seen}); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.RecordServerStart(base.Add(40 * time.Second)); err != nil {
				t.Fatal(err)
			}
			rows = nodeStatusRows(t, s, NodeStatusServerID)
			if len(rows) != 3 || rows[1].To != NodeStatusOffline || rows[1].Cause != NodeStatusCauseServerStop || !rows[1].At.Equal(base) ||
				rows[2].To != NodeStatusOnline || !rows[2].At.Equal(base.Add(40*time.Second)) {
				t.Fatalf("stop must sit at the freshest heartbeat: %+v", rows)
			}

			// Nothing beat since: the previous start is the newest known instant,
			// and the stop must neither precede it nor overwrite its row.
			if err := s.RecordServerStart(base.Add(100 * time.Second)); err != nil {
				t.Fatal(err)
			}
			rows = nodeStatusRows(t, s, NodeStatusServerID)
			if len(rows) != 5 || rows[3].To != NodeStatusOffline || !rows[3].At.Equal(base.Add(40*time.Second+time.Nanosecond)) || !rows[4].At.Equal(base.Add(100*time.Second)) {
				t.Fatalf("stop must sit one tick after the previous start: %+v", rows)
			}
		})
	}
}
