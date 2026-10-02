package store

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The paged spells are written when they change and only then, in both
// persistence modes, and survive a reopen.
func TestNodeOfflineAlertsPersistOnlyOnChange(t *testing.T) {
	for _, hot := range []bool{false, true} {
		t.Run(fmt.Sprintf("bolt_hot_%v", hot), func(t *testing.T) {
			s, path := openReportClockStore(t)
			if hot {
				if err := s.EnableRuntimeBoltHotStore(filepath.Join(t.TempDir(), "hot.db")); err != nil {
					t.Fatal(err)
				}
			}
			at := time.Date(2026, 10, 2, 9, 0, 0, 0, time.FixedZone("x", 3600))

			before := s.testPersistCalls
			if err := s.SetNodeOfflineAlerts(map[string]time.Time{"node-a": at}); err != nil {
				t.Fatal(err)
			}
			if calls := s.testPersistCalls - before; calls != 1 {
				t.Fatalf("a new page wrote %d times, want 1", calls)
			}
			before = s.testPersistCalls
			// The same instant in another zone is the same spell.
			for i := 0; i < 10; i++ {
				if err := s.SetNodeOfflineAlerts(map[string]time.Time{"node-a": at.UTC()}); err != nil {
					t.Fatal(err)
				}
			}
			if calls := s.testPersistCalls - before; calls != 0 {
				t.Fatalf("an unchanged set wrote %d times, want 0", calls)
			}

			got := s.NodeOfflineAlerts()
			got["node-b"] = at
			if _, leaked := s.NodeOfflineAlerts()["node-b"]; leaked {
				t.Fatal("NodeOfflineAlerts handed out the store's own map")
			}

			if hot {
				// The reopen below reads the JSON state; the hot store is a
				// sidecar for other domains, so this domain stays in JSON.
				return
			}
			reopened := reopenReportClockStore(t, s, path)
			if got := reopened.NodeOfflineAlerts(); len(got) != 1 || !got["node-a"].Equal(at) {
				t.Fatalf("after reopen: %v", got)
			}
			if err := reopened.SetNodeOfflineAlerts(nil); err != nil {
				t.Fatal(err)
			}
			again := reopenReportClockStore(t, reopened, path)
			if got := again.NodeOfflineAlerts(); len(got) != 0 {
				t.Fatalf("a cleared set came back: %v", got)
			}
		})
	}
}

// The bolt state store round-trips the domain like every other node-keyed map.
func TestNodeOfflineAlertsRoundTripThroughBoltState(t *testing.T) {
	bs, err := OpenBoltState(filepath.Join(t.TempDir(), "state.db"), testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()
	at := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	st := emptyState()
	st.NodeOfflineAlerts["node-a"] = at
	if err := bs.ImportState(st); err != nil {
		t.Fatal(err)
	}
	out, err := bs.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if got := out.NodeOfflineAlerts; len(got) != 1 || !got["node-a"].Equal(at) {
		t.Fatalf("bolt round trip: %v", got)
	}
}

// Deleting a node removes its paged spell with the rest of the node's state.
func TestNodeOfflineAlertsGoWithTheNode(t *testing.T) {
	s, _ := openReportClockStore(t)
	defer s.Close()
	if err := s.UpsertNode(model.Node{ID: "node-a", Name: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeOfflineAlerts(map[string]time.Time{"node-a": time.Now(), "node-b": time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.DeleteNode("node-a"); err != nil || !ok {
		t.Fatalf("delete: ok=%v err=%v", ok, err)
	}
	got := s.NodeOfflineAlerts()
	if _, ok := got["node-a"]; ok || len(got) != 1 {
		t.Fatalf("after deleting node-a: %v", got)
	}
}
