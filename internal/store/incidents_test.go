package store

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func testIncident(id, key string, at time.Time, state string) Incident {
	return Incident{ID: id, Key: key, Kind: "node.offline", Severity: "warning", NodeID: "node-a",
		State: state, Title: "title " + id, FirstOpenedAt: at, OpenedAt: at, UpdatedAt: at}
}

// Incidents and maintenance windows survive a reopen on the hot store, never
// reach the state file, and are memory only without the hot store.
func TestIncidentsSurviveAReopenOnlyOnTheHotStore(t *testing.T) {
	for _, hot := range []bool{true, false} {
		t.Run(fmt.Sprintf("bolt_hot_%v", hot), func(t *testing.T) {
			s, path := openReportClockStore(t)
			hotPath := filepath.Join(filepath.Dir(path), "hot.db")
			if hot {
				if err := s.EnableRuntimeBoltHotStore(hotPath); err != nil {
					t.Fatal(err)
				}
			}
			at := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
			inc := testIncident("inc-1", "node.offline/node-a", at, IncidentStateAcknowledged)
			inc.Title = "MARKER-INCIDENT-TITLE"
			inc.AckedBy, inc.AckedAt = "user-1", at.Add(time.Minute)
			inc.Escalated = map[string]time.Time{"rule-1": at.Add(30 * time.Minute)}
			if err := s.PutIncidents(inc); err != nil {
				t.Fatal(err)
			}
			mw := MaintenanceWindow{ID: "mw-1", Name: "MARKER-WINDOW", NodeIDs: []string{"node-a"}, StartsAt: at, EndsAt: at.Add(time.Hour), CreatedAt: at}
			if err := s.PutMaintenanceWindow(mw, at); err != nil {
				t.Fatal(err)
			}
			if err := s.UpsertNode(model.Node{ID: "node-a", Name: "a"}); err != nil {
				t.Fatal(err) // forces a state file write
			}
			if s.IncidentsDurable() != hot {
				t.Fatalf("IncidentsDurable = %v with hot %v", s.IncidentsDurable(), hot)
			}
			s = reopenReportClockStore(t, s, path)
			if hot {
				if err := s.EnableRuntimeBoltHotStore(hotPath); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { _ = s.Close() })
			got, ok := s.ActiveIncident("node.offline/node-a")
			_, mwOK := s.MaintenanceWindow("mw-1")
			if hot {
				if !ok || got.State != IncidentStateAcknowledged || got.AckedBy != "user-1" || !got.Escalated["rule-1"].Equal(at.Add(30*time.Minute)) || !mwOK {
					t.Fatalf("after reopen: %v %+v, window %v", ok, got, mwOK)
				}
			} else if ok || mwOK {
				t.Fatalf("memory-only incidents survived a reopen: %v %v", ok, mwOK)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, []byte("MARKER-INCIDENT")) || bytes.Contains(data, []byte("MARKER-WINDOW")) {
				t.Fatal("incidents reached the state file")
			}
		})
	}
}

// No incident write rewrites the JSON state.
func TestIncidentWritesNeverPersistTheJSONState(t *testing.T) {
	for _, hot := range []bool{false, true} {
		t.Run(fmt.Sprintf("bolt_hot_%v", hot), func(t *testing.T) {
			s, _ := openReportClockStore(t)
			if hot {
				if err := s.EnableRuntimeBoltHotStore(filepath.Join(t.TempDir(), "hot.db")); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { _ = s.Close() })
			at := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
			before := s.testPersistCalls
			for i := 0; i < 20; i++ {
				inc := testIncident(fmt.Sprintf("inc-%d", i), fmt.Sprintf("k-%d", i), at, IncidentStateOpen)
				if err := s.PutIncidents(inc); err != nil {
					t.Fatal(err)
				}
				inc.State, inc.ResolvedAt = IncidentStateResolved, at.Add(time.Minute)
				if err := s.PutIncidents(inc); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.PutMaintenanceWindow(MaintenanceWindow{ID: "mw", StartsAt: at, EndsAt: at.Add(time.Hour)}, at); err != nil {
				t.Fatal(err)
			}
			if _, err := s.PruneIncidents(at.Add(48 * time.Hour)); err != nil {
				t.Fatal(err)
			}
			if got := s.testPersistCalls - before; got != 0 {
				t.Fatalf("incident writes persisted the JSON state %d times", got)
			}
		})
	}
}

// One problem, one record: a second unresolved incident for a key is refused,
// and the indexes follow resolves and deletes.
func TestIncidentKeyHasAtMostOneUnresolvedRecord(t *testing.T) {
	s, _ := openReportClockStore(t)
	t.Cleanup(func() { _ = s.Close() })
	at := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	first := testIncident("inc-1", "service.down/node-a", at, IncidentStateOpen)
	if err := s.PutIncidents(first); err != nil {
		t.Fatal(err)
	}
	if err := s.PutIncidents(testIncident("inc-2", "service.down/node-a", at.Add(time.Minute), IncidentStateOpen)); err == nil {
		t.Fatal("a second unresolved incident for one key was accepted")
	}
	first.State, first.ResolvedAt = IncidentStateResolved, at.Add(2*time.Minute)
	if err := s.PutIncidents(first); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ActiveIncident("service.down/node-a"); ok {
		t.Fatal("a resolved incident is still active")
	}
	second := testIncident("inc-2", "service.down/node-a", at.Add(time.Hour), IncidentStateOpen)
	if err := s.PutIncidents(second); err != nil {
		t.Fatal(err)
	}
	if got, ok := s.LatestIncident("service.down/node-a"); !ok || got.ID != "inc-2" {
		t.Fatalf("latest = %+v %v", got, ok)
	}
	if err := s.DeleteIncidents("inc-2"); err != nil {
		t.Fatal(err)
	}
	if got, ok := s.LatestIncident("service.down/node-a"); !ok || got.ID != "inc-1" {
		t.Fatalf("latest after delete = %+v %v", got, ok)
	}
	if err := s.DeleteIncidentsWhere(func(inc Incident) bool { return inc.NodeID == "node-a" }); err != nil {
		t.Fatal(err)
	}
	if n := len(s.Incidents()); n != 0 {
		t.Fatalf("%d incidents left after deleting the node's", n)
	}
}

// The bound evicts the oldest resolved incidents and never an open one.
func TestIncidentBoundEvictsOldestResolvedOnly(t *testing.T) {
	s, _ := openReportClockStore(t)
	t.Cleanup(func() { _ = s.Close() })
	at := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	open := testIncident("inc-open", "k-open", at, IncidentStateOpen)
	if err := s.PutIncidents(open); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxIncidents+5; i++ {
		inc := testIncident(fmt.Sprintf("inc-%05d", i), fmt.Sprintf("k-%d", i), at, IncidentStateResolved)
		inc.ResolvedAt = at.Add(time.Duration(i) * time.Second)
		if err := s.PutIncidents(inc); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(s.Incidents()); n != MaxIncidents {
		t.Fatalf("book holds %d, want %d", n, MaxIncidents)
	}
	if _, ok := s.Incident("inc-open"); !ok {
		t.Fatal("an open incident was evicted")
	}
	if _, ok := s.Incident("inc-00000"); ok {
		t.Fatal("the oldest resolved incident survived the bound")
	}
	if _, ok := s.Incident(fmt.Sprintf("inc-%05d", MaxIncidents+4)); !ok {
		t.Fatal("the newest resolved incident was evicted")
	}
}

// Pruning drops resolved incidents past the cutoff but keeps one still marked
// flapping, which the server settles first.
func TestPruneIncidentsKeepsActiveAndFlapping(t *testing.T) {
	s, _ := openReportClockStore(t)
	t.Cleanup(func() { _ = s.Close() })
	at := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	old := testIncident("inc-old", "k-old", at, IncidentStateResolved)
	old.ResolvedAt = at
	flapping := testIncident("inc-flap", "k-flap", at, IncidentStateResolved)
	flapping.ResolvedAt, flapping.Flapping = at, true
	open := testIncident("inc-open", "k-open", at, IncidentStateOpen)
	if err := s.PutIncidents(old, flapping, open); err != nil {
		t.Fatal(err)
	}
	n, err := s.PruneIncidents(at.Add(IncidentRetention + time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("pruned %d, %v", n, err)
	}
	if got := s.FlappingIncidents(); len(got) != 1 || got[0].ID != "inc-flap" {
		t.Fatalf("flapping = %+v", got)
	}
	if got := s.ActiveIncidents(); len(got) != 1 || got[0].ID != "inc-open" {
		t.Fatalf("active = %+v", got)
	}
}

// Windows that ended long ago are pruned when a new one is written, and the
// bound refuses a new window rather than dropping a live one.
func TestMaintenanceWindowsPruneAndBound(t *testing.T) {
	s, _ := openReportClockStore(t)
	t.Cleanup(func() { _ = s.Close() })
	at := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	ended := MaintenanceWindow{ID: "mw-ended", StartsAt: at.Add(-40 * 24 * time.Hour), EndsAt: at.Add(-31 * 24 * time.Hour)}
	if err := s.PutMaintenanceWindow(ended, at.Add(-31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxMaintenanceWindows-1; i++ {
		mw := MaintenanceWindow{ID: fmt.Sprintf("mw-%03d", i), StartsAt: at, EndsAt: at.Add(time.Hour)}
		if err := s.PutMaintenanceWindow(mw, at); err != nil {
			t.Fatalf("window %d: %v", i, err)
		}
	}
	if _, ok := s.MaintenanceWindow("mw-ended"); ok {
		t.Fatal("a window that ended 31 days ago was kept")
	}
	if err := s.PutMaintenanceWindow(MaintenanceWindow{ID: "mw-last", StartsAt: at, EndsAt: at.Add(time.Hour)}, at); err != nil {
		t.Fatal(err)
	}
	if err := s.PutMaintenanceWindow(MaintenanceWindow{ID: "mw-over", StartsAt: at, EndsAt: at.Add(time.Hour)}, at); err == nil {
		t.Fatal("a window past the bound was accepted")
	}
	if !(MaintenanceWindow{StartsAt: at, EndsAt: at.Add(time.Hour)}).ActiveAt(at) {
		t.Fatal("a window is not active at its start")
	}
	if (MaintenanceWindow{StartsAt: at, EndsAt: at.Add(time.Hour)}).ActiveAt(at.Add(time.Hour)) {
		t.Fatal("a window is still active at its end")
	}
}

// A suppressed message is stored like an unrouted one: folded, bounded and
// apart from the per-source floor.
func TestSuppressedRowsFoldLikeUnroutedRows(t *testing.T) {
	s, _ := openReportClockStore(t)
	t.Cleanup(func() { _ = s.Close() })
	at := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		row := NotifyDelivery{ID: fmt.Sprintf("nd-%d", i), EventID: fmt.Sprintf("evt-%d", i), EventType: "node.offline",
			Source: NotifySourceServer, SourceID: "inc-1", Reason: "maintenance window", Title: "t", CreatedAt: at.Add(time.Duration(i) * time.Minute)}
		if err := s.RecordNotifySuppressed(row); err != nil {
			t.Fatal(err)
		}
	}
	rows := s.NotifyDeliveries(NotifyDeliveryFilter{})
	if len(rows) != 1 || rows[0].Outcome != NotifyOutcomeSuppressed || rows[0].Repeats != 2 {
		t.Fatalf("suppressed rows = %+v", rows)
	}
	if !rows[0].Unsent() || !rows[0].Settled() {
		t.Fatalf("a suppressed row must read unsent and settled: %+v", rows[0])
	}
	// An unrouted row with the same source and reason folds separately.
	if err := s.RecordNotifyNoRoute(NotifyDelivery{ID: "nd-nr", EventID: "evt-nr", EventType: "node.offline",
		Source: NotifySourceServer, SourceID: "inc-1", Reason: "maintenance window", CreatedAt: at.Add(5 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if n := len(s.NotifyDeliveries(NotifyDeliveryFilter{})); n != 2 {
		t.Fatalf("suppressed and unrouted rows folded together: %d rows", n)
	}
}

// Deleting a node or a monitor removes its incidents in the same cascade, so
// a node enrolled again under the same id starts with no open problem, and
// the recovery text of a resolved record survives a reopen.
func TestDeleteCascadesRemoveIncidents(t *testing.T) {
	s, path := openReportClockStore(t)
	if err := s.EnableRuntimeBoltHotStore(filepath.Join(filepath.Dir(path), "hot.db")); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	for _, id := range []string{"node-a", "node-b"} {
		if err := s.UpsertNode(model.Node{ID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UpsertMonitor(model.Monitor{ID: "mon-1", Name: "web", Type: model.MonitorTypeTCP, Target: "x:1", NodeIDs: []string{"node-b"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	offline := testIncident("inc-a", "node.offline/node-a", at, IncidentStateOpen)
	monitor := testIncident("inc-m", "monitor.down/mon-1/node-b", at, IncidentStateResolved)
	monitor.NodeID, monitor.MonitorID, monitor.Kind = "node-b", "mon-1", "monitor.down"
	monitor.RecoveryTitle, monitor.OwedRecovery = "MARKER-RECOVERY", true
	other := testIncident("inc-b", "node.offline/node-b", at, IncidentStateOpen)
	other.NodeID = "node-b"
	if err := s.PutIncidents(offline, monitor, other); err != nil {
		t.Fatal(err)
	}
	if got, ok := s.Incident("inc-m"); !ok || got.RecoveryTitle != "MARKER-RECOVERY" || !got.OwedRecovery {
		t.Fatalf("recovery fields = %+v", got)
	}
	if err := s.DeleteMonitor("mon-1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Incident("inc-m"); ok {
		t.Fatal("a deleted monitor's incident remains")
	}
	if _, _, err := s.DeleteNode("node-a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ActiveIncident("node.offline/node-a"); ok {
		t.Fatal("a deleted node's incident remains")
	}
	if _, ok := s.ActiveIncident("node.offline/node-b"); !ok {
		t.Fatal("another node's incident went with it")
	}
	got := s.IncidentsWhere(func(inc Incident) bool { return inc.NodeID != "" })
	if len(got) != 1 || got[0].ID != "inc-b" {
		t.Fatalf("left = %+v", got)
	}
}
