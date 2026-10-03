package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
)

// A save names the version it was read at; a second save from the same read
// is refused, and the stored copy is not the caller's slice.
func TestLatencyProbeConfigSaveIsVersioned(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	if _, ok := s.LatencyProbeConfig(); ok {
		t.Fatal("a fresh store has a stored configuration")
	}
	in := model.LatencyProbeConfig{Enabled: true, IntervalSec: 60, TimeoutSec: 5, Sources: []string{"node-sh"}}
	at := time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)
	stored, err := s.SetLatencyProbeConfig(in, 0, "user-a", at)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Version != 1 || stored.UpdatedBy != "user-a" || !stored.UpdatedAt.Equal(at) {
		t.Fatalf("stored = %+v", stored)
	}
	in.Sources[0] = "mutated"
	if got, _ := s.LatencyProbeConfig(); got.Sources[0] != "node-sh" {
		t.Fatalf("the store shares the caller's slice: %+v", got)
	}
	if _, err := s.SetLatencyProbeConfig(in, 0, "user-b", at); !errors.Is(err, ErrLatencyProbeVersion) {
		t.Fatalf("a stale save = %v, want ErrLatencyProbeVersion", err)
	}
	if next, err := s.SetLatencyProbeConfig(in, 1, "user-b", at); err != nil || next.Version != 2 {
		t.Fatalf("a save from version 1 = %+v, %v", next, err)
	}
}

// The configuration survives a restart and the offline migrate round trip.
func TestLatencyProbeConfigPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	cfg := model.LatencyProbeConfig{Enabled: true, IntervalSec: 30, TimeoutSec: 5, Sources: []string{"node-sh"}, DisabledPairs: []model.LatencyPair{{Source: "node-sh", Target: "node-jp"}}}
	if _, err := s.SetLatencyProbeConfig(cfg, 0, "user-a", time.Now()); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reopened.LatencyProbeConfig()
	if !ok || got.Version != 1 || got.IntervalSec != 30 || len(got.DisabledPairs) != 1 {
		t.Fatalf("after reopen: %+v %v", got, ok)
	}

	bs, err := OpenBoltState(filepath.Join(dir, "migrate.db"), secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()
	if err := bs.ImportState(reopened.state); err != nil {
		t.Fatal(err)
	}
	exported, err := bs.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if exported.LatencyProbes == nil || exported.LatencyProbes.Version != 1 || exported.LatencyProbes.DisabledPairs[0].Target != "node-jp" {
		t.Fatalf("migrate round trip lost the configuration: %+v", exported.LatencyProbes)
	}
}

// Managed monitors are written once when they change and not at all when
// they do not; operator monitors are never touched; a managed monitor that
// leaves the desired set goes with its history.
func TestSyncManagedMonitors(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	seedMonitor(t, s, model.Monitor{ID: "mon-op", Name: "operator", Type: model.MonitorTypeTCP, Target: "a:1", AssignAll: true})
	desired := []model.Monitor{
		{ID: "mon_lat_jp", Name: "Latency to jp", Type: model.MonitorTypeTCP, Target: "203.0.113.1:443", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-sh"}, Enabled: true},
		{ID: "mon_lat_hk", Name: "Latency to hk", Type: model.MonitorTypeTCP, Target: "203.0.113.2:8443", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-sh"}, Enabled: true},
		// An operator monitor holds this id: the sync must not take it over.
		{ID: "mon-op", Name: "hijack", Type: model.MonitorTypeTCP, Target: "evil:1", Enabled: true},
	}
	now := time.Now().UTC()
	calls := s.testPersistCalls
	changes, err := s.SyncManagedMonitors(model.MonitorManagedLatency, desired, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes.Created) != 2 || len(changes.Updated) != 0 || s.testPersistCalls-calls != 1 {
		t.Fatalf("first sync = %+v, writes %d", changes, s.testPersistCalls-calls)
	}
	if op, _ := s.Monitor("mon-op"); op.Name != "operator" || op.ManagedBy != "" {
		t.Fatalf("operator monitor changed: %+v", op)
	}
	if jp, _ := s.Monitor("mon_lat_jp"); jp.ManagedBy != model.MonitorManagedLatency || jp.CreatedAt.IsZero() {
		t.Fatalf("generated monitor = %+v", jp)
	}

	calls = s.testPersistCalls
	again, err := s.SyncManagedMonitors(model.MonitorManagedLatency, desired, now.Add(time.Minute))
	if err != nil || again.Changed() || s.testPersistCalls != calls {
		t.Fatalf("an unchanged sync wrote: %+v err=%v writes=%d", again, err, s.testPersistCalls-calls)
	}

	if _, err := s.IngestAgentMonitorResults("node-sh", []model.MonitorResult{{MonitorID: "mon_lat_hk", At: now, Success: true, LatencyMs: 50}}, now); err != nil {
		t.Fatal(err)
	}
	desired[0].NodeIDs = []string{"node-sh", "node-bj"}
	changes, err = s.SyncManagedMonitors(model.MonitorManagedLatency, desired[:1], now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(changes.Updated) != 1 || len(changes.Deleted) != 1 || changes.Deleted[0] != "mon_lat_hk" {
		t.Fatalf("second sync = %+v", changes)
	}
	jp, _ := s.Monitor("mon_lat_jp")
	if !jp.CreatedAt.Equal(now) || len(jp.NodeIDs) != 2 || jp.NodeIDs[0] != "node-bj" {
		t.Fatalf("updated monitor keeps its creation time and sorts its nodes: %+v", jp)
	}
	if _, ok := s.Monitor("mon_lat_hk"); ok {
		t.Fatal("a managed monitor left the desired set and survived")
	}
	if rows, _ := s.MonitorPairResults("mon_lat_hk", "node-sh", 0); len(rows) != 0 {
		t.Fatalf("its history survived: %d rows", len(rows))
	}
	if _, ok := s.Monitor("mon-op"); !ok {
		t.Fatal("the operator monitor was deleted")
	}
}
