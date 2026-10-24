package store

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func checkDefStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func checkMon(id, _ string, interval int) model.Monitor {
	return model.Monitor{ID: id, Name: id, Type: model.MonitorTypeTCP, Target: "203.0.113.3:443", TargetNode: "node-jp", IntervalSec: interval, TimeoutSec: 5, NodeIDs: []string{"node-sh"}, Enabled: true}
}

// A save writes the definition and every expanded monitor, of every owner
// it carries, in one state write; an edit of a shared field rewrites every
// monitor in that one write.
func TestSaveCheckDefinitionIsOneWrite(t *testing.T) {
	s := checkDefStore(t)
	now := time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)
	def := model.CheckDefinition{ID: "chk_a", CheckDefinitionSpec: model.CheckDefinitionSpec{Name: "a", Type: model.MonitorTypeTCP, IntervalSec: 60, TimeoutSec: 5, Enabled: true}}
	owner := CheckDefinitionOwner(def.ID)
	sets := map[string][]model.Monitor{owner: {checkMon("mon_chk_a_1", owner, 60), checkMon("mon_chk_a_2", owner, 60), checkMon("mon_chk_a_3", owner, 60)}}
	before := s.testPersistCalls
	stored, changes, err := s.SaveCheckDefinition(def, 0, "admin", sets, now)
	if err != nil {
		t.Fatal(err)
	}
	if calls := s.testPersistCalls - before; calls != 1 {
		t.Fatalf("create took %d writes, want 1", calls)
	}
	if stored.Version != 1 || len(changes[owner].Created) != 3 {
		t.Fatalf("stored %+v changes %+v", stored, changes)
	}
	for i := range sets[owner] {
		sets[owner][i].IntervalSec = 120
	}
	def.IntervalSec = 120
	before = s.testPersistCalls
	if _, changes, err = s.SaveCheckDefinition(def, 1, "admin", sets, now); err != nil {
		t.Fatal(err)
	}
	if calls := s.testPersistCalls - before; calls != 1 || len(changes[owner].Updated) != 3 {
		t.Fatalf("edit took %d writes and updated %v, want 1 write and 3 monitors", calls, changes[owner].Updated)
	}
	if _, _, err := s.SaveCheckDefinition(def, 1, "admin", sets, now); !errors.Is(err, ErrCheckDefinitionVersion) {
		t.Fatalf("stale save = %v", err)
	}
}

// A sync of many owners is one write, and an owner whose definition is gone
// keeps nothing.
func TestSyncManagedMonitorSetsIsOneWrite(t *testing.T) {
	s := checkDefStore(t)
	now := time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)
	var sets = map[string][]model.Monitor{}
	for _, id := range []string{"chk_a", "chk_b", "chk_c"} {
		def := model.CheckDefinition{ID: id, CheckDefinitionSpec: model.CheckDefinitionSpec{Name: id, Type: model.MonitorTypeTCP}}
		if _, _, err := s.SaveCheckDefinition(def, 0, "admin", nil, now); err != nil {
			t.Fatal(err)
		}
		owner := CheckDefinitionOwner(id)
		sets[owner] = []model.Monitor{checkMon("mon_"+id+"_1", owner, 60)}
	}
	ghost := CheckDefinitionOwner("chk_gone")
	sets[ghost] = []model.Monitor{checkMon("mon_chk_gone_1", ghost, 60)}
	before := s.testPersistCalls
	changes, err := s.SyncManagedMonitorSets(sets, now)
	if err != nil {
		t.Fatal(err)
	}
	if calls := s.testPersistCalls - before; calls != 1 {
		t.Fatalf("three owners took %d writes, want 1", calls)
	}
	if changes[ghost].Changed() {
		t.Fatalf("an owner with no definition got monitors: %+v", changes[ghost])
	}
	if _, ok := s.Monitor("mon_chk_gone_1"); ok {
		t.Fatal("a deleted definition's monitor was created")
	}
	before = s.testPersistCalls
	if changes, err := s.SyncManagedMonitorSets(sets, now); err != nil || managedChangesAny(changes) || s.testPersistCalls != before {
		t.Fatalf("a sync with no change wrote %+v (%d writes) %v", changes, s.testPersistCalls-before, err)
	}
}

// A delete goes only with the exact confirmation, and takes every monitor;
// a forget takes only paused monitors of the definition.
func TestDeleteAndForgetNeedTheirConfirmation(t *testing.T) {
	s := checkDefStore(t)
	now := time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)
	def := model.CheckDefinition{ID: "chk_a", CheckDefinitionSpec: model.CheckDefinitionSpec{Name: "a", Type: model.MonitorTypeTCP}}
	owner := CheckDefinitionOwner(def.ID)
	paused := checkMon("mon_chk_a_2", owner, 60)
	paused.Enabled = false
	if _, _, err := s.SaveCheckDefinition(def, 0, "admin", map[string][]model.Monitor{owner: {checkMon("mon_chk_a_1", owner, 60), paused}}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ForgetCheckMonitors(def.ID, []string{"mon_chk_a_1"}); !errors.Is(err, ErrCheckDefinitionMonitors) {
		t.Fatalf("forget a running monitor = %v", err)
	}
	if gone, err := s.ForgetCheckMonitors(def.ID, []string{"mon_chk_a_2"}); err != nil || !slices.Equal(gone, []string{"mon_chk_a_2"}) {
		t.Fatalf("forget = %v %v", gone, err)
	}
	if _, err := s.DeleteCheckDefinition(def.ID, 1, []string{"mon_chk_a_1", "mon_chk_a_2"}); !errors.Is(err, ErrCheckDefinitionMonitors) {
		t.Fatalf("delete with a stale list = %v", err)
	}
	if _, err := s.DeleteCheckDefinition(def.ID, 2, []string{"mon_chk_a_1"}); !errors.Is(err, ErrCheckDefinitionVersion) {
		t.Fatalf("delete with a stale version = %v", err)
	}
	if gone, err := s.DeleteCheckDefinition(def.ID, 1, []string{"mon_chk_a_1"}); err != nil || !slices.Equal(gone, []string{"mon_chk_a_1"}) {
		t.Fatalf("delete = %v %v", gone, err)
	}
	if _, ok := s.CheckDefinition(def.ID); ok {
		t.Fatal("the definition survived")
	}
}

// Definitions survive a reopen and the offline migrate round trip.
func TestCheckDefinitionsPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	def := model.CheckDefinition{ID: "chk_a", CheckDefinitionSpec: model.CheckDefinitionSpec{
		Name: "a", Type: model.MonitorTypeTCP, Sources: model.TargetSelector{Groups: []string{"grp_x"}}, Targets: model.TargetSelector{All: true, Exclude: []string{"node-b"}},
	}}
	if _, _, err := s.SaveCheckDefinition(def, 0, "admin", nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := again.CheckDefinition("chk_a")
	if !ok || !got.Targets.All || !slices.Equal(got.Sources.Groups, []string{"grp_x"}) || got.Version != 1 {
		t.Fatalf("reopened definition = %+v %v", got, ok)
	}
	bolt, err := OpenBoltState(filepath.Join(dir, "migrate.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bolt.Close()
	if err := bolt.ImportState(again.state); err != nil {
		t.Fatal(err)
	}
	exported, err := bolt.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if back, ok := exported.CheckDefinitions["chk_a"]; !ok || !back.Targets.All {
		t.Fatalf("migrate round trip lost the definition: %+v", exported.CheckDefinitions)
	}
}
