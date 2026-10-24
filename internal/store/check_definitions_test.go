package store

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

// A definition's secret header values are encrypted at rest, as its
// monitors' are, in the state file and in the migrate round trip.
func TestCheckDefinitionSecretsEncryptedAtRest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	cph := testCipher(t)
	s, err := OpenWithCipher(path, cph)
	if err != nil {
		t.Fatal(err)
	}
	def := model.CheckDefinition{
		ID:                  "chk_a",
		CheckDefinitionSpec: model.CheckDefinitionSpec{Name: "a", Type: model.MonitorTypeHTTP, Addresses: []string{"https://api.example.com/x"}},
		Headers:             []model.MonitorHeader{{Name: "X-Api-Key", Value: "s3cret-value", Secret: true}, {Name: "Accept", Value: "text/plain"}},
	}
	if _, _, err := s.SaveCheckDefinition(def, 0, "admin", nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "s3cret-value") {
		t.Fatal("the state file holds the secret header value in plaintext")
	}
	if !strings.Contains(string(raw), "text/plain") {
		t.Fatal("a plain header should stay readable")
	}
	again, err := OpenWithCipher(path, cph)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := again.CheckDefinition("chk_a")
	if len(got.Headers) != 2 || got.Headers[0].Value != "s3cret-value" {
		t.Fatalf("reopened headers = %+v", got.Headers)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("opening the state without the key should refuse, not read envelopes as values")
	}
	bolt, err := OpenBoltState(filepath.Join(dir, "migrate.db"), cph)
	if err != nil {
		t.Fatal(err)
	}
	defer bolt.Close()
	if err := bolt.ImportState(again.state); err != nil {
		t.Fatal(err)
	}
	dbRaw, err := os.ReadFile(filepath.Join(dir, "migrate.db"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(dbRaw), "s3cret-value") {
		t.Fatal("the bolt file holds the secret header value in plaintext")
	}
	exported, err := bolt.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if back := exported.CheckDefinitions["chk_a"]; len(back.Headers) != 2 || back.Headers[0].Value != "s3cret-value" {
		t.Fatalf("migrate round trip headers = %+v", back.Headers)
	}
}

// A save whose state write fails leaves memory as it was: no definition,
// no monitors.
func TestSaveCheckDefinitionRollsBackAFailedWrite(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	def := model.CheckDefinition{ID: "chk_a", CheckDefinitionSpec: model.CheckDefinitionSpec{Name: "a", Type: model.MonitorTypeTCP}}
	owner := CheckDefinitionOwner(def.ID)
	if _, _, err := s.SaveCheckDefinition(def, 0, "admin", map[string][]model.Monitor{owner: {checkMon("mon_chk_a_1", owner, 60)}}, time.Now()); err == nil {
		t.Fatal("a save into a read-only directory succeeded")
	}
	if _, ok := s.CheckDefinition(def.ID); ok {
		t.Fatal("the definition survived a failed write")
	}
	if _, ok := s.Monitor("mon_chk_a_1"); ok {
		t.Fatal("the monitor survived a failed write")
	}
}

// The dry run and the sync judge by one rule: the same sets give the same
// changes, an id two owners want is refused by both, and an owner whose
// definition is gone keeps nothing unless the dry run assumes it exists.
func TestDiffManagedMonitorSetsMatchesTheSync(t *testing.T) {
	s := checkDefStore(t)
	now := time.Now()
	for _, id := range []string{"chk_a", "chk_b"} {
		if _, _, err := s.SaveCheckDefinition(model.CheckDefinition{ID: id, CheckDefinitionSpec: model.CheckDefinitionSpec{Name: id, Type: model.MonitorTypeTCP}}, 0, "admin", nil, now); err != nil {
			t.Fatal(err)
		}
	}
	a, b := CheckDefinitionOwner("chk_a"), CheckDefinitionOwner("chk_b")
	if _, err := s.SyncManagedMonitorSets(map[string][]model.Monitor{a: {checkMon("mon_chk_a_1", a, 60), checkMon("mon_chk_a_2", a, 60)}}, now); err != nil {
		t.Fatal(err)
	}
	sets := map[string][]model.Monitor{
		a: {checkMon("mon_chk_a_1", a, 120)},
		b: {checkMon("mon_chk_b_1", b, 60)},
	}
	diff, err := s.DiffManagedMonitorSets(sets)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := s.SyncManagedMonitorSets(sets, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{a, b} {
		if !slices.Equal(diff[owner].Created, applied[owner].Created) || !slices.Equal(diff[owner].Updated, applied[owner].Updated) || !slices.Equal(diff[owner].Deleted, applied[owner].Deleted) {
			t.Fatalf("%s: dry run %+v, sync %+v", owner, diff[owner], applied[owner])
		}
	}
	twice := map[string][]model.Monitor{a: {checkMon("mon_x", a, 60)}, b: {checkMon("mon_x", b, 60)}}
	if _, err := s.DiffManagedMonitorSets(twice); err == nil {
		t.Fatal("the dry run accepted an id two owners want")
	}
	if _, err := s.SyncManagedMonitorSets(twice, now); err == nil {
		t.Fatal("the sync accepted an id two owners want")
	}
	ghost := CheckDefinitionOwner("chk_new")
	ghostSet := map[string][]model.Monitor{ghost: {checkMon("mon_chk_new_1", ghost, 60)}}
	if diff, _ := s.DiffManagedMonitorSets(ghostSet); diff[ghost].Changed() {
		t.Fatalf("an owner with no definition would get monitors: %+v", diff[ghost])
	}
	if diff, _ := s.DiffManagedMonitorSets(ghostSet, "chk_new"); len(diff[ghost].Created) != 1 {
		t.Fatalf("a dry run of a create should show its monitors: %+v", diff[ghost])
	}
}
