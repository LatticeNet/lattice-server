package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func enableReminders(p model.MachineProfile) (model.MachineProfile, bool) {
	if p.RemindersEnabled {
		return p, false
	}
	p.RemindersEnabled = true
	return p, true
}

// The migration runs once per store: the marker lands in the same write as
// the profiles it changed, survives a reopen, and a second call is a no-op
// even after the operator has undone the change.
func TestMigrateMachineProfilesOnceRunsOncePerStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []model.MachineProfile{{ID: "mp-a", NodeID: "node-a"}, {ID: "mp-b", NodeID: "node-b", RemindersEnabled: true}} {
		if err := s.UpsertMachineProfile(p); err != nil {
			t.Fatal(err)
		}
	}
	changed, ran, err := s.MigrateMachineProfilesOnce("reminders_default_on", enableReminders)
	if err != nil || !ran || len(changed) != 1 || changed[0] != "mp-a" {
		t.Fatalf("first run: changed=%v ran=%v err=%v", changed, ran, err)
	}
	if p, _ := s.MachineProfile("mp-a"); !p.RemindersEnabled {
		t.Fatalf("mp-a not migrated: %+v", p)
	}

	// The operator turns it back off; a restart must not turn it on again.
	off, _ := s.MachineProfile("mp-a")
	off.RemindersEnabled = false
	if err := s.UpsertMachineProfile(off); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	changed, ran, err = reopened.MigrateMachineProfilesOnce("reminders_default_on", enableReminders)
	if err != nil || ran || len(changed) != 0 {
		t.Fatalf("second run: changed=%v ran=%v err=%v", changed, ran, err)
	}
	if p, _ := reopened.MachineProfile("mp-a"); p.RemindersEnabled {
		t.Fatalf("operator's choice was overwritten: %+v", p)
	}
}

// A store carried through bbolt and back keeps its markers, so the round trip
// cannot re-arm a migration that already ran.
func TestMigrationMarkersSurviveBoltRoundTrip(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "state.json")
	boltPath := filepath.Join(dir, "state.db")
	exportPath := filepath.Join(dir, "state.export.json")
	c := testCipher(t)
	now := time.Unix(1_700_000_001, 0).UTC()

	st := seedMigrationState(now)
	st.Migrations["reminders_default_on"] = now
	if err := WriteJSONState(jsonPath, st, c, MigrationOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := MigrateJSONToBolt(jsonPath, boltPath, c, MigrationOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := ExportBoltToJSON(boltPath, exportPath, c, MigrationOptions{}); err != nil {
		t.Fatal(err)
	}
	back, err := LoadJSONState(exportPath, c)
	if err != nil {
		t.Fatal(err)
	}
	if got := back.Migrations["reminders_default_on"]; !got.Equal(now) {
		t.Fatalf("marker after round trip = %v, want %v (all: %v)", got, now, back.Migrations)
	}
}
