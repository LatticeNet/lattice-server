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
// is refused and leaves the first in place.
func TestEvidenceSettingsVersioning(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	if _, ok := s.EvidenceSettings(); ok {
		t.Fatal("a fresh store has stored evidence settings")
	}
	in := model.EvidenceSettings{
		TraceDBMaxBytes: 1 << 30, RecordTTLSeconds: 7 * 86400, LineTTLSeconds: 86400,
		Rollup5mTTLSeconds: 30 * 86400, RawSourceMaxBytes: 32 << 20,
		// A client cannot choose the version or the author.
		Version: 41, UpdatedBy: "someone-else",
	}
	at := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	stored, err := s.SetEvidenceSettings(in, 0, "user-a", at)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Version != 1 || stored.UpdatedBy != "user-a" || !stored.UpdatedAt.Equal(at) || stored.TraceDBMaxBytes != 1<<30 {
		t.Fatalf("stored = %+v", stored)
	}
	if _, err := s.SetEvidenceSettings(in, 0, "user-b", at); !errors.Is(err, ErrEvidenceSettingsVersion) {
		t.Fatalf("a stale save = %v, want ErrEvidenceSettingsVersion", err)
	}
	if got, _ := s.EvidenceSettings(); got.UpdatedBy != "user-a" || got.Version != 1 {
		t.Fatalf("a refused save changed the stored settings: %+v", got)
	}
	in.RecordTTLSeconds = 3 * 86400
	next, err := s.SetEvidenceSettings(in, 1, "user-b", at.Add(time.Minute))
	if err != nil || next.Version != 2 || next.RecordTTLSeconds != 3*86400 {
		t.Fatalf("a save from version 1 = %+v, %v", next, err)
	}
}

// The settings survive a restart and the offline migrate round trip, because
// they are what bounds trace.db and must outlive it.
func TestEvidenceSettingsPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	cfg := model.EvidenceSettings{
		TraceDBMaxBytes: 512 << 20, RecordTTLSeconds: 86400, LineTTLSeconds: 3600,
		Rollup5mTTLSeconds: 86400, RawSourceMaxBytes: 1 << 20,
	}
	if _, err := s.SetEvidenceSettings(cfg, 0, "user-a", time.Now()); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reopened.EvidenceSettings()
	if !ok || got.Version != 1 || got.TraceDBMaxBytes != 512<<20 || got.RawSourceMaxBytes != 1<<20 {
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
	if exported.EvidenceSettings == nil || exported.EvidenceSettings.Version != 1 || exported.EvidenceSettings.LineTTLSeconds != 3600 {
		t.Fatalf("migrate round trip lost the settings: %+v", exported.EvidenceSettings)
	}
}
