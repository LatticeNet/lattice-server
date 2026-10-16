package store

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-server/internal/secret"
)

func probeTarget(id string) ProbeTarget {
	return ProbeTarget{ID: id, Label: "Edge", URL: "https://edge.example.net/health", Method: "GET", ExpectStatus: "204"}
}

func TestProbeTargetsCreateUpdateDelete(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC)
	first, err := s.CreateProbeTarget(probeTarget("custom-edge"), 32, at)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != "custom-edge" || first.Version != 1 || !first.CreatedAt.Equal(at) || !first.UpdatedAt.Equal(at) {
		t.Fatalf("created %+v", first)
	}
	second, err := s.CreateProbeTarget(probeTarget("custom-edge"), 32, at.Add(time.Second))
	if err != nil || second.ID != "custom-edge-2" {
		t.Fatalf("second create %+v %v, want custom-edge-2", second, err)
	}
	long := "custom-" + strings.Repeat("a", 33)
	if _, err := s.CreateProbeTarget(probeTarget(long), 32, at); err != nil {
		t.Fatal(err)
	}
	clipped, err := s.CreateProbeTarget(probeTarget(long), 32, at.Add(2*time.Second))
	if err != nil || len(clipped.ID) != 40 || !strings.HasSuffix(clipped.ID, "-2") {
		t.Fatalf("clipped id %q %v", clipped.ID, err)
	}

	edited := first
	edited.Label, edited.URL, edited.Version, edited.CreatedAt = "Edge HEAD", "https://edge.example.net/", 99, time.Time{}
	updated, err := s.UpdateProbeTarget(edited, 1, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if updated.Version != 2 || !updated.CreatedAt.Equal(at) || !updated.UpdatedAt.Equal(at.Add(time.Hour)) || updated.Label != "Edge HEAD" {
		t.Fatalf("updated %+v", updated)
	}
	if _, err := s.UpdateProbeTarget(edited, 1, at); !errors.Is(err, ErrProbeTargetVersion) {
		t.Fatalf("stale update = %v, want ErrProbeTargetVersion", err)
	}
	if _, err := s.UpdateProbeTarget(probeTarget("custom-nope"), 1, at); !errors.Is(err, ErrProbeTargetNotFound) {
		t.Fatalf("update of a missing target = %v", err)
	}
	if _, err := s.DeleteProbeTarget("custom-edge", 1); !errors.Is(err, ErrProbeTargetVersion) {
		t.Fatalf("stale delete = %v, want ErrProbeTargetVersion", err)
	}
	if _, err := s.DeleteProbeTarget("custom-nope", 1); !errors.Is(err, ErrProbeTargetNotFound) {
		t.Fatalf("delete of a missing target = %v", err)
	}
	removed, err := s.DeleteProbeTarget("custom-edge", 2)
	if err != nil || removed.Label != "Edge HEAD" {
		t.Fatalf("delete %+v %v", removed, err)
	}

	list := s.ProbeTargets()
	if len(list) != 3 || list[0].ID != long || list[1].ID != "custom-edge-2" || list[2].ID != clipped.ID {
		ids := []string{}
		for _, t := range list {
			ids = append(ids, t.ID)
		}
		t.Fatalf("list order %v", ids)
	}
	found, missing := s.ProbeTargetsByID([]string{"custom-edge-2", "custom-edge", "gstatic-204"})
	if len(found) != 1 || found[0].ID != "custom-edge-2" || len(missing) != 2 || missing[0] != "custom-edge" {
		t.Fatalf("by id: %+v missing %v", found, missing)
	}
}

func TestProbeTargetsLimit(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := s.CreateProbeTarget(probeTarget("custom-edge"), 3, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.CreateProbeTarget(probeTarget("custom-other"), 3, time.Now()); !errors.Is(err, ErrProbeTargetLimit) {
		t.Fatalf("create past the limit = %v", err)
	}
	if n := len(s.ProbeTargets()); n != 3 {
		t.Fatalf("%d targets after a refused create", n)
	}
}

func TestProbeTargetsPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	in := probeTarget("custom-edge")
	in.BodyContains = "ok"
	if _, err := s.CreateProbeTarget(in, 32, time.Now()); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	got := reopened.ProbeTargets()
	if len(got) != 1 || got[0].BodyContains != "ok" || got[0].Version != 1 {
		t.Fatalf("after reopen: %+v", got)
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
	if exported.ProbeTargets["custom-edge"].URL != in.URL || exported.ProbeTargets["custom-edge"].BodyContains != "ok" {
		t.Fatalf("migrate round trip lost the targets: %+v", exported.ProbeTargets)
	}
}
