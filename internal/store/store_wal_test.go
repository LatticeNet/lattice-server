package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/audit"
)

func TestStoreAuditWALTamperEvident(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := s.AppendAudit(model.AuditEvent{ID: "e" + string(rune('0'+i)), Action: "act", Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	res, enabled, err := s.AuditWALVerify()
	if !enabled || err != nil || res.Count != 3 {
		t.Fatalf("expected a verified chain of 3, got enabled=%v count=%d err=%v", enabled, res.Count, err)
	}
	s.Close()

	walPath := path + ".audit-wal"
	raw, _ := os.ReadFile(walPath)
	os.WriteFile(walPath, []byte(strings.Replace(string(raw), "allow", "deny", 1)), 0o600)

	if _, err := Open(path); err == nil {
		t.Fatal("Open must fail when the audit WAL chain is corrupt")
	}
}

func TestStoreAuditWALAnchorDetectsEndTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := s.AppendAudit(model.AuditEvent{ID: "e" + string(rune('0'+i)), Action: "act", Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	res, enabled, err := s.AuditWALVerify()
	if !enabled || err != nil || res.Count != 3 || res.Anchor == nil || res.Anchor.Count != 3 {
		t.Fatalf("expected anchored verified chain of 3, got enabled=%v res=%+v err=%v", enabled, res, err)
	}
	s.Close()

	anchorPath := path + ".audit-anchor"
	if _, err := os.Stat(anchorPath); err != nil {
		t.Fatalf("expected audit anchor file: %v", err)
	}
	walPath := path + ".audit-wal"
	raw, _ := os.ReadFile(walPath)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 wal lines, got %d", len(lines))
	}
	if err := os.WriteFile(walPath, []byte(strings.Join(lines[:2], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "anchor mismatch") {
		t.Fatalf("Open must fail when the audit WAL tail is truncated, got %v", err)
	}
}

func TestStoreAuditWALAnchorBootstrapsExistingWAL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	walPath := path + ".audit-wal"
	anchorPath := path + ".audit-anchor"
	w, err := audit.OpenWAL(walPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(model.AuditEvent{ID: "e0", Action: "act", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	w.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := os.Stat(anchorPath); err != nil {
		t.Fatalf("expected bootstrapped audit anchor file: %v", err)
	}
	res, enabled, err := s.AuditWALVerify()
	if !enabled || err != nil || res.Count != 1 || res.Anchor == nil || res.Anchor.Count != 1 {
		t.Fatalf("expected bootstrapped anchored chain of 1, got enabled=%v res=%+v err=%v", enabled, res, err)
	}
}

func TestStoreNoWALForInMemory(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AppendAudit(model.AuditEvent{ID: "x", Action: "act"}); err != nil {
		t.Fatal(err)
	}
	if _, enabled, err := s.AuditWALVerify(); enabled || err != nil {
		t.Fatalf("in-memory store should report WAL disabled, got enabled=%v err=%v", enabled, err)
	}
}
