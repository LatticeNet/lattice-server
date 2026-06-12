package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
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
