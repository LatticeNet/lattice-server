package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func ev(id, action string) model.AuditEvent {
	return model.AuditEvent{
		ID: id, At: time.Unix(1_700_000_000, 0).UTC(), Action: action,
		Decision: "allow", Metadata: map[string]string{"b": "2", "a": "1"},
	}
}

func verifyFile(t *testing.T, path string) (Result, error) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return Verify(f)
}

func TestWALAppendAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.wal")
	w, err := OpenWAL(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := w.Append(ev("id"+string(rune('0'+i)), "act")); err != nil {
			t.Fatal(err)
		}
	}
	head, n := w.Head()
	if n != 5 || head == "" {
		t.Fatalf("head=%q n=%d", head, n)
	}
	w.Close()

	res, err := verifyFile(t, path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Count != 5 || res.Head != head {
		t.Fatalf("res=%+v head=%q", res, head)
	}

	// reopening recovers the head and lets the chain continue intact
	w2, err := OpenWAL(path)
	if err != nil {
		t.Fatal(err)
	}
	if h, c := w2.Head(); h != head || c != 5 {
		t.Fatalf("reopened head=%q count=%d", h, c)
	}
	w2.Append(ev("id5", "act"))
	w2.Close()
	if res, err := verifyFile(t, path); err != nil || res.Count != 6 {
		t.Fatalf("post-append verify: %+v %v", res, err)
	}
}

func TestWALDetectsEditReorderAndGap(t *testing.T) {
	build := func(t *testing.T) (string, []string) {
		path := filepath.Join(t.TempDir(), "audit.wal")
		w, _ := OpenWAL(path)
		w.Append(ev("a", "first"))
		w.Append(ev("b", "second"))
		w.Append(ev("c", "third"))
		w.Close()
		raw, _ := os.ReadFile(path)
		return path, strings.Split(strings.TrimSpace(string(raw)), "\n")
	}

	// edit a middle event
	path, lines := build(t)
	os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
	if _, err := verifyFile(t, path); err != nil {
		t.Fatalf("untouched chain should verify: %v", err)
	}
	os.WriteFile(path, []byte(strings.Replace(strings.Join(lines, "\n"), "second", "SECOND", 1)+"\n"), 0o600)
	if _, err := verifyFile(t, path); err == nil {
		t.Fatal("edited event must fail verification")
	}

	// reorder
	path, lines = build(t)
	os.WriteFile(path, []byte(lines[1]+"\n"+lines[0]+"\n"+lines[2]+"\n"), 0o600)
	if _, err := verifyFile(t, path); err == nil {
		t.Fatal("reordered records must fail verification")
	}

	// mid-truncation (delete a record)
	path, lines = build(t)
	os.WriteFile(path, []byte(lines[0]+"\n"+lines[2]+"\n"), 0o600)
	if _, err := verifyFile(t, path); err == nil {
		t.Fatal("deleted record must fail verification")
	}
}

func TestOpenWALRejectsCorruptExistingChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.wal")
	w, _ := OpenWAL(path)
	w.Append(ev("a", "first"))
	w.Close()
	raw, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(raw), "first", "FORGED", 1)), 0o600)
	if _, err := OpenWAL(path); err == nil {
		t.Fatal("OpenWAL must refuse to extend a corrupt chain")
	}
}
