package audit

import (
	"encoding/json"
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

func TestAnchoredWALDetectsEndTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.wal")
	anchorPath := path + ".anchor"
	w, err := OpenAnchoredWAL(path, anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"a", "b", "c"} {
		if err := w.Append(ev(id, "act"+string(rune('0'+i)))); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()

	res, err := VerifyAnchoredFile(path, anchorPath)
	if err != nil {
		t.Fatalf("verify anchored: %v", err)
	}
	if res.Count != 3 || res.Anchor == nil || res.Anchor.Count != 3 || res.Anchor.Head != res.Head {
		t.Fatalf("unexpected anchored result: %+v", res)
	}

	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 wal lines, got %d", len(lines))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines[:2], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAnchoredFile(path, anchorPath); err == nil || !strings.Contains(err.Error(), "anchor mismatch") {
		t.Fatalf("end-truncated WAL must fail anchor verification, got %v", err)
	}
	if _, err := OpenAnchoredWAL(path, anchorPath); err == nil {
		t.Fatal("OpenAnchoredWAL must refuse to extend an end-truncated chain")
	}
}

func TestOpenAnchoredWALBootstrapsExistingChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.wal")
	anchorPath := path + ".anchor"
	w, err := OpenWAL(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(ev("a", "first")); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(ev("b", "second")); err != nil {
		t.Fatal(err)
	}
	w.Close()
	if _, err := os.Stat(anchorPath); !os.IsNotExist(err) {
		t.Fatalf("anchor should not exist before anchored open, err=%v", err)
	}

	w2, err := OpenAnchoredWAL(path, anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	w2.Close()
	res, err := VerifyAnchoredFile(path, anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 2 || res.Anchor == nil || res.Anchor.Count != 2 || res.Anchor.Head != res.Head {
		t.Fatalf("unexpected bootstrapped anchor: %+v", res)
	}
}

func TestOpenAnchoredWALFinalizesPendingAfterCrash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.wal")
	anchorPath := path + ".anchor"
	w, err := OpenWAL(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(ev("a", "first")); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(ev("b", "second")); err != nil {
		t.Fatal(err)
	}
	w.Close()

	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 wal lines, got %d", len(lines))
	}
	var first, second Entry
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatal(err)
	}
	if err := writeAnchor(anchorPath, anchorWithPending(first.Seq, first.Hash, &AnchorCheckpoint{Count: second.Seq, Head: second.Hash})); err != nil {
		t.Fatal(err)
	}

	w2, err := OpenAnchoredWAL(path, anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	w2.Close()
	anchor, ok, err := readAnchor(anchorPath)
	if err != nil || !ok {
		t.Fatalf("read anchor ok=%v err=%v", ok, err)
	}
	if anchor.Count != 2 || anchor.Head != second.Hash || anchor.Pending != nil {
		t.Fatalf("pending anchor was not finalized: %+v", anchor)
	}
}
