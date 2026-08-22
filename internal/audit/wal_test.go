package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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

func TestWALIdempotentRetryRepairsFinalAnchorWithoutDuplicate(t *testing.T) {
	dir := t.TempDir()
	path, anchorPath := filepath.Join(dir, "audit.wal"), filepath.Join(dir, "audit.anchor")
	w, err := OpenAnchoredWAL(path, anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	realWrite := w.writeAnchor
	writes := 0
	w.writeAnchor = func(path string, anchor Anchor) error {
		writes++
		if writes == 2 {
			return os.ErrPermission
		}
		return realWrite(path, anchor)
	}
	event := ev("exact-id", "linechain.apply")
	if committed, err := w.AppendIdempotent(event); !committed || err == nil {
		t.Fatalf("append committed=%v err=%v", committed, err)
	}
	w.writeAnchor = realWrite
	if committed, err := w.AppendIdempotent(event); committed || err != nil {
		t.Fatalf("retry committed=%v err=%v", committed, err)
	}
	if committed, err := w.AppendIdempotent(ev("exact-id", "linechain.failed")); committed || err == nil {
		t.Fatalf("conflicting retry committed=%v err=%v", committed, err)
	}
	if result, err := verifyFile(t, path); err != nil || result.Count != 1 {
		t.Fatalf("verify=%+v err=%v", result, err)
	}
	anchor, ok, err := readAnchor(anchorPath)
	if err != nil || !ok || anchor.Count != 1 || anchor.Pending != nil {
		t.Fatalf("final anchor was not repaired: anchor=%+v ok=%v err=%v", anchor, ok, err)
	}
}

func TestOpenWALRejectsDuplicateEventIDs(t *testing.T) {
	for _, conflicting := range []bool{false, true} {
		t.Run(fmt.Sprintf("conflicting_%v", conflicting), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.wal")
			w, err := OpenWAL(path)
			if err != nil {
				t.Fatal(err)
			}
			first := ev("duplicate-id", "linechain.apply")
			if err := w.Append(first); err != nil {
				t.Fatal(err)
			}
			second := first
			if conflicting {
				second.Action = "linechain.failed"
			}
			if err := w.Append(second); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenWAL(path); err == nil || !strings.Contains(err.Error(), "duplicate event id") {
				t.Fatalf("duplicate WAL id was accepted: %v", err)
			}
		})
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

// buildWAL writes a valid chain of events directly, without paying one fsync
// per record. The open path is what this file is testing; how the bytes got
// there is not.
func buildWAL(t *testing.T, path string, count int, metadata string) int64 {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	prev := genesisHash
	for seq := 1; seq <= count; seq++ {
		e := ev(fmt.Sprintf("audit_%08d", seq), "node.update")
		e.Metadata = map[string]string{"payload": metadata}
		hash, err := ChainHash(prev, seq, e)
		if err != nil {
			t.Fatal(err)
		}
		line, err := json.Marshal(Entry{Seq: seq, PrevHash: prev, Hash: hash, Event: e})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(append(line, '\n')); err != nil {
			t.Fatal(err)
		}
		prev = hash
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

// The WAL is opened on every server boot, and the duplicate-id index it builds
// there is retained for the life of the process. Holding whole decoded events
// made that index cost several times the file on disk: a 510 MB production WAL
// put the server at 3.5 GB resident before it could listen, on a 3.8 GB host,
// which OOM-killed it in a loop. The index only ever decides "same id, same
// bytes?", so a fingerprint per id answers it without keeping the bytes.
func TestOpenWALIndexDoesNotGrowWithEventBodies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.wal")
	size := buildWAL(t, path, 1000, strings.Repeat("x", 4096))

	runtime.GC()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	w, err := OpenWAL(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	runtime.GC()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(w)

	retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	limit := size / 4
	if retained > limit {
		t.Fatalf("opening a %d byte WAL retained %d bytes of heap, over the %d byte limit; the duplicate-id index is holding event bodies", size, retained, limit)
	}
}

// Fingerprinting must not weaken the contract the index exists for: a replayed
// event is still skipped, and a different event reusing a durable id is still
// refused.
func TestAppendIdempotentStillSeparatesReplayFromConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.wal")
	buildWAL(t, path, 3, "small")

	w, err := OpenWAL(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	replay := ev("audit_00000002", "node.update")
	replay.Metadata = map[string]string{"payload": "small"}
	appended, err := w.AppendIdempotent(replay)
	if err != nil {
		t.Fatalf("replaying a durable event must not error: %v", err)
	}
	if appended {
		t.Fatal("replaying a durable event must not append a second copy")
	}

	conflict := replay
	conflict.Metadata = map[string]string{"payload": "tampered"}
	if _, err := w.AppendIdempotent(conflict); err == nil {
		t.Fatal("a different event reusing a durable id must be refused")
	}
}
