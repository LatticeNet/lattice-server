package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/LatticeNet/lattice-sdk/model"
)

// genesisHash anchors the head of an empty chain.
const genesisHash = "lattice-audit-genesis-v1"

// Entry is one tamper-evident audit record: the event plus its position and the
// hash that chains it to the previous record.
type Entry struct {
	Seq      int              `json:"seq"`
	PrevHash string           `json:"prev_hash"`
	Hash     string           `json:"hash"`
	Event    model.AuditEvent `json:"event"`
}

// ChainHash binds an event to its position and the preceding chain. Any change to
// the event, its sequence number, or any earlier record changes this value.
// json.Marshal is deterministic here: AuditEvent has a fixed field order and
// encoding/json sorts map keys, so Metadata serialises stably.
func ChainHash(prevHash string, seq int, ev model.AuditEvent) (string, error) {
	body, err := json.Marshal(ev)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%d\n", prevHash, seq)
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Result summarises a chain verification.
type Result struct {
	Count int    `json:"count"`
	Head  string `json:"head"`
}

// Verify walks an audit WAL and validates the hash chain: sequence numbers must
// be contiguous from 1, each prev_hash must match the running head, and each hash
// must equal the recomputed ChainHash. It returns the verified count and head, or
// an error naming the first inconsistency (edit, reorder, gap, or mid-truncation).
// Truncation at the very end is detected by comparing the returned Head against an
// independently-anchored head (e.g. one shipped off-box).
func Verify(r io.Reader) (Result, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	prev := genesisHash
	count := 0
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec Entry
		if err := json.Unmarshal(line, &rec); err != nil {
			return Result{}, fmt.Errorf("record %d: malformed: %w", count+1, err)
		}
		want := count + 1
		if rec.Seq != want {
			return Result{}, fmt.Errorf("record %d: out-of-order seq %d", want, rec.Seq)
		}
		if rec.PrevHash != prev {
			return Result{}, fmt.Errorf("record %d: prev_hash mismatch (chain broken)", want)
		}
		hash, err := ChainHash(prev, rec.Seq, rec.Event)
		if err != nil {
			return Result{}, err
		}
		if hash != rec.Hash {
			return Result{}, fmt.Errorf("record %d: hash mismatch (event tampered)", want)
		}
		prev = rec.Hash
		count++
	}
	if err := sc.Err(); err != nil {
		return Result{}, err
	}
	return Result{Count: count, Head: prev}, nil
}

// WAL is an append-only, hash-chained audit log file. It is the durable,
// tamper-evident channel: it is only ever appended to and fsync'd, so a rewrite
// of the main JSON state cannot silently erase audit history, and any edit,
// reorder, or truncation of the WAL itself is detectable by Verify.
type WAL struct {
	mu   sync.Mutex
	f    *os.File
	seq  int
	head string
}

// OpenWAL opens (creating if needed) the append-only audit WAL at path and
// recovers the chain head by verifying existing records. It fails loudly if the
// existing chain does not verify, so corruption cannot be silently extended.
func OpenWAL(path string) (*WAL, error) {
	if existing, err := os.Open(path); err == nil {
		res, verr := Verify(existing)
		existing.Close()
		if verr != nil {
			return nil, fmt.Errorf("audit wal verify on open: %w", verr)
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			return nil, err
		}
		return &WAL{f: f, seq: res.Count, head: res.Head}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	return &WAL{f: f, seq: 0, head: genesisHash}, nil
}

// Append writes ev as the next chained record and fsyncs before returning.
func (w *WAL) Append(ev model.AuditEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	seq := w.seq + 1
	hash, err := ChainHash(w.head, seq, ev)
	if err != nil {
		return err
	}
	line, err := json.Marshal(Entry{Seq: seq, PrevHash: w.head, Hash: hash, Event: ev})
	if err != nil {
		return err
	}
	if _, err := w.f.Write(append(line, '\n')); err != nil {
		return err
	}
	if err := w.f.Sync(); err != nil {
		return err
	}
	w.seq = seq
	w.head = hash
	return nil
}

// Head returns the current chain head hash and record count.
func (w *WAL) Head() (string, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.head, w.seq
}

// Close closes the underlying file.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
