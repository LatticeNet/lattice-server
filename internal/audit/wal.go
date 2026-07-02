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
	"path/filepath"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// genesisHash anchors the head of an empty chain.
const genesisHash = "lattice-audit-genesis-v1"

const anchorVersion = 1

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
	Count  int     `json:"count"`
	Head   string  `json:"head"`
	Anchor *Anchor `json:"anchor,omitempty"`
}

// AnchorCheckpoint is a recorded audit WAL head.
type AnchorCheckpoint struct {
	Count int    `json:"count"`
	Head  string `json:"head"`
}

// Anchor is the durable sidecar head used to detect end-truncation. Pending is
// written before the WAL append and cleared after the append is fsync'd, so a
// crash can be reconciled without trusting a shorter WAL.
type Anchor struct {
	Version   int               `json:"version"`
	Count     int               `json:"count"`
	Head      string            `json:"head"`
	Pending   *AnchorCheckpoint `json:"pending,omitempty"`
	UpdatedAt time.Time         `json:"updated_at"`
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
	mu         sync.Mutex
	f          *os.File
	seq        int
	head       string
	anchorPath string
}

// OpenWAL opens (creating if needed) the append-only audit WAL at path and
// recovers the chain head by verifying existing records. It fails loudly if the
// existing chain does not verify, so corruption cannot be silently extended.
func OpenWAL(path string) (*WAL, error) {
	return openWAL(path, "")
}

// OpenAnchoredWAL opens a WAL with a separate sidecar anchor file. Existing WALs
// without an anchor are bootstrapped to their current verified head; after that,
// the anchor is authoritative for detecting end-truncation.
func OpenAnchoredWAL(path, anchorPath string) (*WAL, error) {
	if anchorPath == "" {
		return OpenWAL(path)
	}
	return openWAL(path, anchorPath)
}

func openWAL(path, anchorPath string) (*WAL, error) {
	res, err := verifyWALPath(path)
	if err != nil {
		return nil, fmt.Errorf("audit wal verify on open: %w", err)
	}
	if anchorPath != "" {
		anchored, err := ensureAnchor(anchorPath, res)
		if err != nil {
			return nil, err
		}
		res = anchored
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	return &WAL{f: f, seq: res.Count, head: res.Head, anchorPath: anchorPath}, nil
}

// Append writes ev as the next chained record and fsyncs before returning.
func (w *WAL) Append(ev model.AuditEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return errors.New("audit wal is closed")
	}
	seq := w.seq + 1
	hash, err := ChainHash(w.head, seq, ev)
	if err != nil {
		return err
	}
	next := AnchorCheckpoint{Count: seq, Head: hash}
	if w.anchorPath != "" {
		if err := writeAnchor(w.anchorPath, anchorWithPending(w.seq, w.head, &next)); err != nil {
			return err
		}
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
	if w.anchorPath != "" {
		if err := writeAnchor(w.anchorPath, anchorCommitted(seq, hash)); err != nil {
			return err
		}
	}
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

// VerifyAnchoredFile verifies a WAL and then checks that its current head still
// matches the sidecar anchor. It returns the verified WAL result even when the
// anchor check fails, so callers can report the observed head to operators.
func VerifyAnchoredFile(walPath, anchorPath string) (Result, error) {
	res, err := verifyWALPath(walPath)
	if err != nil {
		return res, err
	}
	if anchorPath == "" {
		return res, nil
	}
	anchor, ok, err := readAnchor(anchorPath)
	if err != nil {
		return res, fmt.Errorf("audit wal anchor read: %w", err)
	}
	if !ok {
		return res, fmt.Errorf("audit wal anchor missing: %s", anchorPath)
	}
	res.Anchor = &anchor
	if !anchorMatchesResult(anchor, res) {
		return res, anchorMismatchError(anchor, res)
	}
	return res, nil
}

func verifyWALPath(path string) (Result, error) {
	existing, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return Result{Count: 0, Head: genesisHash}, nil
	}
	if err != nil {
		return Result{}, err
	}
	defer existing.Close()
	return Verify(existing)
}

func ensureAnchor(path string, res Result) (Result, error) {
	anchor, ok, err := readAnchor(path)
	if err != nil {
		return res, fmt.Errorf("audit wal anchor read: %w", err)
	}
	if !ok {
		anchor = anchorCommitted(res.Count, res.Head)
		if err := writeAnchor(path, anchor); err != nil {
			return res, fmt.Errorf("audit wal anchor bootstrap: %w", err)
		}
		res.Anchor = &anchor
		return res, nil
	}
	res.Anchor = &anchor
	if anchor.Count == res.Count && anchor.Head == res.Head {
		if anchor.Pending != nil {
			anchor = anchorCommitted(res.Count, res.Head)
			if err := writeAnchor(path, anchor); err != nil {
				return res, fmt.Errorf("audit wal anchor clear pending: %w", err)
			}
			res.Anchor = &anchor
		}
		return res, nil
	}
	if anchor.Pending != nil && anchor.Pending.Count == res.Count && anchor.Pending.Head == res.Head {
		anchor = anchorCommitted(res.Count, res.Head)
		if err := writeAnchor(path, anchor); err != nil {
			return res, fmt.Errorf("audit wal anchor finalize pending: %w", err)
		}
		res.Anchor = &anchor
		return res, nil
	}
	return res, anchorMismatchError(anchor, res)
}

func anchorMatchesResult(anchor Anchor, res Result) bool {
	if anchor.Count == res.Count && anchor.Head == res.Head {
		return true
	}
	return anchor.Pending != nil && anchor.Pending.Count == res.Count && anchor.Pending.Head == res.Head
}

func anchorMismatchError(anchor Anchor, res Result) error {
	pending := "none"
	if anchor.Pending != nil {
		pending = fmt.Sprintf("count=%d head=%s", anchor.Pending.Count, anchor.Pending.Head)
	}
	return fmt.Errorf("audit wal anchor mismatch: anchor count=%d head=%s pending=%s, wal count=%d head=%s", anchor.Count, anchor.Head, pending, res.Count, res.Head)
}

func readAnchor(path string) (Anchor, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Anchor{}, false, nil
	}
	if err != nil {
		return Anchor{}, false, err
	}
	var anchor Anchor
	if err := json.Unmarshal(data, &anchor); err != nil {
		return Anchor{}, false, err
	}
	if anchor.Version != anchorVersion {
		return Anchor{}, false, fmt.Errorf("unsupported anchor version %d", anchor.Version)
	}
	if anchor.Count < 0 || anchor.Head == "" {
		return Anchor{}, false, errors.New("invalid committed anchor")
	}
	if anchor.Pending != nil && (anchor.Pending.Count < 0 || anchor.Pending.Head == "") {
		return Anchor{}, false, errors.New("invalid pending anchor")
	}
	return anchor, true, nil
}

func anchorCommitted(count int, head string) Anchor {
	return Anchor{
		Version:   anchorVersion,
		Count:     count,
		Head:      head,
		UpdatedAt: time.Now().UTC(),
	}
}

func anchorWithPending(count int, head string, pending *AnchorCheckpoint) Anchor {
	anchor := anchorCommitted(count, head)
	if pending != nil {
		cp := *pending
		anchor.Pending = &cp
	}
	return anchor
}

func writeAnchor(path string, anchor Anchor) error {
	data, err := json.Marshal(anchor)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := path + ".tmp"
	if err := writeSyncedFile(tmp, data, 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}

func writeSyncedFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
