// Package logstore is the dedicated, bounded, append-only persistence layer for
// ingested node log lines. It owns its own bbolt database (logs.db) and is
// deliberately NOT part of the whole-file JSON state store: log volume must
// never trigger a full state rewrite. Storage is append-O(record), time-ordered
// by a server-assigned per-source sequence, and bounded by a per-source byte cap
// with oldest-first eviction so disk can never grow unbounded.
package logstore

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
)

const (
	// DefaultMaxSourceBytes caps stored (post-encode) bytes per source; the
	// oldest chunks are evicted on append once exceeded.
	DefaultMaxSourceBytes = 64 << 20 // 64 MiB
	// DefaultQueryLimit / MaxQueryLimit bound a single query's line count.
	DefaultQueryLimit = 200
	MaxQueryLimit     = 1000
	metaBucketName    = "_meta"
	dataBucketPrefix  = "data:"
)

// Store is a bbolt-backed bounded log store.
type Store struct {
	db             *bolt.DB
	cipher         secret.Cipher
	maxSourceBytes uint64
	mu             sync.Mutex // guards meta read-modify-write sequencing across Append calls
}

// Meta is the per-source bookkeeping record (also the stats projection).
type Meta struct {
	FirstSeq     uint64    `json:"first_seq"`
	LastSeq      uint64    `json:"last_seq"`
	Bytes        uint64    `json:"bytes"`
	Lines        uint64    `json:"lines"`
	RotID        string    `json:"rot_id"`
	LastOff      uint64    `json:"last_off"`
	LastIngestAt time.Time `json:"last_ingest_at"`
}

// Filter is a per-source query. Cross-source merge is the server's job.
type Filter struct {
	SourceID  string
	Since     time.Time
	Until     time.Time
	Contains  string // case-insensitive substring; empty matches all
	Limit     int    // clamped to [1, MaxQueryLimit]; 0 => DefaultQueryLimit
	BeforeSeq uint64 // cursor: only chunks with Seq < BeforeSeq (0 => from newest)
}

// Result is a newest-first page of lines.
type Result struct {
	Lines         []model.LogLine
	NextBeforeSeq uint64 // pass back as Filter.BeforeSeq to page older; 0 => no more
	Truncated     bool   // a stored chunk failed to decode and was skipped
}

// Open opens (creating if needed) the log store at path. A nil or disabled
// cipher stores chunks in plaintext; an enabled cipher seals each chunk as a
// unit. maxSourceBytes<=0 uses DefaultMaxSourceBytes.
func Open(path string, cipher secret.Cipher, maxSourceBytes int64) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("logstore: path is required")
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("logstore: open %s: %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists([]byte(metaBucketName))
		return e
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("logstore: init: %w", err)
	}
	cap_ := uint64(DefaultMaxSourceBytes)
	if maxSourceBytes > 0 {
		cap_ = uint64(maxSourceBytes)
	}
	if cipher == nil {
		cipher = secret.Disabled()
	}
	return &Store{db: db, cipher: cipher, maxSourceBytes: cap_}, nil
}

// Close releases the underlying database.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Path returns the on-disk path of the database file.
func (s *Store) Path() string {
	if s == nil || s.db == nil {
		return ""
	}
	return s.db.Path()
}

func dataBucketName(sourceID string) []byte {
	return []byte(dataBucketPrefix + sourceID)
}

func be64(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

// Append packs lines into one chunk under the next sequence for sourceID,
// updates the source meta (rotID/lastOff/lastIngestAt from the batch context),
// and evicts oldest chunks until the per-source byte cap is honored. It returns
// the assigned chunk sequence. lines must already be truncated/validated by the
// caller; their Seq field is overwritten with the assigned sequence.
func (s *Store) Append(sourceID string, lines []model.LogLine, rotID string, lastOff uint64, at time.Time) (uint64, error) {
	if strings.TrimSpace(sourceID) == "" {
		return 0, fmt.Errorf("logstore: source id is required")
	}
	if len(lines) == 0 {
		return 0, fmt.Errorf("logstore: no lines to append")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var assigned uint64
	err := s.db.Update(func(tx *bolt.Tx) error {
		data, err := tx.CreateBucketIfNotExists(dataBucketName(sourceID))
		if err != nil {
			return err
		}
		meta := s.readMeta(tx, sourceID)
		assigned = meta.LastSeq + 1
		for i := range lines {
			lines[i].Seq = assigned
		}
		chunk, err := s.encodeChunk(lines)
		if err != nil {
			return err
		}
		if err := data.Put(be64(assigned), chunk); err != nil {
			return err
		}
		meta.LastSeq = assigned
		if meta.FirstSeq == 0 {
			meta.FirstSeq = assigned
		}
		meta.Bytes += uint64(len(chunk))
		meta.Lines += uint64(len(lines))
		meta.RotID = rotID
		meta.LastOff = lastOff
		meta.LastIngestAt = at.UTC()
		// Evict oldest chunks until under the byte cap.
		if err := s.evictToCap(data, &meta); err != nil {
			return err
		}
		return s.writeMeta(tx, sourceID, meta)
	})
	if err != nil {
		return 0, fmt.Errorf("logstore: append: %w", err)
	}
	return assigned, nil
}

// evictToCap deletes oldest chunks until meta.Bytes <= cap. It must run inside
// the same write tx as the append so the store is never observed over cap.
func (s *Store) evictToCap(data *bolt.Bucket, meta *Meta) error {
	for meta.Bytes > s.maxSourceBytes && meta.FirstSeq <= meta.LastSeq {
		key := be64(meta.FirstSeq)
		v := data.Get(key)
		if v == nil {
			// Hole (already evicted) — advance and keep going.
			meta.FirstSeq++
			continue
		}
		evictedLines := 0
		if decoded, err := s.decodeChunk(v); err == nil {
			evictedLines = len(decoded)
		}
		if err := data.Delete(key); err != nil {
			return err
		}
		if uint64(len(v)) >= meta.Bytes {
			meta.Bytes = 0
		} else {
			meta.Bytes -= uint64(len(v))
		}
		if uint64(evictedLines) >= meta.Lines {
			meta.Lines = 0
		} else {
			meta.Lines -= uint64(evictedLines)
		}
		meta.FirstSeq++
		if meta.FirstSeq > meta.LastSeq {
			// Store emptied; reset so the next append starts a fresh series.
			meta.FirstSeq = 0
			meta.LastSeq = 0
			meta.Bytes = 0
			meta.Lines = 0
			break
		}
	}
	return nil
}

// Query returns a newest-first page of lines for one source.
func (s *Store) Query(f Filter) (Result, error) {
	if strings.TrimSpace(f.SourceID) == "" {
		return Result{}, fmt.Errorf("logstore: source id is required")
	}
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultQueryLimit
	}
	if limit > MaxQueryLimit {
		limit = MaxQueryLimit
	}
	needle := strings.ToLower(strings.TrimSpace(f.Contains))
	res := Result{Lines: []model.LogLine{}}
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(dataBucketName(f.SourceID))
		if data == nil {
			return nil
		}
		c := data.Cursor()
		// Walk chunks newest -> oldest.
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			seq := binary.BigEndian.Uint64(k)
			if f.BeforeSeq != 0 && seq >= f.BeforeSeq {
				continue
			}
			decoded, derr := s.decodeChunk(v)
			if derr != nil {
				res.Truncated = true
				continue
			}
			// Lines within a chunk are oldest->newest; emit newest-first.
			for i := len(decoded) - 1; i >= 0; i-- {
				ln := decoded[i]
				if !f.Since.IsZero() && ln.At.Before(f.Since) {
					continue
				}
				if !f.Until.IsZero() && ln.At.After(f.Until) {
					continue
				}
				if needle != "" && !strings.Contains(strings.ToLower(ln.Line), needle) {
					continue
				}
				res.Lines = append(res.Lines, ln)
			}
			if len(res.Lines) >= limit {
				// Page boundary at this chunk; older chunks (if any) are the next page.
				if pk, _ := c.Prev(); pk != nil {
					res.NextBeforeSeq = seq
				}
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("logstore: query: %w", err)
	}
	return res, nil
}

// Stats returns the meta projection for a source (with computed first/last At).
func (s *Store) Stats(sourceID string) (Meta, time.Time, time.Time, bool) {
	var (
		meta    Meta
		firstAt time.Time
		lastAt  time.Time
		found   bool
	)
	_ = s.db.View(func(tx *bolt.Tx) error {
		mb := tx.Bucket([]byte(metaBucketName))
		raw := mb.Get([]byte(sourceID))
		if raw == nil {
			return nil
		}
		found = true
		_ = json.Unmarshal(raw, &meta)
		data := tx.Bucket(dataBucketName(sourceID))
		if data == nil {
			return nil
		}
		c := data.Cursor()
		if _, v := c.First(); v != nil {
			if lines, err := s.decodeChunk(v); err == nil && len(lines) > 0 {
				firstAt = lines[0].At
			}
		}
		if _, v := c.Last(); v != nil {
			if lines, err := s.decodeChunk(v); err == nil && len(lines) > 0 {
				lastAt = lines[len(lines)-1].At
			}
		}
		return nil
	})
	return meta, firstAt, lastAt, found
}

// PurgeSource drops a source's data bucket and meta (used on source delete).
func (s *Store) PurgeSource(sourceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(dataBucketName(sourceID)); b != nil {
			if err := tx.DeleteBucket(dataBucketName(sourceID)); err != nil {
				return err
			}
		}
		if mb := tx.Bucket([]byte(metaBucketName)); mb != nil {
			if err := mb.Delete([]byte(sourceID)); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) readMeta(tx *bolt.Tx, sourceID string) Meta {
	var meta Meta
	mb := tx.Bucket([]byte(metaBucketName))
	if mb == nil {
		return meta
	}
	if raw := mb.Get([]byte(sourceID)); raw != nil {
		_ = json.Unmarshal(raw, &meta)
	}
	return meta
}

func (s *Store) writeMeta(tx *bolt.Tx, sourceID string, meta Meta) error {
	mb, err := tx.CreateBucketIfNotExists([]byte(metaBucketName))
	if err != nil {
		return err
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return mb.Put([]byte(sourceID), raw)
}

func (s *Store) encodeChunk(lines []model.LogLine) ([]byte, error) {
	raw, err := json.Marshal(lines)
	if err != nil {
		return nil, err
	}
	if s.cipher != nil && s.cipher.Enabled() {
		sealed, err := s.cipher.Encrypt(string(raw))
		if err != nil {
			return nil, err
		}
		return []byte(sealed), nil
	}
	return raw, nil
}

func (s *Store) decodeChunk(stored []byte) ([]model.LogLine, error) {
	raw := stored
	if s.cipher != nil {
		// Disabled cipher passes plaintext through unchanged; enabled cipher
		// unseals. Non-envelope input under an enabled cipher also passes through.
		dec, err := s.cipher.Decrypt(string(stored))
		if err != nil {
			return nil, err
		}
		raw = []byte(dec)
	}
	var lines []model.LogLine
	if err := json.Unmarshal(raw, &lines); err != nil {
		return nil, err
	}
	return lines, nil
}

// SourceBytesCap reports the configured per-source byte cap (for diagnostics).
func (s *Store) SourceBytesCap() uint64 { return s.maxSourceBytes }

// EnvMaxSourceBytes parses an optional per-source byte cap override.
func EnvMaxSourceBytes(raw string) int64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// FileSize returns the current on-disk size of the database in bytes.
func (s *Store) FileSize() int64 {
	if s == nil || s.db == nil {
		return 0
	}
	info, err := os.Stat(s.db.Path())
	if err != nil {
		return 0
	}
	return info.Size()
}
