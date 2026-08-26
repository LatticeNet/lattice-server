// Package tracestore is the durable store for sing-box trace data: the
// assembled connection records, the raw log lines a trace session asked to
// keep, and the five-minute rollups the usage and failure views read.
//
// It owns its own SQLite database (trace.db), a sibling of logstore's logs.db
// in the same directory and with the same permissions. SQLite rather than
// bbolt because the query shape here is relational: an operator filters
// connections by any combination of user, line, node, destination, close
// reason and time, then pages newest-first across nodes. Hand-maintaining that
// many secondary indexes on bbolt is a permanent cost, and it is a relational
// database's day job. The driver is modernc.org/sqlite, which is pure Go:
// keeping lattice-server a single static binary with no cgo is a hard product
// property, so the cgo driver is not an option.
//
// Unlabelled node log lines stay in logstore. Only what a session marked comes
// here.
//
// Design: Lattice/SINGBOX-TRACE-DESIGN.md section 4.8.
package tracestore

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/LatticeNet/lattice-server/internal/secret"
)

const (
	// DefaultRecordTTL, DefaultLineTTL and DefaultRollupTTL are the retention
	// floors from design section 4.8. Records outlive raw lines because a
	// record is a summary an operator still wants a week later, while a raw
	// line is bulk evidence for a capture that has already been read.
	DefaultRecordTTL = 14 * 24 * time.Hour
	DefaultLineTTL   = 7 * 24 * time.Hour
	DefaultRollupTTL = 90 * 24 * time.Hour

	// DefaultMaxBytes caps the whole database. Over it, oldest records are
	// deleted first, because the newest data is what an operator is looking at
	// during an incident.
	DefaultMaxBytes = int64(2) << 30 // 2 GiB

	// DefaultQueryLimit / MaxQueryLimit bound one page of records, matching
	// logstore's numbers so the two views page at the same rate.
	DefaultQueryLimit = 200
	MaxQueryLimit     = 1000

	// DefaultRollupLimit / MaxRollupLimit bound one rollup query. A rollup row
	// is small, and a chart over a week at five-minute resolution for one user
	// is about 2000 buckets, so the ceiling has to sit well above that.
	DefaultRollupLimit = 2000
	MaxRollupLimit     = 20000

	// RollupBucket is the rollup resolution. Five minutes is the design's
	// number: fine enough to see a failure burst, coarse enough that a busy
	// fleet does not write a row per connection.
	RollupBucket = 5 * time.Minute
)

// ErrBadCursor is returned when a pagination cursor does not decode. Callers
// map it to a 400: a cursor is client-supplied input, and a bad one must never
// degrade into a silent full scan or a panic.
var ErrBadCursor = errors.New("tracestore: malformed cursor")

// Options configures retention. A zero value takes every default.
type Options struct {
	RecordTTL time.Duration // default DefaultRecordTTL
	LineTTL   time.Duration // default DefaultLineTTL
	RollupTTL time.Duration // default DefaultRollupTTL
	MaxBytes  int64         // default DefaultMaxBytes
}

func (o Options) withDefaults() Options {
	if o.RecordTTL <= 0 {
		o.RecordTTL = DefaultRecordTTL
	}
	if o.LineTTL <= 0 {
		o.LineTTL = DefaultLineTTL
	}
	if o.RollupTTL <= 0 {
		o.RollupTTL = DefaultRollupTTL
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	return o
}

// Store is the SQLite-backed trace store.
type Store struct {
	db     *sql.DB
	cipher secret.Cipher
	opts   Options
	path   string

	// autoVacuum reports whether the database was created with incremental
	// auto-vacuum. Without it, deleting rows frees pages inside the file but
	// never shrinks the file, so a MaxBytes sweep could never converge.
	autoVacuum bool

	// mu serializes writers. SQLite would serialize them anyway and busy_timeout
	// would absorb the contention, but AppendRecords does a read-modify-write on
	// the rollups and Retain walks in batches, so a Go-side write lock keeps
	// those sequences honest and keeps SQLITE_BUSY out of the hot path. Readers
	// do not take it: WAL gives them a snapshot concurrent with the writer.
	mu sync.Mutex
}

// Stats is the diagnostic projection of the store.
type Stats struct {
	Path           string    `json:"path"`
	SchemaVersion  int       `json:"schema_version"`
	Records        int64     `json:"records"`
	OpenRecords    int64     `json:"open_records"`
	Lines          int64     `json:"lines"`
	Rollups        int64     `json:"rollups"`
	OldestRecordAt time.Time `json:"oldest_record_at,omitzero"`
	NewestRecordAt time.Time `json:"newest_record_at,omitzero"`
	SizeBytes      int64     `json:"size_bytes"`
	MaxBytes       int64     `json:"max_bytes"`
	CipherEnabled  bool      `json:"cipher_enabled"`
}

// Open opens (creating if needed) the trace store at path and runs any pending
// migration. A nil or disabled cipher stores the sealed columns in plaintext,
// exactly as logstore does when there is no master key.
func Open(path string, cipher secret.Cipher, opts Options) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("tracestore: path is required")
	}
	if cipher == nil {
		cipher = secret.Disabled()
	}
	// Create the file ourselves at 0600 before SQLite touches it. SQLite would
	// create it at 0644 minus the umask, which would leave connection records
	// and destination hostnames world readable for the moment between creation
	// and any later chmod. SQLite copies this mode onto the -wal and -shm
	// sidecars it creates, so setting it once here covers all three.
	if _, statErr := os.Stat(path); errors.Is(statErr, fs.ErrNotExist) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("tracestore: create %s: %w", path, err)
		}
		f.Close()
	}
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("tracestore: open %s: %w", path, err)
	}
	// A small pool keeps concurrent queries from opening an unbounded number of
	// file handles. Idle equals open on purpose: database/sql closes a
	// connection it cannot park, and closing a SQLite connection runs a WAL
	// checkpoint, which is a database write appearing from a connection nobody
	// asked to write.
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("tracestore: open %s: %w", path, err)
	}
	s := &Store{db: db, cipher: cipher, opts: opts.withDefaults(), path: path}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	var mode int
	if err := db.QueryRow("PRAGMA auto_vacuum").Scan(&mode); err == nil {
		s.autoVacuum = mode == 2 // 2 == INCREMENTAL
	}
	return s, nil
}

// dsn builds the connection string. The pragmas travel in the DSN because
// database/sql pools connections and a PRAGMA issued on one connection would
// not reach the others; modernc.org/sqlite applies _pragma parameters to every
// connection it opens.
//
// The set, and why:
//
//   - auto_vacuum(incremental): first, because auto-vacuum can only be turned
//     on before the first table is written. It is what lets Retain hand freed
//     pages back to the filesystem so the MaxBytes sweep converges instead of
//     deleting rows into a file that never shrinks.
//   - journal_mode(WAL): one writer plus concurrent readers, which is exactly
//     the ingest-while-an-operator-queries shape.
//   - busy_timeout(5000): a reader that meets a checkpoint waits rather than
//     failing the operator's query.
//   - foreign_keys(1): the record-to-session index rows are declared ON DELETE
//     CASCADE, so retention cannot leave them dangling.
//   - synchronous(NORMAL): with WAL this means commits are not fsynced
//     individually. A hard crash or power loss can lose the last few seconds of
//     ingest, and the database still cannot corrupt. That trade is right here:
//     this is a diagnostic store fed by a node agent that will re-send, and
//     paying an fsync per batch to protect a few seconds of log lines would
//     cost far more than the data is worth.
//
// _txlock=immediate is not a pragma but belongs to the same decision. Every
// explicit transaction in this package writes, and several of them read first
// (the rollup merge, the snapshot-versus-final check). A deferred transaction
// takes its read snapshot on that first SELECT and then has to upgrade to a
// writer, which fails with SQLITE_BUSY_SNAPSHOT if anything touched the
// database in between, and no busy timeout retries that error. Taking the write
// lock up front turns that into ordinary contention, which busy_timeout does
// handle.
func dsn(path string) string {
	u := url.URL{Scheme: "file", Path: path}
	q := url.Values{}
	q.Add("_pragma", "auto_vacuum(incremental)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Set("_txlock", "immediate")
	u.RawQuery = q.Encode()
	return u.String()
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
	if s == nil {
		return ""
	}
	return s.path
}

// Stats returns the diagnostic projection of the store.
func (s *Store) Stats() (Stats, error) {
	st := Stats{Path: s.path, MaxBytes: s.opts.MaxBytes, CipherEnabled: s.cipher != nil && s.cipher.Enabled()}
	row := s.db.QueryRow(`SELECT
		(SELECT COUNT(*) FROM conn_records),
		(SELECT COUNT(*) FROM conn_records WHERE open = 1),
		(SELECT COUNT(*) FROM trace_lines),
		(SELECT COUNT(*) FROM rollups_5m),
		(SELECT MIN(started_at) FROM conn_records),
		(SELECT MAX(started_at) FROM conn_records),
		(SELECT COALESCE(MAX(version), 0) FROM schema_version)`)
	var oldest, newest sql.NullInt64
	if err := row.Scan(&st.Records, &st.OpenRecords, &st.Lines, &st.Rollups, &oldest, &newest, &st.SchemaVersion); err != nil {
		return Stats{}, fmt.Errorf("tracestore: stats: %w", err)
	}
	st.OldestRecordAt = timeFromNanos(oldest)
	st.NewestRecordAt = timeFromNanos(newest)
	size, err := s.sizeBytes()
	if err != nil {
		return Stats{}, err
	}
	st.SizeBytes = size
	return st, nil
}

// sizeBytes reports the logical size of the database: pages in use times page
// size. It deliberately ignores the WAL, which is transient and is checkpointed
// back into the main file, so the number an operator sees is the size that
// retention actually controls.
func (s *Store) sizeBytes() (int64, error) {
	var pageCount, pageSize int64
	if err := s.db.QueryRow("PRAGMA page_count").Scan(&pageCount); err != nil {
		return 0, fmt.Errorf("tracestore: page_count: %w", err)
	}
	if err := s.db.QueryRow("PRAGMA page_size").Scan(&pageSize); err != nil {
		return 0, fmt.Errorf("tracestore: page_size: %w", err)
	}
	return pageCount * pageSize, nil
}

// seal encrypts a free-text value when a cipher is enabled. A disabled cipher
// passes the value through, which is what logstore does with no master key.
func (s *Store) seal(v string) (string, error) {
	if s.cipher == nil {
		return v, nil
	}
	out, err := s.cipher.Encrypt(v)
	if err != nil {
		return "", fmt.Errorf("tracestore: seal: %w", err)
	}
	return out, nil
}

// unseal reverses seal. secret.Cipher passes non-envelope input through, so a
// value written before encryption was turned on still reads back.
func (s *Store) unseal(v string) (string, error) {
	if s.cipher == nil {
		return v, nil
	}
	out, err := s.cipher.Decrypt(v)
	if err != nil {
		return "", fmt.Errorf("tracestore: unseal: %w", err)
	}
	return out, nil
}

// nanos encodes a timestamp for storage. Times are unix nanoseconds in UTC so
// that ordering, range scans and the keyset cursor are all plain integer
// comparisons.
func nanos(t time.Time) int64 { return t.UTC().UnixNano() }

// nullNanos encodes an optional timestamp. The zero time becomes NULL rather
// than an integer, so a connection that never ended reads back as a zero
// EndedAt instead of a fabricated instant at the Unix epoch.
func nullNanos(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().UnixNano()
}

func timeFromNanos(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return time.Unix(0, v.Int64).UTC()
}
