package tracestore

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Filter is one page request against conn_records. Empty fields mean "no
// constraint on this dimension"; the fields combine with AND, and a slice
// combines with OR inside its own dimension.
type Filter struct {
	Since, Until time.Time
	NodeIDs      []string
	UserIDs      []string
	LineUUIDs    []string
	SessionIDs   []string
	// DstContains is a case-insensitive substring of the destination host, which
	// is what an operator actually types. It cannot use the dst_host index (no
	// index serves a leading wildcard), so it narrows whatever the other
	// predicates already selected.
	DstContains  string
	CloseReasons []string
	UserKinds    []string
	OnlyStalled  bool
	// IncludeOpen defaults false: a periodic snapshot of a still-running
	// connection is not a result an operator asked for, and mixing snapshots
	// into a list of finished connections double-reports live traffic.
	IncludeOpen bool
	Limit       int    // clamped to [1, MaxQueryLimit]; 0 means DefaultQueryLimit
	Cursor      string // opaque, from RecordPage.NextCursor
}

// RecordPage is a newest-first page of records. An empty NextCursor means the
// result was exhausted.
//
// CollectedTotal and CollectedNewestAt describe what the store holds for the
// nodes the caller may see, before any operator filter. An empty Records with
// CollectedTotal 0 means nothing has been collected (every policy off, or no
// agent has reported yet); an empty Records with CollectedTotal above zero
// means the filter matched nothing. Without the distinction both cases were
// one empty list, and the console told an operator with tracing switched off
// that "nothing matched these filters".
type RecordPage struct {
	Records           []model.ConnRecord `json:"records"`
	NextCursor        string             `json:"next_cursor,omitempty"`
	CollectedTotal    int64              `json:"collected_total"`
	CollectedNewestAt time.Time          `json:"collected_newest_at,omitzero"`
}

// Collected counts every record the store holds for the given nodes, open or
// final, and the start time of the newest one. An empty nodeIDs counts the
// whole store.
func (s *Store) Collected(nodeIDs []string) (int64, time.Time, error) {
	query := "SELECT COUNT(*), MAX(started_at) FROM conn_records"
	args := []any{}
	if clause, in := inClause("node_id", nodeIDs); clause != "" {
		query += " WHERE " + clause
		args = append(args, in...)
	}
	var total int64
	var newest sql.NullInt64
	if err := s.db.QueryRow(query, args...).Scan(&total, &newest); err != nil {
		return 0, time.Time{}, fmt.Errorf("tracestore: collected: %w", err)
	}
	return total, timeFromNanos(newest), nil
}

// RollupFilter mirrors the rollup grain: time, user, line, node.
type RollupFilter struct {
	Since, Until time.Time
	UserIDs      []string
	LineUUIDs    []string
	NodeIDs      []string
	Limit        int // clamped to [1, MaxRollupLimit]; 0 means DefaultRollupLimit
}

// Rollup is one five-minute bucket.
type Rollup struct {
	BucketStart time.Time `json:"bucket_start"`
	UserID      string    `json:"user_id,omitempty"`
	LineUUID    string    `json:"line_uuid,omitempty"`
	NodeID      string    `json:"node_id,omitempty"`

	// Connections counts every final record in the bucket.
	Connections int64 `json:"connections"`
	// BytesKnownCount is how many of those connections had their bytes actually
	// measured. Upload and Download sum only those. The two numbers travel
	// together on purpose: a caller that renders the sums without saying they
	// cover BytesKnownCount of Connections is presenting a partial total as a
	// whole one, which is the exact lie this feature exists to prevent.
	BytesKnownCount int64 `json:"bytes_known_count"`
	Upload          int64 `json:"upload"`
	Download        int64 `json:"download"`

	// CloseReasons counts final records per close reason. The counts sum to
	// Connections; a record with no reason is counted as unknown.
	CloseReasons map[string]int64 `json:"close_reasons,omitempty"`
}

// QueryRecords returns one newest-first page.
//
// Paging is keyset, not OFFSET: the cursor carries the last row's full primary
// key so page N+1 is an index seek regardless of depth. OFFSET would re-walk
// every skipped row, and it would also silently duplicate or skip rows when
// ingest inserts underneath an operator who is paging.
func (s *Store) QueryRecords(f Filter) (RecordPage, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultQueryLimit
	}
	if limit > MaxQueryLimit {
		limit = MaxQueryLimit
	}

	where := []string{}
	args := []any{}

	if !f.Since.IsZero() {
		where = append(where, "started_at >= ?")
		args = append(args, nanos(f.Since))
	}
	if !f.Until.IsZero() {
		where = append(where, "started_at <= ?")
		args = append(args, nanos(f.Until))
	}
	addIn := func(column string, values []string) {
		clause, in := inClause(column, values)
		if clause == "" {
			return
		}
		where = append(where, clause)
		args = append(args, in...)
	}
	addIn("node_id", f.NodeIDs)
	addIn("user_id", f.UserIDs)
	addIn("line_uuid", f.LineUUIDs)
	addIn("close_reason", f.CloseReasons)
	addIn("user_kind", f.UserKinds)

	if needle := strings.TrimSpace(f.DstContains); needle != "" {
		// LIKE is ASCII case-insensitive in SQLite by default, which is the
		// behaviour an operator expects from a typed substring. The wildcards
		// inside the needle are escaped so a host containing a percent sign
		// cannot turn into a match-everything pattern.
		where = append(where, `dst_host LIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLike(needle)+"%")
	}
	if f.OnlyStalled {
		where = append(where, "stalled_at IS NOT NULL")
	}
	if !f.IncludeOpen {
		where = append(where, "open = 0")
	}
	if clause, in := inClause("cs.session_id", f.SessionIDs); clause != "" {
		where = append(where, `EXISTS (SELECT 1 FROM conn_record_sessions cs
			WHERE cs.node_id = conn_records.node_id
			  AND cs.core_generation = conn_records.core_generation
			  AND cs.log_id = conn_records.log_id
			  AND cs.started_at = conn_records.started_at
			  AND `+clause+`)`)
		args = append(args, in...)
	}
	if f.Cursor != "" {
		c, err := decodeCursor(f.Cursor)
		if err != nil {
			return RecordPage{}, err
		}
		// Strict lexicographic "less than" over the ordering tuple, which is the
		// primary key in descending order.
		where = append(where, `(started_at < ?
			OR (started_at = ? AND (node_id < ?
			OR (node_id = ? AND (core_generation < ?
			OR (core_generation = ? AND log_id < ?))))))`)
		args = append(args, c.StartedAt, c.StartedAt, c.NodeID, c.NodeID, c.CoreGeneration, c.CoreGeneration, c.LogID)
	}

	query := "SELECT " + recordColumns + " FROM conn_records"
	if len(where) > 0 {
		query += "\nWHERE " + strings.Join(where, "\n  AND ")
	}
	// The order is the primary key reversed, so the cursor comparison above and
	// this ordering are the same tuple and paging cannot skip or repeat a row.
	query += "\nORDER BY started_at DESC, node_id DESC, core_generation DESC, log_id DESC\nLIMIT ?"
	// One extra row tells us whether a next page exists without a second query.
	args = append(args, limit+1)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return RecordPage{}, fmt.Errorf("tracestore: query records: %w", err)
	}
	defer rows.Close()

	page := RecordPage{Records: []model.ConnRecord{}}
	for rows.Next() {
		r, err := s.scanRecord(rows)
		if err != nil {
			return RecordPage{}, fmt.Errorf("tracestore: query records: %w", err)
		}
		page.Records = append(page.Records, r)
	}
	if err := rows.Err(); err != nil {
		return RecordPage{}, fmt.Errorf("tracestore: query records: %w", err)
	}
	if len(page.Records) > limit {
		last := page.Records[limit-1]
		page.Records = page.Records[:limit]
		page.NextCursor = encodeCursor(cursor{
			StartedAt:      nanos(last.StartedAt),
			NodeID:         last.NodeID,
			CoreGeneration: int64(last.CoreGeneration),
			LogID:          int64(last.LogID),
		})
	}
	return page, nil
}

// QueryLines returns the raw lines of one session with seq greater than
// afterSeq, oldest first. That is the tail shape the dashboard polls with: pass
// back the last seq you saw and you get only what is new.
// RecordByKey returns one record by its identity. It exists because a scan of
// the newest page cannot answer this: a record older than that page is present
// in the database and absent from the scan, so a caller looking one up by key
// would report "not found" for something it is storing.
// startedAt completes the identity: one core generation can reuse a log id, and
// the store keeps both rows because its primary key includes the start time.
// A zero startedAt asks for the newest, which is the best a caller that does not
// know the exact connection can be given.
func (s *Store) RecordByKey(nodeID string, coreGeneration uint64, logID uint32, startedAt time.Time) (model.ConnRecord, bool, error) {
	query := `SELECT ` + recordColumns + ` FROM conn_records
		WHERE node_id = ? AND core_generation = ? AND log_id = ?`
	args := []any{nodeID, int64(coreGeneration), int64(logID)}
	if !startedAt.IsZero() {
		query += ` AND started_at = ?`
		args = append(args, nanos(startedAt))
	}
	query += ` ORDER BY started_at DESC LIMIT 1`
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return model.ConnRecord{}, false, fmt.Errorf("tracestore: record by key: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return model.ConnRecord{}, false, rows.Err()
	}
	rec, err := s.scanRecord(rows)
	if err != nil {
		return model.ConnRecord{}, false, err
	}
	return rec, true, nil
}

func (s *Store) QueryLines(sessionID string, afterSeq uint64, limit int) ([]model.TraceLine, error) {
	if strings.TrimSpace(sessionID) == "" {
		return nil, fmt.Errorf("tracestore: query lines: session id is required")
	}
	if limit <= 0 {
		limit = DefaultQueryLimit
	}
	if limit > MaxQueryLimit {
		limit = MaxQueryLimit
	}
	rows, err := s.db.Query(`SELECT session_id, node_id, seq, at, level, log_id, tag, message, raw
		FROM trace_lines WHERE session_id = ? AND seq > ?
		ORDER BY seq ASC, node_id ASC LIMIT ?`, sessionID, int64(afterSeq), limit)
	if err != nil {
		return nil, fmt.Errorf("tracestore: query lines: %w", err)
	}
	defer rows.Close()

	out := []model.TraceLine{}
	for rows.Next() {
		var (
			l              model.TraceLine
			seq, at, logID int64
			message, raw   string
		)
		if err := rows.Scan(&l.SessionID, &l.NodeID, &seq, &at, &l.Level, &logID, &l.Tag, &message, &raw); err != nil {
			return nil, fmt.Errorf("tracestore: query lines: %w", err)
		}
		l.Seq = uint64(seq)
		l.At = time.Unix(0, at).UTC()
		l.LogID = uint32(logID)
		if l.Message, err = s.unseal(message); err != nil {
			return nil, err
		}
		if l.Raw, err = s.unseal(raw); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("tracestore: query lines: %w", err)
	}
	return out, nil
}

// Rollups returns five-minute buckets in ascending time order, which is the
// order a chart draws them in.
func (s *Store) Rollups(f RollupFilter) ([]Rollup, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultRollupLimit
	}
	if limit > MaxRollupLimit {
		limit = MaxRollupLimit
	}
	where := []string{}
	args := []any{}
	if !f.Since.IsZero() {
		// Since is compared against the bucket start, so a window that begins
		// mid-bucket still returns the bucket it begins in only when that bucket
		// starts at or after Since. Callers wanting the partial leading bucket
		// pass a Since already truncated to the bucket.
		where = append(where, "bucket_start >= ?")
		args = append(args, nanos(f.Since))
	}
	if !f.Until.IsZero() {
		where = append(where, "bucket_start <= ?")
		args = append(args, nanos(f.Until))
	}
	addIn := func(column string, values []string) {
		clause, in := inClause(column, values)
		if clause == "" {
			return
		}
		where = append(where, clause)
		args = append(args, in...)
	}
	addIn("user_id", f.UserIDs)
	addIn("line_uuid", f.LineUUIDs)
	addIn("node_id", f.NodeIDs)

	query := `SELECT bucket_start, user_id, line_uuid, node_id, connections, bytes_known_count, upload, download, close_reasons
		FROM rollups_5m`
	if len(where) > 0 {
		query += "\nWHERE " + strings.Join(where, "\n  AND ")
	}
	query += "\nORDER BY bucket_start ASC, user_id ASC, line_uuid ASC, node_id ASC\nLIMIT ?"
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("tracestore: rollups: %w", err)
	}
	defer rows.Close()

	out := []Rollup{}
	for rows.Next() {
		var (
			r          Rollup
			bucket     int64
			reasonsRaw string
		)
		if err := rows.Scan(&bucket, &r.UserID, &r.LineUUID, &r.NodeID,
			&r.Connections, &r.BytesKnownCount, &r.Upload, &r.Download, &reasonsRaw); err != nil {
			return nil, fmt.Errorf("tracestore: rollups: %w", err)
		}
		r.BucketStart = time.Unix(0, bucket).UTC()
		if r.CloseReasons, err = decodeReasons(reasonsRaw); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("tracestore: rollups: %w", err)
	}
	return out, nil
}

// Rollup series groupings: what one series in a RollupSeries answer is keyed
// by.
const (
	RollupGroupNode   = "node"
	RollupGroupLine   = "line"
	RollupGroupUser   = "user"
	RollupGroupReason = "reason"
)

// DefaultRollupMaxSeries bounds how many series one RollupSeries call
// returns. A chart cannot draw more than a couple of hundred lines legibly,
// and a per-user grouping over a large fleet would otherwise return one
// series per user.
const DefaultRollupMaxSeries = 200

// DefaultRollupMaxCells bounds the memory one RollupSeries call may hold:
// every (key, step) point it sums into, counted across the concurrent scans,
// each of which can hold every key. A point with its close reasons costs a
// few hundred bytes, so the default keeps one read under about 100 MiB. A
// fleet-wide 90-day read of 34 nodes at hourly steps holds about 100,000.
const DefaultRollupMaxCells = 262144

// ErrRollupTooManyPoints is returned when a read would hold more points than
// its cell ceiling: the window is too long for the number of keys it matches.
var ErrRollupTooManyPoints = errors.New("tracestore: the rollup read matches too many points; narrow the window or filter by node, line or user")

// rollupCtxCheckRows is how often a scan checks whether its caller has gone.
const rollupCtxCheckRows = 4096

// RollupSeriesFilter is one trend read: a window, a step to coarsen the
// five-minute buckets to, and the dimension each series is keyed by.
type RollupSeriesFilter struct {
	Since, Until time.Time
	// Step is the width of one point. It must be a positive multiple of
	// RollupBucket; Since is truncated down to it.
	Step      time.Duration
	GroupBy   string // RollupGroupNode, RollupGroupLine, RollupGroupUser or RollupGroupReason
	NodeIDs   []string
	LineUUIDs []string
	UserIDs   []string
	MaxSeries int // 0 means DefaultRollupMaxSeries
	MaxCells  int // 0 means DefaultRollupMaxCells
}

// RollupPoint is one step of one series. CloseReasons is empty when the
// series is keyed by reason, where Key is the reason and Connections its
// count.
type RollupPoint struct {
	BucketStart     time.Time
	Key             string
	Connections     int64
	BytesKnownCount int64
	Upload          int64
	Download        int64
	CloseReasons    map[string]int64
}

// rollupKeyColumns maps a grouping to its column. Reason has no column: its
// key comes from the close_reasons document.
var rollupKeyColumns = map[string]string{
	RollupGroupNode: "node_id",
	RollupGroupLine: "line_uuid",
	RollupGroupUser: "user_id",
}

// rollupScanWorkers is how many range scans one RollupSeries runs at once.
// Each scan is bound by row decoding and page reads in the pure-Go driver,
// so parallel scans over disjoint ranges divide the wall time. Four leaves
// half of the eight-connection pool to ingest and other readers.
const rollupScanWorkers = 4

// rollupNodeIndexMaxNodes is the longest node list a series scan still reads
// through the per-node index; see scanRollupSeries.
const rollupNodeIndexMaxNodes = 4

// rollupTableScanDivisor sets how much of the held time span a window must
// cover (at least one part in this many) before RollupSeries reads the table
// in rowid order instead of through the primary key. Reading through the key costs one table lookup
// per row, and with the default 2 MiB page cache each lookup is likely a
// pread: measured on 30 days at 60 rows per bucket (86 MiB), the key path
// read every row in 525 ms on one connection, the rowid path in 310 ms on
// one and 140 ms on four. Below this share the key path reads few enough
// rows that its lookups cost less than walking the whole table.
const rollupTableScanDivisor = 4

// rollupScanRange is the slice of rollups_5m one scan reads: bucket_start in
// [from, to) through the primary key, or rowid in [from, to) through the
// table, in which case the window still bounds bucket_start.
type rollupScanRange struct {
	byRowid  bool
	from, to int64
}

// rollupSeriesPoints is one scan's partial answer: key, then step start in
// unix nanoseconds.
type rollupSeriesPoints map[string]map[int64]*RollupPoint

// cell returns the point for key at bucket, creating it when new and charging
// the creation to cells. It fails once cells passes limit.
func (m rollupSeriesPoints) cell(key string, bucket int64, cells *atomic.Int64, limit int64) (*RollupPoint, error) {
	if p := m[key][bucket]; p != nil {
		return p, nil
	}
	if cells.Add(1) > limit {
		return nil, ErrRollupTooManyPoints
	}
	return m.point(key, bucket), nil
}

func (m rollupSeriesPoints) point(key string, bucket int64) *RollupPoint {
	byBucket := m[key]
	if byBucket == nil {
		byBucket = map[int64]*RollupPoint{}
		m[key] = byBucket
	}
	p := byBucket[bucket]
	if p == nil {
		p = &RollupPoint{BucketStart: time.Unix(0, bucket).UTC(), Key: key, CloseReasons: map[string]int64{}}
		byBucket[bucket] = p
	}
	return p
}

// RollupSeries coarsens rollups_5m into steps for a trend read.
//
// Points come grouped by series, the series with the most connections first
// (ties by key), and in ascending time within a series. A step with nothing
// recorded is absent, and so is a step whose counters all net to zero (a
// reattribution moved its connections to another user or line). When more
// keys match than MaxSeries, only the largest are returned and truncated is
// true.
//
// The concurrent scans each read their own snapshot. A reattribution that
// commits while they run moves a connection between two rows of one bucket,
// and when those rows fall in different rowid ranges one key can show the
// move and the other not yet. The skew is one write transaction wide and
// gone on the next read, which a trend chart can carry; one snapshot would
// mean one connection and lose the parallel read.
//
// The aggregation runs in Go over one pass of the rows rather than in SQL.
// Measured on 30 days at 60 rows per bucket, SQLite's GROUP BY sorter and
// json_each over close_reasons took 3.5 s for a 90-day read; a plain scan
// summed in maps takes a fraction of that, and splitting the scan across a
// few concurrent readers divides what is left. A window that covers most of
// what the table holds is split by rowid and read in table order; a narrow
// one, or one filtered to a few nodes, users or lines, is read through an
// index (see rollupTableScanDivisor).
//
// The read is bounded: it stops when ctx is done, checked by SQLite and every
// few thousand rows here, and fails with ErrRollupTooManyPoints once it
// would hold more than MaxCells points.
//
// retainedFrom is the oldest bucket the table holds for the requested nodes
// (for the whole table when NodeIDs is empty), whatever the window: it is the
// horizon a chart can reach back to, not the start of this answer.
func (s *Store) RollupSeries(ctx context.Context, f RollupSeriesFilter) ([]RollupPoint, time.Time, bool, error) {
	step := int64(f.Step)
	if f.Step <= 0 || f.Step%RollupBucket != 0 {
		return nil, time.Time{}, false, fmt.Errorf("tracestore: rollup step %s is not a positive multiple of %s", f.Step, RollupBucket)
	}
	keyColumn, byColumn := rollupKeyColumns[f.GroupBy]
	if !byColumn && f.GroupBy != RollupGroupReason {
		return nil, time.Time{}, false, fmt.Errorf("tracestore: unknown rollup grouping %q", f.GroupBy)
	}
	since := nanos(f.Since) / step * step
	until := nanos(f.Until)
	if since >= until {
		return nil, time.Time{}, false, fmt.Errorf("tracestore: rollup window is empty")
	}
	maxSeries := f.MaxSeries
	if maxSeries <= 0 {
		maxSeries = DefaultRollupMaxSeries
	}
	maxCells := int64(f.MaxCells)
	if maxCells <= 0 {
		maxCells = DefaultRollupMaxCells
	}

	// Clamp the window to the buckets the table holds, so the split below
	// divides real rows: a 90-day window over 30 days of data would otherwise
	// hand two of three scans nothing to do. Each bound is its own subquery so
	// SQLite answers it from one end of a b-tree.
	var oldest, newest, firstRow, lastRow sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT
		(SELECT MIN(bucket_start) FROM rollups_5m), (SELECT MAX(bucket_start) FROM rollups_5m),
		(SELECT MIN(rowid) FROM rollups_5m), (SELECT MAX(rowid) FROM rollups_5m)`).Scan(&oldest, &newest, &firstRow, &lastRow); err != nil {
		return nil, time.Time{}, false, fmt.Errorf("tracestore: rollup series: %w", err)
	}
	merged := rollupSeriesPoints{}
	if oldest.Valid {
		lo, hi := max(since, oldest.Int64), min(until, newest.Int64+1)
		if lo < hi {
			// The narrow filters have their own indexes, which beat any full
			// walk; only a fleet-wide read over most of the span walks the table.
			held := newest.Int64 + 1 - oldest.Int64
			byRowid := len(f.LineUUIDs) == 0 && len(f.UserIDs) == 0 &&
				(len(f.NodeIDs) == 0 || len(f.NodeIDs) > rollupNodeIndexMaxNodes) &&
				(hi-lo)*rollupTableScanDivisor >= held
			from, to := lo, hi
			if byRowid {
				from, to = firstRow.Int64, lastRow.Int64+1
			}
			parts := min(int64(rollupScanWorkers), to-from)
			if !byRowid {
				parts = min(parts, (hi-lo)/int64(RollupBucket)+1)
			}
			width := (to - from + parts - 1) / parts
			results := make([]rollupSeriesPoints, parts)
			errs := make([]error, parts)
			var cells atomic.Int64
			// The first scan to fail stops the others.
			scanCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			var wg sync.WaitGroup
			for i := range parts {
				r := rollupScanRange{byRowid: byRowid, from: from + i*width, to: min(from+(i+1)*width, to)}
				wg.Add(1)
				go func() {
					defer wg.Done()
					results[i], errs[i] = s.scanRollupSeries(scanCtx, f, keyColumn, step, since, until, r, &cells, maxCells)
					if errs[i] != nil {
						cancel()
					}
				}()
			}
			wg.Wait()
			if err := errors.Join(errs...); err != nil {
				return nil, time.Time{}, false, err
			}
			for i, part := range results {
				results[i] = nil
				for key, byBucket := range part {
					for bucket, p := range byBucket {
						m := merged.point(key, bucket)
						m.Connections += p.Connections
						m.BytesKnownCount += p.BytesKnownCount
						m.Upload += p.Upload
						m.Download += p.Download
						for reason, n := range p.CloseReasons {
							m.CloseReasons[reason] += n
						}
					}
				}
			}
		}
	}

	type keyTotal struct {
		key   string
		total int64
	}
	totals := make([]keyTotal, 0, len(merged))
	for key, byBucket := range merged {
		var total int64
		for bucket, p := range byBucket {
			if p.Connections == 0 && p.BytesKnownCount == 0 && p.Upload == 0 && p.Download == 0 {
				delete(byBucket, bucket)
				continue
			}
			for reason, n := range p.CloseReasons {
				if n == 0 {
					delete(p.CloseReasons, reason)
				}
			}
			total += p.Connections
		}
		if len(byBucket) > 0 {
			totals = append(totals, keyTotal{key, total})
		}
	}
	sort.Slice(totals, func(i, j int) bool {
		if totals[i].total != totals[j].total {
			return totals[i].total > totals[j].total
		}
		return totals[i].key < totals[j].key
	})
	truncated := len(totals) > maxSeries
	if truncated {
		totals = totals[:maxSeries]
	}

	out := []RollupPoint{}
	for _, kt := range totals {
		byBucket := merged[kt.key]
		buckets := make([]int64, 0, len(byBucket))
		for bucket := range byBucket {
			buckets = append(buckets, bucket)
		}
		slices.Sort(buckets)
		for _, bucket := range buckets {
			p := byBucket[bucket]
			if !byColumn {
				p.CloseReasons = nil
			}
			out = append(out, *p)
		}
	}

	retainedFrom, err := s.rollupsRetainedFrom(ctx, f.NodeIDs)
	if err != nil {
		return nil, time.Time{}, false, err
	}
	return out, retainedFrom, truncated, nil
}

// scanRollupSeries reads the rollups_5m rows in r with bucket_start in
// [since, until) that match f, and sums them into steps. keyColumn is empty
// for a reason series, whose keys come out of each row's close_reasons. Each
// point it creates is charged to cells, shared with the other scans of the
// same read.
func (s *Store) scanRollupSeries(ctx context.Context, f RollupSeriesFilter, keyColumn string, step, since, until int64, r rollupScanRange, cells *atomic.Int64, maxCells int64) (rollupSeriesPoints, error) {
	where := []string{"bucket_start >= ?", "bucket_start < ?"}
	args := []any{r.from, r.to}
	if r.byRowid {
		// The unary plus keeps the primary key out of index choice, so the
		// rowid range drives the scan and the window only filters.
		where = []string{"rowid >= ?", "rowid < ?", "+bucket_start >= ?", "+bucket_start < ?"}
		args = []any{r.from, r.to, since, until}
	}
	// For a handful of nodes, idx_rollups_5m_node reads only their rows. For
	// many (the usual case: every node the caller may see), SQLite still picks
	// it, and then walks one index range per node with a table lookup per row
	// scattered over the whole file, which measured slower than walking the
	// time range once. The unary plus keeps the column out of index choice.
	nodeColumn := "node_id"
	if r.byRowid || len(f.NodeIDs) > rollupNodeIndexMaxNodes {
		nodeColumn = "+node_id"
	}
	for _, in := range []struct {
		column string
		values []string
	}{{nodeColumn, f.NodeIDs}, {"line_uuid", f.LineUUIDs}, {"user_id", f.UserIDs}} {
		if clause, vals := inClause(in.column, in.values); clause != "" {
			where = append(where, clause)
			args = append(args, vals...)
		}
	}
	columns := "bucket_start, close_reasons"
	if keyColumn != "" {
		columns = "bucket_start, close_reasons, " + keyColumn + ", connections, bytes_known_count, upload, download"
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+columns+` FROM rollups_5m WHERE `+strings.Join(where, " AND "), args...)
	if err != nil {
		return nil, fmt.Errorf("tracestore: rollup series: %w", err)
	}
	defer rows.Close()

	out := rollupSeriesPoints{}
	// intern keeps one string per distinct key or reason, so a pass over half
	// a million rows allocates per distinct value rather than per row.
	intern := map[string]string{}
	canonical := func(b []byte) string {
		if v, ok := intern[string(b)]; ok {
			return v
		}
		v := string(b)
		intern[v] = v
		return v
	}
	reasons := map[string]int64{}
	var (
		bucket                       int64
		rawReasons, rawKey           sql.RawBytes
		conns, known, upload, downld int64
	)
	for n := 0; rows.Next(); n++ {
		// SQLite interrupts its own step when ctx is done; this catches a
		// caller that left while rows were being summed here.
		if n%rollupCtxCheckRows == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if keyColumn != "" {
			err = rows.Scan(&bucket, &rawReasons, &rawKey, &conns, &known, &upload, &downld)
		} else {
			err = rows.Scan(&bucket, &rawReasons)
		}
		if err != nil {
			return nil, fmt.Errorf("tracestore: rollup series: %w", err)
		}
		clear(reasons)
		if err := addReasonCounts(reasons, rawReasons, canonical); err != nil {
			return nil, err
		}
		stepStart := bucket / step * step
		if keyColumn == "" {
			for reason, count := range reasons {
				p, err := out.cell(reason, stepStart, cells, maxCells)
				if err != nil {
					return nil, err
				}
				p.Connections += count
			}
			continue
		}
		p, err := out.cell(canonical(rawKey), stepStart, cells, maxCells)
		if err != nil {
			return nil, err
		}
		p.Connections += conns
		p.BytesKnownCount += known
		p.Upload += upload
		p.Download += downld
		for reason, n := range reasons {
			p.CloseReasons[reason] += n
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("tracestore: rollup series: %w", err)
	}
	return out, nil
}

// addReasonCounts adds one close_reasons document into into. The documents
// are written by applyRollupDeltas through encoding/json, a flat object of
// short reason names to integers with no whitespace, so that shape is parsed
// by hand: encoding/json would cost more than the rest of a row. Anything
// else (an escape, a space, a fraction) takes the encoding/json path, so an
// unexpected document is read correctly, only slower.
func addReasonCounts(into map[string]int64, raw []byte, canonical func([]byte) string) error {
	if counts, ok := parseFlatCounts(raw); ok {
		for _, c := range counts {
			into[canonical(c.key)] += c.n
		}
		return nil
	}
	decoded, err := decodeReasons(string(raw))
	if err != nil {
		return err
	}
	for reason, n := range decoded {
		into[reason] += n
	}
	return nil
}

type flatCount struct {
	key []byte
	n   int64
}

// parseFlatCounts parses {"a":1,"b":-2} exactly, or reports false. The keys
// alias raw.
func parseFlatCounts(raw []byte) ([]flatCount, bool) {
	var out [8]flatCount
	counts := out[:0]
	if len(raw) < 2 || raw[0] != '{' || raw[len(raw)-1] != '}' {
		return nil, false
	}
	i, end := 1, len(raw)-1
	if i == end {
		return counts, true
	}
	for {
		if i >= end || raw[i] != '"' {
			return nil, false
		}
		i++
		start := i
		for i < end && raw[i] != '"' {
			if raw[i] == '\\' || raw[i] < 0x20 {
				return nil, false
			}
			i++
		}
		if i >= end {
			return nil, false
		}
		key := raw[start:i]
		i++
		if i >= end || raw[i] != ':' {
			return nil, false
		}
		i++
		neg := false
		if i < end && raw[i] == '-' {
			neg = true
			i++
		}
		digits := 0
		var n int64
		for i < end && raw[i] >= '0' && raw[i] <= '9' {
			if digits >= 18 {
				return nil, false
			}
			n = n*10 + int64(raw[i]-'0')
			digits++
			i++
		}
		if digits == 0 {
			return nil, false
		}
		if neg {
			n = -n
		}
		counts = append(counts, flatCount{key, n})
		if i == end {
			return counts, true
		}
		if raw[i] != ',' {
			return nil, false
		}
		i++
	}
}

// rollupsRetainedFrom is the oldest bucket held for the given nodes, or for
// the whole table when none is given. One indexed MIN per node rather than a
// single MIN over an IN list: SQLite answers the per-node form from the front
// of idx_rollups_5m_node, while the IN form walks every matching index entry.
func (s *Store) rollupsRetainedFrom(ctx context.Context, nodeIDs []string) (time.Time, error) {
	var oldest sql.NullInt64
	_, in := inClause("node_id", nodeIDs)
	if len(in) == 0 {
		if err := s.db.QueryRowContext(ctx, `SELECT MIN(bucket_start) FROM rollups_5m`).Scan(&oldest); err != nil {
			return time.Time{}, fmt.Errorf("tracestore: rollups retained from: %w", err)
		}
		return timeFromNanos(oldest), nil
	}
	for _, nodeID := range in {
		var v sql.NullInt64
		if err := s.db.QueryRowContext(ctx, `SELECT MIN(bucket_start) FROM rollups_5m WHERE node_id = ?`, nodeID).Scan(&v); err != nil {
			return time.Time{}, fmt.Errorf("tracestore: rollups retained from: %w", err)
		}
		if v.Valid && (!oldest.Valid || v.Int64 < oldest.Int64) {
			oldest = v
		}
	}
	return timeFromNanos(oldest), nil
}

// scanRecord reads one row in recordColumns order.
func (s *Store) scanRecord(rows *sql.Rows) (model.ConnRecord, error) {
	var (
		r                  model.ConnRecord
		coreGeneration     int64
		logID              int64
		startedAt          int64
		srcPort, dstPort   int64
		ruleIndex          int64
		endedAt, stalledAt sql.NullInt64
		open, bytesKnown   int64
		closeError         string
		sessionIDs         string
	)
	if err := rows.Scan(
		&r.NodeID, &coreGeneration, &logID, &startedAt,
		&r.LineUUID, &r.LineHashID, &r.InboundTag, &r.InboundType,
		&r.UserName, &r.UserID, &r.UserKind,
		&r.Network, &r.SrcIP, &srcPort, &r.DstHost, &r.DstIP, &dstPort,
		&r.SniffedProtocol, &r.SniffedDomain, &ruleIndex, &r.RuleText, &r.OutboundTag, &r.OutboundType, &r.ChainEdgeUUID,
		&endedAt, &r.DurationMS, &open,
		&r.Upload, &r.Download, &bytesKnown,
		&r.CloseReason, &closeError, &stalledAt,
		&sessionIDs, &r.HopPathID); err != nil {
		return model.ConnRecord{}, err
	}
	r.CoreGeneration = uint64(coreGeneration)
	r.LogID = uint32(logID)
	r.StartedAt = time.Unix(0, startedAt).UTC()
	r.SrcPort = int(srcPort)
	r.DstPort = int(dstPort)
	r.RuleIndex = int(ruleIndex)
	r.EndedAt = timeFromNanos(endedAt)
	r.StalledAt = timeFromNanos(stalledAt)
	r.Open = open != 0
	r.BytesKnown = bytesKnown != 0
	var err error
	if r.CloseError, err = s.unseal(closeError); err != nil {
		return model.ConnRecord{}, err
	}
	if r.SessionIDs, err = decodeSessionIDs(sessionIDs); err != nil {
		return model.ConnRecord{}, err
	}
	return r, nil
}

// inClause builds "column IN (?, ?)" plus its arguments. Empty and blank values
// are dropped so a filter carrying one empty string does not become a filter
// that matches nothing by accident.
func inClause(column string, values []string) (string, []any) {
	args := make([]any, 0, len(values))
	for _, v := range values {
		if strings.TrimSpace(v) == "" {
			continue
		}
		args = append(args, v)
	}
	if len(args) == 0 {
		return "", nil
	}
	return column + " IN (" + strings.TrimSuffix(strings.Repeat("?, ", len(args)), ", ") + ")", args
}

// escapeLike neutralises the LIKE metacharacters inside an operator's typed
// substring. The backslash is the ESCAPE character declared at the call site.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// cursor is the keyset position: the full primary key of the last row returned.
type cursor struct {
	StartedAt      int64  `json:"t"`
	NodeID         string `json:"n"`
	CoreGeneration int64  `json:"g"`
	LogID          int64  `json:"i"`
}

// cursorVersion prefixes the encoded form so a future change of shape can be
// told apart from corruption instead of being misread.
const cursorVersion byte = 1

// encodeCursor produces the opaque page token: version, CRC32 of the payload,
// then the payload, base64url without padding. The checksum is not a security
// boundary (nothing here is a secret and a cursor only selects a page an
// authorised caller could already request); it is there so a truncated or
// hand-edited token fails loudly at decode instead of decoding into a position
// that quietly skips rows.
func encodeCursor(c cursor) string {
	payload, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	blob := make([]byte, 0, 5+len(payload))
	blob = append(blob, cursorVersion)
	blob = binary.BigEndian.AppendUint32(blob, crc32.ChecksumIEEE(payload))
	blob = append(blob, payload...)
	return base64.RawURLEncoding.EncodeToString(blob)
}

func decodeCursor(s string) (cursor, error) {
	blob, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(blob) < 6 {
		return cursor{}, ErrBadCursor
	}
	if blob[0] != cursorVersion {
		return cursor{}, ErrBadCursor
	}
	payload := blob[5:]
	if binary.BigEndian.Uint32(blob[1:5]) != crc32.ChecksumIEEE(payload) {
		return cursor{}, ErrBadCursor
	}
	var c cursor
	if err := json.Unmarshal(payload, &c); err != nil {
		return cursor{}, ErrBadCursor
	}
	return c, nil
}
