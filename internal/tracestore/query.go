package tracestore

import (
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"strings"
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
