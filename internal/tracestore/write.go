package tracestore

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// recordColumns is the full column list in insert order. It exists once so the
// insert, the upsert clause and the scan cannot drift apart.
const recordColumns = `node_id, core_generation, log_id, started_at,
	line_uuid, line_hash_id, inbound_tag, inbound_type,
	user_name, user_id, user_kind,
	network, src_ip, src_port, dst_host, dst_ip, dst_port,
	sniffed_protocol, sniffed_domain, rule_index, rule_text, outbound_tag, outbound_type, chain_edge_uuid,
	ended_at, duration_ms, open,
	upload, download, bytes_known,
	close_reason, close_error, stalled_at,
	session_ids, hop_path_id`

// insertRecordSQL upserts one record on the composite key.
//
// The conflict clause updates every non-key column, which gives two properties
// the ingest path depends on. An Open snapshot replaces the previous snapshot
// for the same connection rather than accumulating a row per sample, so a long
// connection is one row that grows. And re-delivering an identical record (the
// agent retries a batch the server already committed) leaves the store exactly
// as it was.
const insertRecordSQL = `INSERT INTO conn_records (` + recordColumns + `)
VALUES (?, ?, ?, ?,
	?, ?, ?, ?,
	?, ?, ?,
	?, ?, ?, ?, ?, ?,
	?, ?, ?, ?, ?, ?, ?,
	?, ?, ?,
	?, ?, ?,
	?, ?, ?,
	?, ?)
ON CONFLICT (node_id, core_generation, log_id, started_at) DO UPDATE SET
	line_uuid = excluded.line_uuid,
	line_hash_id = excluded.line_hash_id,
	inbound_tag = excluded.inbound_tag,
	inbound_type = excluded.inbound_type,
	user_name = excluded.user_name,
	user_id = excluded.user_id,
	user_kind = excluded.user_kind,
	network = excluded.network,
	src_ip = excluded.src_ip,
	src_port = excluded.src_port,
	dst_host = excluded.dst_host,
	dst_ip = excluded.dst_ip,
	dst_port = excluded.dst_port,
	sniffed_protocol = excluded.sniffed_protocol,
	sniffed_domain = excluded.sniffed_domain,
	rule_index = excluded.rule_index,
	rule_text = excluded.rule_text,
	outbound_tag = excluded.outbound_tag,
	outbound_type = excluded.outbound_type,
	chain_edge_uuid = excluded.chain_edge_uuid,
	ended_at = excluded.ended_at,
	duration_ms = excluded.duration_ms,
	open = excluded.open,
	upload = excluded.upload,
	download = excluded.download,
	bytes_known = excluded.bytes_known,
	close_reason = excluded.close_reason,
	close_error = excluded.close_error,
	stalled_at = excluded.stalled_at,
	session_ids = excluded.session_ids,
	hop_path_id = excluded.hop_path_id`

// AppendRecords writes a batch of connection records and folds the final ones
// into the five-minute rollups, all in one transaction. It returns the number
// of records applied.
//
// The batch is all or nothing: an invalid record fails the call and writes
// nothing, so the caller can answer the agent with a 400 rather than silently
// keeping part of a batch it believes was rejected.
func (s *Store) AppendRecords(rs []model.ConnRecord) (int, error) {
	if len(rs) == 0 {
		return 0, nil
	}
	for i := range rs {
		if err := validateRecord(rs[i]); err != nil {
			return 0, fmt.Errorf("tracestore: append records: record %d: %w", i, err)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("tracestore: append records: %w", err)
	}
	defer tx.Rollback()

	applied := 0
	deltas := map[rollupKey]*rollupDelta{}
	for i := range rs {
		r := rs[i]
		existed, wasOpen, err := recordState(tx, r)
		if err != nil {
			return 0, fmt.Errorf("tracestore: append records: %w", err)
		}
		if existed && !wasOpen && r.Open {
			// A late Open snapshot must never overwrite a final record. Batches
			// can arrive out of order after a retry, and the final record is the
			// only one that says how the connection ended; letting a stale
			// snapshot win would resurrect a closed connection as live.
			continue
		}
		if err := s.insertRecord(tx, r); err != nil {
			return 0, fmt.Errorf("tracestore: append records: %w", err)
		}
		if err := replaceRecordSessions(tx, r); err != nil {
			return 0, fmt.Errorf("tracestore: append records: %w", err)
		}
		// Roll up from final records only, and only the first time a connection
		// goes final. Open snapshots are excluded because the same connection
		// snapshots every 60 seconds and would be counted once per sample; the
		// already-final case is excluded so a re-delivered batch does not
		// double-count what it already contributed.
		if !r.Open && !(existed && !wasOpen) {
			addRollupDelta(deltas, r)
		}
		applied++
	}
	if err := applyRollupDeltas(tx, deltas); err != nil {
		return 0, fmt.Errorf("tracestore: append records: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("tracestore: append records: %w", err)
	}
	return applied, nil
}

func validateRecord(r model.ConnRecord) error {
	if strings.TrimSpace(r.NodeID) == "" {
		return fmt.Errorf("node id is required")
	}
	if r.StartedAt.IsZero() {
		// started_at is part of the primary key and of the pagination cursor. A
		// zero one would sort into 1754 and make a record unreachable by every
		// time-bounded query, which is worse than refusing it.
		return fmt.Errorf("started at is required")
	}
	return nil
}

// recordState reports whether the key already exists and whether the stored row
// is an open snapshot.
func recordState(tx *sql.Tx, r model.ConnRecord) (existed, wasOpen bool, err error) {
	var open int64
	row := tx.QueryRow(`SELECT open FROM conn_records
		WHERE node_id = ? AND core_generation = ? AND log_id = ? AND started_at = ?`,
		r.NodeID, int64(r.CoreGeneration), int64(r.LogID), nanos(r.StartedAt))
	switch err := row.Scan(&open); err {
	case nil:
		return true, open != 0, nil
	case sql.ErrNoRows:
		return false, false, nil
	default:
		return false, false, err
	}
}

func (s *Store) insertRecord(tx *sql.Tx, r model.ConnRecord) error {
	// close_error is free text straight out of a sing-box error and is sealed
	// with the same cipher logstore uses on its chunks. dst_host is NOT sealed:
	// it is an index column, and an index cannot be built over ciphertext. That
	// is a deliberate, documented tradeoff (design 4.8): destination hostnames
	// sit at the same protection level they already have in logs.db with no
	// master key, and the planned hardening is HMAC tokenisation, which keeps
	// equality filtering and gives up substring search.
	closeError, err := s.seal(r.CloseError)
	if err != nil {
		return err
	}
	sessionIDs, err := encodeSessionIDs(r.SessionIDs)
	if err != nil {
		return err
	}
	_, err = tx.Exec(insertRecordSQL,
		r.NodeID, int64(r.CoreGeneration), int64(r.LogID), nanos(r.StartedAt),
		r.LineUUID, r.LineHashID, r.InboundTag, r.InboundType,
		r.UserName, r.UserID, r.UserKind,
		r.Network, r.SrcIP, int64(r.SrcPort), r.DstHost, r.DstIP, int64(r.DstPort),
		r.SniffedProtocol, r.SniffedDomain, int64(r.RuleIndex), r.RuleText, r.OutboundTag, r.OutboundType, r.ChainEdgeUUID,
		nullNanos(r.EndedAt), r.DurationMS, boolToInt(r.Open),
		r.Upload, r.Download, boolToInt(r.BytesKnown),
		r.CloseReason, closeError, nullNanos(r.StalledAt),
		sessionIDs, r.HopPathID)
	return err
}

// replaceRecordSessions rewrites the session index rows for one record. A
// snapshot can pick up a new session between samples, so the set is replaced
// rather than added to.
func replaceRecordSessions(tx *sql.Tx, r model.ConnRecord) error {
	if _, err := tx.Exec(`DELETE FROM conn_record_sessions
		WHERE node_id = ? AND core_generation = ? AND log_id = ? AND started_at = ?`,
		r.NodeID, int64(r.CoreGeneration), int64(r.LogID), nanos(r.StartedAt)); err != nil {
		return err
	}
	for _, id := range r.SessionIDs {
		if strings.TrimSpace(id) == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO conn_record_sessions
			(session_id, started_at, node_id, core_generation, log_id) VALUES (?, ?, ?, ?, ?)`,
			id, nanos(r.StartedAt), r.NodeID, int64(r.CoreGeneration), int64(r.LogID)); err != nil {
			return err
		}
	}
	return nil
}

// rollupKey is the rollup grain: five-minute bucket by user, line and node.
type rollupKey struct {
	bucket   int64
	userID   string
	lineUUID string
	nodeID   string
}

type rollupDelta struct {
	connections     int64
	bytesKnownCount int64
	upload          int64
	download        int64
	reasons         map[string]int64
}

func addRollupDelta(deltas map[rollupKey]*rollupDelta, r model.ConnRecord) {
	key := rollupKey{
		bucket: nanos(r.StartedAt.UTC().Truncate(RollupBucket)),
		// An unattributed connection rolls up under the empty user id rather
		// than being dropped, so the bucket totals still add up to what
		// happened. The same holds for line and node.
		userID:   r.UserID,
		lineUUID: r.LineUUID,
		nodeID:   r.NodeID,
	}
	d := deltas[key]
	if d == nil {
		d = &rollupDelta{reasons: map[string]int64{}}
		deltas[key] = d
	}
	d.connections++
	if r.BytesKnown {
		// Only measured bytes are summed. A record with BytesKnown false is
		// still counted as a connection, so the caller can see that the sums
		// cover fewer connections than the count.
		d.bytesKnownCount++
		d.upload += r.Upload
		d.download += r.Download
	}
	reason := r.CloseReason
	if reason == "" {
		// A final record with no reason is an honest gap, not a clean close.
		// Naming it keeps the per-reason counts summing to connections.
		reason = model.CloseUnknown
	}
	d.reasons[reason]++
}

func applyRollupDeltas(tx *sql.Tx, deltas map[rollupKey]*rollupDelta) error {
	for key, d := range deltas {
		var (
			connections, bytesKnown, upload, download int64
			reasonsRaw                                string
		)
		row := tx.QueryRow(`SELECT connections, bytes_known_count, upload, download, close_reasons
			FROM rollups_5m WHERE bucket_start = ? AND user_id = ? AND line_uuid = ? AND node_id = ?`,
			key.bucket, key.userID, key.lineUUID, key.nodeID)
		switch err := row.Scan(&connections, &bytesKnown, &upload, &download, &reasonsRaw); err {
		case nil:
		case sql.ErrNoRows:
			reasonsRaw = "{}"
		default:
			return err
		}
		reasons, err := decodeReasons(reasonsRaw)
		if err != nil {
			return err
		}
		for reason, n := range d.reasons {
			reasons[reason] += n
		}
		merged, err := json.Marshal(reasons)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO rollups_5m
			(bucket_start, user_id, line_uuid, node_id, connections, bytes_known_count, upload, download, close_reasons)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (bucket_start, user_id, line_uuid, node_id) DO UPDATE SET
				connections = excluded.connections,
				bytes_known_count = excluded.bytes_known_count,
				upload = excluded.upload,
				download = excluded.download,
				close_reasons = excluded.close_reasons`,
			key.bucket, key.userID, key.lineUUID, key.nodeID,
			connections+d.connections, bytesKnown+d.bytesKnownCount,
			upload+d.upload, download+d.download, string(merged)); err != nil {
			return err
		}
	}
	return nil
}

// AppendLines writes raw session lines. Re-delivering a line replaces it, so an
// agent that retries a batch cannot duplicate the evidence.
func (s *Store) AppendLines(ls []model.TraceLine) (int, error) {
	if len(ls) == 0 {
		return 0, nil
	}
	for i := range ls {
		if strings.TrimSpace(ls[i].SessionID) == "" {
			return 0, fmt.Errorf("tracestore: append lines: line %d: session id is required", i)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("tracestore: append lines: %w", err)
	}
	defer tx.Rollback()

	// Seq is assigned HERE, not by the agent.
	//
	// It is the tail cursor: QueryLines pages with "seq > afterSeq", and the
	// primary key is (session_id, seq, node_id). An agent cannot know a global
	// order across its own batches, let alone across several nodes feeding one
	// session, so if it were left to set Seq every line would arrive as zero,
	// they would all collapse onto a single primary key, and a tail starting at
	// zero could never return any of them. Assigning it under the write lock
	// inside the transaction makes it monotonic per session across every node.
	next := map[string]uint64{}
	for i := range ls {
		sessionID := ls[i].SessionID
		if _, ok := next[sessionID]; ok {
			continue
		}
		var maxSeq sql.NullInt64
		if err := tx.QueryRow(`SELECT MAX(seq) FROM trace_lines WHERE session_id = ?`, sessionID).Scan(&maxSeq); err != nil {
			return 0, fmt.Errorf("tracestore: append lines: read sequence: %w", err)
		}
		if maxSeq.Valid && maxSeq.Int64 > 0 {
			next[sessionID] = uint64(maxSeq.Int64)
		}
	}

	for i := range ls {
		l := ls[i]
		next[l.SessionID]++
		l.Seq = next[l.SessionID]
		// Both message and raw are free-text log body and are sealed. Neither is
		// an index column, so unlike dst_host there is no reason not to.
		message, err := s.seal(l.Message)
		if err != nil {
			return 0, err
		}
		raw, err := s.seal(l.Raw)
		if err != nil {
			return 0, err
		}
		at := l.At
		if at.IsZero() {
			// A line with no timestamp would be immortal under a TTL sweep that
			// deletes by age, so it is stamped on arrival instead.
			at = time.Now().UTC()
		}
		// The dedupe key is computed from the line's own content, before
		// sealing, so it stays stable whether or not a cipher is configured.
		sum := sha256.Sum256([]byte(strings.Join([]string{
			l.NodeID, strconv.FormatUint(uint64(l.LogID), 10),
			strconv.FormatInt(nanos(at), 10), l.Level, l.Tag, l.Message, l.Raw,
		}, "\x00")))
		dedupe := hex.EncodeToString(sum[:])

		res, err := tx.Exec(`INSERT INTO trace_lines
			(session_id, node_id, seq, at, level, log_id, tag, message, raw, dedupe_key)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (session_id, dedupe_key) DO NOTHING`,
			l.SessionID, l.NodeID, int64(l.Seq), nanos(at), l.Level, int64(l.LogID), l.Tag, message, raw, dedupe)
		if err != nil {
			return 0, fmt.Errorf("tracestore: append lines: %w", err)
		}
		// A conflict means this exact line is already stored, so the sequence it
		// was about to consume is handed back rather than leaving a hole.
		if n, err := res.RowsAffected(); err == nil && n == 0 {
			next[l.SessionID]--
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("tracestore: append lines: %w", err)
	}
	return len(ls), nil
}

func encodeSessionIDs(ids []string) (string, error) {
	if len(ids) == 0 {
		return "", nil
	}
	raw, err := json.Marshal(ids)
	if err != nil {
		return "", fmt.Errorf("tracestore: encode session ids: %w", err)
	}
	return string(raw), nil
}

func decodeSessionIDs(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	var ids []string
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		return nil, fmt.Errorf("tracestore: decode session ids: %w", err)
	}
	return ids, nil
}

func decodeReasons(raw string) (map[string]int64, error) {
	if strings.TrimSpace(raw) == "" {
		return map[string]int64{}, nil
	}
	out := map[string]int64{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("tracestore: decode close reasons: %w", err)
	}
	return out, nil
}

func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
