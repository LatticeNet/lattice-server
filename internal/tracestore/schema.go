package tracestore

import (
	"database/sql"
	"fmt"
	"time"
)

// currentSchemaVersion is the schema this build writes.
const currentSchemaVersion = 1

// migration is one numbered step. Every step runs inside a single transaction
// together with the row that records it, so a half-applied migration cannot
// exist.
//
// Adding version 2 is: append {version: 2, statements: []string{...}} to
// migrations and bump currentSchemaVersion. Never edit a released entry:
// databases in the field have already run it and will not run it again.
type migration struct {
	version    int
	statements []string
}

var migrations = []migration{
	{version: 1, statements: schemaV1},
}

// migrate brings the database up to currentSchemaVersion. It is safe to call on
// every Open: applied versions are recorded and skipped.
func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (
		version    INTEGER PRIMARY KEY,
		applied_at INTEGER NOT NULL
	) STRICT`); err != nil {
		return fmt.Errorf("tracestore: create schema_version: %w", err)
	}
	var have int
	if err := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&have); err != nil {
		return fmt.Errorf("tracestore: read schema version: %w", err)
	}
	if have > currentSchemaVersion {
		// A newer binary wrote this file. Refuse rather than run queries against
		// a shape this build does not know, which would fail in ways that look
		// like data loss.
		return fmt.Errorf("tracestore: database schema version %d is newer than this build supports (%d)", have, currentSchemaVersion)
	}
	for _, m := range migrations {
		if m.version <= have {
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("tracestore: migrate v%d: %w", m.version, err)
		}
		for _, stmt := range m.statements {
			if _, err := tx.Exec(stmt); err != nil {
				tx.Rollback()
				return fmt.Errorf("tracestore: migrate v%d: %w", m.version, err)
			}
		}
		if _, err := tx.Exec("INSERT INTO schema_version (version, applied_at) VALUES (?, ?)", m.version, time.Now().UTC().UnixNano()); err != nil {
			tx.Rollback()
			return fmt.Errorf("tracestore: migrate v%d: %w", m.version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("tracestore: migrate v%d: %w", m.version, err)
		}
	}
	return nil
}

// schemaV1 is the initial shape. Tables are STRICT so a wrong Go type is a
// write error here rather than a surprise at read time.
var schemaV1 = []string{
	// conn_records is one assembled sing-box connection per row: the object an
	// operator filters, sorts and opens.
	//
	// The primary key is (node_id, core_generation, log_id, started_at), never
	// log_id alone. sing-box draws the log id from rand.Uint32 per connection,
	// so it is unique enough inside one core lifetime and nowhere else: two
	// nodes collide constantly, and one node collides with itself across a
	// restart. started_at is in the key as well because ids can repeat inside a
	// single core generation on a busy node, and because it makes the key sort
	// in the same order the query pages in.
	//
	// Times are unix nanoseconds UTC. Optional times (ended_at, stalled_at) are
	// NULL when unset so "never ended" cannot be confused with "ended in 1970".
	`CREATE TABLE IF NOT EXISTS conn_records (
		node_id         TEXT    NOT NULL,
		core_generation INTEGER NOT NULL,
		log_id          INTEGER NOT NULL,
		started_at      INTEGER NOT NULL,

		line_uuid    TEXT NOT NULL DEFAULT '',
		line_hash_id TEXT NOT NULL DEFAULT '',
		inbound_tag  TEXT NOT NULL DEFAULT '',
		inbound_type TEXT NOT NULL DEFAULT '',

		user_name TEXT NOT NULL DEFAULT '',
		user_id   TEXT NOT NULL DEFAULT '',
		user_kind TEXT NOT NULL DEFAULT '',

		network  TEXT    NOT NULL DEFAULT '',
		src_ip   TEXT    NOT NULL DEFAULT '',
		src_port INTEGER NOT NULL DEFAULT 0,
		dst_host TEXT    NOT NULL DEFAULT '',
		dst_ip   TEXT    NOT NULL DEFAULT '',
		dst_port INTEGER NOT NULL DEFAULT 0,

		sniffed_protocol TEXT    NOT NULL DEFAULT '',
		sniffed_domain   TEXT    NOT NULL DEFAULT '',
		rule_index       INTEGER NOT NULL DEFAULT 0,
		rule_text        TEXT    NOT NULL DEFAULT '',
		outbound_tag     TEXT    NOT NULL DEFAULT '',
		outbound_type    TEXT    NOT NULL DEFAULT '',
		chain_edge_uuid  TEXT    NOT NULL DEFAULT '',

		ended_at    INTEGER,
		duration_ms INTEGER NOT NULL DEFAULT 0,
		open        INTEGER NOT NULL DEFAULT 0,

		upload      INTEGER NOT NULL DEFAULT 0,
		download    INTEGER NOT NULL DEFAULT 0,
		bytes_known INTEGER NOT NULL DEFAULT 0,

		close_reason TEXT NOT NULL DEFAULT '',
		close_error  TEXT NOT NULL DEFAULT '',
		stalled_at   INTEGER,

		session_ids TEXT NOT NULL DEFAULT '',
		hop_path_id TEXT NOT NULL DEFAULT '',

		PRIMARY KEY (node_id, core_generation, log_id, started_at)
	) STRICT`,

	// Every index below is (dimension, started_at) because every query in the
	// product is "this dimension, newest first, within a time window". The
	// trailing started_at lets one index serve the filter, the ordering and the
	// keyset cursor together.

	// The bare time index serves the default view (newest connections across the
	// whole fleet) and the retention sweep, which deletes oldest-first.
	`CREATE INDEX IF NOT EXISTS idx_conn_records_started ON conn_records(started_at)`,
	// "what did this user do" is the most common entry point, reached from the
	// user page and from a support question about one person.
	`CREATE INDEX IF NOT EXISTS idx_conn_records_user_started ON conn_records(user_id, started_at)`,
	// "what went through this line" is the same question asked from the topology
	// side, and it is how a multi-hop path is walked.
	`CREATE INDEX IF NOT EXISTS idx_conn_records_line_started ON conn_records(line_uuid, started_at)`,
	// "what is happening on this node" is the incident entry point, and node is
	// also the dimension a core restart is scoped to.
	`CREATE INDEX IF NOT EXISTS idx_conn_records_node_started ON conn_records(node_id, started_at)`,
	// dst_host is indexed for equality and prefix work: which connections went
	// to this exact host. The DstContains substring filter cannot use it (no
	// index can serve a leading wildcard) and narrows a scan instead. The index
	// is also what the planned HMAC tokenisation of dst_host will use, since
	// tokenisation keeps equality and gives up substring (design 4.8).
	`CREATE INDEX IF NOT EXISTS idx_conn_records_dst_started ON conn_records(dst_host, started_at)`,
	// close_reason drives the failure views: every dial_failed in the last hour,
	// every connection a restart swept.
	`CREATE INDEX IF NOT EXISTS idx_conn_records_reason_started ON conn_records(close_reason, started_at)`,

	// conn_record_sessions is the index for "which records did this capture
	// see". It exists because a record carries a list of session ids and SQLite
	// cannot index inside a list. It holds no data of its own: session_ids on
	// conn_records stays the source of truth for the round trip, and these rows
	// are rewritten from it on every upsert. ON DELETE CASCADE keeps retention
	// from leaving orphans behind.
	`CREATE TABLE IF NOT EXISTS conn_record_sessions (
		session_id      TEXT    NOT NULL,
		started_at      INTEGER NOT NULL,
		node_id         TEXT    NOT NULL,
		core_generation INTEGER NOT NULL,
		log_id          INTEGER NOT NULL,
		PRIMARY KEY (session_id, started_at, node_id, core_generation, log_id),
		FOREIGN KEY (node_id, core_generation, log_id, started_at)
			REFERENCES conn_records(node_id, core_generation, log_id, started_at) ON DELETE CASCADE
	) STRICT`,
	// The reverse direction: needed by the semi-join when a query filters by
	// session, and by SQLite itself to apply the cascade without scanning.
	`CREATE INDEX IF NOT EXISTS idx_conn_record_sessions_record ON conn_record_sessions(node_id, core_generation, log_id, started_at)`,

	// trace_lines holds only the raw lines a session marked. Unlabelled lines
	// stay in logstore and never reach here. The primary key is the tail query:
	// one session, ascending sequence, so QueryLines is an index range scan and
	// a re-delivered line replaces itself instead of duplicating.
	`CREATE TABLE IF NOT EXISTS trace_lines (
		session_id  TEXT    NOT NULL,
		node_id     TEXT    NOT NULL,
		seq         INTEGER NOT NULL,
		at          INTEGER NOT NULL,
		level       TEXT    NOT NULL DEFAULT '',
		log_id      INTEGER NOT NULL DEFAULT 0,
		tag         TEXT    NOT NULL DEFAULT '',
		message     TEXT    NOT NULL DEFAULT '',
		raw         TEXT    NOT NULL DEFAULT '',
		dedupe_key  TEXT    NOT NULL DEFAULT '',
		PRIMARY KEY (session_id, seq, node_id)
	) STRICT`,
	// Two different jobs, two different keys. seq is the tail cursor and is
	// assigned by the store, because no agent can order its lines against
	// another node feeding the same session. dedupe_key is content derived, so
	// a batch re-delivered after a lost response is recognised and ignored
	// rather than appearing twice under fresh sequence numbers. Using seq for
	// both would force the agent to invent the cursor, which is what collapsed
	// every line onto one row.
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_trace_lines_dedupe ON trace_lines(session_id, dedupe_key)`,
	// Retention deletes lines by age across all sessions, which the primary key
	// cannot serve.
	`CREATE INDEX IF NOT EXISTS idx_trace_lines_at ON trace_lines(at)`,

	// rollups_5m is the pre-aggregate behind the usage and failure-sequence
	// views: five-minute buckets keyed by user, line and node.
	//
	// bytes_known_count is not decoration. upload and download only include
	// records whose bytes were actually measured, because a connection shorter
	// than the /connections sampling interval is never sampled and its bytes are
	// unknown, not zero. Carrying the count of measured connections next to the
	// sums is what lets a caller say "these sums cover 40 of 120 connections"
	// instead of quietly presenting a partial total as the whole.
	//
	// close_reasons is a JSON object of reason to count. It is a document rather
	// than its own table because the reason set is small and closed, and callers
	// want it per bucket, never as a cross-bucket SQL aggregation.
	`CREATE TABLE IF NOT EXISTS rollups_5m (
		bucket_start INTEGER NOT NULL,
		user_id      TEXT    NOT NULL DEFAULT '',
		line_uuid    TEXT    NOT NULL DEFAULT '',
		node_id      TEXT    NOT NULL DEFAULT '',

		connections       INTEGER NOT NULL DEFAULT 0,
		bytes_known_count INTEGER NOT NULL DEFAULT 0,
		upload            INTEGER NOT NULL DEFAULT 0,
		download          INTEGER NOT NULL DEFAULT 0,
		close_reasons     TEXT    NOT NULL DEFAULT '{}',

		PRIMARY KEY (bucket_start, user_id, line_uuid, node_id)
	) STRICT`,
	// The primary key leads with time, so a per-user or per-node series over a
	// window would scan every bucket in it without these.
	`CREATE INDEX IF NOT EXISTS idx_rollups_5m_user ON rollups_5m(user_id, bucket_start)`,
	`CREATE INDEX IF NOT EXISTS idx_rollups_5m_node ON rollups_5m(node_id, bucket_start)`,
	`CREATE INDEX IF NOT EXISTS idx_rollups_5m_line ON rollups_5m(line_uuid, bucket_start)`,
}
