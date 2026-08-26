package tracestore

import (
	"fmt"
	"time"
)

const (
	// retainBatch is how many rows one delete statement removes. Retention runs
	// against a store that is being written to, and a single unbounded DELETE
	// would hold the write lock for as long as it takes to walk millions of
	// rows, stalling ingest. Batching releases the lock between statements.
	retainBatch = 500
	// maxRetainBatches bounds one Retain call so a sweeper tick cannot turn into
	// an unbounded run. Hitting it sets RetainResult.Truncated; the next tick
	// continues where this one stopped.
	maxRetainBatches = 400
)

// RetainResult is what one Retain call removed.
type RetainResult struct {
	// Expired counts come from the three TTLs.
	RecordsExpired int64 `json:"records_expired"`
	LinesExpired   int64 `json:"lines_expired"`
	RollupsExpired int64 `json:"rollups_expired"`
	// Evicted counts come from the MaxBytes ceiling, oldest first.
	RecordsEvicted int64 `json:"records_evicted"`
	LinesEvicted   int64 `json:"lines_evicted"`

	BytesBefore int64 `json:"bytes_before"`
	BytesAfter  int64 `json:"bytes_after"`
	// Truncated reports that the batch ceiling was reached with work left. It is
	// surfaced rather than hidden: a store that never gets back under its cap
	// should be visible, not quietly growing.
	Truncated bool `json:"truncated"`
}

// Retain enforces the three TTLs and then the total size ceiling, deleting
// oldest first, and reports what it removed. now is passed in rather than read
// from the clock so the sweeper and the tests drive the same code path.
func (s *Store) Retain(now time.Time) (RetainResult, error) {
	var res RetainResult
	before, err := s.sizeBytes()
	if err != nil {
		return res, err
	}
	res.BytesBefore = before

	budget := maxRetainBatches

	n, spent, err := s.deleteOldest(`DELETE FROM conn_records WHERE rowid IN (
		SELECT rowid FROM conn_records WHERE started_at < ? ORDER BY started_at LIMIT ?)`,
		nanos(now.Add(-s.opts.RecordTTL)), budget)
	if err != nil {
		return res, fmt.Errorf("tracestore: retain records: %w", err)
	}
	res.RecordsExpired, budget = n, budget-spent

	n, spent, err = s.deleteOldest(`DELETE FROM trace_lines WHERE rowid IN (
		SELECT rowid FROM trace_lines WHERE at < ? ORDER BY at LIMIT ?)`,
		nanos(now.Add(-s.opts.LineTTL)), budget)
	if err != nil {
		return res, fmt.Errorf("tracestore: retain lines: %w", err)
	}
	res.LinesExpired, budget = n, budget-spent

	n, spent, err = s.deleteOldest(`DELETE FROM rollups_5m WHERE rowid IN (
		SELECT rowid FROM rollups_5m WHERE bucket_start < ? ORDER BY bucket_start LIMIT ?)`,
		nanos(now.Add(-s.opts.RollupTTL)), budget)
	if err != nil {
		return res, fmt.Errorf("tracestore: retain rollups: %w", err)
	}
	res.RollupsExpired, budget = n, budget-spent

	if err := s.reclaim(); err != nil {
		return res, err
	}
	if err := s.evictToMaxBytes(&res, &budget); err != nil {
		return res, err
	}

	after, err := s.sizeBytes()
	if err != nil {
		return res, err
	}
	res.BytesAfter = after
	if budget <= 0 {
		res.Truncated = true
	}
	return res, nil
}

// evictToMaxBytes deletes oldest-first until the database is under the ceiling.
// Records go first because they are the bulk and the oldest ones are the least
// useful; only when there are none left does it fall back to raw lines, so the
// sweep still converges on a store that holds nothing but session lines.
func (s *Store) evictToMaxBytes(res *RetainResult, budget *int) error {
	for *budget > 0 {
		size, err := s.sizeBytes()
		if err != nil {
			return err
		}
		if size <= s.opts.MaxBytes {
			return nil
		}
		n, spent, err := s.deleteOldest(`DELETE FROM conn_records WHERE rowid IN (
			SELECT rowid FROM conn_records ORDER BY started_at LIMIT ?)`, nil, 1)
		if err != nil {
			return fmt.Errorf("tracestore: evict records: %w", err)
		}
		*budget -= spent
		res.RecordsEvicted += n
		if n == 0 {
			m, spent, err := s.deleteOldest(`DELETE FROM trace_lines WHERE rowid IN (
				SELECT rowid FROM trace_lines ORDER BY at LIMIT ?)`, nil, 1)
			if err != nil {
				return fmt.Errorf("tracestore: evict lines: %w", err)
			}
			*budget -= spent
			res.LinesEvicted += m
			if m == 0 {
				// Nothing left to delete and still over the ceiling. That means
				// the floor is schema and free-page overhead, not data; report
				// rather than spin.
				return nil
			}
		}
		if err := s.reclaim(); err != nil {
			return err
		}
	}
	return nil
}

// deleteOldest runs a batched delete and returns the rows removed and the
// batches spent. cutoff is nil for the size-driven sweep, which has no time
// bound and deletes the oldest rows outright.
func (s *Store) deleteOldest(query string, cutoff any, budget int) (int64, int, error) {
	var (
		total   int64
		batches int
	)
	for batches < budget {
		s.mu.Lock()
		var (
			args []any
		)
		if cutoff != nil {
			args = []any{cutoff, retainBatch}
		} else {
			args = []any{retainBatch}
		}
		out, err := s.db.Exec(query, args...)
		s.mu.Unlock()
		if err != nil {
			return total, batches, err
		}
		n, err := out.RowsAffected()
		if err != nil {
			return total, batches, err
		}
		batches++
		total += n
		if n < retainBatch {
			break
		}
	}
	return total, batches, nil
}

// reclaim hands freed pages back to the filesystem. Without it a delete only
// marks pages free inside the file, the file never shrinks, and the MaxBytes
// sweep would delete forever without the measured size moving. It is a no-op on
// a database that predates incremental auto-vacuum, which is why Open records
// whether the mode took.
func (s *Store) reclaim() error {
	if !s.autoVacuum {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec("PRAGMA incremental_vacuum"); err != nil {
		return fmt.Errorf("tracestore: incremental vacuum: %w", err)
	}
	return nil
}
