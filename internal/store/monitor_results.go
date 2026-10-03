package store

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Monitor results: one row per probe outcome, keyed
// "<monitor_id>/<node_id>/<instant>", and one latest record per (monitor,
// node) pair, keyed "<monitor_id>/<node_id>". A tls monitor is evaluated by
// the control plane, so its pair has an empty node id.
//
// Placement follows the node status history and the usage-day rollups: with
// the hot store on, rows and latest records live only in bolt and every result
// is one record-level transaction, so a fleet-wide monitor never rewrites
// state.json. Without the hot store they stay in State.MonResults, bounded
// harder, and the whole file is saved only when a pair changes state or its
// copy on disk is monitorResultPersistenceInterval old.
//
// History is bounded per pair, not per monitor. The old bound, 500 results
// shared by every node, was about seven minutes of a 30 s monitor on a
// 34-node fleet.
const (
	// MonitorResultsPerPair is the history one (monitor, node) pair keeps in
	// the hot store: 12 hours at the 30 s default interval. Each row is about
	// 120 bytes with its key, so a monitor on every node of a 34-node fleet
	// holds about 6 MB.
	MonitorResultsPerPair = 1440
	// monitorResultsPerPairJSON is the same bound without the hot store,
	// where every row kept is rewritten with the whole state file: one hour
	// at the default interval.
	monitorResultsPerPairJSON = 120
	// MonitorResultMaxAge drops an agent result that arrives this long after
	// it was taken. An agent's outage buffer holds minutes, so an older stamp
	// is a broken clock or a replay, not a late report.
	MonitorResultMaxAge = 24 * time.Hour
	// MonitorResultMaxSkew is how far ahead of the control plane an agent's
	// stamp may run. A later stamp is dropped like a stale one rather than
	// replaced by the arrival time: the stamp is the row's key, and a key the
	// server made up differs on every attempt, so a batch sent again after a
	// lost response would store its results twice and count one failure as
	// two. An agent stamps a probe before it sends it, so a synced clock is
	// never ahead; one a minute ahead is broken, and the server logs it.
	MonitorResultMaxSkew = time.Minute
	// monitorResultErrorMax bounds the error text one row keeps. The text
	// comes from the agent, and a pair keeps up to MonitorResultsPerPair rows.
	monitorResultErrorMax = 512
	// monitorResultLayout is fixed width so keys sort as instants.
	monitorResultLayout = nodeStatusEventLayout
)

// Reasons an agent's result is not admitted. The agent ingest response
// carries them so an agent can tell a result to drop from one to retry.
const (
	MonitorResultDropUnknownMonitor  = "unknown_monitor"
	MonitorResultDropServerEvaluated = "server_evaluated"
	MonitorResultDropDisabled        = "disabled"
	MonitorResultDropNotAssigned     = "not_assigned"
	MonitorResultDropOutOfWindow     = "out_of_window"
	MonitorResultDropInvalid         = "invalid"
)

// MonitorResultRecord is one stored result: the probe outcome as reported,
// and when the control plane received it. A ReceivedAt well after At marks a
// result that waited in an agent's buffer, so a reader can show the gap as
// unheard rather than as down.
type MonitorResultRecord struct {
	model.MonitorResult
	ReceivedAt time.Time `json:"received_at,omitzero"`
}

// MonitorLatest is one pair's newest result and the run it ends.
type MonitorLatest struct {
	MonitorResultRecord
	// FailStreak counts the failures in a row that end with this result. It
	// is zero after a success. The alert hold decides on it.
	FailStreak int `json:"fail_streak"`
	// Since is when the current run of successes or failures began: the At
	// of its first result, as far back as the pair's history reaches.
	Since time.Time `json:"since"`
	// Held is how many rows the pair holds, so the hot store trims without
	// counting keys on every result.
	Held int `json:"held"`
}

// MonitorResultOutcome is what the store did with one result.
type MonitorResultOutcome struct {
	// Dropped is empty when the result was admitted, else why it was not.
	Dropped string
	// Duplicate is true when the pair already held a result at this
	// instant: a retried batch. Nothing was written and nothing changed.
	Duplicate bool
	// PriorFailStreak is the pair's FailStreak before this result.
	PriorFailStreak int
	// Result is the result as admitted: node id set, stamp normalized.
	Result MonitorResultRecord
}

// Stored reports whether the result became a new row.
func (o MonitorResultOutcome) Stored() bool { return o.Dropped == "" && !o.Duplicate }

func monitorPairKey(monitorID, nodeID string) string { return monitorID + "/" + nodeID }

func monitorResultKey(monitorID, nodeID string, at time.Time) string {
	return monitorPairKey(monitorID, nodeID) + "/" + at.UTC().Format(monitorResultLayout)
}

// splitMonitorPairKey is the inverse of monitorPairKey. Monitor ids never
// hold a slash, so the first one ends it; the node id may be empty.
func splitMonitorPairKey(key string) (monitorID, nodeID string, ok bool) {
	i := strings.IndexByte(key, '/')
	if i <= 0 {
		return "", "", false
	}
	return key[:i], key[i+1:], true
}

// splitMonitorResultKey is the inverse of monitorResultKey.
func splitMonitorResultKey(key string) (monitorID, nodeID string, at time.Time, ok bool) {
	i := strings.LastIndexByte(key, '/')
	if i <= 0 {
		return "", "", time.Time{}, false
	}
	monitorID, nodeID, ok = splitMonitorPairKey(key[:i])
	if !ok {
		return "", "", time.Time{}, false
	}
	at, err := time.Parse(monitorResultLayout, key[i+1:])
	if err != nil {
		return "", "", time.Time{}, false
	}
	return monitorID, nodeID, at, true
}

// validMonitorPair refuses ids that would break the key layout.
func validMonitorPair(monitorID, nodeID string) error {
	if monitorID == "" || strings.ContainsAny(monitorID, "/\x00") || strings.ContainsAny(nodeID, "/\x00") {
		return fmt.Errorf("invalid monitor result pair %q/%q", monitorID, nodeID)
	}
	return nil
}

// advanceMonitorLatest is the pair's latest record after rec. The run and the
// streak follow arrival order, which is the order the alert hold has always
// judged in.
func advanceMonitorLatest(prior MonitorLatest, hadPrior bool, rec MonitorResultRecord) MonitorLatest {
	next := MonitorLatest{MonitorResultRecord: rec, Since: rec.At, Held: 1}
	if hadPrior {
		next.Held = prior.Held + 1
		if prior.Success == rec.Success {
			next.Since = prior.Since
		}
	}
	if !rec.Success {
		next.FailStreak = 1
		if hadPrior {
			next.FailStreak = prior.FailStreak + 1
		}
	}
	return next
}

// latestFromSeries derives one pair's latest record from a monitor's JSON
// series (arrival order). Without the hot store nothing else holds it.
func latestFromSeries(series []MonitorResultRecord, nodeID string) (MonitorLatest, bool) {
	var out MonitorLatest
	found, runOpen := false, true
	for i := len(series) - 1; i >= 0; i-- {
		r := series[i]
		if r.NodeID != nodeID {
			continue
		}
		out.Held++
		if !found {
			out.MonitorResultRecord, out.Since, found = r, r.At, true
			if !r.Success {
				out.FailStreak = 1
			}
			continue
		}
		if runOpen && r.Success == out.Success {
			out.Since = r.At
			if !r.Success {
				out.FailStreak++
			}
			continue
		}
		runOpen = false
	}
	return out, found
}

func truncateUTF8(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	s = s[:limit]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// admitAgentMonitorResultLocked decides whether an agent's result may be
// stored for its node and normalizes it.
//
// Every admitted result keeps the stamp the agent gave it. A result without
// one is invalid and one outside the window is dropped; neither is restamped
// with the arrival time, because the stamp is the row key that makes a retry
// a duplicate. Every agent released so far stamps each probe when it starts.
//
// The checks run under the store lock, together with the write, so a monitor
// deleted or unassigned while a batch is in flight cannot gain rows the
// delete would have removed.
func (s *Store) admitAgentMonitorResultLocked(nodeID string, r model.MonitorResult, receivedAt time.Time) (MonitorResultRecord, string) {
	mon, ok := s.state.Monitors[r.MonitorID]
	switch {
	case r.MonitorID == "" || !ok:
		return MonitorResultRecord{}, MonitorResultDropUnknownMonitor
	case mon.Type == model.MonitorTypeTLS:
		// The control plane dials tls monitors itself. An agent's verdict
		// on one would overwrite the server's reading of a certificate.
		return MonitorResultRecord{}, MonitorResultDropServerEvaluated
	case !mon.Enabled:
		return MonitorResultRecord{}, MonitorResultDropDisabled
	case !mon.AssignAll && !contains(mon.NodeIDs, nodeID):
		return MonitorResultRecord{}, MonitorResultDropNotAssigned
	}
	if nodeID == "" || validMonitorPair(r.MonitorID, nodeID) != nil || r.At.IsZero() {
		return MonitorResultRecord{}, MonitorResultDropInvalid
	}
	receivedAt = receivedAt.UTC()
	if r.At.Before(receivedAt.Add(-MonitorResultMaxAge)) || r.At.After(receivedAt.Add(MonitorResultMaxSkew)) {
		return MonitorResultRecord{}, MonitorResultDropOutOfWindow
	}
	r.At = r.At.UTC()
	r.NodeID = nodeID
	r.Error = truncateUTF8(r.Error, monitorResultErrorMax)
	// Only a tls probe reads a certificate, and agents never run those.
	r.CertNotAfter = time.Time{}
	return MonitorResultRecord{MonitorResult: r, ReceivedAt: receivedAt}, ""
}

// IngestAgentMonitorResults admits an agent's results for its own node and
// records the admitted ones in order, in one write. The outcomes line up with
// results. Results for one pair are judged in the order given, so an agent
// sends a buffered backlog oldest first.
//
// A failed write stores nothing and returns the error; the whole batch can be
// sent again, and the results the first attempt did store come back as
// duplicates.
func (s *Store) IngestAgentMonitorResults(nodeID string, results []model.MonitorResult, receivedAt time.Time) ([]MonitorResultOutcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	outcomes := make([]MonitorResultOutcome, len(results))
	records := make([]MonitorResultRecord, 0, len(results))
	positions := make([]int, 0, len(results))
	for i, r := range results {
		rec, reason := s.admitAgentMonitorResultLocked(nodeID, r, receivedAt)
		if reason != "" {
			r.NodeID = nodeID
			outcomes[i] = MonitorResultOutcome{Dropped: reason, Result: MonitorResultRecord{MonitorResult: r}}
			continue
		}
		records = append(records, rec)
		positions = append(positions, i)
	}
	recorded, err := s.recordMonitorResultsLocked(records)
	if err != nil {
		return nil, err
	}
	for j, i := range positions {
		outcomes[i] = recorded[j]
	}
	return outcomes, nil
}

// AddMonitorResult records one result without the agent admission checks.
// The control plane's tls sweep uses it for its own readings, and tests seed
// history with it.
func (s *Store) AddMonitorResult(r model.MonitorResult) (MonitorResultOutcome, error) {
	if err := validMonitorPair(r.MonitorID, r.NodeID); err != nil {
		return MonitorResultOutcome{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if r.At.IsZero() {
		r.At = now
	}
	r.At = r.At.UTC()
	out, err := s.recordMonitorResultsLocked([]MonitorResultRecord{{MonitorResult: r, ReceivedAt: now}})
	if err != nil {
		return MonitorResultOutcome{}, err
	}
	return out[0], nil
}

func (s *Store) recordMonitorResultsLocked(records []MonitorResultRecord) ([]MonitorResultOutcome, error) {
	if len(records) == 0 {
		return nil, nil
	}
	if s.runtimeBoltHot != nil {
		return s.runtimeBoltHot.RecordMonitorResults(records, MonitorResultsPerPair)
	}
	return s.recordMonitorResultsJSONLocked(records)
}

// recordMonitorResultsJSONLocked is the fallback without the hot store. The
// whole state file is saved once for the batch, and only when a pair changed
// state, reached its second failure in a row (the alert hold pages there and
// must not forget it across a restart), or has not been written for
// monitorResultPersistenceInterval.
func (s *Store) recordMonitorResultsJSONLocked(records []MonitorResultRecord) ([]MonitorResultOutcome, error) {
	if s.monitorPersistedAt == nil {
		s.monitorPersistedAt = map[string]time.Time{}
	}
	now := time.Now().UTC()
	outcomes := make([]MonitorResultOutcome, len(records))
	touched := map[string]struct{}{}
	save := false
	for i, rec := range records {
		series := s.state.MonResults[rec.MonitorID]
		prior, hadPrior := latestFromSeries(series, rec.NodeID)
		outcomes[i] = MonitorResultOutcome{Result: rec, PriorFailStreak: prior.FailStreak}
		if monitorSeriesHolds(series, rec.NodeID, rec.At) {
			outcomes[i].Duplicate = true
			continue
		}
		series = trimMonitorSeries(append(series, rec), rec.NodeID, monitorResultsPerPairJSON)
		s.state.MonResults[rec.MonitorID] = series

		key := monitorResultPersistenceKey(rec.MonitorID, rec.NodeID)
		touched[key] = struct{}{}
		transitioned := !hadPrior || prior.Success != rec.Success || prior.Error != rec.Error
		secondFailure := !rec.Success && hadPrior && prior.FailStreak == 1
		lastPersisted, persisted := s.monitorPersistedAt[key]
		if !persisted || transitioned || secondFailure || now.Sub(lastPersisted) >= monitorResultPersistenceInterval {
			save = true
		}
	}
	if !save {
		return outcomes, nil
	}
	if err := s.Save(); err != nil {
		return nil, err
	}
	// The write carried every pair, so each one touched here is now on disk.
	for key := range touched {
		s.monitorPersistedAt[key] = now
	}
	return outcomes, nil
}

func monitorSeriesHolds(series []MonitorResultRecord, nodeID string, at time.Time) bool {
	for i := len(series) - 1; i >= 0; i-- {
		if series[i].NodeID == nodeID && series[i].At.Equal(at) {
			return true
		}
	}
	return false
}

// trimMonitorSeries drops the oldest rows of one pair beyond limit, keeping
// the other pairs' rows and the series order.
func trimMonitorSeries(series []MonitorResultRecord, nodeID string, limit int) []MonitorResultRecord {
	held := 0
	for _, r := range series {
		if r.NodeID == nodeID {
			held++
		}
	}
	excess := held - limit
	if excess <= 0 {
		return series
	}
	kept := series[:0]
	for _, r := range series {
		if r.NodeID == nodeID && excess > 0 {
			excess--
			continue
		}
		kept = append(kept, r)
	}
	return kept
}

// MonitorLatest is one pair's latest record.
func (s *Store) MonitorLatest(monitorID, nodeID string) (MonitorLatest, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runtimeBoltHot != nil {
		return s.runtimeBoltHot.MonitorLatest(monitorID, nodeID)
	}
	latest, ok := latestFromSeries(s.state.MonResults[monitorID], nodeID)
	return latest, ok, nil
}

// LatestMonitorResults is every pair's latest record, keyed by monitor id and
// sorted by node id. It answers the monitors list in one read instead of one
// history read per monitor.
func (s *Store) LatestMonitorResults() (map[string][]MonitorLatest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runtimeBoltHot != nil {
		return s.runtimeBoltHot.LatestMonitorResults()
	}
	out := map[string][]MonitorLatest{}
	for monitorID, series := range s.state.MonResults {
		seen := map[string]struct{}{}
		for _, r := range series {
			if _, ok := seen[r.NodeID]; ok {
				continue
			}
			seen[r.NodeID] = struct{}{}
			if latest, ok := latestFromSeries(series, r.NodeID); ok {
				out[monitorID] = append(out[monitorID], latest)
			}
		}
		sort.Slice(out[monitorID], func(i, j int) bool { return out[monitorID][i].NodeID < out[monitorID][j].NodeID })
	}
	return out, nil
}

// MonitorPairResults is one pair's newest limit results, oldest first.
func (s *Store) MonitorPairResults(monitorID, nodeID string, limit int) ([]MonitorResultRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runtimeBoltHot != nil {
		return s.runtimeBoltHot.MonitorPairResults(monitorID, nodeID, limit)
	}
	out := []MonitorResultRecord{}
	for _, r := range s.state.MonResults[monitorID] {
		if r.NodeID == nodeID {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return newestTail(out, limit), nil
}

// RecentMonitorResults is a monitor's newest limit results across the pairs
// allow admits (every pair when allow is nil), oldest first.
func (s *Store) RecentMonitorResults(monitorID string, limit int, allow func(nodeID string) bool) ([]MonitorResultRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runtimeBoltHot != nil {
		return s.runtimeBoltHot.RecentMonitorResults(monitorID, limit, allow)
	}
	out := []MonitorResultRecord{}
	for _, r := range s.state.MonResults[monitorID] {
		if allow == nil || allow(r.NodeID) {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return newestTail(out, limit), nil
}

// NewestMonitorResult walks one pair's history newest first and returns the
// first result match accepts.
func (s *Store) NewestMonitorResult(monitorID, nodeID string, match func(MonitorResultRecord) bool) (MonitorResultRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runtimeBoltHot != nil {
		return s.runtimeBoltHot.NewestMonitorResult(monitorID, nodeID, match)
	}
	series := append([]MonitorResultRecord(nil), s.state.MonResults[monitorID]...)
	sort.SliceStable(series, func(i, j int) bool { return series[i].At.Before(series[j].At) })
	for i := len(series) - 1; i >= 0; i-- {
		if series[i].NodeID == nodeID && match(series[i]) {
			return series[i], true, nil
		}
	}
	return MonitorResultRecord{}, false, nil
}

func newestTail(rows []MonitorResultRecord, limit int) []MonitorResultRecord {
	if limit > 0 && len(rows) > limit {
		return rows[len(rows)-limit:]
	}
	return rows
}

// monitorResultsHeldForNodeLocked counts the rows a node's pairs hold, for
// the node delete report. With the hot store it reads each pair's Held, so a
// preview never walks the rows.
func (s *Store) monitorResultsHeldForNodeLocked(nodeID string) int {
	if s.runtimeBoltHot != nil {
		held, err := s.runtimeBoltHot.MonitorResultsHeldForNode(nodeID)
		if err != nil {
			// A count for a report. The delete itself returns the error.
			return 0
		}
		return held
	}
	held := 0
	for _, series := range s.state.MonResults {
		for _, r := range series {
			if r.NodeID == nodeID {
				held++
			}
		}
	}
	return held
}
