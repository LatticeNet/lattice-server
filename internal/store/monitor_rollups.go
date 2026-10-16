package store

import (
	"math"
	"sort"
	"time"
)

// Monitor result rollups: per (monitor, node) pair, one record per time
// bucket holding the count of results, the count of failures, a histogram of
// the successful probes' latency and the sum of the jumps between consecutive
// successful probes (jitter). Two tiers: five-minute buckets kept for the
// operator's fine retention (3 to 14 days, 7 by default), which answer every
// series up to that span, and one-hour buckets kept 35 days, which answer
// the longer windows and the matrix from three days up.
//
// Raw rows cannot answer those windows. A pair keeps MonitorResultsPerPair
// rows, which is 24 hours at a 60 s interval and 12 at 30 s, and nothing
// older. The rollups are written in the same transaction as the row they
// count, so they never disagree with what was stored, and a duplicate (a
// batch sent again) adds nothing to either.
//
// Placement follows the rows: in the hot store only, record by record. The
// JSON fallback keeps no rollups and folds the raw series it still holds on
// read, so it answers what that series covers and the rest of the window
// reads as unknown.
//
// The histogram has eight bins per doubling from 0.5 ms, so a bin is about
// 9 percent wide and a percentile read off it is within about 4.5 percent of
// the exact value, which is finer than any colour band drawn from it. Bins
// are sparse: a pair's latency sits in a handful of them.
const (
	MonitorRollupFine   = 5 * time.Minute
	MonitorRollupCoarse = time.Hour
	// monitorRetentionSlack is kept beyond each tier's retention, so the
	// oldest step of the longest window a tier answers is whole: that step
	// starts up to one step before the window does.
	monitorRetentionSlack = time.Hour
	// monitorJitterGap is the longest time between two successful probes
	// whose difference still counts as jitter. A probe after a longer
	// silence (a pause, an outage) starts afresh instead of comparing
	// itself with a reading from another part of the day.
	monitorJitterGap = time.Hour

	monitorRollupBinsPerOctave = 8
	monitorRollupFloorMs       = 0.5
	// monitorRollupBins reaches 0.5 ms * 2^16, about 33 s, past any probe
	// timeout.
	monitorRollupBins = 16 * monitorRollupBinsPerOctave
)

// MonitorRollup is one pair's results over one bucket.
type MonitorRollup struct {
	// At is the bucket start. It is the key, not part of the stored value.
	At time.Time `json:"-"`
	// N counts results and F the failures among them.
	N int `json:"n"`
	F int `json:"f,omitempty"`
	// H is the histogram of successful latencies by bin.
	H map[int]int `json:"h,omitempty"`
	// Min and Max are the exact extremes of the successful latencies, so an
	// estimate never lands outside what was measured.
	Min float64 `json:"min,omitzero"`
	Max float64 `json:"max,omitzero"`
	// JS sums the absolute differences between consecutive successful
	// latencies, JN counts them. Each difference lands in the bucket of the
	// later probe, so merged buckets add up exactly and JS/JN over any merge
	// is the mean jump. Buckets written before jitter existed carry neither.
	JS float64 `json:"js,omitzero"`
	JN int     `json:"jn,omitempty"`
	// S counts probes sent and L the lost ones: every echo of a
	// multi-packet run (icmp), one per run of a single-probe kind, so Loss
	// reads the same for every kind. Buckets written before the fields
	// existed carry neither, and their loss is F over N.
	S int `json:"s,omitempty"`
	L int `json:"l,omitempty"`
}

// MonitorPair names one (monitor, node) result pair.
type MonitorPair struct {
	MonitorID string
	NodeID    string
}

func monitorRollupBin(ms float64) int {
	if !(ms > monitorRollupFloorMs) {
		return 0
	}
	bin := int(math.Floor(monitorRollupBinsPerOctave * math.Log2(ms/monitorRollupFloorMs)))
	return min(max(bin, 0), monitorRollupBins-1)
}

func monitorRollupBinLower(bin int) float64 {
	return monitorRollupFloorMs * math.Exp2(float64(bin)/monitorRollupBinsPerOctave)
}

// Successes is how many of the bucket's results succeeded.
func (r MonitorRollup) Successes() int { return r.N - r.F }

// add counts one result.
func (r *MonitorRollup) add(success bool, latencyMs float64) {
	r.N++
	if !success {
		r.F++
		return
	}
	if math.IsNaN(latencyMs) || math.IsInf(latencyMs, 0) || latencyMs < 0 {
		latencyMs = 0
	}
	if r.H == nil {
		r.H = map[int]int{}
	}
	r.H[monitorRollupBin(latencyMs)]++
	if r.Successes() == 1 || latencyMs < r.Min {
		r.Min = latencyMs
	}
	if r.Successes() == 1 || latencyMs > r.Max {
		r.Max = latencyMs
	}
}

// countable reports whether a result is counted in rollups: a result with a
// reason measured nothing, so it is stored and shown but counts as neither
// a success nor a failure.
func countable(rec MonitorResultRecord) bool { return rec.Reason == "" }

// addResult counts one countable result, its probes included.
func (r *MonitorRollup) addResult(rec MonitorResultRecord) {
	if r.S == 0 && r.N > 0 {
		// A bucket written before buckets counted probes: count its runs
		// as one probe each first, so its loss keeps them.
		r.S, r.L = r.N, r.F
	}
	r.add(rec.Success, rec.LatencyMs)
	if rec.Sent > 0 {
		r.S += rec.Sent
		r.L += min(max(rec.Lost, 0), rec.Sent)
		return
	}
	r.S++
	if !rec.Success {
		r.L++
	}
}

// Loss is the share of probes lost, L over S where the bucket counted
// probes and F over N in a bucket written before it did. False when the
// bucket holds no result.
func (r MonitorRollup) Loss() (float64, bool) {
	switch {
	case r.S > 0:
		return float64(r.L) / float64(r.S), true
	case r.N > 0:
		return float64(r.F) / float64(r.N), true
	}
	return 0, false
}

// addJitter counts one jump between consecutive successful probes.
func (r *MonitorRollup) addJitter(delta float64) {
	if math.IsNaN(delta) || math.IsInf(delta, 0) {
		return
	}
	r.JS += math.Abs(delta)
	r.JN++
}

// Jitter is the mean absolute difference between consecutive successful
// probes counted in the bucket. False when it holds no such pair.
func (r MonitorRollup) Jitter() (float64, bool) {
	if r.JN <= 0 {
		return 0, false
	}
	return r.JS / float64(r.JN), true
}

// monitorJitterDelta is the jump a successful probe at at with latency ms
// makes from the last successful one, false when there is none close enough
// in time to compare with.
func monitorJitterDelta(lastAt time.Time, lastMs float64, at time.Time, ms float64) (float64, bool) {
	if lastAt.IsZero() {
		return 0, false
	}
	gap := at.Sub(lastAt)
	if gap < 0 {
		gap = -gap
	}
	if gap > monitorJitterGap {
		return 0, false
	}
	return math.Abs(ms - lastMs), true
}

// Merge folds o into r. The bucket start stays r's.
func (r *MonitorRollup) Merge(o MonitorRollup) {
	if o.N == 0 {
		return
	}
	hadSuccess, otherSuccess := r.Successes() > 0, o.Successes() > 0
	if r.S == 0 && o.S > 0 && r.N > 0 {
		// r was written before buckets counted probes: count its runs as
		// one probe each, so the merged loss weighs both sides.
		r.S, r.L = r.N, r.F
	}
	if o.S == 0 && r.S > 0 {
		o.S, o.L = o.N, o.F
	}
	r.N += o.N
	r.F += o.F
	r.JS += o.JS
	r.JN += o.JN
	r.S += o.S
	r.L += o.L
	if len(o.H) > 0 && r.H == nil {
		r.H = make(map[int]int, len(o.H))
	}
	for bin, n := range o.H {
		r.H[bin] += n
	}
	switch {
	case otherSuccess && !hadSuccess:
		r.Min, r.Max = o.Min, o.Max
	case otherSuccess:
		r.Min = math.Min(r.Min, o.Min)
		r.Max = math.Max(r.Max, o.Max)
	}
}

// Quantile estimates the q quantile (0 to 1) of the successful latencies. It
// finds the bin holding the nearest-rank sample, places it inside the bin by
// its position among the bin's samples on the bin's log scale, and clamps it
// to the measured extremes. False when nothing succeeded.
func (r MonitorRollup) Quantile(q float64) (float64, bool) {
	n := r.Successes()
	if n <= 0 || len(r.H) == 0 {
		return 0, false
	}
	q = math.Min(math.Max(q, 0), 1)
	rank := max(int(math.Ceil(q*float64(n))), 1)
	bins := make([]int, 0, len(r.H))
	for bin := range r.H {
		bins = append(bins, bin)
	}
	sort.Ints(bins)
	seen := 0
	for _, bin := range bins {
		count := r.H[bin]
		if count <= 0 {
			continue
		}
		if seen+count < rank {
			seen += count
			continue
		}
		frac := (float64(rank-seen) - 0.5) / float64(count)
		value := monitorRollupBinLower(bin) * math.Exp2(frac/monitorRollupBinsPerOctave)
		return math.Min(math.Max(value, r.Min), r.Max), true
	}
	return r.Max, true
}

// RollupMonitorResults buckets raw results at res, keeping the buckets whose
// start lies in [from, to), oldest first. The JSON fallback answers rollup
// reads with it, and a reader folds a pair's recent rows with it at a finer
// step than the stored tiers. rows are one pair's, oldest first; jitter is
// counted between consecutive successes as the hot store counts it, so a
// row before from still serves as the first one's predecessor.
func RollupMonitorResults(rows []MonitorResultRecord, res time.Duration, from, to time.Time) []MonitorRollup {
	byStart := map[time.Time]*MonitorRollup{}
	var lastAt time.Time
	var lastMs float64
	for _, rec := range rows {
		if !countable(rec) {
			continue
		}
		start := rec.At.UTC().Truncate(res)
		delta, jump := 0.0, false
		if rec.Success {
			delta, jump = monitorJitterDelta(lastAt, lastMs, rec.At, rec.LatencyMs)
			lastAt, lastMs = rec.At, rec.LatencyMs
		}
		if start.Before(from) || !start.Before(to) {
			continue
		}
		b := byStart[start]
		if b == nil {
			b = &MonitorRollup{At: start}
			byStart[start] = b
		}
		b.addResult(rec)
		if jump {
			b.addJitter(delta)
		}
	}
	out := make([]MonitorRollup, 0, len(byStart))
	for _, b := range byStart {
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

// MonitorRollups returns each pair's buckets at res (MonitorRollupFine or
// MonitorRollupCoarse) whose start lies in [from, to), oldest first. A pair
// with no buckets in the range has no entry.
func (s *Store) MonitorRollups(pairs []MonitorPair, res time.Duration, from, to time.Time) (map[MonitorPair][]MonitorRollup, error) {
	from, to = from.UTC().Truncate(res), to.UTC()
	if hot := s.hotForMonitorRead(); hot != nil {
		return hot.MonitorRollups(pairs, res, from, to)
	}
	defer s.mu.Unlock()
	out := map[MonitorPair][]MonitorRollup{}
	for _, pair := range pairs {
		rows := s.jsonPairRowsLocked(pair)
		if folded := RollupMonitorResults(rows, res, from, to); len(folded) > 0 {
			out[pair] = folded
		}
	}
	return out, nil
}

// MergeMonitorRollups folds buckets into one summary whose start is the
// first bucket's.
func MergeMonitorRollups(buckets []MonitorRollup) MonitorRollup {
	var out MonitorRollup
	for i, b := range buckets {
		if i == 0 {
			out.At = b.At
		}
		out.Merge(b)
	}
	return out
}

// SummarizeMonitorResults counts raw results (one pair's, oldest first) into
// one bucket, jitter included.
func SummarizeMonitorResults(rows []MonitorResultRecord) MonitorRollup {
	var out MonitorRollup
	var lastAt time.Time
	var lastMs float64
	for i, rec := range rows {
		if i == 0 {
			out.At = rec.At
		}
		if !countable(rec) {
			continue
		}
		out.addResult(rec)
		if !rec.Success {
			continue
		}
		if delta, ok := monitorJitterDelta(lastAt, lastMs, rec.At, rec.LatencyMs); ok {
			out.addJitter(delta)
		}
		lastAt, lastMs = rec.At, rec.LatencyMs
	}
	return out
}
