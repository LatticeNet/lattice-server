package store

import (
	"math"
	"sort"
	"time"
)

// Monitor result rollups: per (monitor, node) pair, one record per time
// bucket holding the count of results, the count of failures and a histogram
// of the successful probes' latency. Two tiers: five-minute buckets kept two
// days, which answer the 1 h and 24 h windows and their series, and one-hour
// buckets kept eight days, which answer 7 d.
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
	// monitorRollupFineKeep covers the 24 h window, its series, and a day of
	// slack for a late batch.
	monitorRollupFineKeep = 48 * time.Hour
	// monitorRollupCoarseKeep covers the 7 d window and a day of slack.
	monitorRollupCoarseKeep = 8 * 24 * time.Hour

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

// Merge folds o into r. The bucket start stays r's.
func (r *MonitorRollup) Merge(o MonitorRollup) {
	if o.N == 0 {
		return
	}
	hadSuccess, otherSuccess := r.Successes() > 0, o.Successes() > 0
	r.N += o.N
	r.F += o.F
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
// step than the stored tiers.
func RollupMonitorResults(rows []MonitorResultRecord, res time.Duration, from, to time.Time) []MonitorRollup {
	byStart := map[time.Time]*MonitorRollup{}
	for _, rec := range rows {
		start := rec.At.UTC().Truncate(res)
		if start.Before(from) || !start.Before(to) {
			continue
		}
		b := byStart[start]
		if b == nil {
			b = &MonitorRollup{At: start}
			byStart[start] = b
		}
		b.add(rec.Success, rec.LatencyMs)
	}
	out := make([]MonitorRollup, 0, len(byStart))
	for _, b := range byStart {
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

func monitorRollupKeep(res time.Duration) time.Duration {
	if res == MonitorRollupCoarse {
		return monitorRollupCoarseKeep
	}
	return monitorRollupFineKeep
}

// MonitorRollups returns each pair's buckets at res (MonitorRollupFine or
// MonitorRollupCoarse) whose start lies in [from, to), oldest first. A pair
// with no buckets in the range has no entry.
func (s *Store) MonitorRollups(pairs []MonitorPair, res time.Duration, from, to time.Time) (map[MonitorPair][]MonitorRollup, error) {
	from, to = from.UTC().Truncate(res), to.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runtimeBoltHot != nil {
		return s.runtimeBoltHot.MonitorRollups(pairs, res, from, to)
	}
	out := map[MonitorPair][]MonitorRollup{}
	for _, pair := range pairs {
		var rows []MonitorResultRecord
		for _, r := range s.state.MonResults[pair.MonitorID] {
			if r.NodeID == pair.NodeID {
				rows = append(rows, r)
			}
		}
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

// SummarizeMonitorResults counts raw results into one bucket.
func SummarizeMonitorResults(rows []MonitorResultRecord) MonitorRollup {
	var out MonitorRollup
	for i, rec := range rows {
		if i == 0 {
			out.At = rec.At
		}
		out.add(rec.Success, rec.LatencyMs)
	}
	return out
}
