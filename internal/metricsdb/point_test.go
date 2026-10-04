package metricsdb

import (
	"encoding/binary"
	"math"
	"math/rand"
	"sort"
	"testing"
	"time"
)

func TestGaugeObserveAndMerge(t *testing.T) {
	var g Gauge
	for _, v := range []float64{3, 1, 2, math.NaN(), math.Inf(1)} {
		g.Observe(v)
	}
	if g.Count != 3 || g.Min != 1 || g.Max != 3 || g.Sum != 6 || g.Avg() != 2 {
		t.Fatalf("gauge = %+v avg %v, want count 3 min 1 max 3 sum 6 avg 2", g, g.Avg())
	}
	var empty Gauge
	empty.Merge(g)
	if empty != g {
		t.Fatalf("merge into empty = %+v, want %+v", empty, g)
	}
	other := Gauge{Count: 2, Min: -1, Max: 10, Sum: 9}
	g.Merge(other)
	if g.Count != 5 || g.Min != -1 || g.Max != 10 || g.Sum != 15 {
		t.Fatalf("merged = %+v", g)
	}
}

func TestEventQuantileWithinBinError(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	var e Event
	var raw []float64
	for i := 0; i < 5000; i++ {
		// Log-normal around 20 ms: the shape of a request latency.
		s := 0.02 * math.Exp(rng.NormFloat64()*0.8)
		raw = append(raw, s)
		e.Observe(time.Duration(s*float64(time.Second)), i%50 == 0)
	}
	sort.Float64s(raw)
	for _, q := range []float64{0.5, 0.95, 0.99} {
		got, ok := e.Quantile(q)
		if !ok {
			t.Fatalf("quantile %v not ok", q)
		}
		want := raw[int(math.Ceil(q*float64(len(raw))))-1]
		if rel := math.Abs(got-want) / want; rel > 0.10 {
			t.Fatalf("p%v = %.5f, exact %.5f, off by %.1f%% (bin error bound is about 9.5%%)", q*100, got, want, rel*100)
		}
	}
	if e.Errors != 100 || e.Count != 5000 {
		t.Fatalf("count %d errors %d, want 5000 and 100", e.Count, e.Errors)
	}
	if got, _ := e.Quantile(1); got != e.Max {
		t.Fatalf("p100 = %v, want the measured max %v", got, e.Max)
	}
}

func TestEventMergeIsExact(t *testing.T) {
	var a, b, all Event
	for i := 1; i <= 100; i++ {
		d := time.Duration(i) * time.Millisecond
		all.Observe(d, i%10 == 0)
		if i <= 40 {
			a.Observe(d, i%10 == 0)
		} else {
			b.Observe(d, i%10 == 0)
		}
	}
	a.Merge(&b)
	if a.Count != all.Count || a.Errors != all.Errors || a.Bins != all.Bins || a.Min != all.Min || a.Max != all.Max {
		t.Fatalf("merged %+v differs from observed together %+v", a, all)
	}
	if math.Abs(a.Sum-all.Sum) > 1e-12 {
		t.Fatalf("sum %v, want %v", a.Sum, all.Sum)
	}
}

func TestRowRoundTripAndSkip(t *testing.T) {
	ev := &Event{}
	for _, ms := range []int{1, 2, 3, 250, 900, 4000} {
		ev.Observe(time.Duration(ms)*time.Millisecond, ms == 900)
	}
	points := []rowPoint{
		{series: 1, point: Point{Kind: KindGauge, Gauge: Gauge{Count: 6, Min: 0.5, Max: 92.25, Sum: 301.5}}},
		{series: 7, point: Point{Kind: KindEvent, Event: ev}},
		{series: 9, point: Point{Kind: KindGauge}}, // empty: left out
	}
	row := encodeRow(points)
	got := map[uint32]Point{}
	if err := decodeRow(row, nil, func(s uint32, p Point) { got[s] = p }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("decoded %d points, want 2 (the empty one is not stored)", len(got))
	}
	if g := got[1].Gauge; g.Count != 6 || g.Min != 0.5 || g.Max != 92.25 || g.Sum != 301.5 {
		t.Fatalf("gauge round trip = %+v", g)
	}
	// Stored as float32: one rounding, within a part in ten million.
	e := got[7].Event
	if e.Count != ev.Count || e.Errors != ev.Errors || e.Bins != ev.Bins || math.Abs(e.Sum-ev.Sum) > ev.Sum*1e-7 || math.Abs(e.Max-ev.Max) > ev.Max*1e-7 {
		t.Fatalf("event round trip = %+v, want %+v", e, ev)
	}
	// A reader that wants one series decodes only that one.
	calls := 0
	if err := decodeRow(row, func(s uint32) bool { return s == 7 }, func(s uint32, p Point) {
		calls++
		if s != 7 {
			t.Fatalf("decoded unwanted series %d", s)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("decoded %d points, want 1", calls)
	}
	// Truncation anywhere is an error, never a panic or a silent partial row.
	for cut := 2; cut < len(row); cut++ {
		_ = decodeRow(row[:cut], nil, func(uint32, Point) {})
	}
	if err := decodeRow(row[:len(row)-1], nil, func(uint32, Point) {}); err == nil {
		t.Fatal("truncated row decoded without error")
	}
}

func TestRowSkipsUnknownKind(t *testing.T) {
	row := encodeRow([]rowPoint{{series: 3, point: Point{Kind: KindGauge, Gauge: Gauge{Count: 1, Min: 1, Max: 1, Sum: 1}}}})
	// Append a point of a kind from the future: series 4, kind 9, 2 bytes.
	row = append(row, 4, 9, 2, 0xAA, 0xBB)
	seen := 0
	if err := decodeRow(row, nil, func(uint32, Point) { seen++ }); err != nil {
		t.Fatalf("unknown kind failed the row: %v", err)
	}
	if seen != 1 {
		t.Fatalf("saw %d points, want 1", seen)
	}
}

// TestQuantilePlacedInsideItsBin uses durations spread evenly on a log scale
// from 1 ms to 1 s, so the exact quantiles fall inside their bins rather
// than on an edge. Placing the estimate inside the bin keeps it within a
// fraction of a percent; reading the bin's lower edge would be off by up to
// a bin's width (about 19 percent), here about 3 percent.
func TestQuantilePlacedInsideItsBin(t *testing.T) {
	var e Event
	const n = 4000
	raw := make([]float64, n)
	for i := range raw {
		raw[i] = 1e-3 * math.Pow(1000, (float64(i)+0.5)/n)
		e.Observe(time.Duration(raw[i]*float64(time.Second)), false)
	}
	for _, q := range []float64{0.5, 0.9} {
		got, _ := e.Quantile(q)
		want := raw[int(math.Ceil(q*n))-1]
		if rel := math.Abs(got-want) / want; rel > 0.015 {
			t.Fatalf("p%v = %.5f, exact %.5f, off by %.1f%%", q*100, got, want, rel*100)
		}
	}
}

// TestRowRejectsBinsPastTheEnd hands decodeRow an event whose bin gaps are
// each in range but add up past the last bin: an error, never an index out
// of range.
func TestRowRejectsBinsPastTheEnd(t *testing.T) {
	var payload []byte
	payload = binary.AppendUvarint(payload, 2) // count
	payload = binary.AppendUvarint(payload, 0) // errors
	for i := 0; i < 3; i++ {                   // sum, min, max
		payload = appendF32(payload, 0.01)
	}
	payload = binary.AppendUvarint(payload, 2)           // two non-empty bins
	payload = binary.AppendUvarint(payload, EventBins-8) // the first at bin 80
	payload = binary.AppendUvarint(payload, 1)           // one event
	payload = binary.AppendUvarint(payload, EventBins-8) // the next 81 bins on
	payload = binary.AppendUvarint(payload, 1)           // one event
	row := []byte{rowVersion}
	row = binary.AppendUvarint(row, 1)
	row = append(row, byte(KindEvent))
	row = binary.AppendUvarint(row, uint64(len(payload)))
	row = append(row, payload...)
	if err := decodeRow(row, nil, func(uint32, Point) {}); err == nil {
		t.Fatal("bins past the last decoded without error")
	}
}

// TestHugeValuesStayFinite stores a gauge past the float32 range, as a
// misbehaving agent could report, and a sum that only overflows once added
// up: both come back finite, at the largest float32.
func TestHugeValuesStayFinite(t *testing.T) {
	var g Gauge
	g.Observe(1e39)
	g.Observe(-1e39)
	sum := Gauge{Count: 2, Min: 3e38, Max: 3e38, Sum: 6e38}
	row := encodeRow([]rowPoint{{series: 1, point: Point{Kind: KindGauge, Gauge: g}}, {series: 2, point: Point{Kind: KindGauge, Gauge: sum}}})
	got := map[uint32]Gauge{}
	if err := decodeRow(row, nil, func(s uint32, p Point) { got[s] = p.Gauge }); err != nil {
		t.Fatal(err)
	}
	for s, g := range got {
		for _, v := range []float64{g.Min, g.Max, g.Sum, g.Avg()} {
			if math.IsInf(v, 0) || math.IsNaN(v) {
				t.Fatalf("series %d read back %+v, want every field finite", s, g)
			}
		}
	}
	if got[1].Max != math.MaxFloat32 || got[1].Min != -math.MaxFloat32 || got[2].Sum != math.MaxFloat32 {
		t.Fatalf("read back %+v, want the values clamped to the float32 range", got)
	}
}
