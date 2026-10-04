package metricsdb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
)

// Kind says how a series summarises what it records.
type Kind uint8

const (
	// KindGauge is a level sampled now and then (memory in use, CPU percent,
	// a file's size). A point keeps the samples' count, min, max and sum, so
	// a chart can draw the average and the spread at any resolution.
	KindGauge Kind = 1
	// KindEvent is a stream of timed events (an HTTP request, a plugin call,
	// a state write). A point keeps how many happened, how many failed, the
	// summed, smallest and largest duration, and a latency histogram that
	// merges exactly, so a p95 read off a day bucket is as honest as one read
	// off a minute.
	KindEvent Kind = 2
)

func (k Kind) String() string {
	switch k {
	case KindGauge:
		return "gauge"
	case KindEvent:
		return "event"
	default:
		return fmt.Sprintf("kind(%d)", uint8(k))
	}
}

func (k Kind) valid() bool { return k == KindGauge || k == KindEvent }

// Gauge summarises samples of a level. The average is Sum/Count.
type Gauge struct {
	Count uint32
	Min   float64
	Max   float64
	Sum   float64
}

// Observe adds one sample. A NaN or infinite sample is ignored: it would
// poison every rollup above it.
func (g *Gauge) Observe(v float64) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return
	}
	if g.Count == 0 || v < g.Min {
		g.Min = v
	}
	if g.Count == 0 || v > g.Max {
		g.Max = v
	}
	g.Count++
	g.Sum += v
}

// Merge folds o into g.
func (g *Gauge) Merge(o Gauge) {
	if o.Count == 0 {
		return
	}
	if g.Count == 0 {
		*g = o
		return
	}
	g.Min = math.Min(g.Min, o.Min)
	g.Max = math.Max(g.Max, o.Max)
	g.Count += o.Count
	g.Sum += o.Sum
}

// Avg is the mean of the samples, zero when there are none.
func (g Gauge) Avg() float64 {
	if g.Count == 0 {
		return 0
	}
	return g.Sum / float64(g.Count)
}

// The event histogram: four bins per doubling from 0.1 ms, 22 doublings, so
// the top bin starts near 6 minutes, past every request and plugin budget the
// server sets. A bin is about 19 percent wide and a quantile read off it is
// placed inside its bin on the log scale and clamped to the measured extremes,
// so it lands within about 9 percent of the exact value. That is coarser than
// the monitor rollups (eight bins per doubling) on purpose: an event point is
// written for every route group and plugin method every minute, and the bins
// are most of its bytes.
const (
	eventBinsPerOctave = 4
	eventFloorSeconds  = 1e-4
	// EventBins is the number of histogram bins an Event carries.
	EventBins = 22 * eventBinsPerOctave
)

// Event summarises timed events. Durations are seconds.
type Event struct {
	Count  uint32
	Errors uint32
	Sum    float64
	Min    float64
	Max    float64
	Bins   [EventBins]uint32
}

func eventBin(seconds float64) int {
	if !(seconds > eventFloorSeconds) {
		return 0
	}
	bin := int(math.Floor(eventBinsPerOctave * math.Log2(seconds/eventFloorSeconds)))
	return min(max(bin, 0), EventBins-1)
}

func eventBinLower(bin int) float64 {
	return eventFloorSeconds * math.Exp2(float64(bin)/eventBinsPerOctave)
}

// Observe counts one event that took d and, when failed, one failure.
func (e *Event) Observe(d time.Duration, failed bool) {
	s := d.Seconds()
	if s < 0 || math.IsNaN(s) {
		s = 0
	}
	if e.Count == 0 || s < e.Min {
		e.Min = s
	}
	if e.Count == 0 || s > e.Max {
		e.Max = s
	}
	e.Count++
	if failed {
		e.Errors++
	}
	e.Sum += s
	e.Bins[eventBin(s)]++
}

// Merge folds o into e.
func (e *Event) Merge(o *Event) {
	if o == nil || o.Count == 0 {
		return
	}
	if e.Count == 0 {
		*e = *o
		return
	}
	e.Min = math.Min(e.Min, o.Min)
	e.Max = math.Max(e.Max, o.Max)
	e.Count += o.Count
	e.Errors += o.Errors
	e.Sum += o.Sum
	for i, n := range o.Bins {
		e.Bins[i] += n
	}
}

// Avg is the mean duration in seconds, zero when nothing happened.
func (e *Event) Avg() float64 {
	if e.Count == 0 {
		return 0
	}
	return e.Sum / float64(e.Count)
}

// Quantile estimates the q quantile (0 to 1) of the durations in seconds. It
// finds the bin holding the nearest-rank event, places the value inside the
// bin by its rank among the bin's events on the bin's log scale, and clamps
// it to the measured extremes. False when nothing happened.
func (e *Event) Quantile(q float64) (float64, bool) {
	if e.Count == 0 {
		return 0, false
	}
	q = math.Min(math.Max(q, 0), 1)
	rank := max(uint64(math.Ceil(q*float64(e.Count))), 1)
	if rank >= uint64(e.Count) {
		// The largest event is measured exactly; no need to estimate it.
		return e.Max, true
	}
	var seen uint64
	for bin, n := range e.Bins {
		if n == 0 {
			continue
		}
		count := uint64(n)
		if seen+count < rank {
			seen += count
			continue
		}
		frac := (float64(rank-seen) - 0.5) / float64(count)
		value := eventBinLower(bin) * math.Exp2(frac/eventBinsPerOctave)
		return math.Min(math.Max(value, e.Min), e.Max), true
	}
	return e.Max, true
}

// Point is one bucket of one series. Exactly one of Gauge and Event is
// meaningful, chosen by Kind.
type Point struct {
	Kind  Kind
	Gauge Gauge
	Event *Event
}

// Merge folds o into p. Points of different kinds never merge.
func (p *Point) Merge(o Point) {
	if p.Kind == 0 {
		p.Kind = o.Kind
	}
	if p.Kind != o.Kind {
		return
	}
	switch p.Kind {
	case KindGauge:
		p.Gauge.Merge(o.Gauge)
	case KindEvent:
		if o.Event == nil {
			return
		}
		if p.Event == nil {
			p.Event = &Event{}
		}
		p.Event.Merge(o.Event)
	}
}

func (p Point) empty() bool {
	switch p.Kind {
	case KindGauge:
		return p.Gauge.Count == 0
	case KindEvent:
		return p.Event == nil || p.Event.Count == 0
	}
	return true
}

// Row encoding. One row holds every point an owner has in one bucket:
//
//	version byte (rowVersion)
//	repeated: uvarint series id, kind byte, uvarint payload length, payload
//
// The length prefix lets a reader skip the series it was not asked for
// without decoding them, and lets a later version add fields to a payload.
//
// A gauge payload is uvarint count, float32 min, float32 max, float32 sum. An
// event payload is uvarint count, uvarint errors, float32 sum, float32 min,
// float32 max, uvarint number of non-empty bins, then for each a uvarint gap
// from the previous bin and a uvarint count. Float32 keeps seven significant
// digits, which is more than any of these readings has. Sums are added in
// float64 in memory and rounded once when stored, so a day bucket built from
// 1440 minutes carries one rounding of about one part in ten million, not
// 1440 of them; storing them as float32 is a fifth of every gauge point.
const rowVersion = 1

var errCorruptRow = errors.New("metricsdb: corrupt row")

type rowPoint struct {
	series uint32
	point  Point
}

func appendF32(b []byte, v float64) []byte {
	return binary.LittleEndian.AppendUint32(b, math.Float32bits(float32(v)))
}

func appendPayload(b []byte, p Point) []byte {
	switch p.Kind {
	case KindGauge:
		b = binary.AppendUvarint(b, uint64(p.Gauge.Count))
		b = appendF32(b, p.Gauge.Min)
		b = appendF32(b, p.Gauge.Max)
		b = appendF32(b, p.Gauge.Sum)
	case KindEvent:
		e := p.Event
		b = binary.AppendUvarint(b, uint64(e.Count))
		b = binary.AppendUvarint(b, uint64(e.Errors))
		b = appendF32(b, e.Sum)
		b = appendF32(b, e.Min)
		b = appendF32(b, e.Max)
		nonEmpty := 0
		for _, n := range e.Bins {
			if n != 0 {
				nonEmpty++
			}
		}
		b = binary.AppendUvarint(b, uint64(nonEmpty))
		prev := -1
		for bin, n := range e.Bins {
			if n == 0 {
				continue
			}
			b = binary.AppendUvarint(b, uint64(bin-prev-1))
			b = binary.AppendUvarint(b, uint64(n))
			prev = bin
		}
	}
	return b
}

// encodeRow writes points in the order given. Empty points are left out.
func encodeRow(points []rowPoint) []byte {
	b := make([]byte, 0, 1+len(points)*24)
	b = append(b, rowVersion)
	var payload []byte
	for _, rp := range points {
		if rp.point.empty() {
			continue
		}
		payload = appendPayload(payload[:0], rp.point)
		b = binary.AppendUvarint(b, uint64(rp.series))
		b = append(b, byte(rp.point.Kind))
		b = binary.AppendUvarint(b, uint64(len(payload)))
		b = append(b, payload...)
	}
	return b
}

type byteReader struct {
	b   []byte
	err error
}

func (r *byteReader) uvarint() uint64 {
	if r.err != nil {
		return 0
	}
	v, n := binary.Uvarint(r.b)
	if n <= 0 {
		r.err = errCorruptRow
		return 0
	}
	r.b = r.b[n:]
	return v
}

func (r *byteReader) u32() uint32 {
	v := r.uvarint()
	if v > math.MaxUint32 {
		r.err = errCorruptRow
		return 0
	}
	return uint32(v)
}

func (r *byteReader) f32() float64 {
	if r.err != nil || len(r.b) < 4 {
		r.err = errCorruptRow
		return 0
	}
	v := math.Float32frombits(binary.LittleEndian.Uint32(r.b))
	r.b = r.b[4:]
	return float64(v)
}

func decodePayload(kind Kind, payload []byte) (Point, error) {
	r := &byteReader{b: payload}
	p := Point{Kind: kind}
	switch kind {
	case KindGauge:
		p.Gauge.Count = r.u32()
		p.Gauge.Min = r.f32()
		p.Gauge.Max = r.f32()
		p.Gauge.Sum = r.f32()
	case KindEvent:
		e := &Event{}
		e.Count = r.u32()
		e.Errors = r.u32()
		e.Sum = r.f32()
		e.Min = r.f32()
		e.Max = r.f32()
		nonEmpty := r.uvarint()
		if nonEmpty > EventBins {
			return Point{}, errCorruptRow
		}
		bin := -1
		for i := uint64(0); i < nonEmpty && r.err == nil; i++ {
			gap := r.uvarint()
			if gap >= EventBins {
				return Point{}, errCorruptRow
			}
			bin += int(gap) + 1
			if bin >= EventBins {
				return Point{}, errCorruptRow
			}
			e.Bins[bin] = r.u32()
		}
		p.Event = e
	default:
		return Point{}, errCorruptRow
	}
	if r.err != nil {
		return Point{}, r.err
	}
	return p, nil
}

// decodeRow calls fn for each point in the row whose series want accepts; a
// nil want accepts every series. Points that are skipped are not decoded.
func decodeRow(row []byte, want func(series uint32) bool, fn func(series uint32, p Point)) error {
	if len(row) == 0 {
		return nil
	}
	if row[0] != rowVersion {
		return fmt.Errorf("metricsdb: row version %d not understood", row[0])
	}
	r := &byteReader{b: row[1:]}
	for len(r.b) > 0 {
		series := r.u32()
		if r.err != nil || len(r.b) < 1 {
			return errCorruptRow
		}
		kind := Kind(r.b[0])
		r.b = r.b[1:]
		size := r.uvarint()
		if r.err != nil || size > uint64(len(r.b)) {
			return errCorruptRow
		}
		payload := r.b[:size]
		r.b = r.b[size:]
		if want != nil && !want(series) {
			continue
		}
		if !kind.valid() {
			// A kind this version does not know: skip it rather than fail
			// the whole row.
			continue
		}
		p, err := decodePayload(kind, payload)
		if err != nil {
			return err
		}
		fn(series, p)
	}
	return nil
}
