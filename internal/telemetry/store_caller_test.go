package telemetry

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestStoreSavesAreExposedByCaller(t *testing.T) {
	r := NewRegistry()
	r.ObserveStoreSave("UpdateMetrics", 2*time.Millisecond, nil)
	r.ObserveStoreSave("UpdateMetrics", 4*time.Millisecond, nil)
	r.ObserveStoreSave("UpsertApproval", time.Millisecond, errors.New("disk full"))
	r.ObserveStoreSave("", time.Millisecond, nil)

	snap := r.Snapshot()
	if got := snap.StoreCallers["UpdateMetrics"].Count; got != 2 {
		t.Fatalf("UpdateMetrics count = %d, want 2", got)
	}
	if got := snap.StoreCallers[StoreCallerOther].Count; got != 1 {
		t.Fatalf("an unnamed caller counts as %s: %d, want 1", StoreCallerOther, got)
	}
	if got := snap.Store["success"].Count + snap.Store["error"].Count; got != 4 {
		t.Fatalf("the by-result family must still count every save: %d", got)
	}
	text := r.Prometheus()
	for _, want := range []string{
		`lattice_store_save_by_caller_total{caller="UpdateMetrics"} 2`,
		`lattice_store_save_by_caller_total{caller="UpsertApproval"} 1`,
		`lattice_store_save_by_caller_duration_seconds_sum{caller="UpdateMetrics"} 0.006000000`,
		`lattice_store_save_total{result="success"} 3`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("metrics text has no %q:\n%s", want, text)
		}
	}
	r.Reset()
	if got := len(r.Snapshot().StoreCallers); got != 0 {
		t.Fatalf("callers survived reset: %d", got)
	}
}

// The caller label is bounded however many names arrive: past
// maxStoreCallers distinct names, new ones count as other.
func TestStoreCallerLabelIsBounded(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < maxStoreCallers+50; i++ {
		r.ObserveStoreSave(fmt.Sprintf("Caller%d", i), time.Millisecond, nil)
	}
	snap := r.Snapshot()
	if got := len(snap.StoreCallers); got > maxStoreCallers+1 {
		t.Fatalf("%d distinct caller labels, want at most %d", got, maxStoreCallers+1)
	}
	if got := snap.StoreCallers[StoreCallerOther].Count; got != 50 {
		t.Fatalf("names past the bound counted as %s: %d, want 50", StoreCallerOther, got)
	}
	r.ObserveStoreSave("Caller3", time.Millisecond, nil)
	if got := r.Snapshot().StoreCallers["Caller3"].Count; got != 2 {
		t.Fatalf("a name seen before the bound keeps its own label: %d", got)
	}
}

// The periodic summary names the busiest callers first and starts a new
// window each time it is taken; the cumulative /metrics counters keep
// counting.
func TestStoreSaveSummaryFormatsAndResets(t *testing.T) {
	r := NewRegistry()
	if line, ok := r.TakeStoreSaveSummary(time.Hour); ok {
		t.Fatalf("a window with no writes logged %q", line)
	}
	for caller, n := range map[string]int{"UpdateMetrics": 12, "UpsertDDNSProfile": 12, "RecordDDNSRun": 3, "": 1} {
		for i := 0; i < n; i++ {
			r.ObserveStoreSave(caller, time.Millisecond, nil)
		}
	}
	line, ok := r.TakeStoreSaveSummary(time.Hour)
	want := "state.json writes in the last 60m: 28 (UpdateMetrics 12, UpsertDDNSProfile 12, RecordDDNSRun 3, other 1)"
	if !ok || line != want {
		t.Fatalf("summary = %q, %v\nwant      %q", line, ok, want)
	}
	if line, ok := r.TakeStoreSaveSummary(time.Hour); ok {
		t.Fatalf("taking the summary did not start a new window: %q", line)
	}
	if got := r.Snapshot().StoreCallers["UpdateMetrics"].Count; got != 12 {
		t.Fatalf("the summary reset the cumulative counter: %d, want 12", got)
	}

	r.ObserveStoreSave("UpdateMetrics", time.Millisecond, nil)
	line, ok = r.TakeStoreSaveSummary(59*time.Minute + 40*time.Second)
	if want := "state.json writes in the last 60m: 1 (UpdateMetrics 1)"; !ok || line != want {
		t.Fatalf("summary = %q, %v, want %q", line, ok, want)
	}

	r.ObserveStoreSave("UpdateMetrics", time.Millisecond, nil)
	r.Reset()
	if line, ok := r.TakeStoreSaveSummary(time.Hour); ok {
		t.Fatalf("the window survived Reset: %q", line)
	}
}

// The summary names at most storeSaveSummaryTop callers and folds the rest
// into one count, unless only one caller would be folded.
func TestStoreSaveSummaryIsBounded(t *testing.T) {
	r := NewRegistry()
	// Caller00 writes once, Caller01 twice, up to Caller09 ten times.
	for i := 0; i < storeSaveSummaryTop+4; i++ {
		for j := 0; j <= i; j++ {
			r.ObserveStoreSave(fmt.Sprintf("Caller%02d", i), time.Millisecond, nil)
		}
	}
	line, _ := r.TakeStoreSaveSummary(time.Hour)
	want := "state.json writes in the last 60m: 55 (Caller09 10, Caller08 9, Caller07 8, Caller06 7, Caller05 6, Caller04 5, 4 more callers 10)"
	if line != want {
		t.Fatalf("summary = %q\nwant      %q", line, want)
	}

	for i := 0; i < storeSaveSummaryTop+1; i++ {
		r.ObserveStoreSave(fmt.Sprintf("Caller%02d", i), time.Millisecond, nil)
	}
	line, _ = r.TakeStoreSaveSummary(time.Hour)
	want = "state.json writes in the last 60m: 7 (Caller00 1, Caller01 1, Caller02 1, Caller03 1, Caller04 1, Caller05 1, Caller06 1)"
	if line != want {
		t.Fatalf("one caller past the bound is named, not folded: %q\nwant %q", line, want)
	}
}
