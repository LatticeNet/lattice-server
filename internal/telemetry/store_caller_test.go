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
