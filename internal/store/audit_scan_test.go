package store

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The audit log is append-only and, in the JSON-backed store, resident in
// memory. ScanAuditEventsDesc used to copy the whole slice on every call so the
// visitor could run outside the store lock; at a million events that is about
// 170 MB of allocation per page view. It now walks a slice header captured
// under the lock instead. These pin the two properties that trade rests on: the
// walk is safe against concurrent appends, and its cost tracks the page, not
// the log.

func syntheticAuditLog(n int) []model.AuditEvent {
	base := time.Unix(1_700_000_000, 0).UTC()
	out := make([]model.AuditEvent, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, model.AuditEvent{
			ID:       fmt.Sprintf("audit-%012d", i),
			At:       base.Add(time.Duration(i) * time.Second),
			ActorID:  "user_admin",
			NodeID:   "node-" + strconv.Itoa(i%50),
			Action:   "task.create",
			Scope:    "tasks:write",
			Decision: "allow",
			Reason:   "operator request",
			Metadata: map[string]string{"source_ip": "203.0.113.7"},
		})
	}
	return out
}

func TestScanAuditEventsDescIsStableUnderConcurrentAppends(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	// Events carry their append sequence in the id so a page can be checked
	// for the only ordering the walk promises: newest first, contiguous.
	seq := 0
	appendOne := func() {
		ev := model.AuditEvent{
			ID:       fmt.Sprintf("%012d", seq),
			At:       time.Unix(1_700_000_000+int64(seq), 0).UTC(),
			Action:   "agent.auth",
			Decision: "deny",
		}
		seq++
		if err := s.AppendAudit(ev); err != nil {
			panic(err)
		}
	}
	for i := 0; i < 1_000; i++ {
		appendOne()
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				appendOne()
			}
		}
	}()

	for round := 0; round < 500; round++ {
		const page = 50
		ids := make([]int, 0, page)
		err := s.ScanAuditEventsDesc(func(ev model.AuditEvent) bool {
			n, err := strconv.Atoi(ev.ID)
			if err != nil {
				t.Errorf("unexpected id %q", ev.ID)
				return false
			}
			ids = append(ids, n)
			return len(ids) < page
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(ids) != page {
			t.Fatalf("round %d: walked %d events, want a page of %d", round, len(ids), page)
		}
		for i := 1; i < len(ids); i++ {
			if ids[i] != ids[i-1]-1 {
				t.Fatalf("round %d: page is not a contiguous newest-first slice of the log: %v", round, ids)
			}
		}
	}
	close(stop)
	<-done
}

// BenchmarkScanAuditEventsDescNewestPage reads the newest 100 events, which
// is what a bare GET /api/audit does. The ns/op and B/op columns must stay flat
// across log sizes; a copy-then-walk implementation grows linearly.
func BenchmarkScanAuditEventsDescNewestPage(b *testing.B) {
	for _, size := range []int{1_000, 10_000, 100_000, 1_000_000} {
		b.Run(fmt.Sprintf("events=%d", size), func(b *testing.B) {
			s, err := Open("")
			if err != nil {
				b.Fatal(err)
			}
			s.mu.Lock()
			s.state.Audit = syntheticAuditLog(size)
			s.mu.Unlock()
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				seen := 0
				if err := s.ScanAuditEventsDesc(func(model.AuditEvent) bool {
					seen++
					return seen < 100
				}); err != nil {
					b.Fatal(err)
				}
				if seen != 100 {
					b.Fatalf("walked %d events, want 100", seen)
				}
			}
		})
	}
}
