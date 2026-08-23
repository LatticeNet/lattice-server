package store

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The audit log is append-only and unbounded. It used to be read into a slice
// on the in-memory State at every boot and appended to there for the life of
// the process, so a control plane that had recorded a million events could not
// start on the host that had been running it for weeks. These cover the move to
// bolt as the only copy, read through a cursor.

func auditEvent(id string, at time.Time, action string) model.AuditEvent {
	return model.AuditEvent{ID: id, At: at.UTC(), Action: action, Decision: "allow"}
}

func hotStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "state.json")
	boltPath := filepath.Join(dir, "state-hot.db")
	s, err := OpenWithCipher(jsonPath, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnableRuntimeBoltHotStore(boltPath); err != nil {
		t.Fatal(err)
	}
	return s, jsonPath
}

func TestHotAuditLivesInBoltAndNotInMemory(t *testing.T) {
	s, jsonPath := hotStore(t)
	base := time.Unix(1_700_000_000, 0).UTC()
	for i := 0; i < 25; i++ {
		if err := s.AppendAudit(auditEvent(fmt.Sprintf("a%02d", i), base.Add(time.Duration(i)*time.Minute), "node.update")); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.state.Audit) != 0 {
		t.Fatalf("the hot store owns the log; the in-memory copy grew to %d events", len(s.state.Audit))
	}

	seen := []string{}
	if err := s.ScanAuditEventsDesc(func(ev model.AuditEvent) bool {
		seen = append(seen, ev.ID)
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 25 {
		t.Fatalf("scan returned %d events, want all 25", len(seen))
	}
	if seen[0] != "a24" || seen[24] != "a00" {
		t.Fatalf("scan must run newest-first, got %s first and %s last", seen[0], seen[24])
	}

	// The events have to survive a restart, which is the whole reason they are
	// durable rather than resident. The bolt file is single-writer, so the
	// first store has to let go before a second one can open it.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWithCipher(jsonPath, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.EnableRuntimeBoltHotStore(filepath.Join(filepath.Dir(jsonPath), "state-hot.db")); err != nil {
		t.Fatal(err)
	}
	if len(reopened.state.Audit) != 0 {
		t.Fatalf("reopening pulled %d events back into memory", len(reopened.state.Audit))
	}
	if got := len(reopened.AuditEvents()); got != 25 {
		t.Fatalf("reopened store sees %d events, want 25", got)
	}
}

// The regression guard for the outage: opening a store whose audit log is large
// must not cost the log.
func TestOpeningAHotStoreDoesNotHoldTheAuditLog(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "state.json")
	boltPath := filepath.Join(dir, "state-hot.db")

	s, err := OpenWithCipher(jsonPath, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnableRuntimeBoltHotStore(boltPath); err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_700_000_000, 0).UTC()
	body := strings.Repeat("x", 4096)
	const events = 600
	for i := 0; i < events; i++ {
		ev := auditEvent(fmt.Sprintf("a%06d", i), base.Add(time.Duration(i)*time.Second), "netguard.reality.report")
		ev.Metadata = map[string]string{"payload": body}
		if err := s.AppendAudit(ev); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	logged := int64(events) * int64(len(body))

	runtime.GC()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	reopened, err := OpenWithCipher(jsonPath, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.EnableRuntimeBoltHotStore(boltPath); err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	runtime.GC()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(reopened)

	retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	limit := logged / 4
	if retained > limit {
		t.Fatalf("opening a store holding %d bytes of audit payload retained %d bytes of heap, over the %d byte limit", logged, retained, limit)
	}
}

func TestScanAuditEventsDescStopsWhenTheCallerIsDone(t *testing.T) {
	s, _ := hotStore(t)
	base := time.Unix(1_700_000_000, 0).UTC()
	for i := 0; i < 50; i++ {
		if err := s.AppendAudit(auditEvent(fmt.Sprintf("a%02d", i), base.Add(time.Duration(i)*time.Minute), "node.update")); err != nil {
			t.Fatal(err)
		}
	}
	visits := 0
	if err := s.ScanAuditEventsDesc(func(model.AuditEvent) bool {
		visits++
		return visits < 5
	}); err != nil {
		t.Fatal(err)
	}
	if visits != 5 {
		t.Fatalf("the walk visited %d events after being told to stop at 5", visits)
	}
}

func TestAppendAuditIdempotentDedupesAgainstBolt(t *testing.T) {
	s, _ := hotStore(t)
	at := time.Unix(1_700_000_000, 0).UTC()
	ev := auditEvent("evidence-1", at, "linechain.apply")

	committed, err := s.AppendAuditIdempotent(ev)
	if err != nil {
		t.Fatal(err)
	}
	if !committed {
		t.Fatal("the first write of a durable evidence id must commit")
	}
	committed, err = s.AppendAuditIdempotent(ev)
	if err != nil {
		t.Fatalf("replaying identical evidence must not error: %v", err)
	}
	if committed {
		t.Fatal("replaying identical evidence must not write a second copy")
	}

	count := 0
	if err := s.ScanAuditEventsDesc(func(current model.AuditEvent) bool {
		if current.ID == ev.ID {
			count++
		}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("the log holds %d copies of the evidence id, want 1", count)
	}

	conflicting := ev
	conflicting.Action = "linechain.remove"
	if _, err := s.AppendAuditIdempotent(conflicting); err == nil {
		t.Fatal("a different event reusing a durable evidence id must be refused")
	}
}

func TestAuditEventByIDReadsThroughToBolt(t *testing.T) {
	s, _ := hotStore(t)
	base := time.Unix(1_700_000_000, 0).UTC()
	for i := 0; i < 30; i++ {
		if err := s.AppendAudit(auditEvent(fmt.Sprintf("a%02d", i), base.Add(time.Duration(i)*time.Minute), "node.update")); err != nil {
			t.Fatal(err)
		}
	}
	event, ok := s.AuditEventByID("a07")
	if !ok || event.Action != "node.update" {
		t.Fatalf("lookup by id missed a durable event: ok=%v event=%+v", ok, event)
	}
	if _, ok := s.AuditEventByID("nope"); ok {
		t.Fatal("lookup by id invented an event that was never recorded")
	}
}

// Every boot-time and probe-time caller goes through ExportStateWithoutAudit.
// If it ever starts filling Audit again, the whole log is back in one slice and
// the peak that killed this control plane is back with it. This is the
// structural guard; the heap test above covers what is retained afterwards.
func TestExportStateWithoutAuditLeavesTheLogAlone(t *testing.T) {
	s, jsonPath := hotStore(t)
	base := time.Unix(1_700_000_000, 0).UTC()
	for i := 0; i < 40; i++ {
		if err := s.AppendAudit(auditEvent(fmt.Sprintf("a%02d", i), base.Add(time.Duration(i)*time.Minute), "node.update")); err != nil {
			t.Fatal(err)
		}
	}
	boltPath := filepath.Join(filepath.Dir(jsonPath), "state-hot.db")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	bs, err := OpenBoltState(boltPath, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()

	without, err := bs.ExportStateWithoutAudit()
	if err != nil {
		t.Fatal(err)
	}
	if len(without.Audit) != 0 {
		t.Fatalf("the export carried %d audit events; every boot and probe caller uses this path", len(without.Audit))
	}

	// The events are there; only this export declines to hold them.
	full, err := bs.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Audit) != 40 {
		t.Fatalf("the log itself lost events: %d of 40", len(full.Audit))
	}
	events, err := bs.AuditEvents()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 40 {
		t.Fatalf("AuditEvents returned %d of 40", len(events))
	}
}

// The log is still checked, just once, where checking it is paid for.
func TestOpeningTheHotStoreRejectsACorruptAuditRecord(t *testing.T) {
	s, jsonPath := hotStore(t)
	base := time.Unix(1_700_000_000, 0).UTC()
	if err := s.AppendAudit(auditEvent("a1", base, "node.update")); err != nil {
		t.Fatal(err)
	}
	boltPath := filepath.Join(filepath.Dir(jsonPath), "state-hot.db")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	corrupt, err := OpenBoltState(boltPath, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := corrupt.writeRawAuditRecordForTest("{ not json"); err != nil {
		t.Fatal(err)
	}
	if err := corrupt.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenBoltState(boltPath, testCipher(t)); err == nil {
		t.Fatal("opening a store whose audit log no longer decodes must fail loudly")
	}
}

// Turning the hot store on is an upgrade, and the events a JSON-only store had
// already recorded have to cross into bolt before the in-memory copy is
// dropped. Getting that order wrong loses audit history on restart, which is
// the one kind of data this store exists to never lose.
func TestEnablingTheHotStoreCarriesExistingAuditAcross(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "state.json")
	boltPath := filepath.Join(dir, "state-hot.db")

	s, err := OpenWithCipher(jsonPath, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_700_000_000, 0).UTC()
	for i := 0; i < 12; i++ {
		if err := s.AppendAudit(auditEvent(fmt.Sprintf("legacy%02d", i), base.Add(time.Duration(i)*time.Minute), "login")); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.state.Audit) != 12 {
		t.Fatalf("the fixture is wrong: a JSON-only store must hold its own audit, got %d", len(s.state.Audit))
	}

	if err := s.EnableRuntimeBoltHotStore(boltPath); err != nil {
		t.Fatal(err)
	}
	if len(s.state.Audit) != 0 {
		t.Fatalf("the in-memory copy survived the move: %d events", len(s.state.Audit))
	}

	seen := map[string]bool{}
	if err := s.ScanAuditEventsDesc(func(ev model.AuditEvent) bool {
		seen[ev.ID] = true
		return true
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		id := fmt.Sprintf("legacy%02d", i)
		if !seen[id] {
			t.Fatalf("%s did not cross into bolt; enabling the hot store lost audit history", id)
		}
	}

	// And it is durable, not just reachable from this process.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWithCipher(jsonPath, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.EnableRuntimeBoltHotStore(boltPath); err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := len(reopened.AuditEvents()); got != 12 {
		t.Fatalf("after a restart the log holds %d of 12 events", got)
	}
}
