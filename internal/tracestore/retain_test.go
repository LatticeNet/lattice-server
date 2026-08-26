package tracestore

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func mustRetain(t *testing.T, s *Store, now time.Time) RetainResult {
	t.Helper()
	res, err := s.Retain(now)
	if err != nil {
		t.Fatalf("Retain: %v", err)
	}
	return res
}

func TestRetainAppliesEachTTL(t *testing.T) {
	s := newStore(t, Options{})
	day := 24 * time.Hour

	// One record past the 14 day record TTL and past the 90 day rollup TTL, one
	// past only the record TTL, one inside every window.
	ancient := rec("n1", 1, t0.Add(-100*day))
	ancient.SessionIDs = []string{"sess-a"}
	old := rec("n1", 2, t0.Add(-20*day))
	fresh := rec("n1", 3, t0.Add(-time.Hour))
	mustAppend(t, s, ancient, old, fresh)

	if _, err := s.AppendLines([]model.TraceLine{
		{SessionID: "sess-a", NodeID: "n1", Seq: 1, At: t0.Add(-10 * day), Message: "old line"},
		{SessionID: "sess-a", NodeID: "n1", Seq: 2, At: t0.Add(-time.Hour), Message: "fresh line"},
	}); err != nil {
		t.Fatalf("AppendLines: %v", err)
	}

	before, err := s.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if before.Records != 3 || before.Lines != 2 || before.Rollups != 3 {
		t.Fatalf("setup produced %+v", before)
	}

	res := mustRetain(t, s, t0)
	if res.RecordsExpired != 2 {
		t.Errorf("RecordsExpired = %d, want 2", res.RecordsExpired)
	}
	if res.LinesExpired != 1 {
		t.Errorf("LinesExpired = %d, want 1", res.LinesExpired)
	}
	if res.RollupsExpired != 1 {
		t.Errorf("RollupsExpired = %d, want 1", res.RollupsExpired)
	}
	if res.RecordsEvicted != 0 || res.LinesEvicted != 0 {
		t.Errorf("size eviction ran under the default 2 GiB cap: %+v", res)
	}
	if res.Truncated {
		t.Error("Truncated = true on a three row store")
	}

	after, err := s.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if after.Records != 1 || after.Lines != 1 || after.Rollups != 2 {
		t.Errorf("after retain: %+v, want 1 record / 1 line / 2 rollups", after)
	}
	page := mustQuery(t, s, Filter{})
	if len(page.Records) != 1 || page.Records[0].LogID != 3 {
		t.Errorf("the surviving record is %+v, want the newest one", page.Records)
	}
	// Deleting a record must take its session index rows with it.
	var sessionRows int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM conn_record_sessions").Scan(&sessionRows); err != nil {
		t.Fatalf("count session index: %v", err)
	}
	if sessionRows != 0 {
		t.Errorf("session index rows = %d, want 0: the cascade left orphans", sessionRows)
	}
}

func TestRetainHonoursCustomTTLs(t *testing.T) {
	s := newStore(t, Options{
		RecordTTL: time.Hour,
		LineTTL:   30 * time.Minute,
		RollupTTL: 2 * time.Hour,
	})
	mustAppend(t, s,
		rec("n1", 1, t0.Add(-3*time.Hour)),
		rec("n1", 2, t0.Add(-90*time.Minute)),
		rec("n1", 3, t0.Add(-10*time.Minute)),
	)
	if _, err := s.AppendLines([]model.TraceLine{
		{SessionID: "sess-a", Seq: 1, At: t0.Add(-45 * time.Minute), Message: "a"},
		{SessionID: "sess-a", Seq: 2, At: t0.Add(-5 * time.Minute), Message: "b"},
	}); err != nil {
		t.Fatalf("AppendLines: %v", err)
	}

	res := mustRetain(t, s, t0)
	if res.RecordsExpired != 2 || res.LinesExpired != 1 || res.RollupsExpired != 1 {
		t.Errorf("res = %+v, want 2 records / 1 line / 1 rollup expired", res)
	}
	st, err := s.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Records != 1 || st.Lines != 1 || st.Rollups != 2 {
		t.Errorf("after retain: %+v", st)
	}
}

func TestRetainOnAnEmptyStoreIsANoop(t *testing.T) {
	s := newStore(t, Options{})
	res := mustRetain(t, s, t0)
	if res.RecordsExpired != 0 || res.LinesExpired != 0 || res.RollupsExpired != 0 ||
		res.RecordsEvicted != 0 || res.LinesEvicted != 0 || res.Truncated {
		t.Errorf("res = %+v, want all zero", res)
	}
	if res.BytesBefore <= 0 || res.BytesAfter <= 0 {
		t.Errorf("size reporting looks wrong: %+v", res)
	}
}

// TestRetainEvictsOldestFirstUnderMaxBytes drives the size ceiling with TTLs set
// far enough out that only the cap can delete anything. The cap is derived from
// the size the fixture actually reached rather than guessed, so the test does
// not depend on how many bytes a row and its index entries happen to occupy.
func TestRetainEvictsOldestFirstUnderMaxBytes(t *testing.T) {
	const total = 3000
	path := filepath.Join(t.TempDir(), "trace.db")
	year := 365 * 24 * time.Hour

	filled, err := Open(path, nil, Options{RecordTTL: year, LineTTL: year, RollupTTL: year})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	batch := make([]model.ConnRecord, 0, 500)
	for i := range total {
		r := rec("n1", uint32(i+1), t0.Add(time.Duration(i)*time.Second))
		r.UserID = "u1"
		r.DstHost = "host-" + strings.Repeat("x", 40) + ".example.com"
		r.RuleText = strings.Repeat("rule text that takes up room ", 6)
		batch = append(batch, r)
		if len(batch) == cap(batch) {
			mustAppend(t, filled, batch...)
			batch = batch[:0]
		}
	}
	if len(batch) > 0 {
		mustAppend(t, filled, batch...)
	}
	full, err := filled.sizeBytes()
	if err != nil {
		t.Fatalf("sizeBytes: %v", err)
	}
	if err := filled.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Half of what the fixture grew to: comfortably above the empty schema floor
	// and comfortably below the current size, so eviction has to remove some
	// records and cannot need to remove all of them.
	maxBytes := full / 2
	s, err := Open(path, nil, Options{MaxBytes: maxBytes, RecordTTL: year, LineTTL: year, RollupTTL: year})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()

	res := mustRetain(t, s, t0.Add(time.Hour))
	if res.RecordsExpired != 0 {
		t.Errorf("RecordsExpired = %d, want 0: the TTLs are a year out", res.RecordsExpired)
	}
	if res.RecordsEvicted == 0 {
		t.Fatal("RecordsEvicted = 0 while the store was over its size cap")
	}
	if res.BytesAfter > maxBytes {
		t.Errorf("BytesAfter = %d, still over the %d cap", res.BytesAfter, maxBytes)
	}
	if res.BytesAfter >= res.BytesBefore {
		t.Errorf("the file did not shrink: %d then %d", res.BytesBefore, res.BytesAfter)
	}
	if res.Truncated {
		t.Error("Truncated = true; the batch budget was not enough for one sweep")
	}

	after, err := s.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if after.Records != int64(total)-res.RecordsEvicted {
		t.Errorf("records = %d, evicted = %d, total was %d", after.Records, res.RecordsEvicted, total)
	}
	if after.Records == 0 {
		t.Fatal("eviction emptied the store")
	}
	// Oldest first: everything that survived is newer than everything that went,
	// so the newest record is still there and the oldest is not.
	if !after.NewestRecordAt.Equal(t0.Add(time.Duration(total-1) * time.Second)) {
		t.Errorf("newest record is %v; eviction took from the wrong end", after.NewestRecordAt)
	}
	wantOldest := t0.Add(time.Duration(res.RecordsEvicted) * time.Second)
	if !after.OldestRecordAt.Equal(wantOldest) {
		t.Errorf("oldest surviving record is %v, want %v", after.OldestRecordAt, wantOldest)
	}
}

// TestRetainFallsBackToLinesWhenRecordsRunOut covers a store whose bulk is raw
// session lines: the sweep still has to converge instead of deleting records
// that are not there.
func TestRetainFallsBackToLinesWhenRecordsRunOut(t *testing.T) {
	const total = 3000
	path := filepath.Join(t.TempDir(), "trace.db")
	year := 365 * 24 * time.Hour

	filled, err := Open(path, nil, Options{RecordTTL: year, LineTTL: year, RollupTTL: year})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	lines := make([]model.TraceLine, 0, 500)
	for i := range total {
		lines = append(lines, model.TraceLine{
			SessionID: "sess-a",
			NodeID:    "n1",
			Seq:       uint64(i + 1),
			At:        t0.Add(time.Duration(i) * time.Second),
			Level:     "info",
			Message:   strings.Repeat("inbound connection to host.example.com ", 3),
			Raw:       strings.Repeat("raw sing-box payload ", 4),
		})
		if len(lines) == cap(lines) {
			if _, err := filled.AppendLines(lines); err != nil {
				t.Fatalf("AppendLines: %v", err)
			}
			lines = lines[:0]
		}
	}
	full, err := filled.sizeBytes()
	if err != nil {
		t.Fatalf("sizeBytes: %v", err)
	}
	if err := filled.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	maxBytes := full / 2
	s, err := Open(path, nil, Options{MaxBytes: maxBytes, RecordTTL: year, LineTTL: year, RollupTTL: year})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()

	res := mustRetain(t, s, t0.Add(time.Hour))
	if res.RecordsEvicted != 0 {
		t.Errorf("RecordsEvicted = %d, want 0: there are no records to evict", res.RecordsEvicted)
	}
	if res.LinesEvicted == 0 {
		t.Fatal("LinesEvicted = 0 while the store was over its cap with nothing but lines in it")
	}
	if res.BytesAfter > maxBytes {
		t.Errorf("BytesAfter = %d, still over the %d cap", res.BytesAfter, maxBytes)
	}
	after, err := s.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if after.Lines == 0 {
		t.Fatal("eviction removed every line")
	}
	// Oldest first here too: the tail an operator is watching survives.
	got, err := s.QueryLines("sess-a", 0, 1)
	if err != nil {
		t.Fatalf("QueryLines: %v", err)
	}
	if len(got) != 1 || got[0].Seq != uint64(res.LinesEvicted+1) {
		t.Errorf("oldest surviving line has seq %v, want %d", got, res.LinesEvicted+1)
	}
}

func TestRetainReportsTruncationInsteadOfRunningForever(t *testing.T) {
	// A cap the store can never reach, since the empty schema is already larger
	// than one page. The sweep must stop and say so rather than spin.
	s := newStore(t, Options{MaxBytes: 1})
	mustAppend(t, s, rec("n1", 1, t0), rec("n1", 2, t0.Add(time.Second)))
	res := mustRetain(t, s, t0.Add(time.Hour))
	if res.BytesAfter > res.BytesBefore {
		t.Errorf("the store grew during retention: %d then %d", res.BytesBefore, res.BytesAfter)
	}
	st, err := s.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Records != 0 {
		t.Errorf("records = %d, want 0: an unreachable cap still evicts everything it can", st.Records)
	}
}
