package tracestore

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
)

// t0 is the fixed clock every test works from. Nothing here sleeps or reads the
// wall clock, so retention boundaries are exact rather than nearly exact.
var t0 = time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)

func newStore(t *testing.T, opts Options) *Store {
	t.Helper()
	return newStoreWithCipher(t, nil, opts)
}

func newStoreWithCipher(t *testing.T, cipher secret.Cipher, opts Options) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trace.db")
	s, err := Open(path, cipher, opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func testCipher(t *testing.T) secret.Cipher {
	t.Helper()
	key := make([]byte, secret.KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("gen key: %v", err)
	}
	c, err := secret.NewAESGCM(key)
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}
	return c
}

// rec is a minimal valid final record. Tests override the fields they care
// about so the interesting difference is the only thing on screen.
func rec(nodeID string, logID uint32, at time.Time) model.ConnRecord {
	return model.ConnRecord{
		NodeID:         nodeID,
		CoreGeneration: 1,
		LogID:          logID,
		StartedAt:      at,
		EndedAt:        at.Add(time.Second),
		CloseReason:    model.CloseEOF,
	}
}

// normalize puts a record through the same time encoding the store uses, so a
// round-trip comparison tests storage rather than time.Time representation.
func normalize(r model.ConnRecord) model.ConnRecord {
	round := func(t time.Time) time.Time {
		if t.IsZero() {
			return time.Time{}
		}
		return time.Unix(0, t.UTC().UnixNano()).UTC()
	}
	r.StartedAt = round(r.StartedAt)
	r.EndedAt = round(r.EndedAt)
	r.StalledAt = round(r.StalledAt)
	if len(r.SessionIDs) == 0 {
		r.SessionIDs = nil
	}
	return r
}

func mustAppend(t *testing.T, s *Store, rs ...model.ConnRecord) int {
	t.Helper()
	n, err := s.AppendRecords(rs)
	if err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}
	return n
}

func mustQuery(t *testing.T, s *Store, f Filter) RecordPage {
	t.Helper()
	page, err := s.QueryRecords(f)
	if err != nil {
		t.Fatalf("QueryRecords: %v", err)
	}
	return page
}

func TestOpenIsIdempotentAndSetsPragmas(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.db")
	s, err := Open(path, nil, Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !s.autoVacuum {
		t.Fatal("auto_vacuum is not INCREMENTAL; the MaxBytes sweep could never shrink the file")
	}
	for _, p := range []struct {
		pragma string
		want   string
	}{
		{"journal_mode", "wal"},
		{"synchronous", "1"}, // 1 == NORMAL
		{"foreign_keys", "1"},
		{"busy_timeout", "5000"},
	} {
		var got string
		if err := s.db.QueryRow("PRAGMA " + p.pragma).Scan(&got); err != nil {
			t.Fatalf("PRAGMA %s: %v", p.pragma, err)
		}
		if got != p.want {
			t.Errorf("PRAGMA %s = %q, want %q", p.pragma, got, p.want)
		}
	}
	mustAppend(t, s, rec("n1", 1, t0))
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopening runs migrate again and must neither fail nor lose data.
	s2, err := Open(path, nil, Options{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	st, err := s2.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Records != 1 {
		t.Errorf("records after reopen = %d, want 1", st.Records)
	}
	if st.SchemaVersion != currentSchemaVersion {
		t.Errorf("schema version = %d, want %d", st.SchemaVersion, currentSchemaVersion)
	}
	var applied int
	if err := s2.db.QueryRow("SELECT COUNT(*) FROM schema_version").Scan(&applied); err != nil {
		t.Fatalf("count schema_version: %v", err)
	}
	if applied != currentSchemaVersion {
		t.Errorf("schema_version rows = %d, want %d (migrate re-applied a version)", applied, currentSchemaVersion)
	}
}

func TestOpenCreatesTheFileAtRestrictedPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.db")
	s, err := Open(path, nil, Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	// The store holds destination hostnames in the clear by design, so the file
	// mode is part of the protection. It matches logs.db at 0600.
	mustAppend(t, s, rec("n1", 1, t0))
	for _, suffix := range []string{"", "-wal"} {
		info, err := os.Stat(path + suffix)
		if err != nil {
			if suffix != "" && os.IsNotExist(err) {
				continue
			}
			t.Fatalf("stat %s%s: %v", path, suffix, err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s%s mode = %04o, want 0600", path, suffix, mode)
		}
	}
}

func TestRecordRoundTripEveryField(t *testing.T) {
	s := newStore(t, Options{})
	want := model.ConnRecord{
		NodeID:          "node-a",
		LineUUID:        "line-uuid-1",
		LineHashID:      "line-hash-1",
		InboundTag:      "in-vless",
		InboundType:     "vless",
		UserName:        "u_00112233445566ff",
		UserID:          "user-1",
		UserKind:        model.UserKindManaged,
		LogID:           4294967295, // max uint32: the id really is rand.Uint32
		Network:         "tcp",
		SrcIP:           "203.0.113.7",
		SrcPort:         51234,
		DstHost:         "api.example.com",
		DstIP:           "198.51.100.9",
		DstPort:         443,
		SniffedProtocol: "tls",
		SniffedDomain:   "api.example.com",
		RuleIndex:       7,
		RuleText:        "domain_suffix=example.com => proxy",
		OutboundTag:     "out-chain",
		OutboundType:    "vless",
		ChainEdgeUUID:   "edge-1",
		StartedAt:       t0,
		EndedAt:         t0.Add(90 * time.Second),
		DurationMS:      90123,
		Open:            false,
		Upload:          1 << 40,
		Download:        1 << 41,
		BytesKnown:      true,
		CloseReason:     model.CloseReset,
		CloseError:      "connection reset by peer",
		StalledAt:       t0.Add(30 * time.Second),
		CoreGeneration:  42,
		SessionIDs:      []string{"sess-a", "sess-b"},
		HopPathID:       "hop-1",
	}
	mustAppend(t, s, want)

	page := mustQuery(t, s, Filter{})
	if len(page.Records) != 1 {
		t.Fatalf("got %d records, want 1", len(page.Records))
	}
	if got := page.Records[0]; !reflect.DeepEqual(got, normalize(want)) {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got, normalize(want))
	}
}

func TestRecordRoundTripZeroTimesAndByteHonesty(t *testing.T) {
	s := newStore(t, Options{})
	// An open connection: no end, no stall, and bytes that were never measured.
	// The zero times must come back zero, not as an instant at the Unix epoch.
	unmeasured := model.ConnRecord{
		NodeID:    "node-a",
		LogID:     1,
		StartedAt: t0,
		Open:      true,
	}
	// Bytes measured and genuinely zero: a connection that opened and moved
	// nothing. This must be distinguishable from the record above.
	measuredZero := model.ConnRecord{
		NodeID:      "node-a",
		LogID:       2,
		StartedAt:   t0,
		BytesKnown:  true,
		CloseReason: model.CloseEOF,
	}
	mustAppend(t, s, unmeasured, measuredZero)

	page := mustQuery(t, s, Filter{IncludeOpen: true})
	if len(page.Records) != 2 {
		t.Fatalf("got %d records, want 2", len(page.Records))
	}
	byID := map[uint32]model.ConnRecord{}
	for _, r := range page.Records {
		byID[r.LogID] = r
	}
	got := byID[1]
	if !got.EndedAt.IsZero() {
		t.Errorf("EndedAt = %v, want zero", got.EndedAt)
	}
	if !got.StalledAt.IsZero() {
		t.Errorf("StalledAt = %v, want zero", got.StalledAt)
	}
	if got.BytesKnown {
		t.Error("BytesKnown = true, want false: nothing measured this connection")
	}
	if !got.Open {
		t.Error("Open = false, want true")
	}
	if got := byID[2]; !got.BytesKnown {
		t.Error("BytesKnown = false, want true: zero bytes were actually measured")
	}
}

func TestAppendRecordsRejectsInvalidBatchWhole(t *testing.T) {
	s := newStore(t, Options{})
	good := rec("n1", 1, t0)
	cases := []struct {
		name string
		bad  model.ConnRecord
	}{
		{"no node id", model.ConnRecord{LogID: 2, StartedAt: t0}},
		{"no started at", model.ConnRecord{NodeID: "n1", LogID: 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.AppendRecords([]model.ConnRecord{good, tc.bad}); err == nil {
				t.Fatal("AppendRecords accepted an invalid record")
			}
			st, err := s.Stats()
			if err != nil {
				t.Fatalf("Stats: %v", err)
			}
			if st.Records != 0 {
				t.Errorf("records = %d, want 0: a rejected batch must write nothing", st.Records)
			}
		})
	}
}

func TestOpenSnapshotsCollapseToOneFinalRow(t *testing.T) {
	s := newStore(t, Options{})
	for i, up := range []int64{100, 200, 300} {
		snap := rec("node-a", 7, t0)
		snap.Open = true
		snap.CloseReason = ""
		snap.EndedAt = time.Time{}
		snap.BytesKnown = true
		snap.Upload = up
		snap.Download = int64(i)
		mustAppend(t, s, snap)
	}
	st, err := s.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Records != 1 || st.OpenRecords != 1 {
		t.Fatalf("after three snapshots: records=%d open=%d, want 1 and 1", st.Records, st.OpenRecords)
	}

	final := rec("node-a", 7, t0)
	final.BytesKnown = true
	final.Upload = 400
	final.Download = 40
	final.DurationMS = 1234
	mustAppend(t, s, final)

	st, err = s.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Records != 1 {
		t.Fatalf("records = %d, want exactly 1 row for one connection", st.Records)
	}
	if st.OpenRecords != 0 {
		t.Fatalf("open records = %d, want 0", st.OpenRecords)
	}
	page := mustQuery(t, s, Filter{})
	if len(page.Records) != 1 {
		t.Fatalf("got %d records, want 1", len(page.Records))
	}
	got := page.Records[0]
	if got.Open {
		t.Error("Open = true, want false")
	}
	if got.Upload != 400 || got.DurationMS != 1234 {
		t.Errorf("final record did not replace the snapshot: upload=%d duration=%d", got.Upload, got.DurationMS)
	}

	rollups, err := s.Rollups(RollupFilter{})
	if err != nil {
		t.Fatalf("Rollups: %v", err)
	}
	if len(rollups) != 1 || rollups[0].Connections != 1 {
		t.Fatalf("rollups = %+v, want exactly one bucket with one connection", rollups)
	}
}

func TestLateOpenSnapshotCannotResurrectAFinalRecord(t *testing.T) {
	s := newStore(t, Options{})
	final := rec("node-a", 7, t0)
	final.Upload = 400
	mustAppend(t, s, final)

	stale := rec("node-a", 7, t0)
	stale.Open = true
	stale.CloseReason = ""
	stale.Upload = 1
	applied := mustAppend(t, s, stale)
	if applied != 0 {
		t.Errorf("applied = %d, want 0: a stale snapshot must not be applied", applied)
	}

	page := mustQuery(t, s, Filter{IncludeOpen: true})
	if len(page.Records) != 1 {
		t.Fatalf("got %d records, want 1", len(page.Records))
	}
	if page.Records[0].Open || page.Records[0].Upload != 400 {
		t.Errorf("final record was overwritten by a late snapshot: %+v", page.Records[0])
	}
	rollups, err := s.Rollups(RollupFilter{})
	if err != nil {
		t.Fatalf("Rollups: %v", err)
	}
	if len(rollups) != 1 || rollups[0].Connections != 1 {
		t.Fatalf("rollups = %+v, want one connection", rollups)
	}
}

func TestAppendRecordsIsIdempotent(t *testing.T) {
	s := newStore(t, Options{})
	r := rec("node-a", 9, t0)
	r.BytesKnown = true
	r.Upload = 10
	r.Download = 20
	r.SessionIDs = []string{"sess-a"}

	mustAppend(t, s, r)
	mustAppend(t, s, r)
	mustAppend(t, s, r, r)

	st, err := s.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Records != 1 {
		t.Errorf("records = %d, want 1", st.Records)
	}
	var sessionRows int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM conn_record_sessions").Scan(&sessionRows); err != nil {
		t.Fatalf("count session index: %v", err)
	}
	if sessionRows != 1 {
		t.Errorf("session index rows = %d, want 1", sessionRows)
	}
	rollups, err := s.Rollups(RollupFilter{})
	if err != nil {
		t.Fatalf("Rollups: %v", err)
	}
	if len(rollups) != 1 {
		t.Fatalf("rollups = %+v, want one bucket", rollups)
	}
	if rollups[0].Connections != 1 || rollups[0].Upload != 10 || rollups[0].Download != 20 {
		t.Errorf("re-delivering a record double counted the rollup: %+v", rollups[0])
	}
}

func TestLinesRoundTripAndTail(t *testing.T) {
	s := newStore(t, Options{})
	lines := []model.TraceLine{}
	for i := 1; i <= 5; i++ {
		lines = append(lines, model.TraceLine{
			SessionID: "sess-a",
			NodeID:    "node-a",
			Seq:       uint64(i),
			At:        t0.Add(time.Duration(i) * time.Second),
			Level:     "info",
			LogID:     uint32(1000 + i),
			Tag:       "inbound/vless[in]",
			Message:   fmt.Sprintf("inbound connection to host-%d:443", i),
			Raw:       fmt.Sprintf("raw payload %d", i),
		})
	}
	lines = append(lines, model.TraceLine{SessionID: "sess-b", NodeID: "node-a", Seq: 1, At: t0, Message: "other session"})
	n, err := s.AppendLines(lines)
	if err != nil {
		t.Fatalf("AppendLines: %v", err)
	}
	if n != len(lines) {
		t.Errorf("AppendLines = %d, want %d", n, len(lines))
	}

	got, err := s.QueryLines("sess-a", 0, 100)
	if err != nil {
		t.Fatalf("QueryLines: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("got %d lines, want 5 (session scoping leaked)", len(got))
	}
	for i, l := range got {
		want := lines[i]
		if l.Seq != want.Seq || l.Message != want.Message || l.Raw != want.Raw || l.LogID != want.LogID || l.Tag != want.Tag || l.Level != want.Level {
			t.Fatalf("line %d mismatch:\n got %+v\nwant %+v", i, l, want)
		}
		if !l.At.Equal(want.At) {
			t.Errorf("line %d At = %v, want %v", i, l.At, want.At)
		}
	}

	tail, err := s.QueryLines("sess-a", 3, 100)
	if err != nil {
		t.Fatalf("QueryLines tail: %v", err)
	}
	if len(tail) != 2 || tail[0].Seq != 4 {
		t.Fatalf("tail after seq 3 = %d lines starting at %d, want 2 starting at 4", len(tail), tail[0].Seq)
	}

	// Re-delivering the same sequence replaces it rather than duplicating.
	if _, err := s.AppendLines(lines[:3]); err != nil {
		t.Fatalf("AppendLines replay: %v", err)
	}
	got, err = s.QueryLines("sess-a", 0, 100)
	if err != nil {
		t.Fatalf("QueryLines: %v", err)
	}
	if len(got) != 5 {
		t.Errorf("after replay got %d lines, want 5", len(got))
	}
}

func TestCipherSealsFreeTextButNotTheIndexColumn(t *testing.T) {
	const (
		secretError = "dial tcp 198.51.100.9:443: i/o timeout to payroll-internal"
		secretRaw   = "raw evidence line with a bearer-ish blob"
		dstHost     = "payroll.internal.example"
	)
	path := filepath.Join(t.TempDir(), "trace.db")
	s, err := Open(path, testCipher(t), Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	r := rec("node-a", 1, t0)
	r.CloseReason = model.CloseTimeout
	r.CloseError = secretError
	r.DstHost = dstHost
	if _, err := s.AppendRecords([]model.ConnRecord{r}); err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}
	if _, err := s.AppendLines([]model.TraceLine{{
		SessionID: "sess-a", NodeID: "node-a", Seq: 1, At: t0,
		Message: secretError, Raw: secretRaw,
	}}); err != nil {
		t.Fatalf("AppendLines: %v", err)
	}

	// Read back through the store first: sealing must be transparent.
	page, err := s.QueryRecords(Filter{})
	if err != nil {
		t.Fatalf("QueryRecords: %v", err)
	}
	if len(page.Records) != 1 || page.Records[0].CloseError != secretError {
		t.Fatalf("sealed close_error did not round trip: %+v", page.Records)
	}
	lines, err := s.QueryLines("sess-a", 0, 10)
	if err != nil {
		t.Fatalf("QueryLines: %v", err)
	}
	if len(lines) != 1 || lines[0].Raw != secretRaw || lines[0].Message != secretError {
		t.Fatalf("sealed line did not round trip: %+v", lines)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	onDisk := readAllDBFiles(t, path)
	for _, plaintext := range []string{secretError, secretRaw} {
		if bytesContains(onDisk, plaintext) {
			t.Errorf("plaintext %q is readable in the raw database file", plaintext)
		}
	}
	// dst_host is deliberately NOT sealed: it is an index column, and an index
	// cannot be built over ciphertext. This assertion documents the known
	// tradeoff from design 4.8 so nobody believes the file is fully opaque. The
	// planned hardening is HMAC tokenisation, which keeps equality filtering.
	if !bytesContains(onDisk, dstHost) {
		t.Errorf("dst_host %q is not plaintext on disk; the documented tradeoff changed and the comment in schema.go needs updating", dstHost)
	}
}

func TestDisabledCipherStoresPlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.db")
	s, err := Open(path, secret.Disabled(), Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	r := rec("node-a", 1, t0)
	r.CloseError = "plain close error"
	if _, err := s.AppendRecords([]model.ConnRecord{r}); err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}
	page, err := s.QueryRecords(Filter{})
	if err != nil {
		t.Fatalf("QueryRecords: %v", err)
	}
	if len(page.Records) != 1 || page.Records[0].CloseError != "plain close error" {
		t.Fatalf("plaintext round trip failed: %+v", page.Records)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !bytesContains(readAllDBFiles(t, path), "plain close error") {
		t.Error("a disabled cipher should store plaintext, as logstore does")
	}
}

// readAllDBFiles reads the database and any sidecar (-wal, -shm) so the
// plaintext assertion cannot be fooled by data still sitting in the WAL.
func readAllDBFiles(t *testing.T, path string) []byte {
	t.Helper()
	var out []byte
	for _, suffix := range []string{"", "-wal", "-shm"} {
		b, err := os.ReadFile(path + suffix)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read %s%s: %v", path, suffix, err)
		}
		out = append(out, b...)
	}
	return out
}

func bytesContains(haystack []byte, needle string) bool {
	return len(needle) > 0 && indexOf(haystack, []byte(needle)) >= 0
}

func indexOf(haystack, needle []byte) int {
outer:
	for i := 0; i+len(needle) <= len(haystack); i++ {
		for j := range needle {
			if haystack[i+j] != needle[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}

func TestStatsReportsTheStore(t *testing.T) {
	s := newStore(t, Options{MaxBytes: 1 << 20})
	open := rec("node-a", 1, t0.Add(time.Hour))
	open.Open = true
	open.CloseReason = ""
	mustAppend(t, s, rec("node-a", 2, t0), open)
	if _, err := s.AppendLines([]model.TraceLine{{SessionID: "sess-a", Seq: 1, At: t0, Message: "x"}}); err != nil {
		t.Fatalf("AppendLines: %v", err)
	}
	st, err := s.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Records != 2 || st.OpenRecords != 1 || st.Lines != 1 || st.Rollups != 1 {
		t.Errorf("stats = %+v, want 2 records / 1 open / 1 line / 1 rollup", st)
	}
	if !st.OldestRecordAt.Equal(t0) || !st.NewestRecordAt.Equal(t0.Add(time.Hour)) {
		t.Errorf("stats time span = %v..%v, want %v..%v", st.OldestRecordAt, st.NewestRecordAt, t0, t0.Add(time.Hour))
	}
	if st.SizeBytes <= 0 || st.MaxBytes != 1<<20 {
		t.Errorf("stats size = %d, cap = %d", st.SizeBytes, st.MaxBytes)
	}
	if st.CipherEnabled {
		t.Error("CipherEnabled = true with no cipher")
	}
	if st.Path != s.Path() {
		t.Errorf("stats path = %q, want %q", st.Path, s.Path())
	}
}

// TestConcurrentAppendAndQuery is the -race case: writers and readers hitting
// the same store at once, which is exactly the ingest-while-an-operator-looks
// shape this store lives in.
func TestConcurrentAppendAndQuery(t *testing.T) {
	s := newStore(t, Options{})
	const (
		writers = 4
		perW    = 25
		readers = 4
	)
	var writeWG, readWG sync.WaitGroup
	stop := make(chan struct{})
	errs := make(chan error, writers+readers)

	for w := range writers {
		writeWG.Add(1)
		go func(w int) {
			defer writeWG.Done()
			for i := range perW {
				r := rec(fmt.Sprintf("node-%d", w), uint32(i+1), t0.Add(time.Duration(i)*time.Second))
				r.UserID = fmt.Sprintf("user-%d", w)
				r.BytesKnown = true
				r.Upload = int64(i)
				if _, err := s.AppendRecords([]model.ConnRecord{r}); err != nil {
					errs <- fmt.Errorf("append: %w", err)
					return
				}
			}
		}(w)
	}
	for range readers {
		readWG.Add(1)
		go func() {
			defer readWG.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := s.QueryRecords(Filter{Limit: 10}); err != nil {
					errs <- fmt.Errorf("query: %w", err)
					return
				}
				if _, err := s.Rollups(RollupFilter{}); err != nil {
					errs <- fmt.Errorf("rollups: %w", err)
					return
				}
				if _, err := s.Stats(); err != nil {
					errs <- fmt.Errorf("stats: %w", err)
					return
				}
			}
		}()
	}
	writeWG.Wait()
	close(stop)
	readWG.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent access failed: %v", err)
	}
	st, err := s.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Records != writers*perW {
		t.Errorf("records = %d, want %d", st.Records, writers*perW)
	}
}

// Line sequence is assigned by the store, not by the agent.
//
// This is the cursor the live tail pages on, and the primary key includes it.
// If it stayed zero every line would collapse onto one row and a tail starting
// at zero could never return any of them, which is exactly what happened before
// it was assigned here.
func TestAppendLinesAssignsMonotonicSeq(t *testing.T) {
	s := newStore(t, Options{})

	batch := func(n int, node string) []model.TraceLine {
		out := make([]model.TraceLine, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, model.TraceLine{
				SessionID: "sess-1",
				NodeID:    node,
				At:        time.Date(2026, 8, 26, 12, 0, i, 0, time.UTC),
				Level:     "trace",
				Message:   fmt.Sprintf("%s line %d", node, i),
			})
		}
		return out
	}

	if _, err := s.AppendLines(batch(3, "node-a")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendLines(batch(2, "node-b")); err != nil {
		t.Fatal(err)
	}

	got, err := s.QueryLines("sess-1", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("stored %d lines, want 5; a zero sequence collapses them onto one primary key", len(got))
	}
	for i, l := range got {
		if l.Seq != uint64(i+1) {
			t.Fatalf("line %d has seq %d, want %d", i, l.Seq, i+1)
		}
	}

	// The tail must advance: asking for everything after the third line returns
	// exactly the last two.
	tail, err := s.QueryLines("sess-1", 3, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(tail) != 2 {
		t.Fatalf("tail after seq 3 returned %d lines, want 2", len(tail))
	}
	if tail[0].Seq != 4 {
		t.Fatalf("tail starts at seq %d, want 4", tail[0].Seq)
	}
}

// A record older than one page must still be findable by key.
//
// The hops view looks a connection up by identity. Scanning the newest page
// instead would report "not found" for a record the database is holding, which
// is the wrong answer for a lookup that has an exact key available.
func TestRecordByKeyFindsARecordBeyondOnePage(t *testing.T) {
	s := newStore(t, Options{})
	base := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)

	// One target, then far more recent records than a single page returns.
	target := model.ConnRecord{
		NodeID: "node-a", CoreGeneration: 7, LogID: 4242,
		StartedAt: base, EndedAt: base.Add(time.Second),
		DstHost: "target.example", CloseReason: model.CloseEOF,
	}
	if _, err := s.AppendRecords([]model.ConnRecord{target}); err != nil {
		t.Fatal(err)
	}
	filler := make([]model.ConnRecord, 0, MaxQueryLimit+50)
	for i := 0; i < MaxQueryLimit+50; i++ {
		filler = append(filler, model.ConnRecord{
			NodeID: "node-a", CoreGeneration: 7, LogID: uint32(100000 + i),
			StartedAt:   base.Add(time.Duration(i+1) * time.Minute),
			EndedAt:     base.Add(time.Duration(i+1)*time.Minute + time.Second),
			CloseReason: model.CloseEOF,
		})
	}
	if _, err := s.AppendRecords(filler); err != nil {
		t.Fatal(err)
	}

	got, found, err := s.RecordByKey("node-a", 7, 4242, base)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("the oldest record was not found by key; a page scan would miss it")
	}
	if got.DstHost != "target.example" {
		t.Fatalf("dst = %q", got.DstHost)
	}

	if _, found, err = s.RecordByKey("node-a", 7, 999999, time.Time{}); err != nil {
		t.Fatal(err)
	} else if found {
		t.Fatal("a key that was never stored reported found")
	}
}

// Repairing a record's identity must move its aggregate too.
//
// A record ingested while the topology was cold is stored unresolved. Fixing
// the row alone would leave the rollup counted under the empty user and line,
// so the aggregate and the record would disagree permanently.
func TestReattributeMovesTheRollupContribution(t *testing.T) {
	s := newStore(t, Options{})
	at := time.Date(2026, 8, 26, 12, 3, 0, 0, time.UTC)

	rec := model.ConnRecord{
		NodeID: "node-a", CoreGeneration: 1, LogID: 77,
		StartedAt: at, EndedAt: at.Add(time.Second),
		CloseReason: model.CloseEOF,
		UserKind:    model.UserKindUnresolved,
		BytesKnown:  true, Upload: 100, Download: 400,
	}
	if _, err := s.AppendRecords([]model.ConnRecord{rec}); err != nil {
		t.Fatal(err)
	}

	before, err := s.Rollups(RollupFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 1 || before[0].UserID != "" {
		t.Fatalf("expected one unattributed bucket, got %+v", before)
	}

	fixed := rec
	fixed.UserID = "usr_alice"
	fixed.UserKind = model.UserKindManaged
	fixed.LineUUID = "line-1"
	fixed.LineHashID = "hash-1"
	if err := s.Reattribute(model.ConnRecordKey{NodeID: "node-a", CoreGeneration: 1, LogID: 77}, at, fixed); err != nil {
		t.Fatal(err)
	}

	page, err := s.QueryRecords(Filter{UserIDs: []string{"usr_alice"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 || page.Records[0].LineUUID != "line-1" {
		t.Fatalf("the record was not repaired: %+v", page.Records)
	}

	after, err := s.Rollups(RollupFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var moved, stale *Rollup
	for i := range after {
		switch after[i].UserID {
		case "usr_alice":
			moved = &after[i]
		case "":
			stale = &after[i]
		}
	}
	if moved == nil || moved.Connections != 1 || moved.Upload != 100 || moved.Download != 400 {
		t.Fatalf("the contribution did not move to the resolved grain: %+v", after)
	}
	if stale != nil && stale.Connections != 0 {
		t.Fatalf("the old grain still counts %d connections; the aggregate disagrees with the record", stale.Connections)
	}
}

// A reused log id must not collapse two connections.
//
// sing-box's log id is rand.Uint32, so one core generation on one node can
// issue it twice. The assembler splits them and the store keeps both, but a
// lookup without the start time returns whichever the query ordered first, and
// a hop view would walk into the wrong connection.
func TestRecordByKeyDistinguishesAReusedLogID(t *testing.T) {
	s := newStore(t, Options{})
	base := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	first := model.ConnRecord{
		NodeID: "node-a", CoreGeneration: 3, LogID: 42,
		StartedAt: base, EndedAt: base.Add(time.Second),
		DstHost: "first.example", CloseReason: model.CloseEOF,
	}
	second := first
	second.StartedAt = base.Add(10 * time.Minute)
	second.EndedAt = second.StartedAt.Add(time.Second)
	second.DstHost = "second.example"
	if _, err := s.AppendRecords([]model.ConnRecord{first, second}); err != nil {
		t.Fatal(err)
	}

	gotFirst, ok, err := s.RecordByKey("node-a", 3, 42, first.StartedAt)
	if err != nil || !ok {
		t.Fatalf("first not found: %v %v", ok, err)
	}
	if gotFirst.DstHost != "first.example" {
		t.Fatalf("asked for the earlier connection, got %q", gotFirst.DstHost)
	}
	gotSecond, ok, err := s.RecordByKey("node-a", 3, 42, second.StartedAt)
	if err != nil || !ok {
		t.Fatalf("second not found: %v %v", ok, err)
	}
	if gotSecond.DstHost != "second.example" {
		t.Fatalf("asked for the later connection, got %q", gotSecond.DstHost)
	}
}
