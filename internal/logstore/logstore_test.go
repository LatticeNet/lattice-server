package logstore

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
)

func openTest(t *testing.T, cipher secret.Cipher, cap int64) *Store {
	t.Helper()
	if cipher == nil {
		cipher = secret.Disabled()
	}
	s, err := Open(filepath.Join(t.TempDir(), "logs.db"), cipher, cap)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mkLines(base time.Time, texts ...string) []model.LogLine {
	out := make([]model.LogLine, 0, len(texts))
	for i, tx := range texts {
		out = append(out, model.LogLine{
			SourceID: "src1", NodeID: "node-a", Path: "/var/log/x.log",
			At: base.Add(time.Duration(i) * time.Second), Line: tx,
		})
	}
	return out
}

func TestAppendQueryRoundtrip(t *testing.T) {
	s := openTest(t, nil, 0)
	base := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	if _, err := s.Append("src1", mkLines(base, "alpha", "beta"), "rot1", 12, base); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append("src1", mkLines(base.Add(time.Minute), "gamma", "delta"), "rot1", 24, base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	res, err := s.Query(Filter{SourceID: "src1", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	// Newest-first: delta, gamma, beta, alpha.
	want := []string{"delta", "gamma", "beta", "alpha"}
	if len(res.Lines) != len(want) {
		t.Fatalf("got %d lines, want %d: %+v", len(res.Lines), len(want), res.Lines)
	}
	for i, w := range want {
		if res.Lines[i].Line != w {
			t.Fatalf("line %d = %q, want %q", i, res.Lines[i].Line, w)
		}
	}
}

func TestQuerySubstringAndTimeFilter(t *testing.T) {
	s := openTest(t, nil, 0)
	base := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	if _, err := s.Append("src1", mkLines(base, "ERROR boom", "info ok", "ERROR again"), "r", 9, base); err != nil {
		t.Fatal(err)
	}
	res, err := s.Query(Filter{SourceID: "src1", Contains: "error", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Lines) != 2 {
		t.Fatalf("substring filter: got %d, want 2: %+v", len(res.Lines), res.Lines)
	}
	// Time window: only the line at base+1s.
	res, err = s.Query(Filter{SourceID: "src1", Since: base.Add(time.Second), Until: base.Add(time.Second), Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Lines) != 1 || res.Lines[0].Line != "info ok" {
		t.Fatalf("time filter: %+v", res.Lines)
	}
}

func TestQueryPaginationCursor(t *testing.T) {
	s := openTest(t, nil, 0)
	base := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	// 5 single-line chunks (seq 1..5).
	for i := 0; i < 5; i++ {
		if _, err := s.Append("src1", mkLines(base.Add(time.Duration(i)*time.Second), fmt.Sprintf("line%d", i)), "r", uint64(i+1), base); err != nil {
			t.Fatal(err)
		}
	}
	first, err := s.Query(Filter{SourceID: "src1", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Lines) < 2 || first.NextBeforeSeq == 0 {
		t.Fatalf("first page should have a cursor: %+v", first)
	}
	older, err := s.Query(Filter{SourceID: "src1", Limit: 2, BeforeSeq: first.NextBeforeSeq})
	if err != nil {
		t.Fatal(err)
	}
	if len(older.Lines) == 0 {
		t.Fatal("second page should return older lines")
	}
	// No overlap: every older seq is strictly below the cursor.
	for _, ln := range older.Lines {
		if ln.Seq >= first.NextBeforeSeq {
			t.Fatalf("pagination overlap: seq %d >= cursor %d", ln.Seq, first.NextBeforeSeq)
		}
	}
}

func TestByteCapEvictsOldest(t *testing.T) {
	// Tiny cap so a few chunks force eviction.
	s := openTest(t, nil, 200)
	base := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 40; i++ {
		line := fmt.Sprintf("line-%03d-padding-padding-padding", i)
		if _, err := s.Append("src1", mkLines(base.Add(time.Duration(i)*time.Second), line), "r", uint64(i+1), base); err != nil {
			t.Fatal(err)
		}
	}
	meta, _, _, ok := s.Stats("src1")
	if !ok {
		t.Fatal("expected stats")
	}
	if meta.Bytes > s.SourceBytesCap() {
		t.Fatalf("byte cap violated: %d > %d", meta.Bytes, s.SourceBytesCap())
	}
	// Oldest lines are gone; newest survive.
	res, err := s.Query(Filter{SourceID: "src1", Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Lines) == 0 {
		t.Fatal("expected surviving lines")
	}
	if res.Lines[0].Line != "line-039-padding-padding-padding" {
		t.Fatalf("newest line should survive, got %q", res.Lines[0].Line)
	}
	for _, ln := range res.Lines {
		if ln.Line == "line-000-padding-padding-padding" {
			t.Fatal("oldest line should have been evicted")
		}
	}
}

func TestCipherRoundtrip(t *testing.T) {
	key := make([]byte, secret.KeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cipher, err := secret.NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	s := openTest(t, cipher, 0)
	base := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	if _, err := s.Append("src1", mkLines(base, "secret-token-abc"), "r", 16, base); err != nil {
		t.Fatal(err)
	}
	res, err := s.Query(Filter{SourceID: "src1", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Lines) != 1 || res.Lines[0].Line != "secret-token-abc" {
		t.Fatalf("sealed roundtrip failed: %+v", res.Lines)
	}
}

func TestPurgeSource(t *testing.T) {
	s := openTest(t, nil, 0)
	base := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	if _, err := s.Append("src1", mkLines(base, "x"), "r", 1, base); err != nil {
		t.Fatal(err)
	}
	if err := s.PurgeSource("src1"); err != nil {
		t.Fatal(err)
	}
	res, err := s.Query(Filter{SourceID: "src1", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Lines) != 0 {
		t.Fatalf("purged source should be empty: %+v", res.Lines)
	}
	if _, _, _, ok := s.Stats("src1"); ok {
		t.Fatal("purged source should have no stats")
	}
}

func TestSeqAssignedAndMonotonic(t *testing.T) {
	s := openTest(t, nil, 0)
	base := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	seq1, err := s.Append("src1", mkLines(base, "a"), "r", 1, base)
	if err != nil {
		t.Fatal(err)
	}
	seq2, err := s.Append("src1", mkLines(base, "b"), "r", 2, base)
	if err != nil {
		t.Fatal(err)
	}
	if seq1 != 1 || seq2 != 2 {
		t.Fatalf("seq should be monotonic 1,2 got %d,%d", seq1, seq2)
	}
}

// TestSetSourceBytesCapEvictsOnTheNextAppend lowers the cap on an open store,
// the way an evidence settings save does: nothing is evicted by the call, and
// the source is brought under the new cap by its next append.
func TestSetSourceBytesCapEvictsOnTheNextAppend(t *testing.T) {
	s := openTest(t, nil, 0)
	base := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for i := range 40 {
		line := fmt.Sprintf("line-%03d-padding-padding-padding", i)
		if _, err := s.Append("src1", mkLines(base.Add(time.Duration(i)*time.Second), line), "r", uint64(i+1), base); err != nil {
			t.Fatal(err)
		}
	}
	before, _, _, _ := s.Stats("src1")
	if before.Bytes <= 200 {
		t.Fatalf("seed holds %d bytes; the test needs more than the new cap", before.Bytes)
	}

	s.SetSourceBytesCap(200)
	if got := s.SourceBytesCap(); got != 200 {
		t.Fatalf("SourceBytesCap() = %d, want 200", got)
	}
	if meta, _, _, _ := s.Stats("src1"); meta.Bytes != before.Bytes {
		t.Fatalf("the call itself evicted: %d bytes, was %d", meta.Bytes, before.Bytes)
	}

	if _, err := s.Append("src1", mkLines(base.Add(time.Minute), "after-the-cap"), "r", 41, base); err != nil {
		t.Fatal(err)
	}
	after, _, _, _ := s.Stats("src1")
	if after.Bytes > 200 {
		t.Fatalf("after the next append the source holds %d bytes, over the new cap of 200", after.Bytes)
	}

	// Zero or less restores the default, as at Open.
	s.SetSourceBytesCap(0)
	if got := s.SourceBytesCap(); got != DefaultMaxSourceBytes {
		t.Fatalf("SourceBytesCap() after a zero cap = %d, want the default %d", got, DefaultMaxSourceBytes)
	}
}

// TestEnforceSourceBytesCapShrinksIdleSources: after a cap is lowered, one
// pass brings every source under it without waiting for an append, and
// leaves sources already under it alone.
func TestEnforceSourceBytesCapShrinksIdleSources(t *testing.T) {
	s := openTest(t, nil, 0)
	base := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for _, source := range []string{"big-a", "big-b"} {
		for i := range 40 {
			line := fmt.Sprintf("%s-%03d-padding-padding-padding", source, i)
			if _, err := s.Append(source, mkLines(base.Add(time.Duration(i)*time.Second), line), "r", uint64(i+1), base); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := s.Append("small", mkLines(base, "x"), "r", 1, base); err != nil {
		t.Fatal(err)
	}
	small, _, _, _ := s.Stats("small")

	s.SetSourceBytesCap(200)
	n, err := s.EnforceSourceBytesCap()
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("shrank %d sources, want the two over the cap", n)
	}
	for _, source := range []string{"big-a", "big-b"} {
		meta, _, _, _ := s.Stats(source)
		if meta.Bytes > 200 {
			t.Fatalf("%s holds %d bytes after the pass, over the cap of 200", source, meta.Bytes)
		}
		res, err := s.Query(Filter{SourceID: source, Limit: 1})
		if err != nil || len(res.Lines) != 1 || !strings.HasSuffix(res.Lines[0].Line, "039-padding-padding-padding") {
			t.Fatalf("%s lost its newest line: %+v %v", source, res.Lines, err)
		}
	}
	if after, _, _, _ := s.Stats("small"); after != small {
		t.Fatalf("a source under the cap changed: %+v, was %+v", after, small)
	}
	if n, err := s.EnforceSourceBytesCap(); err != nil || n != 0 {
		t.Fatalf("a second pass shrank %d (%v), want none", n, err)
	}
}
