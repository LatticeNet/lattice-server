package tracestore

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// filterFixture is the record set every filter case runs against. Each record
// differs from its neighbours in exactly the dimensions under test, and log ids
// double as the assertion labels. Ids run newest to oldest: id N started N
// minutes before t0.
func filterFixture(t *testing.T) *Store {
	t.Helper()
	s := newStore(t, Options{})
	type spec struct {
		id       uint32
		node     string
		user     string
		kind     string
		line     string
		dst      string
		reason   string
		stalled  bool
		open     bool
		sessions []string
	}
	specs := []spec{
		{1, "n1", "u1", model.UserKindManaged, "l1", "api.github.com", model.CloseEOF, false, false, []string{"s1"}},
		{2, "n1", "u1", model.UserKindManaged, "l1", "API.GitHub.com", model.CloseReset, true, false, []string{"s1", "s2"}},
		{3, "n1", "u2", model.UserKindManaged, "l2", "cdn.example.net", model.CloseDialFailed, false, false, nil},
		{4, "n2", "u1", model.UserKindManaged, "l2", "api.github.com", model.CloseTimeout, true, false, []string{"s2"}},
		{5, "n2", "u2", model.UserKindLegacy, "l1", "mail.example.org", model.CloseEOF, false, false, nil},
		{6, "n2", "u2", model.UserKindLegacy, "l3", "api.github.com", "", false, true, []string{"s2"}},
		{7, "n1", "u3", model.UserKindUnnamed, "l1", "search.example.com", model.CloseAuthFailed, false, false, nil},
		{8, "n2", "u1", model.UserKindManaged, "l1", "api.github.com", model.CloseCoreRestart, false, false, []string{"s3"}},
		{9, "n1", "u1", model.UserKindManaged, "l1", "100%pure.example", model.CloseEOF, false, false, nil},
	}
	batch := make([]model.ConnRecord, 0, len(specs))
	for _, sp := range specs {
		r := rec(sp.node, sp.id, t0.Add(-time.Duration(sp.id)*time.Minute))
		r.UserID = sp.user
		r.UserKind = sp.kind
		r.LineUUID = sp.line
		r.DstHost = sp.dst
		r.CloseReason = sp.reason
		r.SessionIDs = sp.sessions
		if sp.stalled {
			r.StalledAt = t0.Add(-time.Duration(sp.id) * time.Minute).Add(30 * time.Second)
		}
		if sp.open {
			r.Open = true
			r.EndedAt = time.Time{}
		}
		batch = append(batch, r)
	}
	mustAppend(t, s, batch...)
	return s
}

func ids(page RecordPage) []int {
	out := make([]int, 0, len(page.Records))
	for _, r := range page.Records {
		out = append(out, int(r.LogID))
	}
	sort.Ints(out)
	return out
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestQueryRecordsFilterDimensions(t *testing.T) {
	s := filterFixture(t)
	cases := []struct {
		name string
		f    Filter
		want []int
	}{
		{"no filter excludes open snapshots", Filter{}, []int{1, 2, 3, 4, 5, 7, 8, 9}},
		{"include open", Filter{IncludeOpen: true}, []int{1, 2, 3, 4, 5, 6, 7, 8, 9}},
		{"since", Filter{Since: t0.Add(-4*time.Minute - 30*time.Second)}, []int{1, 2, 3, 4}},
		{"until", Filter{Until: t0.Add(-7 * time.Minute)}, []int{7, 8, 9}},
		{"since and until", Filter{Since: t0.Add(-5 * time.Minute), Until: t0.Add(-3 * time.Minute)}, []int{3, 4, 5}},
		{"node", Filter{NodeIDs: []string{"n1"}}, []int{1, 2, 3, 7, 9}},
		{"two nodes", Filter{NodeIDs: []string{"n1", "n2"}}, []int{1, 2, 3, 4, 5, 7, 8, 9}},
		{"user", Filter{UserIDs: []string{"u1"}}, []int{1, 2, 4, 8, 9}},
		{"line", Filter{LineUUIDs: []string{"l1"}}, []int{1, 2, 5, 7, 8, 9}},
		{"user kind", Filter{UserKinds: []string{model.UserKindUnnamed}}, []int{7}},
		{"close reasons", Filter{CloseReasons: []string{model.CloseReset, model.CloseTimeout}}, []int{2, 4}},
		{"dst substring is case insensitive", Filter{DstContains: "github"}, []int{1, 2, 4, 8}},
		{"dst substring matches a full host", Filter{DstContains: "mail.example.org"}, []int{5}},
		{"only stalled", Filter{OnlyStalled: true}, []int{2, 4}},
		{"session", Filter{SessionIDs: []string{"s1"}}, []int{1, 2}},
		{"session with an open record needs include open", Filter{SessionIDs: []string{"s2"}}, []int{2, 4}},
		{"session including open", Filter{SessionIDs: []string{"s2"}, IncludeOpen: true}, []int{2, 4, 6}},
		{"two sessions", Filter{SessionIDs: []string{"s1", "s3"}}, []int{1, 2, 8}},
		{"blank values in a slice are ignored", Filter{UserIDs: []string{"", "u2", "  "}}, []int{3, 5}},

		// Combinations: the real UI never sends one dimension at a time.
		{"user and time", Filter{UserIDs: []string{"u1"}, Since: t0.Add(-4*time.Minute - 30*time.Second)}, []int{1, 2, 4}},
		{"node and close reason", Filter{NodeIDs: []string{"n2"}, CloseReasons: []string{model.CloseTimeout, model.CloseCoreRestart}}, []int{4, 8}},
		{"dst substring and stalled", Filter{DstContains: "github", OnlyStalled: true}, []int{2, 4}},
		{"user and line and node", Filter{UserIDs: []string{"u1"}, LineUUIDs: []string{"l1"}, NodeIDs: []string{"n1"}}, []int{1, 2, 9}},
		{"session and reason and time", Filter{SessionIDs: []string{"s1", "s2", "s3"}, CloseReasons: []string{model.CloseEOF, model.CloseCoreRestart}, Until: t0}, []int{1, 8}},
		{"a filter that matches nothing", Filter{UserIDs: []string{"u1"}, NodeIDs: []string{"n2"}, LineUUIDs: []string{"l3"}}, []int{}},

		// LIKE metacharacters inside the needle are escaped, so a percent sign
		// is a percent sign and not a wildcard that matches every host.
		{"literal percent in the needle", Filter{DstContains: "100%p"}, []int{9}},
		{"a bare percent does not match everything", Filter{DstContains: "%"}, []int{9}},
		{"a bare underscore does not match everything", Filter{DstContains: "_"}, []int{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ids(mustQuery(t, s, tc.f))
			if !equalInts(got, tc.want) {
				t.Errorf("ids = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestQueryRecordsIsNewestFirst(t *testing.T) {
	s := filterFixture(t)
	page := mustQuery(t, s, Filter{})
	for i := 1; i < len(page.Records); i++ {
		if page.Records[i-1].StartedAt.Before(page.Records[i].StartedAt) {
			t.Fatalf("records are not newest first at index %d: %v then %v",
				i, page.Records[i-1].StartedAt, page.Records[i].StartedAt)
		}
	}
}

// TestKeysetPaginationCoversEverythingExactlyOnce inserts rows that share
// timestamps across nodes, which is the case a naive cursor on started_at alone
// would silently skip or repeat.
func TestKeysetPaginationCoversEverythingExactlyOnce(t *testing.T) {
	s := newStore(t, Options{})
	const total = 25
	batch := make([]model.ConnRecord, 0, total)
	for i := range total {
		// Five distinct timestamps, five nodes each: every page boundary has a
		// good chance of landing inside a group of ties.
		r := rec(fmt.Sprintf("node-%d", i%5), uint32(i+1), t0.Add(-time.Duration(i/5)*time.Minute))
		batch = append(batch, r)
	}
	mustAppend(t, s, batch...)

	seen := map[uint32]int{}
	cursor := ""
	pages := 0
	for {
		page := mustQuery(t, s, Filter{Limit: 10, Cursor: cursor})
		pages++
		wantLen := 10
		if pages == 3 {
			wantLen = 5
		}
		if len(page.Records) != wantLen {
			t.Fatalf("page %d has %d records, want %d", pages, len(page.Records), wantLen)
		}
		for _, r := range page.Records {
			seen[r.LogID]++
		}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
		if pages > 5 {
			t.Fatal("pagination did not terminate")
		}
	}
	if pages != 3 {
		t.Errorf("pages = %d, want 3", pages)
	}
	if len(seen) != total {
		t.Errorf("saw %d distinct records across pages, want %d (a gap)", len(seen), total)
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("record %d returned %d times, want once (a duplicate across pages)", id, n)
		}
	}
}

func TestPaginationLimitIsClamped(t *testing.T) {
	s := filterFixture(t)
	if got := len(mustQuery(t, s, Filter{Limit: -5}).Records); got != 8 {
		t.Errorf("a negative limit returned %d records, want the default page", got)
	}
	if got := len(mustQuery(t, s, Filter{Limit: 1 << 20}).Records); got != 8 {
		t.Errorf("an oversized limit returned %d records, want everything available", got)
	}
	page := mustQuery(t, s, Filter{Limit: 1})
	if len(page.Records) != 1 || page.NextCursor == "" {
		t.Errorf("limit 1 returned %d records with cursor %q", len(page.Records), page.NextCursor)
	}
}

func TestMalformedCursorFailsCleanly(t *testing.T) {
	s := filterFixture(t)
	valid := mustQuery(t, s, Filter{Limit: 1}).NextCursor
	if valid == "" {
		t.Fatal("expected a cursor to tamper with")
	}
	tampered := []byte(valid)
	tampered[len(tampered)-1] ^= 'A' ^ 'B'

	cases := []struct {
		name   string
		cursor string
	}{
		{"not base64", "!!!! not base64 !!!!"},
		{"empty payload", base64.RawURLEncoding.EncodeToString([]byte{1})},
		{"unknown version", base64.RawURLEncoding.EncodeToString([]byte{9, 0, 0, 0, 0, '{', '}'})},
		{"random bytes", base64.RawURLEncoding.EncodeToString([]byte("random bytes that are not a cursor"))},
		{"tampered", string(tampered)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			page, err := s.QueryRecords(Filter{Cursor: tc.cursor})
			if err == nil {
				t.Fatalf("a malformed cursor was accepted and returned %d records", len(page.Records))
			}
			if !errors.Is(err, ErrBadCursor) {
				t.Fatalf("err = %v, want ErrBadCursor so the caller can answer 400", err)
			}
		})
	}
}

func TestCursorRoundTrip(t *testing.T) {
	want := cursor{StartedAt: t0.UnixNano(), NodeID: "node-a", CoreGeneration: 7, LogID: 4294967295}
	got, err := decodeCursor(encodeCursor(want))
	if err != nil {
		t.Fatalf("decodeCursor: %v", err)
	}
	if got != want {
		t.Errorf("cursor round trip: got %+v want %+v", got, want)
	}
}

func TestQueryLinesValidatesSession(t *testing.T) {
	s := newStore(t, Options{})
	if _, err := s.QueryLines("  ", 0, 10); err == nil {
		t.Fatal("QueryLines accepted a blank session id")
	}
	got, err := s.QueryLines("no-such-session", 0, 10)
	if err != nil {
		t.Fatalf("QueryLines: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d lines for an unknown session, want none", len(got))
	}
}
