package traceattr

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// userLineName reproduces the server's on-box name derivation so the tests
// exercise the real production shape rather than a hand-written lookalike.
func userLineName(userID, lineUUID string) string {
	sum := sha256.Sum256([]byte(userID + "|" + lineUUID))
	return "u_" + hex.EncodeToString(sum[:])[:16]
}

const (
	testNode     = "node-entry"
	testTag      = "vless-in"
	testLineUUID = "8f14e45f-ceea-467a-9b21-7a0d5f9b1b91"
	testLineHash = "lh_entry_vless"
	testUserID   = "usr_abc123"
)

func testTopology() Topology {
	return Topology{
		LinesByNodeTag: map[NodeTag]LineRef{
			{NodeID: testNode, Tag: testTag}: {LineUUID: testLineUUID, LineHashID: testLineHash},
		},
		UserIDByName: map[string]string{
			userLineName(testUserID, testLineUUID): testUserID,
		},
		BuiltAt: time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC),
	}
}

func baseRecord() model.ConnRecord {
	return model.ConnRecord{
		NodeID:     testNode,
		InboundTag: testTag,
		UserName:   userLineName(testUserID, testLineUUID),
		LogID:      1,
	}
}

func TestAttributeManagedUserAndLine(t *testing.T) {
	a := New(testTopology())
	r := baseRecord()
	a.Attribute(&r)

	if r.LineUUID != testLineUUID || r.LineHashID != testLineHash {
		t.Fatalf("line not attributed: uuid=%q hash=%q", r.LineUUID, r.LineHashID)
	}
	if r.UserID != testUserID {
		t.Fatalf("user id = %q, want %q", r.UserID, testUserID)
	}
	if r.UserKind != model.UserKindManaged {
		t.Fatalf("user kind = %q, want %q", r.UserKind, model.UserKindManaged)
	}
	if a.NeedsRetry(r) {
		t.Fatal("a fully attributed record must not need a retry")
	}
}

func TestAttributeUnknownTagLeavesLineEmpty(t *testing.T) {
	a := New(testTopology())
	r := baseRecord()
	r.InboundTag = "tag-that-does-not-exist"
	a.Attribute(&r)

	if r.LineUUID != "" || r.LineHashID != "" {
		t.Fatalf("unknown tag must not resolve a line, got uuid=%q hash=%q", r.LineUUID, r.LineHashID)
	}
	if !a.NeedsRetry(r) {
		t.Fatal("a record with no line must be queued for retry")
	}
}

func TestAttributeTagIsScopedToNode(t *testing.T) {
	// The same tag string on another node is a different line. Matching it would
	// attribute a connection to a node that never carried it.
	a := New(testTopology())
	r := baseRecord()
	r.NodeID = "node-exit"
	a.Attribute(&r)

	if r.LineUUID != "" || r.LineHashID != "" {
		t.Fatalf("tag matched across nodes: uuid=%q hash=%q", r.LineUUID, r.LineHashID)
	}
}

func TestAttributeEmptyTagNeverMatches(t *testing.T) {
	topo := testTopology()
	// A snapshot that somehow carries an empty tag must still not act as a
	// catch-all for records whose tag was never parsed.
	topo.LinesByNodeTag[NodeTag{NodeID: testNode, Tag: ""}] = LineRef{LineUUID: "wrong", LineHashID: "wrong"}
	a := New(topo)
	r := baseRecord()
	r.InboundTag = "   "
	a.Attribute(&r)

	if r.LineUUID != "" || r.LineHashID != "" {
		t.Fatalf("empty tag resolved a line: uuid=%q hash=%q", r.LineUUID, r.LineHashID)
	}
}

func TestAttributeClearsStaleLineOnMiss(t *testing.T) {
	// A line identity is only as good as the snapshot that proved it. An older
	// value must not survive a miss, or an unverified guess would be presented
	// as fact and the record would never be retried.
	a := New(testTopology())
	r := baseRecord()
	r.InboundTag = "renamed-tag"
	r.LineUUID, r.LineHashID = "stale-uuid", "stale-hash"
	a.Attribute(&r)

	if r.LineUUID != "" || r.LineHashID != "" {
		t.Fatalf("stale line survived a miss: uuid=%q hash=%q", r.LineUUID, r.LineHashID)
	}
}

func TestAttributeUnresolvedManagedName(t *testing.T) {
	a := New(testTopology())
	r := baseRecord()
	r.UserName = userLineName("someone-else", testLineUUID)
	a.Attribute(&r)

	if r.UserKind != model.UserKindUnresolved {
		t.Fatalf("user kind = %q, want %q", r.UserKind, model.UserKindUnresolved)
	}
	if r.UserID != "" {
		t.Fatalf("unresolved name must not carry a user id, got %q", r.UserID)
	}
	if !a.NeedsRetry(r) {
		t.Fatal("an unresolved name must be queued for retry")
	}
}

func TestAttributeServerVerdictBeatsAgentGuess(t *testing.T) {
	// The agent can tell managed from legacy by shape, but only the server holds
	// the index that separates managed from unresolved.
	a := New(testTopology())
	r := baseRecord()
	r.UserName = userLineName("someone-else", testLineUUID)
	r.UserKind = model.UserKindManaged
	r.UserID = "usr_agent_guess"
	a.Attribute(&r)

	if r.UserKind != model.UserKindUnresolved || r.UserID != "" {
		t.Fatalf("agent guess survived: kind=%q id=%q", r.UserKind, r.UserID)
	}
}

func TestAttributeLegacyLabel(t *testing.T) {
	for _, name := range []string{
		"alice-laptop",
		"u_short",
		"u_0123456789abcdef0", // one hex digit too many
		"u_0123456789ABCDEF",  // hex.EncodeToString never emits uppercase
		"u_0123456789abcdeg",  // g is not hex
		"x_0123456789abcdef",  // wrong prefix
	} {
		a := New(testTopology())
		r := baseRecord()
		r.UserName = name
		a.Attribute(&r)

		if r.UserKind != model.UserKindLegacy {
			t.Fatalf("name %q: kind = %q, want %q", name, r.UserKind, model.UserKindLegacy)
		}
		if r.UserID != "" {
			t.Fatalf("name %q: legacy label must not carry a user id, got %q", name, r.UserID)
		}
		if a.NeedsRetry(r) {
			t.Fatalf("name %q: a legacy label is never resolvable, so it must not be retried", name)
		}
	}
}

func TestAttributeUnnamed(t *testing.T) {
	for _, name := range []string{"", "   "} {
		a := New(testTopology())
		r := baseRecord()
		r.UserName = name
		a.Attribute(&r)

		if r.UserKind != model.UserKindUnnamed {
			t.Fatalf("name %q: kind = %q, want %q", name, r.UserKind, model.UserKindUnnamed)
		}
		if r.UserID != "" {
			t.Fatalf("name %q: unnamed record must not carry a user id, got %q", name, r.UserID)
		}
	}
}

func TestAttributeNeverInventsAUserFromTheLine(t *testing.T) {
	// Exactly one user is bound to this line, and the record's name does not
	// resolve. Falling back to "the only user on that line" is the tempting
	// wrong answer this package refuses to give.
	a := New(testTopology())
	r := baseRecord()
	r.UserName = "someone"
	a.Attribute(&r)

	if r.UserID != "" {
		t.Fatalf("user id was invented from the line: %q", r.UserID)
	}
}

func TestNeedsRetryTruthTable(t *testing.T) {
	a := New(testTopology())
	cases := []struct {
		name string
		rec  model.ConnRecord
		want bool
	}{
		{"line and managed user", model.ConnRecord{LineUUID: testLineUUID, UserKind: model.UserKindManaged}, false},
		{"line and legacy label", model.ConnRecord{LineUUID: testLineUUID, UserKind: model.UserKindLegacy}, false},
		{"line and unnamed", model.ConnRecord{LineUUID: testLineUUID, UserKind: model.UserKindUnnamed}, false},
		{"line and unresolved user", model.ConnRecord{LineUUID: testLineUUID, UserKind: model.UserKindUnresolved}, true},
		{"no line, managed user", model.ConnRecord{UserKind: model.UserKindManaged}, true},
		{"no line, unresolved user", model.ConnRecord{UserKind: model.UserKindUnresolved}, true},
		{"blank line uuid", model.ConnRecord{LineUUID: "  ", UserKind: model.UserKindLegacy}, true},
	}
	for _, c := range cases {
		if got := a.NeedsRetry(c.rec); got != c.want {
			t.Errorf("%s: NeedsRetry = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAttributeAllCounters(t *testing.T) {
	a := New(testTopology())
	records := []model.ConnRecord{
		baseRecord(), // resolves fully
		{NodeID: testNode, InboundTag: testTag, UserName: "legacy-label"},                      // line ok, legacy user
		{NodeID: testNode, InboundTag: "unknown", UserName: baseRecord().UserName},             // no line
		{NodeID: testNode, InboundTag: testTag, UserName: userLineName("ghost", testLineUUID)}, // unresolved user
	}
	res := a.AttributeAll(records)

	if res.Attributed != 2 || res.Unresolved != 2 {
		t.Fatalf("counters = %+v, want Attributed 2 Unresolved 2", res)
	}
	if res.Attributed+res.Unresolved != len(records) {
		t.Fatalf("counters do not cover every record: %+v over %d", res, len(records))
	}
	if records[0].UserID != testUserID {
		t.Fatalf("AttributeAll did not mutate in place: %+v", records[0])
	}
	if records[2].LineUUID != "" {
		t.Fatalf("record 2 must have no line, got %q", records[2].LineUUID)
	}
}

func TestAttributeNilRecordIsSafe(t *testing.T) {
	New(testTopology()).Attribute(nil)
}

func TestEmptyTopologyResolvesNothing(t *testing.T) {
	a := New(Topology{})
	r := baseRecord()
	a.Attribute(&r)

	if r.LineUUID != "" || r.UserID != "" {
		t.Fatalf("empty topology resolved something: %+v", r)
	}
	if r.UserKind != model.UserKindUnresolved {
		t.Fatalf("kind = %q, want %q", r.UserKind, model.UserKindUnresolved)
	}
	if !a.NeedsRetry(r) {
		t.Fatal("a cold topology must produce retry candidates, not silent gaps")
	}
}

func TestTopologyRoundTrip(t *testing.T) {
	topo := testTopology()
	got := New(topo).Topology()
	if !got.BuiltAt.Equal(topo.BuiltAt) {
		t.Fatalf("BuiltAt = %v, want %v", got.BuiltAt, topo.BuiltAt)
	}
	if len(got.LinesByNodeTag) != len(topo.LinesByNodeTag) || len(got.UserIDByName) != len(topo.UserIDByName) {
		t.Fatalf("snapshot not returned intact: %+v", got)
	}
}

func TestRetryHealsAfterTopologyRefresh(t *testing.T) {
	// The cold window is expected: the line read model is cached for 60s and the
	// sing-box inventory is memory-only. The record must repair itself on the
	// next pass rather than keep the gap.
	cold := New(Topology{})
	r := baseRecord()
	cold.Attribute(&r)
	if !cold.NeedsRetry(r) {
		t.Fatal("cold attribution must be flagged for retry")
	}

	warm := New(testTopology())
	warm.Attribute(&r)
	if warm.NeedsRetry(r) {
		t.Fatalf("retry did not heal the record: %+v", r)
	}
	if r.UserID != testUserID || r.LineUUID != testLineUUID {
		t.Fatalf("retry produced the wrong answer: %+v", r)
	}
}
