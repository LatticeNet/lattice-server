package store

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func usageDayFixtureNode(day string, tag, hash string, up, down int64, user string) UsageDayNode {
	line := UsageDayLine{LineHashID: hash, Uplink: up, Downlink: down}
	if user != "" {
		line.Users = map[string]UsageDayBytes{user: {Uplink: up, Downlink: down}}
	}
	return UsageDayNode{NodeID: "node-a", Day: day, Lines: map[string]UsageDayLine{tag: line}}
}

func usageDayFixtureUser(day, user, hash string, up, down int64, at time.Time) UsageDayUser {
	return UsageDayUser{UserID: user, Day: day, Uplink: up, Downlink: down,
		ByLine: map[string]UsageDayUserLine{hash: {Uplink: up, Downlink: down, LastSeenAt: at}}, LastSeenAt: at}
}

// Deltas add into the stored row; a second report on the same day does not
// replace the first, and an unknown tag (empty hash) keeps its bytes.
func TestUsageDayDeltasAccumulate(t *testing.T) {
	for _, mode := range []string{"json", "bolt"} {
		t.Run(mode, func(t *testing.T) {
			s := openUsageDayStore(t, mode)
			at := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
			for _, step := range []struct{ up, down int64 }{{100, 200}, {5, 7}} {
				err := s.ApplyProxyUsage(ProxyUsageUpdate{
					DayNode:  ptr(usageDayFixtureNode("20260902", "vless-443", "line_a", step.up, step.down, "vu_1")),
					DayUsers: []UsageDayUser{usageDayFixtureUser("20260902", "vu_1", "line_a", step.up, step.down, at)},
				})
				if err != nil {
					t.Fatal(err)
				}
				at = at.Add(time.Minute)
			}
			if err := s.ApplyProxyUsage(ProxyUsageUpdate{DayNode: ptr(usageDayFixtureNode("20260902", "stray", "", 1, 2, ""))}); err != nil {
				t.Fatal(err)
			}
			nodes, err := s.UsageDayNodeRows("node-a", "20260902", "20260902")
			if err != nil || len(nodes) != 1 {
				t.Fatalf("node rows: %v %+v", err, nodes)
			}
			line := nodes[0].Lines["vless-443"]
			if line.Uplink != 105 || line.Downlink != 207 || line.LineHashID != "line_a" || line.Users["vu_1"] != (UsageDayBytes{105, 207}) {
				t.Fatalf("line row: %+v", line)
			}
			if stray := nodes[0].Lines["stray"]; stray.Uplink != 1 || stray.Downlink != 2 || stray.LineHashID != "" {
				t.Fatalf("unknown tag row must be kept: %+v", stray)
			}
			users, err := s.UsageDayUserRows("vu_1", "20260902", "20260902")
			if err != nil || len(users) != 1 {
				t.Fatalf("user rows: %v %+v", err, users)
			}
			u := users[0]
			if u.Uplink != 105 || u.Downlink != 207 || u.ByLine["line_a"].Uplink != 105 || !u.LastSeenAt.Equal(time.Date(2026, 9, 2, 10, 1, 0, 0, time.UTC)) {
				t.Fatalf("user row: %+v", u)
			}
		})
	}
}

// The range read is inclusive, ordered oldest first, and never crosses into
// another id that shares a prefix.
func TestUsageDayRangeReads(t *testing.T) {
	for _, mode := range []string{"json", "bolt"} {
		t.Run(mode, func(t *testing.T) {
			s := openUsageDayStore(t, mode)
			for _, day := range []string{"20260830", "20260831", "20260901", "20260902"} {
				if err := s.ApplyProxyUsage(ProxyUsageUpdate{
					DayNode:  ptr(usageDayFixtureNode(day, "t", "h", 1, 1, "")),
					DayUsers: []UsageDayUser{usageDayFixtureUser(day, "vu_1", "h", 1, 1, time.Time{})},
				}); err != nil {
					t.Fatal(err)
				}
			}
			// A sibling id with the first id as prefix must not leak into its scan.
			if err := s.ApplyProxyUsage(ProxyUsageUpdate{DayUsers: []UsageDayUser{usageDayFixtureUser("20260901", "vu_10", "h", 9, 9, time.Time{})}}); err != nil {
				t.Fatal(err)
			}
			rows, err := s.UsageDayUserRows("vu_1", "20260831", "20260901")
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 2 || rows[0].Day != "20260831" || rows[1].Day != "20260901" || rows[1].Uplink != 1 {
				t.Fatalf("range: %+v", rows)
			}
			nodes, err := s.UsageDayNodeRows("node-a", "20260101", "20261231")
			if err != nil || len(nodes) != 4 || nodes[0].Day != "20260830" || nodes[3].Day != "20260902" {
				t.Fatalf("node range: %v %+v", err, nodes)
			}
			if _, err := s.UsageDayNodeRows("node-a", "bad", "20260902"); err == nil {
				t.Fatal("malformed day must be rejected")
			}
		})
	}
}

// Pruning removes only rows older than the cutoff, in both buckets.
func TestUsageDayPrune(t *testing.T) {
	for _, mode := range []string{"json", "bolt"} {
		t.Run(mode, func(t *testing.T) {
			s := openUsageDayStore(t, mode)
			for _, day := range []string{"20250701", "20250702", "20260902"} {
				if err := s.ApplyProxyUsage(ProxyUsageUpdate{
					DayNode:  ptr(usageDayFixtureNode(day, "t", "h", 1, 1, "")),
					DayUsers: []UsageDayUser{usageDayFixtureUser(day, "vu_1", "h", 1, 1, time.Time{})},
				}); err != nil {
					t.Fatal(err)
				}
			}
			pruned, err := s.PruneUsageDays("20250702")
			if err != nil || pruned != 2 {
				t.Fatalf("pruned=%d err=%v", pruned, err)
			}
			nodes, _ := s.UsageDayNodeRows("node-a", "20250101", "20261231")
			users, _ := s.UsageDayUserRows("vu_1", "20250101", "20261231")
			if len(nodes) != 2 || nodes[0].Day != "20250702" || len(users) != 2 || users[0].Day != "20250702" {
				t.Fatalf("after prune: nodes=%+v users=%+v", nodes, users)
			}
		})
	}
}

// Rows written while the store was JSON-only are carried into bolt once, and
// the JSON file stops carrying them afterwards.
func TestUsageDaySeedIntoBolt(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "state.json")
	boltPath := filepath.Join(dir, "state-hot.db")
	c := testCipher(t)
	s, err := OpenWithCipher(jsonPath, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyProxyUsage(ProxyUsageUpdate{DayNode: ptr(usageDayFixtureNode("20260902", "t", "h", 3, 4, ""))}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableRuntimeBoltHotStore(boltPath); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyProxyUsage(ProxyUsageUpdate{DayNode: ptr(usageDayFixtureNode("20260902", "t", "h", 1, 1, ""))}); err != nil {
		t.Fatal(err)
	}
	nodes, err := s.UsageDayNodeRows("node-a", "20260902", "20260902")
	if err != nil || len(nodes) != 1 || nodes[0].Lines["t"].Uplink != 4 {
		t.Fatalf("seeded row must keep accumulating in bolt: %v %+v", err, nodes)
	}
	// The next JSON write is what drops the stale copy, as for every other
	// hot collection.
	if err := s.UpsertNode(model.Node{ID: "node-a"}); err != nil {
		t.Fatal(err)
	}
	jsonState, err := LoadJSONState(jsonPath, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(jsonState.UsageDayNodes) != 0 {
		t.Fatalf("day rows must leave the JSON state once bolt owns them: %+v", jsonState.UsageDayNodes)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWithCipher(jsonPath, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.EnableRuntimeBoltHotStore(boltPath); err != nil {
		t.Fatal(err)
	}
	nodes, err = reopened.UsageDayNodeRows("node-a", "20260902", "20260902")
	if err != nil || len(nodes) != 1 || nodes[0].Lines["t"].Uplink != 4 {
		t.Fatalf("row not recovered from bolt: %v %+v", err, nodes)
	}
	// The snapshot and the day rows share one transaction.
	if err := reopened.ApplyProxyUsage(ProxyUsageUpdate{
		Snapshot: &model.ProxyUsageSnapshot{NodeID: "node-a", CoreUptimeSec: 7},
		DayNode:  ptr(usageDayFixtureNode("20260903", "t", "h", 1, 1, "")),
	}); err != nil {
		t.Fatal(err)
	}
	if snap, ok := reopened.ProxyUsageSnapshot("node-a"); !ok || snap.CoreUptimeSec != 7 {
		t.Fatalf("snapshot: %+v", snap)
	}
}

// The documented size bound: 33 nodes, 200 lines each, 400 days. Every line
// active every day with one named user is the worst case; the fleet must stay
// under 512 MiB and one node-day record under 40 KiB.
func TestUsageDaySizeBound(t *testing.T) {
	row := UsageDayNode{NodeID: "node_0123456789abcdef", Day: "20260902", Lines: map[string]UsageDayLine{}}
	for i := 0; i < 200; i++ {
		tag := fmt.Sprintf("vless-reality-%03d", i)
		row.Lines[tag] = UsageDayLine{
			LineHashID: fmt.Sprintf("line_%024x", i),
			Uplink:     9_876_543_210 + int64(i), Downlink: 98_765_432_100 + int64(i),
			Users: map[string]UsageDayBytes{fmt.Sprintf("vpnuser_%016x", i): {Uplink: 9_876_543_210, Downlink: 98_765_432_100}},
		}
	}
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	const recordBudget = 40 * 1024
	const fleetBudget = 512 << 20
	if len(raw) > recordBudget {
		t.Fatalf("node-day record is %d bytes, budget %d", len(raw), recordBudget)
	}
	fleet := int64(len(raw)) * 33 * UsageDayRetentionDays
	if fleet > fleetBudget {
		t.Fatalf("fleet at the bound is %d bytes, budget %d", fleet, fleetBudget)
	}
	t.Logf("node-day record %d bytes, fleet at bound %d MiB", len(raw), fleet>>20)
}

func openUsageDayStore(t *testing.T, mode string) *Store {
	t.Helper()
	dir := t.TempDir()
	c := testCipher(t)
	s, err := OpenWithCipher(filepath.Join(dir, "state.json"), c)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "bolt" {
		if err := s.EnableRuntimeBoltHotStore(filepath.Join(dir, "state-hot.db")); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func ptr[T any](v T) *T { return &v }
