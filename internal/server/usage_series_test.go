package server

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-server/internal/store"
)

type usageQueryWire struct {
	Lines    []usageLineRow `json:"lines"`
	Series   *usageSeries   `json:"series"`
	Previous *usagePrevious `json:"previous"`
	From     string         `json:"from"`
	To       string         `json:"to"`
}

func queryUsage(t *testing.T, srv *Server, period string) usageQueryWire {
	t.Helper()
	raw, err := srv.vpnCoreUsageRPC(context.Background(), "query", []byte(`{"period":"`+period+`"}`))
	if err != nil {
		t.Fatalf("query %s: %v", period, err)
	}
	var out usageQueryWire
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Series == nil {
		t.Fatalf("query %s: no series in %s", period, raw)
	}
	return out
}

// isEgressRole is the contract's definition, stated here rather than taken
// from the code under test: exit, direct and shared lines leave the fleet.
func isEgressRole(role string) bool {
	return role == usageRoleExit || role == usageRoleDirect || role == usageRoleShared
}

// The daily series is the lines' own day rows per node and role: summed over
// the window, its exit, direct and shared bytes are exactly the used_bytes of
// the exit, direct and shared lines rows. previous is the same egress one
// period back.
func TestUsageSeriesEgressMatchesLines(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	f := seedUsageFleet(t, srv)
	// Today's rows come through ingestion, with a named user counter on the
	// entry, a credential line, a bound direct line and an unknown tag.
	reportUsageFleet(t, srv, f)
	seed := func(offset int, nodeID string, lines map[string]store.UsageDayLine) {
		t.Helper()
		row := store.UsageDayNode{NodeID: nodeID, Day: store.UsageDay(now.AddDate(0, 0, offset)), Lines: lines}
		if err := srv.store.ApplyProxyUsage(store.ProxyUsageUpdate{DayNode: &row}); err != nil {
			t.Fatal(err)
		}
	}
	// Days inside this 7d window (-1, -3, -6), in the previous one (-7, -10,
	// -13), and one before both (-14).
	for _, offset := range []int{-1, -3, -6, -7, -10, -13, -14} {
		scale := int64(-offset) * 1000
		seed(offset, "node-a", map[string]store.UsageDayLine{
			"hub-a":    {LineHashID: f.hub.LineHashID, Uplink: scale, Downlink: 2 * scale},
			"direct-a": {LineHashID: f.direct.LineHashID, Uplink: scale / 10, Downlink: scale / 5},
			"ghost":    {Uplink: 7, Downlink: 3},
		})
		seed(offset, "node-b", map[string]store.UsageDayLine{
			"exit-b-in": {LineHashID: f.exit.LineHashID, Uplink: scale / 2, Downlink: scale},
			"shared-b":  {LineHashID: f.shared.LineHashID, Uplink: 11, Downlink: 13},
		})
	}

	out := queryUsage(t, srv, "7d")
	wantDays := []string{"20260923", "20260924", "20260925", "20260926", "20260927", "20260928", "20260929"}
	if !reflect.DeepEqual(out.Series.Days, wantDays) || out.Series.Truncated {
		t.Fatalf("days = %v truncated=%v", out.Series.Days, out.Series.Truncated)
	}
	daily := make([]int64, len(wantDays))
	var seriesEgress, linesEgress int64
	roles := map[string]bool{}
	seen := map[[2]string]bool{}
	for _, row := range out.Series.Rows {
		key := [2]string{row.NodeID, row.Role}
		if seen[key] || len(row.Bytes) != len(wantDays) {
			t.Fatalf("series row repeated or misaligned: %+v", row)
		}
		seen[key] = true
		roles[row.Role] = true
		if !isEgressRole(row.Role) {
			continue
		}
		for i, b := range row.Bytes {
			daily[i] += b
			seriesEgress += b
		}
	}
	for _, row := range out.Lines {
		if isEgressRole(row.Role) {
			linesEgress += row.UsedBytes
		}
	}
	if seriesEgress == 0 || seriesEgress != linesEgress {
		t.Fatalf("series egress %d != lines egress %d", seriesEgress, linesEgress)
	}
	for _, role := range []string{usageRoleEntry, usageRoleDirect, usageRoleExit, usageRoleShared} {
		if !roles[role] {
			t.Fatalf("series is missing role %s: %+v", role, out.Series.Rows)
		}
	}
	// 09-28: direct-a 300, the unknown tag 10 (direct, as its lines row), exit
	// 1500, shared 24. The entry lines' 3000 forward inside the fleet.
	if daily[5] != 1834 || daily[4] != 0 {
		t.Fatalf("daily egress = %v", daily)
	}
	// 09-16..09-22 holds -7, -10 and -13: 12634 + 18034 + 23434.
	if out.Previous == nil || out.Previous.From != "20260916" || out.Previous.To != "20260922" || out.Previous.EgressBytes != 54102 {
		t.Fatalf("previous = %+v", out.Previous)
	}

	// A window longer than 90 days keeps its latest 90 and says so; a named
	// range has no previous period.
	all := queryUsage(t, srv, "all")
	if len(all.Series.Days) != usageSeriesMaxDays || !all.Series.Truncated || all.Series.Days[89] != "20260929" || all.Previous != nil {
		t.Fatalf("all: %d days truncated=%v last=%s previous=%+v", len(all.Series.Days), all.Series.Truncated, all.Series.Days[len(all.Series.Days)-1], all.Previous)
	}
	ranged := queryUsage(t, srv, "20260920..20260929")
	if len(ranged.Series.Days) != 10 || ranged.Series.Truncated || ranged.Previous != nil {
		t.Fatalf("range: days=%v previous=%+v", ranged.Series.Days, ranged.Previous)
	}
	today := queryUsage(t, srv, "today")
	if len(today.Series.Days) != 1 || today.Previous == nil || today.Previous.From != "20260928" || today.Previous.To != "20260928" || today.Previous.EgressBytes != 1834 {
		t.Fatalf("today: days=%v previous=%+v", today.Series.Days, today.Previous)
	}
}
