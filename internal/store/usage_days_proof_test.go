package store

import (
	"encoding/json"
	"testing"
	"time"
)

// The proven part of a user-day row adds across reports like the bytes do, on
// the row and on each line, and survives the store in both modes.
func TestUsageDayUserProofAddsAcrossReports(t *testing.T) {
	for _, mode := range []string{"json", "bolt"} {
		t.Run(mode, func(t *testing.T) {
			s := openUsageDayStore(t, mode)
			at := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
			for _, step := range []struct{ up, down, proof int64 }{{100, 200, 300}, {40, 60, 0}, {5, 5, 10}} {
				row := usageDayFixtureUser("20260902", "vu_1", "line_a", step.up, step.down, at)
				row.Proof = step.proof
				line := row.ByLine["line_a"]
				line.Proof = step.proof
				row.ByLine["line_a"] = line
				if err := s.ApplyProxyUsage(ProxyUsageUpdate{DayUsers: []UsageDayUser{row}}); err != nil {
					t.Fatal(err)
				}
				at = at.Add(time.Minute)
			}
			rows, err := s.UsageDayUserRows("vu_1", "20260902", "20260902")
			if err != nil || len(rows) != 1 {
				t.Fatalf("user rows: %v %+v", err, rows)
			}
			if got := rows[0]; got.Uplink+got.Downlink != 410 || got.Proof != 310 || got.ByLine["line_a"].Proof != 310 {
				t.Fatalf("row = %+v, want 410 bytes of which 310 proven", got)
			}
		})
	}
}

// A row written before the field existed decodes with nothing proven, so its
// bytes can only ever hold an action on proof back.
func TestUsageDayUserRowWithoutProofReadsAsUnproven(t *testing.T) {
	var row UsageDayUser
	if err := json.Unmarshal([]byte(`{"uid":"vu_1","day":"20260902","u":10,"d":20,"bl":{"line_a":{"u":10,"d":20}}}`), &row); err != nil {
		t.Fatal(err)
	}
	if row.Proof != 0 || row.ByLine["line_a"].Proof != 0 || row.Uplink+row.Downlink != 30 {
		t.Fatalf("old row = %+v", row)
	}
	raw, err := json.Marshal(UsageDayUser{UserID: "vu_1", Day: "20260902", Uplink: 1})
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	if _, ok := keys["p"]; ok {
		t.Fatalf("a row with nothing proven must keep the old shape: %s", raw)
	}
}
