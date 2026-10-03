package server

import (
	"testing"
	"time"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// Each user-day row records how much of what it counted a proof rule counted.
// In the fleet fixture alice's bytes come from her own u_ counter (named),
// carol's from a single-credential inbound holding her credential
// (credential), and bob's from being the one identity bound to a line whose
// users carry no name (binding, inferred). The quota counts all three; only
// the first two are proof.
func TestUsageDayRowsRecordWhichBytesAreProof(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	f := seedUsageFleet(t, srv)
	reportUsageFleet(t, srv, f)
	day := store.UsageDay(now)
	for _, tc := range []struct {
		name        string
		user        VpnUser
		line        string
		used, proof int64
	}{
		{"named counter", f.alice, f.hub.LineHashID, 300, 300},
		{"single credential", f.carol, "", 30, 30},
		{"only binding", f.bob, f.direct.LineHashID, 80, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := srv.store.UsageDayUserRows(tc.user.ID, day, day)
			if err != nil || len(rows) != 1 {
				t.Fatalf("day rows: %v %+v", err, rows)
			}
			row := rows[0]
			if row.Uplink+row.Downlink != tc.used || row.Proof != tc.proof {
				t.Fatalf("row counts %d bytes with %d proven, want %d with %d proven", row.Uplink+row.Downlink, row.Proof, tc.used, tc.proof)
			}
			if tc.line != "" {
				if line := row.ByLine[tc.line]; line.Uplink+line.Downlink != tc.used || line.Proof != tc.proof {
					t.Fatalf("line %s counts %+v, want %d with %d proven", tc.line, line, tc.used, tc.proof)
				}
			}
		})
	}
}
