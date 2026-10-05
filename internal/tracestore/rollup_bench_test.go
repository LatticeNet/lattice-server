package tracestore

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// Rollup series read cost, the design 26 R1 acceptance for the trends read:
// a 90-day window over 30 days of rollups answers in under 200 ms on a
// developer machine.
//
// The fleet is synthetic and deliberately larger than today's: 60 rows in
// every five-minute bucket (34 nodes, up to 31 users, 4 lines), 518,400 rows
// and about 86 MiB of trace.db. The rows go straight into rollups_5m because
// writing them through AppendRecords would take minutes and measure ingest,
// not the read.
//
//	go test ./internal/tracestore/ -run '^$' -bench RollupSeries -benchtime 10x

const (
	benchRollupRowsPerBucket = 60
	benchRollupNodes         = 34
)

func benchRollupStore(b *testing.B) (*Store, time.Time, []string) {
	b.Helper()
	s, err := Open(filepath.Join(b.TempDir(), "trace.db"), nil, Options{})
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	b.Cleanup(func() { s.Close() })
	end := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	tx, err := s.db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO rollups_5m (bucket_start, user_id, line_uuid, node_id,
		connections, bytes_known_count, upload, download, close_reasons) VALUES (?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		b.Fatal(err)
	}
	bucket := 0
	for at := end.Add(-30 * 24 * time.Hour); at.Before(end); at = at.Add(RollupBucket) {
		for i := range benchRollupRowsPerBucket {
			c := int64(5 + (i+bucket)%20)
			if _, err := stmt.Exec(nanos(at),
				fmt.Sprintf("u%03d", (i+bucket)%(benchRollupRowsPerBucket/2+1)),
				fmt.Sprintf("l%d", (i/10)%4),
				fmt.Sprintf("n%02d", i%benchRollupNodes),
				c, c-1, c*1000, c*50000,
				fmt.Sprintf(`{"eof":%d,"reset":1,"timeout":1}`, c-2)); err != nil {
				b.Fatal(err)
			}
		}
		bucket++
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	nodes := make([]string, 0, benchRollupNodes)
	for i := range benchRollupNodes {
		nodes = append(nodes, fmt.Sprintf("n%02d", i))
	}
	return s, end, nodes
}

func BenchmarkRollupSeries90DayWindow(b *testing.B) {
	s, end, nodes := benchRollupStore(b)
	for _, groupBy := range []string{RollupGroupNode, RollupGroupUser, RollupGroupReason} {
		b.Run(groupBy, func(b *testing.B) {
			f := RollupSeriesFilter{
				Since: end.Add(-90 * 24 * time.Hour), Until: end, Step: time.Hour,
				GroupBy: groupBy, NodeIDs: nodes,
			}
			for b.Loop() {
				if _, _, _, err := s.RollupSeries(context.Background(), f); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
