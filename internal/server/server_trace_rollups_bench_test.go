package server

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
	"github.com/LatticeNet/lattice-server/internal/store"
	"github.com/LatticeNet/lattice-server/internal/tracestore"
)

// BenchmarkTraceRollups90DayWindow is the lane D acceptance read end to end:
// GET /api/trace/rollups for a 90-day window over 30 days of rollups, as a
// full administrator who sees every node, answered in under 200 ms on a
// developer machine. The fleet matches BenchmarkRollupSeries90DayWindow in
// internal/tracestore: 34 nodes, 60 rows in every five-minute bucket, 518,400
// rows. The rows go straight into rollups_5m through a second connection to
// the same file, because ingesting them would take minutes.
//
//	go test ./internal/server/ -run '^$' -bench TraceRollups -benchtime 10x
func BenchmarkTraceRollups90DayWindow(b *testing.B) {
	const rowsPerBucket, nodes = 60, 34
	st, err := store.Open("")
	if err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(b.TempDir(), "trace.db")
	ts, err := tracestore.Open(path, secret.Disabled(), tracestore.Options{})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { ts.Close() })
	for i := range nodes {
		id := fmt.Sprintf("n%02d", i)
		if err := st.UpsertNode(model.Node{ID: id, Name: id}); err != nil {
			b.Fatal(err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		b.Fatal(err)
	}
	end := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	tx, err := db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO rollups_5m (bucket_start, user_id, line_uuid, node_id,
		connections, bytes_known_count, upload, download, close_reasons) VALUES (?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		b.Fatal(err)
	}
	bucket := 0
	for at := end.Add(-30 * 24 * time.Hour); at.Before(end); at = at.Add(tracestore.RollupBucket) {
		for i := range rowsPerBucket {
			c := int64(5 + (i+bucket)%20)
			if _, err := stmt.Exec(at.UnixNano(),
				fmt.Sprintf("u%03d", (i+bucket)%(rowsPerBucket/2+1)), fmt.Sprintf("l%d", (i/10)%4), fmt.Sprintf("n%02d", i%nodes),
				c, c-1, c*1000, c*50000, fmt.Sprintf(`{"eof":%d,"reset":1,"timeout":1}`, c-2)); err != nil {
				b.Fatal(err)
			}
		}
		bucket++
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	if err := db.Close(); err != nil {
		b.Fatal(err)
	}

	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, TraceStore: ts, DisableRenewalScheduler: true})
	if err != nil {
		b.Fatal(err)
	}
	handler := srv.Handler()
	login := httptest.NewRequest(http.MethodPost, "/api/login",
		strings.NewReader(`{"username":"admin","password":"`+testAdminPass+`"}`))
	login.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	handler.ServeHTTP(loginRec, login)
	if loginRec.Code != http.StatusOK {
		b.Fatalf("login: %d", loginRec.Code)
	}
	cookies := loginRec.Result().Cookies()
	for _, groupBy := range []string{"node", "user", "reason"} {
		b.Run(groupBy, func(b *testing.B) {
			target := fmt.Sprintf("/api/trace/rollups?group_by=%s&since=%s&until=%s", groupBy,
				end.Add(-90*24*time.Hour).Format(time.RFC3339), end.Format(time.RFC3339))
			for b.Loop() {
				req := httptest.NewRequest(http.MethodGet, target, nil)
				for _, c := range cookies {
					req.AddCookie(c)
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					b.Fatalf("%d %s", rec.Code, rec.Body.String())
				}
				b.SetBytes(int64(rec.Body.Len()))
				_, _ = io.Copy(io.Discard, rec.Body)
			}
		})
	}
}
