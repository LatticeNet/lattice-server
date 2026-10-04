package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/LatticeNet/lattice-server/internal/metricsdb"
)

func noEnv(string) (string, bool) { return "", false }

// futureSchemaMetricsDB writes a metrics.db that a newer release left behind:
// what a rollback finds.
func futureSchemaMetricsDB(t *testing.T, path string) {
	t.Helper()
	db, err := metricsdb.Open(path, metricsdb.Options{})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	bdb, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()
	if err := bdb.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("meta")).Put([]byte("schema"), binary.BigEndian.AppendUint32(nil, 99))
	}); err != nil {
		t.Fatal(err)
	}
}

// TestOpenSelfMonitorSurvivesAnUnusableFile: a metrics.db from a newer schema
// or full of garbage must not keep the control plane from starting. It is
// moved aside, a fresh history starts, and the log says so.
func TestOpenSelfMonitorSurvivesAnUnusableFile(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for name, spoil := range map[string]func(t *testing.T, path string){
		"future schema": futureSchemaMetricsDB,
		"garbage": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte(strings.Repeat("x", 1<<16)), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			spoil(t, filepath.Join(dir, "metrics.db"))
			var logs []string
			logf := func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
			opts, closeFn, err := openSelfMonitor(dir, filepath.Join(dir, "state.json"), "", noEnv, now, logf)
			if err != nil {
				t.Fatal(err)
			}
			defer closeFn()
			if opts.DB == nil || opts.Unavailable != "" {
				t.Fatalf("options = %+v, want a fresh store", opts)
			}
			aside := filepath.Join(dir, fmt.Sprintf("metrics.db.unreadable-%d", now.Unix()))
			if _, err := os.Stat(aside); err != nil {
				t.Fatalf("the unusable file was not moved aside: %v", err)
			}
			if joined := strings.Join(logs, "\n"); !strings.Contains(joined, "moved it to "+aside) {
				t.Fatalf("log does not say where the old file went:\n%s", joined)
			}
		})
	}
}

// TestOpenSelfMonitorRunsWithoutHistoryWhenItCannotRecover: when the file
// cannot even be moved aside, the server still starts, keeps no history,
// and the System page is told why.
func TestOpenSelfMonitorRunsWithoutHistoryWhenItCannotRecover(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory's permissions")
	}
	dir := t.TempDir()
	futureSchemaMetricsDB(t, filepath.Join(dir, "metrics.db"))
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	opts, closeFn, err := openSelfMonitor(dir, filepath.Join(dir, "state.json"), "", noEnv, time.Now(), func(string, ...any) {})
	if err != nil {
		t.Fatalf("openSelfMonitor = %v, want the server to start without history", err)
	}
	defer closeFn()
	if opts.DB != nil || !strings.Contains(opts.Unavailable, "metrics.db could not be opened") {
		t.Fatalf("options = %+v, want no store and the reason", opts)
	}
}

func TestOpenSelfMonitorRejectsAMalformedSeriesCap(t *testing.T) {
	dir := t.TempDir()
	env := func(key string) (string, bool) {
		if key == "LATTICE_METRICS_MAX_SERIES" {
			return "lots", true
		}
		return "", false
	}
	if _, closeFn, err := openSelfMonitor(dir, filepath.Join(dir, "state.json"), "", env, time.Now(), func(string, ...any) {}); err == nil {
		closeFn()
		t.Fatal("a malformed LATTICE_METRICS_MAX_SERIES was accepted")
	}
}
