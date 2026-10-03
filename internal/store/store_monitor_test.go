package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
	bolt "go.etcd.io/bbolt"
)

// Without the hot store: the JSON fallback keeps the old write throttle.

func TestAddMonitorResultThrottlesStableResultPersistence(t *testing.T) {
	path := t.TempDir() + "/state.json"
	s, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}

	first := model.MonitorResult{MonitorID: "mon-a", NodeID: "node-a", At: time.Unix(100, 0).UTC(), Success: true, LatencyMs: 12}
	if _, err := s.AddMonitorResult(first); err != nil {
		t.Fatalf("first monitor result: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	second := model.MonitorResult{MonitorID: "mon-a", NodeID: "node-a", At: time.Unix(110, 0).UTC(), Success: true, LatencyMs: 15}
	if _, err := s.AddMonitorResult(second); err != nil {
		t.Fatalf("second monitor result: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("stable monitor result rewrote persisted state")
	}
	latest, ok, err := s.MonitorLatest("mon-a", "node-a")
	if err != nil || !ok {
		t.Fatalf("missing latest in-memory monitor result: ok=%v err=%v", ok, err)
	}
	if !latest.At.Equal(second.At) || latest.LatencyMs != second.LatencyMs {
		t.Fatalf("in-memory monitor result not refreshed: %+v", latest)
	}
}

func TestAddMonitorResultPersistsStateTransitionImmediately(t *testing.T) {
	path := t.TempDir() + "/state.json"
	s, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddMonitorResult(model.MonitorResult{MonitorID: "mon-a", NodeID: "node-a", At: time.Unix(100, 0).UTC(), Success: true, LatencyMs: 12}); err != nil {
		t.Fatalf("first monitor result: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	failed := model.MonitorResult{MonitorID: "mon-a", NodeID: "node-a", At: time.Unix(110, 0).UTC(), Success: false, Error: "timeout"}
	if _, err := s.AddMonitorResult(failed); err != nil {
		t.Fatalf("transition monitor result: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) == string(before) {
		t.Fatalf("monitor result transition was not persisted")
	}
	reopened, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	latest, ok, err := reopened.MonitorLatest("mon-a", "node-a")
	if err != nil || !ok {
		t.Fatalf("missing durable monitor result after reopen: ok=%v err=%v", ok, err)
	}
	if latest.Success || latest.Error != "timeout" || latest.FailStreak != 1 {
		t.Fatalf("transition result not durable: %+v", latest)
	}
}

func TestAddMonitorResultPersistsPeriodicStableSnapshot(t *testing.T) {
	path := t.TempDir() + "/state.json"
	s, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	first := model.MonitorResult{MonitorID: "mon-a", NodeID: "node-a", At: time.Unix(100, 0).UTC(), Success: true, LatencyMs: 12}
	if _, err := s.AddMonitorResult(first); err != nil {
		t.Fatalf("first monitor result: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	key := monitorResultPersistenceKey("mon-a", "node-a")
	s.monitorPersistedAt[key] = time.Now().UTC().Add(-monitorResultPersistenceInterval - time.Second)
	second := model.MonitorResult{MonitorID: "mon-a", NodeID: "node-a", At: time.Unix(200, 0).UTC(), Success: true, LatencyMs: 15}
	if _, err := s.AddMonitorResult(second); err != nil {
		t.Fatalf("periodic monitor result: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) == string(before) {
		t.Fatalf("periodic stable monitor result was not persisted")
	}
	reopened, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	latest, ok, err := reopened.MonitorLatest("mon-a", "node-a")
	if err != nil || !ok {
		t.Fatalf("missing durable monitor result after reopen: ok=%v err=%v", ok, err)
	}
	if !latest.At.Equal(second.At) || latest.LatencyMs != second.LatencyMs {
		t.Fatalf("periodic monitor result not durable: %+v", latest)
	}
}

// The second failure in a row is where monitor.down pages, so the JSON
// fallback writes it at once even though the error text did not change.
func TestJSONMonitorSecondFailureIsWrittenAtOnce(t *testing.T) {
	path := t.TempDir() + "/state.json"
	s, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	add := func(sec int64, ok bool) MonitorResultOutcome {
		t.Helper()
		out, err := s.AddMonitorResult(model.MonitorResult{MonitorID: "mon-a", NodeID: "node-a", At: time.Unix(sec, 0).UTC(), Success: ok, Error: map[bool]string{false: "refused"}[ok]})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	add(100, true)
	add(110, false)
	calls := s.testPersistCalls
	out := add(120, false)
	if out.PriorFailStreak != 1 || s.testPersistCalls != calls+1 {
		t.Fatalf("second failure: prior=%d writes=%d", out.PriorFailStreak, s.testPersistCalls-calls)
	}
	calls = s.testPersistCalls
	if out := add(130, false); out.PriorFailStreak != 2 || s.testPersistCalls != calls {
		t.Fatalf("third identical failure wrote the state file: prior=%d writes=%d", out.PriorFailStreak, s.testPersistCalls-calls)
	}
}

// Each pair keeps its own bound without the hot store too, and one pair's
// volume never evicts another's history.
func TestJSONMonitorHistoryIsBoundedPerPair(t *testing.T) {
	s, err := OpenWithCipher(t.TempDir()+"/state.json", secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_000, 0).UTC()
	if _, err := s.AddMonitorResult(model.MonitorResult{MonitorID: "mon-a", NodeID: "quiet", At: base, Success: true}); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= monitorResultsPerPairJSON+10; i++ {
		if _, err := s.AddMonitorResult(model.MonitorResult{MonitorID: "mon-a", NodeID: "busy", At: base.Add(time.Duration(i) * time.Second), Success: true}); err != nil {
			t.Fatal(err)
		}
	}
	busy, _ := s.MonitorPairResults("mon-a", "busy", 0)
	quiet, _ := s.MonitorPairResults("mon-a", "quiet", 0)
	if len(busy) != monitorResultsPerPairJSON || len(quiet) != 1 {
		t.Fatalf("busy=%d quiet=%d, want %d and 1", len(busy), len(quiet), monitorResultsPerPairJSON)
	}
	if !busy[0].At.Equal(base.Add(11 * time.Second)) {
		t.Fatalf("oldest busy row kept is %s, want the 11th", busy[0].At)
	}
}

// With the hot store: the production layout.

func openHotStore(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := OpenWithCipher(filepath.Join(dir, "state.json"), secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnableRuntimeBoltHotStore(filepath.Join(dir, "state-hot.db")); err != nil {
		t.Fatal(err)
	}
	return s
}

func seedMonitor(t *testing.T, s *Store, m model.Monitor) {
	t.Helper()
	m.Enabled = true
	if err := s.UpsertMonitor(m); err != nil {
		t.Fatal(err)
	}
}

// A fleet-wide monitor's results never touch the JSON state: not on a flip,
// not on the second failure, not after five minutes.
func TestHotMonitorResultsNeverWriteTheStateFile(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, AssignAll: true})
	base := time.Now().UTC().Add(-time.Hour)
	calls := s.testPersistCalls
	for round := 0; round < 12; round++ {
		batch := make([]model.MonitorResult, 0, 34)
		for n := 0; n < 34; n++ {
			// Node 0 flaps every round; node 1 goes down for good at round 4.
			ok := !(n == 0 && round%2 == 1) && !(n == 1 && round >= 4)
			batch = append(batch, model.MonitorResult{MonitorID: "mon-a", At: base.Add(time.Duration(round) * 30 * time.Second), Success: ok, Error: map[bool]string{false: "refused"}[ok]})
		}
		for n, r := range batch {
			if _, err := s.IngestAgentMonitorResults(fmt.Sprintf("node-%02d", n), []model.MonitorResult{r}, base.Add(time.Duration(round)*30*time.Second+time.Second)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if got := s.testPersistCalls - calls; got != 0 {
		t.Fatalf("408 results wrote the state file %d times, want 0", got)
	}
	latest, err := s.LatestMonitorResults()
	if err != nil {
		t.Fatal(err)
	}
	if len(latest["mon-a"]) != 34 {
		t.Fatalf("latest pairs = %d, want 34", len(latest["mon-a"]))
	}
	down := latest["mon-a"][1]
	if down.NodeID != "node-01" || down.Success || down.FailStreak != 8 || !down.Since.Equal(base.Add(4*30*time.Second)) || down.Held != 12 {
		t.Fatalf("node-01 latest = %+v", down)
	}
	if data, err := os.ReadFile(s.path); err != nil || strings.Contains(string(data), "node-01") && strings.Contains(string(data), `"success"`) {
		t.Fatalf("state file carries monitor rows (err=%v)", err)
	}
}

// The agent may only write results for monitors it was given, for its own
// node, inside the time window; what it sends is normalized before storage.
func TestAgentMonitorResultAdmission(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	seedMonitor(t, s, model.Monitor{ID: "mon-all", Type: model.MonitorTypeHTTP, AssignAll: true})
	seedMonitor(t, s, model.Monitor{ID: "mon-b", Type: model.MonitorTypeTCP, NodeIDs: []string{"node-b"}})
	seedMonitor(t, s, model.Monitor{ID: "mon-tls", Type: model.MonitorTypeTLS})
	if err := s.UpsertMonitor(model.Monitor{ID: "mon-off", Type: model.MonitorTypeTCP, AssignAll: true}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	long := strings.Repeat("é", monitorResultErrorMax)
	results := []model.MonitorResult{
		{MonitorID: "mon-all", NodeID: "someone-else", At: now.Add(-time.Minute), Success: false, Error: long, CertNotAfter: now},
		{MonitorID: "mon-b", At: now, Success: true},
		{MonitorID: "mon-tls", At: now, Success: true},
		{MonitorID: "mon-off", At: now, Success: true},
		{MonitorID: "nope", At: now, Success: true},
		{MonitorID: "", At: now, Success: true},
		{MonitorID: "mon-all", At: now.Add(-MonitorResultMaxAge - time.Second), Success: true},
		{MonitorID: "mon-all", At: now.Add(MonitorResultMaxSkew + time.Nanosecond), Success: true},
		{MonitorID: "mon-all", Success: true},
		{MonitorID: "mon-all", At: now.Add(MonitorResultMaxSkew), Success: true},
		{MonitorID: "mon-all", At: now.Add(-MonitorResultMaxAge), Success: true},
	}
	out, err := s.IngestAgentMonitorResults("node-a", results, now)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"", MonitorResultDropNotAssigned, MonitorResultDropServerEvaluated, MonitorResultDropDisabled, MonitorResultDropUnknownMonitor, MonitorResultDropUnknownMonitor, MonitorResultDropOutOfWindow, MonitorResultDropOutOfWindow, MonitorResultDropInvalid, "", ""}
	for i, reason := range want {
		if out[i].Dropped != reason {
			t.Errorf("result %d: dropped %q, want %q", i, out[i].Dropped, reason)
		}
	}
	first := out[0].Result
	if first.NodeID != "node-a" || !first.CertNotAfter.IsZero() || len(first.Error) > monitorResultErrorMax || !strings.HasPrefix(long, first.Error) || first.ReceivedAt != now {
		t.Fatalf("first result not normalized: node=%q cert=%s errlen=%d received=%s", first.NodeID, first.CertNotAfter, len(first.Error), first.ReceivedAt)
	}
	// The window's edges are inside it, and an admitted result keeps the
	// stamp the agent gave it.
	if !out[9].Result.At.Equal(now.Add(MonitorResultMaxSkew)) || !out[10].Result.At.Equal(now.Add(-MonitorResultMaxAge)) || !out[9].Stored() || !out[10].Stored() {
		t.Fatalf("results on the window's edges: %+v %+v", out[9], out[10])
	}
	rows, err := s.MonitorPairResults("mon-all", "node-a", 0)
	if err != nil || len(rows) != 3 {
		t.Fatalf("stored rows = %d (err=%v), want 3", len(rows), err)
	}
	if other, _ := s.MonitorPairResults("mon-all", "someone-else", 0); len(other) != 0 {
		t.Fatalf("an agent wrote rows for another node: %+v", other)
	}
}

// A batch sent again after a lost response stores nothing new and moves no
// streak, so the alert hold never counts one failure twice.
func TestRetriedBatchIsADuplicate(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, AssignAll: true})
	now := time.Now().UTC()
	batch := []model.MonitorResult{
		{MonitorID: "mon-a", At: now.Add(-20 * time.Second), Success: true},
		{MonitorID: "mon-a", At: now.Add(-10 * time.Second), Success: false, Error: "refused"},
		{MonitorID: "mon-a", At: now, Success: false, Error: "refused"},
	}
	first, err := s.IngestAgentMonitorResults("node-a", batch, now)
	if err != nil {
		t.Fatal(err)
	}
	if first[1].PriorFailStreak != 0 || first[2].PriorFailStreak != 1 || !first[2].Stored() {
		t.Fatalf("first attempt: %+v", first)
	}
	again, err := s.IngestAgentMonitorResults("node-a", batch, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for i, out := range again {
		if !out.Duplicate || out.Stored() {
			t.Fatalf("retry %d not a duplicate: %+v", i, out)
		}
	}
	latest, _, _ := s.MonitorLatest("mon-a", "node-a")
	if latest.FailStreak != 2 || latest.Held != 3 {
		t.Fatalf("retry moved the pair: %+v", latest)
	}
}

// A result the server would have had to stamp itself is dropped, on the
// first attempt and on every retry, so a batch sent again after a lost
// response never stores it twice or counts one failure as two. Before, a
// missing or future stamp took the arrival time, which differs on every
// attempt, so each retry became a new row and advanced the streak.
func TestResultsWithoutAUsableStampStayDroppedOnRetry(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, AssignAll: true})
	now := time.Now().UTC()
	batch := []model.MonitorResult{
		{MonitorID: "mon-a", At: now.Add(-10 * time.Second), Success: true},
		{MonitorID: "mon-a", Success: false, Error: "refused"},
		{MonitorID: "mon-a", At: now.Add(time.Hour), Success: false, Error: "refused"},
	}
	for attempt := range 3 {
		out, err := s.IngestAgentMonitorResults("node-a", batch, now.Add(time.Duration(attempt)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if out[1].Dropped != MonitorResultDropInvalid || out[2].Dropped != MonitorResultDropOutOfWindow {
			t.Fatalf("attempt %d: unusable stamps admitted: %+v", attempt, out)
		}
		if first := out[0]; first.Stored() != (attempt == 0) || first.Duplicate != (attempt > 0) {
			t.Fatalf("attempt %d: stamped result: %+v", attempt, first)
		}
	}
	latest, ok, err := s.MonitorLatest("mon-a", "node-a")
	if err != nil || !ok || latest.FailStreak != 0 || latest.Held != 1 || !latest.Success {
		t.Fatalf("pair after three attempts: %+v (ok=%v err=%v)", latest, ok, err)
	}
}

// Rows and latest records survive a restart, and the store still never
// carries them in the JSON state.
func TestHotMonitorResultsSurviveReopen(t *testing.T) {
	dir := t.TempDir()
	s := openHotStore(t, dir)
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, AssignAll: true})
	now := time.Now().UTC()
	if _, err := s.IngestAgentMonitorResults("node-a", []model.MonitorResult{
		{MonitorID: "mon-a", At: now.Add(-time.Second), Success: false, Error: "refused"},
		{MonitorID: "mon-a", At: now, Success: false, Error: "refused"},
	}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openHotStore(t, dir)
	defer s.Close()
	latest, ok, err := s.MonitorLatest("mon-a", "node-a")
	if err != nil || !ok || latest.FailStreak != 2 || latest.Held != 2 {
		t.Fatalf("latest after reopen: ok=%v err=%v %+v", ok, err, latest)
	}
	if len(s.state.MonResults) != 0 {
		t.Fatalf("reopen held monitor rows in the JSON state: %+v", s.state.MonResults)
	}
}

// legacyMonitorState writes a state file the way a104 left it: results in
// the JSON state, 500 per monitor across nodes, no hot store yet.
func legacyMonitorState(t *testing.T, dir string, base time.Time) {
	t.Helper()
	s, err := OpenWithCipher(filepath.Join(dir, "state.json"), secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, AssignAll: true})
	seedMonitor(t, s, model.Monitor{ID: "mon-b", Type: model.MonitorTypeTCP, AssignAll: true})
	series := []MonitorResultRecord{}
	for i := 0; i < 6; i++ {
		ok := i < 3 // node-a: three successes, then three failures
		series = append(series, MonitorResultRecord{MonitorResult: model.MonitorResult{MonitorID: "mon-a", NodeID: "node-a", At: base.Add(time.Duration(i) * 30 * time.Second), Success: ok}})
		series = append(series, MonitorResultRecord{MonitorResult: model.MonitorResult{MonitorID: "mon-a", NodeID: "node-b", At: base.Add(time.Duration(i) * 30 * time.Second), Success: true, LatencyMs: float64(i)}})
	}
	s.state.MonResults["mon-a"] = series
	s.state.MonResults["mon-b"] = []MonitorResultRecord{{MonitorResult: model.MonitorResult{MonitorID: "mon-b", NodeID: "node-a", At: base, Success: true}}}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
}

// Turning the hot store on moves an existing history across, rebuilds each
// pair's streak from it, and drops the JSON copy.
func TestEnablingTheHotStoreMigratesMonitorResults(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	legacyMonitorState(t, dir, base)

	s := openHotStore(t, dir)
	latestA, ok, err := s.MonitorLatest("mon-a", "node-a")
	if err != nil || !ok {
		t.Fatalf("migrated latest: ok=%v err=%v", ok, err)
	}
	if latestA.FailStreak != 3 || !latestA.Since.Equal(base.Add(90*time.Second)) || latestA.Held != 6 {
		t.Fatalf("streak not rebuilt from history: %+v", latestA)
	}
	rowsB, err := s.MonitorPairResults("mon-a", "node-b", 0)
	if err != nil || len(rowsB) != 6 || rowsB[5].LatencyMs != 5 {
		t.Fatalf("node-b rows: %+v err=%v", rowsB, err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var onDisk struct {
		MonResults map[string][]json.RawMessage `json:"monitor_results"`
	}
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatal(err)
	}
	if len(onDisk.MonResults) != 0 {
		t.Fatalf("state.json still carries monitor results after the move: %d monitors", len(onDisk.MonResults))
	}

	// Deleted after the move, then restarted: the flag keeps the stale copy
	// (if any write had been lost) from coming back.
	if err := s.DeleteMonitor("mon-b"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openHotStore(t, dir)
	defer s.Close()
	if rows, _ := s.RecentMonitorResults("mon-b", 0, nil); len(rows) != 0 {
		t.Fatalf("deleted monitor's results came back: %+v", rows)
	}
	if latest, _, _ := s.MonitorLatest("mon-a", "node-a"); latest.FailStreak != 3 {
		t.Fatalf("second open re-imported or lost history: %+v", latest)
	}
}

// The migration runs once even if the JSON file still has its copy, which is
// what a crash between the bolt write and the state write leaves.
func TestMonitorResultMigrationRunsOnce(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	legacyMonitorState(t, dir, base)
	stale, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := openHotStore(t, dir)
	if err := s.DeleteMonitor("mon-b"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Put the pre-migration file back, as if no state write had landed.
	if err := os.WriteFile(filepath.Join(dir, "state.json"), stale, 0o600); err != nil {
		t.Fatal(err)
	}
	s = openHotStore(t, dir)
	defer s.Close()
	if rows, _ := s.MonitorPairResults("mon-b", "node-a", 0); len(rows) != 0 {
		t.Fatalf("a second migration resurrected deleted rows: %+v", rows)
	}
	if latest, _, _ := s.MonitorLatest("mon-a", "node-a"); latest.Held != 6 {
		t.Fatalf("a second migration duplicated or lost rows: %+v", latest)
	}
}

// Each pair holds MonitorResultsPerPair rows in the hot store.
func TestHotMonitorHistoryIsBoundedPerPair(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, AssignAll: true})
	now := time.Now().UTC()
	start := now.Add(-time.Duration(MonitorResultsPerPair+20) * time.Second)
	total := MonitorResultsPerPair + 20
	for sent := 0; sent < total; {
		batch := []model.MonitorResult{}
		for len(batch) < 500 && sent < total {
			batch = append(batch, model.MonitorResult{MonitorID: "mon-a", At: start.Add(time.Duration(sent) * time.Second), Success: true, LatencyMs: float64(sent)})
			sent++
		}
		if _, err := s.IngestAgentMonitorResults("node-a", batch, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.IngestAgentMonitorResults("node-b", []model.MonitorResult{{MonitorID: "mon-a", At: start, Success: true}}, now); err != nil {
		t.Fatal(err)
	}
	rows, err := s.MonitorPairResults("mon-a", "node-a", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != MonitorResultsPerPair || rows[0].LatencyMs != 20 || rows[len(rows)-1].LatencyMs != float64(total-1) {
		t.Fatalf("pair rows = %d first=%v last=%v", len(rows), rows[0].LatencyMs, rows[len(rows)-1].LatencyMs)
	}
	latest, _, _ := s.MonitorLatest("mon-a", "node-a")
	if latest.Held != MonitorResultsPerPair {
		t.Fatalf("held = %d", latest.Held)
	}
	if b, _ := s.MonitorPairResults("mon-a", "node-b", 0); len(b) != 1 {
		t.Fatalf("node-b lost its row to node-a's volume: %d", len(b))
	}
	if limited, _ := s.MonitorPairResults("mon-a", "node-a", 10); len(limited) != 10 || limited[9].LatencyMs != float64(total-1) {
		t.Fatalf("limit returns the newest rows oldest first: %+v", limited)
	}
}

// A drifted Held never deletes the row just written: the rows present decide.
func TestTrimTrustsRowsOverADriftedCount(t *testing.T) {
	bs, err := OpenBoltState(filepath.Join(t.TempDir(), "hot.db"), secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()
	base := time.Unix(1_000, 0).UTC()
	for i := 0; i < 3; i++ {
		if _, err := bs.RecordMonitorResults([]MonitorResultRecord{{MonitorResult: model.MonitorResult{MonitorID: "m", NodeID: "n", At: base.Add(time.Duration(i) * time.Second), Success: true}}}, 10); err != nil {
			t.Fatal(err)
		}
	}
	// Claim far more rows than the pair holds.
	if err := bs.db.Update(func(tx *bolt.Tx) error {
		var latest MonitorLatest
		if _, err := getRecord(tx, boltBucketMonResultLatest, "m/n", &latest); err != nil {
			return err
		}
		latest.Held = 40
		return putRecord(tx, boltBucketMonResultLatest, "m/n", latest)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := bs.RecordMonitorResults([]MonitorResultRecord{{MonitorResult: model.MonitorResult{MonitorID: "m", NodeID: "n", At: base.Add(10 * time.Second), Success: true}}}, 10); err != nil {
		t.Fatal(err)
	}
	rows, _ := bs.MonitorPairResults("m", "n", 0)
	latest, _, _ := bs.MonitorLatest("m", "n")
	if len(rows) != 4 || latest.Held != 4 {
		t.Fatalf("drifted count deleted rows: rows=%d held=%d", len(rows), latest.Held)
	}
}

// The cross-pair read merges newest first and stops at the limit, honoring
// the caller's node filter.
func TestRecentMonitorResultsMergesPairsNewestFirst(t *testing.T) {
	for _, hot := range []bool{false, true} {
		t.Run(map[bool]string{false: "json", true: "hot"}[hot], func(t *testing.T) {
			var s *Store
			if hot {
				s = openHotStore(t, t.TempDir())
			} else {
				var err error
				if s, err = OpenWithCipher(t.TempDir()+"/state.json", secret.Disabled()); err != nil {
					t.Fatal(err)
				}
			}
			defer s.Close()
			base := time.Unix(10_000, 0).UTC()
			for i := 0; i < 9; i++ {
				node := []string{"a", "b", "c"}[i%3]
				if _, err := s.AddMonitorResult(model.MonitorResult{MonitorID: "mon", NodeID: node, At: base.Add(time.Duration(i) * time.Second), LatencyMs: float64(i), Success: true}); err != nil {
					t.Fatal(err)
				}
			}
			got, err := s.RecentMonitorResults("mon", 4, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 4 || got[0].LatencyMs != 5 || got[3].LatencyMs != 8 {
				t.Fatalf("newest four across pairs: %+v", got)
			}
			only, err := s.RecentMonitorResults("mon", 0, func(node string) bool { return node == "b" })
			if err != nil {
				t.Fatal(err)
			}
			if len(only) != 3 || only[0].LatencyMs != 1 || only[2].LatencyMs != 7 {
				t.Fatalf("filtered read: %+v", only)
			}
		})
	}
}

// Deleting a node removes its pairs from the hot store and counts them; the
// other node's pairs stay.
func TestDeleteNodeRemovesItsHotMonitorRows(t *testing.T) {
	s := openHotStore(t, t.TempDir())
	defer s.Close()
	for _, id := range []string{"node-a", "node-b"} {
		if err := s.UpsertNode(model.Node{ID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
	}
	seedMonitor(t, s, model.Monitor{ID: "mon-a", Type: model.MonitorTypeTCP, AssignAll: true})
	now := time.Now().UTC()
	for _, node := range []string{"node-a", "node-b"} {
		if _, err := s.IngestAgentMonitorResults(node, []model.MonitorResult{
			{MonitorID: "mon-a", At: now.Add(-time.Second), Success: false},
			{MonitorID: "mon-a", At: now, Success: false},
		}, now); err != nil {
			t.Fatal(err)
		}
	}
	plan, ok := s.PlanDeleteNode("node-a")
	if !ok || plan.MonitorResults != 2 {
		t.Fatalf("plan counts %d monitor rows, want 2", plan.MonitorResults)
	}
	report, ok, err := s.DeleteNode("node-a")
	if err != nil || !ok || report.MonitorResults != 2 {
		t.Fatalf("delete: ok=%v err=%v report=%d", ok, err, report.MonitorResults)
	}
	if _, ok, _ := s.MonitorLatest("mon-a", "node-a"); ok {
		t.Fatal("deleted node kept its streak")
	}
	if rows, _ := s.MonitorPairResults("mon-a", "node-a", 0); len(rows) != 0 {
		t.Fatalf("deleted node kept rows: %d", len(rows))
	}
	if latest, ok, _ := s.MonitorLatest("mon-a", "node-b"); !ok || latest.FailStreak != 2 {
		t.Fatalf("other node's pair: ok=%v %+v", ok, latest)
	}
}

// The full-state export carries rows back to the JSON shape, including a
// state.db written before the rows existed.
func TestFullExportReadsRowsAndTheLegacyBucket(t *testing.T) {
	bs, err := OpenBoltState(filepath.Join(t.TempDir(), "state.db"), secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()
	at := time.Unix(5_000, 0).UTC()
	if _, err := bs.RecordMonitorResults([]MonitorResultRecord{{MonitorResult: model.MonitorResult{MonitorID: "m-new", NodeID: "n1", At: at, Success: true, LatencyMs: 3}}}, MonitorResultsPerPair); err != nil {
		t.Fatal(err)
	}
	if err := bs.db.Update(func(tx *bolt.Tx) error {
		return putRecord(tx, boltBucketMonResults, "m-old", []model.MonitorResult{{MonitorID: "m-old", NodeID: "n1", At: at, Success: false, Error: "refused"}})
	}); err != nil {
		t.Fatal(err)
	}
	st, err := bs.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.MonResults["m-new"]) != 1 || st.MonResults["m-new"][0].LatencyMs != 3 || st.MonResults["m-new"][0].NodeID != "n1" {
		t.Fatalf("rows not exported: %+v", st.MonResults["m-new"])
	}
	if len(st.MonResults["m-old"]) != 1 || st.MonResults["m-old"][0].Error != "refused" {
		t.Fatalf("legacy bucket not exported: %+v", st.MonResults["m-old"])
	}
	hot, err := bs.ExportStateWithoutAudit()
	if err != nil {
		t.Fatal(err)
	}
	if len(hot.MonResults) != 0 {
		t.Fatalf("the hot export read monitor rows: %+v", hot.MonResults)
	}
}
