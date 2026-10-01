package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/ratelimit"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// ingestFixture is a server over the production storage layout: a JSON state
// file with the record-level bolt sidecar enabled, so audit appends and proxy
// usage go to bolt and the state file is rewritten only by JSON-domain writes.
type ingestFixture struct {
	dir     string
	srv     *Server
	handler http.Handler
	st      *store.Store
}

func (f ingestFixture) statePath() string { return filepath.Join(f.dir, "state.json") }

func openIngestFixture(t *testing.T, dir string) ingestFixture {
	t.Helper()
	st, err := store.OpenWithCipher(filepath.Join(dir, "state.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnableRuntimeBoltHotStore(filepath.Join(dir, "state-hot.db")); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	// A whole report cycle many times over in a few milliseconds is far past
	// the per-IP agent budget; the budget is not what these tests measure.
	srv.agentLimiter = ratelimit.New(ratelimit.Config{Rate: 1e6, Burst: 1e6})
	return ingestFixture{dir: dir, srv: srv, handler: srv.Handler(), st: st}
}

// stateFileWrites counts rewrites of the state file. Every write goes through
// a temp file and a rename, so a rewrite always changes the file's identity.
type stateFileWrites struct {
	t    *testing.T
	path string
	last os.FileInfo
	n    int
}

func watchStateFile(t *testing.T, path string) *stateFileWrites {
	t.Helper()
	w := &stateFileWrites{t: t, path: path}
	w.last = w.stat()
	return w
}

func (w *stateFileWrites) stat() os.FileInfo {
	w.t.Helper()
	info, err := os.Stat(w.path)
	if err != nil {
		w.t.Fatal(err)
	}
	return info
}

// check records whether the file was rewritten since the previous check.
func (w *stateFileWrites) check() bool {
	w.t.Helper()
	info := w.stat()
	rewritten := !os.SameFile(w.last, info) || !info.ModTime().Equal(w.last.ModTime()) || info.Size() != w.last.Size()
	if rewritten {
		w.n++
	}
	w.last = info
	return rewritten
}

// take returns the rewrites counted since the previous take.
func (w *stateFileWrites) take() int {
	w.check()
	n := w.n
	w.n = 0
	return n
}

// TestSteadyAgentReportsDoNotRewriteState drives one agent's report cycle the
// way a healthy node sends it every ten seconds: the same facts with fresh
// clocks. After the first cycle, which may write what is new, repeated cycles
// must leave the state file alone. Production rewrote a 16 MB state file every
// half second on a 34-node fleet because singbox-inventory (liveness) and
// guard-reality persisted the whole state on every report.
func TestSteadyAgentReportsDoNotRewriteState(t *testing.T) {
	f := openIngestFixture(t, t.TempDir())
	defer f.st.Close()
	cookies, csrf := loginSession(t, f.handler)
	token := enrollNamedNodeToken(t, f.handler, cookies, csrf, "node-a", "Node A")
	if err := f.st.UpsertMonitor(model.Monitor{ID: "mon-1", Name: "web", Type: "http", Target: "https://example.test", IntervalSec: 30, AssignAll: true, Enabled: true}); err != nil {
		t.Fatal(err)
	}

	send := func(method, path, body string) {
		t.Helper()
		rec := doAgentRaw(t, f.handler, method, path, body, token)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %s: want 200, got %d (%s)", method, path, rec.Code, rec.Body.String())
		}
	}
	stamp := func(at time.Time) string { return at.Format(time.RFC3339Nano) }
	routes := []struct {
		name   string
		report func(at time.Time)
	}{
		{"config", func(time.Time) { send(http.MethodGet, "/api/agent/config?node_id=node-a", "") }},
		{"metrics", func(at time.Time) {
			send(http.MethodPost, "/api/agent/metrics", fmt.Sprintf(`{"node_id":"node-a","version":"0.9.0","metrics":{"cpu_percent":3.5,"collected_at":%q}}`, stamp(at)))
		}},
		{"proxy-usage", func(at time.Time) {
			send(http.MethodPost, "/api/agent/proxy-usage", fmt.Sprintf(`{"node_id":"node-a","snapshot":{"at":%q,"core_uptime_sec":100,"user_bytes":{},"collector_source":"singbox-stats","collector_status":"ok","collector_checked_at":%q}}`, stamp(at), stamp(at)))
		}},
		{"singbox-inventory", func(at time.Time) {
			send(http.MethodPost, "/api/agent/singbox-inventory", fmt.Sprintf(`{"node_id":"node-a","inventory":{"status":"ok","core_version":"1.12.12","nodes":[{"name":"VLESS-REALITY-17891.json","protocol":"vless","port":"17891"}],"runtime":{"running":true,"pid":4242,"active_state":"active","sub_state":"running","restart_count":3,"probed_at":%q}}}`, stamp(at)))
		}},
		{"tasks", func(time.Time) { send(http.MethodGet, "/api/agent/tasks?node_id=node-a", "") }},
		{"monitors", func(time.Time) { send(http.MethodGet, "/api/agent/monitors?node_id=node-a", "") }},
		{"monitor-result", func(at time.Time) {
			send(http.MethodPost, "/api/agent/monitor-result", fmt.Sprintf(`{"node_id":"node-a","result":{"monitor_id":"mon-1","at":%q,"success":true,"latency_ms":12}}`, stamp(at)))
		}},
		{"log-sources", func(time.Time) { send(http.MethodGet, "/api/agent/log-sources?node_id=node-a", "") }},
		{"trace-config", func(time.Time) { send(http.MethodGet, "/api/agent/trace-config?node_id=node-a", "") }},
		{"terminal-sessions", func(time.Time) { send(http.MethodGet, "/api/agent/terminal/sessions?node_id=node-a", "") }},
		{"guard-reality", func(at time.Time) {
			send(http.MethodPost, "/api/agent/guard-reality", fmt.Sprintf(`{"node_id":"node-a","reality":{"listeners":[{"protocol":"tcp","port":22,"process":"sshd"}],"interfaces":[{"name":"eth0","addresses":["10.0.0.5/24"],"up":true}],"nft_version":"1.0.9","sshd":{"password_authentication":false,"pubkey_authentication":true,"permit_root_login":"prohibit-password","ports":[22],"observed_at":%q},"collected_at":%q}}`, stamp(at), stamp(at)))
		}},
	}

	base := time.Now().UTC().Truncate(time.Second)
	send(http.MethodPost, "/api/agent/hello", `{"node_id":"node-a","version":"0.9.0"}`)
	for _, route := range routes {
		route.report(base)
	}

	writes := watchStateFile(t, f.statePath())
	const cycles = 30
	for _, route := range routes {
		for i := 1; i <= cycles; i++ {
			route.report(base.Add(time.Duration(i) * 10 * time.Second))
			writes.check()
		}
		if n := writes.take(); n != 0 {
			t.Errorf("%s: %d steady reports rewrote the state file %d times, want 0", route.name, cycles, n)
		}
	}
}

// TestSingBoxLivenessWritesOnlyTransitionsAndSurvivesRestart walks one
// incident through the inventory route on the production storage layout: a
// steady stream of identical reports writes nothing, every transition and the
// notification bookkeeping are written at once, the down notice fires once
// after serviceDownHold, and a restarted server resumes the episode from disk
// without notifying it again. Both restarts are covered: a clean shutdown,
// which flushes clocks still held in memory, and a crash, which resumes from
// whatever the last write left.
func TestSingBoxLivenessWritesOnlyTransitionsAndSurvivesRestart(t *testing.T) {
	for _, crash := range []bool{false, true} {
		name := "clean_shutdown"
		if crash {
			name = "crash"
		}
		t.Run(name, func(t *testing.T) { singBoxLivenessEpisodeAcrossRestart(t, crash) })
	}
}

func singBoxLivenessEpisodeAcrossRestart(t *testing.T, crash bool) {
	dir := t.TempDir()
	f := openIngestFixture(t, dir)
	cookies, csrf := loginSession(t, f.handler)
	token := enrollNamedNodeToken(t, f.handler, cookies, csrf, "node-a", "Node A")

	base := time.Date(2026, 10, 1, 17, 0, 0, 0, time.UTC)
	at := base
	f.srv.now = func() time.Time { return at }
	notices := captureTypedNotices(f.srv)
	writes := watchStateFile(t, f.statePath())

	report := func(handler http.Handler, running bool) {
		t.Helper()
		runtime := `"running":true,"pid":4242,"active_state":"active","sub_state":"running"`
		if !running {
			runtime = `"running":false,"active_state":"failed","sub_state":"failed"`
		}
		body := fmt.Sprintf(`{"node_id":"node-a","inventory":{"status":"ok","nodes":[],"runtime":{%s,"restart_count":3,"probed_at":%q}}}`,
			runtime, at.Format(time.RFC3339Nano))
		rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/singbox-inventory", body, token)
		if rec.Code != http.StatusOK {
			t.Fatalf("inventory at %s: %d %s", at, rec.Code, rec.Body.String())
		}
		writes.check()
	}
	expectWrites := func(when string, want int) {
		t.Helper()
		if got := writes.take(); got != want {
			t.Fatalf("%s: state file rewritten %d times, want %d", when, got, want)
		}
	}
	expectNotices := func(when string, want ...string) {
		t.Helper()
		got := *notices
		*notices = nil
		if len(got) != len(want) {
			t.Fatalf("%s: notices %+v, want event types %v", when, got, want)
		}
		for i := range want {
			if got[i].eventType != want[i] {
				t.Fatalf("%s: notice %d is %q, want %q", when, i, got[i].eventType, want[i])
			}
		}
	}

	report(f.handler, true)
	expectWrites("first report", 1)
	for i := 1; i <= 30; i++ {
		at = base.Add(time.Duration(i) * 10 * time.Second)
		report(f.handler, true)
	}
	expectWrites("30 identical running reports", 0)

	// Down: the transition is written at once, the notice waits for the hold.
	downAt := base.Add(310 * time.Second)
	at = downAt
	report(f.handler, false)
	expectWrites("running to down", 1)
	for at = downAt.Add(10 * time.Second); at.Sub(downAt) < serviceDownHold; at = at.Add(10 * time.Second) {
		report(f.handler, false)
	}
	expectWrites("down inside the hold", 0)
	expectNotices("down inside the hold")

	// The hold elapses: one notice, and its bookkeeping is written.
	notifiedAt := downAt.Add(serviceDownHold)
	at = notifiedAt
	report(f.handler, false)
	expectWrites("hold elapsed", 1)
	expectNotices("hold elapsed", EventServiceDown)
	for i := 1; i <= 6; i++ {
		at = notifiedAt.Add(time.Duration(i) * 10 * time.Second)
		report(f.handler, false)
	}
	expectWrites("still down after the notice", 0)
	expectNotices("still down after the notice")
	lastSeenDown := at

	// Restart. A clean shutdown closes the store; a crash is the files as
	// they stand, copied while the old store is still open.
	restartDir, wantReceivedAt := dir, lastSeenDown
	if crash {
		restartDir, wantReceivedAt = t.TempDir(), notifiedAt
		copyStateFiles(t, dir, restartDir)
		t.Cleanup(func() { _ = f.st.Close() })
	} else if err := f.st.Close(); err != nil {
		t.Fatal(err)
	}
	restarted := openIngestFixture(t, restartDir)
	defer restarted.st.Close()
	rec, ok := restarted.st.SingBoxLivenessRecord("node-a")
	if !ok || rec.State != "down" || !rec.StateSince.Equal(downAt) || !rec.ProblemSince.Equal(downAt) || !rec.NotifiedDownAt.Equal(notifiedAt) {
		t.Fatalf("restart lost the episode: %+v", rec)
	}
	if !rec.ReceivedAt.Equal(wantReceivedAt) {
		t.Fatalf("received_at after restart is %s, want %s", rec.ReceivedAt, wantReceivedAt)
	}
	at = lastSeenDown.Add(10 * time.Second)
	restarted.srv.now = func() time.Time { return at }
	notices = captureTypedNotices(restarted.srv)
	writes = watchStateFile(t, restarted.statePath())

	report(restarted.handler, false)
	expectWrites("first down report after restart", 0)
	expectNotices("first down report after restart")

	at = at.Add(10 * time.Second)
	report(restarted.handler, true)
	expectWrites("down to running", 1)
	expectNotices("down to running", EventServiceRecovered)
	rec, _ = restarted.st.SingBoxLivenessRecord("node-a")
	if rec.State != "running" || !rec.ProblemSince.IsZero() || !rec.NotifiedDownAt.IsZero() {
		t.Fatalf("recovery did not close the episode: %+v", rec)
	}
}

// copyStateFiles copies every regular file in one storage directory to
// another: what a crashed server leaves behind, without closing anything.
func copyStateFiles(t *testing.T, from, to string) {
	t.Helper()
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(from, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, entry.Name()), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// postLiveness sends one inventory report carrying only the liveness probe.
func postLiveness(t *testing.T, handler http.Handler, token string, running bool, at time.Time) {
	t.Helper()
	runtime := `"running":true,"pid":4242,"active_state":"active","sub_state":"running"`
	if !running {
		runtime = `"running":false,"active_state":"failed","sub_state":"failed"`
	}
	body := fmt.Sprintf(`{"node_id":"node-a","inventory":{"status":"ok","nodes":[],"runtime":{%s,"restart_count":3,"probed_at":%q}}}`,
		runtime, at.Format(time.RFC3339Nano))
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/singbox-inventory", body, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("inventory at %s: %d %s", at, rec.Code, rec.Body.String())
	}
}

// A node deleted mid-incident and enrolled again under the same id starts a
// fresh episode: its first outage is announced after the hold, and its first
// healthy report announces no recovery from the deleted node's incident.
func TestReenrolledNodeDoesNotInheritLivenessEpisode(t *testing.T) {
	f := openIngestFixture(t, t.TempDir())
	defer f.st.Close()
	cookies, csrf := loginSession(t, f.handler)
	token := enrollNamedNodeToken(t, f.handler, cookies, csrf, "node-a", "Node A")
	base := time.Date(2026, 10, 1, 17, 0, 0, 0, time.UTC)
	at := base
	f.srv.now = func() time.Time { return at }
	notices := captureTypedNotices(f.srv)

	postLiveness(t, f.handler, token, true, at)
	at = base.Add(10 * time.Second)
	postLiveness(t, f.handler, token, false, at)
	at = base.Add(10*time.Second + serviceDownHold)
	postLiveness(t, f.handler, token, false, at)
	if len(*notices) != 1 || (*notices)[0].eventType != EventServiceDown {
		t.Fatalf("setup: want one down notice, got %+v", *notices)
	}
	*notices = nil

	if _, ok, err := f.st.DeleteNode("node-a"); err != nil || !ok {
		t.Fatalf("delete: ok=%v err=%v", ok, err)
	}
	token = enrollNamedNodeToken(t, f.handler, cookies, csrf, "node-a", "Node A again")

	reenrolledAt := base.Add(time.Hour)
	at = reenrolledAt
	postLiveness(t, f.handler, token, false, at)
	rec, ok := f.st.SingBoxLivenessRecord("node-a")
	if !ok || !rec.StateSince.Equal(reenrolledAt) || !rec.ProblemSince.Equal(reenrolledAt) || !rec.NotifiedDownAt.IsZero() {
		t.Fatalf("the re-enrolled node inherited the deleted episode: %+v", rec)
	}
	if len(*notices) != 0 {
		t.Fatalf("a fresh outage was announced before the hold: %+v", *notices)
	}
	at = reenrolledAt.Add(serviceDownHold)
	postLiveness(t, f.handler, token, false, at)
	if len(*notices) != 1 || (*notices)[0].eventType != EventServiceDown {
		t.Fatalf("the re-enrolled node's outage was not announced once after the hold: %+v", *notices)
	}
	*notices = nil
	at = at.Add(10 * time.Second)
	postLiveness(t, f.handler, token, true, at)
	if len(*notices) != 1 || (*notices)[0].eventType != EventServiceRecovered {
		t.Fatalf("recovery from the new episode: %+v", *notices)
	}
}
