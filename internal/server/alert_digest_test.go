package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// createAllNodesMonitor creates a tcp monitor assigned to every node.
func createAllNodesMonitor(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, name string) string {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/monitors",
		`{"name":"`+name+`","type":"tcp","target":"x:443","assign_all":true}`, cookies, csrf)
	defer res.Body.Close()
	var mon struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(res.Body).Decode(&mon); err != nil || mon.ID == "" {
		t.Fatalf("create monitor: %v %+v", err, mon)
	}
	return mon.ID
}

func reportMonitor(t *testing.T, handler http.Handler, nodeID, token, monitorID string, success bool, errMsg string) {
	t.Helper()
	body := `{"node_id":"` + nodeID + `","result":{"monitor_id":"` + monitorID + `","success":` + boolStr(success) + `,"error":"` + errMsg + `"}}`
	if rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/monitor-result", body, token); rec.Code != http.StatusOK {
		t.Fatalf("monitor result: %d %s", rec.Code, rec.Body.String())
	}
}

// flushTake runs the sweep's digest flush and returns what it sent.
func flushTake(srv *Server, sent *[]typedNotice) []typedNotice {
	srv.flushAlertDigests()
	out := *sent
	*sent = nil
	return out
}

// One failed probe is held; the second in a row pages, typed, naming the node
// by its name; a recovery follows only a run that paged.
func TestMonitorAlertHoldsForTwoFailuresAndNamesTheNode(t *testing.T) {
	srv, handler, _ := newInventoryServer(t)
	sent := captureTypedNotices(srv)
	cookies, csrf := loginSession(t, handler)
	token := enrollAndBeat(t, handler, cookies, csrf, "n-web", "tokyo-edge")
	monID := createAllNodesMonitor(t, handler, cookies, csrf, "web")

	reportMonitor(t, handler, "n-web", token, monID, true, "")
	reportMonitor(t, handler, "n-web", token, monID, false, "conn refused")
	if got := flushTake(srv, sent); len(got) != 0 {
		t.Fatalf("one failed probe paged: %+v", got)
	}
	reportMonitor(t, handler, "n-web", token, monID, true, "")
	if got := flushTake(srv, sent); len(got) != 0 {
		t.Fatalf("a recovery from a run that never paged: %+v", got)
	}

	reportMonitor(t, handler, "n-web", token, monID, false, "conn refused")
	reportMonitor(t, handler, "n-web", token, monID, false, "conn refused")
	got := flushTake(srv, sent)
	if len(got) != 1 || got[0].eventType != EventMonitorDown || got[0].title != "Monitor down: web on tokyo-edge" {
		t.Fatalf("second failure in a row: %+v", got)
	}
	if !strings.Contains(got[0].body, "conn refused") || strings.Contains(got[0].body, "n-web") {
		t.Fatalf("the body names the node by name and carries the error: %q", got[0].body)
	}
	reportMonitor(t, handler, "n-web", token, monID, false, "timeout")
	if got := flushTake(srv, sent); len(got) != 0 {
		t.Fatalf("a third failure paged again: %+v", got)
	}
	reportMonitor(t, handler, "n-web", token, monID, true, "")
	got = flushTake(srv, sent)
	if len(got) != 1 || got[0].eventType != EventMonitorRecovered || got[0].title != "Monitor recovered: web on tokyo-edge" {
		t.Fatalf("recovery: %+v", got)
	}
	if classifyNotifyEvent("\U0001F534 Monitor down") != EventMonitorDown || classifyNotifyEvent("\u2705 Monitor recovered") != EventMonitorRecovered {
		t.Fatal("legacy untyped monitor titles still classify")
	}
}

// An all-nodes monitor whose target goes down pages once, naming every node.
func TestAllNodesMonitorDownIsOneDigest(t *testing.T) {
	srv, handler, _ := newInventoryServer(t)
	sent := captureTypedNotices(srv)
	cookies, csrf := loginSession(t, handler)
	tokens := map[string]string{}
	for i := 1; i <= 5; i++ {
		id := fmt.Sprintf("n-%d", i)
		tokens[id] = enrollAndBeat(t, handler, cookies, csrf, id, fmt.Sprintf("edge-%d", i))
	}
	monID := createAllNodesMonitor(t, handler, cookies, csrf, "api")
	for round := 0; round < 2; round++ {
		for id, token := range tokens {
			reportMonitor(t, handler, id, token, monID, false, "conn refused")
		}
	}
	got := flushTake(srv, sent)
	if len(got) != 1 || got[0].eventType != EventMonitorDown || got[0].title != "Monitor down digest: 5" {
		t.Fatalf("five nodes down: %+v", got)
	}
	lines := strings.Split(got[0].body, "\n")
	if len(lines) != 5 || lines[0] != "api on edge-1: conn refused" || lines[4] != "api on edge-5: conn refused" {
		t.Fatalf("digest lines name every node in order: %q", got[0].body)
	}
	for id, token := range tokens {
		reportMonitor(t, handler, id, token, monID, true, "")
	}
	got = flushTake(srv, sent)
	if len(got) != 1 || got[0].eventType != EventMonitorRecovered || got[0].title != "Monitor recovered digest: 5" {
		t.Fatalf("five nodes back: %+v", got)
	}
}

// A page sent before a restart is answered after it, and not repeated: the
// second failure is written at once, so the restarted process reads the run
// as one that paged.
func TestMonitorRecoveryIsOwedAcrossARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st1, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	srv1, err := New(Options{Store: st1, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	sent1 := captureTypedNotices(srv1)
	h1 := srv1.Handler()
	cookies, csrf := loginSession(t, h1)
	token := enrollAndBeat(t, h1, cookies, csrf, "n-web", "tokyo-edge")
	monID := createAllNodesMonitor(t, h1, cookies, csrf, "web")
	reportMonitor(t, h1, "n-web", token, monID, true, "")
	reportMonitor(t, h1, "n-web", token, monID, false, "conn refused")
	reportMonitor(t, h1, "n-web", token, monID, false, "conn refused")
	if got := flushTake(srv1, sent1); len(got) != 1 || got[0].eventType != EventMonitorDown {
		t.Fatalf("before the restart: %+v", got)
	}
	// A crash, not a clean close: only what was written at once survives.
	crashDir := t.TempDir()
	copyStateFiles(t, filepath.Dir(path), crashDir)
	t.Cleanup(func() { _ = st1.Close() })

	st2, err := store.Open(filepath.Join(crashDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st2.Close() })
	srv2, err := New(Options{Store: st2, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	sent2 := captureTypedNotices(srv2)
	h2 := srv2.Handler()
	reportMonitor(t, h2, "n-web", token, monID, false, "conn refused")
	if got := flushTake(srv2, sent2); len(got) != 0 {
		t.Fatalf("the restarted process paged the same run again: %+v", got)
	}
	reportMonitor(t, h2, "n-web", token, monID, true, "")
	if got := flushTake(srv2, sent2); len(got) != 1 || got[0].eventType != EventMonitorRecovered {
		t.Fatalf("the recovery owed across the restart: %+v", got)
	}
}

func postNodeLiveness(t *testing.T, handler http.Handler, nodeID, token string, running bool, at time.Time) {
	t.Helper()
	runtime := `"running":true,"pid":4242,"active_state":"active","sub_state":"running"`
	if !running {
		runtime = `"running":false,"active_state":"failed","sub_state":"failed"`
	}
	body := fmt.Sprintf(`{"node_id":%q,"inventory":{"status":"ok","nodes":[],"runtime":{%s,"restart_count":3,"probed_at":%q}}}`,
		nodeID, runtime, at.Format(time.RFC3339Nano))
	if rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/singbox-inventory", body, token); rec.Code != http.StatusOK {
		t.Fatalf("inventory %s at %s: %d %s", nodeID, at, rec.Code, rec.Body.String())
	}
}

// A sing-box roll that breaks many cores pages once, naming every node, and
// their recovery is one message too. A single node keeps its own wording.
func TestServiceDownForManyNodesIsOneDigest(t *testing.T) {
	srv, handler, _ := newInventoryServer(t)
	sent := captureTypedNotices(srv)
	cookies, csrf := loginSession(t, handler)
	base := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	at := base
	srv.now = func() time.Time { return at }
	tokens := map[string]string{}
	for _, n := range []struct{ id, name string }{{"n-a", "alpha"}, {"n-b", "bravo"}, {"n-c", "charlie"}} {
		tokens[n.id] = enrollAndBeat(t, handler, cookies, csrf, n.id, n.name)
	}
	for id, token := range tokens {
		postNodeLiveness(t, handler, id, token, true, at)
	}
	at = base.Add(10 * time.Second)
	for id, token := range tokens {
		postNodeLiveness(t, handler, id, token, false, at)
	}
	if got := flushTake(srv, sent); len(got) != 0 {
		t.Fatalf("inside the hold: %+v", got)
	}
	at = at.Add(serviceDownHold)
	for id, token := range tokens {
		postNodeLiveness(t, handler, id, token, false, at)
	}
	got := flushTake(srv, sent)
	if len(got) != 1 || got[0].eventType != EventServiceDown || got[0].title != "sing-box down digest: 3 nodes" {
		t.Fatalf("three cores down: %+v", got)
	}
	lines := strings.Split(got[0].body, "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "alpha: down since ") || !strings.HasPrefix(lines[2], "charlie: down since ") {
		t.Fatalf("digest names every node by name: %q", got[0].body)
	}

	at = at.Add(10 * time.Second)
	for id, token := range tokens {
		postNodeLiveness(t, handler, id, token, true, at)
	}
	got = flushTake(srv, sent)
	if len(got) != 1 || got[0].eventType != EventServiceRecovered || got[0].title != "sing-box recovered digest: 3 nodes" {
		t.Fatalf("three cores back: %+v", got)
	}

	// One node alone keeps the single-node title and a body that names it.
	at = at.Add(10 * time.Second)
	postNodeLiveness(t, handler, "n-a", tokens["n-a"], false, at)
	at = at.Add(serviceDownHold)
	postNodeLiveness(t, handler, "n-a", tokens["n-a"], false, at)
	got = flushTake(srv, sent)
	if len(got) != 1 || got[0].title != "sing-box down on alpha" || !strings.HasPrefix(got[0].body, "alpha (n-a): sing-box has been down since ") {
		t.Fatalf("a single node: %+v", got)
	}
}

// The liveness sweep is what sends queued notices in production.
func TestLivenessSweepFlushesQueuedAlerts(t *testing.T) {
	srv, _, _ := newInventoryServer(t)
	sent := captureTypedNotices(srv)
	srv.queueAlertDigest(EventServiceDown, alertDigestLine{title: "t", body: "b", line: "l"})
	srv.sweepNodeLiveness(time.Now(), store.NodeStatusCauseLivenessSweep)
	if len(*sent) != 1 || (*sent)[0].eventType != EventServiceDown {
		t.Fatalf("the sweep did not flush: %+v", *sent)
	}
}

// A restart through SIGTERM ends in Server.Close. What the digest holds was
// decided and recorded already, so Close sends it rather than dropping it.
func TestCloseSendsQueuedAlerts(t *testing.T) {
	srv, _, _ := newInventoryServer(t)
	sent := captureTypedNotices(srv)
	srv.queueAlertDigest(EventServiceDown, alertDigestLine{title: "sing-box down on alpha", body: "b", line: "l"})
	if err := srv.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 1 || (*sent)[0].eventType != EventServiceDown || (*sent)[0].title != "sing-box down on alpha" {
		t.Fatalf("Close did not send the queued alert: %+v", *sent)
	}
}

// Close waits for a delivery that is still running, within its context, so a
// page handed to a slow channel is not cut off by the exit that follows. The
// held count stands in for a delivery stuck on a slow channel; the real
// sender refuses the loopback listener a test could hold it on.
func TestCloseWaitsForRunningDeliveries(t *testing.T) {
	srv, _, _ := newInventoryServer(t)
	srv.notifyDeliveries.begin()

	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := srv.Close(short); err != nil {
		t.Fatal(err)
	}
	if waited := time.Since(start); waited > 5*time.Second {
		t.Fatalf("Close outlived its context: %s", waited)
	}

	done := make(chan struct{})
	go func() {
		_ = srv.Close(context.Background())
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Close returned while a delivery was still running")
	case <-time.After(200 * time.Millisecond):
	}
	srv.notifyDeliveries.end()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return after the delivery finished")
	}
}

// logLines is a log destination a test can read while the server writes.
type logLines chan string

func (l logLines) Write(p []byte) (int, error) {
	l <- string(p)
	return len(p), nil
}

// A real delivery is counted while it runs and released when it ends, so the
// wait above covers every typed notification.
func TestNotifyDeliveryIsCountedUntilItEnds(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	lines := make(logLines, 16)
	srv.logger = log.New(lines, "", 0)
	if err := st.UpsertNotifyChannel(model.NotifyChannel{ID: "nc-hook", Name: "hook", Kind: "webhook", Enabled: true, Config: map[string]string{"url": "http://127.0.0.1:9/hook"}}); err != nil {
		t.Fatal(err)
	}
	srv.notifyEventTyped(EventServiceDown, "sing-box down on alpha", "b")
	deadline := time.After(5 * time.Second)
	for delivered := false; !delivered; {
		select {
		case line := <-lines:
			delivered = strings.Contains(line, "webhook delivery failed")
		case <-deadline:
			t.Fatal("the delivery never ran")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if left := srv.notifyDeliveries.wait(ctx); left != 0 {
		t.Fatalf("a finished delivery is still counted: %d", left)
	}
	// The goroutine may still be unwinding after the log line; give it a
	// moment, then the count must be exactly zero, not below it.
	time.Sleep(100 * time.Millisecond)
	srv.notifyDeliveries.mu.Lock()
	n := srv.notifyDeliveries.n
	srv.notifyDeliveries.mu.Unlock()
	if n != 0 {
		t.Fatalf("delivery count after the delivery ended = %d, want 0", n)
	}
}
