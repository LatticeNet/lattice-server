package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Trace collector readiness tests (design 26, slice R1).
//
// The cases that matter are the honest ones: a node switched on that cannot
// record must say so within one poll, from the server at once for agents that
// predate the status and from the agent's next beat for the rest, and nothing
// an agent sends may make a node look more ready than it is.

// collectorBeat posts one metrics beat as an agent of the given version.
// status is the trace_collector JSON, or "" for a beat without it, which is
// what every agent before 0.3.10-alpha.4 sends.
func collectorBeat(t *testing.T, handler http.Handler, nodeID, version string, collectedAt time.Time, status string) {
	t.Helper()
	body := fmt.Sprintf(`{"node_id":%q,"version":%q,"metrics":{"collected_at":%q}`, nodeID, version, collectedAt.Format(time.RFC3339Nano))
	if status != "" {
		body += `,"trace_collector":` + status
	}
	body += "}"
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/metrics", body, "node-token-"+nodeID)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics beat: %d %s", rec.Code, rec.Body.String())
	}
}

func postTracePolicy(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf string, body map[string]any) tracePolicyView {
	t.Helper()
	res := doTrace(t, handler, http.MethodPost, "/api/trace/policy", cookies, csrf, body)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("set policy: %d %s", res.StatusCode, b)
	}
	var v tracePolicyView
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func readTracePolicy(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, nodeID string) tracePolicyView {
	t.Helper()
	res := doTrace(t, handler, http.MethodGet, "/api/trace/policy?node_id="+nodeID, cookies, csrf, nil)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("read policy: %d", res.StatusCode)
	}
	var out struct {
		Policies []tracePolicyView `json:"policies"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Policies) != 1 {
		t.Fatalf("read %d policies for %s, want 1", len(out.Policies), nodeID)
	}
	return out.Policies[0]
}

func readyCollectorStatus(agentNow time.Time) string {
	return fmt.Sprintf(`{"state":"ready","since":%q,"level":"debug","clash_api_addr":"127.0.0.1:9090","addr_source":"config",
		"raw_lines":false,"lines_per_sec":41.3,"budget_lines_per_sec":5000,"shed_connections":12,"unparsed":1,"counters_since":%q}`,
		agentNow.Add(-time.Minute).Format(time.RFC3339), agentNow.Add(-time.Hour).Format(time.RFC3339))
}

const noClashAPIStatus = `{"state":"no_clash_api","detail":"no experimental.clash_api in /etc/sing-box/config.json","budget_lines_per_sec":5000}`

func TestMetricsBeatRecordsTraceCollectorStatus(t *testing.T) {
	clock := &testClock{at: time.Now().UTC()}
	f := newTraceFixture(t, clock)
	traceNode(t, f.st, "node-a")
	cookies, csrf := loginSession(t, f.handler)

	// The agent's clock runs an hour behind; its instants are carried as sent.
	agentNow := clock.now().Add(-time.Hour)
	collectorBeat(t, f.handler, "node-a", traceCollectorStatusMinAgent, agentNow, readyCollectorStatus(agentNow))

	c := readTracePolicy(t, f.handler, cookies, csrf, "node-a").Collector
	if c == nil {
		t.Fatal("the beat's collector status was not recorded")
	}
	if c.State != model.CollectorReady || c.ReportedBy != traceCollectorByAgent || c.Level != model.TraceLevelDebug ||
		c.ClashAPIAddr != "127.0.0.1:9090" || c.AddrSource != model.ClashAddrFromConfig || c.LinesPerSec != 41.3 ||
		c.BudgetLinesPerSec != 5000 || c.ShedConnections != 12 || c.Unparsed != 1 {
		t.Fatalf("collector = %+v", c)
	}
	if !c.CollectedAt.Equal(agentNow) || !c.ReceivedAt.Equal(clock.now()) || !c.Since.Equal(agentNow.Add(-time.Minute).Truncate(time.Second)) {
		t.Fatalf("clocks: collected %s received %s since %s", c.CollectedAt, c.ReceivedAt, c.Since)
	}
	if c.Stale || c.Pending {
		t.Fatalf("a fresh report reads stale=%v pending=%v", c.Stale, c.Pending)
	}
}

// Lane C acceptance with a 0.3.9-shaped agent (no trace_collector on its
// beat): records switched on with no address read no_clash_api from the
// server on the save's own response, and switching raw lines off withholds
// the raw source and refuses a straggler with 409.
func TestA039AgentReadsNoClashAPIAndShipsNoRawLines(t *testing.T) {
	f := newTraceFixture(t, nil)
	traceNode(t, f.st, "node-a")
	cookies, csrf := loginSession(t, f.handler)
	collectorBeat(t, f.handler, "node-a", "0.3.9", time.Now().UTC(), "")

	v := postTracePolicy(t, f.handler, cookies, csrf, map[string]any{
		"node_id": "node-a", "enabled": true, "raw": map[string]any{"enabled": true},
	})
	if c := v.Collector; c == nil || c.State != model.CollectorNoClashAPI || c.ReportedBy != traceCollectorByServer {
		t.Fatalf("save response collector = %+v, want no_clash_api from the server", c)
	}
	sourceID := doTraceAgent(t, f.handler, "node-a").RawSourceID
	if sourceID == "" {
		t.Fatal("raw on handed the agent no raw source id")
	}

	postTracePolicy(t, f.handler, cookies, csrf, map[string]any{"node_id": "node-a", "raw": map[string]any{"enabled": false}})
	if cfg := doTraceAgent(t, f.handler, "node-a"); cfg.RawSourceID != "" || !cfg.Policy.Enabled {
		t.Fatalf("raw off: raw_source_id %q, records enabled %v", cfg.RawSourceID, cfg.Policy.Enabled)
	}
	rec := doAgentRaw(t, f.handler, http.MethodPost, "/api/agent/logs", rawLogBatch(sourceID, "a straggler"), "node-token-node-a")
	if rec.Code != http.StatusConflict {
		t.Fatalf("a straggler raw batch answered %d %s, want 409", rec.Code, rec.Body.String())
	}
	if meta, _, _, found := f.logs.Stats(sourceID); found && meta.Lines != 0 {
		t.Fatalf("logs.db holds %d raw lines after raw was switched off", meta.Lines)
	}
}

func TestOlderAgentWithoutAddressIsInferredNoClashAPI(t *testing.T) {
	f := newTraceFixture(t, nil)
	traceNode(t, f.st, "node-a")
	cookies, csrf := loginSession(t, f.handler)
	collectorBeat(t, f.handler, "node-a", "0.3.9", time.Now().UTC(), "")

	if c := readTracePolicy(t, f.handler, cookies, csrf, "node-a").Collector; c == nil || c.State != model.CollectorOff || c.ReportedBy != traceCollectorByServer {
		t.Fatalf("records off on an older agent = %+v, want off from the server", c)
	}
	v := postTracePolicy(t, f.handler, cookies, csrf, map[string]any{"node_id": "node-a", "enabled": true})
	c := v.Collector
	if c == nil || c.State != model.CollectorNoClashAPI || c.ReportedBy != traceCollectorByServer || c.Pending || c.Stale {
		t.Fatalf("save response collector = %+v", c)
	}
	// The remedy differs from a new agent's: 0.3.9 never reads the config,
	// so the detail has to say the address belongs in the policy.
	if !strings.Contains(c.Detail, "clash_api_addr") || !strings.Contains(c.Detail, "0.3.9") {
		t.Fatalf("detail %q does not name the version and the remedy", c.Detail)
	}
	if got := readTracePolicy(t, f.handler, cookies, csrf, "node-a").Collector; got == nil || got.State != model.CollectorNoClashAPI {
		t.Fatalf("GET disagrees with the save response: %+v", got)
	}

	// Offline, the inference still holds but rests on the last version heard.
	node, _ := f.st.Node("node-a")
	node.Online = false
	if err := f.st.UpsertNode(node); err != nil {
		t.Fatal(err)
	}
	if got := readTracePolicy(t, f.handler, cookies, csrf, "node-a").Collector; got == nil || got.State != model.CollectorNoClashAPI || !got.Stale {
		t.Fatalf("an offline older agent = %+v, want no_clash_api marked stale", got)
	}
}

func TestOlderAgentWithAddressIsInferredTooOld(t *testing.T) {
	f := newTraceFixture(t, nil)
	traceNode(t, f.st, "node-a")
	cookies, csrf := loginSession(t, f.handler)
	collectorBeat(t, f.handler, "node-a", "v0.3.10-alpha.3", time.Now().UTC(), "")

	c := postTracePolicy(t, f.handler, cookies, csrf, map[string]any{
		"node_id": "node-a", "enabled": true, "clash_api_addr": "127.0.0.1:9090",
	}).Collector
	if c == nil || c.State != model.CollectorAgentTooOld || c.ReportedBy != traceCollectorByServer ||
		c.ClashAPIAddr != "127.0.0.1:9090" || c.AddrSource != model.ClashAddrFromPolicy {
		t.Fatalf("collector = %+v, want agent_too_old with the policy address", c)
	}
}

// A capture switches the collector on as much as the policy does, so an
// older agent covered by one with records off is inferred like records on.
func TestCaptureSwitchesAnOlderAgentsCollectorOn(t *testing.T) {
	f := newTraceFixture(t, nil)
	traceNode(t, f.st, "node-a")
	traceNode(t, f.st, "node-b")
	cookies, csrf := loginSession(t, f.handler)
	collectorBeat(t, f.handler, "node-a", "0.3.9", time.Now().UTC(), "")
	collectorBeat(t, f.handler, "node-b", "0.3.9", time.Now().UTC(), "")

	res := doTrace(t, f.handler, http.MethodPost, "/api/trace/sessions", cookies, csrf, map[string]any{
		"name": "capture", "level": "debug", "ttl_seconds": 600,
		"filter": map[string]any{"node_ids": []string{"node-a"}},
	})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create session: %d", res.StatusCode)
	}
	if c := readTracePolicy(t, f.handler, cookies, csrf, "node-a").Collector; c == nil || c.State != model.CollectorNoClashAPI {
		t.Fatalf("captured node with records off = %+v, want no_clash_api", c)
	}
	if c := readTracePolicy(t, f.handler, cookies, csrf, "node-b").Collector; c == nil || c.State != model.CollectorOff {
		t.Fatalf("a node outside the capture = %+v, want off", c)
	}
}

func TestNewAgentBeforeItsFirstBeatHasNoCollector(t *testing.T) {
	f := newTraceFixture(t, nil)
	traceNode(t, f.st, "node-a")
	traceNode(t, f.st, "node-b")
	cookies, csrf := loginSession(t, f.handler)

	// The recovery-blocked start beats before the collector exists, with no
	// trace_collector key. That is not an old agent and must not read as one.
	collectorBeat(t, f.handler, "node-a", traceCollectorStatusMinAgent, time.Now().UTC(), "")
	if c := postTracePolicy(t, f.handler, cookies, csrf, map[string]any{"node_id": "node-a", "enabled": true}).Collector; c != nil {
		t.Fatalf("a new agent that has not reported reads %+v, want nothing (waiting)", c)
	}
	// A version this server cannot order is not guessed at either.
	collectorBeat(t, f.handler, "node-b", "dev-1a4e65d", time.Now().UTC(), "")
	if c := postTracePolicy(t, f.handler, cookies, csrf, map[string]any{"node_id": "node-b", "enabled": true}).Collector; c != nil {
		t.Fatalf("an unordered version reads %+v, want nothing", c)
	}
}

func TestAgentMayNotClaimAgentTooOld(t *testing.T) {
	f := newTraceFixture(t, nil)
	traceNode(t, f.st, "node-a")
	cookies, csrf := loginSession(t, f.handler)
	now := time.Now().UTC()

	collectorBeat(t, f.handler, "node-a", traceCollectorStatusMinAgent, now, `{"state":"agent_too_old"}`)
	if c := readTracePolicy(t, f.handler, cookies, csrf, "node-a").Collector; c != nil {
		t.Fatalf("an agent's agent_too_old was recorded: %+v", c)
	}
	collectorBeat(t, f.handler, "node-a", traceCollectorStatusMinAgent, now, readyCollectorStatus(now))
	collectorBeat(t, f.handler, "node-a", traceCollectorStatusMinAgent, now, `{"state":"agent_too_old"}`)
	if c := readTracePolicy(t, f.handler, cookies, csrf, "node-a").Collector; c == nil || c.State != model.CollectorReady {
		t.Fatalf("agent_too_old from an agent replaced the record: %+v", c)
	}
}

func TestUnknownCollectorStateIsDropped(t *testing.T) {
	f := newTraceFixture(t, nil)
	traceNode(t, f.st, "node-a")
	cookies, csrf := loginSession(t, f.handler)
	now := time.Now().UTC()

	collectorBeat(t, f.handler, "node-a", traceCollectorStatusMinAgent, now, noClashAPIStatus)
	collectorBeat(t, f.handler, "node-a", traceCollectorStatusMinAgent, now, `{"state":"recording","level":"debug"}`)
	if c := readTracePolicy(t, f.handler, cookies, csrf, "node-a").Collector; c == nil || c.State != model.CollectorNoClashAPI {
		t.Fatalf("an unknown state replaced the record: %+v", c)
	}
}

func TestCollectorDetailAndAddressAreBounded(t *testing.T) {
	f := newTraceFixture(t, nil)
	traceNode(t, f.st, "node-a")
	cookies, csrf := loginSession(t, f.handler)

	status, err := json.Marshal(map[string]any{
		"state":                "stream_failing",
		"detail":               "GET /logs: 401\n" + strings.Repeat("x", 600),
		"clash_api_addr":       strings.Repeat("1", 200),
		"addr_source":          "elsewhere",
		"level":                "loud",
		"lines_per_sec":        -5,
		"budget_lines_per_sec": -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	collectorBeat(t, f.handler, "node-a", traceCollectorStatusMinAgent, time.Now().UTC(), string(status))
	c := readTracePolicy(t, f.handler, cookies, csrf, "node-a").Collector
	if c == nil || c.State != model.CollectorStreamFailing {
		t.Fatalf("collector = %+v", c)
	}
	if len(c.Detail) > model.CollectorDetailMaxBytes || strings.ContainsAny(c.Detail, "\r\n") || !strings.HasPrefix(c.Detail, "GET /logs: 401 ") {
		t.Fatalf("detail is not one bounded line: %d bytes %q", len(c.Detail), c.Detail)
	}
	if len(c.ClashAPIAddr) > maxTraceCollectorAddr {
		t.Fatalf("address kept %d bytes", len(c.ClashAPIAddr))
	}
	if c.AddrSource != "" || c.Level != "" || c.LinesPerSec != 0 || c.BudgetLinesPerSec != 0 {
		t.Fatalf("out-of-contract fields kept: source %q level %q lines %v budget %d", c.AddrSource, c.Level, c.LinesPerSec, c.BudgetLinesPerSec)
	}
}

func TestCollectorIsStaleWhenTheNodeGoesQuiet(t *testing.T) {
	clock := &testClock{at: time.Now().UTC()}
	f := newTraceFixture(t, clock)
	traceNode(t, f.st, "node-a")
	cookies, csrf := loginSession(t, f.handler)

	collectorBeat(t, f.handler, "node-a", traceCollectorStatusMinAgent, clock.now(), readyCollectorStatus(clock.now()))
	if c := readTracePolicy(t, f.handler, cookies, csrf, "node-a").Collector; c == nil || c.Stale {
		t.Fatalf("fresh report = %+v", c)
	}
	clock.advance(agentLoopLateAfter + time.Second)
	c := readTracePolicy(t, f.handler, cookies, csrf, "node-a").Collector
	if c == nil || !c.Stale || c.State != model.CollectorReady {
		t.Fatalf("no report for %s = %+v, want the last state marked stale", agentLoopLateAfter, c)
	}
	collectorBeat(t, f.handler, "node-a", traceCollectorStatusMinAgent, clock.now(), readyCollectorStatus(clock.now()))
	if c := readTracePolicy(t, f.handler, cookies, csrf, "node-a").Collector; c == nil || c.Stale {
		t.Fatalf("a new report did not clear stale: %+v", c)
	}

	node, _ := f.st.Node("node-a")
	node.Online = false
	if err := f.st.UpsertNode(node); err != nil {
		t.Fatal(err)
	}
	if c := readTracePolicy(t, f.handler, cookies, csrf, "node-a").Collector; c == nil || !c.Stale {
		t.Fatalf("an offline node's collector = %+v, want stale", c)
	}
}

func TestCollectorIsPendingAfterAPolicyChange(t *testing.T) {
	clock := &testClock{at: time.Now().UTC()}
	f := newTraceFixture(t, clock)
	traceNode(t, f.st, "node-a")
	cookies, csrf := loginSession(t, f.handler)

	collectorBeat(t, f.handler, "node-a", traceCollectorStatusMinAgent, clock.now(), `{"state":"off"}`)
	clock.advance(time.Second)
	c := postTracePolicy(t, f.handler, cookies, csrf, map[string]any{"node_id": "node-a", "enabled": true}).Collector
	if c == nil || !c.Pending || c.State != model.CollectorOff || c.ReportedBy != traceCollectorByAgent {
		t.Fatalf("save response = %+v, want the last report marked pending", c)
	}
	clock.advance(time.Second)
	collectorBeat(t, f.handler, "node-a", traceCollectorStatusMinAgent, clock.now(), noClashAPIStatus)
	if c := readTracePolicy(t, f.handler, cookies, csrf, "node-a").Collector; c == nil || c.Pending {
		t.Fatalf("a report after the change still reads pending: %+v", c)
	}

	// A capture that starts after the last report also waits for an answer.
	clock.advance(time.Second)
	res := doTrace(t, f.handler, http.MethodPost, "/api/trace/sessions", cookies, csrf, map[string]any{
		"name": "capture", "level": "debug", "ttl_seconds": 600,
		"filter": map[string]any{"node_ids": []string{"node-a"}},
	})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create session: %d", res.StatusCode)
	}
	if c := readTracePolicy(t, f.handler, cookies, csrf, "node-a").Collector; c == nil || !c.Pending {
		t.Fatalf("a capture started after the last report = %+v, want pending", c)
	}
}

func TestDeletedNodeForgetsItsCollector(t *testing.T) {
	f := newTraceFixture(t, nil)
	traceNode(t, f.st, "node-a")
	collectorBeat(t, f.handler, "node-a", traceCollectorStatusMinAgent, time.Now().UTC(), noClashAPIStatus)
	if _, ok := f.srv.traceCollectorRecord("node-a"); !ok {
		t.Fatal("the beat left no record")
	}
	if _, ok, err := f.srv.deleteGraphNode("node-a"); err != nil || !ok {
		t.Fatalf("delete node: ok=%v err=%v", ok, err)
	}
	if _, ok := f.srv.traceCollectorRecord("node-a"); ok {
		t.Fatal("a deleted node's collector status is still in memory")
	}
}

// Acceptance 1 on the server for a new agent: save the policy, take one beat
// carrying no_clash_api, and the read says so with nothing pending.
func TestNoClashAPIIsVisibleOneBeatAfterThePolicyIsSaved(t *testing.T) {
	clock := &testClock{at: time.Now().UTC()}
	f := newTraceFixture(t, clock)
	traceNode(t, f.st, "node-a")
	cookies, csrf := loginSession(t, f.handler)
	collectorBeat(t, f.handler, "node-a", traceCollectorStatusMinAgent, clock.now(), `{"state":"off"}`)

	clock.advance(time.Second)
	postTracePolicy(t, f.handler, cookies, csrf, map[string]any{"node_id": "node-a", "enabled": true})
	clock.advance(time.Second)
	collectorBeat(t, f.handler, "node-a", traceCollectorStatusMinAgent, clock.now(), noClashAPIStatus)

	c := readTracePolicy(t, f.handler, cookies, csrf, "node-a").Collector
	if c == nil || c.State != model.CollectorNoClashAPI || c.Pending || c.Stale || c.ReportedBy != traceCollectorByAgent {
		t.Fatalf("collector = %+v, want no_clash_api from the agent, settled", c)
	}
	if !strings.Contains(c.Detail, "/etc/sing-box/config.json") {
		t.Fatalf("detail %q lost the agent's reason", c.Detail)
	}
}

// An agent replaced by an older one stops reporting, and the record the newer
// one left says nothing about the older one, so the version decides.
func TestDowngradedAgentIsInferredFromItsVersion(t *testing.T) {
	f := newTraceFixture(t, nil)
	traceNode(t, f.st, "node-a")
	cookies, csrf := loginSession(t, f.handler)
	postTracePolicy(t, f.handler, cookies, csrf, map[string]any{"node_id": "node-a", "enabled": true})

	now := time.Now().UTC()
	collectorBeat(t, f.handler, "node-a", traceCollectorStatusMinAgent, now, readyCollectorStatus(now))
	if c := readTracePolicy(t, f.handler, cookies, csrf, "node-a").Collector; c == nil || c.State != model.CollectorReady {
		t.Fatalf("new agent = %+v", c)
	}
	collectorBeat(t, f.handler, "node-a", "0.3.9", now, "")
	if c := readTracePolicy(t, f.handler, cookies, csrf, "node-a").Collector; c == nil || c.State != model.CollectorNoClashAPI || c.ReportedBy != traceCollectorByServer {
		t.Fatalf("after a downgrade = %+v, want the server's inference", c)
	}
}

// rawLogBatch is a raw-line batch for a node's singbox:// source, as the agent
// posts it to /api/agent/logs.
func rawLogBatch(sourceID, line string) string {
	return fmt.Sprintf(`{"node_id":"node-a","batch":{"source_id":%q,"lines":[%q],"last_off":1,"captured_at":%q}}`,
		sourceID, line, time.Now().UTC().Format(time.RFC3339Nano))
}
