package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/store"
)

const (
	witnessTestKey    = "WitnessDeviceKey2026xyz"
	witnessTestPublic = "https://lattice.example.test"
)

type witnessFixture struct {
	srv     *Server
	handler http.Handler
	st      *store.Store
	cookies []*http.Cookie
	csrf    string
	token   string // the node's agent token
}

func newWitnessFixture(t *testing.T, publicURL string) witnessFixture {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true, PublicURL: publicURL})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)
	token := enrollNamedNodeToken(t, handler, cookies, csrf, "node-w", "[cd]-gomami-jpn-pulse-nano")
	if err := st.UpsertNotifyChannel(model.NotifyChannel{ID: "nc-bark", Name: "Bark urgent", Kind: "bark", Enabled: true,
		Config: map[string]string{"base_url": "https://bark.example.com", "key": witnessTestKey}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNotifyChannel(model.NotifyChannel{ID: "nc-tg", Name: "Telegram", Kind: "telegram", Enabled: true,
		Config: map[string]string{"token": "123:abc", "chat_id": "42"}}); err != nil {
		t.Fatal(err)
	}
	return witnessFixture{srv: srv, handler: handler, st: st, cookies: cookies, csrf: csrf, token: token}
}

func (f witnessFixture) beat(t *testing.T, body string) {
	t.Helper()
	res := doAgentRaw(t, f.handler, http.MethodPost, "/api/agent/metrics", body, f.token)
	if res.Code != http.StatusOK {
		t.Fatalf("metrics: %d %s", res.Code, res.Body.String())
	}
}

func (f witnessFixture) capable(t *testing.T) {
	t.Helper()
	f.beat(t, `{"node_id":"node-w","version":"0.3.10-alpha.2","capabilities":["`+witnessCapability+`"],"metrics":{}}`)
}

func (f witnessFixture) plan(t *testing.T, body string) (*http.Response, model.Approval) {
	t.Helper()
	res := doJSON(t, f.handler, http.MethodPost, "/api/notify/witness/plan", body, f.cookies, f.csrf)
	var out struct {
		Approval model.Approval `json:"approval"`
	}
	if res.StatusCode == http.StatusOK {
		out = decodeBody[struct {
			Approval model.Approval `json:"approval"`
		}](t, res)
	}
	return res, out.Approval
}

func (f witnessFixture) approve(t *testing.T, a model.Approval) *http.Response {
	t.Helper()
	return doJSON(t, f.handler, http.MethodPost, "/api/network/approvals/approve",
		`{"approval_id":"`+a.ID+`","queue_apply":true,"plan_sha256":"`+planSHA256(a.Plan)+`"}`, f.cookies, f.csrf)
}

const witnessPlanBody = `{"node_id":"node-w","channel_id":"nc-bark","bark_url":"http://127.0.0.1:7001"}`

// The plan shows the config and the unit verbatim, the key file and a prefix
// of the key's hash, and never the key; the files read back out of it are the
// bytes the node will hash.
func TestWitnessPlanShowsConfigAndUnitButNeverTheKey(t *testing.T) {
	f := newWitnessFixture(t, witnessTestPublic)
	f.capable(t)
	res, a := f.plan(t, witnessPlanBody)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("plan: %d", res.StatusCode)
	}
	if a.Plugin != witnessPlugin || a.Action != witnessConfigureAction || a.Status != model.ApprovalPending || a.NodeID != "node-w" {
		t.Fatalf("approval = %+v", a)
	}
	if strings.Contains(a.Plan, witnessTestKey) {
		t.Fatal("the plan carries the device key")
	}
	for _, want := range []string{
		"device_key_channel_id: nc-bark",
		"device_key_sha256_prefix: " + witnessKeyPrefix(witnessTestKey),
		"device_key_file: " + witnessKeyPath + " (0600, root)",
		"--- file " + witnessConfigPath,
		"--- file " + witnessUnitPath,
		"ExecStart=" + witnessBinaryPath + " -witness " + witnessConfigPath,
		`"health_url": "` + witnessTestPublic + `/readyz"`,
		`"bark_url": "http://127.0.0.1:7001"`,
		`"bark_level": "critical"`,
	} {
		if !strings.Contains(a.Plan, want) {
			t.Fatalf("plan lacks %q:\n%s", want, a.Plan)
		}
	}
	config, unit, err := witnessPlanFiles(a.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if unit != renderWitnessUnit() {
		t.Fatalf("unit read back differs:\n%s", unit)
	}
	if approvalPlanField(a.Plan, witnessFieldConfigSHA) != witnessConfigSHA(config) {
		t.Fatal("the plan's config_sha256 is not the hash of the config it shows")
	}
	if got := approvalDisplayReason(a); got != "Set up the control-plane witness, pushing to Bark urgent (bark)" {
		t.Fatalf("display reason = %q", got)
	}
}

// The config document is a contract with the node agent's witness.Config,
// which refuses unknown fields: exactly these keys, with the defaults the
// agent would also apply.
func TestWitnessConfigMatchesTheAgentContract(t *testing.T) {
	doc, err := witnessConfigFromRequest(witnessPlanRequest{BarkURL: "http://127.0.0.1:7001/"}, "pulse-nano", witnessTestPublic+"/readyz")
	if err != nil {
		t.Fatal(err)
	}
	config, err := renderWitnessConfig(doc)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(config), &fields); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{"bark_device_key_file", "bark_group", "bark_level", "bark_url", "health_url", "hold_seconds", "interval_seconds", "node_name", "recover_seconds", "reference_urls", "state_file", "version"}
	if !slices.Equal(keys, want) {
		t.Fatalf("config keys = %v, want %v", keys, want)
	}
	if doc.BarkURL != "http://127.0.0.1:7001" || doc.IntervalSeconds != 30 || doc.HoldSeconds != 180 || doc.RecoverSeconds != 60 ||
		doc.StateFile != witnessStatePath || doc.BarkDeviceKeyFile != witnessKeyPath || !slices.Equal(doc.ReferenceURLs, witnessDefaultReferences) {
		t.Fatalf("defaults = %+v", doc)
	}
	if !strings.HasSuffix(config, "}\n") {
		t.Fatal("the config file must end in one newline, as the heredoc writes it")
	}

	// A slow interval pulls the hold and the recovery up with it.
	doc, err = witnessConfigFromRequest(witnessPlanRequest{BarkURL: "http://[::1]:8080", IntervalSeconds: 120}, "n", witnessTestPublic+"/readyz")
	if err != nil || doc.HoldSeconds != 240 || doc.RecoverSeconds != 120 {
		t.Fatalf("slow interval = %+v, %v", doc, err)
	}
}

// Every request the node would refuse is refused before an approval exists.
func TestWitnessPlanRefusals(t *testing.T) {
	f := newWitnessFixture(t, witnessTestPublic)
	if res, _ := f.plan(t, witnessPlanBody); res.StatusCode != http.StatusConflict {
		t.Fatalf("a node without witness mode: %d", res.StatusCode)
	}
	f.capable(t)
	for name, body := range map[string]string{
		"no node":            `{"channel_id":"nc-bark","bark_url":"http://127.0.0.1:7001"}`,
		"no channel":         `{"node_id":"node-w","bark_url":"http://127.0.0.1:7001"}`,
		"telegram channel":   `{"node_id":"node-w","channel_id":"nc-tg","bark_url":"http://127.0.0.1:7001"}`,
		"no bark url":        `{"node_id":"node-w","channel_id":"nc-bark"}`,
		"public bark url":    `{"node_id":"node-w","channel_id":"nc-bark","bark_url":"https://bark.example.com"}`,
		"bark url with path": `{"node_id":"node-w","channel_id":"nc-bark","bark_url":"http://127.0.0.1:7001/?k=1"}`,
		"reference on cp":    `{"node_id":"node-w","channel_id":"nc-bark","bark_url":"http://127.0.0.1:7001","reference_urls":["https://lattice.example.test/x"]}`,
		"plain http ref":     `{"node_id":"node-w","channel_id":"nc-bark","bark_url":"http://127.0.0.1:7001","reference_urls":["http://example.com"]}`,
		"four refs":          `{"node_id":"node-w","channel_id":"nc-bark","bark_url":"http://127.0.0.1:7001","reference_urls":["https://a.example","https://b.example","https://c.example","https://d.example"]}`,
		"fast interval":      `{"node_id":"node-w","channel_id":"nc-bark","bark_url":"http://127.0.0.1:7001","interval_seconds":5}`,
		"short hold":         `{"node_id":"node-w","channel_id":"nc-bark","bark_url":"http://127.0.0.1:7001","interval_seconds":30,"hold_seconds":45}`,
		"bad level":          `{"node_id":"node-w","channel_id":"nc-bark","bark_url":"http://127.0.0.1:7001","bark_level":"loud"}`,
	} {
		res, _ := f.plan(t, body)
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: %d", name, res.StatusCode)
		}
	}
	if len(f.st.Approvals()) != 0 {
		t.Fatalf("a refused plan left an approval: %+v", f.st.Approvals())
	}

	noURL := newWitnessFixture(t, "")
	noURL.capable(t)
	if res, _ := noURL.plan(t, witnessPlanBody); res.StatusCode != http.StatusConflict {
		t.Fatalf("a server without a public URL: %d", res.StatusCode)
	}
}

// Approving renders the task with the key in it, from the channel as it is
// now; a key changed since the plan makes the approval stale, and the
// approval is rejected rather than left to be retried.
func TestWitnessApprovalCarriesTheReviewedKeyOnly(t *testing.T) {
	f := newWitnessFixture(t, witnessTestPublic)
	f.capable(t)
	_, a := f.plan(t, witnessPlanBody)
	res := f.approve(t, a)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("approve: %d", res.StatusCode)
	}
	tasks := f.st.Tasks()
	if len(tasks) != 1 || tasks[0].ApprovalID != a.ID || tasks[0].TimeoutSec != witnessApplyTaskTimeoutSec {
		t.Fatalf("tasks = %+v", tasks)
	}
	script := tasks[0].Script
	config, unit, _ := witnessPlanFiles(a.Plan)
	for _, want := range []string{
		"cat > " + witnessKeyPath + ".new <<'LATTICE_WITNESS_KEY_EOF", witnessTestKey + "\n",
		config, unit,
		"-witness " + witnessConfigPath + ".new -witness-check >/dev/null",
		`grep -q '"` + witnessCapability + `"'`,
		"systemctl restart " + witnessUnitName,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script lacks %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "set -x") || strings.Contains(script, "echo "+witnessTestKey) {
		t.Fatal("the script could print the key")
	}

	// A second plan, then the key changes before anyone approves it.
	_, b := f.plan(t, witnessPlanBody)
	if err := f.st.UpsertNotifyChannel(model.NotifyChannel{ID: "nc-bark", Name: "Bark urgent", Kind: "bark", Enabled: true,
		Config: map[string]string{"base_url": "https://bark.example.com", "key": "RotatedDeviceKey99"}}); err != nil {
		t.Fatal(err)
	}
	if res := f.approve(t, b); res.StatusCode != http.StatusConflict {
		t.Fatalf("approve after a key change: %d", res.StatusCode)
	}
	stored, _ := f.st.Approval(b.ID)
	if stored.Status != model.ApprovalRejected || !strings.Contains(stored.Reason, "device key of channel nc-bark changed") {
		t.Fatalf("stale approval = %+v", stored)
	}
	if len(f.st.Tasks()) != 1 {
		t.Fatal("a stale approval queued a task")
	}
}

// A node that stopped advertising witness mode does not get the task, and
// an approval without its task is refused rather than stranded.
func TestWitnessApprovalNeedsTheCapabilityAtDecision(t *testing.T) {
	f := newWitnessFixture(t, witnessTestPublic)
	f.capable(t)
	_, a := f.plan(t, witnessPlanBody)
	res := doJSON(t, f.handler, http.MethodPost, "/api/network/approvals/approve",
		`{"approval_id":"`+a.ID+`","queue_apply":false,"plan_sha256":"`+planSHA256(a.Plan)+`"}`, f.cookies, f.csrf)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("approve without queue_apply: %d", res.StatusCode)
	}
	if stored, _ := f.st.Approval(a.ID); stored.Status != model.ApprovalPending {
		t.Fatalf("an unqueued approve moved the approval: %+v", stored)
	}
	f.beat(t, `{"node_id":"node-w","version":"0.3.9","metrics":{}}`)
	if res := f.approve(t, a); res.StatusCode != http.StatusConflict {
		t.Fatalf("approve without the capability: %d", res.StatusCode)
	}
	if stored, _ := f.st.Approval(a.ID); stored.Status != model.ApprovalPending {
		t.Fatalf("the approval moved: %+v", stored)
	}
}

// Deciding a witness plan needs notify:admin on top of network:apply, and so
// does reading it.
func TestWitnessApprovalScopes(t *testing.T) {
	f := newWitnessFixture(t, witnessTestPublic)
	f.capable(t)
	_, a := f.plan(t, witnessPlanBody)
	if got := approvalDecisionExtraScope(a); got != "notify:admin" {
		t.Fatalf("decision extra scope = %q", got)
	}
	applyOnly := createPAT(t, f.handler, f.cookies, f.csrf, []string{"network:apply", "network:plan"}, nil)
	res := doBearerJSON(t, f.handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": a.ID, "queue_apply": true, "plan_sha256": planSHA256(a.Plan)})), applyOnly)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("network-only decision: %d", res.StatusCode)
	}
	planOnly := createPAT(t, f.handler, f.cookies, f.csrf, []string{"network:plan", "node:admin"}, nil)
	res = doBearerJSON(t, f.handler, http.MethodPost, "/api/notify/witness/plan", witnessPlanBody, planOnly)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("plan without notify:admin: %d", res.StatusCode)
	}
	confined := createPAT(t, f.handler, f.cookies, f.csrf, []string{"notify:admin", "network:plan", "node:admin"}, []string{"node-w"})
	res = doBearerJSON(t, f.handler, http.MethodPost, "/api/notify/witness/plan", witnessPlanBody, confined)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a node-confined token planned a witness: %d", res.StatusCode)
	}
}

// The task result moves the approval, and the status view reads the relayed
// witness state against the applied plan.
func TestWitnessStatusFollowsTheTaskAndTheHeartbeat(t *testing.T) {
	f := newWitnessFixture(t, witnessTestPublic)
	f.capable(t)
	_, a := f.plan(t, witnessPlanBody)
	if res := f.approve(t, a); res.StatusCode != http.StatusOK {
		t.Fatalf("approve: %d", res.StatusCode)
	}
	status := func() witnessStatusResponse {
		return decodeBody[witnessStatusResponse](t, doJSON(t, f.handler, http.MethodGet, "/api/notify/witness", "", f.cookies, ""))
	}
	got := status()
	if got.HealthURL != witnessTestPublic+"/readyz" || len(got.CapableNodes) != 1 || len(got.Nodes) != 1 {
		t.Fatalf("status = %+v", got)
	}
	if n := got.Nodes[0]; n.Pending == nil || n.Pending.Status != model.ApprovalApproved || n.Configured != nil || n.Report != nil {
		t.Fatalf("before the result = %+v", n)
	}

	task := f.st.Tasks()[0]
	if err := f.srv.handleApprovalTaskResult(httptest.NewRequest(http.MethodPost, "/api/agent/task-result", nil), task, model.TaskResult{ExitCode: 0, Stdout: "lattice witness: active"}); err != nil {
		t.Fatal(err)
	}
	if stored, _ := f.st.Approval(a.ID); stored.Status != model.ApprovalApplied {
		t.Fatalf("approval after success = %+v", stored)
	}
	config, _, _ := witnessPlanFiles(a.Plan)
	sha := witnessConfigSHA(config)
	checked := time.Now().UTC().Add(-10 * time.Second).Format(time.RFC3339)
	f.beat(t, `{"node_id":"node-w","version":"0.3.10-alpha.2","capabilities":["`+witnessCapability+`"],"metrics":{},
		"witness":{"version":1,"config_sha256":"`+sha+`","phase":"watching","health_url":"`+witnessTestPublic+`/readyz",
		"last_check_at":"`+checked+`","last_check_ok":true,"last_check_detail":"`+strings.Repeat("x", 200)+`",
		"last_push_at":"`+checked+`","last_push_kind":"recovery","last_push_ok":true,"pushes":2,"device_key":"nope"}}`)
	got = status()
	n := got.Nodes[0]
	if n.Configured == nil || n.Configured.ConfigSHA256 != sha || n.Configured.ChannelName != "Bark urgent" || n.Pending != nil {
		t.Fatalf("after the result = %+v", n)
	}
	if n.Report == nil || n.Report.Phase != "watching" || !n.ReportFresh || !n.ConfigMatches || n.Report.Pushes != 2 || n.Report.LastPushKind != "recovery" {
		t.Fatalf("report = %+v", n)
	}
	if len(n.Report.LastCheckDetail) != 64 {
		t.Fatalf("detail not bounded: %d bytes", len(n.Report.LastCheckDetail))
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "nope") || strings.Contains(string(raw), witnessTestKey) {
		t.Fatalf("status carried something it should not: %s", raw)
	}

	// An unknown phase and a malformed hash are not passed on as they came.
	f.beat(t, `{"node_id":"node-w","version":"0.3.10-alpha.2","capabilities":["`+witnessCapability+`"],"metrics":{},
		"witness":{"version":1,"config_sha256":"not-a-sha","phase":"<b>exploded</b>","last_push_kind":"spam"}}`)
	n = status().Nodes[0]
	if n.Report.Phase != "unknown" || n.Report.ConfigSHA256 != "" || n.ConfigMatches || n.Report.LastPushKind != "" {
		t.Fatalf("normalised report = %+v", n.Report)
	}

	// A remove plan applied: nothing is configured any more.
	_, rm := f.plan(t, `{"node_id":"node-w","remove":true}`)
	if rm.Action != witnessRemoveAction || !strings.Contains(rm.Plan, "Remove "+witnessConfigDir) {
		t.Fatalf("remove plan = %+v", rm)
	}
	if res := f.approve(t, rm); res.StatusCode != http.StatusOK {
		t.Fatalf("approve remove: %d", res.StatusCode)
	}
	var removeTask model.Task
	for _, tk := range f.st.Tasks() {
		if tk.ApprovalID == rm.ID {
			removeTask = tk
		}
	}
	if !strings.Contains(removeTask.Script, "systemctl disable --now "+witnessUnitName) || !strings.Contains(removeTask.Script, "rm -rf "+witnessConfigDir) {
		t.Fatalf("remove script = %s", removeTask.Script)
	}
	if err := f.srv.handleApprovalTaskResult(httptest.NewRequest(http.MethodPost, "/api/agent/task-result", nil), removeTask, model.TaskResult{ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
	if n := status().Nodes[0]; n.Configured != nil {
		t.Fatalf("still configured after a remove = %+v", n.Configured)
	}
}

// A failed apply rejects the approval with the task's reason and shows as
// the last failure.
func TestWitnessFailedApplyIsShown(t *testing.T) {
	f := newWitnessFixture(t, witnessTestPublic)
	f.capable(t)
	_, a := f.plan(t, witnessPlanBody)
	if res := f.approve(t, a); res.StatusCode != http.StatusOK {
		t.Fatalf("approve: %d", res.StatusCode)
	}
	task := model.Task{ID: id.New("task"), ApprovalID: a.ID, Targets: []string{"node-w"}}
	if err := f.srv.handleWitnessTaskResult(httptest.NewRequest(http.MethodPost, "/", nil), a, task, model.TaskResult{ExitCode: 1, Stderr: "lattice witness: this agent has no witness mode; update the agent first"}); err != nil {
		t.Fatal(err)
	}
	stored, _ := f.st.Approval(a.ID)
	if stored.Status != model.ApprovalRejected || !strings.Contains(stored.Reason, "no witness mode") {
		t.Fatalf("approval = %+v", stored)
	}
	got := decodeBody[witnessStatusResponse](t, doJSON(t, f.handler, http.MethodGet, "/api/notify/witness", "", f.cookies, ""))
	if len(got.Nodes) != 1 || got.Nodes[0].LastFailed == nil || got.Nodes[0].LastFailed.ApprovalID != a.ID {
		t.Fatalf("status = %+v", got)
	}
}

// A witness whose service stopped leaves its last status on disk and the
// agent keeps relaying it. The relay is fresh, so only relayed_at against the
// last check, both on the node's clock, shows that nothing is watching.
func TestWitnessStoppedWitnessReadsAsStale(t *testing.T) {
	f := newWitnessFixture(t, witnessTestPublic)
	f.capable(t)
	status := func() witnessNodeView {
		t.Helper()
		got := decodeBody[witnessStatusResponse](t, doJSON(t, f.handler, http.MethodGet, "/api/notify/witness", "", f.cookies, ""))
		if len(got.Nodes) != 1 {
			t.Fatalf("nodes = %+v", got.Nodes)
		}
		return got.Nodes[0]
	}
	// The node's clock runs an hour ahead of this server's; only the gap
	// between its own two times counts.
	nodeNow := time.Now().UTC().Add(time.Hour)
	beat := func(started, checked time.Time, relayed string) {
		t.Helper()
		f.beat(t, `{"node_id":"node-w","version":"0.3.10-alpha.3","capabilities":["`+witnessCapability+`"],"metrics":{},
			"witness":{"version":1,"phase":"watching","interval_seconds":30,"started_at":"`+started.Format(time.RFC3339)+`",
			"last_check_at":"`+checked.Format(time.RFC3339)+`","last_check_ok":true`+relayed+`}}`)
	}
	relayedNow := `,"relayed_at":"` + nodeNow.Format(time.RFC3339) + `"`

	beat(nodeNow.Add(-time.Hour), nodeNow.Add(-20*time.Second), relayedNow)
	if n := status(); !n.ReportFresh || n.CheckStale {
		t.Fatalf("a witness that checked 20 s ago = fresh %v stale %v", n.ReportFresh, n.CheckStale)
	}
	beat(nodeNow.Add(-time.Hour), nodeNow.Add(-10*time.Minute), relayedNow)
	if n := status(); !n.ReportFresh || !n.CheckStale {
		t.Fatalf("a witness silent for 10 min = fresh %v stale %v", n.ReportFresh, n.CheckStale)
	}
	// Just restarted after a long stop: the start counts as a sign of life.
	beat(nodeNow.Add(-5*time.Second), nodeNow.Add(-10*time.Minute), relayedNow)
	if n := status(); n.CheckStale {
		t.Fatal("a witness that just started reads as stopped")
	}
	// Without relayed_at nothing can be judged, and nothing is claimed.
	beat(nodeNow.Add(-time.Hour), nodeNow.Add(-10*time.Minute), "")
	if n := status(); n.CheckStale {
		t.Fatal("a report without relayed_at was judged stale")
	}
}

func TestWitnessCheckStaleAfterFollowsTheInterval(t *testing.T) {
	for _, tc := range []struct {
		interval int
		want     time.Duration
	}{{0, 2 * time.Minute}, {15, 2 * time.Minute}, {30, 2 * time.Minute}, {60, 3 * time.Minute}, {600, 30 * time.Minute}} {
		if got := witnessCheckStaleAfter(witnessReport{IntervalSeconds: tc.interval}); got != tc.want {
			t.Errorf("interval %d: stale after %s, want %s", tc.interval, got, tc.want)
		}
	}
	at := time.Date(2026, 10, 3, 3, 0, 0, 0, time.UTC)
	r := witnessReport{IntervalSeconds: 600, LastCheckAt: at, RelayedAt: at.Add(29 * time.Minute)}
	if witnessCheckStale(r) {
		t.Fatal("a 600 s witness 29 min after its check reads as stopped")
	}
	r.RelayedAt = at.Add(31 * time.Minute)
	if !witnessCheckStale(r) {
		t.Fatal("a 600 s witness 31 min after its check reads as alive")
	}
}

// A classified reason is bounded to 64 bytes without splitting a character.
func TestWitnessShortTextCutsOnARuneBoundary(t *testing.T) {
	in := strings.Repeat("a", 63) + "é" + "tail"
	got := witnessShortText(in)
	if got != strings.Repeat("a", 63) || !utf8.ValidString(got) {
		t.Fatalf("short text = %q (%d bytes)", got, len(got))
	}
	if got := witnessShortText("http 503\x00\xff"); got != "http 503" {
		t.Fatalf("control and invalid bytes = %q", got)
	}
	if got := witnessShortText(strings.Repeat("界", 30)); len(got) != 63 || !utf8.ValidString(got) {
		t.Fatalf("three-byte runes = %d bytes, valid %v", len(got), utf8.ValidString(got))
	}
}

// At decision the plan's files are checked as strictly as when the plan was
// made: the unit this server writes, a valid config in the form it writes,
// the key and state files the scripts use, and the SHA-256 the header shows.
func TestWitnessDecisionRefusesPlanFilesThatDoNotCheckOut(t *testing.T) {
	f := newWitnessFixture(t, witnessTestPublic)
	f.capable(t)
	_, base := f.plan(t, witnessPlanBody)
	config, unit, err := witnessPlanFiles(base.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := witnessConfigureFiles(base); err != nil {
		t.Fatalf("the plan this server made does not check out: %v", err)
	}
	headerSHA := approvalPlanField(base.Plan, witnessFieldConfigSHA)
	withConfig := func(plan, newConfig string, fixHeader bool) string {
		plan = strings.Replace(plan, config, newConfig, 1)
		if fixHeader {
			plan = strings.Replace(plan, witnessFieldConfigSHA+": "+headerSHA, witnessFieldConfigSHA+": "+witnessConfigSHA(newConfig), 1)
		}
		return plan
	}
	for name, tc := range map[string]struct {
		plan string
		want string
	}{
		"unit": {strings.Replace(base.Plan, unit, strings.Replace(unit, "NoNewPrivileges=yes\n", "ExecStartPre=/bin/sh -c id\n", 1), 1), "the unit is not the one"},
		"sha":  {withConfig(base.Plan, strings.Replace(config, `"interval_seconds": 30`, `"interval_seconds": 45`, 1), false), "SHA-256 is not the one the plan shows"},
		"key file": {withConfig(base.Plan, strings.Replace(config, `"bark_device_key_file": "`+witnessKeyPath+`"`, `"bark_device_key_file": "/etc/shadow"`, 1), true),
			"another version, key file or state file"},
		"extra field": {withConfig(base.Plan, strings.Replace(config, "{\n", "{\n  \"exec\": \"id\",\n", 1), true), "not in the form this server writes"},
		"invalid":     {withConfig(base.Plan, strings.Replace(config, "http://127.0.0.1:7001", "http://10.0.0.7:7001", 1), true), "loopback"},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.plan == base.Plan {
				t.Fatal("the tampering did not change the plan")
			}
			a := base
			a.ID = id.New("approval")
			a.Plan = tc.plan
			if err := f.st.UpsertApproval(a); err != nil {
				t.Fatal(err)
			}
			res := f.approve(t, a)
			res.Body.Close()
			if res.StatusCode != http.StatusConflict {
				t.Fatalf("approve: %d", res.StatusCode)
			}
			stored, _ := f.st.Approval(a.ID)
			if stored.Status != model.ApprovalRejected || !strings.Contains(stored.Reason, tc.want) {
				t.Fatalf("approval = %s %q, want reason containing %q", stored.Status, stored.Reason, tc.want)
			}
		})
	}
	for _, tk := range f.st.Tasks() {
		if tk.ApprovalID != "" {
			t.Fatalf("a refused plan queued a task: %+v", tk)
		}
	}
}

// Two plans can wait side by side and be approved in either order; the node
// runs whichever applied last, and both the status and the capability's
// enrolment follow that, not the order the plans were filed.
func TestWitnessLastAppliedPlanWinsWhateverOrderItWasFiled(t *testing.T) {
	f := newWitnessFixture(t, witnessTestPublic)
	f.capable(t)
	_, configure := f.plan(t, witnessPlanBody)
	_, remove := f.plan(t, `{"node_id":"node-w","remove":true}`)
	if !remove.CreatedAt.After(configure.CreatedAt) && !remove.CreatedAt.Equal(configure.CreatedAt) {
		t.Fatalf("filing order: configure %s, remove %s", configure.CreatedAt, remove.CreatedAt)
	}
	// MutateApproval keeps the UpdatedAt the callback sets; UpsertApproval
	// would stamp now, and two stamps can be equal.
	apply := func(a model.Approval, at time.Time) {
		t.Helper()
		if _, ok, err := f.st.MutateApproval(a.ID, func(row *model.Approval) bool {
			row.Status, row.UpdatedAt = model.ApprovalApplied, at
			return true
		}); err != nil || !ok {
			t.Fatalf("apply %s: %v %v", a.ID, ok, err)
		}
	}
	status := func() witnessNodeView {
		t.Helper()
		return decodeBody[witnessStatusResponse](t, doJSON(t, f.handler, http.MethodGet, "/api/notify/witness", "", f.cookies, "")).Nodes[0]
	}
	if enrolled, known := deriveWitness(f.srv, "node-w"); enrolled || known {
		t.Fatalf("nothing applied: derive = %v %v", enrolled, known)
	}
	// The remove, filed later, applied first; the configure applied after it.
	t0 := time.Now().UTC()
	apply(remove, t0)
	apply(configure, t0.Add(time.Minute))
	if n := status(); n.Configured == nil || n.Configured.ApprovalID != configure.ID {
		t.Fatalf("configured = %+v", n.Configured)
	}
	if enrolled, known := deriveWitness(f.srv, "node-w"); !enrolled || !known {
		t.Fatalf("configure applied last: derive = %v %v", enrolled, known)
	}
	// A later remove takes the node off.
	_, again := f.plan(t, `{"node_id":"node-w","remove":true}`)
	apply(again, t0.Add(2*time.Minute))
	if n := status(); n.Configured != nil {
		t.Fatalf("still configured after a later remove = %+v", n.Configured)
	}
	if enrolled, known := deriveWitness(f.srv, "node-w"); enrolled || !known {
		t.Fatalf("remove applied last: derive = %v %v", enrolled, known)
	}
	// A plan filed before the last applied one is still pending, and shown.
	_, waiting := f.plan(t, witnessPlanBody)
	stored, _ := f.st.Approval(waiting.ID)
	stored.CreatedAt = configure.CreatedAt.Add(-time.Hour)
	if err := f.st.UpsertApproval(stored); err != nil {
		t.Fatal(err)
	}
	if n := status(); n.Pending == nil || n.Pending.ApprovalID != waiting.ID {
		t.Fatalf("an older plan still waiting is not shown: %+v", n.Pending)
	}
}
