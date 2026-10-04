package server

import (
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/secret"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// newWitnessCipherFixture is newWitnessFixture on a file-backed store with
// the at-rest cipher on, as production runs it, so the bytes on disk can be
// read back. It returns the data directory.
func newWitnessCipherFixture(t *testing.T) (witnessFixture, string) {
	t.Helper()
	key := make([]byte, secret.KeySize)
	for i := range key {
		key[i] = byte(0x40 + i)
	}
	cph, err := secret.NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	st, err := store.OpenWithCipher(filepath.Join(dir, "state.json"), cph)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true, PublicURL: witnessTestPublic})
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
	return witnessFixture{srv: srv, handler: handler, st: st, cookies: cookies, csrf: csrf, token: token}, dir
}

// witnessStepUp issues a step-up grant to the fixture's admin session.
func (f witnessFixture) witnessStepUp(t *testing.T) string {
	t.Helper()
	user, ok := f.srv.store.UserByUsername("admin")
	if !ok {
		t.Fatal("admin user missing")
	}
	sessionID := ""
	for _, cookie := range f.cookies {
		if cookie.Name == "lattice_session" {
			sessionID = cookie.Value
		}
	}
	grant, _, err := f.srv.issueStepUpGrant(principal{Principal: rbac.Principal{ActorID: user.ID}, sessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

// witnessToken mints an API token; withReveal adds secrets:reveal through its
// own door.
func (f witnessFixture) witnessToken(t *testing.T, scopes []string, withReveal bool) string {
	t.Helper()
	body := map[string]any{"name": "witness-key", "scopes": scopes, "server_allowlist": []string{}}
	if withReveal {
		body["scopes"] = append(append([]string(nil), scopes...), rbac.SecretRevealScope)
		body["step_up_grant"] = f.witnessStepUp(t)
	}
	res := doJSON(t, f.handler, http.MethodPost, "/api/tokens", string(mustJSON(t, body)), f.cookies, f.csrf)
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("token create: %d %s", res.StatusCode, raw)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out.Token
}

// The witness device key reaches the node inside the apply task's script and
// nowhere else: on disk the script is sealed with the master key, and no read
// API returns it without the secret-reveal gate.
func TestWitnessDeviceKeyIsNotAtRestInPlaintextNorReadableWithoutReveal(t *testing.T) {
	f, dir := newWitnessCipherFixture(t)
	f.capable(t)
	_, a := f.plan(t, witnessPlanBody)
	if res := f.approve(t, a); res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("approve: %d %s", res.StatusCode, b)
	}

	// Control: the in-memory task does carry the key, because the node needs
	// it. Every absence asserted below is therefore a real redaction.
	tasks := f.st.Tasks()
	if len(tasks) != 1 || !strings.Contains(tasks[0].Script, witnessTestKey) {
		t.Fatalf("control failed: the queued task should carry the key for the node: %+v", tasks)
	}
	task := tasks[0]

	// The node leases the task (the one intended recipient) and reports.
	lease := doAgentRaw(t, f.handler, http.MethodGet, "/api/agent/tasks?node_id=node-w", "", f.token)
	if lease.Code != http.StatusOK || !strings.Contains(lease.Body.String(), witnessTestKey) {
		t.Fatalf("agent lease: %d, carries key=%v", lease.Code, strings.Contains(lease.Body.String(), witnessTestKey))
	}
	var leased []struct {
		ID      string `json:"id"`
		LeaseID string `json:"lease_id"`
	}
	if err := json.Unmarshal(lease.Body.Bytes(), &leased); err != nil || len(leased) != 1 {
		t.Fatalf("lease body: %v %d", err, len(leased))
	}
	config, _, _ := witnessPlanFiles(a.Plan)
	stdout := "lattice witness: active, config sha256 " + witnessConfigSHA(config) + "\n"
	result := `{"node_id":"node-w","result":{"task_id":"` + leased[0].ID + `","lease_id":"` + leased[0].LeaseID + `","exit_code":0,"stdout":` + string(mustJSON(t, stdout)) + `}}`
	if rec := doAgentRaw(t, f.handler, http.MethodPost, "/api/agent/task-result", result, f.token); rec.Code != http.StatusOK {
		t.Fatalf("task result: %d %s", rec.Code, rec.Body.String())
	}
	if stored, _ := f.st.Approval(a.ID); stored.Status != model.ApprovalApplied {
		t.Fatalf("approval after result = %s", stored.Status)
	}

	// At rest: no file the store wrote (state, audit WAL and anchor, any
	// sidecar) holds the key, and the persisted task script is an envelope.
	files := 0
	if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files++
		if strings.Contains(string(raw), witnessTestKey) {
			t.Errorf("%s holds the device key in plaintext", filepath.Base(path))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("the store wrote no files")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var persisted struct {
		Tasks map[string]model.Task `json:"tasks"`
	}
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if p, ok := persisted.Tasks[task.ID]; !ok || !secret.IsEnvelope(p.Script) {
		t.Fatalf("persisted task script is not sealed (present=%v)", ok)
	}

	// Read APIs, as a full administrator session without step-up: none of
	// them carries the key.
	for _, path := range []string{
		"/api/tasks",
		"/api/tasks?approval_id=" + a.ID,
		"/api/tasks/counts",
		"/api/task-results",
		"/api/task-results?task_id=" + task.ID,
		"/api/network/approvals",
		"/api/audit",
		"/api/notify/witness",
		"/api/notify/channels",
	} {
		res := doJSON(t, f.handler, http.MethodGet, path, "", f.cookies, "")
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, res.StatusCode, body)
		}
		if strings.Contains(string(body), witnessTestKey) {
			t.Errorf("GET %s returns the device key", path)
		}
	}

	// The one door that returns a script: refused to a session without
	// step-up and to a token without secrets:reveal, even one holding
	// task:read and notify:admin.
	revealBody := `{"id":"` + task.ID + `"}`
	res := doJSON(t, f.handler, http.MethodPost, "/api/tasks/reveal-script", revealBody, f.cookies, f.csrf)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden || strings.Contains(string(body), witnessTestKey) {
		t.Fatalf("reveal without step-up: %d, carries key=%v", res.StatusCode, strings.Contains(string(body), witnessTestKey))
	}
	noReveal := f.witnessToken(t, []string{"task:read", "notify:admin"}, false)
	tres := doBearerJSON(t, f.handler, http.MethodPost, "/api/tasks/reveal-script", revealBody, noReveal)
	body, _ = io.ReadAll(tres.Body)
	tres.Body.Close()
	if tres.StatusCode != http.StatusForbidden || strings.Contains(string(body), witnessTestKey) {
		t.Fatalf("reveal by a token without secrets:reveal: %d, carries key=%v", tres.StatusCode, strings.Contains(string(body), witnessTestKey))
	}
}

// The task-script door used to check task:read on the node and nothing about
// notify:admin behind the reveal gate, so it handed a Bark key, which the
// notify API never returns to anyone, to a principal the witness plan itself
// refuses to show the plan to. It now asks for notify:admin as well, and the
// answer to a principal that holds it is unchanged.
func TestWitnessTaskScriptRevealAsksForNotifyAdmin(t *testing.T) {
	f, _ := newWitnessCipherFixture(t)
	f.capable(t)
	_, a := f.plan(t, witnessPlanBody)
	if res := f.approve(t, a); res.StatusCode != http.StatusOK {
		t.Fatalf("approve: %d", res.StatusCode)
	}
	task := f.st.Tasks()[0]

	tok := f.witnessToken(t, []string{"task:read"}, true)
	// The same principal cannot read the witness approval.
	ares := doBearerJSON(t, f.handler, http.MethodGet, "/api/network/approvals", "", tok)
	abody, _ := io.ReadAll(ares.Body)
	ares.Body.Close()
	if strings.Contains(string(abody), a.ID) {
		t.Fatalf("a task:read token listed the witness approval: %d", ares.StatusCode)
	}
	expectScriptOwnerRefusal(t, f.handler, task.ID, tok, witnessTestKey, "notify:admin")

	// notify:admin on a node-restricted token is not the unconfined scope
	// the witness plan asks for.
	confined := revealScopeToken(t, f.srv, f.handler, f.cookies, f.csrf, []string{"task:read", "notify:admin"}, []string{"node-w"})
	expectScriptOwnerRefusal(t, f.handler, task.ID, confined, witnessTestKey, "notify:admin")

	admin := f.witnessToken(t, []string{"task:read", "notify:admin"}, true)
	got := expectScriptRevealed(t, f.handler, task.ID, admin, witnessTestKey)
	if got.ID != task.ID || got.Interpreter != task.Interpreter || got.Script != task.Script ||
		got.ScriptSHA256 != scriptSHA256(task.Script) || got.ScriptSizeBytes != len(task.Script) {
		t.Fatalf("allowed reveal changed shape: %+v", got)
	}
}

// A rerun copies its source's script and not its approval link, so the gate
// follows the rerun back to the source's approval; and once the source is
// deleted, only a full administrator can reveal the copy.
func TestWitnessRerunScriptRevealFollowsTheSourceApproval(t *testing.T) {
	f, _ := newWitnessCipherFixture(t)
	f.capable(t)
	_, a := f.plan(t, witnessPlanBody)
	if res := f.approve(t, a); res.StatusCode != http.StatusOK {
		t.Fatalf("approve: %d", res.StatusCode)
	}
	source := f.st.Tasks()[0]
	res := doJSON(t, f.handler, http.MethodPost, "/api/tasks/rerun", `{"id":"`+source.ID+`"}`, f.cookies, f.csrf)
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("rerun: %d %s", res.StatusCode, raw)
	}
	var rerun model.Task
	for _, task := range f.st.Tasks() {
		if task.RerunOfTaskID == source.ID {
			rerun = task
		}
	}
	if rerun.ID == "" || rerun.ApprovalID != "" || !strings.Contains(rerun.Script, witnessTestKey) {
		t.Fatalf("control failed: the rerun should copy the key and not the approval link: %+v", rerun)
	}

	reader := f.witnessToken(t, []string{"task:read"}, true)
	notifyAdmin := f.witnessToken(t, []string{"task:read", "notify:admin"}, true)
	expectScriptOwnerRefusal(t, f.handler, rerun.ID, reader, witnessTestKey, "notify:admin")
	expectScriptRevealed(t, f.handler, rerun.ID, notifyAdmin, witnessTestKey)

	// A rerun of the rerun names the original as its source too.
	res = doJSON(t, f.handler, http.MethodPost, "/api/tasks/rerun", `{"id":"`+rerun.ID+`"}`, f.cookies, f.csrf)
	raw, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("rerun of the rerun: %d %s", res.StatusCode, raw)
	}
	var second model.Task
	for _, task := range f.st.Tasks() {
		if task.RerunOfTaskID == source.ID && task.ID != rerun.ID {
			second = task
		}
	}
	if second.ID == "" {
		t.Fatal("the rerun of the rerun should name the original task as its source")
	}
	expectScriptOwnerRefusal(t, f.handler, second.ID, reader, witnessTestKey, "notify:admin")
	expectScriptRevealed(t, f.handler, second.ID, notifyAdmin, witnessTestKey)

	res = doJSON(t, f.handler, http.MethodPost, "/api/tasks/delete", `{"id":"`+source.ID+`"}`, f.cookies, f.csrf)
	raw, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("delete source: %d %s", res.StatusCode, raw)
	}
	expectScriptOwnerRefusal(t, f.handler, rerun.ID, notifyAdmin, witnessTestKey, "full administrator")
	res = doJSON(t, f.handler, http.MethodPost, "/api/tasks/reveal-script",
		`{"id":"`+rerun.ID+`","step_up_grant":"`+f.witnessStepUp(t)+`"}`, f.cookies, f.csrf)
	raw, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.Contains(string(raw), witnessTestKey) {
		t.Fatalf("a full administrator with step-up should still reveal an orphaned rerun: %d", res.StatusCode)
	}
}
