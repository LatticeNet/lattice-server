package server

import (
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// updateWitnessPlanGolden regenerates testdata/witness_configure_plan.golden.
// The file was written from origin/integration at 9e4fdaf (a118), before the
// health URL override existed: a plan without an override must stay byte for
// byte what a118 rendered, so its SHA-256, which the approval hashes, does not
// move under a plan an operator already reviewed.
var updateWitnessPlanGolden = flag.Bool("update-witness-golden", false, "rewrite the witness configure plan golden file")

const witnessTestReadyURL = "https://lattice-ready.example.test/readyz"

func witnessGoldenPlan(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "witness_configure_plan.golden"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func witnessPlanDoc(t *testing.T, plan string) witnessConfigDoc {
	t.Helper()
	config, _, err := witnessPlanFiles(plan)
	if err != nil {
		t.Fatal(err)
	}
	var doc witnessConfigDoc
	if err := json.Unmarshal([]byte(config), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func witnessPlanBodyWith(extra string) string {
	return `{"node_id":"node-w","channel_id":"nc-bark","bark_url":"http://127.0.0.1:7001",` + extra + `}`
}

func TestWitnessPlanWithoutAnOverrideIsByteIdenticalToA118(t *testing.T) {
	f := newWitnessFixture(t, witnessTestPublic)
	f.capable(t)
	golden := filepath.Join("testdata", "witness_configure_plan.golden")
	for name, body := range map[string]string{
		"no health_url":     witnessPlanBody,
		"empty health_url":  witnessPlanBodyWith(`"health_url":"  "`),
		"the default named": witnessPlanBodyWith(`"health_url":"` + witnessTestPublic + `/readyz"`),
	} {
		res, a := f.plan(t, body)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s: plan: %d", name, res.StatusCode)
		}
		if *updateWitnessPlanGolden && name == "no health_url" {
			if err := os.WriteFile(golden, []byte(a.Plan), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want := witnessGoldenPlan(t)
		if a.Plan != want {
			t.Fatalf("%s: the plan without an override changed:\n--- got\n%s\n--- want\n%s", name, a.Plan, want)
		}
		if planSHA256(a.Plan) != planSHA256(want) {
			t.Fatalf("%s: the plan's SHA-256 moved", name)
		}
	}
}

// An operator's health URL replaces <public URL>/readyz in the config, is
// named in the reviewed text, is what the approval hashes, and is what the
// apply task writes; the status shows it per node while the top-level
// health_url stays the server's default.
func TestWitnessHealthURLOverrideSurvivesDecideAndApply(t *testing.T) {
	f := newWitnessFixture(t, witnessTestPublic)
	f.capable(t)
	res, a := f.plan(t, witnessPlanBodyWith(`"health_url":"  `+witnessTestReadyURL+` "`))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("plan: %d", res.StatusCode)
	}
	doc := witnessPlanDoc(t, a.Plan)
	if doc.HealthURL != witnessTestReadyURL {
		t.Fatalf("config health_url = %q", doc.HealthURL)
	}
	if want := "  " + witnessTestReadyURL + "\nSet by the operator, in place of " + witnessTestPublic + "/readyz\n"; !strings.Contains(a.Plan, want) {
		t.Fatalf("plan lacks the override line %q:\n%s", want, a.Plan)
	}
	if strings.Contains(a.Plan, `"health_url": "`+witnessTestPublic) {
		t.Fatal("the config still watches the public URL")
	}
	config, _, _ := witnessPlanFiles(a.Plan)
	if approvalPlanField(a.Plan, witnessFieldConfigSHA) != witnessConfigSHA(config) {
		t.Fatal("the plan's config_sha256 is not the hash of the overridden config")
	}
	if planSHA256(a.Plan) == planSHA256(witnessGoldenPlan(t)) {
		t.Fatal("the override did not change the hashed plan")
	}
	var audited bool
	for _, ev := range f.st.AuditEvents() {
		if ev.Action == "notify.witness.plan" && ev.Metadata["health_url"] == witnessTestReadyURL {
			audited = true
		}
	}
	if !audited {
		t.Fatal("the audit event does not name the operator's health URL")
	}

	// Decide: the approval re-reads the key and re-checks the files.
	if res := f.approve(t, a); res.StatusCode != http.StatusOK {
		t.Fatalf("approve: %d", res.StatusCode)
	}
	tasks := f.st.Tasks()
	if len(tasks) != 1 || !strings.Contains(tasks[0].Script, config) || !strings.Contains(tasks[0].Script, `"health_url": "`+witnessTestReadyURL+`"`) {
		t.Fatalf("the apply task does not write the overridden config: %+v", tasks)
	}
	// Apply renders the same script from the stored approval.
	stored, _ := f.st.Approval(a.ID)
	if script, err := f.srv.witnessApplyScript(stored); err != nil || !strings.Contains(script, config) {
		t.Fatalf("apply script = %v", err)
	}
	if err := f.srv.handleApprovalTaskResult(httptest.NewRequest(http.MethodPost, "/api/agent/task-result", nil), tasks[0], model.TaskResult{ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
	got := decodeBody[witnessStatusResponse](t, doJSON(t, f.handler, http.MethodGet, "/api/notify/witness", "", f.cookies, ""))
	if got.HealthURL != witnessTestPublic+"/readyz" {
		t.Fatalf("top-level health_url = %q, want the server default", got.HealthURL)
	}
	if len(got.Nodes) != 1 || got.Nodes[0].Configured == nil || got.Nodes[0].Configured.HealthURL != witnessTestReadyURL {
		t.Fatalf("configured view = %+v", got.Nodes)
	}
}

// Without a public URL the default cannot be derived, but an operator's
// health URL needs none; the plan says there was nothing to derive.
func TestWitnessHealthURLOverrideWorksWithoutAPublicURL(t *testing.T) {
	f := newWitnessFixture(t, "")
	f.capable(t)
	if res, _ := f.plan(t, witnessPlanBody); res.StatusCode != http.StatusConflict {
		t.Fatalf("no override, no public URL: %d", res.StatusCode)
	}
	res, a := f.plan(t, witnessPlanBodyWith(`"health_url":"`+witnessTestReadyURL+`"`))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("override, no public URL: %d", res.StatusCode)
	}
	if !strings.Contains(a.Plan, witnessTestReadyURL+"\nSet by the operator; this server has no public URL") {
		t.Fatalf("plan:\n%s", a.Plan)
	}
	if res := f.approve(t, a); res.StatusCode != http.StatusOK {
		t.Fatalf("approve: %d", res.StatusCode)
	}
}

// An override is held to the shape of a readiness check on another name for
// the control plane, and the references must not sit on either of its names.
func TestWitnessHealthURLOverrideRefusals(t *testing.T) {
	f := newWitnessFixture(t, witnessTestPublic)
	f.capable(t)
	for name, tc := range map[string]struct{ extra, want string }{
		"http":                {`"health_url":"http://lattice-ready.example.test/readyz"`, "https"},
		"http on loopback":    {`"health_url":"http://127.0.0.1:8080/readyz"`, "https"},
		"other scheme":        {`"health_url":"ftp://lattice-ready.example.test/readyz"`, "https"},
		"not absolute":        {`"health_url":"lattice-ready.example.test/readyz"`, "absolute"},
		"no path":             {`"health_url":"https://lattice-ready.example.test"`, "/readyz"},
		"root path":           {`"health_url":"https://lattice-ready.example.test/"`, "/readyz"},
		"wrong path":          {`"health_url":"https://lattice-ready.example.test/healthz"`, "/readyz"},
		"trailing slash":      {`"health_url":"https://lattice-ready.example.test/readyz/"`, "/readyz"},
		"prefixed path":       {`"health_url":"https://lattice-ready.example.test/x/readyz"`, "/readyz"},
		"encoded path":        {`"health_url":"https://lattice-ready.example.test/ready%7Az"`, "/readyz"},
		"query":               {`"health_url":"https://lattice-ready.example.test/readyz?probe=1"`, "query"},
		"empty query":         {`"health_url":"https://lattice-ready.example.test/readyz?"`, "query"},
		"fragment":            {`"health_url":"https://lattice-ready.example.test/readyz#top"`, "fragment"},
		"empty fragment":      {`"health_url":"https://lattice-ready.example.test/readyz#"`, "fragment"},
		"credentials":         {`"health_url":"https://ops:secret@lattice-ready.example.test/readyz"`, "credentials"},
		"port zero":           {`"health_url":"https://lattice-ready.example.test:0/readyz"`, "port"},
		"port too high":       {`"health_url":"https://lattice-ready.example.test:65536/readyz"`, "port"},
		"port far too high":   {`"health_url":"https://lattice-ready.example.test:99999999999999999999/readyz"`, "port"},
		"inner space":         {`"health_url":"https://lattice-ready.example.test/ready z"`, ""},
		"reference on health": {`"health_url":"` + witnessTestReadyURL + `","reference_urls":["https://lattice-ready.example.test/cdn-cgi/trace"]`, "control plane's host"},
		"reference on public": {`"health_url":"` + witnessTestReadyURL + `","reference_urls":["https://lattice.example.test/x"]`, "control plane's public host"},
	} {
		res, _ := f.plan(t, witnessPlanBodyWith(tc.extra))
		body := decodeBody[model.APIErrorResponse](t, res)
		if res.StatusCode != http.StatusBadRequest || !strings.Contains(body.Error.Message, tc.want) {
			t.Fatalf("%s: %d %q, want 400 naming %q", name, res.StatusCode, body.Error.Message, tc.want)
		}
	}
	if len(f.st.Approvals()) != 0 {
		t.Fatalf("a refused plan left an approval: %+v", f.st.Approvals())
	}
	for _, ok := range []string{"https://lattice-ready.example.test:1/readyz", "https://lattice-ready.example.test:8443/readyz", "https://lattice-ready.example.test:65535/readyz"} {
		if err := checkWitnessHealthOverride(ok); err != nil {
			t.Fatalf("%s refused: %v", ok, err)
		}
	}
}

// At decision an override plan is checked against the override rules again,
// so a plan whose config moved a reference onto the control plane's public
// host is refused even with a header that matches it.
func TestWitnessDecisionRechecksTheOverride(t *testing.T) {
	f := newWitnessFixture(t, witnessTestPublic)
	f.capable(t)
	_, base := f.plan(t, witnessPlanBodyWith(`"health_url":"`+witnessTestReadyURL+`"`))
	config, _, err := witnessPlanFiles(base.Plan)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ from, to, want string }{
		"reference on public": {"https://www.apple.com/library/test/success.html", witnessTestPublic + "/x", "public host"},
		"query":               {witnessTestReadyURL, witnessTestReadyURL + "?x=1", "query"},
	} {
		t.Run(name, func(t *testing.T) {
			tampered := strings.Replace(config, tc.from, tc.to, 1)
			if tampered == config {
				t.Fatal("the tampering did not change the config")
			}
			a := base
			a.ID = id.New("approval")
			a.Plan = strings.Replace(strings.Replace(base.Plan, config, tampered, 1),
				witnessFieldConfigSHA+": "+witnessConfigSHA(config), witnessFieldConfigSHA+": "+witnessConfigSHA(tampered), 1)
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
				t.Fatalf("approval = %s %q, want a reason naming %q", stored.Status, stored.Reason, tc.want)
			}
		})
	}
	for _, tk := range f.st.Tasks() {
		if tk.ApprovalID != "" {
			t.Fatalf("a refused plan queued a task: %+v", tk)
		}
	}
}

// A configure approval a118 stored, with no override and its plan exactly as
// a118 rendered it, still decides, applies and shows what it watches.
func TestWitnessA118ApprovalStillDecidesAndApplies(t *testing.T) {
	f := newWitnessFixture(t, witnessTestPublic)
	f.capable(t)
	a := model.Approval{
		ID: id.New("approval"), NodeID: "node-w", Plugin: witnessPlugin, Action: witnessConfigureAction,
		Status: model.ApprovalPending, ActorID: "admin", Plan: witnessGoldenPlan(t), CreatedAt: time.Now().UTC(),
	}
	if err := f.st.UpsertApproval(a); err != nil {
		t.Fatal(err)
	}
	if res := f.approve(t, a); res.StatusCode != http.StatusOK {
		t.Fatalf("approve the a118 plan: %d", res.StatusCode)
	}
	config, _, _ := witnessPlanFiles(a.Plan)
	tasks := f.st.Tasks()
	if len(tasks) != 1 || tasks[0].ApprovalID != a.ID || !strings.Contains(tasks[0].Script, config) {
		t.Fatalf("tasks = %+v", tasks)
	}
	if err := f.srv.handleApprovalTaskResult(httptest.NewRequest(http.MethodPost, "/api/agent/task-result", nil), tasks[0], model.TaskResult{ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
	got := decodeBody[witnessStatusResponse](t, doJSON(t, f.handler, http.MethodGet, "/api/notify/witness", "", f.cookies, ""))
	if len(got.Nodes) != 1 || got.Nodes[0].Configured == nil || got.Nodes[0].Configured.HealthURL != witnessTestPublic+"/readyz" {
		t.Fatalf("configured view = %+v", got.Nodes)
	}
}
