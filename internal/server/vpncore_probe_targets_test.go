package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/store"
)

const probeTestHealthCustom = `{"probe_version":"0.2.0","engine":"sing-box","core_version":"1.13.19","uptime_s":3600,"inflight":0,"max_inflight":32,"targets":3,"capabilities":["custom_targets"]}`

// answerWithHealth is answer with a health body of the caller's choosing,
// for a probe that does or does not take custom targets.
func (f *fakeProbe) answerWithHealth(health string, status int, body string) {
	f.serve(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/health":
			_, _ = io.WriteString(w, health)
			return
		case "/v1/targets":
			_, _ = io.WriteString(w, `{"targets":[{"id":"gstatic-204","url":"https://www.gstatic.com/generate_204","expect":204}]}`)
			return
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
}

func probeAdmin(actor string) principal {
	return probeOperator(actor, probeScope, probeTargetsAdminScope)
}

func TestNormalizeProbeTargetAccepts(t *testing.T) {
	cases := map[string]struct {
		in     probeTargetInput
		host   string
		expect string
		method string
	}{
		"plain":           {probeTargetInput{Label: " Edge ", URL: "https://edge.example.net/health", ExpectStatus: "204"}, "edge.example.net", "204", "GET"},
		"ranges merged":   {probeTargetInput{Label: "a", URL: "https://edge.example.net/", ExpectStatus: "301, 200-250,251-299 ,204"}, "edge.example.net", "200-299,301", "GET"},
		"head lower case": {probeTargetInput{Label: "a", URL: "https://edge.example.net/", Method: "head", ExpectStatus: "200"}, "edge.example.net", "200", "HEAD"},
		"high port":       {probeTargetInput{Label: "a", URL: "https://Edge.Example.NET:8443/x?q=1", ExpectStatus: "200"}, "edge.example.net:8443", "200", "GET"},
		"explicit 443":    {probeTargetInput{Label: "a", URL: "https://edge.example.net:443/", ExpectStatus: "200"}, "edge.example.net:443", "200", "GET"},
		"public v4":       {probeTargetInput{Label: "a", URL: "https://1.1.1.1/", ExpectStatus: "200"}, "1.1.1.1", "200", "GET"},
		"public v6":       {probeTargetInput{Label: "a", URL: "https://[2606:4700:4700::1111]:8443/", ExpectStatus: "200"}, "[2606:4700:4700::1111]:8443", "200", "GET"},
		"body":            {probeTargetInput{Label: "a", URL: "https://edge.example.net/", ExpectStatus: "200", BodyContains: "Success é"}, "edge.example.net", "200", "GET"},
		"unicode label":   {probeTargetInput{Label: "家里的 NAS", URL: "https://nas.example.net/", ExpectStatus: "200"}, "nas.example.net", "200", "GET"},
	}
	for name, c := range cases {
		got, host, err := normalizeProbeTarget(c.in)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if host != c.host || got.ExpectStatus != c.expect || got.Method != c.method || got.Label != strings.TrimSpace(c.in.Label) {
			t.Errorf("%s: %+v host %q", name, got, host)
		}
	}
}

// TestNormalizeProbeTargetRefuses holds one row per rule the server checks
// on save. The probe checks them all again before a run.
func TestNormalizeProbeTargetRefuses(t *testing.T) {
	ok := probeTargetInput{Label: "a", URL: "https://edge.example.net/", ExpectStatus: "204"}
	with := func(change func(*probeTargetInput)) probeTargetInput {
		in := ok
		change(&in)
		return in
	}
	url := func(u string) probeTargetInput { return with(func(in *probeTargetInput) { in.URL = u }) }
	status := func(s string) probeTargetInput { return with(func(in *probeTargetInput) { in.ExpectStatus = s }) }
	cases := []struct {
		name string
		in   probeTargetInput
		want string
	}{
		{"no label", with(func(in *probeTargetInput) { in.Label = "  " }), "label is required"},
		{"long label", with(func(in *probeTargetInput) { in.Label = strings.Repeat("a", 65) }), "longer than 64"},
		{"control in label", with(func(in *probeTargetInput) { in.Label = "a\tb" }), "printable"},
		{"no url", url(""), "url is required"},
		{"long url", url("https://edge.example.net/" + strings.Repeat("a", 2048)), "longer than 2048"},
		{"space", url("https://edge.example.net/a b"), "printable ASCII"},
		{"non-ascii", url("https://bücher.ch/"), "printable ASCII"},
		{"fragment", url("https://edge.example.net/#x"), "fragment"},
		{"unparseable", url("https://exa%zzmple.net/"), "does not parse"},
		{"http", url("http://edge.example.net/"), "must be https"},
		{"no scheme", url("edge.example.net/"), "must be https"},
		{"opaque", url("https:edge.example.net"), "absolute"},
		{"no host", url("https:///x"), "absolute"},
		{"credentials", url("https://u:p@edge.example.net/"), "credentials"},
		{"empty port", url("https://edge.example.net:/"), "empty port"},
		{"port zero", url("https://edge.example.net:0/"), "port"},
		{"port leading zero", url("https://edge.example.net:0443/"), "leading zero"},
		{"low port", url("https://edge.example.net:22/"), "port 22 is not allowed"},
		{"port 80", url("https://edge.example.net:80/"), "port 80 is not allowed"},
		{"loopback", url("https://127.0.0.1/"), "not a public address"},
		{"private", url("https://10.0.0.1/"), "not a public address"},
		{"metadata", url("https://169.254.169.254/"), "not a public address"},
		{"cgnat", url("https://100.64.0.1/"), "not a public address"},
		{"v6 loopback", url("https://[::1]/"), "not a public address"},
		{"v6 ula", url("https://[fd00::1]/"), "not a public address"},
		{"mapped loopback", url("https://[::ffff:127.0.0.1]/"), "not a public address"},
		{"nat64 private", url("https://[64:ff9b::a00:1]/"), "not a public address"},
		{"zoned", url("https://[fe80::1%25eth0]/"), "not a public address"},
		{"localhost", url("https://localhost/"), "single-label"},
		{"single label", url("https://nas/"), "single-label"},
		{"trailing dot", url("https://edge.example.net./"), "dot"},
		{"bad label", url("https://a_b.example.net/"), "invalid label"},
		{"short v4", url("https://127.1/"), "numeric"},
		{"hex v4", url("https://0x7f.0x1/"), "numeric"},
		{"local suffix", url("https://nas.local/"), ".local"},
		{"internal suffix", url("https://metadata.google.internal/"), ".internal"},
		{"localhost suffix", url("https://api.localhost/"), ".localhost"},
		{"arpa", url("https://nas.home.arpa/"), ".arpa"},
		{"post", with(func(in *probeTargetInput) { in.Method = "POST" }), "GET or HEAD"},
		{"no status", status(" "), "required"},
		{"status word", status("ok"), "three-digit"},
		{"status 600", status("600"), "100 to 599"},
		{"backwards", status("299-200"), "backwards"},
		{"trailing comma", status("200,"), "three-digit"},
		{"too many", status(strings.TrimSuffix(strings.Repeat("200,", 17), ",")), "at most 16"},
		{"long body", with(func(in *probeTargetInput) { in.BodyContains = strings.Repeat("b", 257) }), "longer than 256"},
		{"body newline", with(func(in *probeTargetInput) { in.BodyContains = "a\nb" }), "one line"},
		{"body invalid utf8", with(func(in *probeTargetInput) { in.BodyContains = "\xff" }), "printable"},
		{"body with head", with(func(in *probeTargetInput) { in.Method, in.BodyContains = "HEAD", "ok" }), "needs GET"},
	}
	for _, c := range cases {
		if _, _, err := normalizeProbeTarget(c.in); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error containing %q", c.name, err, c.want)
		}
	}
}

func TestProbeTargetSlug(t *testing.T) {
	for label, want := range map[string]string{
		"Home NAS":                 "home-nas",
		"  edge / health check!! ": "edge-health-check",
		"家里":                       "target",
		"NAS 家里 2":                 "nas-2",
		strings.Repeat("ab-", 20):  strings.TrimRight(strings.Repeat("ab-", 11), "-"),
	} {
		if got := probeTargetSlug(label); got != want || len(got) > 33 {
			t.Errorf("slug(%q) = %q, want %q", label, got, want)
		}
	}
}

func TestProbeTargetEditScopesAndAudit(t *testing.T) {
	fake := startFakeProbe(t)
	srv, st, _ := newProbeTestServer(t, fake.socket)
	create := `{"label":"Home NAS","url":"https://nas.example.net:8443/health?token=s3cr3t","method":"GET","expect_status":"200-299, 301","body_contains":"ok"}`

	// vpn:probe alone reads and runs, but does not edit the list.
	for _, method := range []string{"target_create", "target_update", "target_delete"} {
		_, err := srv.vpnCoreProbeRPC(probeCtx(probeOperator("op", probeScope)), method, []byte(create))
		if status, apiErr := probeErrorOf(t, err); status != http.StatusForbidden || apiErr.Code != model.APIErrorCapabilityDenied {
			t.Fatalf("%s with vpn:probe alone = %d %+v", method, status, apiErr)
		}
	}
	// vpncore:admin alone does not reach the probe service at all.
	_, err := srv.vpnCoreProbeRPC(probeCtx(probeOperator("op", probeTargetsAdminScope)), "target_create", []byte(create))
	if status, _ := probeErrorOf(t, err); status != http.StatusForbidden {
		t.Fatalf("vpncore:admin without vpn:probe = %d", status)
	}

	out, err := srv.vpnCoreProbeRPC(probeCtx(probeAdmin("admin")), "target_create", []byte(create))
	if err != nil {
		t.Fatal(err)
	}
	var created probeTargetView
	if err := json.Unmarshal(out, &created); err != nil {
		t.Fatal(err)
	}
	if created.ID != "custom-home-nas" || created.Source != "custom" || created.ExpectStatus != "200-299,301" || created.Version != 1 || created.CreatedAt == nil {
		t.Fatalf("created %s", out)
	}
	out, err = srv.vpnCoreProbeRPC(probeCtx(probeAdmin("admin")), "target_create", []byte(create))
	if err != nil || !strings.Contains(string(out), `"id":"custom-home-nas-2"`) {
		t.Fatalf("second create %s %v", out, err)
	}

	update := `{"id":"custom-home-nas","version":1,"label":"Home NAS","url":"https://nas.example.net/","method":"HEAD","expect_status":"204"}`
	out, err = srv.vpnCoreProbeRPC(probeCtx(probeAdmin("admin")), "target_update", []byte(update))
	if err != nil || !strings.Contains(string(out), `"version":2`) || !strings.Contains(string(out), `"method":"HEAD"`) {
		t.Fatalf("update %s %v", out, err)
	}
	_, err = srv.vpnCoreProbeRPC(probeCtx(probeAdmin("admin")), "target_update", []byte(update))
	if status, apiErr := probeErrorOf(t, err); status != http.StatusConflict || !strings.Contains(apiErr.Message, "reload") {
		t.Fatalf("stale update = %d %+v", status, apiErr)
	}
	_, err = srv.vpnCoreProbeRPC(probeCtx(probeAdmin("admin")), "target_delete", []byte(`{"id":"custom-gone","version":1}`))
	if status, _ := probeErrorOf(t, err); status != http.StatusNotFound {
		t.Fatalf("delete of a missing target = %d", status)
	}
	for name, body := range map[string]string{
		"unknown field": `{"label":"a","url":"https://a.example.net/","expect_status":"200","extra":1}`,
		"bad url":       `{"label":"a","url":"https://10.0.0.1/","expect_status":"200"}`,
		"not json":      `label`,
		"two values":    `{"label":"a","url":"https://a.example.net/","expect_status":"200"} {}`,
	} {
		_, err := srv.vpnCoreProbeRPC(probeCtx(probeAdmin("admin")), "target_create", []byte(body))
		if status, _ := probeErrorOf(t, err); status != http.StatusBadRequest {
			t.Fatalf("%s = %d, want 400", name, status)
		}
	}
	if _, err := srv.vpnCoreProbeRPC(probeCtx(probeAdmin("admin")), "target_delete", []byte(`{"id":"custom-home-nas","version":2}`)); err != nil {
		t.Fatal(err)
	}

	var actions []string
	for _, ev := range st.AuditEvents() {
		if !strings.HasPrefix(ev.Action, "vpncore.probe_target.") {
			continue
		}
		actions = append(actions, ev.Action)
		if ev.Scope != probeTargetsAdminScope || ev.ActorID != "admin" || len(ev.Metadata) != 2 || ev.Metadata["id"] == "" {
			t.Errorf("audit %+v", ev)
		}
		if h := ev.Metadata["host"]; h != "nas.example.net:8443" && h != "nas.example.net" {
			t.Errorf("audit host %q", h)
		}
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), "s3cr3t") || strings.Contains(string(raw), "/health") {
			t.Errorf("audit carries the URL's path or query: %s", raw)
		}
	}
	if strings.Join(actions, ",") != "vpncore.probe_target.delete,vpncore.probe_target.update,vpncore.probe_target.create,vpncore.probe_target.create" {
		t.Errorf("audit actions %v", actions)
	}
}

func TestProbeTargetsLimitIsEnforced(t *testing.T) {
	fake := startFakeProbe(t)
	srv, _, _ := newProbeTestServer(t, fake.socket)
	body := `{"label":"Edge","url":"https://edge.example.net/","expect_status":"204"}`
	for range probeTargetsLimit {
		if _, err := srv.vpnCoreProbeRPC(probeCtx(probeAdmin("admin")), "target_create", []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	_, err := srv.vpnCoreProbeRPC(probeCtx(probeAdmin("admin")), "target_create", []byte(body))
	if status, apiErr := probeErrorOf(t, err); status != http.StatusConflict || !strings.Contains(apiErr.Message, "at most 32") {
		t.Fatalf("create past the limit = %d %+v", status, apiErr)
	}
}

func TestProbeTargetsAnswerMergesSavedTargets(t *testing.T) {
	fake := startFakeProbe(t)
	srv, st, _ := newProbeTestServer(t, fake.socket)
	if _, err := st.CreateProbeTarget(store.ProbeTarget{ID: "custom-edge", Label: "Edge", URL: "https://edge.example.net/", Method: "GET", ExpectStatus: "204"}, probeTargetsLimit, srv.now()); err != nil {
		t.Fatal(err)
	}
	read := func() probeTargetsAnswer {
		t.Helper()
		out, err := srv.vpnCoreProbeRPC(probeCtx(probeOperator("op", probeScope)), "targets", nil)
		if err != nil {
			t.Fatal(err)
		}
		var answer probeTargetsAnswer
		if err := json.Unmarshal(out, &answer); err != nil {
			t.Fatalf("%s: %v", out, err)
		}
		return answer
	}

	// An older probe: saved targets are listed but cannot run.
	answer := read()
	if len(answer.Targets) != 2 || answer.Targets[0].Source != "builtin" || answer.Targets[0].Expect != 204 || answer.Targets[0].ExpectStatus != "204" ||
		answer.Targets[1].Source != "custom" || answer.Targets[1].Label != "Edge" || answer.Targets[1].Version != 1 {
		t.Fatalf("answer %+v", answer)
	}
	if answer.Custom.Supported || !strings.Contains(answer.Custom.Reason, "0.1.0") || answer.Custom.Limit != probeTargetsLimit {
		t.Fatalf("custom info from an older probe %+v", answer.Custom)
	}

	fake.answerWithHealth(probeTestHealthCustom, http.StatusOK, probeTestAnswer)
	if answer := read(); !answer.Custom.Supported || answer.Custom.Reason != "" {
		t.Fatalf("custom info from a current probe %+v", answer.Custom)
	}
}

func TestProbeRunSendsSavedDefinitions(t *testing.T) {
	fake := startFakeProbe(t)
	fake.answerWithHealth(probeTestHealthCustom, http.StatusOK, probeTestAnswer)
	srv, st, _ := newProbeTestServer(t, fake.socket)
	saved, err := st.CreateProbeTarget(store.ProbeTarget{ID: "custom-nas", Label: "NAS", URL: "https://nas.example.net:8443/health?token=s3cr3t",
		Method: "GET", ExpectStatus: "200-299", BodyContains: "ok"}, probeTargetsLimit, srv.now())
	if err != nil {
		t.Fatal(err)
	}
	req := strings.Replace(probeTestRequest(""), `"targets":["gstatic-204","cloudflare-204"]`, `"targets":["gstatic-204","custom-nas","custom-nas"]`, 1)
	out, err := srv.vpnCoreProbeRPC(probeCtx(probeOperator("op", probeScope)), "run", []byte(req))
	if err != nil || string(out) != probeTestAnswer {
		t.Fatalf("run %s %v", out, err)
	}
	var sent struct {
		Outbounds     json.RawMessage         `json:"outbounds"`
		Targets       []string                `json:"targets"`
		CustomTargets []probeTargetDefinition `json:"custom_targets"`
	}
	if err := json.Unmarshal(fake.body(), &sent); err != nil {
		t.Fatalf("%s: %v", fake.body(), err)
	}
	want := probeTargetDefinition{ID: "custom-nas", URL: saved.URL, Method: "GET", ExpectStatus: "200-299", BodyContains: "ok"}
	if len(sent.CustomTargets) != 1 || sent.CustomTargets[0] != want || len(sent.Targets) != 3 {
		t.Fatalf("sent %s", fake.body())
	}
	if !strings.Contains(string(sent.Outbounds), probeTestPassword) {
		t.Fatalf("the outbounds did not reach the probe: %s", sent.Outbounds)
	}
	audits := probeAudits(st)
	if len(audits) != 1 {
		t.Fatalf("%d run records", len(audits))
	}
	entry := audits[0].Metadata["custom_targets"]
	if entry != "custom-nas nas.example.net:8443 "+probeTargetDigest(saved) || len(probeTargetDigest(saved)) != 12 {
		t.Fatalf("custom_targets audit %q", entry)
	}
	raw, _ := json.Marshal(audits[0])
	if strings.Contains(string(raw), "s3cr3t") || strings.Contains(string(raw), "/health") || strings.Contains(string(raw), probeTestPassword) {
		t.Fatalf("the run record carries the URL's path, query or a credential: %s", raw)
	}

	// A run naming built-in targets only is still forwarded byte for byte.
	plain := probeTestRequest("")
	if _, err := srv.vpnCoreProbeRPC(probeCtx(probeOperator("op", probeScope)), "run", []byte(plain)); err != nil {
		t.Fatal(err)
	}
	if string(fake.body()) != plain {
		t.Fatalf("a built-in run was rewritten: %s", fake.body())
	}
}

func TestProbeRunRefusesUncheckedOrUnrunnableTargets(t *testing.T) {
	fake := startFakeProbe(t)
	srv, st, _ := newProbeTestServer(t, fake.socket)
	if _, err := st.CreateProbeTarget(store.ProbeTarget{ID: "custom-nas", Label: "NAS", URL: "https://nas.example.net/", Method: "GET", ExpectStatus: "204"}, probeTargetsLimit, srv.now()); err != nil {
		t.Fatal(err)
	}
	withTargets := func(targets string, extra string) []byte {
		return []byte(strings.Replace(probeTestRequest(extra), `"targets":["gstatic-204","cloudflare-204"]`, `"targets":`+targets, 1))
	}
	run := func(body []byte) (int, model.APIError) {
		t.Helper()
		_, err := srv.vpnCoreProbeRPC(probeCtx(probeOperator("op", probeScope)), "run", body)
		return probeErrorOf(t, err)
	}

	// The probe here is older: a run naming a saved target is refused
	// clearly and spends nothing.
	if status, apiErr := run(withTargets(`["custom-nas"]`, "")); status != http.StatusConflict || apiErr.Code != apiErrorProbeOutdated || !strings.Contains(apiErr.Message, "Built-in targets still can") {
		t.Fatalf("old probe = %d %+v", status, apiErr)
	}
	fake.answerWithHealth(probeTestHealthCustom, http.StatusOK, probeTestAnswer)
	// A caller cannot bring definitions of its own.
	smuggled := withTargets(`["custom-x"]`, `,"custom_targets":[{"id":"custom-x","url":"https://10.0.0.1/","method":"GET","expect_status":"200"}]`)
	if status, apiErr := run(smuggled); status != http.StatusBadRequest || !strings.Contains(apiErr.Message, "filled in by the server") {
		t.Fatalf("caller custom_targets = %d %+v", status, apiErr)
	}
	if status, apiErr := run(withTargets(`["custom-gone"]`, "")); status != http.StatusBadRequest || !strings.Contains(apiErr.Message, "not a saved target") {
		t.Fatalf("unknown saved id = %d %+v", status, apiErr)
	}
	// Definitions that would push the body past the probe's cap.
	padding := `,"pad":"` + strings.Repeat("x", probeMaxRequestBytes-len(withTargets(`["custom-nas"]`, ""))-20) + `"`
	if status, apiErr := run(withTargets(`["custom-nas"]`, padding)); status != http.StatusBadRequest || !strings.Contains(apiErr.Message, "choose fewer targets") {
		t.Fatalf("oversized = %d %+v", status, apiErr)
	}
	if n := fake.runs.Load(); n != 0 {
		t.Fatalf("%d refused runs reached the probe", n)
	}
	if n := len(probeAudits(st)); n != 0 {
		t.Fatalf("%d refused runs were audited as runs", n)
	}
}

// The edit methods pass the gateway only with every scope the manifest
// declares for them, and core checks both scopes again.
func TestProbeTargetEditThroughTheGateway(t *testing.T) {
	fake := startFakeProbe(t)
	srv, st, _ := newProbeTestServer(t, fake.socket)
	activateCorePlugin(t, st, vpnCorePluginID)
	manifest := probeTestManifest()
	for _, method := range []string{"target_create", "target_update", "target_delete"} {
		manifest.Interfaces[0].MethodSpecs = append(manifest.Interfaces[0].MethodSpecs,
			plugin.InterfaceMethod{Name: method, Effect: plugin.InterfaceEffectWrite, Scopes: []string{probeScope, probeTargetsAdminScope}})
	}
	srv.plugins = append(srv.plugins, plugin.Loaded{Manifest: manifest})
	call := func(p principal, method, payload string) *httptest.ResponseRecorder {
		t.Helper()
		body := fmt.Sprintf(`{"id":%q,"service":%q,"method":%q,"payload":%s}`, vpnCorePluginID, vpnCoreProbeService, method, payload)
		req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.handlePluginCall(rec, req, p)
		return rec
	}
	create := `{"label":"Edge","url":"https://edge.example.net/","expect_status":"204"}`
	if rec := call(probeOperator("op", probeScope), "target_create", create); rec.Code != http.StatusForbidden {
		t.Fatalf("vpn:probe alone through the gateway = %d %s", rec.Code, rec.Body)
	}
	if rec := call(probeAdmin("admin"), "target_create", create); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"id":"custom-edge"`) {
		t.Fatalf("admin through the gateway = %d %s", rec.Code, rec.Body)
	}
	if n := len(st.ProbeTargets()); n != 1 {
		t.Fatalf("%d saved targets", n)
	}
}
