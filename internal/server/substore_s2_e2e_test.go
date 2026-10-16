package server

// S2 end to end over the real Sub-Store plugin (design 28 slice S2, plan
// section 7 lane 7 and section 8). The plugin is built from a checkout at
// the commit testdata/substore-plugin.ref records, bundled and signed with a
// test key, verified by the real loader and started under the real system
// runner, so every path below is production's on both sides: the gateway
// with the plugin's own manifest, the share endpoint, the refresh calling
// fetch, render returning a plan, core's bind, convert, the plans service
// calling apply_revision through the claim, and the host KV the plugin's
// store writes through (kv.put with if_match included).
//
// The checkout is LATTICE_SUBSTORE_PLUGIN_DIR, or the sibling
// lattice-plugin-sub-store beside this repository. Without one at the pinned
// commit the tests skip, except under LATTICE_SUBSTORE_PLUGIN_REQUIRED=1,
// which CI's e2e job sets: five acceptance items live only here, so a skip
// there would be a silent green. Wall-clock bounds are asserted only under
// LATTICE_SUBSTORE_PERF_GATE=1, which the perf job sets.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"gopkg.in/yaml.v3"
)

const (
	substoreS2PluginRefFile     = "testdata/substore-plugin.ref"
	substoreS2PluginDirEnv      = "LATTICE_SUBSTORE_PLUGIN_DIR"
	substoreS2PluginRequiredEnv = "LATTICE_SUBSTORE_PLUGIN_REQUIRED"
	substoreS2PerfGateEnv       = "LATTICE_SUBSTORE_PERF_GATE"
	// substoreS2PlanFixturesDigest pins the plugin's plan fixtures
	// (system-go/testdata/plan-fixtures at the pinned commit): the SHA-256
	// of "<sha256 of the file>  <name>\n" for every file, sorted by name,
	// which `shasum -a 256 * | shasum -a 256` prints in that directory. A
	// fixture the plugin regenerates must be re-pinned here deliberately.
	substoreS2PlanFixturesDigest = "83df89deedf347278205bd7f8ea82d2c715c92a3b22f9fe05acac8339782be92"
	s2CarolID                    = "vu-carol"
	s2CarolUUID                  = "2c3d4e5f-6071-4c8d-8e9f-a0b1c2d3e4f5"
)

// substoreS2Source is the plugin checkout at the pinned commit, or a skip
// (a failure when the checkout is required).
func substoreS2Source(t testing.TB) string {
	t.Helper()
	required := os.Getenv(substoreS2PluginRequiredEnv) == "1"
	unavailable := func(format string, args ...any) {
		t.Helper()
		if required {
			t.Fatalf(format, args...)
		}
		t.Skipf(format+" (set %s=1 to make this a failure)", append(args, substoreS2PluginRequiredEnv)...)
	}
	raw, err := os.ReadFile(substoreS2PluginRefFile)
	if err != nil {
		t.Fatalf("read the plugin pin: %v", err)
	}
	want := strings.TrimSpace(string(raw))
	dir := os.Getenv(substoreS2PluginDirEnv)
	if dir == "" {
		dir = filepath.Join("..", "..", "..", "lattice-plugin-sub-store")
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(dir, "system-go", "go.mod")); err != nil || info.IsDir() {
		unavailable("no lattice-plugin-sub-store checkout at %s", dir)
	}
	head, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		unavailable("read the plugin checkout's head at %s: %v", dir, err)
	}
	if got := strings.TrimSpace(string(head)); got != want {
		unavailable("the plugin checkout at %s is at %s, the pin is %s", dir, got, want)
	}
	if dirty, err := exec.Command("git", "-C", dir, "status", "--porcelain", "--untracked-files=no").Output(); err != nil || len(dirty) != 0 {
		unavailable("the plugin checkout at %s has uncommitted changes: %s", dir, dirty)
	}
	return dir
}

var substoreS2Build struct {
	once   sync.Once
	binary []byte
	err    error
}

// substoreS2Binary builds the plugin once per test binary, as the release
// builds it.
func substoreS2Binary(t testing.TB, source string) []byte {
	t.Helper()
	substoreS2Build.once.Do(func() {
		dir, err := os.MkdirTemp("", "lattice-substore-s2-e2e-")
		if err != nil {
			substoreS2Build.err = err
			return
		}
		defer os.RemoveAll(dir)
		out := filepath.Join(dir, "plugin")
		cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", out, ".")
		cmd.Dir = filepath.Join(source, "system-go")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off")
		if msg, err := cmd.CombinedOutput(); err != nil {
			substoreS2Build.err = fmt.Errorf("build the plugin: %v: %s", err, msg)
			return
		}
		substoreS2Build.binary, substoreS2Build.err = os.ReadFile(out)
	})
	if substoreS2Build.err != nil {
		t.Fatal(substoreS2Build.err)
	}
	return substoreS2Build.binary
}

// s2Call is one invocation the runner carried: the method and the record
// it names.
type s2Call struct {
	Method         string
	SubscriptionID string
	// Took is how long the plugin took to answer, transport included.
	Took time.Duration
}

// s2Runner is the real system runner with every invocation recorded and an
// optional fault: fail answers an error for an invocation instead of
// sending it to the plugin, which is how a test makes one apply_revision or
// one fetch fail the way a crashed worker would.
type s2Runner struct {
	*plugin.SystemRunner
	mu    sync.Mutex
	calls []s2Call
	fail  func(c s2Call) error
}

func (r *s2Runner) AcquireInvocation(pluginID string, generation uint64) (plugin.InvocationGenerationLease, error) {
	lease, err := r.SystemRunner.AcquireInvocation(pluginID, generation)
	if err != nil {
		return nil, err
	}
	return &s2Lease{InvocationGenerationLease: lease, runner: r}, nil
}

func (r *s2Runner) setFail(fail func(c s2Call) error) {
	r.mu.Lock()
	r.fail = fail
	r.mu.Unlock()
}

// count answers how many invocations of method named subscriptionID ("" for
// any) the runner carried.
func (r *s2Runner) count(method, subscriptionID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if c.Method == method && (subscriptionID == "" || c.SubscriptionID == subscriptionID) {
			n++
		}
	}
	return n
}

type s2Lease struct {
	plugin.InvocationGenerationLease
	runner *s2Runner
}

func (l *s2Lease) Invoke(ctx context.Context, req plugin.InvokeRequest) (plugin.InvokeResponse, error) {
	var call struct {
		Method  string          `json:"method"`
		Payload json.RawMessage `json:"payload"`
	}
	_ = json.Unmarshal(req.Payload, &call)
	var named struct {
		SubscriptionID string `json:"subscription_id"`
	}
	_ = json.Unmarshal(call.Payload, &named)
	c := s2Call{Method: call.Method, SubscriptionID: named.SubscriptionID}
	l.runner.mu.Lock()
	fail := l.runner.fail
	l.runner.mu.Unlock()
	if fail != nil {
		if err := fail(c); err != nil {
			l.runner.record(c)
			return plugin.InvokeResponse{OK: false, Message: err.Error()}, err
		}
	}
	start := time.Now()
	res, err := l.InvocationGenerationLease.Invoke(ctx, req)
	c.Took = time.Since(start)
	l.runner.record(c)
	return res, err
}

func (r *s2Runner) record(c s2Call) {
	r.mu.Lock()
	r.calls = append(r.calls, c)
	r.mu.Unlock()
}

// took answers the durations of every invocation of method since call
// index from.
func (r *s2Runner) took(method string, from int) []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []time.Duration
	for _, c := range r.calls[from:] {
		if c.Method == method {
			out = append(out, c.Took)
		}
	}
	return out
}

func (r *s2Runner) mark() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// s2Env is a catalogue fixture with the real plugin loaded and running.
type s2Env struct {
	*catalogueEnv
	rows   []model.LineCatalogueRow
	runner *s2Runner
	loaded plugin.Loaded
	source string
	creds  map[string]string
}

// newS2Env starts the real plugin over a catalogue of nodes times perNode
// vless Reality lines, with alice, bob and carol bound to every line. pool
// is the runtime's worker pool size, with no overflow.
func newS2Env(t *testing.T, nodes, perNode, pool int) *s2Env {
	t.Helper()
	source := substoreS2Source(t)
	binary := substoreS2Binary(t, source)
	manifestRaw, err := os.ReadFile(filepath.Join(source, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest plugin.Manifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	entry := "bin/" + runtime.GOOS + "-" + runtime.GOARCH + "/plugin"
	archive := makeServerPluginV2Archive(t, map[string][]byte{
		entry:           binary,
		"ui/index.html": []byte("<!doctype html><main>Sub-Store</main>"),
	})
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Runtime.Entrypoints = map[string]string{runtime.GOOS + "/" + runtime.GOARCH: entry}
	manifest.Bundle.DigestSHA256 = plugin.DigestSHA256(archive)
	manifest.SignatureEd25519 = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, plugin.SigningPayload(manifest)))
	root := t.TempDir()
	pluginDir, cacheDir, runtimeDir := filepath.Join(root, "plugins"), filepath.Join(root, "cache"), filepath.Join(root, "runtime")
	bundleDir := filepath.Join(pluginDir, manifest.ID)
	for _, dir := range []string{bundleDir, cacheDir, runtimeDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	signed, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "manifest.json"), signed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "artifact"), archive, 0o600); err != nil {
		t.Fatal(err)
	}
	// The Sub-Store manifest requires vpn-core, and the loader refuses it
	// without an installed vpn-core bundle that satisfies the range. The
	// catalogue, the identity list and the export it reads are core-backed,
	// so a bundle carrying vpn-core's identity and nothing else stands in;
	// it is never started.
	writeS2DependencyBundle(t, pluginDir, manifest, priv)
	policy := plugin.TrustPolicy{TrustedPublishers: map[string]ed25519.PublicKey{manifest.Publisher: pub}}
	loadedAll, outcomes, err := (plugin.Loader{Dir: pluginDir, CacheDir: cacheDir, Policy: policy}).Load()
	var loaded plugin.Loaded
	for _, l := range loadedAll {
		if l.Manifest.ID == subStorePluginID {
			loaded = l
		}
	}
	if err != nil || loaded.Manifest.ID == "" {
		t.Fatalf("load the signed plugin bundle: %v, outcomes %+v", err, outcomes)
	}

	cat := catalogueFixture(t, nodes, perNode)
	s := cat.srv
	rows, _, _ := cat.readAll(t, "", 1000)
	env := &s2Env{catalogueEnv: cat, rows: rows, loaded: loaded, source: source,
		creds: map[string]string{e2eAliceID: e2eAliceUUID, e2eBobID: e2eBobUUID, s2CarolID: s2CarolUUID}}
	for _, id := range []string{e2eAliceID, e2eBobID, s2CarolID} {
		env.bind(t, id, rows)
	}
	sys, err := plugin.NewSystemRunner(plugin.SystemRunnerOptions{RuntimeDir: runtimeDir, InvokeTimeout: 60 * time.Second,
		Pool: &plugin.SystemPoolConfig{Size: pool, MaxOverflow: 0, StartTimeout: 30 * time.Second, MaxUses: 256, MaxAge: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	env.runner = &s2Runner{SystemRunner: sys}
	s.plugins = []plugin.Loaded{loaded}
	if err := cat.st.UpsertPluginInstallation(model.PluginInstallation{ID: subStorePluginID, Name: "Sub-Store", Type: plugin.TypeSystem,
		Status: model.PluginStatusActive, Version: loaded.Manifest.Version}); err != nil {
		t.Fatal(err)
	}
	if err := cat.st.UpsertPluginInstallation(model.PluginInstallation{ID: vpnCorePluginID, Name: "vpn-core", Type: plugin.TypeSystem,
		Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	s.pluginRuntime = plugin.NewRuntimeManagerWithOptions(plugin.RuntimeManagerOptions{
		Services: s.pluginHostServices(), Runners: map[string]plugin.Runner{plugin.TypeSystem: env.runner},
	})
	if _, err := s.pluginRuntime.Start(context.Background(), loaded); err != nil {
		t.Fatalf("start the plugin under the system runner: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = s.pluginRuntime.Close(ctx)
	})
	s.applyPluginHostAccess(loaded)
	return env
}

// writeS2DependencyBundle writes a signed vpn-core bundle at the lowest
// version the Sub-Store manifest's dependency range admits, with no
// interface, host access or UI of its own and a placeholder runtime.
func writeS2DependencyBundle(t *testing.T, pluginDir string, subStore plugin.Manifest, priv ed25519.PrivateKey) {
	t.Helper()
	version := ""
	for _, dep := range subStore.Dependencies {
		if dep.ID == vpnCorePluginID {
			version = strings.TrimPrefix(dep.Version, ">=")
		}
	}
	if version == "" {
		t.Fatal("the Sub-Store manifest names no vpn-core dependency")
	}
	entry := "bin/" + runtime.GOOS + "-" + runtime.GOARCH + "/plugin"
	archive := makeServerPluginV2Archive(t, map[string][]byte{entry: []byte("#!/bin/sh\nexit 1\n")})
	m := plugin.Manifest{Schema: subStore.Schema, ID: vpnCorePluginID, Name: "vpn-core (e2e stand-in)", Version: version, Type: subStore.Type,
		Publisher: subStore.Publisher, Capabilities: []string{"kv:read"}, Compatibility: subStore.Compatibility,
		Runtime: &plugin.RuntimeSpec{Protocol: subStore.Runtime.Protocol, Entrypoints: map[string]string{runtime.GOOS + "/" + runtime.GOARCH: entry}},
		Bundle:  &plugin.BundleSpec{Format: subStore.Bundle.Format, DigestSHA256: plugin.DigestSHA256(archive)}}
	m.SignatureEd25519 = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, plugin.SigningPayload(m)))
	dir := filepath.Join(pluginDir, m.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	signed, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), signed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "artifact"), archive, 0o600); err != nil {
		t.Fatal(err)
	}
}

// bind writes identity id with its vless credential bound and applied on
// every one of rows.
func (e *s2Env) bind(t *testing.T, id string, rows []model.LineCatalogueRow) {
	t.Helper()
	u := VpnUser{ID: id, Email: id + "@example.com", Name: id, Enabled: true, CreatedAt: e.now, UpdatedAt: e.now,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: e.creds[id], Flow: bindIdentityFlow}}}
	for _, row := range rows {
		u.Bindings = append(u.Bindings, LineBinding{LineHashID: row.LineHashID, Enabled: true, AppliedCredentialSHA256: bindAppliedSHA(t, u, row.LineUUID)})
	}
	if err := e.srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
}

// gateway is the dashboard's call through the plugin gateway, which admits
// a method only when the loaded manifest declares it.
func (e *s2Env) gateway(t *testing.T, service, method string, payload any) (int, []byte) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"id": subStorePluginID, "service": service, "method": method, "payload": payload})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	e.srv.handlePluginCall(rec, req, e2eOperator)
	return rec.Code, rec.Body.Bytes()
}

func (e *s2Env) mustGateway(t *testing.T, service, method string, payload any) []byte {
	t.Helper()
	code, body := e.gateway(t, service, method, payload)
	if code != http.StatusOK {
		t.Fatalf("%s %s: %d %s", service, method, code, body)
	}
	return body
}

const s2Subscription = subStorePluginID + "/subscription"

// s2SaveReply is the plugin's save reply.
type s2SaveReply struct {
	Saved          bool            `json:"saved"`
	Staged         bool            `json:"staged"`
	StagedRevision string          `json:"staged_revision"`
	BaseRevision   string          `json:"base_revision"`
	Refused        json.RawMessage `json:"refused"`
	Subscription   struct {
		Revision string `json:"revision"`
	} `json:"subscription"`
}

// save writes rec through the plugin's save method.
func (e *s2Env) save(t *testing.T, rec map[string]any) s2SaveReply {
	t.Helper()
	if _, ok := rec["name"]; !ok {
		rec["name"] = rec["id"]
	}
	var reply s2SaveReply
	if err := json.Unmarshal(e.mustGateway(t, s2Subscription, "save", map[string]any{"subscription": rec}), &reply); err != nil {
		t.Fatal(err)
	}
	if !reply.Saved {
		t.Fatalf("save %v refused: %s", rec["id"], reply.Refused)
	}
	return reply
}

// live saves a record and, when the save staged it, publishes the staged
// revision through plans.publish, which a record with no fleet-bound share
// takes without an approval. It answers the live revision.
func (e *s2Env) live(t *testing.T, rec map[string]any) string {
	t.Helper()
	reply := e.save(t, rec)
	if !reply.Staged {
		return reply.Subscription.Revision
	}
	e.mustGateway(t, subStorePlansService, "publish", map[string]any{"subscription_id": rec["id"], "revision": reply.StagedRevision,
		"expected_revision": reply.BaseRevision})
	return reply.StagedRevision
}

// entry is the record's index entry as core reads it.
func (e *s2Env) entry(t *testing.T, id string) subStoreIndexEntry {
	t.Helper()
	for _, rec := range e.srv.subStoreIndexV2().entries {
		if rec.ID == id {
			return rec
		}
	}
	t.Fatalf("record %q is not in the plugin's index", id)
	return subStoreIndexEntry{}
}

// importRecords writes records through the plugin's import, the one path
// that still writes a legacy record.
func (e *s2Env) importRecords(t *testing.T, records ...map[string]any) {
	t.Helper()
	for _, rec := range records {
		if _, ok := rec["name"]; !ok {
			rec["name"] = rec["id"]
		}
	}
	backup, _ := json.Marshal(map[string]any{"format": "lattice.sub-store.subscriptions.v1", "settings": map[string]any{"schema_version": 1}, "records": records})
	var out struct {
		Imported []string          `json:"imported"`
		Skipped  map[string]string `json:"skipped"`
	}
	if err := json.Unmarshal(e.mustGateway(t, s2Subscription, "import", map[string]any{"backup": string(backup)}), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Imported) != len(records) {
		t.Fatalf("import wrote %v and skipped %v", out.Imported, out.Skipped)
	}
}

// createShare creates a share through the REST create the dashboard uses
// (the 0.18 manifest declares no shares.create). A share of a record that
// reads the identity-less export must say it publishes fleet credentials.
func (e *s2Env) createShare(t *testing.T, record, slug, identity string) model.SubscriptionShare {
	t.Helper()
	source := map[string]any{"kind": model.ShareSourcePlugin, "plugin_id": subStorePluginID, "subscription_id": record}
	if identity != "" {
		source["identity_id"] = identity
	}
	body, _ := json.Marshal(map[string]any{"slug": slug, "source": source, "default_format": "plain", "publishes_fleet_credentials": identity == ""})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/subscription-shares", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	e.srv.createSubscriptionShare(rec, req, e2eOperator)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create share %s: %d %s", slug, rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	share, ok := e.st.SubscriptionShare(created.ID)
	if !ok || share.Token == "" {
		t.Fatalf("share %s not stored", slug)
	}
	return share
}

// fetch is a client's request for share as target.
func (e *s2Env) fetch(share model.SubscriptionShare, target string) *httptest.ResponseRecorder {
	path := "/sub/" + share.Slug + "/" + share.Token
	if target != "" {
		path += "?target=" + url.QueryEscape(target)
	}
	rec := httptest.NewRecorder()
	e.srv.handleSubscriptionShare(rec, shareRequest(path, "lattice-e2e/1"))
	return rec
}

func (e *s2Env) refusals(shareID string) []string {
	e.srv.shareRefusalAudits.Wait()
	var out []string
	for _, ev := range e.st.AuditEvents() {
		if ev.Action == auditActionShareFetch && ev.Decision == "deny" && ev.Metadata["share_id"] == shareID {
			out = append(out, ev.Reason)
		}
	}
	return out
}

// propose files a plan through the gateway, as the migration flow does.
func (e *s2Env) propose(t *testing.T, payload map[string]any) subStorePlansProposeReply {
	t.Helper()
	var reply subStorePlansProposeReply
	if err := json.Unmarshal(e.mustGateway(t, subStorePlansService, "propose", payload), &reply); err != nil {
		t.Fatal(err)
	}
	return reply
}

// approve approves a proposed plan with apply queued, as the approver does.
func (e *s2Env) approve(t *testing.T, reply subStorePlansProposeReply) (int, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"approval_id": reply.ApprovalID, "plan_sha256": reply.PlanSHA256, "queue_apply": true})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/network/approvals/approve", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	e.srv.handleApprove(rec, req, e2eApprover)
	return rec.Code, rec.Body.String()
}

// expire drops every cached body and marks every snapshot of the plugin
// stale, so the next request refreshes, renders, binds and converts.
func (e *s2Env) expire(t *testing.T) {
	t.Helper()
	if _, err := e.st.MarkPluginSubscriptionSnapshotsStale(subStorePluginID, e.now); err != nil {
		t.Fatal(err)
	}
	e.srv.invalidateSharesForPlugin(subStorePluginID)
}

// credentialsIn reads the vless credentials a served document carries, by
// target: sing-box outbounds, ClashMeta proxies, or URI lines. It answers
// the uuid of every entry, in order.
func credentialsIn(t *testing.T, target, body string) []string {
	t.Helper()
	var uuids []string
	switch target {
	case "sing-box":
		var doc struct {
			Outbounds []struct {
				Type string `json:"type"`
				UUID string `json:"uuid"`
			} `json:"outbounds"`
		}
		if err := json.Unmarshal([]byte(body), &doc); err != nil {
			t.Fatalf("the sing-box document does not decode: %v: %.300s", err, body)
		}
		for _, o := range doc.Outbounds {
			if o.Type == "vless" {
				uuids = append(uuids, o.UUID)
			}
		}
	case "ClashMeta":
		var doc struct {
			Proxies []struct {
				Type string `yaml:"type"`
				UUID string `yaml:"uuid"`
			} `yaml:"proxies"`
		}
		if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
			t.Fatalf("the ClashMeta document does not decode: %v: %.300s", err, body)
		}
		for _, p := range doc.Proxies {
			if p.Type == "vless" {
				uuids = append(uuids, p.UUID)
			}
		}
	default:
		for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
			if rest, ok := strings.CutPrefix(line, "vless://"); ok {
				if at := strings.IndexByte(rest, '@'); at > 0 {
					uuids = append(uuids, rest[:at])
				}
			}
		}
	}
	return uuids
}

// checkServed holds a served document to who's credential on lines entries:
// every entry carries it, and no other identity's, the line owner's or a
// placeholder appears anywhere.
func (e *s2Env) checkServed(t *testing.T, who, target, body string, lines int) {
	t.Helper()
	uuids := credentialsIn(t, target, body)
	if len(uuids) != lines {
		t.Fatalf("%s's %s document has %d vless entries, want %d", who, target, len(uuids), lines)
	}
	for _, uuid := range uuids {
		if uuid != e.creds[who] {
			t.Fatalf("%s's %s document carries credential %s", who, target, uuid)
		}
	}
	for id, cred := range e.creds {
		if id != who && strings.Contains(body, cred) {
			t.Fatalf("%s's %s document carries %s's credential", who, target, id)
		}
	}
	if strings.Contains(body, catalogueOwnerUUID) || strings.Contains(body, model.PlanPlaceholderPrefix) {
		t.Fatalf("%s's %s document carries the line owner's credential or a placeholder", who, target)
	}
}

func fleetRecord(id string, process ...json.RawMessage) map[string]any {
	rec := map[string]any{"id": id, "source": "fleet", "target": "sing-box"}
	if len(process) > 0 {
		rec["process"] = process
	}
	return rec
}

func structuredKeepStep(field string, values ...string) json.RawMessage {
	step, _ := json.Marshal(map[string]any{"type": "Structured Filter", "args": map[string]any{"mode": "keep", "match": "all",
		"predicates": []map[string]any{{"field": field, "op": "in", "values": values}}}})
	return step
}

func scriptOperatorStep(program string) json.RawMessage {
	step, _ := json.Marshal(map[string]any{"type": "Script Operator", "args": map[string]any{"mode": "script", "content": program}})
	return step
}

// TestTwoIdentitiesTwoCredentialsOneCachedPlan is the first two items of
// the slice's acceptance list: a share for an identity bound to lines on
// several nodes renders for sing-box and ClashMeta with every entry carrying
// that identity's credential and none an owner credential, and two shares on
// one record for two identities render different credentials, at pool size
// 1 so one worker serves both (the single plan computation is asserted in
// the plugin, TestPlanCacheServesTwoIdentitiesFromOnePlan).
func TestTwoIdentitiesTwoCredentialsOneCachedPlan(t *testing.T) {
	env := newS2Env(t, 6, 2, 1)
	env.live(t, fleetRecord("fleet"))
	if e := env.entry(t, "fleet"); !e.Flags.FleetBound {
		t.Fatalf("the published fleet record is not fleet-bound live: %+v", e)
	}
	alice := env.createShare(t, "fleet", "alice", e2eAliceID)
	bob := env.createShare(t, "fleet", "bob", e2eBobID)
	nodes := map[string]bool{}
	for _, row := range env.rows {
		nodes[row.NodeID] = true
	}
	if len(nodes) != 6 {
		t.Fatalf("the catalogue spans %d nodes", len(nodes))
	}
	for _, target := range []string{"sing-box", "ClashMeta"} {
		for _, c := range []struct {
			who   string
			share model.SubscriptionShare
		}{{e2eAliceID, alice}, {e2eBobID, bob}} {
			rec := env.fetch(c.share, target)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s's %s share: %d %.300s refusals=%v", c.who, target, rec.Code, rec.Body.String(), env.refusals(c.share.ID))
			}
			env.checkServed(t, c.who, target, rec.Body.String(), len(env.rows))
		}
	}
	if n := env.runner.count("convert", ""); n != 4 {
		t.Fatalf("convert ran %d times for two identities on two targets", n)
	}
}

// substoreS2Fixtures reads the plugin's plan fixtures and checks their pin.
func substoreS2Fixtures(t *testing.T, source string) map[string][]byte {
	t.Helper()
	dir := filepath.Join(source, "system-go", "testdata", "plan-fixtures")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	var names []string
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name()] = body
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	var list strings.Builder
	for _, name := range names {
		sum := sha256.Sum256(files[name])
		fmt.Fprintf(&list, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	}
	sum := sha256.Sum256([]byte(list.String()))
	if got := hex.EncodeToString(sum[:]); got != substoreS2PlanFixturesDigest {
		t.Fatalf("the plugin's plan fixtures hash to %s, the pin is %s; re-pin only after reading what changed", got, substoreS2PlanFixturesDigest)
	}
	return files
}

// TestPluginPlanFixturesPassBindCheckNode binds every template shape the
// plugin's fleet render builds a node for with core's own checker (spec
// survey G25): core's template builder turns the fixture's share URL into
// the row's template, core's shape for it accepts the plan's node (checks 2
// to 4), and the identity's credential replaces every placeholder.
func TestPluginPlanFixturesPassBindCheckNode(t *testing.T) {
	files := substoreS2Fixtures(t, substoreS2Source(t))
	if len(files) < 12 {
		t.Fatalf("%d plan fixtures", len(files))
	}
	protocols := map[string]bool{}
	for name, body := range files {
		var fixture struct {
			Name     string                 `json:"name"`
			Protocol string                 `json:"protocol"`
			ShareURL string                 `json:"share_url"`
			Row      model.LineCatalogueRow `json:"row"`
			Plan     json.RawMessage        `json:"plan"`
		}
		if err := json.Unmarshal(body, &fixture); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		protocols[fixture.Protocol] = true
		built, err := lineClientTemplateFromShareURL(fixture.ShareURL, fixture.Protocol)
		if err != nil {
			t.Fatalf("%s: core's template builder refuses the share URL: %v", name, err)
		}
		if built.Lossy() {
			t.Fatalf("%s: core's template from the share URL is lossy: %v", name, built.Dropped)
		}
		tpl := fixture.Row.Template
		if tpl == nil || built.Host != tpl.Host || built.Port != tpl.Port || len(built.Params) != len(tpl.Params) {
			t.Fatalf("%s: core builds %+v from the share URL, the row carries %+v", name, built, tpl)
		}
		for k, v := range built.Params {
			if tpl.Params[k] != v {
				t.Fatalf("%s: core keeps %s=%q, the row carries %q", name, k, v, tpl.Params[k])
			}
		}
		plan, err := model.DecodeSelectionPlan(fixture.Plan)
		if err != nil || len(plan.Nodes) != 1 {
			t.Fatalf("%s: plan: %v, %d nodes", name, err, len(plan.Nodes))
		}
		node := plan.Nodes[0]
		shape, ok := substoreBindTemplateShape(built)
		if !ok {
			t.Fatalf("%s: core has no bind shape for %s", name, built.Protocol)
		}
		obj, err := parseSubstoreNodeObject(node.Node)
		if err != nil {
			t.Fatalf("%s: core's strict node parse refuses the node: %v", name, err)
		}
		line := &substoreBindLine{row: fixture.Row, template: built, shape: shape}
		if field := substoreBindCheckNode(node.Node, obj, node, line); field != "" {
			t.Fatalf("%s: core rejects the plugin's node: plan_rejected:%s\nnode: %s", name, field, node.Node)
		}
		u := VpnUser{ID: e2eAliceID, Credentials: []VpnCredential{{Protocol: built.Protocol, UUID: e2eAliceUUID, Password: "alice-line-password"}}}
		payload, err := lineUserCredential(u, built.Protocol, userLineName(u.ID, fixture.Row.LineUUID))
		if err != nil {
			t.Fatalf("%s: credential: %v", name, err)
		}
		line.payload = payload
		bound, err := substoreBindNodeCredential(obj, node, line)
		if err != nil {
			t.Fatalf("%s: core cannot place the credential: %v", name, err)
		}
		encoded := string(bound.encode())
		if strings.Contains(encoded, model.PlanPlaceholderPrefix) {
			t.Fatalf("%s: a placeholder survives the bind: %s", name, encoded)
		}
		for field := range node.Placeholders {
			if value, _ := bound.string(field); value == "" {
				t.Fatalf("%s: the bound node's %s is empty", name, field)
			}
		}
	}
	for protocol := range lineClientSchemes {
		if p := lineClientSchemes[protocol]; !protocols[p] {
			t.Errorf("no plan fixture for %s, a protocol core builds templates for", p)
		}
	}
}

// errS2Injected is the fault an s2Runner answers.
var errS2Injected = errors.New("injected by the e2e runner")

// s2Median is the median of durations.
func s2Median(ds []time.Duration) time.Duration {
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

// TestS2FleetRenderLatency1000 is the slice's latency gate (S2 plan section
// 5): a fleet-bound share's cache miss at 1000 lines for sing-box, the
// refresh reading the catalogue pages, the plugin's render, core's bind and
// the plugin's convert, under 400 ms. Each sample marks the snapshot stale
// and drops the body, so the request pays every step; a second series drops
// the body alone (the next identity's miss on a fresh snapshot). The perf
// job asserts the bound; elsewhere the figures are logged.
func TestS2FleetRenderLatency1000(t *testing.T) {
	env := newS2Env(t, 50, 20, 2)
	if len(env.rows) != 1000 {
		t.Fatalf("the catalogue has %d lines", len(env.rows))
	}
	env.live(t, fleetRecord("fleet-1000"))
	alice := env.createShare(t, "fleet-1000", "alice-1000", e2eAliceID)
	start := time.Now()
	rec := env.fetch(alice, "sing-box")
	cold := time.Since(start)
	if rec.Code != http.StatusOK {
		t.Fatalf("first request: %d refusals=%v", rec.Code, env.refusals(alice.ID))
	}
	env.checkServed(t, e2eAliceID, "sing-box", rec.Body.String(), 1000)
	const samples = 10
	var miss, bodyMiss []time.Duration
	from := env.runner.mark()
	for i := 0; i < samples; i++ {
		env.expire(t)
		start := time.Now()
		rec := env.fetch(alice, "sing-box")
		miss = append(miss, time.Since(start))
		if rec.Code != http.StatusOK {
			t.Fatalf("miss %d: %d", i, rec.Code)
		}
		env.srv.invalidateSharesForPlugin(subStorePluginID)
		start = time.Now()
		rec = env.fetch(alice, "sing-box")
		bodyMiss = append(bodyMiss, time.Since(start))
		if rec.Code != http.StatusOK {
			t.Fatalf("body miss %d: %d", i, rec.Code)
		}
		if i == samples-1 {
			env.checkServed(t, e2eAliceID, "sing-box", rec.Body.String(), 1000)
		}
	}
	median := s2Median(miss)
	// The split: what the plugin's three invocations took, transport
	// included; the rest of a miss is core (snapshot store, bind, cache).
	fetch, render, convert := s2Median(env.runner.took("fetch", from)), s2Median(env.runner.took("render", from)), s2Median(env.runner.took("convert", from))
	t.Logf("1000-line sing-box share: first request %s; cache miss with refresh median %s (%v); body-only miss median %s (%v); plugin medians fetch %s render %s convert %s, so core's share of a refresh miss is about %s",
		cold.Round(time.Millisecond), median.Round(time.Millisecond), miss, s2Median(bodyMiss).Round(time.Millisecond), bodyMiss,
		fetch.Round(time.Millisecond), render.Round(time.Millisecond), convert.Round(time.Millisecond), (median - fetch - render - convert).Round(time.Millisecond))
	if os.Getenv(substoreS2PerfGateEnv) == "1" && median >= 400*time.Millisecond {
		t.Errorf("the cache-miss median is %s, not under 400ms", median)
	}
}

// TestScriptOperatorForeignServerIsPlanRejected: a Script Operator on a
// fleet record that rewrites a node's server to a foreign host runs on the
// bundle's process on the isolated path, keeps the node's line (its
// placeholder), and core's bind rejects that node as plan_rejected:server,
// serving the others.
func TestScriptOperatorForeignServerIsPlanRejected(t *testing.T) {
	env := newS2Env(t, 3, 2, 1)
	program := `function operator(proxies) { if (proxies.length > 0) { proxies[0].server = "foreign.example"; } return proxies; }`
	env.live(t, fleetRecord("scripted", scriptOperatorStep(program)))
	var preview substoreBindPreviewReply
	if err := json.Unmarshal(env.mustGateway(t, substoreBindService, "preview", map[string]any{"subscription_id": "scripted", "identity_id": e2eAliceID}), &preview); err != nil {
		t.Fatal(err)
	}
	rejected := 0
	for _, ex := range preview.Excluded {
		if ex.Reason == substoreBindRejectedPrefix+"server" {
			rejected++
		}
	}
	if rejected != 1 || len(preview.Entries) != len(env.rows)-1 {
		t.Fatalf("preview: %d entries, excluded %+v; want one plan_rejected:server and %d entries", len(preview.Entries), preview.Excluded, len(env.rows)-1)
	}
	alice := env.createShare(t, "scripted", "alice-scripted", e2eAliceID)
	rec := env.fetch(alice, "sing-box")
	if rec.Code != http.StatusOK {
		t.Fatalf("share: %d refusals=%v", rec.Code, env.refusals(alice.ID))
	}
	env.checkServed(t, e2eAliceID, "sing-box", rec.Body.String(), len(env.rows)-1)
	if strings.Contains(rec.Body.String(), "foreign.example") {
		t.Fatal("the foreign server reached the document")
	}
}

// TestZeroRowFleetShareAnswersDecoy: a fleet record whose selection matches
// no line fetches a valid envelope with no rows, its plan carries no node,
// and core answers the identity share with the decoy (empty_plan), never an
// empty 200.
func TestZeroRowFleetShareAnswersDecoy(t *testing.T) {
	env := newS2Env(t, 2, 2, 1)
	env.live(t, fleetRecord("nothing", structuredKeepStep("line_uuid", "ffffffff-ffff-4fff-8fff-ffffffffffff")))
	alice := env.createShare(t, "nothing", "alice-nothing", e2eAliceID)
	rec := env.fetch(alice, "sing-box")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("a zero-row fleet share answered %d %.200s", rec.Code, rec.Body.String())
	}
	if env.runner.count("fetch", "nothing") != 1 || env.runner.count("render", "nothing") != 1 {
		t.Fatalf("fetches %d renders %d: the decoy must come from the empty plan, not a failed fetch", env.runner.count("fetch", "nothing"), env.runner.count("render", "nothing"))
	}
	refusals := strings.Join(env.refusals(alice.ID), ",")
	if !strings.Contains(refusals, "empty_plan") {
		t.Fatalf("refusals %q do not name the empty plan", refusals)
	}
}

// TestStagedRevisionServesOnlyAfterApproval: an edit of a fleet record with
// a live identity share stages; the share keeps serving the live revision
// through the save, the proposal and its pending approval, and serves the
// edit only once the plan is approved and applied.
func TestStagedRevisionServesOnlyAfterApproval(t *testing.T) {
	env := newS2Env(t, 3, 2, 1)
	live := env.live(t, fleetRecord("fleet"))
	alice := env.createShare(t, "fleet", "alice-staged", e2eAliceID)
	serves := func(stage string, lines int) {
		t.Helper()
		rec := env.fetch(alice, "sing-box")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d refusals=%v", stage, rec.Code, env.refusals(alice.ID))
		}
		env.checkServed(t, e2eAliceID, "sing-box", rec.Body.String(), lines)
	}
	serves("before the edit", 6)
	keep := []string{env.rows[0].LineUUID, env.rows[1].LineUUID, env.rows[2].LineUUID}
	saved := env.save(t, fleetRecord("fleet", structuredKeepStep("line_uuid", keep...)))
	if !saved.Staged || saved.BaseRevision != live {
		t.Fatalf("the edit of a record with an identity share did not stage over the live revision: %+v", saved)
	}
	serves("after the save", 6)
	if code, body := env.gateway(t, subStorePlansService, "publish", map[string]any{"subscription_id": "fleet", "revision": saved.StagedRevision, "expected_revision": live}); code == http.StatusOK {
		t.Fatalf("publish took a revision a live identity share would receive: %s", body)
	}
	reply := env.propose(t, map[string]any{"subscription_id": "fleet", "from_revision": live, "to_revision": saved.StagedRevision})
	if !reply.Required || reply.Status != model.ApprovalPending {
		t.Fatalf("propose: %+v", reply)
	}
	serves("with the plan pending", 6)
	if code, body := env.approve(t, reply); code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, body)
	}
	if e := env.entry(t, "fleet"); e.Revision != saved.StagedRevision {
		t.Fatalf("the approved revision is not live: %+v", e)
	}
	serves("after the approval", 3)
}

// TestClearOnlyPlanProposedThroughGateway: an identity-bound share on a
// record that renders a document (left from before S2) answers the decoy;
// a clear-only plan proposed through the plugin gateway, with the real
// manifest loaded so the gateway's manifest admission is on the path, is
// approved and applied without a plugin call, and the share serves the
// document again with no identity.
func TestClearOnlyPlanProposedThroughGateway(t *testing.T) {
	env := newS2Env(t, 1, 1, 1)
	live := env.live(t, map[string]any{"id": "doc", "source": "local", "content": "trojan://provider-secret@198.51.100.9:443#provider-entry", "target": "URI"})
	share := model.SubscriptionShare{ID: "share_doc_alice", Slug: "doc-alice", Token: strings.Repeat("c", 43), Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: subStorePluginID, SubscriptionID: "doc", IdentityID: e2eAliceID}}
	if err := env.st.UpsertSubscriptionShare(share); err != nil {
		t.Fatal(err)
	}
	if rec := env.fetch(share, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("an identity share on a document record answered %d", rec.Code)
	}
	if code, _ := env.gateway(t, subStorePlansService, "not_a_method", map[string]any{}); code == http.StatusOK {
		t.Fatal("the gateway admitted a method the manifest does not declare")
	}
	reply := env.propose(t, map[string]any{"subscription_id": "doc", "from_revision": live, "to_revision": live,
		"share_identities": map[string]string{share.ID: ""}})
	if !reply.Required || reply.Status != model.ApprovalPending {
		t.Fatalf("propose: %+v", reply)
	}
	var plan subStorePlan
	if err := json.Unmarshal([]byte(reply.Plan), &plan); err != nil || plan.Mode != "clear" {
		t.Fatalf("plan mode %q: %v", plan.Mode, err)
	}
	applies := env.runner.count(subStoreApplyRevisionMethod, "")
	if code, body := env.approve(t, reply); code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, body)
	}
	if env.runner.count(subStoreApplyRevisionMethod, "") != applies {
		t.Fatal("a clear-only plan called apply_revision")
	}
	cleared, _ := env.st.SubscriptionShare(share.ID)
	if cleared.Source.IdentityID != "" {
		t.Fatalf("the share still names %q", cleared.Source.IdentityID)
	}
	rec := env.fetch(cleared, "URI")
	body := rec.Body.String()
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(body)); err == nil {
		body = string(decoded)
	}
	if rec.Code != http.StatusOK || !strings.Contains(body, "provider-entry") {
		t.Fatalf("the cleared share: %d %.200s", rec.Code, body)
	}
}

// TestLegacyShareFirstRequestServes: a legacy record's share with no stored
// snapshot is served through the refresh: fetch reads the export (the one
// method allowed to) and render renders the snapshot core hands it, now that
// render no longer falls back to the export itself.
func TestLegacyShareFirstRequestServes(t *testing.T) {
	env := newS2Env(t, 2, 2, 1)
	env.importRecords(t, map[string]any{"id": "legacy", "source": "vpn-core", "target": "URI"})
	if _, ok := env.st.SubscriptionSnapshot(subStorePluginID, "legacy"); ok {
		t.Fatal("a snapshot exists before the first request")
	}
	share := env.createShare(t, "legacy", "legacy-first", "")
	rec := env.fetch(share, "")
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) == "" {
		t.Fatalf("the first request of a legacy share: %d %.200s refusals=%v", rec.Code, rec.Body.String(), env.refusals(share.ID))
	}
	if env.runner.count("fetch", "legacy") != 1 || env.runner.count("render", "legacy") != 1 {
		t.Fatalf("fetch %d render %d", env.runner.count("fetch", "legacy"), env.runner.count("render", "legacy"))
	}
	if _, ok := env.st.SubscriptionSnapshot(subStorePluginID, "legacy"); !ok {
		t.Fatal("the refresh stored no snapshot")
	}
}

// TestCoreReadsRecordDocumentAtPluginKey: record ids holding "%", "/" and
// a control byte, written through the real plugin, are read back by core's
// three readers of the plugin's store at the key the plugin escaped them to:
// the fleet-feed guard (an export record with no identity), usage
// attribution (a graph record's identity and roots) and the expiring list
// (the record's name).
func TestCoreReadsRecordDocumentAtPluginKey(t *testing.T) {
	env := newS2Env(t, 2, 1, 1)
	exportID, graphID := "feed%2F/all\x01x", "graph%/\x02y"
	env.importRecords(t,
		map[string]any{"id": exportID, "name": "Fleet feed", "source": "vpn-core", "target": "URI"},
		map[string]any{"id": graphID, "name": "Alice graph", "source": "vpn-core-graph", "vpn_identity": e2eAliceID,
			"entry_roots": []string{env.rows[0].LineUUID}, "graph_options_version": "ov1:" + strings.Repeat("a", 64), "target": "URI"},
	)
	for _, id := range []string{exportID, graphID} {
		if _, ok := env.st.KVEntry(usageSubStoreKVBucket, subStoreRecordKey(id)); !ok {
			t.Fatalf("no record document for %q at %q", id, subStoreRecordKey(id))
		}
	}
	if verdict := env.srv.subStoreFleetFeed(exportID); !verdict.Fleet || verdict.Unknown {
		t.Fatalf("the fleet-feed guard's verdict on %q: %+v", exportID, verdict)
	}
	found := false
	for _, rec := range env.srv.subStoreGraphRecords() {
		if rec.ID == graphID {
			found = rec.VPNIdentity == e2eAliceID && len(rec.EntryRoots) == 1 && rec.EntryRoots[0] == env.rows[0].LineUUID
		}
	}
	if !found {
		t.Fatalf("usage attribution does not read %q: %+v", graphID, env.srv.subStoreGraphRecords())
	}
	names := env.srv.subStoreRecordNames()
	if names[exportID] != "Fleet feed" || names[graphID] != "Alice graph" {
		t.Fatalf("expiring names: %q", names)
	}
}

// s2ExpiryFixture is a fleet record, a provider record and a legacy graph
// record over a committed chain root, each with a share whose body is
// cached.
type s2ExpiryFixture struct {
	env                     *s2Env
	fleet, provider, legacy model.SubscriptionShare
	writes                  int
}

func newS2ExpiryFixture(t *testing.T) *s2ExpiryFixture {
	t.Helper()
	env := newS2Env(t, 4, 2, 1)
	roots := catalogueChainRoots(t, env.catalogueEnv, 1)
	env.live(t, fleetRecord("fleet"))
	env.live(t, map[string]any{"id": "provider", "source": "local", "content": "trojan://provider-secret@198.51.100.9:443#provider-entry", "target": "URI"})
	env.importRecords(t, map[string]any{"id": "graph", "source": "vpn-core-graph", "vpn_identity": e2eAliceID, "entry_roots": roots,
		"graph_options_version": "ov1:" + strings.Repeat("a", 64), "target": "URI"})
	f := &s2ExpiryFixture{env: env,
		fleet:    env.createShare(t, "fleet", "fleet-alice", e2eAliceID),
		provider: env.createShare(t, "provider", "provider-plain", ""),
		legacy:   env.createShare(t, "graph", "graph-plain", ""),
	}
	f.warm(t)
	return f
}

// warm serves every share once, so each body is cached.
func (f *s2ExpiryFixture) warm(t *testing.T) {
	t.Helper()
	for _, share := range []model.SubscriptionShare{f.fleet, f.provider, f.legacy} {
		if rec := f.env.fetch(share, "URI"); rec.Code != http.StatusOK {
			t.Fatalf("share %s: %d %.200s refusals=%v", share.Slug, rec.Code, rec.Body.String(), f.env.refusals(share.ID))
		}
	}
}

// write commits a fleet write and waits for core's depends_on ask. Core
// advances the generation at most once per vpnCoreLinkChangeInterval, so
// the fixture's clock moves past it before each write.
func (f *s2ExpiryFixture) write(t *testing.T) {
	t.Helper()
	f.writes++
	at := f.env.now.Add(time.Duration(f.writes) * (vpnCoreLinkChangeInterval + time.Second))
	f.env.srv.now = func() time.Time { return at }
	u, _ := f.env.srv.getVpnUser(e2eBobID)
	u.Name = u.Name + "+"
	if err := f.env.srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	f.env.srv.triggerVPNCoreMutation()
	f.env.srv.substoreCatalogue.deps.wg.Wait()
}

// expired answers, per record, whether serving its share again made core
// revalidate it: an expired source is fetched again before it is served, a
// kept one is served from the cache.
func (f *s2ExpiryFixture) expired(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for record, share := range map[string]model.SubscriptionShare{"fleet": f.fleet, "provider": f.provider, "graph": f.legacy} {
		before := f.env.runner.count("fetch", record)
		if rec := f.env.fetch(share, "URI"); rec.Code != http.StatusOK {
			t.Fatalf("share %s after the write: %d refusals=%v", share.Slug, rec.Code, f.env.refusals(share.ID))
		}
		out[record] = f.env.runner.count("fetch", record) > before
	}
	return out
}

// TestFleetWriteExpiresOnlyDependents: a fleet write expires the fleet
// record's body and the legacy graph record's, both named by the real
// plugin's depends_on, and keeps the provider record's. The first write
// after a start expires every share, as core has no answer yet; the second
// shows the refinement.
func TestFleetWriteExpiresOnlyDependents(t *testing.T) {
	f := newS2ExpiryFixture(t)
	asks := f.env.runner.count(fleetDependsMethod, "")
	f.write(t)
	if got := f.expired(t); !got["fleet"] || !got["provider"] || !got["graph"] {
		t.Fatalf("the first write after a start expired %v; every share expires until the plugin has answered", got)
	}
	f.write(t)
	if got := f.expired(t); !got["fleet"] || got["provider"] || !got["graph"] {
		t.Fatalf("the second write expired %v; want the fleet and graph records only", got)
	}
	if n := f.env.runner.count(fleetDependsMethod, "") - asks; n != 2 {
		t.Fatalf("depends_on was asked %d times for two writes", n)
	}
}

// TestFleetSnapshotIsKeyedOnTheHashOfRaw: the plugin's fetch reply for a
// fleet record carries no source_version, because core's schema 2 snapshot
// admits one only paired with the manifest it hashes, so core stores the
// snapshot without one and keys revalidation and the body cache on the hash
// of raw. The envelope's lfe1- digest travels inside raw, and a catalogue
// change moves raw and with it the key.
func TestFleetSnapshotIsKeyedOnTheHashOfRaw(t *testing.T) {
	env := newS2Env(t, 3, 2, 1)
	env.live(t, fleetRecord("keyed"))
	share := env.createShare(t, "keyed", "keyed-alice", e2eAliceID)
	read := func() model.SubscriptionSnapshot {
		t.Helper()
		if rec := env.fetch(share, "sing-box"); rec.Code != http.StatusOK {
			t.Fatalf("fetch: %d refusals=%v", rec.Code, env.refusals(share.ID))
		}
		snap, ok := env.st.SubscriptionSnapshot(subStorePluginID, "keyed")
		if !ok {
			t.Fatal("no snapshot stored")
		}
		if snap.SourceVersion != "" || len(snap.SourceManifest) > 0 {
			t.Fatalf("a fleet snapshot stored source_version %q; core keys it on the hash of raw", snap.SourceVersion)
		}
		if got := subscriptionRevalidationVersion(snap); got != subscriptionContentHash(snap.Raw) {
			t.Fatalf("revalidation version %q is not the hash of raw", got)
		}
		var envelope struct {
			SourceVersion string `json:"source_version"`
		}
		if err := json.Unmarshal([]byte(snap.Raw), &envelope); err != nil || !strings.HasPrefix(envelope.SourceVersion, "lfe1-") {
			t.Fatalf("the envelope inside raw carries %q (%v)", envelope.SourceVersion, err)
		}
		return snap
	}
	before := read()
	node, ok := env.st.Node("node-000")
	if !ok {
		t.Fatal("no node-000")
	}
	node.Name = "Node 000 renamed"
	if err := env.st.UpsertNode(node); err != nil {
		t.Fatal(err)
	}
	env.srv.invalidateLineReadModel()
	env.expire(t)
	after := read()
	if after.Raw == before.Raw || subscriptionRevalidationVersion(after) == subscriptionRevalidationVersion(before) {
		t.Fatal("a catalogue change left raw and its key where they were")
	}
}

// TestFleetWriteExpiresARecordEditedSinceTheAnswer: depends_on's answer
// leaves the provider record out at the epoch core read before asking. An
// edit to that record moves its epoch, so the next fleet write must expire
// its share even though the answer still names it independent; the write
// after that, whose ask read the new epoch, keeps it again.
func TestFleetWriteExpiresARecordEditedSinceTheAnswer(t *testing.T) {
	f := newS2ExpiryFixture(t)
	f.write(t)
	f.expired(t)
	// The first write's ask answered the provider record independent at
	// the epoch core read before asking. The edit moves that epoch.
	f.env.live(t, map[string]any{"id": "provider", "source": "local", "content": "trojan://provider-secret@198.51.100.9:443#provider-entry-2", "target": "URI"})
	f.warm(t)
	f.write(t)
	if got := f.expired(t); !got["provider"] || !got["fleet"] {
		t.Fatalf("a fleet write after the provider record's edit expired %v; the answer that left it out predates the edit", got)
	}
	f.write(t)
	if got := f.expired(t); got["provider"] || !got["fleet"] {
		t.Fatalf("the next write expired %v; its ask read the edited epoch", got)
	}
}

// TestFleetWriteExpiry: after a restart core has forgotten which records an
// earlier answer named, so only the plugin's own answer keeps a legacy graph
// record in the expiry set; a fleet write after the restart still expires
// the graph record's body and keeps the provider record's.
func TestFleetWriteExpiry(t *testing.T) {
	f := newS2ExpiryFixture(t)
	f.write(t)
	f.expired(t)
	// What a restart loses: every answer core learned.
	deps := &f.env.srv.substoreCatalogue.deps
	deps.mu.Lock()
	deps.plugins = nil
	deps.mu.Unlock()
	f.write(t)
	if got := f.expired(t); !got["fleet"] || !got["provider"] || !got["graph"] {
		t.Fatalf("the first write after the restart expired %v", got)
	}
	f.write(t)
	if got := f.expired(t); !got["fleet"] || got["provider"] || !got["graph"] {
		t.Fatalf("after the restart a fleet write expired %v; the legacy graph record must stay in the expiry set", got)
	}
}

// legacyExportBody reports whether a served body carries an entry from the
// legacy export: the line owner's credential, in the text or base64.
func legacyExportBody(body string) bool {
	if strings.Contains(body, catalogueOwnerUUID) {
		return true
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(body))
	return err == nil && strings.Contains(string(decoded), catalogueOwnerUUID)
}

// TestMigrationThenFailedRefetchServesNoLegacyEntry: a legacy export record
// with a collection reading it serves the owner-credential export through
// both shares; after the migration plan applies, the catalogue call fails,
// and neither share in the closure serves any entry of the old export: the
// snapshots were dropped, so a failed refetch answers an error, never the
// legacy envelope.
func TestMigrationThenFailedRefetchServesNoLegacyEntry(t *testing.T) {
	env := newS2Env(t, 3, 2, 1)
	env.importRecords(t,
		map[string]any{"id": "legacy", "source": "vpn-core", "target": "URI"},
		map[string]any{"id": "coll", "kind": "collection", "members": []string{"legacy"}, "target": "URI"},
	)
	own := env.createShare(t, "legacy", "legacy-own", "")
	coll := env.createShare(t, "coll", "legacy-coll", "")
	for _, share := range []model.SubscriptionShare{own, coll} {
		rec := env.fetch(share, "URI")
		if rec.Code != http.StatusOK || !legacyExportBody(rec.Body.String()) {
			t.Fatalf("before the migration %s served %d without the export: %.200s", share.Slug, rec.Code, rec.Body.String())
		}
	}
	var migrated struct {
		LiveRevision   string `json:"live_revision"`
		StagedRevision string `json:"staged_revision"`
		Dependents     struct {
			Collections []string `json:"collections"`
		} `json:"dependents"`
	}
	if err := json.Unmarshal(env.mustGateway(t, s2Subscription, "migrate_record", map[string]any{"subscription_id": "legacy"}), &migrated); err != nil || migrated.StagedRevision == "" {
		t.Fatalf("migrate_record: %+v %v", migrated, err)
	}
	reply := env.propose(t, map[string]any{"subscription_id": "legacy", "from_revision": migrated.LiveRevision, "to_revision": migrated.StagedRevision,
		"share_identities": map[string]string{own.ID: e2eAliceID, coll.ID: e2eAliceID}})
	if !reply.Required {
		t.Fatalf("propose: %+v", reply)
	}
	if code, body := env.approve(t, reply); code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, body)
	}
	if e := env.entry(t, "legacy"); e.Revision != migrated.StagedRevision || !e.Flags.FleetBound {
		t.Fatalf("the migrated record is not fleet-bound live: %+v", e)
	}
	// The catalogue call fails from here: vpn-core, which owns it, is down.
	if err := env.st.UpsertPluginInstallation(model.PluginInstallation{ID: vpnCorePluginID, Name: "vpn-core", Type: plugin.TypeSystem,
		Status: model.PluginStatusDisabled}); err != nil {
		t.Fatal(err)
	}
	fetches := env.runner.count("fetch", "")
	for _, id := range []string{own.ID, coll.ID} {
		share, _ := env.st.SubscriptionShare(id)
		if share.Source.IdentityID != e2eAliceID {
			t.Fatalf("share %s names %q after the apply", share.Slug, share.Source.IdentityID)
		}
		rec := env.fetch(share, "URI")
		if legacyExportBody(rec.Body.String()) || strings.Contains(rec.Body.String(), "vless://") {
			t.Fatalf("share %s served an entry after the failed refetch: %d %.300s", share.Slug, rec.Code, rec.Body.String())
		}
		if rec.Code == http.StatusOK {
			t.Fatalf("share %s answered 200 with the catalogue down: %.200s", share.Slug, rec.Body.String())
		}
	}
	if env.runner.count("fetch", "") == fetches {
		t.Fatal("no refetch was attempted, so the failure path was not exercised")
	}
	// With the catalogue back both shares serve alice's own lines.
	if err := env.st.UpsertPluginInstallation(model.PluginInstallation{ID: vpnCorePluginID, Name: "vpn-core", Type: plugin.TypeSystem,
		Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{own.ID, coll.ID} {
		share, _ := env.st.SubscriptionShare(id)
		rec := env.fetch(share, "sing-box")
		if rec.Code != http.StatusOK {
			t.Fatalf("share %s with the catalogue back: %d refusals=%v", share.Slug, rec.Code, env.refusals(share.ID))
		}
		env.checkServed(t, e2eAliceID, "sing-box", rec.Body.String(), len(env.rows))
	}
}

// s2Migrate stages a legacy record's fleet revision through migrate_record
// and answers its live and staged revisions.
func (e *s2Env) migrate(t *testing.T, id string) (live, staged string) {
	t.Helper()
	var reply struct {
		LiveRevision   string `json:"live_revision"`
		StagedRevision string `json:"staged_revision"`
	}
	if err := json.Unmarshal(e.mustGateway(t, s2Subscription, "migrate_record", map[string]any{"subscription_id": id}), &reply); err != nil || reply.StagedRevision == "" {
		t.Fatalf("migrate_record %s: %+v %v", id, reply, err)
	}
	return reply.LiveRevision, reply.StagedRevision
}

// TestPlansProposeRestAfterPartialMigration: a collection gathering two
// legacy export records is migrated in one multi-record plan; the second
// record's apply_revision fails, so the plan applies the first record only
// (its shares already serve their identity, the collection serves nothing
// while it is mixed) and is marked stale naming what it applied. The rest is
// proposed again over the real render path (the collection previewed with
// the promoted member live and the remaining one staged), approved, and
// every share then serves the identity's own lines.
func TestPlansProposeRestAfterPartialMigration(t *testing.T) {
	env := newS2Env(t, 3, 2, 1)
	env.importRecords(t,
		map[string]any{"id": "east", "source": "vpn-core", "target": "URI"},
		map[string]any{"id": "west", "source": "vpn-core", "target": "URI"},
		map[string]any{"id": "both", "kind": "collection", "members": []string{"east", "west"}, "target": "URI"},
	)
	east := env.createShare(t, "east", "east-own", "")
	west := env.createShare(t, "west", "west-own", "")
	both := env.createShare(t, "both", "both-coll", "")
	eastLive, eastStaged := env.migrate(t, "east")
	westLive, westStaged := env.migrate(t, "west")
	reply := env.propose(t, map[string]any{"subscription_id": "east", "from_revision": eastLive, "to_revision": eastStaged,
		"records":          []map[string]string{{"subscription_id": "west", "from_revision": westLive, "to_revision": westStaged}},
		"share_identities": map[string]string{east.ID: e2eAliceID, west.ID: e2eAliceID, both.ID: e2eAliceID}})
	if !reply.Required {
		t.Fatalf("propose: %+v", reply)
	}
	env.runner.setFail(func(c s2Call) error {
		if c.Method == subStoreApplyRevisionMethod && c.SubscriptionID == "west" {
			return errS2Injected
		}
		return nil
	})
	code, body := env.approve(t, reply)
	env.runner.setFail(nil)
	t.Logf("approve with west's apply failing: %d %s", code, body)
	if e := env.entry(t, "east"); e.Revision != eastStaged || !e.Flags.FleetBound {
		t.Fatalf("east was not promoted: %+v", e)
	}
	if e := env.entry(t, "west"); e.Revision != westLive || e.Source != "vpn-core" {
		t.Fatalf("west moved although its apply failed: %+v", e)
	}
	approval, _ := env.st.Approval(reply.ApprovalID)
	if approval.Status == model.ApprovalApplied || !strings.Contains(approval.Reason, "east") {
		t.Fatalf("the partial plan is %s with reason %q; it must not read applied and must name what it applied", approval.Status, approval.Reason)
	}
	eastShare, _ := env.st.SubscriptionShare(east.ID)
	rec := env.fetch(eastShare, "sing-box")
	if rec.Code != http.StatusOK {
		t.Fatalf("east's share after the partial apply: %d refusals=%v", rec.Code, env.refusals(east.ID))
	}
	env.checkServed(t, e2eAliceID, "sing-box", rec.Body.String(), len(env.rows))
	for _, id := range []string{west.ID, both.ID} {
		share, _ := env.st.SubscriptionShare(id)
		if share.Source.IdentityID != "" {
			t.Fatalf("share %s was assigned although its record was not applied", share.Slug)
		}
	}
	if rec := env.fetch(both, "URI"); rec.Code == http.StatusOK || legacyExportBody(rec.Body.String()) {
		t.Fatalf("the mixed collection served %d: %.200s", rec.Code, rec.Body.String())
	}

	// Propose the rest.
	rest := env.propose(t, map[string]any{"subscription_id": "west", "from_revision": westLive, "to_revision": westStaged,
		"share_identities": map[string]string{west.ID: e2eAliceID, both.ID: e2eAliceID}})
	if !rest.Required {
		t.Fatalf("propose the rest: %+v", rest)
	}
	var plan subStorePlan
	if err := json.Unmarshal([]byte(rest.Plan), &plan); err != nil {
		t.Fatal(err)
	}
	sections := map[string]subStorePlanRecord{}
	for _, r := range plan.Records {
		sections[r.SubscriptionID] = r
	}
	if s, ok := sections["both"]; !ok || s.MemberRevisions["west"] != westStaged {
		t.Fatalf("the rest plan's collection section: %+v (records %v)", s, plan.Records)
	}
	if code, body := env.approve(t, rest); code != http.StatusOK {
		t.Fatalf("approve the rest: %d %s", code, body)
	}
	for _, id := range []string{east.ID, west.ID, both.ID} {
		share, _ := env.st.SubscriptionShare(id)
		rec := env.fetch(share, "sing-box")
		if rec.Code != http.StatusOK {
			t.Fatalf("share %s after the rest: %d refusals=%v", share.Slug, rec.Code, env.refusals(share.ID))
		}
		lines := len(env.rows)
		if id == both.ID {
			lines = 2 * len(env.rows) // two migrated members, each selecting every line
		}
		env.checkServed(t, e2eAliceID, "sing-box", rec.Body.String(), lines)
	}
}

// TestPlansCollectionDiffShowsSwitchedMemberAsProviderContent: a fleet
// member of a collection staged as a provider record changes the
// collection's preview the way it will serve: the member's fleet lines
// leave the identity's diff and its provider nodes arrive as provider
// content, from a staged collection render that resolved the switched
// member live.
func TestPlansCollectionDiffShowsSwitchedMemberAsProviderContent(t *testing.T) {
	env := newS2Env(t, 4, 1, 1)
	first := []string{env.rows[0].LineUUID, env.rows[1].LineUUID}
	second := []string{env.rows[2].LineUUID, env.rows[3].LineUUID}
	moving := env.live(t, fleetRecord("moving", structuredKeepStep("line_uuid", first...)))
	env.live(t, fleetRecord("staying", structuredKeepStep("line_uuid", second...)))
	env.live(t, map[string]any{"id": "group", "kind": "collection", "members": []string{"moving", "staying"}, "target": "sing-box"})
	group := env.createShare(t, "group", "group-alice", e2eAliceID)
	if rec := env.fetch(group, "sing-box"); rec.Code != http.StatusOK {
		t.Fatalf("group before the switch: %d refusals=%v", rec.Code, env.refusals(group.ID))
	} else {
		env.checkServed(t, e2eAliceID, "sing-box", rec.Body.String(), 4)
	}
	saved := env.save(t, map[string]any{"id": "moving", "source": "local", "target": "sing-box",
		"content": "trojan://provider-secret@198.51.100.21:443?sni=p.example#provider-one\ntrojan://provider-secret@198.51.100.22:443?sni=p.example#provider-two"})
	if !saved.Staged {
		t.Fatalf("switching a member of a collection with an identity share did not stage: %+v", saved)
	}
	reply := env.propose(t, map[string]any{"subscription_id": "moving", "from_revision": moving, "to_revision": saved.StagedRevision})
	if !reply.Required {
		t.Fatalf("propose: %+v", reply)
	}
	var plan subStorePlan
	if err := json.Unmarshal([]byte(reply.Plan), &plan); err != nil {
		t.Fatal(err)
	}
	var section *subStorePlanRecord
	for i := range plan.Records {
		if plan.Records[i].SubscriptionID == "group" {
			section = &plan.Records[i]
		}
	}
	if section == nil || section.MemberRevisions["moving"] != saved.StagedRevision {
		t.Fatalf("the plan has no dependent section for the collection: %s", reply.Plan)
	}
	var alice *subStorePlanIdentity
	for i := range section.Identities {
		if section.Identities[i].IdentityID == e2eAliceID {
			alice = &section.Identities[i]
		}
	}
	if alice == nil {
		t.Fatalf("the collection section shows no diff for alice: %+v", section)
	}
	removed := map[string]bool{}
	for _, line := range alice.Removed {
		removed[line.LineUUID] = true
	}
	if len(alice.Removed) != 2 || !removed[first[0]] || !removed[first[1]] {
		t.Fatalf("alice's removed lines %+v, want the switched member's two fleet lines", alice.Removed)
	}
	// Core folds a plan's provider nodes into one entry (subStorePlanProviderKey).
	if len(alice.Added) != 1 || alice.Added[0].LineUUID != subStorePlanProviderKey || alice.Unchanged != 2 ||
		strings.Join(alice.Added[0].Names, ",") != "provider-one,provider-two" {
		t.Fatalf("alice's diff: added %+v unchanged %d; want the two provider nodes as provider content and the other member's two lines unchanged", alice.Added, alice.Unchanged)
	}
	t.Logf("collection diff for alice: removed %d, added %+v, unchanged %d", len(alice.Removed), alice.Added, alice.Unchanged)
}

// TestPlanDeleteApplyRendersTagDependentCollection carries lane 5b's end-to
// end half: deleting a fleet record that a collection gathers by tag goes
// through a plan (the collection's identity share is in the closure), and
// after the apply the collection is fetched and rendered again without the
// deleted member.
func TestPlanDeleteApplyRendersTagDependentCollection(t *testing.T) {
	env := newS2Env(t, 4, 1, 1)
	keepRec := fleetRecord("keep", structuredKeepStep("line_uuid", env.rows[0].LineUUID, env.rows[1].LineUUID))
	keepRec["tags"] = []string{"asia"}
	goneRec := fleetRecord("gone", structuredKeepStep("line_uuid", env.rows[2].LineUUID, env.rows[3].LineUUID))
	goneRec["tags"] = []string{"asia"}
	env.live(t, keepRec)
	gone := env.live(t, goneRec)
	env.live(t, map[string]any{"id": "tagged", "kind": "collection", "member_tags": []string{"asia"}, "target": "sing-box"})
	share := env.createShare(t, "tagged", "tagged-alice", e2eAliceID)
	if rec := env.fetch(share, "sing-box"); rec.Code != http.StatusOK {
		t.Fatalf("before the delete: %d refusals=%v", rec.Code, env.refusals(share.ID))
	} else {
		env.checkServed(t, e2eAliceID, "sing-box", rec.Body.String(), 4)
	}
	if code, body := env.gateway(t, subStorePlansService, "publish", map[string]any{"subscription_id": "gone", "expected_revision": gone, "action": "delete"}); code == http.StatusOK {
		t.Fatalf("a delete reaching an identity share published without a plan: %s", body)
	}
	reply := env.propose(t, map[string]any{"subscription_id": "gone", "from_revision": gone, "action": "delete"})
	if !reply.Required {
		t.Fatalf("propose the delete: %+v", reply)
	}
	fetches := env.runner.count("fetch", "tagged")
	if code, body := env.approve(t, reply); code != http.StatusOK {
		t.Fatalf("approve the delete: %d %s", code, body)
	}
	for _, rec := range env.srv.subStoreIndexV2().entries {
		if rec.ID == "gone" {
			t.Fatalf("the deleted record is still live: %+v", rec)
		}
	}
	rec := env.fetch(share, "sing-box")
	if rec.Code != http.StatusOK {
		t.Fatalf("after the delete: %d refusals=%v", rec.Code, env.refusals(share.ID))
	}
	env.checkServed(t, e2eAliceID, "sing-box", rec.Body.String(), 2)
	if env.runner.count("fetch", "tagged") == fetches {
		t.Fatal("the collection was served without a fetch after the delete")
	}
}

// TestSubstoreE2EJobRunsEveryEndToEndTest: the shards skip these tests (no
// plugin checkout there), so a test the substore-e2e job's -run list leaves
// out never runs in CI. Two of the review fixes' tests were left out that
// way at first.
func TestSubstoreE2EJobRunsEveryEndToEndTest(t *testing.T) {
	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile("substore_s2_e2e_test.go")
	if err != nil {
		t.Fatal(err)
	}
	job := string(workflow)
	if at := strings.Index(job, "substore-e2e:"); at >= 0 {
		job = job[at:]
	}
	// Every test in this file runs the real plugin, except this one.
	for _, m := range regexp.MustCompile(`(?m)^func (Test\w+)\(t \*testing\.T\)`).FindAllStringSubmatch(string(source), -1) {
		name := m[1]
		if name == "TestSubstoreE2EJobRunsEveryEndToEndTest" {
			continue
		}
		if !strings.Contains(job, name+"|") && !strings.Contains(job, name+")") {
			t.Errorf("%s runs the real plugin and is not in the substore-e2e job's -run list", name)
		}
	}
}
