//go:build linechain_lifecycle_e2e

package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/secret"
	"github.com/LatticeNet/lattice-server/internal/store"
)

const (
	e5VPNCoreHead  = "e0af25babf99"
	e5SubStoreHead = "7434d7aee8fe"
)

type e5PluginServerFixture struct {
	server    *Server
	store     *store.Store
	statePath string
	hotPath   string
	cipher    secret.Cipher
}

func newE5PluginServerFixture(t *testing.T, root string) e5PluginServerFixture {
	t.Helper()
	vpnCoreDir := requireE2EDir(t, "LATTICE_VPN_CORE_E2E_DIR")
	subStoreDir := requireE2EDir(t, "LATTICE_SUBSTORE_E2E_DIR")
	requireE2EHead(t, vpnCoreDir, e5VPNCoreHead)
	requireE2EHead(t, subStoreDir, e5SubStoreHead)

	pluginDir := filepath.Join(root, "plugins")
	cacheDir := filepath.Join(root, "plugin-cache")
	runtimeDir := filepath.Join(root, "plugin-runtime")
	for _, dir := range []string{pluginDir, cacheDir, runtimeDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	buildSignedE5PluginBundle(t, vpnCoreDir, pluginDir, priv)
	buildSignedE5PluginBundle(t, subStoreDir, pluginDir, priv)
	policy := plugin.TrustPolicy{TrustedPublishers: map[string]ed25519.PublicKey{"latticenet": pub}}
	loaded, outcomes, err := (plugin.Loader{Dir: pluginDir, CacheDir: cacheDir, Policy: policy}).Load()
	if err != nil || len(loaded) != 2 {
		t.Fatalf("load signed E5 bundles: err=%v loaded=%d outcomes=%+v", err, len(loaded), outcomes)
	}

	cipher, err := secret.NewAESGCM(bytes.Repeat([]byte{0x5e}, secret.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, "state", "state.json")
	hotPath := filepath.Join(root, "state", "hot.db")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenWithCipher(statePath, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnableRuntimeBoltHotStore(hotPath); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{
		Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true,
		PluginDir: pluginDir, PluginBundleCacheDir: cacheDir, PluginRuntimeDir: runtimeDir,
		PluginTrust: policy,
		PublicURL:   "https://lattice.e5.invalid",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return e5PluginServerFixture{server: srv, store: st, statePath: statePath, hotPath: hotPath, cipher: cipher}
}

func requireE2EDir(t *testing.T, name string) string {
	t.Helper()
	dir := strings.TrimSpace(os.Getenv(name))
	if dir == "" || !filepath.IsAbs(dir) {
		t.Fatalf("%s must be an absolute plugin source directory", name)
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("%s: %v", name, err)
	}
	return dir
}

func requireE2EHead(t *testing.T, dir, prefix string) {
	t.Helper()
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").CombinedOutput()
	if err != nil {
		t.Fatalf("plugin head %s: %v: %s", dir, err, out)
	}
	if got := strings.TrimSpace(string(out)); !strings.HasPrefix(got, prefix) {
		t.Fatalf("plugin source %s head=%s want prefix=%s", dir, got, prefix)
	}
	if out, err := exec.Command("git", "-C", dir, "status", "--porcelain").Output(); err != nil || len(out) != 0 {
		t.Fatalf("plugin source %s must be clean: err=%v status=%s", dir, err, out)
	}
}

func buildSignedE5PluginBundle(t *testing.T, sourceDir, pluginDir string, priv ed25519.PrivateKey) {
	t.Helper()
	manifestRaw, err := os.ReadFile(filepath.Join(sourceDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest plugin.Manifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	buildDir := t.TempDir()
	entrypoint := "bin/" + runtime.GOOS + "-" + runtime.GOARCH + "/plugin"
	binaryPath := filepath.Join(buildDir, filepath.FromSlash(entrypoint))
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", binaryPath, ".")
	cmd.Dir = filepath.Join(sourceDir, "system-go")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v: %s", manifest.ID, err, out)
	}
	files := map[string][]byte{}
	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	files[entrypoint] = binary
	uiRoot := filepath.Join(sourceDir, "ui", "dist")
	if err := filepath.WalkDir(uiRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(uiRoot, path)
		if err != nil {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(filepath.Join("ui", rel))] = body
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	archive := makeServerPluginV2Archive(t, files)
	manifest.Runtime.Entrypoints = map[string]string{runtime.GOOS + "/" + runtime.GOARCH: entrypoint}
	manifest.Bundle.DigestSHA256 = plugin.DigestSHA256(archive)
	manifest.SignatureEd25519 = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, plugin.SigningPayload(manifest)))
	bundleDir := filepath.Join(pluginDir, manifest.ID)
	if err := os.MkdirAll(bundleDir, 0o700); err != nil {
		t.Fatal(err)
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
}

func activateE5Plugin(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, pluginID string) {
	t.Helper()
	for _, status := range []string{"installed", "active"} {
		res := doJSON(t, handler, http.MethodPost, "/api/plugins/lifecycle",
			fmt.Sprintf(`{"id":%q,"status":%q}`, pluginID, status), cookies, csrf)
		body := readAndClose(t, res)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("activate %s as %s: status=%d body=%s", pluginID, status, res.StatusCode, body)
		}
	}
}

func callE5Plugin(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, pluginID, service, method string, payload any, out any) []byte {
	t.Helper()
	payloadRaw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(struct {
		ID      string          `json:"id"`
		Service string          `json:"service"`
		Method  string          `json:"method"`
		Payload json.RawMessage `json:"payload"`
	}{pluginID, service, method, payloadRaw})
	if err != nil {
		t.Fatal(err)
	}
	response := doJSON(t, handler, http.MethodPost, "/api/plugins/call", string(body), cookies, csrf)
	raw := readAndClose(t, response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("plugin call %s %s/%s: status=%d body=%s", pluginID, service, method, response.StatusCode, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("decode plugin call %s %s/%s: %v: %s", pluginID, service, method, err, raw)
		}
	}
	return raw
}

type e5GraphPhaseResult struct {
	SourceVersion string
	Share         model.SubscriptionShare
	URI           string
	Published     []byte
}

func exerciseE5GraphAtConvergence(t *testing.T, srv *Server, handler http.Handler, cookies []*http.Cookie, csrf string, user VpnUser, sourceUUID string) e5GraphPhaseResult {
	t.Helper()
	var source Line
	for _, group := range srv.buildLineGroups() {
		for _, line := range group.Lines {
			if line.LineUUID == sourceUUID {
				source = line
			}
		}
	}
	if source.LineHashID == "" {
		t.Fatal("E5 source line missing from canonical projection")
	}
	user.Bindings = []LineBinding{{LineHashID: source.LineHashID, Enabled: true}}
	if err := srv.putVpnUser(user); err != nil {
		t.Fatal(err)
	}
	bound, ok := srv.getVpnUser(user.ID)
	if !ok || bound.SubscriptionGeneration == 0 {
		t.Fatalf("E5 identity generation missing after binding: %+v", bound)
	}
	compileSnapshot, err := srv.captureLineChainCompileSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := composeLine(compileSnapshot, sourceUUID); err != nil {
		t.Fatalf("E5 source is not composable: err=%v lines=%+v definition=%+v", err, compileSnapshot.Lines[sourceUUID], compileSnapshot.Definitions[sourceUUID])
	}

	var coreOptions graphSubscriptionOptionsResponse
	callE5Plugin(t, handler, cookies, csrf, vpnCorePluginID, vpnCoreSubscriptionSourcesService, "graph_options", map[string]any{}, &coreOptions)
	assertE5GraphOptions(t, coreOptions, user.ID, sourceUUID)
	composeRequest := graphSubscriptionRequest{SchemaVersion: 1, IdentityID: user.ID, EntryRoots: []string{sourceUUID}}
	var composed graphSubscriptionResponse
	callE5Plugin(t, handler, cookies, csrf, vpnCorePluginID, vpnCoreSubscriptionSourcesService, "compose", composeRequest, &composed)
	if !composed.OK || composed.SourceVersion == "" || len(composed.SourceManifest) == 0 || len(composed.Entries) != 1 || composed.Raw != composed.Entries[0] {
		t.Fatalf("production graph compose incomplete: %+v", composed)
	}
	credential, _ := vpnCredentialForProtocol(bound.Credentials, model.ProxyProtocolVLESS)
	if strings.EqualFold(sourceUUID, credential.UUID) || !strings.Contains(composed.Raw, credential.UUID+"@") || strings.Contains(composed.Raw, sourceUUID+"@") {
		t.Fatalf("compose did not separate root and credential authority: root=%s credential=%s raw=%s", sourceUUID, credential.UUID, composed.Raw)
	}

	const subStoreID = "latticenet.sub-store"
	const subscriptionService = "latticenet.sub-store/subscription"
	var subOptions graphSubscriptionOptionsResponse
	callE5Plugin(t, handler, cookies, csrf, subStoreID, subscriptionService, "graph_options", map[string]any{}, &subOptions)
	assertE5GraphOptions(t, subOptions, user.ID, sourceUUID)
	if subOptions.OptionsVersion != coreOptions.OptionsVersion {
		t.Fatalf("SubStore options version %s != core %s", subOptions.OptionsVersion, coreOptions.OptionsVersion)
	}

	beforeKV := srv.store.KV("plugin:" + subStoreID)
	var preview struct {
		SourceNodeCount int    `json:"source_node_count"`
		NodeCount       int    `json:"node_count"`
		SourceVersion   string `json:"source_version"`
		Stale           bool   `json:"stale"`
	}
	callE5Plugin(t, handler, cookies, csrf, subStoreID, subscriptionService, "preview", map[string]any{
		"target": "URI", "graph_selection": map[string]any{
			"schema_version": 1, "options_version": subOptions.OptionsVersion,
			"identity_id": user.ID, "entry_roots": []string{sourceUUID},
		},
	}, &preview)
	if preview.SourceNodeCount != 1 || preview.NodeCount != 1 || preview.SourceVersion != composed.SourceVersion || preview.Stale {
		t.Fatalf("graph preview authority mismatch: %+v compose=%s", preview, composed.SourceVersion)
	}
	afterPreviewKV := srv.store.KV("plugin:" + subStoreID)
	if !equalE5JSON(beforeKV, afterPreviewKV) {
		t.Fatalf("graph preview mutated plugin KV: before=%+v after=%+v", beforeKV, afterPreviewKV)
	}

	const subscriptionID = "e5-graph"
	var saved struct {
		Saved bool `json:"saved"`
	}
	callE5Plugin(t, handler, cookies, csrf, subStoreID, subscriptionService, "save", map[string]any{
		"subscription": map[string]any{
			"schema_version": 1, "id": subscriptionID, "name": "E5 graph", "source": "vpn-core-graph",
			"vpn_identity": user.ID, "entry_roots": []string{sourceUUID}, "graph_options_version": subOptions.OptionsVersion,
			"target": "URI",
		},
	}, &saved)
	if !saved.Saved {
		t.Fatal("SubStore graph save did not report success")
	}

	var published []byte
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("publish method=%s", r.Method)
		}
		published, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer destination.Close()
	var publishResult struct {
		SubscriptionID string `json:"subscription_id"`
		Bytes          int    `json:"bytes"`
		StatusCode     int    `json:"status_code"`
	}
	callE5Plugin(t, handler, cookies, csrf, subStoreID, subscriptionService, "publish", map[string]any{
		"subscription_id": subscriptionID, "destination": destination.URL + "/publish", "method": "PUT", "format": "plain",
	}, &publishResult)
	if publishResult.SubscriptionID != subscriptionID || publishResult.StatusCode != http.StatusNoContent ||
		!strings.Contains(string(published), credential.UUID+"@") || strings.Contains(string(published), sourceUUID+"@") {
		t.Fatalf("publish mismatch: result=%+v body=%q compose=%q", publishResult, published, composed.Raw)
	}

	createResponse := doJSON(t, handler, http.MethodPost, "/api/subscription-shares", `{"slug":"e5-graph","source":{"kind":"plugin","plugin_id":"latticenet.sub-store","subscription_id":"e5-graph"},"default_format":"plain"}`, cookies, csrf)
	createRaw := readAndClose(t, createResponse)
	if createResponse.StatusCode != http.StatusCreated {
		t.Fatalf("create E5 share through HTTP: status=%d body=%s", createResponse.StatusCode, createRaw)
	}
	var created shareView
	if err := json.Unmarshal(createRaw, &created); err != nil || created.ID == "" || created.Token == "" {
		t.Fatalf("decode created E5 share: %v body=%s", err, createRaw)
	}
	storedShare, ok := srv.store.SubscriptionShare(created.ID)
	if !ok || storedShare.Token != created.Token {
		t.Fatal("HTTP-created E5 share missing from durable store")
	}
	routeServer := httptest.NewServer(handler)
	defer routeServer.Close()
	request, err := http.NewRequest(http.MethodGet, routeServer.URL+"/sub/"+storedShare.Slug+"/"+storedShare.Token+"?format=plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("User-Agent", "sing-box/1.13.18")
	response, err := routeServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	responseRaw, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Lattice-Subscription-Stale") != "" {
		t.Fatalf("public graph share status=%d headers=%v body=%s", response.StatusCode, response.Header, responseRaw)
	}
	shareBody := strings.TrimSpace(string(responseRaw))
	if shareBody != strings.TrimSpace(string(published)) {
		t.Fatalf("preview/save/publish/share authority diverged: share=%q publish=%q compose=%q", shareBody, published, composed.Raw)
	}
	return e5GraphPhaseResult{SourceVersion: composed.SourceVersion, Share: storedShare, URI: shareBody, Published: append([]byte(nil), published...)}
}

func assertE5GraphOptions(t *testing.T, options graphSubscriptionOptionsResponse, identityID, sourceUUID string) {
	t.Helper()
	if !options.OK || options.OptionsVersion == "" {
		t.Fatalf("graph options unavailable: %+v", options)
	}
	identitySelectable := false
	for _, identity := range options.Identities {
		if identity.ID == identityID && identity.Selectable {
			identitySelectable = true
		}
	}
	rootSelectable := false
	for _, root := range options.Roots {
		if root.LineUUID == sourceUUID && root.Selectable {
			for _, eligible := range root.EligibleIdentityIDs {
				rootSelectable = rootSelectable || eligible == identityID
			}
		}
	}
	if !identitySelectable || !rootSelectable {
		t.Fatalf("identity/root not selectable: identity=%v root=%v options=%+v", identitySelectable, rootSelectable, options)
	}
}

func equalE5JSON(a, b any) bool {
	left, leftErr := json.Marshal(a)
	right, rightErr := json.Marshal(b)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}

func startE5ClientFromShareURI(t *testing.T, singbox, root, uri string, socksPort int) {
	t.Helper()
	parsed, err := url.Parse(strings.TrimSpace(uri))
	if err != nil || parsed.Scheme != "vless" || parsed.User == nil {
		t.Fatalf("invalid public share URI: %v %q", err, uri)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 {
		t.Fatalf("invalid share URI port: %v %q", err, uri)
	}
	query := parsed.Query()
	outbound := map[string]any{
		"type": "vless", "tag": "e5-share", "server": parsed.Hostname(), "server_port": port,
		"uuid": parsed.User.Username(), "flow": query.Get("flow"),
	}
	if query.Get("security") == "reality" {
		outbound["tls"] = map[string]any{
			"enabled": true, "server_name": query.Get("sni"),
			"utls":    map[string]any{"enabled": true, "fingerprint": query.Get("fp")},
			"reality": map[string]any{"enabled": true, "public_key": query.Get("pbk"), "short_id": query.Get("sid")},
		}
	}
	config := map[string]any{
		"log":       map[string]any{"level": "error"},
		"inbounds":  []any{map[string]any{"type": "socks", "tag": "client", "listen": "127.0.0.1", "listen_port": socksPort}},
		"outbounds": []any{outbound},
		"route":     map[string]any{"rules": []any{map[string]any{"inbound": []string{"client"}, "outbound": "e5-share"}}},
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "e5-share-client")
	lifecycleWrite(t, filepath.Join(dir, "config.json"), string(raw))
	if out, err := exec.Command(singbox, "check", "-C", dir).CombinedOutput(); err != nil {
		t.Fatalf("public share client config rejected: %v: %s\nuri=%s", err, out, uri)
	}
	lifecycleStartProcess(t, singbox, root, "e5-share-client", dir, socksPort)
}

func seedE5ConvergedTerminalDefinition(t *testing.T, srv *Server, target managedLineDef) {
	t.Helper()
	const (
		approvalID = "e5-terminal-seed-approval"
		taskID     = "e5-terminal-seed-task"
		artifact   = "e5-terminal-seed-artifact"
		requestSHA = "e5-terminal-seed-request"
	)
	approval := model.Approval{
		ID: approvalID, NodeID: target.NodeID, Plugin: lineChainPlugin, PluginVersion: "test-fixture",
		Service: lineChainService, Method: lineChainRemoveMethod, Action: lineChainActionPrefix + artifact,
		ArtifactDigest: artifact, RequestSHA256: requestSHA, Plan: `{"operation":"remove","fixture":"converged-terminal"}`,
		Status: model.ApprovalPending, Targets: []string{target.NodeID},
	}
	candidate := store.LineChainDefinition{
		SourceLineUUID: target.LineUUID, SourceNodeID: target.NodeID, SourceLineHashID: target.LineHashID,
		SourceInboundTag: target.Tag, ArtifactSHA256: artifact,
	}
	attempt := store.LineChainAttempt{
		ApprovalID: approval.ID, Operation: store.LineChainOperationRemove, SourceLineUUID: target.LineUUID,
		SourceNodeID: target.NodeID, CandidateArtifactSHA256: artifact, CandidateDefinition: candidate,
		RequestSHA256: requestSHA, PlanGraphRevision: srv.store.LineChainSnapshot().Revision,
	}
	if _, _, err := srv.store.PlanLineChainApproval(attempt, approval); err != nil {
		t.Fatalf("persist E5 terminal seed plan: %v", err)
	}
	approved := approval
	approved.Status = model.ApprovalApproved
	task := model.Task{ID: taskID, ApprovalID: approval.ID, Targets: []string{target.NodeID}, Script: "e5-terminal-seed", Status: model.TaskQueued}
	if _, committed, err := srv.store.ApproveLineChain(approved, task); err != nil || !committed {
		t.Fatalf("approve E5 terminal seed: committed=%v err=%v", committed, err)
	}
	validator := func(store.LineChainCompileStateSnapshot, model.Approval, store.LineChainAttempt, model.Task) error {
		return nil
	}
	deliveries, err := srv.store.LeaseTaskDeliveriesWithLineChainValidator(target.NodeID, 1, false, true, validator)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("lease E5 terminal seed: deliveries=%+v err=%v", deliveries, err)
	}
	result := model.TaskResult{TaskID: task.ID, NodeID: target.NodeID, LeaseID: deliveries[0].Task.LeaseID, FinishedAt: time.Now().UTC()}
	if committed, err := srv.store.CompleteLineChainTaskResult(result, approved, store.LineChainStatusAppliedUnobserved, "", ""); err != nil || !committed {
		t.Fatalf("complete E5 terminal seed: committed=%v err=%v", committed, err)
	}
	if committed, err := srv.store.ReconcileLineChains(map[string]store.LineChainObservation{target.LineUUID: {}}); err != nil || !committed {
		t.Fatalf("converge E5 terminal seed: committed=%v err=%v", committed, err)
	}
	definition := srv.store.LineChainSnapshot().Definitions[target.LineUUID]
	if definition.Status != store.LineChainStatusConverged || definition.TargetLineUUID != "" {
		t.Fatalf("E5 terminal definition did not converge: %+v", definition)
	}
}

func readAndClose(t *testing.T, response *http.Response) []byte {
	t.Helper()
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func sortedFixtureFiles(root string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			paths = append(paths, path)
		}
		return nil
	})
	sort.Strings(paths)
	return paths, err
}

func (fixture e5PluginServerFixture) assertNoPlaintextCanaries(t *testing.T, canaries ...string) {
	t.Helper()
	for _, root := range []string{filepath.Dir(fixture.statePath)} {
		paths, err := sortedFixtureFiles(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, canary := range canaries {
				if canary != "" && bytes.Contains(raw, []byte(canary)) {
					t.Fatalf("plaintext canary %q found in %s", canary, path)
				}
			}
		}
	}
}

func (fixture e5PluginServerFixture) reopen(t *testing.T, pluginDir, cacheDir, runtimeDir string, trust plugin.TrustPolicy) *Server {
	t.Helper()
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenWithCipher(fixture.statePath, fixture.cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnableRuntimeBoltHotStore(fixture.hotPath); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true,
		PluginDir: pluginDir, PluginBundleCacheDir: cacheDir, PluginRuntimeDir: runtimeDir, PluginTrust: trust})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return srv
}

func describeE5Fixture(fixture e5PluginServerFixture) string {
	return fmt.Sprintf("state=%s hot=%s", fixture.statePath, fixture.hotPath)
}
