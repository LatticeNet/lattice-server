package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func makeServerPluginV2Archive(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	tw := tar.NewWriter(zw)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		body, ok := files[name]
		if !ok {
			continue
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func newPluginAssetTestServer(t *testing.T) (*Server, http.Handler, []*http.Cookie, string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	archive := makeServerPluginV2Archive(t, map[string][]byte{
		"bin/" + runtime.GOOS + "-" + runtime.GOARCH + "/plugin": []byte("#!/bin/sh\nread line\necho '{\"ok\":true,\"result\":{\"source\":\"runtime\"}}'\n"),
		"ui/index.html":                 []byte("<!doctype html><main>Plugin UI</main>"),
		"ui/assets/app.0123456789ab.js": []byte("globalThis.pluginLoaded = true"),
	})
	m := plugin.Manifest{
		Schema: plugin.ManifestSchemaV2,
		ID:     "test.assets", Name: "Asset Test", Type: plugin.TypeSystem, Version: "0.2.1-alpha.1",
		Publisher: "latticenet", Capabilities: []string{"node:read"},
		Bundle: &plugin.BundleSpec{Format: plugin.BundleFormatTarGzip, DigestSHA256: plugin.DigestSHA256(archive)},
		Runtime: &plugin.RuntimeSpec{Protocol: plugin.RuntimeProtocolStdioJSONV1, Entrypoints: map[string]string{
			runtime.GOOS + "/" + runtime.GOARCH: "bin/" + runtime.GOOS + "-" + runtime.GOARCH + "/plugin",
		}},
		UIRuntime:     &plugin.UIRuntimeSpec{Mode: plugin.UIRuntimeModeSandbox, Entrypoint: "ui/index.html", BridgeVersion: plugin.UIBridgeVersion1},
		Compatibility: &plugin.CompatibilitySpec{Server: ">=0.2.1", DashboardHost: ">=1", RuntimeProtocol: ">=1"},
		Interfaces: []plugin.InterfaceContract{{
			Service:     "test.assets/items",
			MethodSpecs: []plugin.InterfaceMethod{{Name: "list", Effect: plugin.InterfaceEffectRead, Scopes: []string{"proxy:read"}}},
		}},
		UI: &plugin.ManifestUI{
			Nav:   []plugin.NavContribution{{Section: "extensions", Title: "Assets", Route: "items", Scopes: []string{"proxy:read"}}},
			Views: []plugin.ViewContribution{{Route: "items", Title: "Assets", Kind: "sandbox"}},
		},
	}
	m.SignatureEd25519 = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, plugin.SigningPayload(m)))
	pluginRoot := t.TempDir()
	bundleDir := filepath.Join(pluginRoot, m.ID)
	if err := os.MkdirAll(bundleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifestJSON, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "manifest.json"), manifestJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "artifact"), archive, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{
		Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true,
		PluginDir: pluginRoot, PluginBundleCacheDir: t.TempDir(),
		PluginRuntimeDir: t.TempDir(),
		PluginTrust:      plugin.TrustPolicy{TrustedPublishers: map[string]ed25519.PublicKey{"latticenet": pub}},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)
	base := "/api/plugins/assets/" + m.ID + "/" + m.Bundle.DigestSHA256
	return srv, handler, cookies, csrf, base
}

func TestPluginContributionsV2ExposeOnlySafeRuntimeMetadata(t *testing.T) {
	srv, handler, cookies, csrf, base := newPluginAssetTestServer(t)
	for _, status := range []string{model.PluginStatusInstalled, model.PluginStatusActive} {
		res := doJSON(t, handler, http.MethodPost, "/api/plugins/lifecycle", `{"id":"test.assets","status":"`+status+`"}`, cookies, csrf)
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("lifecycle %s status=%d", status, res.StatusCode)
		}
	}
	readToken := createPAT(t, handler, cookies, csrf, []string{"proxy:read"}, nil)
	res := doBearerJSON(t, handler, http.MethodGet, "/api/plugin-contributions", "", readToken)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("contributions status=%d body=%s", res.StatusCode, body)
	}
	var views []pluginView
	if err := json.Unmarshal(body, &views); err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].UIRuntime == nil {
		t.Fatalf("missing v2 UI runtime metadata: %+v", views)
	}
	if views[0].UIRuntime.EntryURL != base+"/ui/index.html" || views[0].UIRuntime.AssetDigest == "" || views[0].UIRuntime.BridgeVersion != "1" {
		t.Fatalf("unsafe or incomplete UI runtime metadata: %+v", views[0].UIRuntime)
	}
	loaded, _ := srv.loadedPlugin("test.assets")
	if bytes.Contains(body, []byte(loaded.ExtractedRoot)) || bytes.Contains(body, []byte("signature_ed25519")) || bytes.Contains(body, []byte(loaded.BundlePath)) {
		t.Fatalf("contribution response leaked local or signature metadata: %s", body)
	}
}

func TestPluginCallV2NeverFallsBackToInCoreRPC(t *testing.T) {
	srv, handler, cookies, csrf, _ := newPluginAssetTestServer(t)
	if err := srv.pluginRPC.Register("test.assets", "test.assets/items", "core", []string{"list"}, func(context.Context, string, []byte) ([]byte, error) {
		return []byte(`{"source":"core"}`), nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{model.PluginStatusInstalled, model.PluginStatusActive} {
		res := doJSON(t, handler, http.MethodPost, "/api/plugins/lifecycle", `{"id":"test.assets","status":"`+status+`"}`, cookies, csrf)
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("lifecycle %s status=%d", status, res.StatusCode)
		}
	}
	readToken := createPAT(t, handler, cookies, csrf, []string{"proxy:read"}, nil)
	res := doBearerJSON(t, handler, http.MethodPost, "/api/plugins/call", `{"id":"test.assets","service":"test.assets/items","method":"list"}`, readToken)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"source":"runtime"`)) || bytes.Contains(body, []byte(`"source":"core"`)) {
		t.Fatalf("v2 call did not stay on runtime: status=%d body=%s", res.StatusCode, body)
	}
}

func TestPluginAssetAuthenticatesHTMLAndBindsSubresourcesToActiveLifecycle(t *testing.T) {
	_, handler, cookies, csrf, base := newPluginAssetTestServer(t)
	unauth := doJSON(t, handler, http.MethodGet, base+"/ui/index.html", "", nil, "")
	unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated HTML status=%d", unauth.StatusCode)
	}
	verifiedJS := doJSON(t, handler, http.MethodGet, base+"/ui/assets/app.0123456789ab.js", "", nil, "")
	verifiedJS.Body.Close()
	if verifiedJS.StatusCode != http.StatusNotFound {
		t.Fatalf("verified plugin subresource must be hidden, got %d", verifiedJS.StatusCode)
	}
	verified := doJSON(t, handler, http.MethodGet, base+"/ui/index.html", "", cookies, "")
	verified.Body.Close()
	if verified.StatusCode != http.StatusNotFound {
		t.Fatalf("verified plugin asset must be hidden, got %d", verified.StatusCode)
	}
	for _, status := range []string{model.PluginStatusInstalled, model.PluginStatusActive} {
		res := doJSON(t, handler, http.MethodPost, "/api/plugins/lifecycle", `{"id":"test.assets","status":"`+status+`"}`, cookies, csrf)
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("lifecycle %s status=%d", status, res.StatusCode)
		}
	}
	active := doJSON(t, handler, http.MethodGet, base+"/ui/index.html", "", cookies, "")
	active.Body.Close()
	if active.StatusCode != http.StatusOK {
		t.Fatalf("active plugin asset status=%d", active.StatusCode)
	}
	activeJS := doJSON(t, handler, http.MethodGet, base+"/ui/assets/app.0123456789ab.js", "", nil, "")
	activeJS.Body.Close()
	if activeJS.StatusCode != http.StatusOK {
		t.Fatalf("opaque-origin subresource must load without a cookie, got %d", activeJS.StatusCode)
	}
	disabled := doJSON(t, handler, http.MethodPost, "/api/plugins/lifecycle", `{"id":"test.assets","status":"disabled"}`, cookies, csrf)
	disabled.Body.Close()
	if disabled.StatusCode != http.StatusOK {
		t.Fatalf("disable status=%d", disabled.StatusCode)
	}
	after := doJSON(t, handler, http.MethodGet, base+"/ui/index.html", "", cookies, "")
	after.Body.Close()
	if after.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled plugin asset must be hidden, got %d", after.StatusCode)
	}
	afterJS := doJSON(t, handler, http.MethodGet, base+"/ui/assets/app.0123456789ab.js", "", nil, "")
	afterJS.Body.Close()
	if afterJS.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled plugin subresource must be hidden, got %d", afterJS.StatusCode)
	}
}

func TestPluginAssetHeadersCacheAndPathValidation(t *testing.T) {
	_, handler, cookies, csrf, base := newPluginAssetTestServer(t)
	for _, status := range []string{model.PluginStatusInstalled, model.PluginStatusActive} {
		res := doJSON(t, handler, http.MethodPost, "/api/plugins/lifecycle", `{"id":"test.assets","status":"`+status+`"}`, cookies, csrf)
		res.Body.Close()
	}

	html := doJSON(t, handler, http.MethodGet, base+"/ui/index.html", "", cookies, "")
	body, _ := io.ReadAll(html.Body)
	html.Body.Close()
	if html.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("Plugin UI")) {
		t.Fatalf("HTML asset failed: status=%d body=%q", html.StatusCode, body)
	}
	if got := html.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("HTML content type=%q", got)
	}
	if got := html.Header.Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Fatalf("plugin HTML frame policy=%q", got)
	}
	if csp := html.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "connect-src 'none'") || !strings.Contains(csp, "frame-ancestors 'self'") {
		t.Fatalf("plugin CSP=%q", csp)
	}
	if cache := html.Header.Get("Cache-Control"); !strings.Contains(cache, "no-cache") {
		t.Fatalf("HTML cache policy=%q", cache)
	}
	if got := html.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("nosniff=%q", got)
	}

	js := doJSON(t, handler, http.MethodGet, base+"/ui/assets/app.0123456789ab.js", "", cookies, "")
	js.Body.Close()
	if js.StatusCode != http.StatusOK || js.Header.Get("Content-Type") != "text/javascript; charset=utf-8" || !strings.Contains(js.Header.Get("Cache-Control"), "immutable") {
		t.Fatalf("hashed JS headers: status=%d type=%q cache=%q", js.StatusCode, js.Header.Get("Content-Type"), js.Header.Get("Cache-Control"))
	}

	badPaths := []string{
		"/api/plugins/assets/test.assets/" + strings.Repeat("0", 64) + "/ui/index.html",
		base + "/ui/missing.js",
		base + "/ui/%2e%2e/index.html",
		base + "/bin/linux-amd64/plugin",
	}
	for _, requestPath := range badPaths {
		req := httptest.NewRequest(http.MethodGet, requestPath, nil)
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("path %q status=%d, want 404", requestPath, rec.Code)
		}
	}

	nonGet := doJSON(t, handler, http.MethodPost, base+"/ui/index.html", "", cookies, csrf)
	nonGet.Body.Close()
	if nonGet.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST asset status=%d", nonGet.StatusCode)
	}

	core := doJSON(t, handler, http.MethodGet, "/api/version", "", nil, "")
	core.Body.Close()
	if core.Header.Get("X-Frame-Options") != "DENY" || strings.Contains(core.Header.Get("Content-Security-Policy"), "frame-ancestors 'self'") {
		t.Fatalf("core security headers were relaxed: frame=%q csp=%q", core.Header.Get("X-Frame-Options"), core.Header.Get("Content-Security-Policy"))
	}
}
