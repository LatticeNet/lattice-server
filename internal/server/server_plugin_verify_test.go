package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestPluginVerifyEndpointAcceptsTrustedSignedHostRiskManifest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifact := []byte("signed plugin artifact bytes")
	manifest := plugin.Manifest{
		ID:           "signed-ops",
		Name:         "Signed Ops",
		Type:         plugin.TypeSystem,
		Version:      "0.1.0",
		Entrypoint:   "system-go/signed-ops",
		Capabilities: []string{"network:plan", "node:read"},
		Publisher:    "latticenet",
		DigestSHA256: plugin.DigestSHA256(artifact),
	}
	manifest.SignatureEd25519 = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, plugin.SigningPayload(manifest)))

	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{
		Store:         st,
		AdminPassword: testAdminPass,
		PluginTrust:   plugin.TrustPolicy{TrustedPublishers: map[string]ed25519.PublicKey{"latticenet": pub}},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)

	body := mustJSON(t, map[string]any{
		"manifest":        manifest,
		"artifact_base64": base64.RawStdEncoding.EncodeToString(artifact),
	})
	res := doJSON(t, handler, http.MethodPost, "/api/plugins/verify", string(body), cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("verify: %d", res.StatusCode)
	}
	var out struct {
		Trusted      bool   `json:"trusted"`
		ArtifactHash string `json:"artifact_sha256"`
		Manifest     plugin.Manifest
		Capabilities []struct {
			Name string `json:"name"`
			Risk string `json:"risk"`
		} `json:"capabilities"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.Trusted || out.Manifest.ID != manifest.ID || out.Manifest.SignatureEd25519 != "" {
		t.Fatalf("unexpected verified manifest projection: %+v", out)
	}
	if out.ArtifactHash != manifest.DigestSHA256 {
		t.Fatalf("artifact digest mismatch: got %s want %s", out.ArtifactHash, manifest.DigestSHA256)
	}
	if len(out.Capabilities) != 2 || out.Capabilities[0].Name != "network:plan" || out.Capabilities[0].Risk != plugin.RiskHost {
		t.Fatalf("expected sorted capability risk summary, got %+v", out.Capabilities)
	}

	list := doJSON(t, handler, http.MethodGet, "/api/plugins", "", cookies, csrf)
	defer list.Body.Close()
	var installed []pluginView
	if err := json.NewDecoder(list.Body).Decode(&installed); err != nil {
		t.Fatal(err)
	}
	if len(installed) != 0 {
		t.Fatalf("verify endpoint must not install/register plugins, got %+v", installed)
	}
}

func TestPluginVerifyEndpointRejectsUnsignedHostRiskAndDoesNotInstall(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	artifact := []byte("unsigned host artifact")
	manifest := plugin.Manifest{
		ID:           "unsigned-host",
		Name:         "Unsigned Host",
		Type:         plugin.TypeSystem,
		Version:      "0.1.0",
		Entrypoint:   "system-go/unsigned-host",
		Capabilities: []string{"network:plan"},
		DigestSHA256: plugin.DigestSHA256(artifact),
	}

	body := mustJSON(t, map[string]any{
		"manifest":        manifest,
		"artifact_base64": base64.RawStdEncoding.EncodeToString(artifact),
	})
	res := doJSON(t, handler, http.MethodPost, "/api/plugins/verify", string(body), cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected unsigned host-risk rejection, got %d", res.StatusCode)
	}
	data, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(data), "publisher") {
		t.Fatalf("expected publisher/signature rejection, got %s", string(data))
	}

	list := doJSON(t, handler, http.MethodGet, "/api/plugins", "", cookies, csrf)
	defer list.Body.Close()
	var installed []pluginView
	if err := json.NewDecoder(list.Body).Decode(&installed); err != nil {
		t.Fatal(err)
	}
	if len(installed) != 0 {
		t.Fatalf("rejected verification must not install/register plugins, got %+v", installed)
	}
}

func TestPluginVerifyEndpointRequiresPluginVerifyScope(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	readOnlyToken := createPAT(t, handler, cookies, csrf, []string{"audit:read"}, nil)

	artifact := []byte("read-only artifact")
	manifest := plugin.Manifest{
		ID:           "readonly-card",
		Name:         "Read Only Card",
		Type:         plugin.TypeWasm,
		Version:      "0.1.0",
		Entrypoint:   "wasm/readonly-card.wasm",
		Capabilities: []string{"node:read"},
		DigestSHA256: plugin.DigestSHA256(artifact),
	}
	body := string(mustJSON(t, map[string]any{
		"manifest":        manifest,
		"artifact_base64": base64.RawStdEncoding.EncodeToString(artifact),
	}))

	denied := doBearerJSON(t, handler, http.MethodPost, "/api/plugins/verify", body, readOnlyToken)
	denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("audit:read token must not verify plugins, got %d", denied.StatusCode)
	}

	verifyToken := createPAT(t, handler, cookies, csrf, []string{"plugin:verify"}, nil)
	allowed := doBearerJSON(t, handler, http.MethodPost, "/api/plugins/verify", body, verifyToken)
	defer allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("plugin:verify token should verify read-only plugin, got %d", allowed.StatusCode)
	}
}

func TestPluginVerifyEndpointRejectsOversizedRequestEvenWithValidJSONPrefix(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	artifact := []byte("tiny artifact")
	manifest := plugin.Manifest{
		ID:           "oversized-prefix",
		Name:         "Oversized Prefix",
		Type:         plugin.TypeWasm,
		Version:      "0.1.0",
		Entrypoint:   "wasm/oversized.wasm",
		Capabilities: []string{"node:read"},
		DigestSHA256: plugin.DigestSHA256(artifact),
	}
	body := string(mustJSON(t, map[string]any{
		"manifest":        manifest,
		"artifact_base64": base64.RawStdEncoding.EncodeToString(artifact),
	})) + strings.Repeat(" ", 4<<20)

	res := doJSON(t, handler, http.MethodPost, "/api/plugins/verify", body, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized request must be rejected even when it starts with valid JSON, got %d", res.StatusCode)
	}
}
