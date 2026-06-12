package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func writeServerBundle(t *testing.T, root, name string, m plugin.Manifest, artifact []byte) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	mb, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), mb, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "artifact"), artifact, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPluginLoaderWiredIntoServer(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	artifact := []byte("artifact-bytes")

	good := plugin.Manifest{
		ID: "ops.bundle", Name: "Ops", Type: "system", Version: "1.0.0",
		Entrypoint: "system-go/ops", Publisher: "latticenet",
		Capabilities: []string{"node:read"},
	}
	good.DigestSHA256 = plugin.DigestSHA256(artifact)
	good.SignatureEd25519 = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, plugin.SigningPayload(good)))
	writeServerBundle(t, dir, "ops", good, artifact)

	// unsigned host-risk bundle -> must be rejected and audited, not loaded
	writeServerBundle(t, dir, "rogue", plugin.Manifest{
		ID: "rogue.bundle", Name: "Rogue", Type: "system", Version: "1.0.0",
		Entrypoint: "system-go/rogue", Capabilities: []string{"network:apply"},
	}, artifact)

	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{
		Store:         st,
		AdminPassword: testAdminPass,
		PluginDir:     dir,
		PluginTrust:   plugin.TrustPolicy{TrustedPublishers: map[string]ed25519.PublicKey{"latticenet": pub}},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)

	res := doJSON(t, handler, http.MethodGet, "/api/plugins", "", cookies, csrf)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("plugins list: %d", res.StatusCode)
	}
	var plugins []struct {
		ID           string   `json:"id"`
		Capabilities []string `json:"capabilities"`
	}
	json.NewDecoder(res.Body).Decode(&plugins)
	res.Body.Close()
	if len(plugins) != 1 || plugins[0].ID != "ops.bundle" {
		t.Fatalf("expected only ops.bundle to load, got %+v", plugins)
	}

	res = doJSON(t, handler, http.MethodGet, "/api/audit?action=plugin.rejected", "", cookies, csrf)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("audit query: %d", res.StatusCode)
	}
	var audit struct {
		Events []map[string]any `json:"events"`
		Total  int              `json:"total"`
	}
	json.NewDecoder(res.Body).Decode(&audit)
	res.Body.Close()
	if audit.Total < 1 {
		t.Fatalf("expected a plugin.rejected audit event for the unsigned bundle, got %+v", audit)
	}
}
