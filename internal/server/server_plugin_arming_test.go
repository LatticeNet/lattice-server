package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// TestPluginArmingIsIndependentOfLoadOrder reproduces the production bug where a
// dependent plugin (alphabetically first, so processed first by the loader) had
// its dependency gate read the dependency's STALE store record — because the
// dependency's record for this boot had not been written yet — leaving the
// dependent permanently unarmed (every /api/plugins/call 502 in ~3ms). The
// two-pass load (record all versions, then arm) must make arming order-free.
func TestPluginArmingIsIndependentOfLoadOrder(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	artifact := []byte("artifact-bytes")

	sign := func(m plugin.Manifest) plugin.Manifest {
		m.DigestSHA256 = plugin.DigestSHA256(artifact)
		m.SignatureEd25519 = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, plugin.SigningPayload(m)))
		return m
	}

	// "aaa.dependent" sorts before "zzz.dependency", so the loader hands it to
	// the arming loop first — the exact ordering that triggered the bug.
	dependent := sign(plugin.Manifest{
		ID: "aaa.dependent", Name: "Dependent", Type: "system", Version: "1.0.0",
		Entrypoint: "system-go/dependent", Publisher: "latticenet",
		Capabilities: []string{"node:read"},
		Dependencies: []plugin.DependencySpec{{ID: "zzz.dependency", Version: ">=2.0.0"}},
	})
	writeServerBundle(t, dir, "dependent", dependent, artifact)

	dependency := sign(plugin.Manifest{
		ID: "zzz.dependency", Name: "Dependency", Type: "system", Version: "2.0.0",
		Entrypoint: "system-go/dependency", Publisher: "latticenet",
		Capabilities: []string{"node:read"},
	})
	writeServerBundle(t, dir, "dependency", dependency, artifact)

	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	// Both are already active from a prior deploy, but the dependency's record
	// is STALE at 1.0.0 (the version before the in-place upgrade to 2.0.0 on
	// disk). This is what an in-place plugin upgrade without a clean record
	// refresh leaves behind.
	if err := st.UpsertPluginInstallation(model.PluginInstallation{ID: "aaa.dependent", Version: "1.0.0", Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertPluginInstallation(model.PluginInstallation{ID: "zzz.dependency", Version: "1.0.0", Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}

	if _, err := New(Options{
		Store:         st,
		AdminPassword: testAdminPass,
		PluginDir:     dir,
		PluginTrust:   plugin.TrustPolicy{TrustedPublishers: map[string]ed25519.PublicKey{"latticenet": pub}},
	}); err != nil {
		t.Fatal(err)
	}

	// The dependency's on-disk version (2.0.0) must be recorded and the
	// dependent must arm — never get a "required dependencies not active" deny.
	inst, ok := st.PluginInstallation("zzz.dependency")
	if !ok || inst.Version != "2.0.0" {
		t.Fatalf("dependency version not refreshed to on-disk 2.0.0: %+v", inst)
	}
	var armed, unarmed bool
	for _, ev := range st.AuditEvents() {
		if ev.Action != "plugin.runtime" || ev.Metadata["plugin_id"] != "aaa.dependent" {
			continue
		}
		if ev.Decision == "allow" {
			armed = true
		}
		if ev.Decision == "deny" {
			unarmed = true
			t.Logf("dependent unarmed: %s", ev.Reason)
		}
	}
	if unarmed {
		t.Fatal("dependent was left unarmed due to load-order race (the production 502 bug)")
	}
	if !armed {
		t.Fatal("dependent did not arm")
	}
}
