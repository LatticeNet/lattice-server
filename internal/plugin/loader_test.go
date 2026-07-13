package plugin

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeBundle creates <dir>/<name>/{manifest.json,artifact}.
func writeBundle(t *testing.T, root, name string, manifest Manifest, artifact []byte) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	mb, err := json.Marshal(manifest)
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

func signedManifest(t *testing.T, priv ed25519.PrivateKey, base Manifest, artifact []byte) Manifest {
	t.Helper()
	base.DigestSHA256 = DigestSHA256(artifact)
	base.SignatureEd25519 = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, SigningPayload(base)))
	return base
}

func signedManifestV2(t *testing.T, priv ed25519.PrivateKey, base Manifest, artifact []byte) Manifest {
	t.Helper()
	base.Bundle.DigestSHA256 = DigestSHA256(artifact)
	base.SignatureEd25519 = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, SigningPayload(base)))
	return base
}

func TestLoaderLoadsSignedAndRejectsRest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	artifact := []byte("trusted plugin artifact")

	// 1) a properly signed, trusted host-risk system plugin -> loads
	good := signedManifest(t, priv, Manifest{
		ID: "good.plugin", Name: "Good", Type: TypeSystem, Version: "1.0.0",
		Entrypoint: "system-go/good", Publisher: "latticenet",
		Capabilities: []string{"network:plan"},
	}, artifact)
	writeBundle(t, root, "good", good, artifact)

	// 2) host-risk but UNSIGNED -> rejected (fail-closed default)
	writeBundle(t, root, "unsigned", Manifest{
		ID: "unsigned.plugin", Name: "Unsigned", Type: TypeSystem, Version: "1.0.0",
		Entrypoint: "system-go/unsigned", Capabilities: []string{"network:plan"},
	}, artifact)

	// 3) signed but artifact tampered -> digest mismatch -> rejected
	writeBundle(t, root, "tampered", good, []byte("DIFFERENT artifact bytes"))

	// 4) signed by an UNTRUSTED publisher key -> rejected
	_, roguePriv, _ := ed25519.GenerateKey(rand.Reader)
	rogue := signedManifest(t, roguePriv, Manifest{
		ID: "rogue.plugin", Name: "Rogue", Type: TypeSystem, Version: "1.0.0",
		Entrypoint: "system-go/rogue", Publisher: "latticenet",
		Capabilities: []string{"network:plan"},
	}, artifact)
	writeBundle(t, root, "rogue", rogue, artifact)

	// 5) a corrupt bundle (manifest is not JSON) -> rejected, must not abort scan
	corrupt := filepath.Join(root, "corrupt")
	os.MkdirAll(corrupt, 0o755)
	os.WriteFile(filepath.Join(corrupt, "manifest.json"), []byte("{not json"), 0o600)
	os.WriteFile(filepath.Join(corrupt, "artifact"), artifact, 0o600)

	loader := Loader{Dir: root, Policy: TrustPolicy{
		TrustedPublishers: map[string]ed25519.PublicKey{"latticenet": pub},
	}}
	loaded, outcomes, err := loader.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].Manifest.ID != "good.plugin" {
		t.Fatalf("expected only good.plugin to load, got %+v", loaded)
	}
	if len(loaded[0].Capabilities) != 1 || loaded[0].Capabilities[0] != "network:plan" {
		t.Fatalf("unexpected granted capabilities: %+v", loaded[0].Capabilities)
	}
	ok, fail := 0, 0
	for _, o := range outcomes {
		if o.Loaded {
			ok++
		} else {
			fail++
		}
	}
	if ok != 1 || fail != 4 {
		t.Fatalf("expected 1 load + 4 rejects, got ok=%d fail=%d (%+v)", ok, fail, outcomes)
	}
}

func TestLoaderEmptyAndMissingDir(t *testing.T) {
	// missing dir
	loaded, _, err := Loader{Dir: filepath.Join(t.TempDir(), "nope")}.Load()
	if err != nil || len(loaded) != 0 {
		t.Fatalf("missing dir should load nothing, got %v %v", loaded, err)
	}
	// empty dir
	loaded, _, err = Loader{Dir: t.TempDir()}.Load()
	if err != nil || len(loaded) != 0 {
		t.Fatalf("empty dir should load nothing, got %v %v", loaded, err)
	}
	// unset dir
	loaded, _, err = Loader{}.Load()
	if err != nil || len(loaded) != 0 {
		t.Fatalf("unset dir should load nothing, got %v %v", loaded, err)
	}
}

func TestLoaderAllowsUnsignedHostRiskOnlyWhenOptedIn(t *testing.T) {
	root := t.TempDir()
	artifact := []byte("dev artifact")
	writeBundle(t, root, "dev", Manifest{
		ID: "dev.plugin", Name: "Dev", Type: TypeSystem, Version: "0.1.0",
		Entrypoint: "system-go/dev", Capabilities: []string{"network:plan"},
	}, artifact)

	// fail-closed default: rejected
	loaded, _, _ := Loader{Dir: root}.Load()
	if len(loaded) != 0 {
		t.Fatalf("unsigned host-risk must be rejected by default, got %+v", loaded)
	}
	// explicit dev opt-out: loads
	loaded, _, _ = Loader{Dir: root, Policy: TrustPolicy{AllowUnsignedHostRisk: true}}.Load()
	if len(loaded) != 1 {
		t.Fatalf("opt-out should load the dev plugin, got %+v", loaded)
	}
}

func TestLoaderV2ExtractsSignedBundleForSelectedPlatform(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	cache := t.TempDir()
	archive := makeTestArchive(t,
		testArchiveEntry{name: "bin/linux-amd64/plugin", body: []byte("amd64")},
		testArchiveEntry{name: "bin/linux-arm64/plugin", body: []byte("arm64")},
		testArchiveEntry{name: "ui/index.html", body: []byte("<main>v2</main>")},
	)
	m := validManifestV2()
	m.Runtime.Entrypoints["linux/arm64"] = "bin/linux-arm64/plugin"
	m = signedManifestV2(t, priv, m, archive)
	writeBundle(t, root, "v2", m, archive)

	loaded, outcomes, err := (Loader{
		Dir: root, CacheDir: cache, Platform: "linux/arm64",
		Policy: TrustPolicy{TrustedPublishers: map[string]ed25519.PublicKey{"latticenet": pub}},
	}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 1 || !outcomes[0].Loaded || len(loaded) != 1 {
		t.Fatalf("unexpected load outcome: loaded=%+v outcomes=%+v", loaded, outcomes)
	}
	got := loaded[0]
	if got.Manifest.Schema != ManifestSchemaV2 || got.ArtifactDigest != m.Bundle.DigestSHA256 {
		t.Fatalf("v2 metadata missing: %+v", got)
	}
	if got.RuntimeEntry != "bin/linux-arm64/plugin" || filepath.Base(filepath.Dir(got.RuntimePath)) != "linux-arm64" {
		t.Fatalf("wrong platform runtime selected: entry=%q path=%q", got.RuntimeEntry, got.RuntimePath)
	}
	if got.ExtractedRoot == "" || got.UIEntry == "" || len(got.Inventory) != 3 {
		t.Fatalf("extracted metadata incomplete: %+v", got)
	}
	if data, err := os.ReadFile(got.RuntimePath); err != nil || string(data) != "arm64" {
		t.Fatalf("selected runtime bytes wrong: %q err=%v", data, err)
	}
}

func TestLoaderV2RequiresCacheAndMatchingPlatform(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	archive := makeTestArchive(t, testArchiveEntry{name: "bin/linux-amd64/plugin", body: []byte("runtime")}, testArchiveEntry{name: "ui/index.html", body: []byte("ui")})
	m := signedManifestV2(t, priv, validManifestV2(), archive)
	writeBundle(t, root, "v2", m, archive)
	policy := TrustPolicy{TrustedPublishers: map[string]ed25519.PublicKey{"latticenet": pub}}

	loaded, outcomes, err := (Loader{Dir: root, Platform: "linux/amd64", Policy: policy}).Load()
	if err != nil || len(loaded) != 0 || len(outcomes) != 1 || !strings.Contains(outcomes[0].Reason, "cache") {
		t.Fatalf("v2 without cache must be rejected: loaded=%+v outcomes=%+v err=%v", loaded, outcomes, err)
	}

	loaded, outcomes, err = (Loader{Dir: root, CacheDir: t.TempDir(), Platform: "linux/riscv64", Policy: policy}).Load()
	if err != nil || len(loaded) != 0 || len(outcomes) != 1 || !strings.Contains(outcomes[0].Reason, "platform") {
		t.Fatalf("v2 without platform entrypoint must be rejected: loaded=%+v outcomes=%+v err=%v", loaded, outcomes, err)
	}
}
