package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-server/internal/plugin"
)

func TestKeygenWritesSeedAndTrustPolicy(t *testing.T) {
	root := t.TempDir()
	seedPath := filepath.Join(root, ".lattice-dev", "publisher.seed")
	trustPath := filepath.Join(root, ".lattice-dev", "plugin-trust.local.json")
	var stdout, stderr bytes.Buffer

	code := run([]string{
		"keygen",
		"-publisher", "dev.hephaestus",
		"-seed", seedPath,
		"-trust", trustPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("keygen exit %d, stderr: %s", code, stderr.String())
	}

	seed, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("seed length: got %d want %d", len(seed), ed25519.SeedSize)
	}
	if info, err := os.Stat(seedPath); err != nil {
		t.Fatal(err)
	} else if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("seed mode: got %o want 600", got)
	}

	raw, err := os.ReadFile(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(seed))) {
		t.Fatalf("trust policy contains private seed material: %s", raw)
	}
	var trust trustPolicyFile
	if err := json.Unmarshal(raw, &trust); err != nil {
		t.Fatal(err)
	}
	if trust.AllowUnsignedHostRisk {
		t.Fatal("dev trust file must keep allow_unsigned_host_risk false")
	}
	if _, ok := trust.TrustedPublishers["dev.hephaestus"]; !ok {
		t.Fatalf("dev publisher missing from trust policy: %s", raw)
	}
	if _, err := plugin.ParseTrustPolicyJSON(raw); err != nil {
		t.Fatalf("server rejected generated trust policy: %v", err)
	}
}

func TestKeygenRejectsNonDevPublisher(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"keygen",
		"-publisher", "latticenet",
		"-seed", filepath.Join(t.TempDir(), "seed"),
		"-trust", filepath.Join(t.TempDir(), "trust.json"),
	}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "dev.<handle>") {
		t.Fatalf("expected non-dev publisher rejection, code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestKeygenExistingTrustLeavesExistingPairUntouched(t *testing.T) {
	root := t.TempDir()
	seedPath := filepath.Join(root, ".lattice-dev", "publisher.seed")
	trustPath := filepath.Join(root, ".lattice-dev", "plugin-trust.local.json")
	if err := os.MkdirAll(filepath.Dir(seedPath), 0o700); err != nil {
		t.Fatal(err)
	}
	oldSeed := bytes.Repeat([]byte{3}, ed25519.SeedSize)
	oldTrust := []byte("{\"trusted_publishers\":{\"dev.hephaestus\":\"old\"}}\n")
	if err := os.WriteFile(seedPath, oldSeed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustPath, oldTrust, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer

	code := run([]string{
		"keygen",
		"-publisher", "dev.hephaestus",
		"-seed", seedPath,
		"-trust", trustPath,
	}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "already exists") {
		t.Fatalf("expected existing destination rejection, code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if got := mustRead(t, seedPath); !bytes.Equal(got, oldSeed) {
		t.Fatalf("seed changed on failed keygen: got %x want %x", got, oldSeed)
	}
	if got := mustRead(t, trustPath); !bytes.Equal(got, oldTrust) {
		t.Fatalf("trust file changed on failed keygen: got %q want %q", got, oldTrust)
	}
}

func TestKeygenExistingTrustLeavesNoPartialSeed(t *testing.T) {
	root := t.TempDir()
	seedPath := filepath.Join(root, ".lattice-dev", "publisher.seed")
	trustPath := filepath.Join(root, ".lattice-dev", "plugin-trust.local.json")
	if err := os.MkdirAll(filepath.Dir(seedPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustPath, []byte("old trust\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer

	code := run([]string{
		"keygen",
		"-publisher", "dev.hephaestus",
		"-seed", seedPath,
		"-trust", trustPath,
	}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "already exists") {
		t.Fatalf("expected existing trust rejection, code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(seedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("seed should not be created when trust destination exists, err=%v", err)
	}
}

func TestSignWritesDevManifestAndVerifiesWithServerPath(t *testing.T) {
	root := t.TempDir()
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	seedPath := filepath.Join(root, "publisher.seed")
	if err := os.WriteFile(seedPath, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	artifact := []byte("local dev bundle bytes")
	artifactPath := filepath.Join(root, "reference-plugin.tar.gz")
	if err := os.WriteFile(artifactPath, artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes(t, "latticenet", strings.Repeat("0", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(root, "manifest.dev.json")
	var stdout, stderr bytes.Buffer

	code := run([]string{
		"sign",
		"-publisher", "dev.hephaestus",
		"-seed", seedPath,
		"-manifest", manifestPath,
		"-artifact", artifactPath,
		"-output", outputPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("sign exit %d, stderr: %s", code, stderr.String())
	}

	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := plugin.DecodeManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Publisher != "dev.hephaestus" {
		t.Fatalf("publisher: got %q", got.Publisher)
	}
	if got.Bundle == nil || got.Bundle.DigestSHA256 != plugin.DigestSHA256(artifact) {
		t.Fatalf("digest not updated from artifact: %+v", got.Bundle)
	}
	if got.SignatureEd25519 == "" {
		t.Fatal("signature missing")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	if _, err := plugin.VerifyInstallManifest(raw, artifact, plugin.TrustPolicy{
		TrustedPublishers: map[string]ed25519.PublicKey{"dev.hephaestus": pub},
	}); err != nil {
		t.Fatalf("server verification failed: %v", err)
	}

	original, err := plugin.DecodeManifest(mustRead(t, manifestPath))
	if err != nil {
		t.Fatal(err)
	}
	if original.Publisher != "latticenet" {
		t.Fatalf("source manifest was modified: publisher=%q", original.Publisher)
	}
}

func TestSignReplacesExistingOutputWithPrivateMode(t *testing.T) {
	root := t.TempDir()
	seedPath, artifactPath, manifestPath := writeSignInputs(t, root)
	outputPath := filepath.Join(root, "manifest.dev.json")
	if err := os.WriteFile(outputPath, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer

	code := run([]string{
		"sign",
		"-publisher", "dev.hephaestus",
		"-seed", seedPath,
		"-manifest", manifestPath,
		"-artifact", artifactPath,
		"-output", outputPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("sign exit %d, stderr: %s", code, stderr.String())
	}
	if info, err := os.Stat(outputPath); err != nil {
		t.Fatal(err)
	} else if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("output mode: got %o want 600", got)
	}
}

func TestSignRejectsInPlaceManifestOutput(t *testing.T) {
	root := t.TempDir()
	seedPath, artifactPath, manifestPath := writeSignInputs(t, root)
	var stdout, stderr bytes.Buffer

	code := run([]string{
		"sign",
		"-publisher", "dev.hephaestus",
		"-seed", seedPath,
		"-manifest", manifestPath,
		"-artifact", artifactPath,
		"-output", manifestPath,
	}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "must not overwrite") {
		t.Fatalf("expected in-place manifest rejection, code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestSignRejectsOutputThatAliasesAnInput(t *testing.T) {
	root := t.TempDir()
	seedPath, artifactPath, manifestPath := writeSignInputs(t, root)
	outputPath := filepath.Join(root, "seed-alias")
	if err := os.Link(seedPath, outputPath); err != nil {
		t.Skipf("hardlinks unavailable: %v", err)
	}
	var stdout, stderr bytes.Buffer

	code := run([]string{
		"sign",
		"-publisher", "dev.hephaestus",
		"-seed", seedPath,
		"-manifest", manifestPath,
		"-artifact", artifactPath,
		"-output", outputPath,
	}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "aliases input") {
		t.Fatalf("expected input alias rejection, code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestSignRejectsSymlinkOutput(t *testing.T) {
	root := t.TempDir()
	seedPath, artifactPath, manifestPath := writeSignInputs(t, root)
	outputPath := filepath.Join(root, "manifest.dev.json")
	if err := os.Symlink(filepath.Join(root, "elsewhere"), outputPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	var stdout, stderr bytes.Buffer

	code := run([]string{
		"sign",
		"-publisher", "dev.hephaestus",
		"-seed", seedPath,
		"-manifest", manifestPath,
		"-artifact", artifactPath,
		"-output", outputPath,
	}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "symlink") {
		t.Fatalf("expected symlink output rejection, code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func writeSignInputs(t *testing.T, root string) (string, string, string) {
	t.Helper()
	seedPath := filepath.Join(root, "publisher.seed")
	if err := os.WriteFile(seedPath, bytes.Repeat([]byte{9}, ed25519.SeedSize), 0o600); err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(root, "bundle.tar.gz")
	if err := os.WriteFile(artifactPath, []byte("bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes(t, "latticenet", strings.Repeat("0", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	return seedPath, artifactPath, manifestPath
}

func manifestBytes(t *testing.T, publisher, digest string) []byte {
	t.Helper()
	raw, err := json.MarshalIndent(plugin.Manifest{
		Schema:       plugin.ManifestSchemaV2,
		ID:           "example.lattice-plugin",
		Name:         "Reference Plugin",
		Type:         plugin.TypeSystem,
		Version:      "0.2.1-alpha.6",
		Capabilities: []string{"network:plan"},
		Publisher:    publisher,
		Bundle: &plugin.BundleSpec{
			Format:       plugin.BundleFormatTarGzip,
			DigestSHA256: digest,
		},
		Runtime: &plugin.RuntimeSpec{
			Protocol: plugin.RuntimeProtocolStdioJSONV1,
			Entrypoints: map[string]string{
				"linux/amd64": "bin/linux-amd64/plugin",
			},
		},
		Compatibility: &plugin.CompatibilitySpec{
			Server:          ">=0.2.1",
			DashboardHost:   ">=1",
			RuntimeProtocol: ">=1",
		},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
