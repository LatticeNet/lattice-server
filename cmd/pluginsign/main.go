// Command pluginsign re-signs a plugin manifest.json with a publisher's ed25519
// seed, reusing the server's own plugin.SigningPayload so the signed bytes match
// the verifier byte-for-byte (including the design-10 ui/interfaces extension).
//
// It reads the manifest, optionally recomputes digest_sha256 from the artifact
// (and fails if it disagrees with the on-disk digest unless -update-digest), signs
// the canonical payload, self-verifies, and writes the manifest back canonically
// so the on-disk ui/interfaces are exactly what was signed.
//
//	go run ./cmd/pluginsign -manifest path/manifest.json -seed seed.bin \
//	    -artifact path/system-go/binary [-update-digest] [-write]
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/LatticeNet/lattice-server/internal/plugin"
)

func main() {
	manifestPath := flag.String("manifest", "", "path to manifest.json")
	seedPath := flag.String("seed", "", "path to 32-byte ed25519 seed")
	artifactPath := flag.String("artifact", "", "path to the plugin artifact (to verify/compute digest)")
	updateDigest := flag.Bool("update-digest", false, "overwrite digest_sha256 from the artifact instead of erroring on mismatch")
	write := flag.Bool("write", false, "write the signed manifest back to -manifest")
	flag.Parse()

	if *manifestPath == "" || *seedPath == "" {
		fmt.Fprintln(os.Stderr, "pluginsign: -manifest and -seed are required")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*manifestPath)
	must(err, "read manifest")
	var m plugin.Manifest
	must(json.Unmarshal(raw, &m), "parse manifest")

	seed, err := os.ReadFile(*seedPath)
	must(err, "read seed")
	if len(seed) != ed25519.SeedSize {
		fatal(fmt.Sprintf("seed must be %d bytes, got %d", ed25519.SeedSize, len(seed)))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	if *artifactPath != "" {
		art, err := os.ReadFile(*artifactPath)
		must(err, "read artifact")
		digest := plugin.DigestSHA256(art)
		manifestDigest := m.DigestSHA256
		if m.Schema == plugin.ManifestSchemaV2 && m.Bundle != nil {
			manifestDigest = m.Bundle.DigestSHA256
		}
		switch {
		case manifestDigest == "" || (manifestDigest != digest && *updateDigest):
			if manifestDigest != "" {
				fmt.Fprintf(os.Stderr, "pluginsign: updating digest %s -> %s\n", manifestDigest, digest)
			}
			if m.Schema == plugin.ManifestSchemaV2 && m.Bundle != nil {
				m.Bundle.DigestSHA256 = digest
			} else {
				m.DigestSHA256 = digest
			}
		case manifestDigest != digest:
			fatal(fmt.Sprintf("digest mismatch: manifest=%s artifact=%s (pass -update-digest to overwrite)", manifestDigest, digest))
		}
	}

	payload := plugin.SigningPayload(m)
	sig := ed25519.Sign(priv, payload)
	if !ed25519.Verify(pub, payload, sig) {
		fatal("self-verify failed")
	}
	m.SignatureEd25519 = base64.StdEncoding.EncodeToString(sig)

	out, err := json.MarshalIndent(m, "", "  ")
	must(err, "marshal manifest")
	out = append(out, '\n')

	fmt.Printf("publisher pubkey (base64): %s\n", base64.StdEncoding.EncodeToString(pub))
	digest := m.DigestSHA256
	if m.Schema == plugin.ManifestSchemaV2 && m.Bundle != nil {
		digest = m.Bundle.DigestSHA256
	}
	fmt.Printf("artifact digest_sha256 : %s\n", digest)
	fmt.Printf("signature_ed25519      : %s\n", m.SignatureEd25519)
	fmt.Printf("signing payload bytes  : %d\n", len(payload))

	if *write {
		must(os.WriteFile(*manifestPath, out, 0o644), "write manifest")
		fmt.Printf("wrote %s\n", *manifestPath)
	} else {
		fmt.Println("--- canonical manifest (not written; pass -write) ---")
		os.Stdout.Write(out)
	}

	// End-to-end gate: reproduce the server's load-time verification exactly —
	// DisallowUnknownFields + ValidateManifest (incl. validateContributions) +
	// digest + signature against the trusted publisher. Reads the bytes we just
	// wrote (or would write) so what we verify is what ships.
	if *artifactPath != "" {
		art, _ := os.ReadFile(*artifactPath)
		policy := plugin.TrustPolicy{TrustedPublishers: map[string]ed25519.PublicKey{m.Publisher: pub}}
		if _, err := plugin.VerifyInstallManifest(out, art, policy); err != nil {
			fatal("VerifyInstallManifest (server-parity) FAILED: " + err.Error())
		}
		fmt.Println("VerifyInstallManifest (server-parity): OK")
	}
}

func must(err error, ctx string) {
	if err != nil {
		fatal(ctx + ": " + err.Error())
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "pluginsign: "+msg)
	os.Exit(1)
}
