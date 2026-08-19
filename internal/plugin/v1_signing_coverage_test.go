package plugin

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

// The v1 signing payload is an explicit field list, so everything the v2 schema
// added sits outside it. The question is whether any of those fields can be
// present on a v1 manifest at all. If they can, a signed v1 manifest could be
// altered where it matters while the signature still verifies.
//
// It cannot: validation refuses them outright, which closes the gap at a
// different layer than the signature. Recorded so a later relaxation of that
// validation does not quietly reopen it.
func TestV1ManifestCannotCarryTheFieldsItsSignatureWouldNotCover(t *testing.T) {
	artifact := []byte("plugin bundle bytes")
	base := Manifest{
		ID: "demo", Name: "Demo", Type: TypeSystem, Version: "1.0.0",
		Entrypoint: "demo", Capabilities: []string{"audit:read"},
		DigestSHA256: DigestSHA256(artifact),
	}
	if err := ValidateManifest(base); err != nil {
		t.Fatalf("baseline v1 manifest should validate: %v", err)
	}

	withRuntime := base
	withRuntime.Runtime = &RuntimeSpec{Protocol: "stdio-json-v2",
		Entrypoints: map[string]string{"linux/amd64": "./attacker-payload"}}
	if err := ValidateManifest(withRuntime); err == nil {
		t.Fatal("a v1 manifest carried runtime.entrypoints, which its signature does not cover")
	}

	withHostAccess := base
	withHostAccess.HostAccess = &HostAccessSpec{RPC: []RPCDependency{{Service: "core/nodes", Methods: []string{"exec"}}}}
	if err := ValidateManifest(withHostAccess); err == nil {
		t.Fatal("a v1 manifest carried host_access, which its signature does not cover")
	}
}

// dependencies used to be the one v2-era field the schema guard did not list,
// while also not being in the v1 signing payload. Both halves were true at once,
// so a signed v1 manifest kept a valid signature after its declared
// dependencies were dropped, and a required dependency is what gates load and
// activation. It is gated with the others now.
func TestV1SignatureCoversDependencies(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	artifact := []byte("plugin bundle bytes")
	m := Manifest{
		ID: "demo", Name: "Demo", Type: TypeSystem, Version: "1.0.0",
		Entrypoint: "demo", Publisher: "trusted", Capabilities: []string{"audit:read"},
		DigestSHA256: DigestSHA256(artifact),
		Dependencies: []DependencySpec{{ID: "required-peer"}},
	}
	m.SignatureEd25519 = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, SigningPayload(m)))
	policy := TrustPolicy{TrustedPublishers: map[string]ed25519.PublicKey{"trusted": pub}}
	if err := VerifyManifest(m, artifact, policy); err != nil {
		t.Fatalf("baseline v1 manifest with dependencies should verify: %v", err)
	}

	tampered := m
	tampered.Dependencies = nil
	if err := VerifyManifest(tampered, artifact, policy); err == nil {
		t.Fatal("a v1 manifest kept a valid signature after its declared dependencies were dropped")
	}
}
