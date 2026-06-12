package plugin

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateManifestRejectsUnknownCapability(t *testing.T) {
	err := ValidateManifest(Manifest{
		ID:           "bad",
		Name:         "Bad",
		Type:         "wasm",
		Capabilities: []string{"exec:anything"},
	})
	if err == nil {
		t.Fatal("expected unknown capability rejection")
	}
}

func TestValidateManifestRejectsUnsafeIdentityAndEmptyCapabilities(t *testing.T) {
	for _, tc := range []Manifest{
		{ID: "../bad", Name: "Bad", Type: "system", Capabilities: []string{"network:plan"}},
		{ID: "bad/slash", Name: "Bad", Type: "system", Capabilities: []string{"network:plan"}},
		{ID: "bad space", Name: "Bad", Type: "system", Capabilities: []string{"network:plan"}},
		{ID: "empty-caps", Name: "Empty Caps", Type: "system"},
	} {
		if err := ValidateManifest(tc); err == nil {
			t.Fatalf("expected manifest rejection for %#v", tc)
		}
	}
}

func TestValidateManifestRejectsDuplicateCapability(t *testing.T) {
	err := ValidateManifest(Manifest{
		ID:           "dup-cap",
		Name:         "Duplicate Capability",
		Type:         "system",
		Capabilities: []string{"network:plan", "network:plan"},
	})
	if err == nil {
		t.Fatal("expected duplicate capability rejection")
	}
}

func TestValidateManifestAcceptsSystemNetworkPlan(t *testing.T) {
	err := ValidateManifest(Manifest{
		ID:           "nft",
		Name:         "nft guard",
		Type:         "system",
		Capabilities: []string{"network:plan", "network:apply"},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateManifestAcceptsBuiltInFeatureCapabilities(t *testing.T) {
	err := ValidateManifest(Manifest{
		ID:   "ops",
		Name: "Ops Bundle",
		Type: "system",
		Capabilities: []string{
			"node:read",
			"monitor:admin",
			"ddns:admin",
			"tunnel:admin",
			"notify:send",
			"audit:read",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateManifestAcceptsReadOnlyTaskCapabilityForWasm(t *testing.T) {
	err := ValidateManifest(Manifest{
		ID:           "task-status",
		Name:         "Task Status",
		Type:         "wasm",
		Capabilities: []string{"task:read"},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateManifestRejectsHostRiskForWasm(t *testing.T) {
	err := ValidateManifest(Manifest{
		ID:           "third-party-network",
		Name:         "Third Party Network",
		Type:         "wasm",
		Capabilities: []string{"network:apply"},
	})
	if err == nil {
		t.Fatal("expected wasm plugin to be denied host-risk capability")
	}
}

func TestValidateManifestRejectsHostRiskForWorker(t *testing.T) {
	err := ValidateManifest(Manifest{
		ID:           "worker-shell",
		Name:         "Worker Shell",
		Type:         "worker",
		Capabilities: []string{"worker:route", "task:run"},
	})
	if err == nil {
		t.Fatal("expected worker plugin to be denied host-risk capability")
	}
}

func TestValidateManifestAcceptsRestrictedWorker(t *testing.T) {
	err := ValidateManifest(Manifest{
		ID:           "status-card",
		Name:         "Status Card",
		Type:         "worker",
		Capabilities: []string{"worker:route", "kv:read"},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyManifestAcceptsTrustedPublisherSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifact := []byte("plugin artifact bytes")
	manifest := Manifest{
		ID:               "signed-plugin",
		Name:             "Signed Plugin",
		Type:             TypeSystem,
		Version:          "0.1.0",
		Entrypoint:       "system-go/signed-plugin",
		Capabilities:     []string{"network:plan"},
		Publisher:        "latticenet",
		DigestSHA256:     DigestSHA256(artifact),
		SignatureEd25519: "",
	}
	manifest.SignatureEd25519 = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, SigningPayload(manifest)))

	err = VerifyManifest(manifest, artifact, TrustPolicy{
		TrustedPublishers: map[string]ed25519.PublicKey{"latticenet": pub},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyManifestRejectsDigestMismatch(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{
		ID:               "digest-plugin",
		Name:             "Digest Plugin",
		Type:             TypeSystem,
		Version:          "0.1.0",
		Entrypoint:       "system-go/digest-plugin",
		Capabilities:     []string{"network:plan"},
		Publisher:        "latticenet",
		DigestSHA256:     DigestSHA256([]byte("expected artifact")),
		SignatureEd25519: "",
	}
	manifest.SignatureEd25519 = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, SigningPayload(manifest)))

	err = VerifyManifest(manifest, []byte("tampered artifact"), TrustPolicy{
		TrustedPublishers: map[string]ed25519.PublicKey{"latticenet": pub},
	})
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("expected digest mismatch, got %v", err)
	}
}

func TestVerifyManifestRequiresTrustedPublisherForHostRisk(t *testing.T) {
	manifest := Manifest{
		ID:           "unsigned-host",
		Name:         "Unsigned Host",
		Type:         TypeSystem,
		Version:      "0.1.0",
		Entrypoint:   "system-go/unsigned-host",
		Capabilities: []string{"network:plan"},
		Publisher:    "unknown",
	}

	err := VerifyManifest(manifest, []byte("artifact"), TrustPolicy{})
	if err == nil || !strings.Contains(err.Error(), "trusted publisher") {
		t.Fatalf("expected trusted publisher rejection, got %v", err)
	}
}

func TestVerifyManifestRejectsSignatureForDifferentManifest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifact := []byte("plugin artifact bytes")
	signed := Manifest{
		ID:           "signed-id",
		Name:         "Signed ID",
		Type:         TypeSystem,
		Version:      "0.1.0",
		Entrypoint:   "system-go/signed-id",
		Capabilities: []string{"network:plan"},
		Publisher:    "latticenet",
		DigestSHA256: DigestSHA256(artifact),
	}
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, SigningPayload(signed)))
	tampered := signed
	tampered.ID = "other-id"
	tampered.SignatureEd25519 = signature

	err = VerifyManifest(tampered, artifact, TrustPolicy{
		TrustedPublishers: map[string]ed25519.PublicKey{"latticenet": pub},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("expected invalid signature, got %v", err)
	}
}

func TestVerifyManifestRejectsSignatureForRenamedManifest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifact := []byte("plugin artifact bytes")
	signed := Manifest{
		ID:           "signed-name",
		Name:         "Expected Name",
		Type:         TypeSystem,
		Version:      "0.1.0",
		Entrypoint:   "system-go/signed-name",
		Capabilities: []string{"network:plan"},
		Publisher:    "latticenet",
		DigestSHA256: DigestSHA256(artifact),
	}
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, SigningPayload(signed)))
	tampered := signed
	tampered.Name = "Misleading Name"
	tampered.SignatureEd25519 = signature

	err = VerifyManifest(tampered, artifact, TrustPolicy{
		TrustedPublishers: map[string]ed25519.PublicKey{"latticenet": pub},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("expected invalid signature, got %v", err)
	}
}

func TestParseTrustPolicyJSONDrivesInstallManifestVerification(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifact := []byte("plugin artifact bytes")
	manifest := Manifest{
		ID:           "install-plugin",
		Name:         "Install Plugin",
		Type:         TypeSystem,
		Version:      "0.1.0",
		Entrypoint:   "system-go/install-plugin",
		Capabilities: []string{"network:plan"},
		Publisher:    "latticenet",
		DigestSHA256: DigestSHA256(artifact),
	}
	manifest.SignatureEd25519 = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, SigningPayload(manifest)))
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	policyBytes, err := json.Marshal(map[string]any{
		"allow_unsigned_host_risk": false,
		"trusted_publishers": map[string]string{
			"latticenet": base64.RawStdEncoding.EncodeToString(pub),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	policy, err := ParseTrustPolicyJSON(policyBytes)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyInstallManifest(manifestBytes, artifact, policy)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != manifest.ID || got.Publisher != manifest.Publisher {
		t.Fatalf("decoded wrong manifest: %+v", got)
	}
}

func TestVerifyInstallManifestRejectsUnknownManifestField(t *testing.T) {
	manifestBytes := []byte(`{
		"id":"bad-field",
		"name":"Bad Field",
		"type":"system",
		"version":"0.1.0",
		"entrypoint":"system-go/bad-field",
		"capabilities":["network:plan"],
		"publisher":"latticenet",
		"digest_sha_256":"misspelled"
	}`)

	_, err := VerifyInstallManifest(manifestBytes, []byte("artifact"), TrustPolicy{})
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown field rejection, got %v", err)
	}
}

func TestParseTrustPolicyJSONRejectsInvalidPublisherKey(t *testing.T) {
	_, err := ParseTrustPolicyJSON([]byte(`{
		"allow_unsigned_host_risk": true,
		"trusted_publishers": {
			"latticenet": "not-base64"
		}
	}`))
	if err == nil || !strings.Contains(err.Error(), "invalid trusted publisher key") {
		t.Fatalf("expected invalid key rejection, got %v", err)
	}
}

func TestVerifyManifestSecureByDefaultRejectsUnsignedHostRisk(t *testing.T) {
	// A zero-value TrustPolicy must be fail-closed: an unsigned host-risk
	// manifest is rejected even though no policy flag was set.
	manifest := Manifest{
		ID:           "unsigned-default",
		Name:         "Unsigned Default",
		Type:         TypeSystem,
		Version:      "0.1.0",
		Entrypoint:   "system-go/unsigned-default",
		Capabilities: []string{"network:plan"},
	}
	if err := VerifyManifest(manifest, []byte("artifact"), TrustPolicy{}); err == nil {
		t.Fatal("zero-value trust policy must reject unsigned host-risk plugin")
	}
}

func TestVerifyManifestAllowUnsignedHostRiskOptOut(t *testing.T) {
	// Operators may explicitly opt into unsigned host-risk plugins (dev only).
	manifest := Manifest{
		ID:           "unsigned-optout",
		Name:         "Unsigned Optout",
		Type:         TypeSystem,
		Version:      "0.1.0",
		Entrypoint:   "system-go/unsigned-optout",
		Capabilities: []string{"network:plan"},
	}
	if err := VerifyManifest(manifest, []byte("artifact"), TrustPolicy{AllowUnsignedHostRisk: true}); err != nil {
		t.Fatalf("opt-out should allow unsigned host-risk plugin, got %v", err)
	}
}
