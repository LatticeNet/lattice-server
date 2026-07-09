package plugin

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
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

func TestValidateManifestAcceptsScopedCustomPluginSectionAndNestedRoute(t *testing.T) {
	err := ValidateManifest(Manifest{
		ID:           "vpn-ui",
		Name:         "VPN UI",
		Type:         TypeSystem,
		Capabilities: []string{"node:read"},
		Interfaces: []InterfaceContract{{
			Service: "vpn-ui/nodes",
			Methods: []string{"list"},
			Scopes:  []string{"proxy:read"},
		}},
		UI: &ManifestUI{
			Nav: []NavContribution{{
				Section: "vpn-manage", SectionTitle: "VPN Manage", Title: "Nodes",
				Route: "vpn-core/nodes", Scopes: []string{"proxy:read"},
			}},
			Views: []ViewContribution{{
				Route: "vpn-core/nodes", Title: "Nodes", Kind: "table",
				Source: &ViewSource{Interface: "vpn-ui/nodes", Method: "list"},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateManifestAcceptsOwnedBuiltinView(t *testing.T) {
	err := ValidateManifest(Manifest{
		ID:           "latticenet.vpn-core",
		Name:         "vpn-core",
		Type:         TypeSystem,
		Capabilities: []string{"node:read", "network:plan", "network:apply", "task:run"},
		UI: &ManifestUI{
			Nav: []NavContribution{{
				Section: "vpn-manage", SectionTitle: "VPN Manage", Title: "Users",
				Route: "users", Icon: "Users", Scopes: []string{"proxy:read"},
			}},
			Views: []ViewContribution{{
				Route: "users", Title: "Users", Kind: "builtin", ComponentKey: "proxy.users",
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateManifestAcceptsOfficialNetworkSecurityBuiltins(t *testing.T) {
	for _, tc := range []struct {
		id           string
		name         string
		title        string
		route        string
		icon         string
		componentKey string
	}{
		{
			id:           "latticenet.netguard",
			name:         "netguard (nftables security groups)",
			title:        "Firewall",
			route:        "firewall",
			icon:         "Shield",
			componentKey: "netguard.firewall",
		},
		{
			id:           "latticenet.wireguard",
			name:         "wireguard (VPN networks)",
			title:        "Networks",
			route:        "networks",
			icon:         "Spline",
			componentKey: "wireguard.networks",
		},
	} {
		t.Run(tc.id, func(t *testing.T) {
			err := ValidateManifest(Manifest{
				ID:           tc.id,
				Name:         tc.name,
				Type:         TypeSystem,
				Capabilities: []string{"node:read", "network:plan", "network:apply", "task:run"},
				UI: &ManifestUI{
					Nav: []NavContribution{{
						Section: "network-security", SectionTitle: "Network Security", Title: tc.title,
						Route: tc.route, Icon: tc.icon, Scopes: []string{"network:plan"},
					}},
					Views: []ViewContribution{{
						Route: tc.route, Title: tc.title, Kind: "builtin", ComponentKey: tc.componentKey,
					}},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidateManifestRejectsForeignBuiltinView(t *testing.T) {
	err := ValidateManifest(Manifest{
		ID:           "other-plugin",
		Name:         "Other Plugin",
		Type:         TypeSystem,
		Capabilities: []string{"node:read"},
		UI: &ManifestUI{Views: []ViewContribution{{
			Route: "users", Title: "Users", Kind: "builtin", ComponentKey: "proxy.users",
		}}},
	})
	if err == nil || !strings.Contains(err.Error(), "builtin component") {
		t.Fatalf("expected foreign builtin component rejection, got %v", err)
	}
}

func TestValidateManifestRejectsComponentKeyOnNonBuiltinView(t *testing.T) {
	err := ValidateManifest(Manifest{
		ID:           "table-ui",
		Name:         "Table UI",
		Type:         TypeSystem,
		Capabilities: []string{"node:read"},
		UI: &ManifestUI{Views: []ViewContribution{{
			Route: "nodes", Title: "Nodes", Kind: "table", ComponentKey: "proxy.users",
		}}},
	})
	if err == nil || !strings.Contains(err.Error(), "component_key requires builtin") {
		t.Fatalf("expected non-builtin component_key rejection, got %v", err)
	}
}

func TestValidateManifestRejectsUnknownContributionScope(t *testing.T) {
	err := ValidateManifest(Manifest{
		ID:           "bad-scope-ui",
		Name:         "Bad Scope UI",
		Type:         TypeSystem,
		Capabilities: []string{"node:read"},
		Interfaces: []InterfaceContract{{
			Service: "bad-scope-ui/nodes",
			Methods: []string{"list"},
			Scopes:  []string{"prox:read"},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid scope") {
		t.Fatalf("expected unknown RBAC scope rejection, got %v", err)
	}
}

func TestValidateManifestRejectsForeignInterfaceService(t *testing.T) {
	err := ValidateManifest(Manifest{
		ID:           "honest-ui",
		Name:         "Honest UI",
		Type:         TypeSystem,
		Capabilities: []string{"node:read"},
		Interfaces: []InterfaceContract{{
			Service: "other-plugin/nodes",
			Methods: []string{"list"},
			Scopes:  []string{"proxy:read"},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "must be under plugin id") {
		t.Fatalf("expected foreign interface service rejection, got %v", err)
	}
}

func TestValidateManifestRejectsInvalidInterfaceMethods(t *testing.T) {
	base := Manifest{
		ID:           "method-ui",
		Name:         "Method UI",
		Type:         TypeSystem,
		Capabilities: []string{"node:read"},
		Interfaces: []InterfaceContract{{
			Service: "method-ui/nodes",
			Methods: []string{"list"},
			Scopes:  []string{"proxy:read"},
		}},
	}
	base.Interfaces[0].Methods = []string{"list", "bad method"}
	if err := ValidateManifest(base); err == nil || !strings.Contains(err.Error(), "invalid method") {
		t.Fatalf("expected invalid method rejection, got %v", err)
	}
	base.Interfaces[0].Methods = []string{"list", "list"}
	if err := ValidateManifest(base); err == nil || !strings.Contains(err.Error(), "duplicate method") {
		t.Fatalf("expected duplicate method rejection, got %v", err)
	}
}

func TestValidateManifestRejectsUndeclaredActionAndUnscopedAction(t *testing.T) {
	base := Manifest{
		ID:           "actions-ui",
		Name:         "Actions UI",
		Type:         TypeSystem,
		Capabilities: []string{"node:read"},
		Interfaces: []InterfaceContract{{
			Service: "actions-ui/nodes",
			Methods: []string{"list"},
			Scopes:  []string{"proxy:read"},
		}},
		UI: &ManifestUI{Views: []ViewContribution{{
			Route: "nodes", Title: "Nodes", Kind: "table",
			Source:  &ViewSource{Interface: "actions-ui/nodes", Method: "list"},
			Actions: []ViewAction{{Label: "Delete", Interface: "actions-ui/nodes", Method: "delete", Scopes: []string{"proxy:admin"}}},
		}}},
	}
	if err := ValidateManifest(base); err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Fatalf("expected undeclared action rejection, got %v", err)
	}
	base.Interfaces = []InterfaceContract{{Service: "actions-ui/nodes", Methods: []string{"delete"}}}
	base.UI.Views[0].Source = nil
	base.UI.Views[0].Actions[0].Scopes = nil
	if err := ValidateManifest(base); err == nil || !strings.Contains(err.Error(), "must declare scopes") {
		t.Fatalf("expected unscoped action rejection, got %v", err)
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

func TestParseTrustPolicyJSONAcceptsStandardBase64PublisherKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policyBytes, err := json.Marshal(map[string]any{
		"trusted_publishers": map[string]string{
			"latticenet": base64.StdEncoding.EncodeToString(pub),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	policy, err := ParseTrustPolicyJSON(policyBytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := policy.TrustedPublishers["latticenet"]; string(got) != string(pub) {
		t.Fatalf("decoded wrong publisher key: got %x want %x", []byte(got), []byte(pub))
	}
}

func TestParseTrustPolicyJSONRejectsHexPublisherKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policyBytes, err := json.Marshal(map[string]any{
		"trusted_publishers": map[string]string{
			"latticenet": hex.EncodeToString(pub),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseTrustPolicyJSON(policyBytes)
	if err == nil || !strings.Contains(err.Error(), "invalid trusted publisher key") {
		t.Fatalf("expected hex key rejection, got %v", err)
	}
}

func TestHTTPEgressIsHostRiskRequiringSignature(t *testing.T) {
	// C6: http:egress is host-risk, so an UNSIGNED plugin carrying it must be
	// rejected (a signature is forced), while a signed-by-trusted-publisher plugin
	// is accepted. ValidateManifest still admits http:egress on a wasm plugin
	// (it is exempt from the system-only confinement) so the gate is the signature.
	if risk, _ := CapabilityRisk("http:egress"); risk != RiskHost {
		t.Fatalf("http:egress must be classified host-risk, got %q", risk)
	}

	// A wasm plugin may DECLARE http:egress (exempt from system-only rule).
	if err := ValidateManifest(Manifest{
		ID:           "egress-wasm",
		Name:         "Egress Wasm",
		Type:         TypeWasm,
		Capabilities: []string{"http:egress"},
	}); err != nil {
		t.Fatalf("wasm plugin must be allowed to declare http:egress: %v", err)
	}

	artifact := []byte("egress artifact bytes")

	// Unsigned http:egress plugin is rejected by the secure-by-default policy.
	unsigned := Manifest{
		ID:           "egress-unsigned",
		Name:         "Egress Unsigned",
		Type:         TypeWasm,
		Version:      "0.1.0",
		Entrypoint:   "wasm/egress-unsigned",
		Capabilities: []string{"http:egress"},
	}
	if err := VerifyManifest(unsigned, artifact, TrustPolicy{}); err == nil {
		t.Fatal("unsigned http:egress plugin must be rejected (signature required)")
	}

	// Signed by a trusted publisher: accepted.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed := Manifest{
		ID:           "egress-signed",
		Name:         "Egress Signed",
		Type:         TypeWasm,
		Version:      "0.1.0",
		Entrypoint:   "wasm/egress-signed",
		Capabilities: []string{"http:egress"},
		Publisher:    "latticenet",
		DigestSHA256: DigestSHA256(artifact),
	}
	signed.SignatureEd25519 = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, SigningPayload(signed)))
	if err := VerifyManifest(signed, artifact, TrustPolicy{
		TrustedPublishers: map[string]ed25519.PublicKey{"latticenet": pub},
	}); err != nil {
		t.Fatalf("signed http:egress plugin must be accepted: %v", err)
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
