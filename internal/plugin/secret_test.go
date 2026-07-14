package plugin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

type fakeSecretHost struct {
	values map[string]string
	err    error
}

func (h *fakeSecretHost) Get(_ context.Context, key string) (string, bool, error) {
	if h.err != nil {
		return "", false, h.err
	}
	v, ok := h.values[key]
	return v, ok, nil
}

func (h *fakeSecretHost) Put(_ context.Context, key, value string) error {
	if h.err != nil {
		return h.err
	}
	h.values[key] = value
	return nil
}

func (h *fakeSecretHost) Delete(_ context.Context, key string) error {
	if h.err != nil {
		return h.err
	}
	delete(h.values, key)
	return nil
}

func secretBroker(t *testing.T, capabilities ...string) (*Broker, *fakeSecretHost) {
	t.Helper()
	host := &fakeSecretHost{values: map[string]string{}}
	broker, err := NewBroker(Loaded{
		Manifest: Manifest{
			ID: "latticenet.wireguard", Name: "WG", Type: TypeSystem, Capabilities: capabilities,
		},
		Capabilities: capabilities,
	}, HostServices{Secret: host})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	return broker, host
}

// The broker pins the bucket, so a plugin can only ever reach its own vault. A key
// carrying a slash would otherwise let it name a bucket and read another plugin's
// private keys — the same confused-deputy escape the KV namespace closes.
func TestSecretKeyIsPinnedToThePluginsOwnVault(t *testing.T) {
	broker, host := secretBroker(t, "secret:read", "secret:write")
	ctx := context.Background()

	if err := broker.SecretPut(ctx, "node-a.privkey", "wg-secret"); err != nil {
		t.Fatal(err)
	}
	if _, ok := host.values["pluginsecret:latticenet.wireguard/node-a.privkey"]; !ok {
		t.Fatalf("secret was not written under the plugin's pinned bucket: %v", host.values)
	}

	for _, escape := range []string{
		"../latticenet.vpn-core/key",
		"pluginsecret:latticenet.vpn-core/key",
		"a/b",
		"a\\b",
		"",
	} {
		if err := broker.SecretPut(ctx, escape, "x"); err == nil {
			t.Fatalf("key %q escaped the plugin's namespace", escape)
		}
		if _, _, err := broker.SecretGet(ctx, escape); err == nil {
			t.Fatalf("key %q escaped the plugin's namespace on read", escape)
		}
	}
}

func TestSecretCallsRequireTheMatchingCapability(t *testing.T) {
	ctx := context.Background()

	readOnly, _ := secretBroker(t, "secret:read")
	if err := readOnly.SecretPut(ctx, "k", "v"); !errors.Is(err, ErrCapabilityDenied) {
		t.Fatalf("secret:read must not grant writes, got %v", err)
	}
	if err := readOnly.SecretDelete(ctx, "k"); !errors.Is(err, ErrCapabilityDenied) {
		t.Fatalf("secret:read must not grant deletes, got %v", err)
	}

	writeOnly, _ := secretBroker(t, "secret:write")
	if _, _, err := writeOnly.SecretGet(ctx, "k"); !errors.Is(err, ErrCapabilityDenied) {
		t.Fatalf("secret:write must not grant reads, got %v", err)
	}

	// Holding some other capability grants nothing here.
	unrelated, _ := secretBroker(t, "kv:read")
	if _, _, err := unrelated.SecretGet(ctx, "k"); !errors.Is(err, ErrCapabilityDenied) {
		t.Fatalf("a plugin without secret:read must be denied, got %v", err)
	}
	if err := unrelated.SecretPut(ctx, "k", "v"); !errors.Is(err, ErrCapabilityDenied) {
		t.Fatalf("a plugin without secret:write must be denied, got %v", err)
	}
}

// A granted capability with no wired service must fail closed rather than silently
// falling back to anything else.
func TestSecretWithoutHostServiceFailsClosed(t *testing.T) {
	broker, err := NewBroker(Loaded{
		Manifest: Manifest{
			ID: "latticenet.wireguard", Name: "WG", Type: TypeSystem,
			Capabilities: []string{"secret:read"},
		},
		Capabilities: []string{"secret:read"},
	}, HostServices{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := broker.SecretGet(context.Background(), "k"); !errors.Is(err, ErrHostServiceUnavailable) {
		t.Fatalf("want ErrHostServiceUnavailable, got %v", err)
	}
}

// secret:read/secret:write are host-risk. Unlike guarded egress, there is no broker
// check that makes handing a sandboxed third party a key vault safe, so they must be
// confined to system plugins — which the capability model enforces by OMITTING them
// from hostRiskExemptForNonSystem and workerCapabilities.
func TestSecretCapabilitiesAreSystemPluginsOnly(t *testing.T) {
	for _, pluginType := range []string{TypeWasm, TypeWorker} {
		for _, capability := range []string{"secret:read", "secret:write"} {
			err := ValidateManifest(Manifest{
				ID: "third.party", Name: "Third party", Type: pluginType, Version: "1",
				Capabilities: []string{capability},
			})
			if err == nil {
				t.Fatalf("%s plugin must not be able to declare %q", pluginType, capability)
			}
			if !strings.Contains(err.Error(), "system plugin") && !strings.Contains(err.Error(), "worker") {
				t.Fatalf("unexpected rejection reason for %s/%s: %v", pluginType, capability, err)
			}
		}
	}
	if err := ValidateManifest(Manifest{
		ID: "latticenet.wireguard", Name: "WG", Type: TypeSystem, Version: "1",
		Capabilities: []string{"secret:read", "secret:write"},
	}); err != nil {
		t.Fatalf("a system plugin may hold the secret capabilities: %v", err)
	}
}

// AllowUnsignedHostRisk is a dev-only escape hatch for host-risk capabilities. It must
// not reach a v2 plugin: a bundle that can read a key vault has to be signed by a
// publisher the operator explicitly trusts, escape hatch or not.
func TestSecretHoldingV2ManifestIsSignatureRequiredEvenWithUnsignedHostRiskAllowed(t *testing.T) {
	m := Manifest{
		Schema: ManifestSchemaV2, ID: "latticenet.wireguard", Name: "WG", Type: TypeSystem,
		Version: "0.1.0-alpha.8", Publisher: "latticenet",
		Capabilities: []string{"secret:read"},
		Bundle:       &BundleSpec{Format: BundleFormatTarGzip, DigestSHA256: strings.Repeat("a", 64)},
		Runtime: &RuntimeSpec{Protocol: RuntimeProtocolStdioJSONV1, Entrypoints: map[string]string{
			"linux/amd64": "bin/linux-amd64/plugin",
		}},
		Compatibility: &CompatibilitySpec{Server: ">=0.2.1", DashboardHost: ">=1", RuntimeProtocol: ">=1"},
		Interfaces: []InterfaceContract{{
			Service: "latticenet.wireguard/networks", Backing: BackingCore,
			MethodSpecs: []InterfaceMethod{{Name: "overview", Effect: InterfaceEffectRead, Scopes: []string{"node:read"}}},
		}},
	}
	policy := TrustPolicy{
		TrustedPublishers:     map[string]ed25519.PublicKey{},
		AllowUnsignedHostRisk: true,
	}
	if err := VerifyManifest(m, nil, policy); err == nil {
		t.Fatal("an unsigned v2 manifest holding secret:read must be rejected even when AllowUnsignedHostRisk is set")
	}

	// With a trusted publisher it verifies, proving the rejection above was the
	// signature requirement and not some unrelated validation failure.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifact := []byte("bundle")
	m.Bundle.DigestSHA256 = DigestSHA256(artifact)
	m.SignatureEd25519 = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, SigningPayload(m)))
	policy.TrustedPublishers["latticenet"] = pub
	if err := VerifyManifest(m, artifact, policy); err != nil {
		t.Fatalf("a signed, trusted v2 manifest holding secret:read must verify: %v", err)
	}
}
