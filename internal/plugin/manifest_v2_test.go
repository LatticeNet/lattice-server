package plugin

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func validManifestV2() Manifest {
	return Manifest{
		Schema:       ManifestSchemaV2,
		ID:           "latticenet.example",
		Name:         "Example",
		Type:         TypeSystem,
		Version:      "0.2.1-alpha.1",
		Publisher:    "latticenet",
		Capabilities: []string{"kv:read"},
		Bundle: &BundleSpec{
			Format:       BundleFormatTarGzip,
			DigestSHA256: strings.Repeat("a", 64),
		},
		Runtime: &RuntimeSpec{
			Protocol: RuntimeProtocolStdioJSONV1,
			Entrypoints: map[string]string{
				"linux/amd64": "bin/linux-amd64/plugin",
			},
		},
		UIRuntime: &UIRuntimeSpec{
			Mode:          UIRuntimeModeSandbox,
			Entrypoint:    "ui/index.html",
			BridgeVersion: UIBridgeVersion1,
		},
		Compatibility: &CompatibilitySpec{
			Server:          ">=0.2.1",
			DashboardHost:   ">=1",
			RuntimeProtocol: ">=1",
		},
		Interfaces: []InterfaceContract{{
			Service: "latticenet.example/items",
			MethodSpecs: []InterfaceMethod{
				{Name: "list", Effect: InterfaceEffectRead, Scopes: []string{"proxy:read"}},
				{Name: "save", Effect: InterfaceEffectWrite, Scopes: []string{"proxy:admin"}},
			},
		}},
		UI: &ManifestUI{
			Nav: []NavContribution{{
				Section: "extensions", Title: "Example", Route: "items", Scopes: []string{"proxy:read"},
			}},
			Views: []ViewContribution{{Route: "items", Title: "Example", Kind: "sandbox"}},
		},
	}
}

func TestManifestV2AcceptsCompleteTypedManifest(t *testing.T) {
	m := validManifestV2()
	m.Capabilities = append(m.Capabilities, "rpc:call", capHTTPOperatorTarget)
	m.Interfaces[0].MethodSpecs[0].OperatorTargetFields = []string{"base_url"}
	m.HostAccess = &HostAccessSpec{RPC: []RPCDependency{{
		Service: "latticenet.vpn-core/nodes", Methods: []string{"export"},
	}}}
	if err := ValidateManifest(m); err != nil {
		t.Fatal(err)
	}

	encoded, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Manifest
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if got := decoded.Interfaces[0].MethodSpecs[1]; got.Name != "save" || got.Effect != InterfaceEffectWrite || len(got.Scopes) != 1 {
		t.Fatalf("typed method did not round-trip: %+v", got)
	}
	if got := decoded.Interfaces[0].Methods; len(got) != 2 || got[0] != "list" || got[1] != "save" {
		t.Fatalf("normalized method names missing: %+v", got)
	}
	if got := decoded.HostAccess.RPC[0]; got.Service != "latticenet.vpn-core/nodes" || len(got.Methods) != 1 || got.Methods[0] != "export" {
		t.Fatalf("host access did not round-trip: %+v", got)
	}
	if got := decoded.Interfaces[0].MethodSpecs[0].OperatorTargetFields; len(got) != 1 || got[0] != "base_url" {
		t.Fatalf("operator target binding did not round-trip: %+v", got)
	}
}

func TestManifestV2RejectsUnsafeHostAccess(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Manifest)
		want string
	}{
		{"missing capability", func(m *Manifest) {
			m.HostAccess = &HostAccessSpec{RPC: []RPCDependency{{Service: "owner.plugin/items", Methods: []string{"list"}}}}
		}, "rpc:call"},
		{"invalid service", func(m *Manifest) {
			m.Capabilities = append(m.Capabilities, "rpc:call")
			m.HostAccess = &HostAccessSpec{RPC: []RPCDependency{{Service: "../items", Methods: []string{"list"}}}}
		}, "service"},
		{"own service", func(m *Manifest) {
			m.Capabilities = append(m.Capabilities, "rpc:call")
			m.HostAccess = &HostAccessSpec{RPC: []RPCDependency{{Service: "latticenet.example/items", Methods: []string{"list"}}}}
		}, "owned by the caller"},
		{"missing methods", func(m *Manifest) {
			m.Capabilities = append(m.Capabilities, "rpc:call")
			m.HostAccess = &HostAccessSpec{RPC: []RPCDependency{{Service: "owner.plugin/items"}}}
		}, "requires methods"},
		{"duplicate methods", func(m *Manifest) {
			m.Capabilities = append(m.Capabilities, "rpc:call")
			m.HostAccess = &HostAccessSpec{RPC: []RPCDependency{{Service: "owner.plugin/items", Methods: []string{"list", "list"}}}}
		}, "duplicate method"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := cloneManifestV2(t, validManifestV2())
			tc.edit(&m)
			if err := ValidateManifest(m); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestManifestV2RejectsLegacyAndIncompleteContracts(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Manifest)
		want string
	}{
		{"legacy entrypoint", func(m *Manifest) { m.Entrypoint = "artifact" }, "legacy entrypoint"},
		{"legacy digest", func(m *Manifest) { m.DigestSHA256 = strings.Repeat("b", 64) }, "legacy digest_sha256"},
		{"missing bundle", func(m *Manifest) { m.Bundle = nil }, "bundle is required"},
		{"wrong bundle format", func(m *Manifest) { m.Bundle.Format = "zip" }, "bundle format"},
		{"missing runtime", func(m *Manifest) { m.Runtime = nil }, "runtime is required"},
		{"missing platform", func(m *Manifest) { m.Runtime.Entrypoints = nil }, "platform entrypoint"},
		{"traversing runtime", func(m *Manifest) { m.Runtime.Entrypoints["linux/amd64"] = "../plugin" }, "runtime entrypoint"},
		{"absolute ui", func(m *Manifest) { m.UIRuntime.Entrypoint = "/ui/index.html" }, "ui entrypoint"},
		{"non-html ui", func(m *Manifest) { m.UIRuntime.Entrypoint = "ui/index.txt" }, ".html document"},
		{"control character path", func(m *Manifest) { m.UIRuntime.Entrypoint = "ui/\nindex.html" }, "ui entrypoint"},
		{"missing compatibility", func(m *Manifest) { m.Compatibility = nil }, "compatibility is required"},
		{"builtin view", func(m *Manifest) {
			m.UI.Views[0].Kind = "builtin"
		}, "builtin"},
		{"sandbox without runtime", func(m *Manifest) { m.UIRuntime = nil }, "ui_runtime"},
		{"unknown effect", func(m *Manifest) { m.Interfaces[0].MethodSpecs[0].Effect = "execute" }, "effect"},
		{"write without method scopes", func(m *Manifest) { m.Interfaces[0].MethodSpecs[1].Scopes = nil }, "method scopes"},
		{"legacy string methods", func(m *Manifest) {
			m.Interfaces[0] = InterfaceContract{
				Service: "latticenet.example/items", Methods: []string{"list"}, Scopes: []string{"proxy:read"},
			}
		}, "typed method"},
		{"duplicate interface service", func(m *Manifest) {
			m.Interfaces = append(m.Interfaces, m.Interfaces[0])
		}, "duplicated"},
		{"native navigation section", func(m *Manifest) { m.UI.Nav[0].Section = "proxy" }, "not allowed"},
		{"operator capability without binding", func(m *Manifest) {
			m.Capabilities = append(m.Capabilities, capHTTPOperatorTarget)
		}, "method-bound"},
		{"operator binding without capability", func(m *Manifest) {
			m.Interfaces[0].MethodSpecs[0].OperatorTargetFields = []string{"base_url"}
		}, capHTTPOperatorTarget},
		{"invalid operator binding field", func(m *Manifest) {
			m.Capabilities = append(m.Capabilities, capHTTPOperatorTarget)
			m.Interfaces[0].MethodSpecs[0].OperatorTargetFields = []string{"../base_url"}
		}, "invalid operator target field"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := cloneManifestV2(t, validManifestV2())
			tc.edit(&m)
			if err := ValidateManifest(m); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestManifestV2RejectsHybridSandboxView(t *testing.T) {
	m := validManifestV2()
	m.UI.Views[0].Source = &ViewSource{Interface: "latticenet.example/items", Method: "list"}
	if err := ValidateManifest(m); err == nil || !strings.Contains(err.Error(), "sandbox kind cannot") {
		t.Fatalf("expected hybrid sandbox rejection, got %v", err)
	}
}

func TestManifestV2InterfaceJSONRejectsMixedMethodEncoding(t *testing.T) {
	raw := []byte(`{
		"schema":"lattice.plugin.manifest.v2",
		"id":"latticenet.example","name":"Example","type":"system","version":"0.2.1-alpha.1",
		"publisher":"latticenet","capabilities":["kv:read"],
		"bundle":{"format":"tar+gzip","digest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		"runtime":{"protocol":"stdio-json-v1","entrypoints":{"linux/amd64":"bin/linux-amd64/plugin"}},
		"compatibility":{"server":">=0.2.1","dashboard_host":">=1","runtime_protocol":">=1"},
		"interfaces":[{"service":"latticenet.example/items","methods":["list",{"name":"save","effect":"write","scopes":["proxy:admin"]}]}]
	}`)
	if _, err := VerifyInstallManifest(raw, []byte("bundle"), TrustPolicy{}); err == nil || !strings.Contains(err.Error(), "methods") {
		t.Fatalf("expected mixed method encoding rejection, got %v", err)
	}
}

func TestSigningPayloadV1ParityWithInterface(t *testing.T) {
	m := Manifest{
		ID: "old.plugin", Name: "Old", Type: TypeSystem, Version: "0.1.0",
		Entrypoint: "system-go/old", Publisher: "latticenet",
		DigestSHA256: strings.Repeat("c", 64), Capabilities: []string{"node:read", "audit:read"},
		Interfaces: []InterfaceContract{{Service: "old.plugin/items", Methods: []string{"list"}, Scopes: []string{"proxy:read"}}},
	}
	want := strings.Join([]string{
		"lattice-plugin-manifest-v1", "old.plugin", "Old", "system", "0.1.0", "system-go/old", "latticenet",
		strings.Repeat("c", 64), "audit:read\x00node:read", "null",
		`[{"service":"old.plugin/items","methods":["list"],"scopes":["proxy:read"]}]`,
	}, "\n")
	if got := string(SigningPayload(m)); got != want {
		t.Fatalf("v1 signing payload changed\nwant: %q\n got: %q", want, got)
	}
}

func TestSigningPayloadV1ParityWithUIContribution(t *testing.T) {
	m := Manifest{
		ID: "old.ui", Name: "Old UI", Type: TypeSystem, Version: "0.1.0",
		Entrypoint: "system-go/old-ui", Publisher: "latticenet",
		DigestSHA256: strings.Repeat("d", 64), Capabilities: []string{"node:read"},
		Interfaces: []InterfaceContract{{Service: "old.ui/items", Methods: []string{"list"}, Scopes: []string{"proxy:read"}}},
		UI: &ManifestUI{
			Nav: []NavContribution{{Section: "proxy", Title: "Items", Route: "items", Icon: "Boxes", Scopes: []string{"proxy:read"}}},
			Views: []ViewContribution{{
				Route: "items", Title: "Items", Kind: "table",
				Source:  &ViewSource{Interface: "old.ui/items", Method: "list"},
				Columns: []ViewColumn{{Key: "name", Label: "Name"}},
			}},
		},
	}
	uiJSON, err := json.Marshal(m.UI)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"lattice-plugin-manifest-v1", "old.ui", "Old UI", "system", "0.1.0", "system-go/old-ui", "latticenet",
		strings.Repeat("d", 64), "node:read", string(uiJSON),
		`[{"service":"old.ui/items","methods":["list"],"scopes":["proxy:read"]}]`,
	}, "\n")
	if got := string(SigningPayload(m)); got != want {
		t.Fatalf("v1 UI signing payload changed\nwant: %q\n got: %q", want, got)
	}
}

func TestSigningPayloadV2CoversTypedManifest(t *testing.T) {
	base := validManifestV2()
	wantPrefix := "LATTICE-PLUGIN-MANIFEST-V2\n"
	if got := string(SigningPayload(base)); !strings.HasPrefix(got, wantPrefix) || strings.Contains(got, "signature_ed25519") {
		t.Fatalf("unexpected v2 payload: %q", got)
	}

	mutations := map[string]func(*Manifest){
		"id":               func(m *Manifest) { m.ID += ".changed" },
		"name":             func(m *Manifest) { m.Name += " changed" },
		"type":             func(m *Manifest) { m.Type = TypeWasm },
		"version":          func(m *Manifest) { m.Version += ".1" },
		"publisher":        func(m *Manifest) { m.Publisher = "other" },
		"capability":       func(m *Manifest) { m.Capabilities[0] = "kv:write" },
		"bundle format":    func(m *Manifest) { m.Bundle.Format = "other" },
		"bundle digest":    func(m *Manifest) { m.Bundle.DigestSHA256 = strings.Repeat("b", 64) },
		"runtime protocol": func(m *Manifest) { m.Runtime.Protocol = "other" },
		"runtime platform": func(m *Manifest) { m.Runtime.Entrypoints["linux/arm64"] = "bin/linux-arm64/plugin" },
		"runtime path":     func(m *Manifest) { m.Runtime.Entrypoints["linux/amd64"] = "bin/linux-amd64/other" },
		"ui mode":          func(m *Manifest) { m.UIRuntime.Mode = "other" },
		"ui path":          func(m *Manifest) { m.UIRuntime.Entrypoint = "ui/other.html" },
		"bridge version":   func(m *Manifest) { m.UIRuntime.BridgeVersion = "2" },
		"server compat":    func(m *Manifest) { m.Compatibility.Server = ">=9" },
		"dashboard compat": func(m *Manifest) { m.Compatibility.DashboardHost = ">=9" },
		"protocol compat":  func(m *Manifest) { m.Compatibility.RuntimeProtocol = ">=9" },
		"host access": func(m *Manifest) {
			m.Capabilities = append(m.Capabilities, "rpc:call")
			m.HostAccess = &HostAccessSpec{RPC: []RPCDependency{{Service: "owner.plugin/items", Methods: []string{"list"}}}}
		},
		"navigation":        func(m *Manifest) { m.UI.Nav[0].Title = "Changed" },
		"view":              func(m *Manifest) { m.UI.Views[0].Route = "changed" },
		"interface effect":  func(m *Manifest) { m.Interfaces[0].MethodSpecs[0].Effect = InterfaceEffectPlan },
		"interface scopes":  func(m *Manifest) { m.Interfaces[0].MethodSpecs[0].Scopes = []string{"proxy:admin"} },
		"interface service": func(m *Manifest) { m.Interfaces[0].Service += ".changed" },
		"interface method":  func(m *Manifest) { m.Interfaces[0].MethodSpecs[0].Name = "get" },
	}
	basePayload := string(SigningPayload(base))
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			m := cloneManifestV2(t, base)
			mutate(&m)
			if got := string(SigningPayload(m)); got == basePayload {
				t.Fatal("mutation was not covered by the v2 signing payload")
			}
		})
	}
}

func TestManifestV2VerificationUsesBundleDigestAndRequiresSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle := []byte("compressed bundle bytes")
	m := validManifestV2()
	m.Bundle.DigestSHA256 = DigestSHA256(bundle)
	if err := VerifyManifest(m, bundle, TrustPolicy{TrustedPublishers: map[string]ed25519.PublicKey{"latticenet": pub}}); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("unsigned v2 manifest must be rejected, got %v", err)
	}
	m.SignatureEd25519 = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, SigningPayload(m)))
	if err := VerifyManifest(m, bundle, TrustPolicy{TrustedPublishers: map[string]ed25519.PublicKey{"latticenet": pub}}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(m, []byte("tampered"), TrustPolicy{TrustedPublishers: map[string]ed25519.PublicKey{"latticenet": pub}}); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("expected bundle digest mismatch, got %v", err)
	}
}

func cloneManifestV2(t *testing.T, in Manifest) Manifest {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Manifest
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// Backing is omitempty, so a manifest signed before the field existed must serialize to
// exactly the same bytes and keep its signature valid. The publisher seed is operator-
// held: if this parity broke, every deployed plugin would need re-signing before it
// could load again.
func TestBackingOmittedKeepsSigningPayloadByteIdentical(t *testing.T) {
	base := Manifest{
		Schema: ManifestSchemaV2, ID: "latticenet.example", Name: "Example", Type: TypeSystem,
		Version: "0.2.1-alpha.1", Publisher: "latticenet", Capabilities: []string{"kv:read"},
		Bundle:  &BundleSpec{Format: BundleFormatTarGzip, DigestSHA256: strings.Repeat("a", 64)},
		Runtime: &RuntimeSpec{Protocol: RuntimeProtocolStdioJSONV1, Entrypoints: map[string]string{"linux/amd64": "bin/linux-amd64/plugin"}},
		Compatibility: &CompatibilitySpec{
			Server: ">=0.2.1", DashboardHost: ">=1", RuntimeProtocol: ">=1",
		},
		Interfaces: []InterfaceContract{{
			Service:     "latticenet.example/items",
			MethodSpecs: []InterfaceMethod{{Name: "list", Effect: InterfaceEffectRead, Scopes: []string{"proxy:read"}}},
		}},
	}

	undeclared := SigningPayload(base)
	if strings.Contains(string(undeclared), "backing") {
		t.Fatalf("an undeclared backing must not appear in the signing payload: %s", undeclared)
	}

	// Declaring backing MUST change the payload — it is a security-relevant claim and
	// has to be covered by the signature, not swappable after signing.
	declared := base
	declared.Interfaces = []InterfaceContract{{
		Service:     "latticenet.example/items",
		Backing:     BackingCore,
		MethodSpecs: []InterfaceMethod{{Name: "list", Effect: InterfaceEffectRead, Scopes: []string{"proxy:read"}}},
	}}
	signed := SigningPayload(declared)
	if string(undeclared) == string(signed) {
		t.Fatal("declaring backing must change the signing payload, or it could be swapped after signing")
	}
	if !strings.Contains(string(signed), `"backing":"core"`) {
		t.Fatalf("declared backing missing from signing payload: %s", signed)
	}
}

func TestBackingValidation(t *testing.T) {
	newManifest := func(pluginType, backing string) Manifest {
		return Manifest{
			Schema: ManifestSchemaV2, ID: "latticenet.example", Name: "Example", Type: pluginType,
			Version: "0.2.1-alpha.1", Publisher: "latticenet", Capabilities: []string{"kv:read"},
			Bundle:  &BundleSpec{Format: BundleFormatTarGzip, DigestSHA256: strings.Repeat("a", 64)},
			Runtime: &RuntimeSpec{Protocol: RuntimeProtocolStdioJSONV1, Entrypoints: map[string]string{"linux/amd64": "bin/linux-amd64/plugin"}},
			Compatibility: &CompatibilitySpec{
				Server: ">=0.2.1", DashboardHost: ">=1", RuntimeProtocol: ">=1",
			},
			Interfaces: []InterfaceContract{{
				Service:     "latticenet.example/items",
				Backing:     backing,
				MethodSpecs: []InterfaceMethod{{Name: "list", Effect: InterfaceEffectRead, Scopes: []string{"proxy:read"}}},
			}},
		}
	}

	for _, valid := range []string{"", BackingRuntime, BackingCore} {
		if err := ValidateManifest(newManifest(TypeSystem, valid)); err != nil {
			t.Fatalf("backing %q should be valid for a system plugin: %v", valid, err)
		}
	}
	if err := ValidateManifest(newManifest(TypeSystem, "wasm")); err == nil {
		t.Fatal("an unknown backing must be rejected")
	}
	// Claiming core is a claim on the host's own trust base.
	if err := ValidateManifest(newManifest(TypeWasm, BackingCore)); err == nil {
		t.Fatal("a non-system plugin must not declare core backing")
	}
}
