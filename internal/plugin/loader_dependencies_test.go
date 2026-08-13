package plugin

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

// design-18 E1: dependency enforcement at load. Fixture shape: one trusted
// base plugin plus plugins that require it in various ways.
func TestLoaderEnforcesRequiredDependencies(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	artifact := []byte("artifact bytes")

	base := signedManifest(t, priv, Manifest{
		ID: "latticenet.vpn-core", Name: "VPN Core", Type: TypeSystem, Version: "0.8.0-alpha.7",
		Entrypoint: "system-go/p", Publisher: "latticenet", Capabilities: []string{"network:plan"},
	}, artifact)
	happy := signedManifest(t, priv, Manifest{
		ID: "latticenet.sub-store", Name: "Sub Store", Type: TypeSystem, Version: "0.12.1-alpha.8",
		Entrypoint: "system-go/p", Publisher: "latticenet", Capabilities: []string{"network:plan"},
		Dependencies: []DependencySpec{{ID: "latticenet.vpn-core", Version: ">=0.8.0-alpha.5"}},
	}, artifact)
	missing := signedManifest(t, priv, Manifest{
		ID: "needs.ghost", Name: "Needs Ghost", Type: TypeSystem, Version: "1.0.0",
		Entrypoint: "system-go/p", Publisher: "latticenet", Capabilities: []string{"network:plan"},
		Dependencies: []DependencySpec{{ID: "latticenet.netguard", Version: ">=0.1.0"}},
	}, artifact)
	tooLow := signedManifest(t, priv, Manifest{
		ID: "needs.newer", Name: "Needs Newer", Type: TypeSystem, Version: "1.0.0",
		Entrypoint: "system-go/p", Publisher: "latticenet", Capabilities: []string{"network:plan"},
		Dependencies: []DependencySpec{{ID: "latticenet.vpn-core", Version: ">=0.9.0"}},
	}, artifact)
	optionalMissing := signedManifest(t, priv, Manifest{
		ID: "wants.ghost", Name: "Wants Ghost", Type: TypeSystem, Version: "1.0.0",
		Entrypoint: "system-go/p", Publisher: "latticenet", Capabilities: []string{"network:plan"},
		Dependencies: []DependencySpec{{ID: "latticenet.wireguard", Optional: true}},
	}, artifact)

	for name, m := range map[string]Manifest{"base": base, "happy": happy, "missing": missing, "toolow": tooLow, "optional": optionalMissing} {
		writeBundle(t, root, name, m, artifact)
	}
	loaded, outcomes, err := (Loader{Dir: root, Policy: TrustPolicy{TrustedPublishers: map[string]ed25519.PublicKey{"latticenet": pub}}}).Load()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]bool{}
	for _, pl := range loaded {
		byID[pl.Manifest.ID] = true
	}
	for _, want := range []string{"latticenet.vpn-core", "latticenet.sub-store", "wants.ghost"} {
		if !byID[want] {
			t.Errorf("%s should load", want)
		}
	}
	for _, reject := range []string{"needs.ghost", "needs.newer"} {
		if byID[reject] {
			t.Errorf("%s should be rejected", reject)
		}
	}
	reasons := map[string]string{}
	for _, o := range outcomes {
		if !o.Loaded {
			reasons[o.PluginID] = o.Reason
		}
	}
	if !strings.Contains(reasons["needs.ghost"], "latticenet.netguard") || !strings.Contains(reasons["needs.ghost"], "not installed") {
		t.Errorf("needs.ghost reason = %q", reasons["needs.ghost"])
	}
	if !strings.Contains(reasons["needs.newer"], "0.8.0-alpha.7") || !strings.Contains(reasons["needs.newer"], ">=0.9.0") {
		t.Errorf("needs.newer reason = %q", reasons["needs.newer"])
	}
}

// A chain A→B→C with C missing rejects both A and B (fixpoint), rather than
// loading A against a B that was itself rejected.
func TestLoaderDependencyChainRejectsToFixpoint(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	artifact := []byte("artifact bytes")
	chainA := signedManifest(t, priv, Manifest{
		ID: "chain.a", Name: "A", Type: TypeSystem, Version: "1.0.0",
		Entrypoint: "system-go/p", Publisher: "latticenet", Capabilities: []string{"network:plan"},
		Dependencies: []DependencySpec{{ID: "chain.b"}},
	}, artifact)
	chainB := signedManifest(t, priv, Manifest{
		ID: "chain.b", Name: "B", Type: TypeSystem, Version: "1.0.0",
		Entrypoint: "system-go/p", Publisher: "latticenet", Capabilities: []string{"network:plan"},
		Dependencies: []DependencySpec{{ID: "chain.c"}},
	}, artifact)
	writeBundle(t, root, "a", chainA, artifact)
	writeBundle(t, root, "b", chainB, artifact)

	loaded, _, err := (Loader{Dir: root, Policy: TrustPolicy{TrustedPublishers: map[string]ed25519.PublicKey{"latticenet": pub}}}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 0 {
		t.Fatalf("the whole broken chain must reject; loaded: %+v", loaded)
	}
}

func TestValidateDependenciesShape(t *testing.T) {
	base := Manifest{ID: "p.one", Name: "P", Type: TypeSystem, Capabilities: []string{"network:plan"}}
	for name, deps := range map[string][]DependencySpec{
		"self":      {{ID: "p.one"}},
		"dup":       {{ID: "p.two"}, {ID: "p.two"}},
		"bad id":    {{ID: "not a plugin id!!"}},
		"bad range": {{ID: "p.two", Version: "garbage!!"}},
	} {
		m := base
		m.Dependencies = deps
		if err := ValidateManifest(m); err == nil {
			t.Errorf("%s: ValidateManifest should reject %+v", name, deps)
		}
	}
	ok := base
	ok.Dependencies = []DependencySpec{{ID: "p.two", Version: ">=1.0, <2.0"}, {ID: "p.three", Optional: true}}
	if err := ValidateManifest(ok); err != nil {
		t.Errorf("valid dependencies rejected: %v", err)
	}
}
