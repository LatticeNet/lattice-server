package plugin

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestServerSemverReadsTheReleaseTags(t *testing.T) {
	for tag, want := range map[string]string{
		"alpha-0.2.2a147": "0.2.2-alpha.147",
		"alpha-0.2.2a9":   "0.2.2-alpha.9",
		"beta-0.3.0b2":    "0.3.0-beta.2",
		"v0.2.3":          "0.2.3",
		"0.2.3":           "0.2.3",
	} {
		got, ok := ServerSemver(tag)
		if !ok || got != want {
			t.Errorf("ServerSemver(%q) = %q, %v; want %q", tag, got, ok, want)
		}
	}
	for _, tag := range []string{"dev", "", "alpha", "latest", "sha-0123abc", "alpha-0.2.2", "v0.2"} {
		if got, ok := ServerSemver(tag); ok {
			t.Errorf("ServerSemver(%q) = %q, want not recognised", tag, got)
		}
	}
}

func TestCheckServerFloor(t *testing.T) {
	with := func(server, minServer string) Manifest {
		return Manifest{Compatibility: &CompatibilitySpec{Server: server}, MinServer: minServer}
	}
	cases := []struct {
		name    string
		m       Manifest
		server  string
		refused bool
	}{
		{"meets the floor", with(">=0.2.2-alpha.133", ""), "0.2.2-alpha.147", false},
		{"meets it exactly", with(">=0.2.2-alpha.147", ""), "0.2.2-alpha.147", false},
		{"below the floor", with(">=0.2.2-alpha.147", ""), "0.2.2-alpha.146", true},
		{"numeric train order, not text", with(">=0.2.2-alpha.99", ""), "0.2.2-alpha.147", false},
		{"a stable release outranks its alphas", with(">=0.2.2-alpha.147", ""), "0.2.2", false},
		{"an old floor", with(">=0.2.1", ""), "0.2.2-alpha.146", false},
		{"a bare version is a floor", with("0.2.2-alpha.147", ""), "0.2.2-alpha.150", false},
		{"a bare version below", with("0.2.2-alpha.147", ""), "0.2.2-alpha.140", true},
		{"min_server is read too", with(">=0.2.1", "0.2.2-alpha.150"), "0.2.2-alpha.147", true},
		{"a floor that does not parse is not enforced", with("0.2.x", ""), "0.2.2-alpha.1", false},
		{"no server version enforces nothing", with(">=9.0.0", ""), "", false},
		{"a legacy manifest has no floor", Manifest{}, "0.2.2-alpha.147", false},
	}
	for _, tc := range cases {
		err := checkServerFloor(tc.m, tc.server)
		if (err != nil) != tc.refused {
			t.Errorf("%s: err = %v, refused want %v", tc.name, err, tc.refused)
		}
	}
	err := checkServerFloor(with(">=0.2.2-alpha.147", ""), "0.2.2-alpha.146")
	if err == nil || !strings.Contains(err.Error(), ">=0.2.2-alpha.147") || !strings.Contains(err.Error(), "0.2.2-alpha.146") {
		t.Errorf("refusal should name the floor and this server: %v", err)
	}
}

// A plugin that needs a newer server is rejected with that reason, and a
// plugin that requires it is rejected through the dependency pass.
func TestLoaderRejectsAPluginAboveTheServerFloor(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	cache := t.TempDir()
	archive := makeTestArchive(t,
		testArchiveEntry{name: "bin/linux-amd64/plugin", body: []byte("amd64")},
		testArchiveEntry{name: "ui/index.html", body: []byte("<main>floor</main>")},
	)
	bundle := func(dir, id, floor string, deps ...DependencySpec) {
		m := validManifestV2()
		m.ID, m.Name, m.Version, m.Dependencies = id, id, "1.0.0", deps
		m.Interfaces = nil
		m.Compatibility.Server = floor
		writeBundle(t, root, dir, signedManifestV2(t, priv, m, archive), archive)
	}
	bundle("old", "fits.old", ">=0.2.1")
	bundle("new", "needs.newer", ">=0.2.2-alpha.147")
	bundle("dep", "needs.dependent", ">=0.2.1", DependencySpec{ID: "needs.newer", Version: ">=1.0.0"})
	load := func(serverVersion string) ([]Loaded, map[string]string) {
		loaded, outcomes, err := Loader{
			Dir: root, CacheDir: cache, Platform: "linux/amd64", ServerVersion: serverVersion,
			Policy: TrustPolicy{TrustedPublishers: map[string]ed25519.PublicKey{"latticenet": pub}},
		}.Load()
		if err != nil {
			t.Fatal(err)
		}
		reasons := map[string]string{}
		for _, o := range outcomes {
			if !o.Loaded {
				reasons[o.PluginID] = o.Reason
			}
		}
		return loaded, reasons
	}

	loaded, reasons := load("0.2.2-alpha.146")
	if len(loaded) != 1 || loaded[0].Manifest.ID != "fits.old" {
		t.Fatalf("loaded = %d plugins, reasons %v; want only fits.old", len(loaded), reasons)
	}
	if !strings.Contains(reasons["needs.newer"], "needs a server >=0.2.2-alpha.147") {
		t.Errorf("needs.newer reason = %q", reasons["needs.newer"])
	}
	if reasons["needs.dependent"] == "" {
		t.Errorf("needs.dependent should be rejected through its dependency")
	}
	if loaded, reasons := load("0.2.2-alpha.147"); len(loaded) != 3 {
		t.Errorf("on a server that meets the floor all three load, got %d (%v)", len(loaded), reasons)
	}
	if loaded, reasons := load(""); len(loaded) != 3 {
		t.Errorf("a development build enforces no floor, got %d (%v)", len(loaded), reasons)
	}
}
