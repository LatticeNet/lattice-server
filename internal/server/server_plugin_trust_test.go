package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func trustView(t *testing.T, policy plugin.TrustPolicy) (pluginTrustView, string) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true, PluginTrust: policy})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)
	resp := doJSON(t, handler, http.MethodGet, "/api/plugin-trust", "", cookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: want 200, got %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	var view pluginTrustView
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("decode: %v (%s)", err, raw)
	}
	return view, string(raw)
}

// The boring case must be STATED, not implied by silence: a dashboard that renders a
// banner only when a field appears would show nothing against a server that never
// answered, and "nothing" would then mean both "trust is normal" and "I do not know".
func TestPluginTrustAlwaysAnswersEvenWhenNormal(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	view, raw := trustView(t, plugin.TrustPolicy{TrustedPublishers: map[string]ed25519.PublicKey{officialPublisher: pub}})
	if view.NonOfficial {
		t.Fatalf("official-only trust reported as non-official: %s", raw)
	}
	if !strings.Contains(raw, `"non_official":false`) {
		t.Fatalf("the negative answer must be present in the payload, not omitted: %s", raw)
	}
	if len(view.Publishers) != 0 {
		t.Fatalf("publishers should be empty: %v", view.Publishers)
	}
}

// A dev key trusted alongside the official one is exactly the condition the banner
// exists for, and the operator needs to know WHICH key it is.
func TestPluginTrustNamesNonOfficialPublishers(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	dev, _, _ := ed25519.GenerateKey(nil)
	view, _ := trustView(t, plugin.TrustPolicy{TrustedPublishers: map[string]ed25519.PublicKey{
		officialPublisher: pub, "devkey-somebody": dev,
	}})
	if !view.NonOfficial {
		t.Fatal("a trusted non-official publisher must set non_official")
	}
	if len(view.Publishers) != 1 || view.Publishers[0] != "devkey-somebody" {
		t.Fatalf("publishers: want [devkey-somebody], got %v", view.Publishers)
	}
}

// Key material must never leave the server through this surface: the banner needs the
// name of the publisher, never its key.
func TestPluginTrustNeverLeaksKeyMaterial(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	dev, _, _ := ed25519.GenerateKey(nil)
	_, raw := trustView(t, plugin.TrustPolicy{TrustedPublishers: map[string]ed25519.PublicKey{
		officialPublisher: pub, "devkey-somebody": dev,
	}})
	for _, key := range []ed25519.PublicKey{pub, dev} {
		encoded := base64.StdEncoding.EncodeToString(key)
		if strings.Contains(raw, encoded) {
			t.Fatalf("public key material leaked into the trust payload: %s", raw)
		}
		if strings.Contains(raw, string(key)) {
			t.Fatalf("raw key bytes leaked into the trust payload")
		}
	}
}

// Disabling signature enforcement is categorically worse than an extra publisher and
// must raise the condition on its own, even with no unofficial publisher present.
func TestPluginTrustFlagsUnsignedHostRiskOnItsOwn(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	view, _ := trustView(t, plugin.TrustPolicy{
		TrustedPublishers:     map[string]ed25519.PublicKey{officialPublisher: pub},
		AllowUnsignedHostRisk: true,
	})
	if !view.NonOfficial || !view.AllowUnsignedHostRisk {
		t.Fatalf("allow_unsigned_host_risk must raise the condition by itself: %+v", view)
	}
}
