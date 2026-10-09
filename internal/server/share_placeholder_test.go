package server

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/LatticeNet/lattice-sdk/model"
)

func placeholderShare(id, slug, token string, mutate func(*model.SubscriptionShare)) model.SubscriptionShare {
	share := model.SubscriptionShare{ID: id, Slug: slug, Token: token, Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: subStorePluginID, SubscriptionID: "fleet-1"}}
	if mutate != nil {
		mutate(&share)
	}
	return share
}

// placeholderName decodes a one-entry URI list (plain or base64) and returns
// the entry's name.
func placeholderName(t *testing.T, r idlResponse) string {
	t.Helper()
	body := strings.TrimSpace(r.body)
	if decoded, err := base64.StdEncoding.DecodeString(body); err == nil {
		body = string(decoded)
	}
	if r.status != http.StatusOK || strings.Count(body, "\n") != 0 ||
		!strings.HasPrefix(body, "vless://"+identityLinkPlaceholderUUID+"@"+identityLinkPlaceholderHost+"?") {
		t.Fatalf("want a one-entry placeholder, got %d %q", r.status, r.body)
	}
	name, err := url.PathUnescape(body[strings.Index(body, "#")+1:])
	if err != nil {
		t.Fatal(err)
	}
	return name
}

func TestPluginShareInAPolicyStateServesThePlaceholder(t *testing.T) {
	f := newIdentityLinkFixture(t)
	now := f.srv.now()
	past := now.Add(-time.Hour)
	tok := func(c string) string { return strings.Repeat(c, 32) }
	shares := []model.SubscriptionShare{
		placeholderShare("s-off", "off", tok("d"), func(s *model.SubscriptionShare) { s.Enabled = false }),
		placeholderShare("s-old", "old", tok("e"), func(s *model.SubscriptionShare) { s.ExpiresAt = &past }),
		placeholderShare("s-alice", "alice", tok("f"), func(s *model.SubscriptionShare) { s.Source.IdentityID = "vpnuser_alice" }),
		placeholderShare("s-ghost", "ghost", tok("g"), func(s *model.SubscriptionShare) { s.Source.IdentityID = "vpnuser_gone" }),
		placeholderShare("s-bin", "bin", tok("h"), func(s *model.SubscriptionShare) { s.Enabled = false; s.ArchivedAt = &past }),
		{ID: "s-core", Slug: "core", Token: tok("i"), Enabled: false,
			Source: model.ShareSource{Kind: model.ShareSourceCoreProxyUser, ProxyUserID: "nobody"}},
	}
	for _, share := range shares {
		mustUpsertShare(t, f.srv.store, share)
	}
	alice, _ := f.srv.getVpnUser("vpnuser_alice")
	alice.Suspension = &VpnSuspension{Reason: vpnSuspendReasonOperator, By: "op", Since: now}
	if err := f.srv.putVpnUser(alice); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		slug, token, message string
	}{
		{"off", tok("d"), "Lattice: Disabled by the operator"},
		{"old", tok("e"), "Lattice: Expired on " + past.UTC().Format("2006-01-02")},
		{"alice", tok("f"), "Lattice: Suspended by the operator"},
		{"ghost", tok("g"), "Lattice: Not in service"},
	} {
		r := f.fetch(t, tc.slug, tc.token, "")
		if name := placeholderName(t, r); name != tc.message {
			t.Fatalf("%s: placeholder names %q, want %q", tc.slug, name, tc.message)
		}
		info := userinfoFields(t, r.header.Get("Subscription-Userinfo"))
		if info["total"] == 0 || info["download"] < info["total"] {
			t.Fatalf("%s: a placeholder's quota header must read as used up: %v", tc.slug, info)
		}
		if strings.Contains(r.body, idlAliceUUID) || strings.Contains(r.body, "203.0.113.5") {
			t.Fatalf("%s: the placeholder carries a real credential or host: %s", tc.slug, r.body)
		}
		if r.header.Get("Profile-Update-Interval") == "" || r.header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: client headers missing: %v", tc.slug, r.header)
		}
	}
	if got := f.fetch(t, "off", tok("d"), "format=plain&noFlow=1"); got.header.Get("Subscription-Userinfo") != "" {
		t.Fatal("noFlow still sent a quota header")
	}
	if name := placeholderName(t, f.fetch(t, "off", tok("d"), "format=plain")); name != "Lattice: Disabled by the operator" {
		t.Fatalf("plain placeholder = %q", name)
	}

	// The decoy stays the answer for everything that is not a known plugin
	// share in a policy state.
	decoyLike(t, f, f.fetch(t, "off", tok("z"), ""))  // unknown token
	decoyLike(t, f, f.fetch(t, "nope", tok("d"), "")) // known token, wrong slug
	decoyLike(t, f, f.fetch(t, "bin", tok("h"), ""))  // archived
	decoyLike(t, f, f.fetch(t, "core", tok("i"), "")) // not a plugin share
	decoyLike(t, f, f.fetch(t, "off", tok("d"), "target=EvilClient"))

	// Other clients get the placeholder in their own document, converted once
	// per content version.
	before := len(f.converts)
	r := f.fetch(t, "off", tok("d"), "target=ClashMeta")
	if r.status != http.StatusOK || !strings.Contains(r.body, "# ClashMeta") || !strings.Contains(r.body, identityLinkPlaceholderUUID) {
		t.Fatalf("converted placeholder = %d %q", r.status, r.body)
	}
	f.fetch(t, "off", tok("d"), "target=ClashMeta")
	if len(f.converts) != before+1 {
		t.Fatalf("the placeholder was converted %d times for one version", len(f.converts)-before)
	}
}

// Turning the share back on serves its document again, not the placeholder.
func TestAnActivePluginShareIsNotAPlaceholder(t *testing.T) {
	f := newIdentityLinkFixture(t)
	share := placeholderShare("s-on", "on", strings.Repeat("k", 32), func(s *model.SubscriptionShare) { s.Source.IdentityID = "vpnuser_alice" })
	mustUpsertShare(t, f.srv.store, share)
	if _, ok := f.srv.pluginSharePlaceholderFor("on", share.Token, f.srv.now()); ok {
		t.Fatal("an enabled share with an active identity answered with the placeholder")
	}
	share.Enabled = false
	mustUpsertShare(t, f.srv.store, share)
	if answer, ok := f.srv.pluginSharePlaceholderFor("on", share.Token, f.srv.now()); !ok || answer.reason != sharePlaceholderDisabled {
		t.Fatalf("a disabled share = %+v, %v", answer, ok)
	}
}

// A share with an age recipient answers its placeholder in age, as it answers
// its document: the recipient's identity decrypts the body to the placeholder
// a share without one serves, and nothing of it goes out in the clear. An
// unknown token under the sealed share's slug is still the decoy: there is
// no share, so no recipient to tell apart.
func TestSealedPluginSharePlaceholderAnswersInAge(t *testing.T) {
	f := newIdentityLinkFixture(t)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	tok := func(c string) string { return strings.Repeat(c, 32) }
	disabled := func(s *model.SubscriptionShare) { s.Enabled = false }
	mustUpsertShare(t, f.srv.store, subStoreSvcWithAgeRecipient(placeholderShare("s-sealed", "sealed", tok("m"), disabled), identity.Recipient().String()))
	mustUpsertShare(t, f.srv.store, placeholderShare("s-plain", "plain", tok("n"), disabled))

	for _, query := range []string{"", "format=plain", "target=ClashMeta"} {
		r := f.fetch(t, "sealed", tok("m"), query)
		if r.status != http.StatusOK || !strings.HasPrefix(r.body, "-----BEGIN AGE ENCRYPTED FILE-----") ||
			strings.Contains(r.body, identityLinkPlaceholderUUID) || strings.Contains(r.body, "Disabled") {
			t.Fatalf("%q: the placeholder of a sealed share is not an armored age file: %d %q", query, r.status, r.body)
		}
		if got := r.header.Get("Content-Type"); got != subStoreSvcAgeWireType {
			t.Fatalf("%q: content type %q", query, got)
		}
		plain := f.fetch(t, "plain", tok("n"), query)
		if strings.HasPrefix(plain.body, "-----BEGIN AGE") {
			t.Fatalf("%q: a share without a recipient was sealed: %q", query, plain.body)
		}
		if got := subStoreSvcDecrypt(t, []byte(r.body), identity); got != plain.body {
			t.Fatalf("%q: decrypted %q, want the plain placeholder %q", query, got, plain.body)
		}
	}
	if name := placeholderName(t, f.fetch(t, "plain", tok("n"), "")); name != "Lattice: Disabled by the operator" {
		t.Fatalf("the plain placeholder = %q", name)
	}

	decoy := f.fetch(t, "nope", strings.Repeat("Z", 43), "")
	unknown := f.fetch(t, "sealed", tok("z"), "")
	decoyLike(t, f, unknown)
	if unknown.header.Get("Content-Type") != decoy.header.Get("Content-Type") {
		t.Fatalf("an unknown token under a sealed share's slug answered %q, the decoy %q",
			unknown.header.Get("Content-Type"), decoy.header.Get("Content-Type"))
	}

	// A stored recipient that no longer parses fails closed, as the live
	// body does: the decoy, never the plain placeholder.
	mustUpsertShare(t, f.srv.store, subStoreSvcWithAgeRecipient(placeholderShare("s-broken", "broken", tok("q"), disabled), "age1notarecipient"))
	decoyLike(t, f, f.fetch(t, "broken", tok("q"), ""))
}

// The placeholder is Sub-Store's answer. Another plugin's share in a policy
// state answers as a core share does, with the decoy.
func TestAnotherPluginsShareInAPolicyStateIsTheDecoy(t *testing.T) {
	f := newIdentityLinkFixture(t)
	past := f.srv.now().Add(-time.Hour)
	tok := func(c string) string { return strings.Repeat(c, 32) }
	other := func(mutate func(*model.SubscriptionShare)) func(*model.SubscriptionShare) {
		return func(s *model.SubscriptionShare) { s.Source.PluginID = "acme.other"; mutate(s) }
	}
	shares := []model.SubscriptionShare{
		placeholderShare("s-off", "off", tok("d"), other(func(s *model.SubscriptionShare) { s.Enabled = false })),
		placeholderShare("s-old", "old", tok("e"), other(func(s *model.SubscriptionShare) { s.ExpiresAt = &past })),
		placeholderShare("s-ghost", "ghost", tok("g"), other(func(s *model.SubscriptionShare) { s.Source.IdentityID = "vpnuser_gone" })),
	}
	for _, share := range shares {
		mustUpsertShare(t, f.srv.store, share)
		if answer, ok := f.srv.pluginSharePlaceholderFor(share.Slug, share.Token, f.srv.now()); ok {
			t.Fatalf("%s: another plugin's share answered with the placeholder %+v", share.Slug, answer)
		}
		decoyLike(t, f, f.fetch(t, share.Slug, share.Token, ""))
	}
}
