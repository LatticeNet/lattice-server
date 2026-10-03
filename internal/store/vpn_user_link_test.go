package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// An identity link resolves by its token only once issued, through the same
// index as shares, survives a reopen sealed, follows the one-match rule
// across kinds, and keeps its slug unique across kinds.
func TestIdentityLinkTokensResolveThroughTheOneIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	cipher := testCipher(t)
	s, err := OpenWithCipher(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	public, private := testVpnUserRecords("vpn-link", "secret")
	if err := s.PutVpnUserRecord(public, private); err != nil {
		t.Fatal(err)
	}
	// A SubID with no link is never served: a migrated identity's SubID is
	// its legacy proxy user's old token.
	if _, ok := s.VpnUserIDByLinkToken(private.SubID); ok {
		t.Fatal("a token with no issued link must not resolve")
	}
	token := strings.Repeat("t", 43)
	issue := func(link *VpnUserLink, _ string) (*VpnUserLink, string, error) {
		return &VpnUserLink{Slug: "u-abcdefghij", IssuedAt: time.Now().UTC()}, token, nil
	}
	if err := s.UpdateVpnUserLink(public.ID, issue); err != nil {
		t.Fatal(err)
	}
	if id, ok := s.VpnUserIDByLinkToken(token); !ok || id != public.ID {
		t.Fatalf("issued token resolves to %q %v", id, ok)
	}
	if _, ok := s.VpnUserIDByLinkToken(token[:42] + "u"); ok {
		t.Fatal("a near-miss token resolved")
	}
	if !s.LinkTokenInUse(token) || !s.LinkSlugInUse("u-abcdefghij", "") || s.LinkSlugInUse("u-abcdefghij", public.ID) {
		t.Fatal("uniqueness checks must see the identity link")
	}
	projections := s.VpnUserLinkProjections()
	if len(projections) != 1 || projections[0].Slug != "u-abcdefghij" || projections[0].IdentityID != public.ID {
		t.Fatalf("projections = %+v", projections)
	}

	// A share holding the same token makes both kinds answer nothing.
	if err := s.UpsertSubscriptionShare(model.SubscriptionShare{ID: "share-1", Slug: "share-one", Token: token, Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "x"}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.VpnUserIDByLinkToken(token); ok {
		t.Fatal("a token two kinds hold must not resolve as an identity link")
	}
	if _, ok := s.SubscriptionShareByToken(token); ok {
		t.Fatal("a token two kinds hold must not resolve as a share")
	}
	if err := s.DeleteSubscriptionShare("share-1"); err != nil {
		t.Fatal(err)
	}

	// A share's slug cannot be an identity link's.
	if err := s.UpsertSubscriptionShare(model.SubscriptionShare{ID: "share-2", Slug: "taken", Token: strings.Repeat("s", 43), Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "x"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateVpnUserLink(public.ID, func(link *VpnUserLink, current string) (*VpnUserLink, string, error) {
		link.Slug = "taken"
		return link, current, nil
	}); err == nil {
		t.Fatal("an identity link on a share's slug must be refused")
	}

	// Sealed at rest, resolvable after a reopen.
	reopened, err := OpenWithCipher(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := reopened.VpnUserIDByLinkToken(token); !ok || id != public.ID {
		t.Fatal("the link must resolve after a reopen")
	}

	// Revocation: the link goes, and the stored token is replaced.
	if err := reopened.UpdateVpnUserLink(public.ID, func(*VpnUserLink, string) (*VpnUserLink, string, error) {
		return nil, strings.Repeat("r", 43), nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.VpnUserIDByLinkToken(token); ok {
		t.Fatal("a revoked token must not resolve")
	}
	if _, ok := reopened.VpnUserIDByLinkToken(strings.Repeat("r", 43)); ok {
		t.Fatal("the replacement token of a revoked link must not resolve")
	}
	if err := reopened.UpdateVpnUserLink("missing", issue); err != ErrVpnUserNotFound {
		t.Fatalf("a link write for a missing identity: %v", err)
	}
}
