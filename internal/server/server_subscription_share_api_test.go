package server

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func mustCreateShare(t *testing.T, s *Server) model.SubscriptionShare {
	t.Helper()
	share := model.SubscriptionShare{
		ID: "share1", Slug: "team", Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "s"},
	}
	token, err := s.newUniqueShareToken()
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	share.Token = token
	if err := s.store.UpsertSubscriptionShare(share); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	stored, _ := s.store.SubscriptionShare(share.ID)
	return stored
}

func TestNewShareTokenMatchesTheSubscriptionTokenShape(t *testing.T) {
	s, _ := newShareTestServer(t)
	token, err := s.newUniqueShareToken()
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	// The public URL is unauthenticated, so the token's only protection is that
	// it cannot be guessed. It reuses the same primitive as the proxy-user token.
	if !proxySubTokenRe.MatchString(token) {
		t.Fatalf("token %q does not match the subscription token shape", token)
	}
}

func TestRotateShareTokenAuditsBothHashesAndNeitherToken(t *testing.T) {
	s, st := newShareTestServer(t)
	share := mustCreateShare(t, s)
	old := share.Token

	rec := httptest.NewRecorder()
	s.rotateSubscriptionShare(rec, share, principal{})

	rotated, ok := st.SubscriptionShare(share.ID)
	if !ok {
		t.Fatal("share disappeared during rotation")
	}
	if rotated.Token == old {
		t.Fatal("rotation did not change the token")
	}
	if rotated.RotatedAt == nil {
		t.Fatal("rotation did not stamp rotated_at")
	}

	var rotateEvents int
	for _, ev := range st.AuditEvents() {
		if ev.Action != auditActionShareRotate {
			continue
		}
		rotateEvents++
		if ev.Metadata["old_token_sha256"] != proxySubTokenAuditHash(old) {
			t.Fatalf("old token hash missing or wrong: %v", ev.Metadata)
		}
		if ev.Metadata["new_token_sha256"] != proxySubTokenAuditHash(rotated.Token) {
			t.Fatalf("new token hash missing or wrong: %v", ev.Metadata)
		}
		for k, v := range ev.Metadata {
			if strings.Contains(v, old) || strings.Contains(v, rotated.Token) {
				t.Fatalf("audit metadata %q carried a raw token", k)
			}
		}
	}
	if rotateEvents != 1 {
		t.Fatalf("expected exactly one rotate audit event, got %d", rotateEvents)
	}
}

// A rotated share must stop answering on its old token immediately. The cache is
// consulted before the token is, so an entry left behind would keep serving the
// URL rotation was meant to retire.
func TestRotateInvalidatesTheCachedBody(t *testing.T) {
	s, _ := newShareTestServer(t)
	share := mustCreateShare(t, s)
	key := subscriptionCacheKey{ShareID: share.ID, Format: "base64", UAClass: "surge"}
	s.subscriptionCache.Put(key, []byte("stale"), "text/plain", s.now())

	rec := httptest.NewRecorder()
	s.rotateSubscriptionShare(rec, share, principal{})

	if _, _, ok := s.subscriptionCache.Get(key, s.now()); ok {
		t.Fatal("the pre-rotation body is still cached")
	}
}

func TestValidateShareSource(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source model.ShareSource
		ok     bool
	}{
		{"core with user", model.ShareSource{Kind: model.ShareSourceCoreProxyUser, ProxyUserID: "u1"}, true},
		{"core without user", model.ShareSource{Kind: model.ShareSourceCoreProxyUser}, false},
		{"core naming a plugin", model.ShareSource{Kind: model.ShareSourceCoreProxyUser, ProxyUserID: "u1", PluginID: "p"}, false},
		{"plugin complete", model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "s"}, true},
		{"plugin without subscription", model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p"}, false},
		{"plugin naming a user", model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "s", ProxyUserID: "u"}, false},
		{"unknown kind", model.ShareSource{Kind: "something"}, false},
		{"empty kind", model.ShareSource{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateShareSource(tc.source)
			if tc.ok && err != nil {
				t.Fatalf("valid source rejected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("invalid source accepted")
			}
		})
	}
}
