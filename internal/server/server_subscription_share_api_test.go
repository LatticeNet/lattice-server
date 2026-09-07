package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestManualSubscriptionRefreshInvalidatesEverySiblingShare(t *testing.T) {
	s, st := newShareTestServer(t)
	shares := []model.SubscriptionShare{
		{ID: "s1", Slug: "one", Token: strings.Repeat("a", 32), Enabled: true, Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "shared"}},
		{ID: "s2", Slug: "two", Token: strings.Repeat("b", 32), Enabled: true, Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "shared"}},
	}
	for _, share := range shares {
		mustUpsertShare(t, st, share)
		s.subscriptionCache.Put(shareCacheKey(share.ID), []byte("cached"), "text/plain", "", "v", s.now())
	}
	s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		return model.SubscriptionSnapshot{Raw: "fresh"}, nil
	}
	rec := httptest.NewRecorder()
	s.refreshSubscriptionShare(rec, httptest.NewRequest("POST", "/", nil), shares[0], principal{})
	for _, share := range shares {
		if _, ok := s.subscriptionCache.GetStale(shareCacheKey(share.ID)); ok {
			t.Fatalf("manual refresh left sibling cache %s", share.ID)
		}
	}
}

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
	s.subscriptionCache.Put(key, []byte("stale"), "text/plain", "", "", s.now())

	rec := httptest.NewRecorder()
	s.rotateSubscriptionShare(rec, share, principal{})

	if _, _, _, ok := s.subscriptionCache.Get(key, s.now()); ok {
		t.Fatal("the pre-rotation body is still cached")
	}
}

func postShare(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/subscription-shares", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.createSubscriptionShare(rec, req, principal{})
	return rec
}

// The public URL answers a share whose user is missing exactly like a wrong
// token, so a share created for a user that never existed would be listed as
// live and hand out a dead link with no layer saying so. Creation is the one
// place the operator can be told.
func TestCreatingAShareForAMissingProxyUserIsRefused(t *testing.T) {
	s, st := newShareTestServer(t)
	rec := postShare(t, s, `{"slug":"openjobs-mobile","source":{"kind":"core.proxy_user","proxy_user_id":"openjobs-mobile-team"}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create returned %d, want 400: %s", rec.Code, rec.Body.String())
	}
	var reply model.APIErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if reply.Error.Code != model.APIErrorBadRequest {
		t.Fatalf("error code %q, want %q", reply.Error.Code, model.APIErrorBadRequest)
	}
	if reply.Error.Message != "proxy user openjobs-mobile-team does not exist" {
		t.Fatalf("error message %q", reply.Error.Message)
	}
	if shares := st.SubscriptionShares(); len(shares) != 0 {
		t.Fatalf("a refused share was stored: %+v", shares)
	}
}

func TestCreatingAShareForAnExistingProxyUserSucceeds(t *testing.T) {
	s, st := newShareTestServer(t)
	if err := st.UpsertProxyUser(model.ProxyUser{ID: "u1", Name: "u1", UUID: "uuid", SubToken: "unused"}); err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	rec := postShare(t, s, `{"slug":"team","source":{"kind":"core.proxy_user","proxy_user_id":"u1"}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create returned %d, want 201: %s", rec.Code, rec.Body.String())
	}
	shares := st.SubscriptionShares()
	if len(shares) != 1 {
		t.Fatalf("stored %d shares, want 1", len(shares))
	}
	if shares[0].Source.ProxyUserID != "u1" || !shares[0].Enabled {
		t.Fatalf("stored share = %+v", shares[0])
	}
}

// The check and the stored value must agree on normalisation. A padded id that
// passed the check but was stored raw would be looked up raw at render time and
// fail there, which is the same dead link this check exists to prevent.
func TestCreatingAShareStoresTheTrimmedProxyUserID(t *testing.T) {
	s, st := newShareTestServer(t)
	if err := st.UpsertProxyUser(model.ProxyUser{ID: "u1", Name: "u1", UUID: "uuid", SubToken: "unused"}); err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	rec := postShare(t, s, `{"slug":"team","source":{"kind":"core.proxy_user","proxy_user_id":" u1 "}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create returned %d, want 201: %s", rec.Code, rec.Body.String())
	}
	shares := st.SubscriptionShares()
	if len(shares) != 1 || shares[0].Source.ProxyUserID != "u1" {
		t.Fatalf("stored shares = %+v, want one share pointing at u1", shares)
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
