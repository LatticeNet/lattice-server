package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Expiry was settable only at creation, so extending a share meant deleting it
// and handing out a new link — the one thing a share exists to avoid.

func patchShare(t *testing.T, s *Server, shareID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPatch, "/api/subscription-shares/"+shareID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleSubscriptionShareItem(rec, req, principal{})
	return rec
}

func TestShareExpiryCanBeSetAfterCreation(t *testing.T) {
	s, st := newShareTestServer(t)
	share := mustCreateShare(t, s)
	if share.ExpiresAt != nil {
		t.Fatal("the fixture already had an expiry")
	}

	when := s.now().Add(30 * 24 * time.Hour).UTC()
	rec := patchShare(t, s, share.ID, `{"expires_at":"`+when.Format(time.RFC3339Nano)+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch returned %d: %s", rec.Code, rec.Body.String())
	}

	stored, _ := st.SubscriptionShare(share.ID)
	if stored.ExpiresAt == nil {
		t.Fatal("the expiry was not stored")
	}
	if !stored.ExpiresAt.Equal(when) {
		t.Fatalf("stored %v, want %v", stored.ExpiresAt, when)
	}
	// The token must survive: an edit that rotated the URL would break every
	// client holding it, which is what rotation is for and editing is not.
	if stored.Token != share.Token {
		t.Fatal("editing a share changed its token")
	}
}

// "Not supplied" and "cleared" are different requests. Treating them alike
// would make every unrelated edit silently remove the expiry.
func TestAnEditThatDoesNotMentionExpiryLeavesItAlone(t *testing.T) {
	s, st := newShareTestServer(t)
	share := mustCreateShare(t, s)
	when := s.now().Add(24 * time.Hour).UTC()
	share.ExpiresAt = &when
	if err := st.UpsertSubscriptionShare(share); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := patchShare(t, s, share.ID, `{"default_format":"plain"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch returned %d: %s", rec.Code, rec.Body.String())
	}
	stored, _ := st.SubscriptionShare(share.ID)
	if stored.ExpiresAt == nil {
		t.Fatal("an edit that never mentioned expiry removed it")
	}
	if stored.DefaultFormat != "plain" {
		t.Fatalf("default format is %q", stored.DefaultFormat)
	}
}

func TestShareExpiryCanBeCleared(t *testing.T) {
	s, st := newShareTestServer(t)
	share := mustCreateShare(t, s)
	when := s.now().Add(24 * time.Hour).UTC()
	share.ExpiresAt = &when
	if err := st.UpsertSubscriptionShare(share); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := patchShare(t, s, share.ID, `{"clear_expiry":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch returned %d: %s", rec.Code, rec.Body.String())
	}
	stored, _ := st.SubscriptionShare(share.ID)
	if stored.ExpiresAt != nil {
		t.Fatalf("the expiry was not cleared: %v", stored.ExpiresAt)
	}
}

// A share whose expiry is already past is answered exactly like a wrong token,
// so an operator who set one by accident would get no feedback at all.
func TestAnExpiryInThePastIsRefused(t *testing.T) {
	s, _ := newShareTestServer(t)
	share := mustCreateShare(t, s)
	past := s.now().Add(-time.Hour).UTC()
	rec := patchShare(t, s, share.ID, `{"expires_at":"`+past.Format(time.RFC3339Nano)+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("patch returned %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

func TestSettingAndClearingExpiryTogetherIsRefused(t *testing.T) {
	s, _ := newShareTestServer(t)
	share := mustCreateShare(t, s)
	when := s.now().Add(time.Hour).UTC()
	rec := patchShare(t, s, share.ID, `{"clear_expiry":true,"expires_at":"`+when.Format(time.RFC3339Nano)+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("patch returned %d, want 400", rec.Code)
	}
}

// Disabling has to take effect now. A cached body is served without ever
// consulting the share, so leaving the cache in place would keep answering a
// share the operator has just switched off.
func TestDisablingAShareStopsItBeingResolvable(t *testing.T) {
	s, st := newShareTestServer(t)
	share := mustCreateShare(t, s)
	if _, ok := s.resolveShare(share.Slug, share.Token, s.now()); !ok {
		t.Fatal("the fixture share does not resolve")
	}

	rec := patchShare(t, s, share.ID, `{"enabled":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch returned %d: %s", rec.Code, rec.Body.String())
	}
	stored, _ := st.SubscriptionShare(share.ID)
	if stored.Enabled {
		t.Fatal("the share is still enabled")
	}
	if _, ok := s.resolveShare(share.Slug, share.Token, s.now()); ok {
		t.Fatal("a disabled share still resolves")
	}
}

// An expired share is refused the same way a wrong token is, so its expiry
// cannot be probed from outside.
func TestAnExpiredShareStopsResolving(t *testing.T) {
	s, st := newShareTestServer(t)
	share := mustCreateShare(t, s)
	when := s.now().Add(time.Hour).UTC()
	share.ExpiresAt = &when
	if err := st.UpsertSubscriptionShare(share); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, ok := s.resolveShare(share.Slug, share.Token, s.now()); !ok {
		t.Fatal("a share expiring in an hour does not resolve now")
	}
	if _, ok := s.resolveShare(share.Slug, share.Token, when.Add(time.Second)); ok {
		t.Fatal("an expired share still resolves")
	}
}

func TestShareUpdateIsAudited(t *testing.T) {
	s, st := newShareTestServer(t)
	share := mustCreateShare(t, s)
	when := s.now().Add(48 * time.Hour).UTC()
	if rec := patchShare(t, s, share.ID, `{"expires_at":"`+when.Format(time.RFC3339Nano)+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("patch returned %d", rec.Code)
	}

	found := false
	for _, ev := range st.AuditEvents() {
		if ev.Action != auditActionShareUpdate {
			continue
		}
		found = true
		// The token itself must never reach the audit trail.
		for _, value := range ev.Metadata {
			if strings.Contains(value, share.Token) {
				t.Fatalf("the audit trail carries the token: %+v", ev.Metadata)
			}
		}
		if ev.Metadata["expires_from"] != "never" {
			t.Fatalf("expires_from is %q, want never", ev.Metadata["expires_from"])
		}
		if ev.Metadata["expires_to"] == "never" {
			t.Fatal("expires_to was not recorded")
		}
	}
	if !found {
		t.Fatal("the edit was not audited")
	}
}

// An unknown format would render as something no client asked for, and the
// error belongs at the edit rather than at the next fetch.
func TestAnUnknownDefaultFormatIsRefused(t *testing.T) {
	s, _ := newShareTestServer(t)
	share := mustCreateShare(t, s)
	rec := patchShare(t, s, share.ID, `{"default_format":"not-a-format"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("patch returned %d, want 400", rec.Code)
	}
}

func TestShareViewCarriesExpiry(t *testing.T) {
	s, _ := newShareTestServer(t)
	share := mustCreateShare(t, s)
	when := s.now().Add(72 * time.Hour).UTC()
	rec := patchShare(t, s, share.ID, `{"expires_at":"`+when.Format(time.RFC3339Nano)+`"}`)
	var view struct {
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	// The dashboard shows remaining days from this, so the reply has to carry it
	// rather than making the caller refetch the list.
	if view.ExpiresAt == nil {
		t.Fatalf("the reply did not carry the expiry: %s", rec.Body.String())
	}
}

// PATCH is a new unsafe method on this API. `unsafeMethod` is written as a
// denylist of the safe ones rather than a list of the unsafe ones, so it is
// covered by construction — this pins that, because rewriting it as an
// enumeration would silently expose every method someone forgot.
func TestPatchCountsAsAnUnsafeMethodForCSRF(t *testing.T) {
	for _, method := range []string{http.MethodPatch, http.MethodPost, http.MethodPut, http.MethodDelete} {
		if !unsafeMethod(method) {
			t.Fatalf("%s is not treated as unsafe, so it would skip the CSRF check", method)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		if unsafeMethod(method) {
			t.Fatalf("%s is treated as unsafe", method)
		}
	}
}
