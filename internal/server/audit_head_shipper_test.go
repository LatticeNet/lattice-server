package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestAuditHeadShipperPostsVerifiedAnchoredHead(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.AppendAudit(model.AuditEvent{ID: "audit_ship", At: time.Unix(1700000000, 0).UTC(), Action: "audit.ship", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}

	var seen auditHeadPayload
	client := &http.Client{Transport: auditHeadRoundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer secret-token" {
			t.Errorf("authorization = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("content-type = %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Errorf("decode payload: %v", err)
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}

	shipper := &auditHeadShipper{
		store:       st,
		targetURL:   "https://audit.example.com/head",
		bearerToken: "secret-token",
		client:      client,
		now:         func() time.Time { return time.Unix(1700000100, 0).UTC() },
	}
	if err := shipper.shipOnce(context.Background()); err != nil {
		t.Fatalf("shipOnce: %v", err)
	}

	if seen.Type != "lattice.audit_head.v1" || !seen.OK || !seen.Anchored {
		t.Fatalf("bad payload status: %+v", seen)
	}
	if seen.Count == 0 || seen.Head == "" {
		t.Fatalf("missing head fields: %+v", seen)
	}
	if seen.AnchorCount != seen.Count || seen.AnchorHead != seen.Head {
		t.Fatalf("anchor does not match verified head: %+v", seen)
	}
	if !seen.VerifiedAt.Equal(time.Unix(1700000100, 0).UTC()) {
		t.Fatalf("verified_at = %s", seen.VerifiedAt)
	}
}

func TestAuditHeadShipperDoesNotPostWhenAnchorVerificationFails(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	st, err := store.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.AppendAudit(model.AuditEvent{ID: "audit_bad_anchor", At: time.Unix(1700000000, 0).UTC(), Action: "audit.ship", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath+".audit-anchor", []byte(`{"version":1,"count":999,"head":"bad","updated_at":"2026-01-01T00:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	shipper := &auditHeadShipper{
		store:     st,
		targetURL: "https://audit.example.com/head",
		client: &http.Client{Transport: auditHeadRoundTripperFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("webhook must not be called when audit verification fails")
			return nil, errors.New("unexpected request")
		})},
		now: func() time.Time { return time.Unix(1700000100, 0).UTC() },
	}
	if err := shipper.shipOnce(context.Background()); err == nil {
		t.Fatal("expected verification error")
	}
}

type auditHeadRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f auditHeadRoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestAuditHeadShipperRequiresHTTPSURL(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, raw := range []string{
		"http://audit.example.com/head",
		"https://token@audit.example.com/head",
		"https://audit.example.com/head?token=secret",
		"https://audit.example.com/head#secret",
		"not a url",
	} {
		_, err := newAuditHeadShipper(st, log.New(io.Discard, "", 0), AuditHeadShippingOptions{URL: raw})
		if err == nil {
			t.Fatalf("expected %q to be rejected", raw)
		}
	}
}
