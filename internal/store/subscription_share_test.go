package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
)

func newShareStore(t *testing.T) (*Store, string) {
	t.Helper()
	t.Setenv(secret.EnvMasterKey, "")
	os.Unsetenv(secret.EnvMasterKey)
	os.Unsetenv(secret.EnvMasterKeyFile)
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return s, path
}

// The share token is a bearer credential for an unauthenticated public URL. It
// must never reach disk in the clear, exactly like the proxy-user token
// crypto.go already seals.
func TestSubscriptionShareTokenIsSealedOnDisk(t *testing.T) {
	s, path := newShareStore(t)
	const token = "plaintext-token-value-must-not-appear-anywhere"

	if err := s.UpsertSubscriptionShare(model.SubscriptionShare{
		ID: "share1", Slug: "team", Token: token, Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourceCoreProxyUser, ProxyUserID: "u1"},
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := s.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if strings.Contains(string(raw), token) {
		t.Fatal("subscription share token was written to disk in plaintext")
	}
}

// Reopening must give the token back in the clear: the operator copies the share
// URL out of the dashboard repeatedly, so sealing is an at-rest property only.
func TestSubscriptionShareTokenSurvivesReopen(t *testing.T) {
	s, path := newShareStore(t)
	const token = "round-trip-token-value-0123456789"

	if err := s.UpsertSubscriptionShare(model.SubscriptionShare{
		ID: "share1", Slug: "team", Token: token, Enabled: true,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := s.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, ok := reopened.SubscriptionShare("share1")
	if !ok {
		t.Fatal("share missing after reopen")
	}
	if got.Token != token {
		t.Fatalf("token after reopen = %q, want %q", got.Token, token)
	}
}

func TestSubscriptionShareByTokenFindsExactMatchOnly(t *testing.T) {
	s, _ := newShareStore(t)
	if err := s.UpsertSubscriptionShare(model.SubscriptionShare{
		ID: "share1", Slug: "team", Token: "correct-token", Enabled: true,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	if _, ok := s.SubscriptionShareByToken("correct-token"); !ok {
		t.Fatal("exact token did not resolve")
	}
	if _, ok := s.SubscriptionShareByToken("correct-toke"); ok {
		t.Fatal("a prefix of a token resolved; lookup must be exact")
	}
	if _, ok := s.SubscriptionShareByToken("correct-token-extra"); ok {
		t.Fatal("a superstring of a token resolved; lookup must be exact")
	}
	if _, ok := s.SubscriptionShareByToken(""); ok {
		t.Fatal("the empty token resolved")
	}
}

func TestSubscriptionShareUpsertStampsSchemaVersionAndTimes(t *testing.T) {
	s, _ := newShareStore(t)
	if err := s.UpsertSubscriptionShare(model.SubscriptionShare{
		ID: "share1", Slug: "team", Token: "t", Enabled: true,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, ok := s.SubscriptionShare("share1")
	if !ok {
		t.Fatal("share missing")
	}
	if got.SchemaVersion != model.SubscriptionShareSchemaVersion {
		t.Fatalf("schema version = %d, want %d", got.SchemaVersion, model.SubscriptionShareSchemaVersion)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Fatalf("timestamps not stamped: %+v", got)
	}
}

func TestSubscriptionShareDelete(t *testing.T) {
	s, _ := newShareStore(t)
	if err := s.UpsertSubscriptionShare(model.SubscriptionShare{ID: "share1", Slug: "team", Token: "t"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := s.DeleteSubscriptionShare("share1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := s.SubscriptionShare("share1"); ok {
		t.Fatal("share still present after delete")
	}
	if len(s.SubscriptionShares()) != 0 {
		t.Fatalf("list not empty after delete: %v", s.SubscriptionShares())
	}
}
