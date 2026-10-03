package store

import (
	"bytes"
	"crypto/sha256"
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

// The public token lookup is the one comparison an anonymous caller can drive,
// so it compares in constant time and refuses a duplicate rather than serving
// whichever share the map yielded first.
//
// The documentation claimed both properties before the code had either: it said
// the route "uses a constant-time full scan" and "fails closed on duplicate
// tokens" while the implementation was a plain == with an early return. These
// pin the behaviour so the claim and the code cannot drift apart again.
func TestSubscriptionShareByTokenResolvesExactlyOne(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, sh := range []model.SubscriptionShare{
		{ID: "sh1", Slug: "one", Token: "token-one", Enabled: true,
			Source: model.ShareSource{Kind: model.ShareSourceCoreProxyUser, ProxyUserID: "u1"}},
		{ID: "sh2", Slug: "two", Token: "token-two", Enabled: true,
			Source: model.ShareSource{Kind: model.ShareSourceCoreProxyUser, ProxyUserID: "u2"}},
	} {
		if err := s.UpsertSubscriptionShare(sh); err != nil {
			t.Fatal(err)
		}
	}

	got, ok := s.SubscriptionShareByToken("token-two")
	if !ok || got.ID != "sh2" {
		t.Fatalf("exact token must resolve its own share: ok=%v id=%q", ok, got.ID)
	}
	if _, ok := s.SubscriptionShareByToken("token-thre"); ok {
		t.Fatal("a token of the same length that does not match must not resolve")
	}
	// A prefix must never work: a partially guessed token stays useless.
	if _, ok := s.SubscriptionShareByToken("token-tw"); ok {
		t.Fatal("a prefix of a valid token resolved, which makes guessing incremental")
	}
	if _, ok := s.SubscriptionShareByToken(""); ok {
		t.Fatal("the empty token resolved")
	}
}

func TestSubscriptionShareByTokenFailsClosedOnDuplicateToken(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	// Should be unreachable with CSPRNG tokens. If it ever happens, Go
	// randomises map iteration, so serving the first hit would hand the same
	// URL different subscriptions on different requests. Refusing is the only
	// answer that is the same every time.
	for _, sh := range []model.SubscriptionShare{
		{ID: "sh1", Slug: "one", Token: "collided", Enabled: true,
			Source: model.ShareSource{Kind: model.ShareSourceCoreProxyUser, ProxyUserID: "u1"}},
		{ID: "sh2", Slug: "two", Token: "collided", Enabled: true,
			Source: model.ShareSource{Kind: model.ShareSourceCoreProxyUser, ProxyUserID: "u2"}},
	} {
		if err := s.UpsertSubscriptionShare(sh); err != nil {
			t.Fatal(err)
		}
	}
	if got, ok := s.SubscriptionShareByToken("collided"); ok {
		t.Fatalf("a duplicated token must resolve to nothing, got %q", got.ID)
	}
}

// The token index is rebuilt after every share write, on the JSON path and on
// the bolt hot store path (which mutates the share map in place): a rotated
// token stops resolving the moment the rotation commits, a new one starts,
// and a deleted share's token resolves to nothing.
func TestSubscriptionShareTokenIndexFollowsEveryWrite(t *testing.T) {
	for _, hot := range []bool{false, true} {
		name := "json"
		if hot {
			name = "bolt"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := OpenWithCipher(filepath.Join(dir, "state.json"), testCipher(t))
			if err != nil {
				t.Fatal(err)
			}
			if hot {
				if err := s.EnableRuntimeBoltHotStore(filepath.Join(dir, "state-hot.db")); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { _ = s.Close() })
			share := model.SubscriptionShare{ID: "sh1", Slug: "one", Token: "token-before", Enabled: true}
			if err := s.UpsertSubscriptionShare(share); err != nil {
				t.Fatal(err)
			}
			if _, ok := s.SubscriptionShareByToken("token-before"); !ok {
				t.Fatal("the token did not resolve")
			}
			share.Token = "token-after"
			if err := s.UpsertSubscriptionShare(share); err != nil {
				t.Fatal(err)
			}
			if _, ok := s.SubscriptionShareByToken("token-before"); ok {
				t.Fatal("a rotated-away token still resolved")
			}
			if got, ok := s.SubscriptionShareByToken("token-after"); !ok || got.ID != "sh1" {
				t.Fatalf("the rotated token resolved ok=%v id=%q", ok, got.ID)
			}
			if err := s.DeleteSubscriptionShare("sh1"); err != nil {
				t.Fatal(err)
			}
			if _, ok := s.SubscriptionShareByToken("token-after"); ok {
				t.Fatal("a deleted share's token still resolved")
			}
		})
	}
}

// A reopened store resolves tokens from the state it loaded, and the index
// it builds holds MACs under its own random key, never the tokens.
func TestSubscriptionShareTokenIndexAfterReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	cipher := testCipher(t)
	s, err := OpenWithCipher(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSubscriptionShare(model.SubscriptionShare{ID: "sh1", Slug: "one", Token: "persisted-token", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWithCipher(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := reopened.SubscriptionShareByToken("persisted-token"); !ok || got.ID != "sh1" {
		t.Fatalf("reopened lookup ok=%v id=%q", ok, got.ID)
	}
	reopened.mu.Lock()
	index := reopened.linkIndex
	reopened.mu.Unlock()
	if index == nil || len(index.byMAC) != 1 {
		t.Fatalf("index = %+v", index)
	}
	for mac := range index.byMAC {
		if bytes.Contains(mac[:], []byte("persisted")) || mac == sha256.Sum256([]byte("persisted-token")) {
			t.Fatal("the index is keyed by something derivable from the token alone")
		}
	}
}
