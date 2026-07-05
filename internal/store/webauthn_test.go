package store

import (
	"errors"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-server/internal/auth"
)

func testCredential(userID, name string, credentialID []byte) auth.WebAuthnCredential {
	now := time.Now().UTC()
	return auth.WebAuthnCredential{
		ID:           "wacred_" + name,
		UserID:       userID,
		Name:         name,
		CredentialID: credentialID,
		PublicKey:    []byte("pubkey-" + name),
		AAGUID:       []byte{0, 0, 0, 0},
		SignCount:    0,
		Transports:   []string{"internal", "hybrid"},
		CreatedAt:    now,
	}
}

func TestWebAuthnCredentialCRUDAndCap(t *testing.T) {
	st, err := Open("")
	if err != nil {
		t.Fatal(err)
	}

	// Fill a user up to the per-user cap.
	for i := 0; i < MaxWebAuthnCredentialsPerUser; i++ {
		c := testCredential("u1", "c"+string(rune('a'+i)), []byte{byte(i)})
		if err := st.UpsertWebAuthnCredential(c); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	if got := st.CountWebAuthnCredentialsByUser("u1"); got != MaxWebAuthnCredentialsPerUser {
		t.Fatalf("count = %d, want %d", got, MaxWebAuthnCredentialsPerUser)
	}

	// The next insert for the same user is refused with the typed limit error.
	over := testCredential("u1", "overflow", []byte{99})
	if err := st.UpsertWebAuthnCredential(over); !errors.Is(err, ErrWebAuthnCredentialLimit) {
		t.Fatalf("expected ErrWebAuthnCredentialLimit, got %v", err)
	}

	// A different user is unaffected by u1's cap.
	if err := st.UpsertWebAuthnCredential(testCredential("u2", "other", []byte{200})); err != nil {
		t.Fatalf("second user insert: %v", err)
	}

	// Updating an existing record (same store id) is allowed even at the cap.
	existing := testCredential("u1", "ca", []byte{0})
	existing.Name = "renamed in place"
	if err := st.UpsertWebAuthnCredential(existing); err != nil {
		t.Fatalf("update at cap should be allowed: %v", err)
	}

	// Lookup by raw credential id.
	if _, ok := st.WebAuthnCredentialByCredentialID([]byte{200}); !ok {
		t.Fatal("expected to find u2 credential by credential id")
	}
	if _, ok := st.WebAuthnCredentialByCredentialID([]byte{123}); ok {
		t.Fatal("did not expect to find an unknown credential id")
	}

	// Rename is ownership-scoped: another user cannot rename u1's credential.
	if _, ok, err := st.RenameWebAuthnCredential("wacred_ca", "u2", "hijack"); err != nil || ok {
		t.Fatalf("cross-user rename should fail quietly: ok=%v err=%v", ok, err)
	}
	updated, ok, err := st.RenameWebAuthnCredential("wacred_ca", "u1", "My Laptop")
	if err != nil || !ok || updated.Name != "My Laptop" {
		t.Fatalf("owner rename failed: ok=%v err=%v name=%q", ok, err, updated.Name)
	}

	// Touch updates sign count / backup state / last used.
	used := time.Now().UTC()
	if err := st.TouchWebAuthnCredential("wacred_ca", 42, true, used); err != nil {
		t.Fatal(err)
	}
	got, ok := st.WebAuthnCredential("wacred_ca")
	if !ok || got.SignCount != 42 || !got.BackupState || got.LastUsedAt.IsZero() {
		t.Fatalf("touch not persisted: %+v", got)
	}

	// Delete is ownership-scoped.
	if ok, err := st.DeleteWebAuthnCredential("wacred_ca", "u2"); err != nil || ok {
		t.Fatalf("cross-user delete should fail quietly: ok=%v err=%v", ok, err)
	}
	if ok, err := st.DeleteWebAuthnCredential("wacred_ca", "u1"); err != nil || !ok {
		t.Fatalf("owner delete failed: ok=%v err=%v", ok, err)
	}
	if _, ok := st.WebAuthnCredential("wacred_ca"); ok {
		t.Fatal("credential should be gone after delete")
	}

	// After deleting one, a fresh insert for u1 is possible again (below cap).
	if err := st.UpsertWebAuthnCredential(testCredential("u1", "fresh", []byte{240})); err != nil {
		t.Fatalf("insert after delete should be allowed: %v", err)
	}
}

func TestWebAuthnChallengeLifecycle(t *testing.T) {
	st, err := Open("")
	if err != nil {
		t.Fatal(err)
	}

	ch, err := auth.NewWebAuthnChallenge("u1", "198.51.100.7", auth.WebAuthnPurposeRegister, []byte(`{"challenge":"x"}`), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutWebAuthnChallenge(ch); err != nil {
		t.Fatal(err)
	}

	got, ok := st.WebAuthnChallenge(ch.ID)
	if !ok {
		t.Fatal("active challenge not found")
	}
	if got.ClientIP != "198.51.100.7" || got.Purpose != auth.WebAuthnPurposeRegister || got.UserID != "u1" {
		t.Fatalf("challenge fields not preserved: %+v", got)
	}

	// Single-use: consuming deletes it.
	if err := st.ConsumeWebAuthnChallenge(ch.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.WebAuthnChallenge(ch.ID); ok {
		t.Fatal("consumed challenge must not be retrievable")
	}

	// Expiry: a challenge past its TTL is not active.
	expired, err := auth.NewWebAuthnChallenge("u1", "198.51.100.7", auth.WebAuthnPurposeLogin, []byte("{}"), -1*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutWebAuthnChallenge(expired); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.WebAuthnChallenge(expired.ID); ok {
		t.Fatal("expired challenge must not be active")
	}

	// Active reports correctly at a chosen instant.
	future := auth.WebAuthnChallenge{ExpiresAt: time.Now().Add(time.Minute)}
	if !future.Active(time.Now()) {
		t.Fatal("future challenge should be active")
	}
	if future.Active(time.Now().Add(2 * time.Minute)) {
		t.Fatal("challenge should be inactive after expiry")
	}
	used := auth.WebAuthnChallenge{ExpiresAt: time.Now().Add(time.Minute), Used: true}
	if used.Active(time.Now()) {
		t.Fatal("used challenge should be inactive")
	}
}
