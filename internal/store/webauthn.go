package store

import (
	"bytes"
	"errors"
	"sort"
	"time"

	"github.com/LatticeNet/lattice-server/internal/auth"
)

const (
	// MaxWebAuthnCredentialsPerUser caps how many passkeys one operator may
	// register. It bounds both storage and the allow/exclude lists sent to the
	// browser; a generous ceiling that still refuses runaway growth. Exported so
	// the server can fail a registration fast (before starting a ceremony) with
	// the same limit the store enforces on write.
	MaxWebAuthnCredentialsPerUser = 10
	// maxWebAuthnChallenges bounds pending passkey ceremony challenges, mirroring
	// maxTOTPChallenges. Challenges are short-lived, so this is only a floor under
	// churn / abuse.
	maxWebAuthnChallenges = 4096
)

// ErrWebAuthnCredentialLimit is returned when a user is already at the passkey
// cap. The server surfaces it as a clear client error.
var ErrWebAuthnCredentialLimit = errors.New("passkey limit reached for this account")

// UpsertWebAuthnCredential stores (or replaces) a passkey record. On insert it
// enforces the per-user cap so a client cannot register unbounded credentials;
// updates to an existing record (rename, sign-count refresh) are always allowed.
func (s *Store) UpsertWebAuthnCredential(c auth.WebAuthnCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.state.WebAuthnCreds[c.ID]; !exists {
		count := 0
		for _, existing := range s.state.WebAuthnCreds {
			if existing.UserID == c.UserID {
				count++
			}
		}
		if count >= MaxWebAuthnCredentialsPerUser {
			return ErrWebAuthnCredentialLimit
		}
	}
	s.state.WebAuthnCreds[c.ID] = c
	return s.Save()
}

// WebAuthnCredential returns a passkey record by store id.
func (s *Store) WebAuthnCredential(id string) (auth.WebAuthnCredential, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.state.WebAuthnCreds[id]
	return c, ok
}

// WebAuthnCredentialsByUser returns a user's passkeys, oldest first for a stable
// management list.
func (s *Store) WebAuthnCredentialsByUser(userID string) []auth.WebAuthnCredential {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]auth.WebAuthnCredential, 0)
	for _, c := range s.state.WebAuthnCreds {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// CountWebAuthnCredentialsByUser reports how many passkeys a user has. Used to
// enforce the cap before beginning a registration ceremony (fail fast) and to
// decide whether a delete would remove the operator's last passkey.
func (s *Store) CountWebAuthnCredentialsByUser(userID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.state.WebAuthnCreds {
		if c.UserID == userID {
			n++
		}
	}
	return n
}

// WebAuthnCredentialByCredentialID looks a passkey up by its raw WebAuthn
// credential id (not the store id). Used on login to reject an unknown
// credential and during registration to reject a duplicate.
func (s *Store) WebAuthnCredentialByCredentialID(credentialID []byte) (auth.WebAuthnCredential, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.state.WebAuthnCreds {
		if bytes.Equal(c.CredentialID, credentialID) {
			return c, true
		}
	}
	return auth.WebAuthnCredential{}, false
}

// RenameWebAuthnCredential updates the operator-editable label of a passkey the
// user owns. Ownership is enforced here so a caller cannot rename someone else's
// credential by guessing its id. Returns the updated record.
func (s *Store) RenameWebAuthnCredential(id, userID, name string) (auth.WebAuthnCredential, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.state.WebAuthnCreds[id]
	if !ok || c.UserID != userID {
		return auth.WebAuthnCredential{}, false, nil
	}
	c.Name = name
	s.state.WebAuthnCreds[id] = c
	if err := s.Save(); err != nil {
		return auth.WebAuthnCredential{}, false, err
	}
	return c, true, nil
}

// TouchWebAuthnCredential records the results of a successful login against a
// credential: the refreshed signature counter, the current backup state, and the
// last-used timestamp. Ownership scoping keeps the write authoritative. The
// caller has already applied the clone-detection policy; this method only
// persists the agreed new values.
func (s *Store) TouchWebAuthnCredential(id string, signCount uint32, backupState bool, usedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.state.WebAuthnCreds[id]
	if !ok {
		return nil
	}
	c.SignCount = signCount
	c.BackupState = backupState
	c.LastUsedAt = usedAt.UTC()
	s.state.WebAuthnCreds[id] = c
	return s.Save()
}

// DeleteWebAuthnCredential removes a passkey the user owns. Returns false if no
// such credential exists for that user (id unknown or owned by someone else).
func (s *Store) DeleteWebAuthnCredential(id, userID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.state.WebAuthnCreds[id]
	if !ok || c.UserID != userID {
		return false, nil
	}
	delete(s.state.WebAuthnCreds, id)
	if err := s.Save(); err != nil {
		return false, err
	}
	return true, nil
}

// PutWebAuthnChallenge stores a pending passkey ceremony challenge, sweeping
// expired/used ones first so the set stays bounded (challenges are short-lived),
// exactly like PutTOTPChallenge.
func (s *Store) PutWebAuthnChallenge(c auth.WebAuthnChallenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for id, existing := range s.state.WebAuthnChallenges {
		if !existing.Active(now) {
			delete(s.state.WebAuthnChallenges, id)
		}
	}
	if len(s.state.WebAuthnChallenges) >= maxWebAuthnChallenges {
		return errors.New("too many pending passkey challenges")
	}
	s.state.WebAuthnChallenges[c.ID] = c
	return s.Save()
}

// WebAuthnChallenge returns an active (unused, unexpired) challenge by id.
func (s *Store) WebAuthnChallenge(id string) (auth.WebAuthnChallenge, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.state.WebAuthnChallenges[id]
	if !ok || !c.Active(time.Now().UTC()) {
		return auth.WebAuthnChallenge{}, false
	}
	return c, true
}

// ConsumeWebAuthnChallenge marks a challenge spent by deleting it (single-use).
func (s *Store) ConsumeWebAuthnChallenge(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.WebAuthnChallenges[id]; !ok {
		return nil
	}
	delete(s.state.WebAuthnChallenges, id)
	return s.Save()
}
