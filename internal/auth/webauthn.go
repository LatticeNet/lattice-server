package auth

import "time"

// WebAuthn (passkey) support. This file carries only the plain data records the
// store persists; all CBOR/COSE/attestation parsing and signature verification
// lives behind github.com/go-webauthn/webauthn in the server package. Keeping
// the auth package dependency-light (stdlib only, like totp.go) means the record
// shapes here are trivially serialisable and the security-sensitive protocol
// code stays in one vetted third-party library rather than being hand-rolled.

// WebAuthnCredential is a single registered passkey belonging to a user. The
// public key and credential id are, by design, not secret (the whole point of
// asymmetric WebAuthn is that the private key never leaves the authenticator),
// so unlike TOTPSecret this record needs no at-rest envelope encryption.
type WebAuthnCredential struct {
	// ID is the opaque store record id (id.New("wacred")). It is the handle the
	// management UI uses to rename/delete; it is NOT the WebAuthn credential id.
	ID     string `json:"id"`
	UserID string `json:"user_id"`
	// Name is an operator-editable label, defaulted at creation from the
	// authenticator/User-Agent so a user with several passkeys can tell them apart.
	Name string `json:"name"`
	// CredentialID is the raw WebAuthn credential id (the authenticator's handle
	// for this key). Unique per credential; used to look a credential up on login.
	CredentialID []byte `json:"credential_id"`
	// PublicKey is the COSE-encoded public key used to verify assertions.
	PublicKey []byte `json:"public_key"`
	// AAGUID identifies the authenticator model (all-zero for many platform
	// authenticators, including Apple's). Advisory only.
	AAGUID []byte `json:"aaguid,omitempty"`
	// SignCount is the last observed authenticator signature counter. Synced
	// passkeys (e.g. Apple's, in iCloud Keychain) always report 0; a regression
	// from a previously non-zero value is a clone signal, logged but not fatal.
	SignCount uint32 `json:"sign_count"`
	// Transports are the hints the authenticator advertised ("internal", "hybrid",
	// "usb", …); passed back to the browser to speed up future prompts.
	Transports []string `json:"transports,omitempty"`
	// BackupEligible (BE) reports whether the credential can be backed up/synced.
	// It is fixed for the life of the credential.
	BackupEligible bool `json:"backup_eligible"`
	// BackupState (BS) reports whether the credential is currently backed
	// up/synced. It can change over time and is refreshed on every login.
	BackupState bool      `json:"backup_state"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsedAt  time.Time `json:"last_used_at,omitempty"`
}

// WebAuthn ceremony purposes. A challenge is minted for exactly one of these and
// may only be redeemed by the matching finish handler.
const (
	WebAuthnPurposeRegister = "register"
	WebAuthnPurposeLogin    = "login"
	WebAuthnPurposeStepUp   = "step_up"
)

// WebAuthnChallenge is the short-lived, single-use, IP-bound gate that ties the
// begin and finish steps of a WebAuthn ceremony together, mirroring
// TOTPChallenge. It stores the library's opaque SessionData (the server-side
// half of the ceremony: the random challenge, the allowed-credential list, and
// the required user-verification level) so the client cannot tamper with it
// between the two calls.
type WebAuthnChallenge struct {
	ID string `json:"id"`
	// UserID is the owning user for a registration ceremony. It is empty for a
	// usernameless (discoverable) login, where the user is only resolved at finish
	// from the authenticator's user handle.
	UserID string `json:"user_id,omitempty"`
	// ClientIP binds the challenge to the requesting client, exactly like
	// TOTPChallenge, so a challenge captured on one network cannot be completed
	// from another.
	ClientIP string `json:"client_ip"`
	// Purpose is one of WebAuthnPurpose*. The finish handler refuses a challenge
	// minted for the other ceremony.
	Purpose string `json:"purpose"`
	// SessionData is the JSON-encoded webauthn.SessionData for this ceremony.
	SessionData []byte    `json:"session_data"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Used        bool      `json:"used"`
}

// NewWebAuthnChallenge mints a challenge for a ceremony bound to the requesting
// client (and, for registration, to a user). The id is a fresh unguessable token
// returned to the client and echoed back at finish.
func NewWebAuthnChallenge(userID, clientIP, purpose string, sessionData []byte, ttl time.Duration) (WebAuthnChallenge, error) {
	id, err := NewRandomToken(32)
	if err != nil {
		return WebAuthnChallenge{}, err
	}
	now := time.Now().UTC()
	return WebAuthnChallenge{
		ID:          id,
		UserID:      userID,
		ClientIP:    clientIP,
		Purpose:     purpose,
		SessionData: sessionData,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
	}, nil
}

// Active reports whether the challenge can still be redeemed at now.
func (c WebAuthnChallenge) Active(now time.Time) bool {
	return !c.Used && !c.ExpiresAt.Before(now)
}
