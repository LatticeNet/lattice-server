package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/secret"
)

// This file is the single boundary where persisted credentials are encrypted on
// save and decrypted on load. The in-memory State always holds plaintext, so
// every other code path (handlers, providers, workers) is unaware encryption
// exists.
//
// The encrypted set is deliberately limited to *reversible* credentials. One-way
// hashes already safe at rest are intentionally left untouched:
//   - model.User.PasswordHash, RecoveryCodeHashes
//   - model.Token.TokenHash, model.Node.TokenHash
//
// Encrypted fields:
//   - model.User.TOTPSecret            2FA shared secret (reversible → 2FA bypass if leaked)
//   - auth.Session.ID/CSRFToken        active login bearer material
//   - auth.TOTPChallenge.ID            pending 2FA challenge bearer material
//   - model.DDNSProfile.CFAPIToken     Cloudflare API token
//   - model.DDNSProfile.WebhookHeaders may carry Authorization headers
//   - model.NotifyChannel.Config[*]    bot tokens, SMTP passwords, webhook secrets
//   - model.OIDCProvider.ClientSecret  OAuth2 client secret for SSO
//   - auth.OIDCAuthState.State/CodeVerifier short-lived OAuth2 state + PKCE verifier
//
// When adding a new persisted credential, encrypt it here AND extend
// stateHasEnvelope so the lost-key guard stays accurate.

// encryptedState returns a shallow copy of st in which the secret-bearing maps
// are replaced by deep copies with their secret fields encrypted. The input is
// never mutated, so the live in-memory state stays plaintext. A disabled cipher
// returns st unchanged.
func encryptedState(st State, c secret.Cipher) (State, error) {
	if !c.Enabled() {
		return st, nil
	}
	out := st // shallow copy; non-secret maps/slices stay shared by reference

	users := make(map[string]model.User, len(st.Users))
	for id, u := range st.Users {
		enc, err := encryptUserRecord(id, u, c)
		if err != nil {
			return State{}, err
		}
		users[id] = enc
	}
	out.Users = users

	sessions := make(map[string]auth.Session, len(st.Sessions))
	for id, sess := range st.Sessions {
		rid := recordID(id, sess.ID)
		if rid == "" {
			return State{}, fmt.Errorf("session %q has empty id; refusing to write a colliding opaque key", id)
		}
		enc, err := encryptSessionRecord(id, sess, c)
		if err != nil {
			return State{}, err
		}
		sessions[sessionStorageKey(rid)] = enc
	}
	out.Sessions = sessions

	totpChallenges := make(map[string]auth.TOTPChallenge, len(st.TOTPChallenges))
	for id, challenge := range st.TOTPChallenges {
		rid := recordID(id, challenge.ID)
		if rid == "" {
			return State{}, fmt.Errorf("totp challenge %q has empty id; refusing to write a colliding opaque key", id)
		}
		enc, err := encryptTOTPChallengeRecord(id, challenge, c)
		if err != nil {
			return State{}, err
		}
		totpChallenges[totpChallengeStorageKey(rid)] = enc
	}
	out.TOTPChallenges = totpChallenges

	ddns := make(map[string]model.DDNSProfile, len(st.DDNS))
	for id, d := range st.DDNS {
		enc, err := encryptDDNSRecord(id, d, c)
		if err != nil {
			return State{}, err
		}
		ddns[id] = enc
	}
	out.DDNS = ddns

	notify := make(map[string]model.NotifyChannel, len(st.NotifyChannels))
	for id, n := range st.NotifyChannels {
		enc, err := encryptNotifyRecord(id, n, c)
		if err != nil {
			return State{}, err
		}
		notify[id] = enc
	}
	out.NotifyChannels = notify

	providers := make(map[string]model.OIDCProvider, len(st.OIDCProviders))
	for id, p := range st.OIDCProviders {
		enc, err := encryptOIDCProviderRecord(id, p, c)
		if err != nil {
			return State{}, err
		}
		providers[id] = enc
	}
	out.OIDCProviders = providers

	oidcAuthStates := make(map[string]auth.OIDCAuthState, len(st.OIDCAuthStates))
	for id, authState := range st.OIDCAuthStates {
		rid := recordID(id, authState.State)
		if rid == "" {
			return State{}, fmt.Errorf("oidc auth state %q has empty state; refusing to write a colliding opaque key", id)
		}
		enc, err := encryptOIDCAuthStateRecord(id, authState, c)
		if err != nil {
			return State{}, err
		}
		oidcAuthStates[oidcAuthStateStorageKey(rid)] = enc
	}
	out.OIDCAuthStates = oidcAuthStates

	return out, nil
}

// decryptState decrypts the secret fields of st in place. It runs once after
// load. A decryption error is fatal (wrong key / tampered file): the caller must
// stop startup rather than silently serve corrupt credentials.
//
// With a disabled cipher, encountering an existing envelope means the state was
// encrypted under a key that is no longer configured; that is reported as an
// error instead of corrupting the value into the raw envelope string.
func decryptState(st *State, c secret.Cipher) error {
	if !c.Enabled() {
		if stateHasEnvelope(st) {
			return fmt.Errorf("state contains encrypted secrets but no master key is configured (set %s or %s)",
				secret.EnvMasterKey, secret.EnvMasterKeyFile)
		}
		normalizeAuthMapKeys(st)
		return nil
	}

	// Build fresh maps rather than mutating in place while ranging. The keys are
	// unchanged here so in-place writes are technically safe, but the re-keyed
	// auth maps below already use the fresh-map form; doing it uniformly removes
	// a fragile pattern that would silently break if a key were ever derived.
	users := make(map[string]model.User, len(st.Users))
	for id, u := range st.Users {
		dec, err := decryptUserRecord(id, u, c)
		if err != nil {
			return err
		}
		users[id] = dec
	}
	st.Users = users

	sessions := make(map[string]auth.Session, len(st.Sessions))
	for id, sess := range st.Sessions {
		dec, err := decryptSessionRecord(id, sess, c)
		if err != nil {
			return err
		}
		sessions[recordID(id, dec.ID)] = dec
	}
	st.Sessions = sessions

	totpChallenges := make(map[string]auth.TOTPChallenge, len(st.TOTPChallenges))
	for id, challenge := range st.TOTPChallenges {
		dec, err := decryptTOTPChallengeRecord(id, challenge, c)
		if err != nil {
			return err
		}
		totpChallenges[recordID(id, dec.ID)] = dec
	}
	st.TOTPChallenges = totpChallenges

	ddns := make(map[string]model.DDNSProfile, len(st.DDNS))
	for id, d := range st.DDNS {
		dec, err := decryptDDNSRecord(id, d, c)
		if err != nil {
			return err
		}
		ddns[id] = dec
	}
	st.DDNS = ddns

	notify := make(map[string]model.NotifyChannel, len(st.NotifyChannels))
	for id, n := range st.NotifyChannels {
		dec, err := decryptNotifyRecord(id, n, c)
		if err != nil {
			return err
		}
		notify[id] = dec
	}
	st.NotifyChannels = notify

	providers := make(map[string]model.OIDCProvider, len(st.OIDCProviders))
	for id, p := range st.OIDCProviders {
		dec, err := decryptOIDCProviderRecord(id, p, c)
		if err != nil {
			return err
		}
		providers[id] = dec
	}
	st.OIDCProviders = providers

	oidcAuthStates := make(map[string]auth.OIDCAuthState, len(st.OIDCAuthStates))
	for id, authState := range st.OIDCAuthStates {
		dec, err := decryptOIDCAuthStateRecord(id, authState, c)
		if err != nil {
			return err
		}
		oidcAuthStates[recordID(id, dec.State)] = dec
	}
	st.OIDCAuthStates = oidcAuthStates

	return nil
}

// stateHasEnvelope reports whether any encrypted secret-bearing field is present.
// Used by the disabled-cipher guard to distinguish "all plaintext, fine" from
// "encrypted but the key is gone".
func stateHasEnvelope(st *State) bool {
	for _, u := range st.Users {
		if secret.IsEnvelope(u.TOTPSecret) {
			return true
		}
	}
	for _, sess := range st.Sessions {
		if secret.IsEnvelope(sess.ID) || secret.IsEnvelope(sess.CSRFToken) {
			return true
		}
	}
	for _, challenge := range st.TOTPChallenges {
		if secret.IsEnvelope(challenge.ID) {
			return true
		}
	}
	for _, d := range st.DDNS {
		if secret.IsEnvelope(d.CFAPIToken) || secret.IsEnvelope(d.WebhookHeaders) {
			return true
		}
	}
	for _, n := range st.NotifyChannels {
		for _, v := range n.Config {
			if secret.IsEnvelope(v) {
				return true
			}
		}
	}
	for _, p := range st.OIDCProviders {
		if secret.IsEnvelope(p.ClientSecret) {
			return true
		}
	}
	for _, authState := range st.OIDCAuthStates {
		if secret.IsEnvelope(authState.State) || secret.IsEnvelope(authState.CodeVerifier) {
			return true
		}
	}
	return false
}

func normalizeAuthMapKeys(st *State) {
	sessions := make(map[string]auth.Session, len(st.Sessions))
	for id, sess := range st.Sessions {
		sessions[recordID(id, sess.ID)] = sess
	}
	st.Sessions = sessions

	totpChallenges := make(map[string]auth.TOTPChallenge, len(st.TOTPChallenges))
	for id, challenge := range st.TOTPChallenges {
		totpChallenges[recordID(id, challenge.ID)] = challenge
	}
	st.TOTPChallenges = totpChallenges

	oidcAuthStates := make(map[string]auth.OIDCAuthState, len(st.OIDCAuthStates))
	for id, authState := range st.OIDCAuthStates {
		oidcAuthStates[recordID(id, authState.State)] = authState
	}
	st.OIDCAuthStates = oidcAuthStates
}

// The encrypt*Record / decrypt*Record helpers below are the per-record crypto
// boundary. They are used by BOTH backends:
//   - the JSON store, via encryptedState/decryptState (which short-circuit the
//     disabled-cipher case in decryptState before reaching these), and
//   - the bbolt store, which calls them directly per record.
// The `if !c.Enabled() && IsEnvelope(...)` guard in each decrypt*Record is
// therefore the authoritative fail-closed point for the bbolt path (it is
// unreachable from the JSON path, which guards earlier) — do not remove it.

func encryptUserRecord(id string, u model.User, c secret.Cipher) (model.User, error) {
	enc, err := c.Encrypt(u.TOTPSecret)
	if err != nil {
		return model.User{}, fmt.Errorf("encrypt user %s totp secret: %w", id, err)
	}
	u.TOTPSecret = enc
	return u, nil
}

func decryptUserRecord(id string, u model.User, c secret.Cipher) (model.User, error) {
	if !c.Enabled() && secret.IsEnvelope(u.TOTPSecret) {
		return model.User{}, lostMasterKeyError()
	}
	dec, err := c.Decrypt(u.TOTPSecret)
	if err != nil {
		return model.User{}, fmt.Errorf("decrypt user %s totp secret: %w", id, err)
	}
	u.TOTPSecret = dec
	return u, nil
}

func encryptSessionRecord(id string, sess auth.Session, c secret.Cipher) (auth.Session, error) {
	encID, err := c.Encrypt(sess.ID)
	if err != nil {
		return auth.Session{}, fmt.Errorf("encrypt session %s id: %w", id, err)
	}
	encCSRF, err := c.Encrypt(sess.CSRFToken)
	if err != nil {
		return auth.Session{}, fmt.Errorf("encrypt session %s csrf token: %w", id, err)
	}
	sess.ID = encID
	sess.CSRFToken = encCSRF
	return sess, nil
}

func decryptSessionRecord(id string, sess auth.Session, c secret.Cipher) (auth.Session, error) {
	if !c.Enabled() && (secret.IsEnvelope(sess.ID) || secret.IsEnvelope(sess.CSRFToken)) {
		return auth.Session{}, lostMasterKeyError()
	}
	decID, err := c.Decrypt(sess.ID)
	if err != nil {
		return auth.Session{}, fmt.Errorf("decrypt session %s id: %w", id, err)
	}
	decCSRF, err := c.Decrypt(sess.CSRFToken)
	if err != nil {
		return auth.Session{}, fmt.Errorf("decrypt session %s csrf token: %w", id, err)
	}
	sess.ID = decID
	sess.CSRFToken = decCSRF
	return sess, nil
}

func encryptTOTPChallengeRecord(id string, challenge auth.TOTPChallenge, c secret.Cipher) (auth.TOTPChallenge, error) {
	enc, err := c.Encrypt(challenge.ID)
	if err != nil {
		return auth.TOTPChallenge{}, fmt.Errorf("encrypt totp challenge %s id: %w", id, err)
	}
	challenge.ID = enc
	return challenge, nil
}

func decryptTOTPChallengeRecord(id string, challenge auth.TOTPChallenge, c secret.Cipher) (auth.TOTPChallenge, error) {
	if !c.Enabled() && secret.IsEnvelope(challenge.ID) {
		return auth.TOTPChallenge{}, lostMasterKeyError()
	}
	dec, err := c.Decrypt(challenge.ID)
	if err != nil {
		return auth.TOTPChallenge{}, fmt.Errorf("decrypt totp challenge %s id: %w", id, err)
	}
	challenge.ID = dec
	return challenge, nil
}

func encryptDDNSRecord(id string, d model.DDNSProfile, c secret.Cipher) (model.DDNSProfile, error) {
	tok, err := c.Encrypt(d.CFAPIToken)
	if err != nil {
		return model.DDNSProfile{}, fmt.Errorf("encrypt ddns %s cf token: %w", id, err)
	}
	hdr, err := c.Encrypt(d.WebhookHeaders)
	if err != nil {
		return model.DDNSProfile{}, fmt.Errorf("encrypt ddns %s webhook headers: %w", id, err)
	}
	d.CFAPIToken = tok
	d.WebhookHeaders = hdr
	return d, nil
}

func decryptDDNSRecord(id string, d model.DDNSProfile, c secret.Cipher) (model.DDNSProfile, error) {
	if !c.Enabled() && (secret.IsEnvelope(d.CFAPIToken) || secret.IsEnvelope(d.WebhookHeaders)) {
		return model.DDNSProfile{}, lostMasterKeyError()
	}
	tok, err := c.Decrypt(d.CFAPIToken)
	if err != nil {
		return model.DDNSProfile{}, fmt.Errorf("decrypt ddns %s cf token: %w", id, err)
	}
	hdr, err := c.Decrypt(d.WebhookHeaders)
	if err != nil {
		return model.DDNSProfile{}, fmt.Errorf("decrypt ddns %s webhook headers: %w", id, err)
	}
	d.CFAPIToken = tok
	d.WebhookHeaders = hdr
	return d, nil
}

func encryptNotifyRecord(id string, n model.NotifyChannel, c secret.Cipher) (model.NotifyChannel, error) {
	if n.Config != nil {
		cfg := make(map[string]string, len(n.Config))
		for k, v := range n.Config {
			ev, err := c.Encrypt(v)
			if err != nil {
				return model.NotifyChannel{}, fmt.Errorf("encrypt notify %s config[%s]: %w", id, k, err)
			}
			cfg[k] = ev
		}
		n.Config = cfg
	}
	return n, nil
}

func decryptNotifyRecord(id string, n model.NotifyChannel, c secret.Cipher) (model.NotifyChannel, error) {
	if n.Config == nil {
		return n, nil
	}
	cfg := make(map[string]string, len(n.Config))
	for k, v := range n.Config {
		if !c.Enabled() && secret.IsEnvelope(v) {
			return model.NotifyChannel{}, lostMasterKeyError()
		}
		dv, err := c.Decrypt(v)
		if err != nil {
			return model.NotifyChannel{}, fmt.Errorf("decrypt notify %s config[%s]: %w", id, k, err)
		}
		cfg[k] = dv
	}
	n.Config = cfg
	return n, nil
}

func encryptOIDCProviderRecord(id string, p model.OIDCProvider, c secret.Cipher) (model.OIDCProvider, error) {
	sec, err := c.Encrypt(p.ClientSecret)
	if err != nil {
		return model.OIDCProvider{}, fmt.Errorf("encrypt oidc provider %s client secret: %w", id, err)
	}
	p.ClientSecret = sec
	return p, nil
}

func decryptOIDCProviderRecord(id string, p model.OIDCProvider, c secret.Cipher) (model.OIDCProvider, error) {
	if !c.Enabled() && secret.IsEnvelope(p.ClientSecret) {
		return model.OIDCProvider{}, lostMasterKeyError()
	}
	sec, err := c.Decrypt(p.ClientSecret)
	if err != nil {
		return model.OIDCProvider{}, fmt.Errorf("decrypt oidc provider %s client secret: %w", id, err)
	}
	p.ClientSecret = sec
	return p, nil
}

func encryptOIDCAuthStateRecord(id string, authState auth.OIDCAuthState, c secret.Cipher) (auth.OIDCAuthState, error) {
	encState, err := c.Encrypt(authState.State)
	if err != nil {
		return auth.OIDCAuthState{}, fmt.Errorf("encrypt oidc auth state %s state: %w", id, err)
	}
	encVerifier, err := c.Encrypt(authState.CodeVerifier)
	if err != nil {
		return auth.OIDCAuthState{}, fmt.Errorf("encrypt oidc auth state %s code verifier: %w", id, err)
	}
	authState.State = encState
	authState.CodeVerifier = encVerifier
	return authState, nil
}

func decryptOIDCAuthStateRecord(id string, authState auth.OIDCAuthState, c secret.Cipher) (auth.OIDCAuthState, error) {
	if !c.Enabled() && (secret.IsEnvelope(authState.State) || secret.IsEnvelope(authState.CodeVerifier)) {
		return auth.OIDCAuthState{}, lostMasterKeyError()
	}
	decState, err := c.Decrypt(authState.State)
	if err != nil {
		return auth.OIDCAuthState{}, fmt.Errorf("decrypt oidc auth state %s state: %w", id, err)
	}
	decVerifier, err := c.Decrypt(authState.CodeVerifier)
	if err != nil {
		return auth.OIDCAuthState{}, fmt.Errorf("decrypt oidc auth state %s code verifier: %w", id, err)
	}
	authState.State = decState
	authState.CodeVerifier = decVerifier
	return authState, nil
}

func sessionStorageKey(id string) string {
	return opaqueStorageKey("session", id)
}

func totpChallengeStorageKey(id string) string {
	return opaqueStorageKey("totp_challenge", id)
}

func oidcAuthStateStorageKey(state string) string {
	return opaqueStorageKey("oidc_auth_state", state)
}

func opaqueStorageKey(kind, id string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + id))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func recordID(key, id string) string {
	if id != "" {
		return id
	}
	return key
}

func lostMasterKeyError() error {
	return fmt.Errorf("state contains encrypted secrets but no master key is configured (set %s or %s)",
		secret.EnvMasterKey, secret.EnvMasterKeyFile)
}
