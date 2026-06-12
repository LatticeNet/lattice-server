package store

import (
	"fmt"

	"github.com/LatticeNet/lattice-sdk/model"
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
//   - model.DDNSProfile.CFAPIToken     Cloudflare API token
//   - model.DDNSProfile.WebhookHeaders may carry Authorization headers
//   - model.NotifyChannel.Config[*]    bot tokens, SMTP passwords, webhook secrets
//   - model.OIDCProvider.ClientSecret  OAuth2 client secret for SSO
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
		enc, err := c.Encrypt(u.TOTPSecret)
		if err != nil {
			return State{}, fmt.Errorf("encrypt user %s totp secret: %w", id, err)
		}
		u.TOTPSecret = enc
		users[id] = u
	}
	out.Users = users

	ddns := make(map[string]model.DDNSProfile, len(st.DDNS))
	for id, d := range st.DDNS {
		tok, err := c.Encrypt(d.CFAPIToken)
		if err != nil {
			return State{}, fmt.Errorf("encrypt ddns %s cf token: %w", id, err)
		}
		hdr, err := c.Encrypt(d.WebhookHeaders)
		if err != nil {
			return State{}, fmt.Errorf("encrypt ddns %s webhook headers: %w", id, err)
		}
		d.CFAPIToken = tok
		d.WebhookHeaders = hdr
		ddns[id] = d
	}
	out.DDNS = ddns

	notify := make(map[string]model.NotifyChannel, len(st.NotifyChannels))
	for id, n := range st.NotifyChannels {
		if n.Config != nil {
			cfg := make(map[string]string, len(n.Config))
			for k, v := range n.Config {
				ev, err := c.Encrypt(v)
				if err != nil {
					return State{}, fmt.Errorf("encrypt notify %s config[%s]: %w", id, k, err)
				}
				cfg[k] = ev
			}
			n.Config = cfg
		}
		notify[id] = n
	}
	out.NotifyChannels = notify

	providers := make(map[string]model.OIDCProvider, len(st.OIDCProviders))
	for id, p := range st.OIDCProviders {
		sec, err := c.Encrypt(p.ClientSecret)
		if err != nil {
			return State{}, fmt.Errorf("encrypt oidc provider %s client secret: %w", id, err)
		}
		p.ClientSecret = sec
		providers[id] = p
	}
	out.OIDCProviders = providers

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
		return nil
	}

	for id, u := range st.Users {
		dec, err := c.Decrypt(u.TOTPSecret)
		if err != nil {
			return fmt.Errorf("decrypt user %s totp secret: %w", id, err)
		}
		u.TOTPSecret = dec
		st.Users[id] = u
	}

	for id, d := range st.DDNS {
		tok, err := c.Decrypt(d.CFAPIToken)
		if err != nil {
			return fmt.Errorf("decrypt ddns %s cf token: %w", id, err)
		}
		hdr, err := c.Decrypt(d.WebhookHeaders)
		if err != nil {
			return fmt.Errorf("decrypt ddns %s webhook headers: %w", id, err)
		}
		d.CFAPIToken = tok
		d.WebhookHeaders = hdr
		st.DDNS[id] = d
	}

	for id, n := range st.NotifyChannels {
		for k, v := range n.Config {
			dv, err := c.Decrypt(v)
			if err != nil {
				return fmt.Errorf("decrypt notify %s config[%s]: %w", id, k, err)
			}
			n.Config[k] = dv
		}
	}

	for id, p := range st.OIDCProviders {
		sec, err := c.Decrypt(p.ClientSecret)
		if err != nil {
			return fmt.Errorf("decrypt oidc provider %s client secret: %w", id, err)
		}
		p.ClientSecret = sec
		st.OIDCProviders[id] = p
	}

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
	return false
}
