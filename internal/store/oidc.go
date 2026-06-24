package store

import (
	"errors"
	"sort"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
)

// maxOIDCAuthStates bounds in-flight login states so a flood of /start calls
// cannot grow the state file without limit.
const maxOIDCAuthStates = 4096

// oidcIdentityKey composes the durable (providerID, subject) link key. The
// trust anchor is the admin-vetted provider record, not the bare issuer string.
// A NUL separator cannot appear in either field, so keys are unambiguous.
func oidcIdentityKey(providerID, subject string) string {
	return providerID + "\x00" + subject
}

// --- providers (admin config) --------------------------------------------

func (s *Store) UpsertOIDCProvider(p model.OIDCProvider) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.OIDCProviders[p.ID] = p
	return s.Save()
}

func (s *Store) OIDCProvider(id string) (model.OIDCProvider, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.state.OIDCProviders[id]
	return p, ok
}

func (s *Store) OIDCProviders() []model.OIDCProvider {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.OIDCProvider, 0, len(s.state.OIDCProviders))
	for _, p := range s.state.OIDCProviders {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (s *Store) EnabledOIDCProviders() []model.OIDCProvider {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.OIDCProvider{}
	for _, p := range s.state.OIDCProviders {
		if p.Enabled {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (s *Store) DeleteOIDCProvider(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.OIDCProviders[id]; !ok {
		return errors.New("oidc provider not found")
	}
	delete(s.state.OIDCProviders, id)
	return s.Save()
}

// --- identities (durable subject→user links) -----------------------------

func (s *Store) OIDCIdentity(providerID, subject string) (model.OIDCIdentity, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idn, ok := s.state.OIDCIdentities[oidcIdentityKey(providerID, subject)]
	return idn, ok
}

func (s *Store) PutOIDCIdentity(idn model.OIDCIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.OIDCIdentities[oidcIdentityKey(idn.ProviderID, idn.Subject)] = idn
	return s.Save()
}

// DeleteOIDCIdentitiesByUser removes every durable subject→user link bound to
// userID. The map is keyed by provider+subject (not user id), so it is scanned.
// Used when deleting a user so a stale link can never re-resolve to a removed
// account. Returns the count removed.
func (s *Store) DeleteOIDCIdentitiesByUser(userID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, idn := range s.state.OIDCIdentities {
		if idn.UserID == userID {
			delete(s.state.OIDCIdentities, k)
			n++
		}
	}
	if n > 0 {
		_ = s.Save()
	}
	return n
}

// --- ephemeral auth states (single-use) ----------------------------------

func (s *Store) PutOIDCAuthState(st auth.OIDCAuthState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for k, existing := range s.state.OIDCAuthStates {
		if now.After(existing.ExpiresAt) {
			delete(s.state.OIDCAuthStates, k)
		}
	}
	if len(s.state.OIDCAuthStates) >= maxOIDCAuthStates {
		return errors.New("too many pending oidc logins")
	}
	s.state.OIDCAuthStates[st.State] = st
	return s.Save()
}

// ConsumeOIDCAuthState atomically fetches and deletes the auth state for the
// given `state` value (single use). It returns false if the state is unknown or
// expired; an expired entry is still deleted.
func (s *Store) ConsumeOIDCAuthState(state string) (auth.OIDCAuthState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.state.OIDCAuthStates[state]
	if !ok {
		return auth.OIDCAuthState{}, false
	}
	delete(s.state.OIDCAuthStates, state)
	if err := s.Save(); err != nil {
		return auth.OIDCAuthState{}, false
	}
	if time.Now().UTC().After(st.ExpiresAt) {
		return auth.OIDCAuthState{}, false
	}
	return st, true
}
