package store

import (
	"errors"
	"maps"
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

// UpsertOIDCProvider stores p and settles its links as every provider write
// does (UpsertOIDCProviderSettlingLinks without clearing confirmations), so
// no caller can store a provider that its links from another issuer outlive.
func (s *Store) UpsertOIDCProvider(p model.OIDCProvider) error {
	_, _, err := s.UpsertOIDCProviderSettlingLinks(p, false, nil)
	return err
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

// ConfirmOIDCIdentitySecondFactor records that userID completed its local
// second factor in a sign-in that started at this provider subject, under the
// given issuer and security epoch. It changes only an existing link that still
// names userID, so it can neither create a link nor resurrect one deleted with
// its user. It returns the link as it was before and whether it changed one.
// The link takes the issuer the sign-in saw, which is what a later skip
// compares with the provider's.
func (s *Store) ConfirmOIDCIdentitySecondFactor(providerID, issuer, subject, userID string, at time.Time, epoch uint64) (model.OIDCIdentity, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := oidcIdentityKey(providerID, subject)
	prior, ok := s.state.OIDCIdentities[key]
	if !ok || prior.UserID != userID || prior.Issuer != issuer {
		return model.OIDCIdentity{}, false, nil
	}
	idn := prior
	idn.Issuer = issuer
	idn.SecondFactorAt = at.UTC()
	idn.SecondFactorEpoch = epoch
	staged := s.state
	staged.OIDCIdentities = maps.Clone(s.state.OIDCIdentities)
	staged.OIDCIdentities[key] = idn
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	return prior, committed, err
}

// ClearOIDCIdentityConfirmations forgets every second-factor confirmation on
// the links of one provider, so none of them may stand in for the local TOTP
// step until it is confirmed again. The links themselves stay. It returns how
// many confirmations it cleared.
func (s *Store) ClearOIDCIdentityConfirmations(providerID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := maps.Clone(s.state.OIDCIdentities)
	n := clearOIDCConfirmations(next, providerID)
	if n == 0 {
		return 0, nil
	}
	staged := s.state
	staged.OIDCIdentities = next
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if !committed {
		return 0, err
	}
	s.state = staged
	return n, err
}

// OIDCLinkChanges is what UpsertOIDCProviderSettlingLinks did to a
// provider's identity links.
type OIDCLinkChanges struct {
	// LinksRemoved counts links recorded under an issuer other than the
	// provider's.
	LinksRemoved int
	// ConfirmationsCleared counts second-factor confirmations forgotten on the
	// links that stayed.
	ConfirmationsCleared int
}

// UpsertOIDCProviderSettlingLinks stores p and, in the same write, settles its
// identity links: every link of p.ID recorded under an issuer other than
// p.Issuer is removed, and with clearConfirmations every confirmation on the
// links that stay is forgotten (the write that turns skip_local_totp on). One
// write, so nothing can land between the provider change and the links it
// invalidates. It returns what changed and whether the write is live; a live
// write may still report a persistence error. guard, when set, sees the
// record about to be replaced (nil for a new provider) under the store lock;
// an error from it refuses the write and is returned as is.
func (s *Store) UpsertOIDCProviderSettlingLinks(p model.OIDCProvider, clearConfirmations bool, guard func(current *model.OIDCProvider) error) (OIDCLinkChanges, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if guard != nil {
		var current *model.OIDCProvider
		if existing, ok := s.state.OIDCProviders[p.ID]; ok {
			current = &existing
		}
		if err := guard(current); err != nil {
			return OIDCLinkChanges{}, false, err
		}
	}
	var changes OIDCLinkChanges
	identities := maps.Clone(s.state.OIDCIdentities)
	for k, idn := range identities {
		if idn.ProviderID == p.ID && idn.Issuer != p.Issuer {
			delete(identities, k)
			changes.LinksRemoved++
		}
	}
	if clearConfirmations {
		changes.ConfirmationsCleared = clearOIDCConfirmations(identities, p.ID)
	}
	providers := maps.Clone(s.state.OIDCProviders)
	providers[p.ID] = p
	staged := s.state
	staged.OIDCIdentities = identities
	staged.OIDCProviders = providers
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if !committed {
		return OIDCLinkChanges{}, false, err
	}
	s.state = staged
	return changes, true, err
}

// clearOIDCConfirmations forgets, in identities (a copy the caller owns), the
// confirmations of providerID's links, and reports how many it cleared.
func clearOIDCConfirmations(identities map[string]model.OIDCIdentity, providerID string) int {
	n := 0
	for k, idn := range identities {
		if idn.ProviderID != providerID || (idn.SecondFactorAt.IsZero() && idn.SecondFactorEpoch == 0) {
			continue
		}
		idn.SecondFactorAt, idn.SecondFactorEpoch = time.Time{}, 0
		identities[k] = idn
		n++
	}
	return n
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
