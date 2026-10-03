package store

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"reflect"
)

// linkTokenIndex resolves a link token to the records that hold it without a
// scan. The public link endpoint is unauthenticated, and the scan it replaced
// walked every share under the store mutex on every request, constant-time
// compare included, which grows with every per-identity link handed out.
//
// The index is keyed by an HMAC of the token under a key drawn at random for
// each index, never by the token itself. A caller cannot aim a guess at a map
// bucket or learn anything from lookup timing about tokens it does not hold,
// and the map never holds a plaintext token. The hit is then confirmed with a
// constant-time compare against the stored token.
//
// "Exactly one match" stays one rule: a MAC that names zero records or more
// than one is a refusal, so a duplicated token fails closed exactly as the
// scan did. Shares and identity links (vpn_user_link.go) are its two kinds,
// in one map, so a token is never resolved by two different rules and a
// share token that equalled an identity's would answer neither.
type linkTokenIndex struct {
	key   [32]byte
	byMAC map[[sha256.Size]byte][]linkRef
	// source identifies the share map the index was built from, so a state
	// replaced wholesale (load, restore) is never answered from an index of
	// the old one. gen is the store's share generation at build time.
	source uintptr
	count  int
	gen    uint64
	// vpnPublic and vpnSecret identify the identity maps, vpnCount their
	// size and vpnGen the store's identity generation at build time. A hit
	// is always confirmed against the stored token, so an index that missed
	// a write can refuse a good token but never resolve a wrong one.
	vpnPublic, vpnSecret uintptr
	vpnCount             int
	vpnGen               uint64
}

// linkRef names one record holding a token.
type linkRef struct {
	kind string
	id   string
}

const (
	linkKindShare    = "share"
	linkKindIdentity = "identity"
)

func (x *linkTokenIndex) mac(token string) [sha256.Size]byte {
	h := hmac.New(sha256.New, x.key[:])
	h.Write([]byte(token))
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// shareTokenIndexLocked returns the link index; see linkTokenIndexLocked.
func (s *Store) shareTokenIndexLocked() *linkTokenIndex { return s.linkTokenIndexLocked() }

// linkTokenIndexLocked returns an index current for the share map and the
// identity maps, building one when there is none or either has moved on.
// Callers hold s.mu.
func (s *Store) linkTokenIndexLocked() *linkTokenIndex {
	source := reflect.ValueOf(s.state.SubscriptionShares).Pointer()
	vpnPublic := reflect.ValueOf(s.state.VpnUsers).Pointer()
	vpnSecret := reflect.ValueOf(s.state.VpnUserSecrets).Pointer()
	if x := s.linkIndex; x != nil && x.source == source && x.count == len(s.state.SubscriptionShares) && x.gen == s.shareGen &&
		x.vpnPublic == vpnPublic && x.vpnSecret == vpnSecret && x.vpnCount == len(s.state.VpnUsers) && x.vpnGen == s.vpnLinkGen {
		return x
	}
	x := &linkTokenIndex{byMAC: make(map[[sha256.Size]byte][]linkRef, len(s.state.SubscriptionShares)),
		source: source, count: len(s.state.SubscriptionShares), gen: s.shareGen,
		vpnPublic: vpnPublic, vpnSecret: vpnSecret, vpnCount: len(s.state.VpnUsers), vpnGen: s.vpnLinkGen}
	if _, err := rand.Read(x.key[:]); err != nil {
		// Without a key the index would be predictable; answer every lookup
		// with a refusal rather than build one.
		return &linkTokenIndex{byMAC: map[[sha256.Size]byte][]linkRef{}}
	}
	for id, share := range s.state.SubscriptionShares {
		if share.Token == "" {
			continue
		}
		mac := x.mac(share.Token)
		x.byMAC[mac] = append(x.byMAC[mac], linkRef{kind: linkKindShare, id: id})
	}
	for id, record := range s.state.VpnUsers {
		if record.Link == nil {
			continue
		}
		token := s.state.VpnUserSecrets[id].SubID
		if token == "" {
			continue
		}
		mac := x.mac(token)
		x.byMAC[mac] = append(x.byMAC[mac], linkRef{kind: linkKindIdentity, id: id})
	}
	s.linkIndex = x
	return x
}

// invalidateIdentityLinkIndexLocked forgets the index after an identity
// write. Callers hold s.mu.
func (s *Store) invalidateIdentityLinkIndexLocked() {
	s.vpnLinkGen++
	s.linkIndex = nil
}

// invalidateShareTokenIndexLocked forgets the index after a share write.
// Callers hold s.mu.
func (s *Store) invalidateShareTokenIndexLocked() {
	s.shareGen++
	s.linkIndex = nil
}
