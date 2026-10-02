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
// scan did. Shares are its only kind today; identity links register here as
// another kind, so a token is never resolved by two different rules.
type linkTokenIndex struct {
	key   [32]byte
	byMAC map[[sha256.Size]byte][]linkRef
	// source identifies the share map the index was built from, so a state
	// replaced wholesale (load, restore) is never answered from an index of
	// the old one. gen is the store's share generation at build time.
	source uintptr
	count  int
	gen    uint64
}

// linkRef names one record holding a token.
type linkRef struct {
	kind string
	id   string
}

const linkKindShare = "share"

func (x *linkTokenIndex) mac(token string) [sha256.Size]byte {
	h := hmac.New(sha256.New, x.key[:])
	h.Write([]byte(token))
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// shareTokenIndexLocked returns an index current for the share map, building
// one when there is none or the map has moved on. Callers hold s.mu.
func (s *Store) shareTokenIndexLocked() *linkTokenIndex {
	source := reflect.ValueOf(s.state.SubscriptionShares).Pointer()
	if x := s.linkIndex; x != nil && x.source == source && x.count == len(s.state.SubscriptionShares) && x.gen == s.shareGen {
		return x
	}
	x := &linkTokenIndex{byMAC: make(map[[sha256.Size]byte][]linkRef, len(s.state.SubscriptionShares)),
		source: source, count: len(s.state.SubscriptionShares), gen: s.shareGen}
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
	s.linkIndex = x
	return x
}

// invalidateShareTokenIndexLocked forgets the index after a share write.
// Callers hold s.mu.
func (s *Store) invalidateShareTokenIndexLocked() {
	s.shareGen++
	s.linkIndex = nil
}
