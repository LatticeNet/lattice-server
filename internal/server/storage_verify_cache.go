package server

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

// storageVerifyCache removes key derivation from the storage route's hot path
// without removing it from an attacker's path.
//
// Why it exists. Every request on that route presents a bearer token and
// nothing remembered the previous answer, so every request paid a full PBKDF2
// at 210,000 iterations. Bounding that with a concurrency permit alone capped
// the route: measured at 4 permits, 16 simultaneous callers all holding a valid
// credential got 4 served and 12 refused, because the permit does not block and
// a public bucket's traffic is not occasional. Enlarging the pool relocates the
// saturation point and spends CPU the rest of the control plane needs; it does
// not remove the ceiling.
//
// What it does. It remembers that one exact presented credential verified, for
// a short time, and collapses simultaneous first-time requests for the same
// credential into a single derivation. Repeat legitimate traffic then costs a
// map lookup, while an attacker's distinct wrong secrets each miss and pay full
// price, which is the property the bound exists for.
//
// Only positive results are stored. A wrong secret is never remembered, so
// guessing can never be made cheap by guessing more.
type storageVerifyCache struct {
	mu      sync.Mutex
	entries map[string]storageVerifyEntry
	flight  singleflight.Group
	ttl     time.Duration
	max     int
	now     func() time.Time

	// derivations counts how many times the cache let a derivation run. Tests
	// assert a burst on one credential costs one, not one per request.
	derivations atomic.Int64
}

type storageVerifyEntry struct {
	expires time.Time
	// tokenID is kept so a revoke can purge by token without knowing the
	// secret. The key is a hash of the whole credential, which is what makes a
	// hit mean "this exact secret was proven" rather than "this id was proven
	// by someone", and a hash cannot be searched by its id half.
	tokenID string
}

// storageVerifyTTL is short on purpose. It is the window in which a credential
// that has been revoked, but not yet purged, would still be accepted, and
// purging on revoke is what makes that window a fallback rather than the
// guarantee.
const storageVerifyTTL = 30 * time.Second

// storageVerifyCacheMax bounds memory. Growth is bounded anyway by the number
// of distinct valid secrets someone actually holds, because a miss is never
// stored, so this is a backstop rather than the mechanism.
const storageVerifyCacheMax = 4096

func newStorageVerifyCache(now func() time.Time) *storageVerifyCache {
	if now == nil {
		now = time.Now
	}
	return &storageVerifyCache{
		entries: make(map[string]storageVerifyEntry),
		ttl:     storageVerifyTTL,
		max:     storageVerifyCacheMax,
		now:     now,
	}
}

// storageVerifyKey binds the whole presented credential, both halves.
//
// Keying on the token id alone would let one legitimate success authorize every
// later guess against that id, which is the bypass this line of work exists to
// close, moved into the cache. A hit has to mean "this exact secret was already
// proven".
func storageVerifyKey(presented string) string {
	sum := sha256.Sum256([]byte(presented))
	return hex.EncodeToString(sum[:])
}

// verified reports whether this exact credential was proven recently. A stale
// entry is deleted as it is found, which is one of the two eviction paths.
func (c *storageVerifyCache) verified(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return false
	}
	if !entry.expires.After(c.now()) {
		delete(c.entries, key)
		return false
	}
	return true
}

func (c *storageVerifyCache) remember(key, tokenID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// The other eviction path, and the one that bounds memory: a TTL decides
	// when an entry stops counting, it does not remove anything by itself, so a
	// credential used once and never presented again would sit in the map for
	// the life of the process.
	if len(c.entries) >= c.max {
		c.sweepLocked()
	}
	if len(c.entries) >= c.max {
		return
	}
	c.entries[key] = storageVerifyEntry{expires: c.now().Add(c.ttl), tokenID: tokenID}
}

func (c *storageVerifyCache) sweepLocked() {
	now := c.now()
	for key, entry := range c.entries {
		if !entry.expires.After(now) {
			delete(c.entries, key)
		}
	}
}

// sweep drops every expired entry. Called on the periodic path so a map that
// nothing looks up again still shrinks.
func (c *storageVerifyCache) sweep() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked()
}

// purgeToken forgets every credential for one token, so a revoke takes effect
// now rather than within the TTL.
func (c *storageVerifyCache) purgeToken(tokenID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		if entry.tokenID == tokenID {
			delete(c.entries, key)
		}
	}
}

func (c *storageVerifyCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// verifyOnce derives at most once for a given credential no matter how many
// callers arrive together, and returns the same answer to all of them.
//
// derive reports whether the secret is correct and whether the machine had a
// permit to spend on finding out. The cache write happens inside the shared
// callback, so a caller that joined an in-flight derivation leaves a cached
// entry behind exactly as the leader does.
func (c *storageVerifyCache) verifyOnce(key, tokenID string, derive func() (ok, permitted bool)) (ok, permitted bool) {
	if c.verified(key) {
		return true, true
	}
	type outcome struct{ ok, permitted bool }
	res, _, _ := c.flight.Do(key, func() (any, error) {
		// Re-check inside the callback: a derivation that completed while this
		// one waited for the group has already answered the question.
		if c.verified(key) {
			return outcome{true, true}, nil
		}
		c.derivations.Add(1)
		verified, allowed := derive()
		if verified && allowed {
			c.remember(key, tokenID)
		}
		return outcome{verified, allowed}, nil
	})
	out := res.(outcome)
	return out.ok, out.permitted
}
