package server

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-server/internal/auth"
)

const (
	agentAuthCacheTTL        = 10 * time.Second
	agentAuthCacheMaxEntries = 4096
)

var agentNodeSecretCache = &agentAuthCache{entries: map[agentAuthCacheKey]agentAuthCacheEntry{}}

type agentAuthCacheKey struct {
	NodeID           string
	SourceIP         string
	TokenHash        string
	TokenFingerprint string
}

type agentAuthCacheEntry struct {
	ExpiresAt time.Time
}

type agentAuthCache struct {
	mu      sync.Mutex
	entries map[agentAuthCacheKey]agentAuthCacheEntry
}

func verifyAgentNodeSecret(nodeID, sourceIP, tokenHash, token string, now time.Time) bool {
	return agentNodeSecretCache.verify(nodeID, sourceIP, tokenHash, token, now)
}

func (c *agentAuthCache) verify(nodeID, sourceIP, tokenHash, token string, now time.Time) bool {
	if nodeID == "" || tokenHash == "" || token == "" {
		return false
	}
	now = now.UTC()
	key := agentAuthCacheKey{
		NodeID:           nodeID,
		SourceIP:         sourceIP,
		TokenHash:        tokenHash,
		TokenFingerprint: agentTokenFingerprint(token),
	}

	c.mu.Lock()
	if entry, ok := c.entries[key]; ok {
		if now.Before(entry.ExpiresAt) {
			c.mu.Unlock()
			return true
		}
		delete(c.entries, key)
	}
	c.mu.Unlock()

	if !auth.VerifySecret(tokenHash, token) {
		return false
	}

	c.mu.Lock()
	if len(c.entries) >= agentAuthCacheMaxEntries {
		c.pruneExpiredLocked(now)
	}
	if len(c.entries) >= agentAuthCacheMaxEntries {
		c.entries = map[agentAuthCacheKey]agentAuthCacheEntry{}
	}
	c.entries[key] = agentAuthCacheEntry{ExpiresAt: now.Add(agentAuthCacheTTL)}
	c.mu.Unlock()
	return true
}

func (c *agentAuthCache) pruneExpiredLocked(now time.Time) {
	for key, entry := range c.entries {
		if !now.Before(entry.ExpiresAt) {
			delete(c.entries, key)
		}
	}
}

func agentTokenFingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
