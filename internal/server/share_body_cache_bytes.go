package server

import (
	"math"
	"time"
)

// subscriptionCacheEntryOverhead is what one cached body costs beyond the
// bytes subscriptionCacheEntrySize counts: the entry struct (about 300 bytes
// of headers, hashes and times), its list element and its index slot. A
// byte-sized cache charges it per entry so many small bodies cannot hold more
// memory than the cap says.
const subscriptionCacheEntryOverhead = 512

// newSubscriptionByteCache returns a body cache bounded by bytes and nothing
// else (design 28). The two serve caches held 512 entries each, which bounds
// neither memory nor reach: 512 one-kilobyte placeholder documents and 512
// four-megabyte sing-box documents were the same budget. Sized by bytes, the
// cache holds as many bodies as fit, and evicts the least recently used ones
// when a new body would pass the cap.
func newSubscriptionByteCache(maxBytes int, ttl time.Duration) *subscriptionCache {
	c := newSubscriptionCache(math.MaxInt, ttl)
	if maxBytes > 0 {
		c.maxBytes = maxBytes
	}
	c.entryOverhead = subscriptionCacheEntryOverhead
	return c
}
