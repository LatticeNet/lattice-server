package server

import (
	"container/list"
	"sync"
	"time"
)

// subscriptionCacheKey identifies one rendered body. Format and UAClass are part
// of the key because they change the bytes: two clients asking for different
// formats must not be served each other's output.
type subscriptionCacheKey struct {
	ShareID string
	Format  string
	UAClass string
}

type subscriptionCacheEntry struct {
	key         subscriptionCacheKey
	body        []byte
	contentType string
	expiresAt   time.Time
}

// subscriptionCache keeps rendered subscription bodies for a short time so a
// client poll does not boot a JavaScript VM and parse a 1.24 MB engine every
// time.
//
// It is bounded in entries rather than bytes because classifyClientUA already
// bounds how many entries one share can produce; an unbounded map keyed on
// caller-supplied data would be a memory amplifier.
type subscriptionCache struct {
	mu      sync.Mutex
	max     int
	ttl     time.Duration
	entries map[subscriptionCacheKey]*list.Element
	order   *list.List
}

func newSubscriptionCache(max int, ttl time.Duration) *subscriptionCache {
	if max <= 0 {
		max = 1
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	return &subscriptionCache{
		max:     max,
		ttl:     ttl,
		entries: map[subscriptionCacheKey]*list.Element{},
		order:   list.New(),
	}
}

func (c *subscriptionCache) Get(key subscriptionCacheKey, now time.Time) ([]byte, string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[key]
	if !ok {
		return nil, "", false
	}
	entry := el.Value.(*subscriptionCacheEntry)
	if !now.Before(entry.expiresAt) {
		c.removeElement(el)
		return nil, "", false
	}
	c.order.MoveToFront(el)
	return entry.body, entry.contentType, true
}

// Put ignores an empty body. The endpoint refuses to serve one, so letting it
// into the cache would create a path back to the exact response that makes a
// client delete every node it had.
func (c *subscriptionCache) Put(key subscriptionCacheKey, body []byte, contentType string, now time.Time) {
	if len(body) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[key]; ok {
		c.removeElement(el)
	}
	el := c.order.PushFront(&subscriptionCacheEntry{
		key:         key,
		body:        body,
		contentType: contentType,
		expiresAt:   now.Add(c.ttl),
	})
	c.entries[key] = el
	for c.order.Len() > c.max {
		if oldest := c.order.Back(); oldest != nil {
			c.removeElement(oldest)
			continue
		}
		break
	}
}

// InvalidateShare drops every cached body for one share, across all formats and
// client classes. Rotation and deletion call it: without it, a rotated-away URL
// would keep being served from cache until its TTL expired, which is precisely
// the window rotation exists to close.
func (c *subscriptionCache) InvalidateShare(shareID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, el := range c.entries {
		if key.ShareID == shareID {
			c.removeElement(el)
		}
	}
}

func (c *subscriptionCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// removeElement drops one element from both the list and the index. Callers hold
// the mutex.
func (c *subscriptionCache) removeElement(el *list.Element) {
	c.order.Remove(el)
	delete(c.entries, el.Value.(*subscriptionCacheEntry).key)
}
