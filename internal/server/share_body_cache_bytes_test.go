package server

import (
	"bytes"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func byteCacheKey(i int) subscriptionCacheKey {
	return subscriptionCacheKey{ShareID: "share-" + strconv.Itoa(i), Format: "base64", UAClass: "other"}
}

// The serve caches are bounded by what their bodies weigh, not by how many
// there are: more than 512 small bodies stay cached under the byte cap.
func TestShareBodyCachesAreSizedByBytesNotEntries(t *testing.T) {
	srv, _ := newServerForPluginHost(t)
	for name, c := range map[string]*subscriptionCache{"share": srv.subscriptionCache, "identity": srv.identityLinkCache} {
		if c.maxBytes != 64<<20 || c.entryOverhead != subscriptionCacheEntryOverhead {
			t.Fatalf("%s cache: maxBytes=%d overhead=%d, want 64 MiB and the per-entry overhead", name, c.maxBytes, c.entryOverhead)
		}
		now := time.Now()
		for i := range 600 {
			c.Put(byteCacheKey(i), []byte("vless://placeholder-"+strconv.Itoa(i)), "text/plain", "", "v", now)
		}
		if c.Len() != 600 {
			t.Fatalf("%s cache holds %d of 600 small bodies; an entry count is evicting", name, c.Len())
		}
		if _, _, _, ok := c.Get(byteCacheKey(0), now); !ok {
			t.Fatalf("%s cache evicted the first small body", name)
		}
	}
}

// Eviction is by bytes, least recently used first, and one large body can
// push out several small ones.
func TestByteSizedShareCacheEvictsByBytes(t *testing.T) {
	now := time.Now()
	body := func(n int) []byte { return bytes.Repeat([]byte("b"), n) }
	size := func(c *subscriptionCache, i, n int) int {
		key := byteCacheKey(i)
		return subscriptionCacheEntrySize(subscriptionCacheEntry{key: key, body: body(n), contentType: "text/plain", revalidationVersion: "v"}) + c.entryOverhead
	}
	probe := newSubscriptionByteCache(1, time.Minute)
	limit := size(probe, 0, 1000) * 3
	c := newSubscriptionByteCache(limit, time.Minute)

	for i := range 3 {
		c.Put(byteCacheKey(i), body(1000), "text/plain", "", "v", now)
	}
	if c.Len() != 3 || c.bytes != limit {
		t.Fatalf("three bodies at the cap: entries=%d bytes=%d cap=%d", c.Len(), c.bytes, limit)
	}
	// Touch 0, so 1 is now the least recently used.
	if _, _, _, ok := c.Get(byteCacheKey(0), now); !ok {
		t.Fatal("body 0 missing")
	}
	c.Put(byteCacheKey(3), body(1000), "text/plain", "", "v", now)
	if _, _, _, ok := c.Get(byteCacheKey(1), now); ok {
		t.Fatal("the least recently used body survived an insert past the byte cap")
	}
	for _, i := range []int{0, 2, 3} {
		if _, _, _, ok := c.Get(byteCacheKey(i), now); !ok {
			t.Fatalf("body %d was evicted although the cap had room after one eviction", i)
		}
	}
	// One body as large as two small ones evicts the two oldest.
	big := 2*size(c, 4, 1000) - size(c, 4, 0)
	c.Put(byteCacheKey(4), body(big), "text/plain", "", "v", now)
	if c.bytes > limit {
		t.Fatalf("cache holds %d bytes over its %d cap", c.bytes, limit)
	}
	if c.Len() != 2 {
		t.Fatalf("after a double-size body the cache holds %d entries, want 2", c.Len())
	}
	if _, _, _, ok := c.Get(byteCacheKey(4), now); !ok {
		t.Fatal("the large body was not cached")
	}
	// A body larger than the whole cap is not cached and evicts nothing.
	before := c.Len()
	c.Put(byteCacheKey(5), body(limit), "text/plain", "", "v", now)
	if c.Len() != before {
		t.Fatalf("an oversized body changed the cache from %d to %d entries", before, c.Len())
	}
}

// The render variant is part of the key the cache stores, so its bytes count
// toward the cap like the other key fields.
func TestShareCacheEntrySizeCountsTheVariant(t *testing.T) {
	plain := subscriptionCacheEntry{key: byteCacheKey(1), body: []byte("body")}
	variant := plain
	variant.key.Variant = "target=" + strings.Repeat("v", 300)
	if got, want := subscriptionCacheEntrySize(variant)-subscriptionCacheEntrySize(plain), len(variant.key.Variant); got != want {
		t.Fatalf("a %d-byte variant adds %d bytes to the entry size", want, got)
	}
}

// The byte count stays exact under concurrent use: after Put, Get,
// ExtendSnapshot, InvalidateShare and ExpireShare race each other, the
// accounted bytes equal the sum of the live entries' sizes and stay within
// the cap. Run with -race.
func TestByteSizedShareCacheAccountsExactlyUnderConcurrency(t *testing.T) {
	probe := newSubscriptionByteCache(1, time.Minute)
	limit := 40 * (subscriptionCacheEntrySize(subscriptionCacheEntry{key: byteCacheKey(0), body: make([]byte, 600)}) + probe.entryOverhead)
	c := newSubscriptionByteCache(limit, time.Minute)
	now := time.Now()
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 400 {
				n := (w*31 + i*7) % 64
				key := byteCacheKey(n)
				if i%3 == 0 {
					key.Variant = "target=" + strings.Repeat("x", n)
				}
				switch i % 6 {
				case 0, 1:
					c.PutSnapshot(key, bytes.Repeat([]byte("b"), 100+n*10), "text/plain", strings.Repeat("u", n), "v", "", false, time.Time{}, now)
				case 2:
					c.GetSnapshot(key, now)
				case 3:
					if entry, ok := c.GetStale(key); ok {
						c.ExtendSnapshot(key, entry.revision, strings.Repeat("u", (n*3)%200), "pv", i%2 == 0, now, now)
					}
				case 4:
					c.InvalidateShare(key.ShareID)
				case 5:
					c.ExpireShare(key.ShareID, now)
				}
			}
		}()
	}
	wg.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	sum := 0
	for el := c.order.Front(); el != nil; el = el.Next() {
		entry := el.Value.(*subscriptionCacheEntry)
		if entry.size != subscriptionCacheEntrySize(*entry)+c.entryOverhead {
			t.Fatalf("entry %+v carries size %d, want %d", entry.key, entry.size, subscriptionCacheEntrySize(*entry)+c.entryOverhead)
		}
		sum += entry.size
	}
	if c.bytes != sum || c.bytes > c.maxBytes || len(c.entries) != c.order.Len() {
		t.Fatalf("bytes=%d sum=%d cap=%d index=%d list=%d", c.bytes, sum, c.maxBytes, len(c.entries), c.order.Len())
	}
}
