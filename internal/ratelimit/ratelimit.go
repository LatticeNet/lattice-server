// Package ratelimit provides a small, dependency-free per-key token-bucket
// rate limiter suitable for guarding authentication and agent endpoints.
//
// Buckets are keyed by an arbitrary string (typically a client IP). Each bucket
// refills lazily based on elapsed wall-clock time, so there is no background
// goroutine on the hot path. Idle buckets are evicted opportunistically to keep
// memory bounded under a churning set of source addresses.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a concurrency-safe collection of per-key token buckets.
type Limiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64 // tokens added per second
	burst    float64 // maximum tokens a bucket may hold
	ttl      time.Duration
	maxKeys  int
	now      func() time.Time
	lastSwic time.Time
}

type bucket struct {
	tokens   float64
	lastFill time.Time
	lastSeen time.Time
}

// Config controls a Limiter. Rate and Burst must both be positive.
type Config struct {
	// Rate is the sustained number of allowed events per second.
	Rate float64
	// Burst is the maximum number of events allowed in an instantaneous spike.
	Burst float64
	// TTL evicts buckets that have not been touched for this long. Defaults to
	// 10 minutes when zero.
	TTL time.Duration
	// MaxKeys caps the number of tracked buckets to bound memory. Defaults to
	// 100000 when zero. When exceeded, the limiter sheds the oldest buckets.
	MaxKeys int
	// Now is an injectable clock for tests. Defaults to time.Now.
	Now func() time.Time
}

// New builds a Limiter from cfg, applying defaults for zero-valued fields.
func New(cfg Config) *Limiter {
	if cfg.Rate <= 0 {
		cfg.Rate = 1
	}
	if cfg.Burst <= 0 {
		cfg.Burst = cfg.Rate
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 10 * time.Minute
	}
	if cfg.MaxKeys <= 0 {
		cfg.MaxKeys = 100_000
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Limiter{
		buckets:  make(map[string]*bucket),
		rate:     cfg.Rate,
		burst:    cfg.Burst,
		ttl:      cfg.TTL,
		maxKeys:  cfg.MaxKeys,
		now:      cfg.Now,
		lastSwic: cfg.Now(),
	}
}

// Allow reports whether an event for key may proceed, consuming one token when
// it returns true.
func (l *Limiter) Allow(key string) bool {
	return l.AllowN(key, 1)
}

// AllowN reports whether n events for key may proceed, consuming n tokens when
// it returns true. A request larger than the burst can never succeed.
func (l *Limiter) AllowN(key string, n float64) bool {
	if n <= 0 {
		return true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweepLocked(now)

	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			l.evictOldestLocked()
		}
		b = &bucket{tokens: l.burst, lastFill: now}
		l.buckets[key] = b
	}

	elapsed := now.Sub(b.lastFill).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.lastFill = now
	}
	b.lastSeen = now

	if b.tokens >= n {
		b.tokens -= n
		return true
	}
	return false
}

// Len returns the number of currently tracked buckets. Primarily for tests.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// sweepLocked evicts expired buckets at most once per TTL window to keep the
// amortized cost of Allow near O(1).
func (l *Limiter) sweepLocked(now time.Time) {
	if now.Sub(l.lastSwic) < l.ttl {
		return
	}
	l.lastSwic = now
	for k, b := range l.buckets {
		if now.Sub(b.lastSeen) > l.ttl {
			delete(l.buckets, k)
		}
	}
}

// evictOldestLocked removes the least-recently-seen bucket. Called only when the
// key cap is hit, which should be rare under normal traffic.
func (l *Limiter) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, b := range l.buckets {
		if first || b.lastSeen.Before(oldest) {
			oldestKey = k
			oldest = b.lastSeen
			first = false
		}
	}
	if !first {
		delete(l.buckets, oldestKey)
	}
}
