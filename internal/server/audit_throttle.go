package server

import (
	"sync"
	"time"
)

// auditFailureThrottle bounds audit emission for repeating authentication
// failures. Failed logins and agent auth must be visible in the audit log (a
// stolen or brute-forced credential is exactly what the operator needs to
// see), but the audit store is unbounded and, in the plain-JSON deployment
// mode, every append rewrites the whole state file under a global lock. An
// unauthenticated caller must not be able to turn "record the failure" into a
// disk-growth / lock-contention DoS by rotating source addresses.
//
// Three layers, each closing a specific abuse:
//  1. Global token bucket — an absolute ceiling on emissions across ALL keys,
//     so no amount of source-address rotation can exceed a fixed write rate.
//     This is the load-bearing defense against the flood.
//  2. Per-key dedup — the first failure per key emits immediately; repeats
//     inside the window fold into suppressed_repeats rather than each writing.
//  3. Fail-closed map bound — the key map is capped and evicts the oldest
//     entry on overflow (mirroring ratelimit.Limiter) instead of failing open,
//     so a churn of fresh keys can never disable the throttle.
//
// Emissions blocked by the global bucket increment a global suppressed counter
// that rides out on the next event that does emit, so a sustained flood still
// leaves a visible "N suppressed" trail once it relents.
type auditFailureThrottle struct {
	mu     sync.Mutex
	window time.Duration

	entries map[string]*auditThrottleEntry

	// Global token bucket (deterministic clock via the now passed to Allow).
	globalBurst   float64
	globalRefill  float64 // tokens per second
	globalTokens  float64
	globalLast    time.Time
	globalDropped int
}

type auditThrottleEntry struct {
	windowStart time.Time
	suppressed  int
}

// auditThrottleMaxKeys caps tracked keys so key churn cannot grow the map
// without bound; on overflow the oldest entry is evicted (fail closed).
const auditThrottleMaxKeys = 4096

func newAuditFailureThrottle(window time.Duration, burst, refillPerSec float64) *auditFailureThrottle {
	return &auditFailureThrottle{
		window:       window,
		entries:      make(map[string]*auditThrottleEntry),
		globalBurst:  burst,
		globalRefill: refillPerSec,
		globalTokens: burst,
	}
}

// Allow reports whether an event for key may be emitted now, how many per-key
// repeats were folded since the last emission for that key, and how many
// emissions the global bucket has dropped since the last one it let through.
func (t *auditFailureThrottle) Allow(key string, now time.Time) (emit bool, suppressed int, globalDropped int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Per-key dedup: a repeat inside the window folds without spending a
	// global token, so a chatty single source never drains the shared budget.
	if entry, ok := t.entries[key]; ok && now.Sub(entry.windowStart) < t.window {
		entry.suppressed++
		return false, 0, 0
	}

	// Candidate emission: gate on the global bucket first. If the flood has
	// drained it, drop (and count the drop) without touching the map, so the
	// absolute write rate stays bounded no matter the key cardinality.
	if !t.takeGlobalTokenLocked(now) {
		t.globalDropped++
		return false, 0, 0
	}

	entry, ok := t.entries[key]
	if ok {
		suppressed = entry.suppressed
		entry.windowStart = now
		entry.suppressed = 0
	} else {
		if len(t.entries) >= auditThrottleMaxKeys {
			t.evictOldestLocked()
		}
		t.entries[key] = &auditThrottleEntry{windowStart: now}
	}
	globalDropped = t.globalDropped
	t.globalDropped = 0
	return true, suppressed, globalDropped
}

// takeGlobalTokenLocked refills by elapsed time and spends one token, returning
// false when the bucket is empty.
func (t *auditFailureThrottle) takeGlobalTokenLocked(now time.Time) bool {
	if t.globalLast.IsZero() {
		t.globalLast = now
	}
	if elapsed := now.Sub(t.globalLast).Seconds(); elapsed > 0 {
		t.globalTokens += elapsed * t.globalRefill
		if t.globalTokens > t.globalBurst {
			t.globalTokens = t.globalBurst
		}
		t.globalLast = now
	}
	if t.globalTokens < 1 {
		return false
	}
	t.globalTokens--
	return true
}

// evictOldestLocked removes the entry with the oldest window start. Called only
// when the map is at capacity, so the throttle fails closed under key churn.
func (t *auditFailureThrottle) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, entry := range t.entries {
		if first || entry.windowStart.Before(oldest) {
			oldestKey, oldest, first = k, entry.windowStart, false
		}
	}
	if !first {
		delete(t.entries, oldestKey)
	}
}
