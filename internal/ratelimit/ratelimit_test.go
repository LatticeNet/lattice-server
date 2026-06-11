package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestBurstThenDeny(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(Config{Rate: 1, Burst: 3, Now: func() time.Time { return now }})
	for i := 0; i < 3; i++ {
		if !l.Allow("ip") {
			t.Fatalf("burst token %d should be allowed", i)
		}
	}
	if l.Allow("ip") {
		t.Fatal("fourth request should be denied after burst exhausted")
	}
}

func TestRefillOverTime(t *testing.T) {
	now := time.Unix(0, 0)
	clock := func() time.Time { return now }
	l := New(Config{Rate: 2, Burst: 2, Now: clock})
	if !l.Allow("ip") || !l.Allow("ip") {
		t.Fatal("initial burst should pass")
	}
	if l.Allow("ip") {
		t.Fatal("should be empty now")
	}
	now = now.Add(time.Second) // +2 tokens at rate 2/s
	if !l.Allow("ip") || !l.Allow("ip") {
		t.Fatal("tokens should have refilled after 1s")
	}
	if l.Allow("ip") {
		t.Fatal("refill is capped at burst")
	}
}

func TestPerKeyIsolation(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(Config{Rate: 1, Burst: 1, Now: func() time.Time { return now }})
	if !l.Allow("a") {
		t.Fatal("a first allowed")
	}
	if !l.Allow("b") {
		t.Fatal("b independent of a")
	}
	if l.Allow("a") {
		t.Fatal("a exhausted")
	}
}

func TestEvictionCapsKeys(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(Config{Rate: 1, Burst: 1, MaxKeys: 4, Now: func() time.Time { return now }})
	for i := 0; i < 50; i++ {
		l.Allow(string(rune('a' + i%50)))
	}
	if l.Len() > 4 {
		t.Fatalf("key set should be capped at 4, got %d", l.Len())
	}
}

func TestConcurrentAccessIsSafe(t *testing.T) {
	l := New(Config{Rate: 1000, Burst: 1000})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				l.Allow("shared")
			}
		}()
	}
	wg.Wait()
}
