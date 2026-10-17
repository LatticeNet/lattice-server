package server

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A panic in fn on a helper goroutine reaches the caller, where net/http's
// per-connection recover sees it, instead of ending the core process; below
// the parallel threshold it is the serial loop's panic.
func TestSubstoreBindEachPanicsOnTheCaller(t *testing.T) {
	for _, n := range []int{10, 128, 4096} {
		for _, at := range []int{0, n / 2, n - 1} {
			got := func() (v any) {
				defer func() { v = recover() }()
				substoreBindEach(n, func(i int) {
					if i == at {
						panic("plan node")
					}
				})
				return nil
			}()
			if got != "plan node" {
				t.Fatalf("n=%d, panic at %d: the caller recovered %v", n, at, got)
			}
		}
	}
}

// Every index is called once, also when other calls hold every helper token
// and the caller works alone.
func TestSubstoreBindEachCallsEveryIndexOnce(t *testing.T) {
	check := func(name string) {
		for _, n := range []int{0, 1, 127, 128, 129, 4097} {
			calls := make([]atomic.Int32, n)
			substoreBindEach(n, func(i int) { calls[i].Add(1) })
			for i := range calls {
				if c := calls[i].Load(); c != 1 {
					t.Fatalf("%s, n=%d: index %d called %d times", name, n, i, c)
				}
			}
		}
	}
	check("tokens free")
	held := 0
	for len(substoreBindHelpers) < cap(substoreBindHelpers) {
		substoreBindHelpers <- struct{}{}
		held++
	}
	defer func() {
		for ; held > 0; held-- {
			<-substoreBindHelpers
		}
	}()
	check("every token held")
}

// Concurrent calls share eight helpers between them: the most fn calls in
// flight at once is the callers plus the helper tokens, not eight per call.
func TestSubstoreBindEachBoundsHelpersAcrossCalls(t *testing.T) {
	const callers = 6
	var inFlight, most atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for c := 0; c < callers; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			substoreBindEach(512, func(int) {
				now := inFlight.Add(1)
				for {
					seen := most.Load()
					if now <= seen || most.CompareAndSwap(seen, now) {
						break
					}
				}
				time.Sleep(200 * time.Microsecond)
				inFlight.Add(-1)
			})
		}()
	}
	close(start)
	wg.Wait()
	if bound := int32(callers + cap(substoreBindHelpers)); most.Load() > bound {
		t.Fatalf("%d fn calls in flight at once across %d calls, over %d", most.Load(), callers, bound)
	}
	if len(substoreBindHelpers) != 0 {
		t.Fatalf("%d helper tokens still held after every call returned", len(substoreBindHelpers))
	}
}
