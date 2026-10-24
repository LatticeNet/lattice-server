package server

import (
	"bytes"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
)

// testClock is a server clock a test moves while the server runs. New
// starts background loops (the terminal reaper reads the clock every five
// seconds), so a test never assigns the server's clock after New: the clock
// goes in through Options.Now and moves through set, advance and runAhead,
// which hold its lock. A clock from newWallClock reads the wall clock, in
// UTC as the server's own does, until a test stops it.
type testClock struct {
	mu   sync.Mutex
	at   time.Time
	wall bool
	skew time.Duration
	// panicMsg, while set, is what a read on goroutine panicG panics with.
	panicMsg string
	panicG   uint64
}

func newWallClock() *testClock { return &testClock{wall: true} }

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.panicMsg != "" && goroutineID() == c.panicG {
		panic(c.panicMsg)
	}
	if c.wall {
		return time.Now().UTC().Add(c.skew)
	}
	return c.at
}

// set stops the clock at at, and ends panicHere.
func (c *testClock) set(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall, c.at = false, at
	c.panicMsg = ""
}

// panicHere makes a read of the clock on the calling goroutine panic with
// msg until set is called, so a test can make a server call panic where it
// reads the clock. Every other goroutine, the server's loops among them,
// reads the clock stopped where it was.
func (c *testClock) panicHere(msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.wall {
		c.wall, c.at = false, time.Now().UTC().Add(c.skew)
	}
	c.panicMsg, c.panicG = msg, goroutineID()
}

// goroutineID is the calling goroutine's id, read from the first line of
// its stack ("goroutine 7 [running]:").
func goroutineID() uint64 {
	var buf [64]byte
	line := bytes.TrimPrefix(buf[:runtime.Stack(buf[:], false)], []byte("goroutine "))
	id, _ := strconv.ParseUint(string(line[:bytes.IndexByte(line, ' ')]), 10, 64)
	return id
}

// advance moves the clock d forward; a running clock keeps running.
func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.wall {
		c.skew += d
	} else {
		c.at = c.at.Add(d)
	}
}

// runAhead lets the clock follow the wall clock again, d ahead of it.
func (c *testClock) runAhead(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall, c.skew = true, d
}

// serverClocks holds the clock newClockedServer gave each server.
var serverClocks sync.Map

// newClockedServer is New for tests. Unless opts names a clock, the server
// runs on a wall clock that serverClock hands to the test to stop or move.
func newClockedServer(t testing.TB, opts Options) (*Server, error) {
	t.Helper()
	var clock *testClock
	if opts.Now == nil {
		clock = newWallClock()
		opts.Now = clock.now
	}
	srv, err := New(opts)
	if err != nil || clock == nil {
		return srv, err
	}
	serverClocks.Store(srv, clock)
	t.Cleanup(func() { serverClocks.Delete(srv) })
	return srv, nil
}

// serverClock is the clock newClockedServer gave srv.
func serverClock(t testing.TB, srv *Server) *testClock {
	t.Helper()
	clock, ok := serverClocks.Load(srv)
	if !ok {
		t.Fatal("this server was not built by newClockedServer, so its clock cannot be moved safely")
	}
	return clock.(*testClock)
}
