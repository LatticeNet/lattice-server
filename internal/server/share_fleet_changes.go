package server

import (
	"sync"
	"sync/atomic"
	"time"
)

// A Sub-Store record can read vpn-core: the node export for one identity, a
// composed graph of lines, or a collection with such members. Its snapshot is
// a copy of that export, so an identity created, suspended or rotated, or a
// line added or removed, changed what the record should serve while the
// snapshot kept serving the old export until it aged past the refresh
// interval and a client happened to poll, up to 30 minutes later plus the
// cache's own 30 minutes.
//
// A committed vpn-core write now advances one generation. A plugin source's
// snapshot counts as fresh only if its last committed refresh started at the
// current generation, and every cached plugin link body is expired (kept,
// not dropped) when the generation advances. The next fetch of a link
// therefore revalidates: it refreshes the snapshot, and when the content did
// not move it extends the body it already had (no render, since the refresh
// publishes nothing); when it moved, the refresh publishes and the link
// renders the new content.
//
// Without more, the core cannot tell which records read vpn-core, so an
// advance makes every plugin source due; one that did not move costs a
// provider fetch and no render. A plugin that declares depends_on names the
// records that read the fleet, and an advance then expires and makes due only
// those (share_fleet_depends.go).
//
// Writes arrive in bursts (a bulk identity import, a quota sweep suspending
// many identities, an operator editing several lines), and advancing once per
// write cost each polled source one provider fetch per write. The generation
// therefore advances at most once per vpnCoreLinkChangeInterval: a write
// after a quiet interval advances it at once, so a single suspension still
// reaches links on the next poll; a write inside the interval is held and
// applied by the first link fetch after the interval ends. A burst costs each
// source at most two refreshes, and a long run of writes at most one per
// interval. The interval matches subscriptionStaleRetryInterval, the bound a
// failing source already retries at.
//
// The generation lives in memory. A restart forgets a change whose sources
// were not refreshed yet, and such a snapshot is then served until its own
// refresh interval passes (at most 30 minutes after it was fetched).
const vpnCoreLinkChangeInterval = subscriptionStaleRetryInterval

// vpnCoreLinkChanges paces generation advances. pending is read without the
// lock on every plugin link fetch, so the common case (nothing held back)
// costs one atomic load.
type vpnCoreLinkChanges struct {
	mu      sync.Mutex
	last    time.Time // when the generation last advanced
	pending atomic.Bool
}

// noteVPNCoreChangeForLinks runs on every committed vpn-core write. It
// advances the generation now, or holds the change for the end of the
// interval when the generation advanced less than an interval ago.
func (s *Server) noteVPNCoreChangeForLinks() {
	now := s.now()
	c := &s.vpnCoreLinks
	c.mu.Lock()
	if !c.last.IsZero() && now.Sub(c.last) < vpnCoreLinkChangeInterval {
		c.pending.Store(true)
		c.mu.Unlock()
		return
	}
	c.last = now
	c.pending.Store(false)
	c.mu.Unlock()
	s.advanceVPNCoreGeneration(now)
}

// settleVPNCoreChanges applies a held change once its interval has ended.
// Link fetches and source refreshes call it before they read the generation.
func (s *Server) settleVPNCoreChanges() {
	c := &s.vpnCoreLinks
	if !c.pending.Load() {
		return
	}
	now := s.now()
	c.mu.Lock()
	if !c.pending.Load() || now.Sub(c.last) < vpnCoreLinkChangeInterval {
		c.mu.Unlock()
		return
	}
	c.last = now
	c.pending.Store(false)
	c.mu.Unlock()
	s.advanceVPNCoreGeneration(now)
}

// advanceVPNCoreGeneration advances the vpn-core generation and expires the
// cached plugin link bodies the change may have moved: only the dependent
// records' shares for a plugin that answers depends_on, every share of any
// other plugin (share_fleet_depends.go). It is cheap (one pass over the
// shares and at most the cache's 512 entries) and runs at most once per
// interval.
func (s *Server) advanceVPNCoreGeneration(now time.Time) {
	s.expirePluginSharesForFleetChange(s.vpnCoreGen.Add(1), now)
}

// subscriptionSourceDue reports whether a source has not been refreshed since
// the last vpn-core change. Callers hold publication.mu.
func (s *Server) subscriptionSourceDue(publication *subscriptionPublicationState) bool {
	return publication.vpnGen != s.vpnCoreGen.Load()
}
