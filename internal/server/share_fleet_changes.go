package server

import (
	"github.com/LatticeNet/lattice-sdk/model"
)

// A Sub-Store record can read vpn-core: the node export for one identity, a
// composed graph of lines, or a collection with such members. Its snapshot is
// a copy of that export, so an identity created, suspended or rotated, or a
// line added or removed, changed what the record should serve while the
// snapshot kept serving the old export until it aged past the refresh
// interval and a client happened to poll, up to 30 minutes later plus the
// cache's own 30 minutes.
//
// Every committed vpn-core write now advances one generation. A plugin
// source's snapshot counts as fresh only if its last committed refresh
// started at the current generation, and every cached plugin link body is
// expired (kept, not dropped) at the change. The next fetch of a link
// therefore revalidates: it refreshes the snapshot, and when the content did
// not move it extends the body it already had (no render, since the refresh
// publishes nothing); when it moved, the refresh publishes and the link
// renders the new content.
//
// The core cannot tell which records read vpn-core, so a change makes every
// plugin source due; one that did not move costs a provider fetch and no
// render. A plugin method naming the records that depend on vpn-core would
// narrow this (logged for the Sub-Store lane).
//
// The generation lives in memory. A restart forgets a change whose sources
// were not refreshed yet, and such a snapshot is then served until its own
// refresh interval passes (at most 30 minutes after it was fetched).

// noteVPNCoreChangeForLinks advances the vpn-core generation and expires
// every cached plugin link body. It is cheap (one pass over at most the
// cache's 512 entries) and runs on every committed vpn-core write.
func (s *Server) noteVPNCoreChangeForLinks() {
	s.vpnCoreGen.Add(1)
	now := s.now()
	for _, share := range s.store.SubscriptionSharesUnordered() {
		if share.Source.Kind == model.ShareSourcePlugin {
			s.subscriptionCache.ExpireShare(share.ID, now)
		}
	}
}

// subscriptionSourceDue reports whether a source has not been refreshed since
// the last vpn-core change. Callers hold publication.mu.
func (s *Server) subscriptionSourceDue(publication *subscriptionPublicationState) bool {
	return publication.vpnGen != s.vpnCoreGen.Load()
}
