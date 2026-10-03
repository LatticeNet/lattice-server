package server

import (
	"compress/gzip"
	"context"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// shareRenderTimeout bounds one shared render: a snapshot refresh (itself
// bounded by subscriptionRefreshTimeout), up to two plugin renders under the
// method's declared budget, and the cache publication. The render runs off
// the requester's context so a client that hangs up does not fail the other
// clients waiting on the same render.
const shareRenderTimeout = 2 * time.Minute

// The per-link render budget a miss spends is in share_render_budget.go.

// shareRenderOutcome is what one render produced: either an entry to serve,
// or the refusal reason every waiter answers with the decoy.
type shareRenderOutcome struct {
	entry subscriptionCacheEntry
	deny  string
}

type shareRenderFlight struct {
	done    chan struct{}
	outcome shareRenderOutcome
}

// renderShareShared renders one cache key at most once at a time. Before it,
// eight cold requests for one key ran eight plugin renders of identical
// bytes, each holding a worker of a pool that has two. Requests that arrive
// while a render for their key is running wait for it and serve its result;
// the key already holds everything that changes the bytes (share, envelope,
// UA class, variant), so every waiter would have rendered the same thing.
//
// A waiter whose own request ends stops waiting; the render carries on for
// the others and still publishes into the cache.
func (s *Server) renderShareShared(ctx context.Context, share model.SubscriptionShare, plan shareRenderPlan, key subscriptionCacheKey) shareRenderOutcome {
	// The content version the source holds now decides whether a known
	// variant re-renders for free; read it before taking the flight lock.
	version := ""
	if snapshot, ok := s.store.SubscriptionSnapshot(share.Source.PluginID, share.Source.SubscriptionID); ok {
		version = subscriptionRevalidationVersion(snapshot)
	}
	s.shareRenderMu.Lock()
	if s.shareRenderFlights == nil {
		s.shareRenderFlights = make(map[subscriptionCacheKey]*shareRenderFlight)
	}
	flight := s.shareRenderFlights[key]
	if flight == nil {
		ticket, ok, announce, refused := s.shareRenderBudget.take(share.ID, shareRenderVariantKey(key), version)
		if !ok {
			s.shareRenderMu.Unlock()
			if announce {
				s.announceShareRenderBudgetExhausted(share, refused)
			}
			return shareRenderOutcome{deny: "subscription_render_budget_exhausted"}
		}
		flight = &shareRenderFlight{done: make(chan struct{})}
		s.shareRenderFlights[key] = flight
		go func() {
			renderCtx, cancel := context.WithTimeout(context.Background(), shareRenderTimeout)
			defer cancel()
			outcome := s.renderShareOnce(renderCtx, share, plan, key)
			s.shareRenderBudget.settle(ticket, outcome.entry.revalidationVersion, outcome.deny != "")
			s.shareRenderMu.Lock()
			flight.outcome = outcome
			delete(s.shareRenderFlights, key)
			close(flight.done)
			s.shareRenderMu.Unlock()
		}()
	} else if waiter := s.shareRenderJoinWaiter; waiter != nil {
		select {
		case waiter <- struct{}{}:
		default:
		}
	}
	s.shareRenderMu.Unlock()
	select {
	case <-flight.done:
		return flight.outcome
	case <-ctx.Done():
		return shareRenderOutcome{deny: "subscription_request_ended"}
	}
}

// renderShareOnce renders a body and, for a plugin source, publishes it into
// the cache under the epoch it was rendered from.
//
// Plugin rendering races durable source transitions. A rejected epoch is not
// merely a cache miss: its body was rendered from superseded authority and
// therefore must not escape in the current response either. Re-capture and
// render once more; sustained churn fails closed instead of serving a body
// whose source transition already committed.
func (s *Server) renderShareOnce(ctx context.Context, share model.SubscriptionShare, plan shareRenderPlan, key subscriptionCacheKey) shareRenderOutcome {
	attempts := 1
	if share.Source.Kind == model.ShareSourcePlugin {
		attempts = 2
	}
	for attempt := 0; attempt < attempts; attempt++ {
		rendered, err := s.renderShare(ctx, share, plan.Format, plan.UAClass, plan.Variant)
		if err != nil {
			s.logger.Printf("subscription share: render failed for share %s (%s)", share.ID, subscriptionDiagnosticSummary(err))
			return shareRenderOutcome{deny: "subscription_render_failed"}
		}
		// A client that receives an empty but successful subscription deletes
		// every node it had. Answering with the decoy keeps that from happening
		// AND keeps the emptiness from confirming that the token was real.
		if len(rendered.Body) == 0 {
			return shareRenderOutcome{deny: "empty render refused"}
		}
		// A plugin body is cached and served many times, so it is compressed
		// once here; a core body is served once and compressed per request.
		served := newShareBody(rendered.Body, share.Source.Kind == model.ShareSourcePlugin, gzip.BestCompression)
		entry := subscriptionCacheEntry{body: rendered.Body, contentType: rendered.ContentType, userinfo: rendered.Userinfo,
			revalidationVersion: rendered.RevalidationVersion, publicSourceVersion: rendered.SourceVersion,
			stale: rendered.Stale, fetchedAt: rendered.FetchedAt,
			wireType: shareWireContentType(plan, reportedRenderTarget(rendered.Target)),
			bodyHash: served.hash, gzipBody: served.gzipBody}
		if share.Source.Kind == model.ShareSourcePlugin &&
			!s.putSubscriptionCacheForSource(key, share.Source.PluginID, share.Source.SubscriptionID, rendered.SourceEpoch, entry, s.now()) {
			continue
		}
		return shareRenderOutcome{entry: entry}
	}
	return shareRenderOutcome{deny: "subscription_source_changed"}
}
