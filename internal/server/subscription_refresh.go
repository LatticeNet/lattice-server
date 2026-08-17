package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// subscriptionRefreshInterval is how old a snapshot may be before a render tries
// to replace it.
//
// Refresh is lazy - it happens on access - rather than driven by a scheduler.
// A plugin is fork-per-call and cannot schedule itself, so a scheduler would
// have to be a new core mechanism; and clients already poll on their own
// schedule, so laziness produces the same freshness for the requests that
// actually exist. Upstream Sub-Store syncs on a timer; this deliberately does
// not, and nothing depends on the difference except the moment a fetch happens.
const subscriptionRefreshInterval = 30 * time.Minute

// subscriptionStaleRetryInterval prevents a provider outage from turning
// sequential client polls into one completed runtime invocation each. Force
// bypasses it for explicit operator refresh; normal traffic retries promptly
// enough to observe recovery without waiting for the freshness interval.
const subscriptionStaleRetryInterval = 30 * time.Second
const subscriptionRefreshTimeout = 30 * time.Second

const auditActionSubscriptionFetch = "subscription.source.fetch"

type subscriptionRefreshFlight struct {
	done     chan struct{}
	force    bool
	snapshot model.SubscriptionSnapshot
	err      error
}

type subscriptionPublicationState struct {
	mu    sync.Mutex
	epoch uint64
}

// subscriptionPluginMutationState brackets subscription-store mutations with
// every provider fetch for the same plugin. A fetch runs without holding this
// mutex, but must re-acquire it and prove the generation is unchanged before it
// may publish. Mutation handlers hold it across the plugin operation, so a
// fetch cannot publish in the post-mutation/pre-invalidation scheduling gap.
type subscriptionPluginMutationState struct {
	gate       chan struct{}
	mu         sync.Mutex
	generation uint64
}

type subscriptionRefreshKey struct {
	pluginID       string
	subscriptionID string
}

type subscriptionRefreshAuthority struct {
	existing         model.SubscriptionSnapshot
	has              bool
	fresh            bool
	recentStale      bool
	sourceEpoch      uint64
	pluginGeneration uint64
}

func subscriptionRevalidationVersion(snapshot model.SubscriptionSnapshot) string {
	if snapshot.SourceVersion != "" {
		return snapshot.SourceVersion
	}
	return subscriptionContentHash(snapshot.Raw)
}

func (s *Server) persistSubscriptionSnapshot(snapshot model.SubscriptionSnapshot) (bool, error) {
	if s.subscriptionSnapshotPersist != nil {
		return s.subscriptionSnapshotPersist(snapshot)
	}
	return s.store.UpsertSubscriptionSnapshotWithCommit(snapshot)
}

func (s *Server) subscriptionPublicationStateFor(key subscriptionRefreshKey) *subscriptionPublicationState {
	s.subscriptionRefreshMu.Lock()
	defer s.subscriptionRefreshMu.Unlock()
	if s.subscriptionPublicationStates == nil {
		s.subscriptionPublicationStates = make(map[subscriptionRefreshKey]*subscriptionPublicationState)
	}
	state := s.subscriptionPublicationStates[key]
	if state == nil {
		state = &subscriptionPublicationState{}
		s.subscriptionPublicationStates[key] = state
	}
	return state
}

func (s *Server) subscriptionPluginMutationStateFor(pluginID string) *subscriptionPluginMutationState {
	s.subscriptionRefreshMu.Lock()
	defer s.subscriptionRefreshMu.Unlock()
	if s.subscriptionPluginMutations == nil {
		s.subscriptionPluginMutations = make(map[string]*subscriptionPluginMutationState)
	}
	state := s.subscriptionPluginMutations[pluginID]
	if state == nil {
		state = &subscriptionPluginMutationState{gate: make(chan struct{}, 1)}
		state.gate <- struct{}{}
		s.subscriptionPluginMutations[pluginID] = state
	}
	return state
}

func (s *Server) acquireSubscriptionPluginGate(ctx context.Context, pluginID string) (*subscriptionPluginMutationState, func(), error) {
	state := s.subscriptionPluginMutationStateFor(pluginID)
	if waiter := s.subscriptionPluginGateWaiter; waiter != nil {
		select {
		case waiter <- struct{}{}:
		default:
		}
	}
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-state.gate:
	}
	if err := ctx.Err(); err != nil {
		state.gate <- struct{}{}
		return nil, nil, err
	}
	return state, func() { state.gate <- struct{}{} }, nil
}

func (s *Server) captureSubscriptionRefreshAuthority(ctx context.Context, pluginID, subscriptionID string, force bool) (authority subscriptionRefreshAuthority, err error) {
	pluginMutation, releasePlugin, err := s.acquireSubscriptionPluginGate(ctx, pluginID)
	if err != nil {
		return authority, err
	}
	// Install the release before clocks, stores, assertions, or test seams can
	// panic. No panic may consume the keyed gate token permanently.
	defer releasePlugin()
	pluginMutation.mu.Lock()
	authority.pluginGeneration = pluginMutation.generation
	pluginMutation.mu.Unlock()
	publication := s.subscriptionPublicationStateFor(subscriptionRefreshKey{pluginID: pluginID, subscriptionID: subscriptionID})
	publication.mu.Lock()
	authority.existing, authority.has = s.store.SubscriptionSnapshot(pluginID, subscriptionID)
	authority.sourceEpoch = publication.epoch
	publication.mu.Unlock()
	now := s.now()
	authority.fresh = authority.has && !authority.existing.Stale && !force && now.Sub(authority.existing.FetchedAt) < subscriptionRefreshInterval
	authority.recentStale = authority.has && authority.existing.Stale && !force && !authority.existing.LastAttemptAt.IsZero() && now.Sub(authority.existing.LastAttemptAt) < subscriptionStaleRetryInterval
	return authority, nil
}

// snapshotFor returns the content to render, refreshing it first when it is
// missing or stale.
//
// The failure behaviour is the reason this function exists: when a refresh
// fails and a snapshot is available, the snapshot is served and the failure is
// recorded on it. A provider being down must not take a client's configuration
// with it - that is the behaviour upstream implements as ignore-failed-remote-sub.
func (s *Server) snapshotFor(ctx context.Context, pluginID, subscriptionID string, force bool) (model.SubscriptionSnapshot, error) {
	for {
		snapshot, joinedNonForce, err := s.snapshotForGeneration(ctx, pluginID, subscriptionID, force)
		if !joinedNonForce {
			return snapshot, err
		}
		// A force request that joined a normal in-flight refresh still owns an
		// explicit forced generation after that flight completes, even when the
		// shared normal generation failed.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return model.SubscriptionSnapshot{}, ctxErr
		}
	}
}

func (s *Server) snapshotForGeneration(ctx context.Context, pluginID, subscriptionID string, force bool) (model.SubscriptionSnapshot, bool, error) {
	key := subscriptionRefreshKey{pluginID: pluginID, subscriptionID: subscriptionID}
	authority, err := s.captureSubscriptionRefreshAuthority(ctx, pluginID, subscriptionID, force)
	if err != nil {
		return model.SubscriptionSnapshot{}, false, err
	}
	if authority.fresh {
		return authority.existing, false, nil
	}
	if authority.recentStale {
		return authority.existing, false, nil
	}
	if err := ctx.Err(); err != nil {
		return model.SubscriptionSnapshot{}, false, err
	}
	s.subscriptionRefreshMu.Lock()
	if s.subscriptionRefreshFlights == nil {
		s.subscriptionRefreshFlights = make(map[subscriptionRefreshKey]*subscriptionRefreshFlight)
	}
	if flight := s.subscriptionRefreshFlights[key]; flight != nil {
		joinedNonForce := force && !flight.force
		waiter := s.subscriptionRefreshWaiter
		s.subscriptionRefreshMu.Unlock()
		if waiter != nil {
			select {
			case waiter <- struct{}{}:
			default:
			}
		}
		select {
		case <-flight.done:
			return flight.snapshot.Clone(), joinedNonForce, flight.err
		case <-ctx.Done():
			return model.SubscriptionSnapshot{}, false, ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		s.subscriptionRefreshMu.Unlock()
		return model.SubscriptionSnapshot{}, false, err
	}
	flight := &subscriptionRefreshFlight{done: make(chan struct{}), force: force}
	s.subscriptionRefreshFlights[key] = flight
	s.subscriptionRefreshMu.Unlock()
	go func() {
		refreshCtx, cancel := context.WithTimeout(context.Background(), subscriptionRefreshTimeout)
		defer cancel()
		flight.snapshot, flight.err = s.refreshSubscriptionSnapshot(refreshCtx, pluginID, subscriptionID, force)
		s.subscriptionRefreshMu.Lock()
		delete(s.subscriptionRefreshFlights, key)
		close(flight.done)
		s.subscriptionRefreshMu.Unlock()
	}()
	select {
	case <-flight.done:
		return flight.snapshot.Clone(), false, flight.err
	case <-ctx.Done():
		return model.SubscriptionSnapshot{}, false, ctx.Err()
	}
}

func (s *Server) refreshSubscriptionSnapshot(ctx context.Context, pluginID, subscriptionID string, force bool) (model.SubscriptionSnapshot, error) {
	key := subscriptionRefreshKey{pluginID: pluginID, subscriptionID: subscriptionID}
	publication := s.subscriptionPublicationStateFor(key)
	authority, err := s.captureSubscriptionRefreshAuthority(ctx, pluginID, subscriptionID, force)
	if err != nil {
		return model.SubscriptionSnapshot{}, err
	}
	existing, has := authority.existing, authority.has
	if authority.fresh {
		return existing, nil
	}
	if authority.recentStale {
		return existing, nil
	}
	pluginGeneration, fetchEpoch := authority.pluginGeneration, authority.sourceEpoch
	fetch := s.fetchSubscriptionSource
	if s.subscriptionFetch != nil {
		fetch = s.subscriptionFetch
	}
	fetched, err := fetch(ctx, pluginID, subscriptionID)
	pluginMutation, releasePlugin, gateErr := s.acquireSubscriptionPluginGate(ctx, pluginID)
	if gateErr != nil {
		return model.SubscriptionSnapshot{}, gateErr
	}
	defer releasePlugin()
	pluginMutation.mu.Lock()
	currentPluginGeneration := pluginMutation.generation
	pluginMutation.mu.Unlock()
	if currentPluginGeneration != pluginGeneration {
		return model.SubscriptionSnapshot{}, errors.New("subscription plugin changed during refresh")
	}
	publication.mu.Lock()
	defer publication.mu.Unlock()
	if publication.epoch != fetchEpoch {
		return model.SubscriptionSnapshot{}, errors.New("subscription source changed during refresh")
	}
	// Provider work runs without the publication lock so unrelated operations on
	// this source can proceed. Re-read authority before applying the outcome.
	existing, has = s.store.SubscriptionSnapshot(pluginID, subscriptionID)
	if err != nil {
		if !has {
			// Nothing to fall back to. Returning the error keeps the caller from
			// serving an empty body, which is the response that wipes a client.
			s.logger.Printf("subscription snapshot: provider fetch failed for %s/%s (%s)", pluginID, subscriptionID, subscriptionDiagnosticSummary(err))
			return model.SubscriptionSnapshot{}, fmt.Errorf("subscription provider fetch failed for %s/%s", pluginID, subscriptionID)
		}
		s.logger.Printf("subscription snapshot: provider fetch failed for %s/%s; preserving last-good (%s)", pluginID, subscriptionID, subscriptionDiagnosticSummary(err))
		existing.FetchError = "provider_fetch_failed"
		existing.LastAttemptAt = s.now()
		existing.Stale = true
		committed, storeErr := s.persistSubscriptionSnapshot(existing)
		if committed {
			publication.epoch++
			s.invalidateSharesForSource(pluginID, subscriptionID)
		}
		if storeErr != nil {
			return model.SubscriptionSnapshot{}, fmt.Errorf("persist stale subscription %s/%s: %w", pluginID, subscriptionID, storeErr)
		}
		metadata := map[string]string{
			"plugin_id": pluginID, "subscription_id": subscriptionID,
			"stale": "true", "snapshot_age_seconds": fmt.Sprintf("%.0f", s.now().Sub(existing.FetchedAt).Seconds()),
		}
		if existing.SourceVersion != "" {
			metadata["source_version"] = existing.SourceVersion
		}
		s.recordAudit(model.AuditEvent{
			ID: id.New("audit"), Action: auditActionSubscriptionFetch, Decision: "observe",
			Reason:   "refresh failed; serving the last good snapshot",
			Metadata: metadata,
		})
		return existing, nil
	}

	fetched.PluginID = pluginID
	fetched.SubscriptionID = subscriptionID
	fetched.SchemaVersion = model.SubscriptionSnapshotSchemaVersion
	fetched.FetchedAt = s.now()
	fetched.LastAttemptAt = fetched.FetchedAt
	fetched.FetchError = ""
	fetched.Stale = false
	committed, persistErr := s.persistSubscriptionSnapshot(fetched)
	if committed {
		publication.epoch++
		// The content moved: any rendered body cached for a share sourcing this
		// record is now stale, no matter how much TTL it had left.
		if has && (force || existing.Stale || existing.Userinfo != fetched.Userinfo || subscriptionRevalidationVersion(existing) != subscriptionRevalidationVersion(fetched)) {
			s.invalidateSharesForSource(pluginID, subscriptionID)
		}
	}
	if persistErr != nil {
		return model.SubscriptionSnapshot{}, persistErr
	}
	metadata := map[string]string{
		"plugin_id": pluginID, "subscription_id": subscriptionID,
		"raw_bytes": fmt.Sprintf("%d", len(fetched.Raw)), "stale": "false", "snapshot_age_seconds": "0",
	}
	if fetched.SourceVersion != "" {
		metadata["source_version"] = fetched.SourceVersion
	}
	s.recordAudit(model.AuditEvent{
		ID: id.New("audit"), Action: auditActionSubscriptionFetch, Decision: "allow",
		Metadata: metadata,
	})
	return fetched, nil
}

func (s *Server) subscriptionSnapshotEpoch(pluginID, subscriptionID string, snapshot model.SubscriptionSnapshot) (uint64, bool) {
	key := subscriptionRefreshKey{pluginID: pluginID, subscriptionID: subscriptionID}
	publication := s.subscriptionPublicationStateFor(key)
	publication.mu.Lock()
	defer publication.mu.Unlock()
	current, ok := s.store.SubscriptionSnapshot(pluginID, subscriptionID)
	if !ok || current.Raw != snapshot.Raw || current.Userinfo != snapshot.Userinfo || current.SourceVersion != snapshot.SourceVersion ||
		current.Stale != snapshot.Stale || current.FetchedAt != snapshot.FetchedAt || current.LastAttemptAt != snapshot.LastAttemptAt {
		return 0, false
	}
	return publication.epoch, true
}

func (s *Server) putSubscriptionCacheForSource(key subscriptionCacheKey, pluginID, subscriptionID string, expectedEpoch uint64, entry subscriptionCacheEntry, now time.Time) bool {
	sourceKey := subscriptionRefreshKey{pluginID: pluginID, subscriptionID: subscriptionID}
	publication := s.subscriptionPublicationStateFor(sourceKey)
	publication.mu.Lock()
	defer publication.mu.Unlock()
	if publication.epoch != expectedEpoch {
		return false
	}
	s.subscriptionCache.PutSnapshot(key, entry.body, entry.contentType, entry.userinfo, entry.revalidationVersion, entry.publicSourceVersion, entry.stale, entry.fetchedAt, now)
	return true
}

func (s *Server) extendSubscriptionCacheForSource(key subscriptionCacheKey, pluginID, subscriptionID string, expectedEpoch uint64, snapshot model.SubscriptionSnapshot, expectedRevision uint64, now time.Time) bool {
	if waiter := s.subscriptionCacheExtendWaiter; waiter != nil {
		select {
		case waiter <- struct{}{}:
		default:
		}
	}
	sourceKey := subscriptionRefreshKey{pluginID: pluginID, subscriptionID: subscriptionID}
	publication := s.subscriptionPublicationStateFor(sourceKey)
	publication.mu.Lock()
	defer publication.mu.Unlock()
	current, ok := s.store.SubscriptionSnapshot(pluginID, subscriptionID)
	if !ok || publication.epoch != expectedEpoch || !subscriptionSnapshotsEqualForCache(current, snapshot) {
		return false
	}
	return s.subscriptionCache.ExtendSnapshot(key, expectedRevision, snapshot.Userinfo, snapshot.SourceVersion, snapshot.Stale, snapshot.FetchedAt, now)
}

func subscriptionSnapshotsEqualForCache(current, captured model.SubscriptionSnapshot) bool {
	return current.Raw == captured.Raw && current.Userinfo == captured.Userinfo && current.SourceVersion == captured.SourceVersion &&
		current.Stale == captured.Stale && current.FetchedAt == captured.FetchedAt && current.LastAttemptAt == captured.LastAttemptAt
}

// fetchSubscriptionSource asks the plugin to retrieve the provider's current
// content. The plugin performs the outbound request under its own guarded egress
// capability; the core neither holds the provider URL nor sees its credentials.
func (s *Server) fetchSubscriptionSource(ctx context.Context, pluginID, subscriptionID string) (model.SubscriptionSnapshot, error) {
	payload, err := json.Marshal(map[string]string{"subscription_id": subscriptionID})
	if err != nil {
		return model.SubscriptionSnapshot{}, err
	}
	out, err := s.callRuntimePluginService(ctx, pluginID, pluginID+"/subscription", "fetch", payload, nil, nil)
	if err != nil {
		return model.SubscriptionSnapshot{}, err
	}
	var reply struct {
		Raw            string          `json:"raw"`
		Userinfo       string          `json:"userinfo"`
		SourceVersion  string          `json:"source_version"`
		SourceManifest json.RawMessage `json:"source_manifest"`
	}
	if err := json.Unmarshal(out, &reply); err != nil {
		return model.SubscriptionSnapshot{}, fmt.Errorf("decode plugin fetch reply: %w", err)
	}
	if reply.Raw == "" {
		// An empty fetch is a failure, not a subscription with no nodes. Accepting
		// it would overwrite a good snapshot with nothing and then serve nothing.
		return model.SubscriptionSnapshot{}, errors.New("plugin fetch returned no content")
	}
	return model.SubscriptionSnapshot{Raw: reply.Raw, Userinfo: reply.Userinfo, SourceVersion: reply.SourceVersion,
		SourceManifest: append(json.RawMessage(nil), reply.SourceManifest...)}, nil
}
