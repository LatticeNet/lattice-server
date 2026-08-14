package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

const auditActionSubscriptionFetch = "subscription.source.fetch"

type subscriptionRefreshFlight struct {
	done     chan struct{}
	snapshot model.SubscriptionSnapshot
	err      error
}

type subscriptionRefreshKey struct {
	pluginID       string
	subscriptionID string
}

func subscriptionRevalidationVersion(snapshot model.SubscriptionSnapshot) string {
	if snapshot.SourceVersion != "" {
		return snapshot.SourceVersion
	}
	return subscriptionContentHash(snapshot.Raw)
}

func (s *Server) persistSubscriptionSnapshot(snapshot model.SubscriptionSnapshot) error {
	if s.subscriptionSnapshotPersist != nil {
		return s.subscriptionSnapshotPersist(snapshot)
	}
	return s.store.UpsertSubscriptionSnapshot(snapshot)
}

// snapshotFor returns the content to render, refreshing it first when it is
// missing or stale.
//
// The failure behaviour is the reason this function exists: when a refresh
// fails and a snapshot is available, the snapshot is served and the failure is
// recorded on it. A provider being down must not take a client's configuration
// with it - that is the behaviour upstream implements as ignore-failed-remote-sub.
func (s *Server) snapshotFor(ctx context.Context, pluginID, subscriptionID string, force bool) (model.SubscriptionSnapshot, error) {
	existing, has := s.store.SubscriptionSnapshot(pluginID, subscriptionID)
	fresh := has && !existing.Stale && !force && s.now().Sub(existing.FetchedAt) < subscriptionRefreshInterval
	if fresh {
		return existing, nil
	}
	key := subscriptionRefreshKey{pluginID: pluginID, subscriptionID: subscriptionID}
	s.subscriptionRefreshMu.Lock()
	if s.subscriptionRefreshFlights == nil {
		s.subscriptionRefreshFlights = make(map[subscriptionRefreshKey]*subscriptionRefreshFlight)
	}
	if flight := s.subscriptionRefreshFlights[key]; flight != nil {
		joined := s.subscriptionRefreshJoined
		s.subscriptionRefreshMu.Unlock()
		if joined != nil {
			joined()
		}
		<-flight.done
		return flight.snapshot.Clone(), flight.err
	}
	flight := &subscriptionRefreshFlight{done: make(chan struct{})}
	s.subscriptionRefreshFlights[key] = flight
	s.subscriptionRefreshMu.Unlock()

	flight.snapshot, flight.err = s.refreshSubscriptionSnapshot(ctx, pluginID, subscriptionID, force)
	s.subscriptionRefreshMu.Lock()
	delete(s.subscriptionRefreshFlights, key)
	close(flight.done)
	s.subscriptionRefreshMu.Unlock()
	return flight.snapshot.Clone(), flight.err
}

func (s *Server) refreshSubscriptionSnapshot(ctx context.Context, pluginID, subscriptionID string, force bool) (model.SubscriptionSnapshot, error) {
	// Re-read only after owning the source flight. This is the current durable
	// authority all fetch outcomes compare against, so a caller that queued
	// behind another refresh cannot overwrite the newer result it just observed.
	existing, has := s.store.SubscriptionSnapshot(pluginID, subscriptionID)
	if has && !existing.Stale && !force && s.now().Sub(existing.FetchedAt) < subscriptionRefreshInterval {
		return existing, nil
	}
	fetch := s.fetchSubscriptionSource
	if s.subscriptionFetch != nil {
		fetch = s.subscriptionFetch
	}
	fetched, err := fetch(ctx, pluginID, subscriptionID)
	if err != nil {
		if !has {
			// Nothing to fall back to. Returning the error keeps the caller from
			// serving an empty body, which is the response that wipes a client.
			return model.SubscriptionSnapshot{}, fmt.Errorf("fetch subscription %s/%s: %w", pluginID, subscriptionID, err)
		}
		existing.FetchError = err.Error()
		existing.LastAttemptAt = s.now()
		existing.Stale = true
		if storeErr := s.persistSubscriptionSnapshot(existing); storeErr != nil {
			return model.SubscriptionSnapshot{}, fmt.Errorf("persist stale subscription %s/%s: %w", pluginID, subscriptionID, storeErr)
		}
		// Stale is snapshot authority, not one render variant's cache metadata.
		// Drop every share/format/UA entry sourcing this snapshot so no sibling
		// cache can continue advertising a fresh response after the durable
		// failure transition.
		s.invalidateSharesForSource(pluginID, subscriptionID)
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
	if err := s.persistSubscriptionSnapshot(fetched); err != nil {
		return model.SubscriptionSnapshot{}, err
	}
	// The content moved: any rendered body cached for a share sourcing this
	// record is now stale, no matter how much TTL it had left. Without this the
	// revalidation cadence, not the content, would decide what clients get.
	if has && (force || existing.Stale || existing.Userinfo != fetched.Userinfo || subscriptionRevalidationVersion(existing) != subscriptionRevalidationVersion(fetched)) {
		s.invalidateSharesForSource(pluginID, subscriptionID)
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
