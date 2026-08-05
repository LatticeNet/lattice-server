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

// snapshotFor returns the content to render, refreshing it first when it is
// missing or stale.
//
// The failure behaviour is the reason this function exists: when a refresh
// fails and a snapshot is available, the snapshot is served and the failure is
// recorded on it. A provider being down must not take a client's configuration
// with it - that is the behaviour upstream implements as ignore-failed-remote-sub.
func (s *Server) snapshotFor(ctx context.Context, pluginID, subscriptionID string, force bool) (model.SubscriptionSnapshot, error) {
	existing, has := s.store.SubscriptionSnapshot(pluginID, subscriptionID)
	fresh := has && !force && s.now().Sub(existing.FetchedAt) < subscriptionRefreshInterval
	if fresh {
		return existing, nil
	}

	fetched, err := s.fetchSubscriptionSource(ctx, pluginID, subscriptionID)
	if err != nil {
		if !has {
			// Nothing to fall back to. Returning the error keeps the caller from
			// serving an empty body, which is the response that wipes a client.
			return model.SubscriptionSnapshot{}, fmt.Errorf("fetch subscription %s/%s: %w", pluginID, subscriptionID, err)
		}
		existing.FetchError = err.Error()
		existing.LastAttemptAt = s.now()
		if storeErr := s.store.UpsertSubscriptionSnapshot(existing); storeErr != nil {
			s.logger.Printf("subscription snapshot: recording fetch failure for %s/%s: %v", pluginID, subscriptionID, storeErr)
		}
		s.recordAudit(model.AuditEvent{
			ID: id.New("audit"), Action: auditActionSubscriptionFetch, Decision: "observe",
			Reason: "refresh failed; serving the last good snapshot",
			Metadata: map[string]string{
				"plugin_id": pluginID, "subscription_id": subscriptionID,
				"snapshot_age_seconds": fmt.Sprintf("%.0f", s.now().Sub(existing.FetchedAt).Seconds()),
			},
		})
		return existing, nil
	}

	fetched.PluginID = pluginID
	fetched.SubscriptionID = subscriptionID
	fetched.SchemaVersion = model.SubscriptionSnapshotSchemaVersion
	fetched.FetchedAt = s.now()
	fetched.LastAttemptAt = fetched.FetchedAt
	fetched.FetchError = ""
	if err := s.store.UpsertSubscriptionSnapshot(fetched); err != nil {
		return model.SubscriptionSnapshot{}, err
	}
	s.recordAudit(model.AuditEvent{
		ID: id.New("audit"), Action: auditActionSubscriptionFetch, Decision: "allow",
		Metadata: map[string]string{
			"plugin_id": pluginID, "subscription_id": subscriptionID,
			"raw_bytes": fmt.Sprintf("%d", len(fetched.Raw)),
		},
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
		Raw      string `json:"raw"`
		Userinfo string `json:"userinfo"`
	}
	if err := json.Unmarshal(out, &reply); err != nil {
		return model.SubscriptionSnapshot{}, fmt.Errorf("decode plugin fetch reply: %w", err)
	}
	if reply.Raw == "" {
		// An empty fetch is a failure, not a subscription with no nodes. Accepting
		// it would overwrite a good snapshot with nothing and then serve nothing.
		return model.SubscriptionSnapshot{}, errors.New("plugin fetch returned no content")
	}
	return model.SubscriptionSnapshot{Raw: reply.Raw, Userinfo: reply.Userinfo}, nil
}
