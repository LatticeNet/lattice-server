package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
)

// SubscriptionSummary is the producer-side, per-identity subscription state
// (design-12 S5). The locked boundary: vpn-core PRODUCES the source (identities,
// credentials, line bindings, a sub token) and Sub-Store COMBINES + PUBLISHES the
// actual delivery. So this read-model intentionally exposes only subscription
// STATE (eligibility, binding/credential counts, whether a sub token exists) — NOT
// the raw sub token or rendered links, which remain with the legacy /sub substrate
// and the Sub-Store publisher. The dashboard renders a thin view of this and points
// the operator at Sub-Store for publishing.
type SubscriptionSummary struct {
	UserID          string `json:"user_id"`
	Email           string `json:"email,omitempty"`
	Enabled         bool   `json:"enabled"`
	Eligible        bool   `json:"eligible"` // enabled AND not expired
	HasSubToken     bool   `json:"has_sub_token"`
	BindingCount    int    `json:"binding_count"`
	CredentialCount int    `json:"credential_count"`
	ExpiresAt       string `json:"expires_at,omitempty"`
}

func (s *Server) buildSubscriptions() []SubscriptionSummary {
	now := s.now()
	out := []SubscriptionSummary{}
	for _, u := range s.listVpnUsers() {
		eligible := u.Enabled && (u.ExpiresAt.IsZero() || u.ExpiresAt.After(now))
		sum := SubscriptionSummary{
			UserID: u.ID, Email: u.Email, Enabled: u.Enabled, Eligible: eligible,
			HasSubToken: u.SubID != "", BindingCount: len(u.Bindings), CredentialCount: len(u.Credentials),
		}
		if !u.ExpiresAt.IsZero() {
			sum.ExpiresAt = u.ExpiresAt.UTC().Format(rtTimeFmt)
		}
		out = append(out, sum)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Email != out[j].Email {
			return out[i].Email < out[j].Email
		}
		return out[i].UserID < out[j].UserID
	})
	return out
}

// vpnCoreSubscriptionsRPC serves latticenet.vpn-core/subscriptions (design-12 S5),
// proxy:read. The publisher (Sub-Store) is a separate plugin; this is source-only.
//
//	query -> {subscriptions: [...], count, publisher: "latticenet.sub-store"}
func (s *Server) vpnCoreSubscriptionsRPC(_ context.Context, method string, _ []byte) ([]byte, error) {
	switch method {
	case "query":
		subs := s.buildSubscriptions()
		return json.Marshal(struct {
			Subscriptions []SubscriptionSummary `json:"subscriptions"`
			Count         int                   `json:"count"`
			Publisher     string                `json:"publisher"`
		}{Subscriptions: subs, Count: len(subs), Publisher: subStorePluginID})
	default:
		return nil, fmt.Errorf("vpn-core/subscriptions: unknown method %q", method)
	}
}
