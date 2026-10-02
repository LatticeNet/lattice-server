package store

import (
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// NotifyRuleOptions are per-rule settings kept beside model.NotifyRule.
//
// yagni: the SDK's NotifyRule has no field for them, and moving the SDK pin
// for one optional string would couple this slice to an SDK release. They
// live in the JSON state keyed by rule id, deleted with the rule and cleared
// when the channel they name is deleted. When the SDK next changes, the field
// moves onto model.NotifyRule and this map is migrated once. The offline
// `migrate` round trip through the full bolt state does not carry the map,
// as it already does not carry notify_webhooks; a fallback lost that way is
// set again on the rule.
type NotifyRuleOptions struct {
	// FallbackChannelID receives the rule's message when every primary
	// channel of the rule failed it for good. It never equals one of the
	// rule's own channels.
	FallbackChannelID string `json:"fallback_channel_id,omitempty"`
}

func (o NotifyRuleOptions) zero() bool { return o == NotifyRuleOptions{} }

// UpsertNotifyRuleWithOptions writes a rule and its options in one save.
func (s *Store) UpsertNotifyRuleWithOptions(rule model.NotifyRule, opts NotifyRuleOptions) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rule.UpdatedAt = time.Now().UTC()
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = rule.UpdatedAt
	}
	s.state.NotifyRules[rule.ID] = rule
	if opts.zero() {
		delete(s.state.NotifyRuleOptions, rule.ID)
	} else {
		s.state.NotifyRuleOptions[rule.ID] = opts
	}
	return s.Save()
}

// NotifyRuleOptionsByRule returns a copy of every rule's options.
func (s *Store) NotifyRuleOptionsByRule() map[string]NotifyRuleOptions {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]NotifyRuleOptions, len(s.state.NotifyRuleOptions))
	for id, opts := range s.state.NotifyRuleOptions {
		out[id] = opts
	}
	return out
}
