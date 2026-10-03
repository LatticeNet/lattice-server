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
// `migrate` round trip carries the map in the bolt meta bucket
// (boltKeyNotifyRuleOptions).
type NotifyRuleOptions struct {
	// FallbackChannelID receives the rule's message when every primary
	// channel of the rule failed it for good. It never equals one of the
	// rule's own channels.
	FallbackChannelID string `json:"fallback_channel_id,omitempty"`
	// Escalation re-sends an unacknowledged critical incident once through
	// the rule's channels. The zero value is the operator's default
	// (2026-10-02): on, after 30 minutes, at Bark level critical.
	EscalationOff        bool   `json:"escalation_off,omitempty"`
	EscalateAfterMinutes int    `json:"escalate_after_minutes,omitempty"`
	EscalationBarkLevel  string `json:"escalation_bark_level,omitempty"`
	// QuietHours holds the rule's non-critical deliveries inside a daily
	// local window; nil (the default) means no quiet hours.
	QuietHours *NotifyQuietHours `json:"quiet_hours,omitempty"`
}

// NotifyQuietHours is a daily window in a time zone, Start and End as
// "15:04". A window whose End is not after Start runs past midnight.
type NotifyQuietHours struct {
	Start    string `json:"start"`
	End      string `json:"end"`
	TimeZone string `json:"time_zone"`
}

func (o NotifyRuleOptions) zero() bool {
	return o.FallbackChannelID == "" && !o.EscalationOff && o.EscalateAfterMinutes == 0 &&
		o.EscalationBarkLevel == "" && o.QuietHours == nil
}

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
		if opts.QuietHours != nil {
			qh := *opts.QuietHours
			opts.QuietHours = &qh
		}
		out[id] = opts
	}
	return out
}
