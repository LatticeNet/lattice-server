package store

import (
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// NotifyChannelOptions are per-channel settings kept beside
// model.NotifyChannel, the way NotifyRuleOptions sit beside a rule.
//
// yagni: model.NotifyChannel has no field for them, and its Config map is the
// encrypted credential, which the console never reads back, so an option
// stored there could not be shown. They live in the JSON state keyed by
// channel id, written only when the operator saves a channel, deleted with
// the channel and cleared when the channel they name is deleted. When the SDK
// next changes, the field moves onto model.NotifyChannel and this map is
// migrated once. The offline `migrate` round trip carries the map in the bolt
// meta bucket (boltKeyNotifyChannelOptions).
type NotifyChannelOptions struct {
	// FallbackChannelID receives a critical message this channel failed to
	// deliver. It never equals the channel itself.
	FallbackChannelID string `json:"fallback_channel_id,omitempty"`
}

func (o NotifyChannelOptions) zero() bool { return o == NotifyChannelOptions{} }

// UpsertNotifyChannelWithOptions writes a channel and its options in one save.
func (s *Store) UpsertNotifyChannelWithOptions(c model.NotifyChannel, opts NotifyChannelOptions) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.UpdatedAt = time.Now().UTC()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = c.UpdatedAt
	}
	s.state.NotifyChannels[c.ID] = c
	if opts.zero() {
		delete(s.state.NotifyChannelOptions, c.ID)
	} else {
		s.state.NotifyChannelOptions[c.ID] = opts
	}
	return s.Save()
}

// NotifyChannelOptionsByChannel returns a copy of every channel's options.
func (s *Store) NotifyChannelOptionsByChannel() map[string]NotifyChannelOptions {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]NotifyChannelOptions, len(s.state.NotifyChannelOptions))
	for id, opts := range s.state.NotifyChannelOptions {
		out[id] = opts
	}
	return out
}

// clearNotifyChannelOptionsLocked drops the deleted channel's own options and
// every other channel's fallback that names it.
func (s *Store) clearNotifyChannelOptionsLocked(id string) {
	delete(s.state.NotifyChannelOptions, id)
	for channelID, opts := range s.state.NotifyChannelOptions {
		if opts.FallbackChannelID != id {
			continue
		}
		opts.FallbackChannelID = ""
		if opts.zero() {
			delete(s.state.NotifyChannelOptions, channelID)
		} else {
			s.state.NotifyChannelOptions[channelID] = opts
		}
	}
}
