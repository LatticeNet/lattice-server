package server

import (
	"errors"
	"fmt"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// A channel's critical fallback.
//
// The rule fallback (planNotifyFallback) covers a rule whose every primary
// channel failed a message for good. It does not cover a message no rule
// routed (the zero-rule broadcast), a rule without a fallback, or the time a
// transient failure spends in its retries: against a dead Bark host that is
// four timed-out attempts over about three and a half minutes before the rule
// fallback is even planned. A channel may therefore name a fallback channel
// for critical events, and the first failed attempt of a critical message on
// that channel hands the message to it at once. The primary keeps retrying,
// so a channel that recovers on a retry may deliver a critical page twice;
// for these events a duplicate costs less than a late page.
//
// A fallback delivery never falls back again, so two channels naming each
// other cannot loop, and a channel that already receives the event (as a
// primary or as another fallback) is not sent it a second time.

// notifyCriticalEventTypes are the events a channel's fallback carries.
//
// service.down and ssh.compromise_suspected are critical in the notify design's
// catalogue (design-notify-abstraction section 3). node.offline is a warning
// there but is carried here as well: when the node hosting the Bark server
// goes offline, its own node.offline page is exactly the message that Bark
// channel can no longer deliver, which is the case this fallback exists for.
// When severity ships (design section 3, keepalive P3), this set becomes
// "severity critical" plus that one exception, decided in one table.
var notifyCriticalEventTypes = map[string]bool{
	EventServiceDown:            true,
	EventSSHCompromiseSuspected: true,
	EventNodeOffline:            true,
}

func notifyEventIsCritical(eventType string) bool {
	return notifyCriticalEventTypes[eventType]
}

// notifyCriticalEventList is the set in a stable order, for the channel view.
func notifyCriticalEventList() []string {
	return []string{EventNodeOffline, EventServiceDown, EventSSHCompromiseSuspected}
}

// planNotifyChannelFallback hands a critical primary delivery that just failed
// an attempt on channel to the channel's fallback, once per event and
// fallback channel, and records the hand-off on the failing channel's health.
func (s *Server) planNotifyChannelFallback(row store.NotifyDelivery, channel model.NotifyChannel) {
	if row.Role != store.NotifyRolePrimary || !notifyEventIsCritical(row.EventType) {
		return
	}
	fallbackID := s.store.NotifyChannelOptionsByChannel()[channel.ID].FallbackChannelID
	if fallbackID == "" || fallbackID == channel.ID {
		return
	}
	fallback, ok := s.notifyChannelByID(fallbackID)
	if !ok || !fallback.Enabled {
		s.logger.Printf("notify: channel %s names fallback %s, which is missing or disabled; critical %s not handed off", channel.ID, fallbackID, row.EventType)
		return
	}
	r := &s.outbox
	r.healthMu.Lock()
	defer r.healthMu.Unlock()
	for _, sib := range s.store.NotifyDeliveries(store.NotifyDeliveryFilter{EventID: row.EventID}) {
		if sib.ChannelID == fallbackID {
			return // that channel already has this event
		}
	}
	now := s.now()
	failed := row.ChannelName
	if failed == "" {
		failed = notifyChannelLabel(channel)
	}
	body, cut := notifyChannelFallbackBody(row.Body, failed, row.Settled())
	next := store.NotifyDelivery{
		ID: id.New("nd"), EventID: row.EventID, EventType: row.EventType,
		Source: row.Source, SourceID: row.SourceID, SourceRef: row.SourceRef,
		RuleID: row.RuleID, RuleName: row.RuleName,
		ChannelID: fallback.ID, ChannelName: fallback.Name, ChannelKind: fallback.Kind,
		Role: store.NotifyRoleFallback, FallbackFor: failed, FallbackOf: row.ID,
		Outcome: store.NotifyOutcomePlanned, NextAttemptAt: now,
		Title: row.Title, Body: body, Truncated: row.Truncated || cut, CreatedAt: now,
	}
	health, _ := s.store.NotifyChannelHealth(channel.ID)
	health.ChannelID = channel.ID
	health.LastFallbackAt = now
	health.LastFallbackChannelID = fallback.ID
	health.Fallbacks++
	if err := s.store.PutNotifyDelivery(next, &health); err != nil {
		s.logger.Printf("notify: record critical fallback for %s: %v", row.ID, err)
		return
	}
	s.wakeNotifyOutbox()
}

// notifyChannelFallbackBody appends the hand-off sentence, shortening the
// message rather than the sentence when the two exceed the body bound.
func notifyChannelFallbackBody(body, failed string, settled bool) (string, bool) {
	why := failed + " failed to deliver this critical alert and is still retrying"
	if settled {
		why = failed + " did not deliver this critical alert"
	}
	return notifyFallbackBodyWith(body, "\n\nSent through the fallback channel because "+why+".")
}

// validateNotifyChannelFallback accepts an empty fallback or another existing
// channel.
func validateNotifyChannelFallback(fallbackID, channelID string, channels []model.NotifyChannel) error {
	if fallbackID == "" {
		return nil
	}
	if fallbackID == channelID {
		return errors.New("a channel cannot be its own fallback")
	}
	for _, c := range channels {
		if c.ID == fallbackID {
			return nil
		}
	}
	return fmt.Errorf("fallback channel %q does not exist", fallbackID)
}
