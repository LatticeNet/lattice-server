package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/notify"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// The console's view of the outbox: channel health, the Sent log, a test of
// a stored channel, and a rule's fallback channel.

// Channel health states, decided here so the console never re-implements the
// failing rule.
const (
	notifyHealthUnknown  = "unknown"  // no delivery or test yet
	notifyHealthOK       = "ok"       // the last attempt delivered
	notifyHealthDegraded = "degraded" // recent failures, not yet failing
	notifyHealthFailing  = "failing"  // notifyChannelFailing holds
)

// notifyChannelHealthView is a channel's health as the console reads it. The
// failure is a classified kind and a status code, never the transport error.
type notifyChannelHealthView struct {
	State               string    `json:"state"`
	LastAttemptAt       time.Time `json:"last_attempt_at,omitzero"`
	LastOKAt            time.Time `json:"last_ok_at,omitzero"`
	LastFailureAt       time.Time `json:"last_failure_at,omitzero"`
	LastFailureKind     string    `json:"last_failure_kind,omitempty"`
	LastStatusCode      int       `json:"last_status_code,omitempty"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	FailingSince        time.Time `json:"failing_since,omitzero"`
	// The last time a critical message this channel failed was handed to its
	// fallback, which channel took it, and how many hand-offs so far.
	LastFallbackAt        time.Time `json:"last_fallback_at,omitzero"`
	LastFallbackChannelID string    `json:"last_fallback_channel_id,omitempty"`
	Fallbacks             int       `json:"fallbacks,omitempty"`
}

func notifyChannelHealthState(h store.NotifyChannelHealth, now time.Time) string {
	switch {
	case h.LastAttemptAt.IsZero():
		return notifyHealthUnknown
	case notifyChannelFailing(h, now):
		return notifyHealthFailing
	case h.ConsecutiveFailures > 0 || h.LastFailureAt.After(h.LastOKAt):
		// Counted failures not yet failing, or a last attempt that failed: a
		// delivery still retrying, or an operator's test.
		return notifyHealthDegraded
	default:
		return notifyHealthOK
	}
}

func toNotifyChannelHealthView(h store.NotifyChannelHealth, now time.Time) notifyChannelHealthView {
	return notifyChannelHealthView{
		State:               notifyChannelHealthState(h, now),
		LastAttemptAt:       h.LastAttemptAt,
		LastOKAt:            h.LastOKAt,
		LastFailureAt:       h.LastFailureAt,
		LastFailureKind:     h.LastFailureKind,
		LastStatusCode:      h.LastStatusCode,
		ConsecutiveFailures: h.ConsecutiveFailures,
		FailingSince:        h.FailingSince,

		LastFallbackAt:        h.LastFallbackAt,
		LastFallbackChannelID: h.LastFallbackChannelID,
		Fallbacks:             h.Fallbacks,
	}
}

// notifyRuleView is a rule with the options kept beside it.
type notifyRuleView struct {
	model.NotifyRule
	FallbackChannelID string `json:"fallback_channel_id,omitempty"`
}

func toNotifyRuleView(rule model.NotifyRule, opts store.NotifyRuleOptions) notifyRuleView {
	return notifyRuleView{NotifyRule: rule, FallbackChannelID: opts.FallbackChannelID}
}

// validateNotifyFallback accepts an empty fallback or an existing channel that
// is not already one of the rule's own channels: a fallback that is also a
// primary has failed by the time it would be used.
func validateNotifyFallback(fallbackID string, rule model.NotifyRule, channels []model.NotifyChannel) error {
	if fallbackID == "" {
		return nil
	}
	if slices.Contains(rule.ChannelIDs, fallbackID) {
		return errors.New("the fallback channel must differ from the rule's own channels")
	}
	for _, c := range channels {
		if c.ID == fallbackID {
			return nil
		}
	}
	return fmt.Errorf("fallback channel %q does not exist", fallbackID)
}

// handleNotifyChannelTest sends a fixed test message through a stored channel,
// so the operator can check a saved key without typing it again. The config
// never leaves the server. It is gated on notify:admin with the channel
// routes, not on the dispatch scope notify:send: a dispatch-only token must
// not be able to put text on the operator's own phone, and the message here is
// fixed for the same reason.
func (s *Server) handleNotifyChannelTest(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if s.refuseConfinedFleetWrite(w, p, "notify.channel.test", "notify:admin") {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	channel, ok := s.notifyChannelByID(strings.TrimSpace(req.ID))
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("notification channel not found"))
		return
	}
	row, health := s.sendNotifyChannelTest(channel)
	sent := row.Outcome == store.NotifyOutcomeSent
	metadata := map[string]string{"channel_id": channel.ID, "kind": channel.Kind, "ok": strconv.FormatBool(sent)}
	if n := len(row.Attempts); n > 0 && row.Attempts[n-1].Kind != "" {
		metadata["failure_kind"] = row.Attempts[n-1].Kind
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "notify.channel.test", Scope: "notify:admin", Metadata: metadata})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       sent,
		"delivery": row,
		"health":   toNotifyChannelHealthView(health, s.now()),
	})
}

// sendNotifyChannelTest sends the test synchronously and records it in the
// outbox with role test. A success clears the channel's failing state (and
// announces the recovery if its failure was announced); a failure updates the
// last failure but neither counts toward failing nor starts its window
// (nextNotifyHealth), since an operator correcting a key by trial should not
// page the other channels, then or later.
func (s *Server) sendNotifyChannelTest(c model.NotifyChannel) (store.NotifyDelivery, store.NotifyChannelHealth) {
	now := s.now()
	name := notifyChannelLabel(c)
	row := store.NotifyDelivery{
		ID: id.New("nd"), EventID: id.New("evt"), EventType: eventNotifyTest, Source: store.NotifySourceOperator,
		ChannelID: c.ID, ChannelName: c.Name, ChannelKind: c.Kind, Role: store.NotifyRoleTest,
		Title:     "Lattice test",
		Body:      fmt.Sprintf("Test message for the %s channel %q, sent from Notifications at %s. If you can read this, the channel works.", c.Kind, name, now.UTC().Format(time.RFC3339)),
		CreatedAt: now,
	}
	ctx, cancel := context.WithTimeout(context.Background(), notifyTestTimeout)
	started := time.Now()
	err := s.notifySend(ctx, c, notify.Message{Title: row.Title, Body: row.Body})
	cancel()
	attempt := store.NotifyAttempt{At: s.now(), OK: err == nil, DurationMS: time.Since(started).Milliseconds()}
	kind, status, _ := redactSendError(err)
	attempt.Kind, attempt.Status = kind, status
	row.Attempts = []store.NotifyAttempt{attempt}
	row.SettledAt = attempt.At
	if err == nil {
		row.Outcome = store.NotifyOutcomeSent
	} else {
		row.Outcome = store.NotifyOutcomeFailed
		row.Reason = notifyFailureSentence(kind, status, 1)
		s.logger.Printf("notify: test of channel %s failed (%s, status %d)", c.ID, kind, status)
	}

	r := &s.outbox
	r.healthMu.Lock()
	health, _ := s.store.NotifyChannelHealth(c.ID)
	health.ChannelID = c.ID
	prev := health
	health = nextNotifyHealth(health, attempt, false, time.Time{})
	recovered := false
	if attempt.OK {
		_, recovered = notifyHealthTransition(prev, &health, attempt.At)
	}
	if perr := s.store.PutNotifyDelivery(row, &health); perr != nil {
		s.logger.Printf("notify: record test %s: %v", row.ID, perr)
	}
	r.healthMu.Unlock()
	if recovered {
		s.announceNotifyChannelOK(c, prev, attempt.At)
	}
	return row, health
}

// defaultNotifyDeliveryLimit is how many deliveries the Sent log shows unless
// asked for more; the outbox holds up to store.MaxNotifyDeliveries.
const defaultNotifyDeliveryLimit = 500

// handleNotifyDeliveries lists the outbox, newest first. Delivery history
// carries rendered message content for every node, so a node-confined token
// is refused here as on the rest of the notify read surface.
func (s *Server) handleNotifyDeliveries(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if s.refuseConfinedNotifyRead(w, p, "notify.delivery.list") {
		return
	}
	q := r.URL.Query()
	limit := defaultNotifyDeliveryLimit
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, errors.New("limit must be a positive integer"))
			return
		}
		limit = min(n, store.MaxNotifyDeliveries)
	}
	filter := store.NotifyDeliveryFilter{
		Outcome:   strings.TrimSpace(q.Get("outcome")),
		ChannelID: strings.TrimSpace(q.Get("channel_id")),
		EventType: strings.TrimSpace(q.Get("event_type")),
		EventID:   strings.TrimSpace(q.Get("event_id")),
		Source:    strings.TrimSpace(q.Get("source")),
		SourceID:  strings.TrimSpace(q.Get("source_id")),
		Query:     q.Get("q"),
		Limit:     limit,
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"deliveries": s.store.NotifyDeliveries(filter),
		"stored":     s.store.NotifyDeliveryCount(),
		"durable":    s.store.NotifyOutboxDurable(),
		"max":        store.MaxNotifyDeliveries,
		"floor":      store.NotifyDeliveryFloorPerSource,
	})
}
