package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/notify"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Notification delivery through a stored outbox.
//
// An event is planned into one delivery per (rule, channel) and every
// delivery is written to the outbox before notifyEventTyped returns. A single
// drainer sends what is due; each attempt appends a receipt, a transient
// failure is retried on notifyRetryDelays, a permanent one settles at once,
// and the channel's health moves in the same store write as the receipt.
// When every primary channel of a rule failed a message for good, the rule's
// fallback channel gets it. A channel that keeps failing raises
// notify.channel_failing, which is never sent to the failing channel itself.
//
// Boot reconciles the outbox before the first send: a delivery planned less
// than notifyRedriveHorizon ago is sent again, an older one settles failed,
// so no row stays "planned" across a restart. Redrive is at least once: a
// send that reached the channel just before a crash is sent again, and the
// row says so.
//
// The defaults are the notify design's D5 (design-notify-abstraction section
// 6 and 11): retries at 5 s, 30 s and 2 min, a 15 minute redrive horizon,
// 1000 deliveries with a floor of 50 per source.

const (
	// EventNotifyChannelFailing and EventNotifyChannelOK report a channel's
	// own delivery health, so a dead Bark key reaches another channel.
	EventNotifyChannelFailing = "notify.channel_failing"
	EventNotifyChannelOK      = "notify.channel_ok"
	// eventNotifyTest marks a stored-channel test in the Sent log; it is not
	// an event any rule routes.
	eventNotifyTest = "notify.test"
	// eventPluginMessage is a plugin's notify.send. Plugins have no event
	// types until the notify capability ships (design section 7).
	eventPluginMessage = "plugin.message"

	notifyRedriveHorizon = 15 * time.Minute
	notifySendTimeout    = 15 * time.Second
	notifyTestTimeout    = 12 * time.Second
	// notifyMaxConcurrentSends bounds sends in flight, so one channel stuck
	// on its timeout does not hold back the others.
	notifyMaxConcurrentSends = 4

	// A channel is failing after this many deliveries in a row settle failed,
	// or once its failures have run this long. The announcement repeats at
	// most once per notifyChannelFailingEvery while it stays failing.
	notifyChannelFailingAfter  = 3
	notifyChannelFailingWindow = 15 * time.Minute
	notifyChannelFailingEvery  = time.Hour
)

// notifyRetryDelays is the wait before each retry of a transient failure: a
// delivery gets one send plus one retry per entry.
var notifyRetryDelays = []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute}

// Failure kinds. They are the only failure detail stored or returned: the
// transport error embeds the channel credential in its URL, and the upstream
// body is text the remote side chose.
const (
	notifyKindNetwork       = "network"
	notifyKindTimeout       = "timeout"
	notifyKindUpstream4xx   = "upstream_4xx"
	notifyKindUpstream5xx   = "upstream_5xx"
	notifyKindRateLimited   = "rate_limited"
	notifyKindConfigInvalid = "config_invalid"
	notifyKindUnknown       = "unknown"
)

// notifyConfigError is a channel whose stored config does not build.
type notifyConfigError struct{ err error }

func (e notifyConfigError) Error() string { return "notify channel config: " + e.err.Error() }

// redactSendError is the only code allowed to look at a raw send error. It
// returns a fixed kind, the upstream status when there is one, and whether a
// retry may help. Nothing it returns can carry a credential or remote text.
func redactSendError(err error) (kind string, status int, transient bool) {
	if err == nil {
		return "", 0, false
	}
	var cfg notifyConfigError
	if errors.As(err, &cfg) {
		return notifyKindConfigInvalid, 0, false
	}
	var se *notify.StatusError
	if errors.As(err, &se) {
		switch {
		case se.Status == 429:
			return notifyKindRateLimited, se.Status, true
		case se.Status >= 500:
			return notifyKindUpstream5xx, se.Status, true
		case se.Status >= 400:
			return notifyKindUpstream4xx, se.Status, false
		default:
			return notifyKindUnknown, se.Status, false
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return notifyKindTimeout, 0, true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return notifyKindTimeout, 0, true
	}
	// The outbound policy refuses a destination with untyped errors. A
	// channel pointed at a private address or a bad URL will not start
	// working on a retry.
	msg := err.Error()
	for _, permanent := range []string{"blocked address", "unsupported scheme", "missing host", "invalid url"} {
		if strings.Contains(msg, permanent) {
			return notifyKindConfigInvalid, 0, false
		}
	}
	var ue *url.Error
	if errors.As(err, &ue) || errors.As(err, &ne) {
		return notifyKindNetwork, 0, true
	}
	return notifyKindUnknown, 0, true
}

// notifyFailureSentence is the stored reason for a settled failure, composed
// from the kind and status only.
func notifyFailureSentence(kind string, status int, attempts int) string {
	var what string
	switch kind {
	case notifyKindUpstream4xx, notifyKindUpstream5xx, notifyKindRateLimited:
		what = fmt.Sprintf("upstream status %d", status)
	case notifyKindTimeout:
		what = "timed out"
	case notifyKindNetwork:
		what = "network error"
	case notifyKindConfigInvalid:
		what = "channel config refused"
	default:
		what = "send failed"
	}
	if attempts > 1 {
		return fmt.Sprintf("%s after %d attempts", what, attempts)
	}
	return what
}

func defaultNotifySend(ctx context.Context, channel model.NotifyChannel, msg notify.Message) error {
	built, err := buildChannel(channel.Kind, channel.Config)
	if err != nil {
		return notifyConfigError{err}
	}
	return built.Send(ctx, msg)
}

// notifyTarget is one planned send: a channel and the message a rule rendered
// for it.
type notifyTarget struct {
	ruleID, ruleName string
	channel          model.NotifyChannel
	message          notify.Message
}

// planNotifyTargets resolves an event to channels. With no rules every
// enabled channel receives it (the zero-rules broadcast); otherwise each
// matching rule sends its rendered message to each of its channels. exclude
// drops one channel, and fanOutIfUnrouted sends to every other enabled
// channel when the rules reach none: that is how a failing channel's
// announcement still reaches someone.
func (s *Server) planNotifyTargets(eventType, title, body string, channels []model.NotifyChannel, rules []model.NotifyRule, exclude string, fanOutIfUnrouted bool) []notifyTarget {
	broadcast := func() []notifyTarget {
		out := []notifyTarget{}
		for _, c := range channels {
			if c.ID == exclude {
				continue
			}
			out = append(out, notifyTarget{channel: c, message: notify.Message{Title: title, Body: body}})
		}
		return out
	}
	if len(channels) == 0 {
		return nil
	}
	if len(rules) == 0 {
		return broadcast()
	}
	channelsByID := make(map[string]model.NotifyChannel, len(channels))
	for _, c := range channels {
		channelsByID[c.ID] = c
	}
	out := []notifyTarget{}
	for _, rule := range rules {
		if !notifyRuleMatches(rule, eventType) {
			continue
		}
		vars := map[string]string{"event_type": eventType, "title": title, "body": body}
		msg := notify.Message{
			Title: renderNotifyTemplate(rule.TitleTemplate, title, vars),
			Body:  renderNotifyTemplate(rule.BodyTemplate, body, vars),
		}
		seen := map[string]bool{}
		for _, channelID := range rule.ChannelIDs {
			if seen[channelID] || channelID == exclude {
				continue
			}
			seen[channelID] = true
			c, ok := channelsByID[channelID]
			if !ok {
				s.logger.Printf("notify: rule %s references missing or disabled channel %s", rule.ID, channelID)
				continue
			}
			out = append(out, notifyTarget{ruleID: rule.ID, ruleName: rule.Name, channel: c, message: msg})
		}
	}
	if len(out) == 0 && fanOutIfUnrouted {
		return broadcast()
	}
	return out
}

// notifyEnqueue says where an event comes from and how it is routed.
type notifyEnqueue struct {
	source string
	// sourceID is the plugin or webhook id; sourceRef the webhook's own
	// delivery record.
	sourceID, sourceRef string
	exclude             string
	fanOut              bool // fanOutIfUnrouted
	// broadcast skips rules and sends to every enabled channel, which is how
	// a plugin's notify.send has always been routed.
	broadcast bool
}

// notifyPlan is an event resolved to its deliveries but not yet stored.
type notifyPlan struct {
	eventID, eventType string
	title, body        string
	how                notifyEnqueue
	targets            []notifyTarget
	// noRoute says why targets is empty.
	noRoute string
	at      time.Time
}

// planNotifyEvent resolves an event to channels without storing anything.
func (s *Server) planNotifyEvent(eventType, title, body string, how notifyEnqueue) notifyPlan {
	channels := s.store.EnabledNotifyChannels()
	var rules []model.NotifyRule
	if !how.broadcast {
		rules = s.store.EnabledNotifyRules()
	}
	plan := notifyPlan{
		eventID: id.New("evt"), eventType: eventType, title: title, body: body, how: how,
		targets: s.planNotifyTargets(eventType, title, body, channels, rules, how.exclude, how.fanOut),
		at:      s.now(),
	}
	if len(plan.targets) == 0 {
		others := 0
		for _, c := range channels {
			if c.ID != how.exclude {
				others++
			}
		}
		switch {
		case others == 0 && how.exclude != "":
			plan.noRoute = "no other enabled channel"
		case others == 0:
			plan.noRoute = "no enabled channel"
		default:
			plan.noRoute = "no enabled rule routes this event type"
		}
	}
	return plan
}

// commitNotifyPlan stores a plan's deliveries and wakes the drainer. The
// deliveries are on disk when it returns, which is what lets a caller record
// a decision (a paged offline spell) knowing the page survives a crash. An
// event that reaches no channel is stored as one no_route row, so "why was I
// not told" has an answer.
func (s *Server) commitNotifyPlan(plan notifyPlan) {
	how := plan.how
	if len(plan.targets) == 0 {
		row := store.NotifyDelivery{
			ID: id.New("nd"), EventID: plan.eventID, EventType: plan.eventType,
			Source: how.source, SourceID: how.sourceID, SourceRef: how.sourceRef,
			Outcome: store.NotifyOutcomeNoRoute, Reason: plan.noRoute, Title: plan.title, Body: plan.body,
			CreatedAt: plan.at, SettledAt: plan.at,
		}
		if err := s.store.RecordNotifyDeliveries([]store.NotifyDelivery{row}); err != nil {
			s.logger.Printf("notify: record unrouted %s: %v", plan.eventType, err)
		}
		return
	}
	rows := make([]store.NotifyDelivery, len(plan.targets))
	for i, t := range plan.targets {
		rows[i] = store.NotifyDelivery{
			ID: id.New("nd"), EventID: plan.eventID, EventType: plan.eventType,
			Source: how.source, SourceID: how.sourceID, SourceRef: how.sourceRef,
			RuleID: t.ruleID, RuleName: t.ruleName,
			ChannelID: t.channel.ID, ChannelName: t.channel.Name, ChannelKind: t.channel.Kind,
			Role: store.NotifyRolePrimary, Outcome: store.NotifyOutcomePlanned,
			NextAttemptAt: plan.at, Title: t.message.Title, Body: t.message.Body, CreatedAt: plan.at,
		}
	}
	if err := s.store.RecordNotifyDeliveries(rows); err != nil {
		// The page matters more than its receipt: send without the outbox
		// rather than drop it.
		s.logger.Printf("notify: outbox write failed, sending %s unrecorded: %v", plan.eventType, err)
		s.sendUnrecorded(plan.targets)
		return
	}
	s.wakeNotifyOutbox()
}

// enqueueNotifyEvent plans and stores an event in one step.
func (s *Server) enqueueNotifyEvent(eventType, title, body string, how notifyEnqueue) {
	s.commitNotifyPlan(s.planNotifyEvent(eventType, title, body, how))
}

// sendUnrecorded is the pre-outbox path, kept for a store that refuses the
// write: one goroutine, one try per channel, failures logged by kind only.
func (s *Server) sendUnrecorded(targets []notifyTarget) {
	s.notifyDeliveries.begin()
	go func() {
		defer s.notifyDeliveries.end()
		for _, t := range targets {
			ctx, cancel := context.WithTimeout(context.Background(), notifySendTimeout)
			err := s.notifySend(ctx, t.channel, t.message)
			cancel()
			if err != nil {
				kind, status, _ := redactSendError(err)
				s.logger.Printf("notify: unrecorded delivery to channel %s failed (%s, status %d)", t.channel.ID, kind, status)
			}
		}
	}()
}

// notifyOutboxRunner is the drainer's state.
type notifyOutboxRunner struct {
	mu       sync.Mutex
	started  bool
	stopped  bool
	wake     chan struct{}
	stop     chan struct{}
	done     chan struct{}
	inflight map[string]bool
	sem      chan struct{}
	// healthMu serialises the read-modify-write of a channel's health and the
	// fallback decision, so two deliveries settling at once neither lose a
	// failure count nor plan the same fallback twice.
	healthMu sync.Mutex
}

// wakeNotifyOutbox starts the drainer on first use and nudges it.
func (s *Server) wakeNotifyOutbox() {
	r := &s.outbox
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return
	}
	if !r.started {
		r.started = true
		r.wake = make(chan struct{}, 1)
		r.stop = make(chan struct{})
		r.done = make(chan struct{})
		r.inflight = map[string]bool{}
		r.sem = make(chan struct{}, notifyMaxConcurrentSends)
		go s.runNotifyOutbox(r.wake, r.stop, r.done)
	}
	wake := r.wake
	r.mu.Unlock()
	select {
	case wake <- struct{}{}:
	default:
	}
}

func (s *Server) runNotifyOutbox(wake <-chan struct{}, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	for {
		next := s.drainNotifyOutbox()
		var timer *time.Timer
		var fire <-chan time.Time
		if !next.IsZero() {
			d := next.Sub(s.now())
			if d < 10*time.Millisecond {
				d = 10 * time.Millisecond
			}
			timer = time.NewTimer(d)
			fire = timer.C
		}
		select {
		case <-wake:
		case <-fire:
		case <-stop:
			if timer != nil {
				timer.Stop()
			}
			return
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

// drainNotifyOutbox starts every due delivery that is not already in flight
// and returns when the next scheduled one falls due, or zero.
func (s *Server) drainNotifyOutbox() time.Time {
	r := &s.outbox
	now := s.now()
	var next time.Time
	for _, row := range s.store.UnsettledNotifyDeliveries() {
		r.mu.Lock()
		if r.inflight == nil || r.inflight[row.ID] {
			r.mu.Unlock()
			continue
		}
		if row.NextAttemptAt.After(now) {
			r.mu.Unlock()
			if next.IsZero() || row.NextAttemptAt.Before(next) {
				next = row.NextAttemptAt
			}
			continue
		}
		r.inflight[row.ID] = true
		sem := r.sem
		r.mu.Unlock()
		s.notifyDeliveries.begin()
		go func(deliveryID string) {
			defer s.notifyDeliveries.end()
			sem <- struct{}{}
			s.attemptNotifyDelivery(deliveryID)
			<-sem
			r.mu.Lock()
			delete(r.inflight, deliveryID)
			r.mu.Unlock()
			s.wakeNotifyOutbox()
		}(row.ID)
	}
	return next
}

// stopNotifyOutbox ends the drainer loop. Deliveries already sending finish;
// Close waits for them through notifyDeliveries.
func (s *Server) stopNotifyOutbox() {
	r := &s.outbox
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	started := r.started
	stop, done := r.stop, r.done
	r.mu.Unlock()
	if started {
		close(stop)
		<-done
	}
}

// drainNotifyOutboxForShutdown starts what is due one last time after the
// loop has stopped, so alerts queued in the final sweep go out before exit.
// Deliveries waiting on a retry stay stored and are redriven at the next
// start.
func (s *Server) drainNotifyOutboxForShutdown() {
	r := &s.outbox
	r.mu.Lock()
	if r.inflight == nil {
		r.inflight = map[string]bool{}
		r.sem = make(chan struct{}, notifyMaxConcurrentSends)
	}
	r.mu.Unlock()
	s.drainNotifyOutbox()
}

// attemptNotifyDelivery sends one delivery once and records the outcome.
func (s *Server) attemptNotifyDelivery(deliveryID string) {
	row, ok := s.store.NotifyDelivery(deliveryID)
	if !ok || row.Settled() {
		return
	}
	channel, found := s.notifyChannelByID(row.ChannelID)
	if !found || !channel.Enabled {
		row.Outcome = store.NotifyOutcomeFailed
		row.Reason = "channel deleted before delivery"
		if found {
			row.Reason = "channel disabled before delivery"
		}
		row.SettledAt = s.now()
		row.NextAttemptAt = time.Time{}
		if err := s.store.PutNotifyDelivery(row, nil); err != nil {
			s.logger.Printf("notify: settle %s: %v", row.ID, err)
		}
		s.afterNotifySettled(row)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), notifySendTimeout)
	started := time.Now()
	err := s.notifySend(ctx, channel, notify.Message{Title: row.Title, Body: row.Body})
	cancel()
	attempt := store.NotifyAttempt{At: s.now(), OK: err == nil, DurationMS: time.Since(started).Milliseconds()}
	kind, status, transient := redactSendError(err)
	attempt.Kind, attempt.Status = kind, status
	if err != nil {
		s.logger.Printf("notify: delivery %s to channel %s failed (%s, status %d), attempt %d", row.ID, channel.ID, kind, status, len(row.Attempts)+1)
	}

	r := &s.outbox
	r.healthMu.Lock()
	row.Attempts = append(row.Attempts, attempt)
	switch {
	case err == nil:
		row.Outcome = store.NotifyOutcomeSent
		row.Reason = ""
		row.SettledAt = attempt.At
		row.NextAttemptAt = time.Time{}
	case transient && len(row.Attempts) <= len(s.notifyRetryDelays):
		row.NextAttemptAt = attempt.At.Add(s.notifyRetryDelays[len(row.Attempts)-1])
		row.Reason = fmt.Sprintf("%s, retrying", notifyFailureSentence(kind, status, len(row.Attempts)))
	default:
		row.Outcome = store.NotifyOutcomeFailed
		row.Reason = notifyFailureSentence(kind, status, len(row.Attempts))
		row.SettledAt = attempt.At
		row.NextAttemptAt = time.Time{}
	}
	health, _ := s.store.NotifyChannelHealth(channel.ID)
	health.ChannelID = channel.ID
	prev := health
	health = nextNotifyHealth(health, attempt, row.Outcome == store.NotifyOutcomeFailed)
	announce, recovered := notifyHealthTransition(prev, &health, attempt.At)
	if perr := s.store.PutNotifyDelivery(row, &health); perr != nil {
		s.logger.Printf("notify: record attempt %s: %v", row.ID, perr)
	}
	r.healthMu.Unlock()

	if announce {
		s.announceNotifyChannelFailing(channel, health)
	}
	if recovered {
		s.announceNotifyChannelOK(channel, prev, attempt.At)
	}
	if row.Settled() {
		s.afterNotifySettled(row)
	}
	if !row.Settled() {
		s.wakeNotifyOutbox()
	}
}

// nextNotifyHealth folds one attempt into a channel's health. settledFailed
// is set when the attempt ended its delivery as failed; only those count
// toward ConsecutiveFailures, so a retry that recovers costs nothing.
func nextNotifyHealth(h store.NotifyChannelHealth, a store.NotifyAttempt, settledFailed bool) store.NotifyChannelHealth {
	h.LastAttemptAt = a.At
	if a.OK {
		h.LastOKAt = a.At
		h.ConsecutiveFailures = 0
		h.FailingSince = time.Time{}
		return h
	}
	h.LastFailureAt = a.At
	h.LastFailureKind = a.Kind
	h.LastStatusCode = a.Status
	if h.FailingSince.IsZero() {
		h.FailingSince = a.At
	}
	if settledFailed {
		h.ConsecutiveFailures++
	}
	return h
}

// notifyChannelFailing is the one rule for "this channel is failing", used for
// the announcement and for the console's health state.
func notifyChannelFailing(h store.NotifyChannelHealth, now time.Time) bool {
	if h.ConsecutiveFailures >= notifyChannelFailingAfter {
		return true
	}
	return h.ConsecutiveFailures > 0 && !h.FailingSince.IsZero() && now.Sub(h.FailingSince) >= notifyChannelFailingWindow
}

// notifyHealthTransition decides, on the new health, whether to announce the
// channel failing (once per run, repeated at most hourly) or recovered, and
// records the announcement on h.
func notifyHealthTransition(prev store.NotifyChannelHealth, h *store.NotifyChannelHealth, now time.Time) (announce, recovered bool) {
	if h.ConsecutiveFailures == 0 && h.FailingSince.IsZero() {
		if prev.Announced {
			h.Announced = false
			return false, true
		}
		return false, false
	}
	if !notifyChannelFailing(*h, now) {
		return false, false
	}
	if h.Announced && now.Sub(h.AnnouncedAt) < notifyChannelFailingEvery {
		return false, false
	}
	h.Announced = true
	h.AnnouncedAt = now
	return true, false
}

func (s *Server) notifyChannelByID(channelID string) (model.NotifyChannel, bool) {
	for _, c := range s.store.NotifyChannels() {
		if c.ID == channelID {
			return c, true
		}
	}
	return model.NotifyChannel{}, false
}

func notifyChannelLabel(c model.NotifyChannel) string {
	if name := strings.TrimSpace(c.Name); name != "" {
		return name
	}
	return c.ID
}

func describeNotifyFailure(h store.NotifyChannelHealth) string {
	switch h.LastFailureKind {
	case notifyKindUpstream4xx:
		return fmt.Sprintf("the endpoint refused it (HTTP %d); the key, token or chat id is likely wrong", h.LastStatusCode)
	case notifyKindUpstream5xx:
		return fmt.Sprintf("the endpoint answered HTTP %d", h.LastStatusCode)
	case notifyKindRateLimited:
		return "the endpoint is rate limiting (HTTP 429)"
	case notifyKindTimeout:
		return "the endpoint did not answer in time"
	case notifyKindNetwork:
		return "the endpoint could not be reached"
	case notifyKindConfigInvalid:
		return "the channel's settings are refused"
	default:
		return "the send failed"
	}
}

// announceNotifyChannelFailing raises notify.channel_failing. It is routed by
// rules like any event but never to the failing channel, and when no rule
// reaches another channel it goes to every other enabled channel.
func (s *Server) announceNotifyChannelFailing(c model.NotifyChannel, h store.NotifyChannelHealth) {
	name := notifyChannelLabel(c)
	title := "Lattice notification channel failing: " + name
	body := fmt.Sprintf("%s (%s) has failed %d deliveries in a row since %s: %s. Alerts routed only to it are not arriving. Check its settings, then send a test from Notifications.",
		name, c.Kind, h.ConsecutiveFailures, h.FailingSince.UTC().Format(time.RFC3339), describeNotifyFailure(h))
	s.enqueueNotifyEvent(EventNotifyChannelFailing, title, body, notifyEnqueue{source: store.NotifySourceServer, exclude: c.ID, fanOut: true})
}

func (s *Server) announceNotifyChannelOK(c model.NotifyChannel, prev store.NotifyChannelHealth, at time.Time) {
	name := notifyChannelLabel(c)
	title := "Lattice notification channel recovered: " + name
	body := fmt.Sprintf("%s (%s) delivered again at %s after failing since %s.", name, c.Kind, at.UTC().Format(time.RFC3339), prev.FailingSince.UTC().Format(time.RFC3339))
	if prev.FailingSince.IsZero() {
		body = fmt.Sprintf("%s (%s) delivered again at %s.", name, c.Kind, at.UTC().Format(time.RFC3339))
	}
	s.enqueueNotifyEvent(EventNotifyChannelOK, title, body, notifyEnqueue{source: store.NotifySourceServer, fanOut: true})
}

// afterNotifySettled runs once per settled delivery: it plans the rule's
// fallback when needed and closes the inbound webhook's record when the
// event's last delivery has settled.
func (s *Server) afterNotifySettled(row store.NotifyDelivery) {
	s.planNotifyFallback(row)
	s.settleNotifyWebhookRecord(row)
}

// planNotifyFallback plans the rule's fallback when this settle leaves every
// primary delivery of the rule's message failed.
func (s *Server) planNotifyFallback(row store.NotifyDelivery) {
	if row.Outcome != store.NotifyOutcomeFailed || row.Role != store.NotifyRolePrimary || row.RuleID == "" {
		return
	}
	opts := s.store.NotifyRuleOptionsByRule()[row.RuleID]
	if opts.FallbackChannelID == "" {
		return
	}
	r := &s.outbox
	r.healthMu.Lock()
	defer r.healthMu.Unlock()
	var failed []string
	for _, sib := range s.store.NotifyDeliveries(store.NotifyDeliveryFilter{EventID: row.EventID}) {
		if sib.RuleID != row.RuleID {
			continue
		}
		switch {
		case sib.Role == store.NotifyRoleFallback:
			return // already planned
		case sib.Role != store.NotifyRolePrimary:
			continue
		case !sib.Settled(), sib.Outcome == store.NotifyOutcomeSent:
			return // still trying, or the message got through
		}
		failed = append(failed, sib.ChannelName)
	}
	sort.Strings(failed)
	now := s.now()
	fallback := store.NotifyDelivery{
		ID: id.New("nd"), EventID: row.EventID, EventType: row.EventType,
		Source: row.Source, SourceID: row.SourceID, SourceRef: row.SourceRef,
		RuleID: row.RuleID, RuleName: row.RuleName, Role: store.NotifyRoleFallback,
		FallbackFor: strings.Join(failed, ", "), Outcome: store.NotifyOutcomePlanned,
		NextAttemptAt: now, Title: row.Title,
		Body:      row.Body + "\n\nSent through the fallback channel because " + strings.Join(failed, ", ") + " did not deliver it.",
		CreatedAt: now,
	}
	channel, found := s.notifyChannelByID(opts.FallbackChannelID)
	fallback.ChannelID = opts.FallbackChannelID
	if found {
		fallback.ChannelName, fallback.ChannelKind = channel.Name, channel.Kind
	}
	if err := s.store.RecordNotifyDeliveries([]store.NotifyDelivery{fallback}); err != nil {
		s.logger.Printf("notify: record fallback for %s: %v", row.ID, err)
		return
	}
	s.wakeNotifyOutbox()
}

// settleNotifyWebhookRecord closes an inbound webhook's own delivery record
// once every delivery of the event it fired has settled, so the webhook page
// reports what the outbox did, retries and fallbacks included.
func (s *Server) settleNotifyWebhookRecord(row store.NotifyDelivery) {
	if row.Source != store.NotifySourceWebhook || row.SourceID == "" || row.SourceRef == "" {
		return
	}
	r := &s.outbox
	r.healthMu.Lock()
	defer r.healthMu.Unlock()
	delivered, failed := 0, 0
	for _, sib := range s.store.NotifyDeliveries(store.NotifyDeliveryFilter{EventID: row.EventID}) {
		switch sib.Outcome {
		case store.NotifyOutcomePlanned:
			return // the record settles with the event's last delivery
		case store.NotifyOutcomeSent:
			delivered++
		case store.NotifyOutcomeFailed:
			failed++
		}
	}
	outcome, reason := store.NotifyWebhookAccepted, ""
	switch {
	case delivered == 0 && failed > 0:
		outcome = store.NotifyWebhookFailed
		reason = fmt.Sprintf("all %d channel sends failed", failed)
	case failed > 0:
		outcome = store.NotifyWebhookPartial
		reason = fmt.Sprintf("%d of %d channel sends failed", failed, delivered+failed)
	}
	if err := s.store.SettleNotifyWebhookDelivery(row.SourceID, row.SourceRef, outcome, reason, delivered); err != nil {
		s.logger.Printf("notify webhook delivery settle: %v", err)
	}
}

// reconcileNotifyOutbox runs once at start, before the first send: every
// delivery still owed a send is marked for redrive inside the horizon or
// settled failed outside it, so the receipts are never left "planned" by a
// restart. It returns how many rows wait for redrive; New wakes the drainer
// for them with the other background loops.
func (s *Server) reconcileNotifyOutbox() int {
	pending := s.store.UnsettledNotifyDeliveries()
	if len(pending) == 0 {
		return 0
	}
	now := s.now()
	changed := make([]store.NotifyDelivery, 0, len(pending))
	redrive := 0
	for _, row := range pending {
		switch {
		case row.Role == store.NotifyRoleTest || now.Sub(row.CreatedAt) > notifyRedriveHorizon:
			row.Outcome = store.NotifyOutcomeFailed
			row.Reason = "interrupted by restart, not retried"
			row.SettledAt = now
			row.NextAttemptAt = time.Time{}
		default:
			row.Redriven = true
			row.Reason = "redriven after restart"
			if row.NextAttemptAt.Before(now) {
				row.NextAttemptAt = now
			}
			redrive++
		}
		changed = append(changed, row)
	}
	if err := s.store.RecordNotifyDeliveries(changed); err != nil {
		s.logger.Printf("notify: reconcile outbox: %v", err)
	}
	s.logger.Printf("notify: outbox at start: %d redriven, %d settled as interrupted", redrive, len(changed)-redrive)
	return redrive
}
