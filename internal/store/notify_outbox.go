package store

import (
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// The notification outbox: one record per (event, channel) delivery with a
// receipt per attempt, the health of each channel, and the alert digest's
// queued lines.
//
// All three live on the record-level bolt path when the hot store is on and
// in memory when it is off. They never enter the JSON state. A delivery is
// written when it is planned, once per attempt and once when it settles, and
// health moves on every attempt, success included; in the JSON state each of
// those writes would re-encrypt, rewrite and fsync the whole state file under
// the store lock, which is the write storm a101 shipped and a102 removed
// (design-notify-abstraction section 6, "Storage"). On bolt each is one small
// transaction, and the delivery and its channel's health share it.
//
// Without the hot store (tests, a pathless store, a server started without
// -runtime-bolt-hot-store) the outbox is memory only: deliveries still run,
// retry and settle, but a restart forgets them and nothing is redriven.
//
// These are operational history, not the evidence record. The audit stream
// stays the evidence record.
//
// yagni: the buckets are created on first write and are not part of
// boltStateBuckets, so a whole-state import (ImportState, the one-time
// subscription secret migration) neither resets nor carries them. The worst
// case is a delivery history that starts empty after that migration; joining
// the import is the upgrade if that ever matters.

const (
	NotifyOutcomePlanned = "planned"
	NotifyOutcomeSent    = "sent"
	NotifyOutcomeFailed  = "failed"
	// NotifyOutcomeNoRoute records an event that reached no channel, so "why
	// was I not told" has an answer instead of a silent drop.
	NotifyOutcomeNoRoute = "no_route"
	// NotifyOutcomeSuppressed records a message the server decided not to
	// send: an incident's message held by a maintenance window or a snooze,
	// or damped while it flaps. Stored and bounded like no_route rows.
	NotifyOutcomeSuppressed = "suppressed"

	NotifyRolePrimary  = "primary"
	NotifyRoleFallback = "fallback"
	NotifyRoleTest     = "test"

	NotifySourceServer   = "server"
	NotifySourcePlugin   = "plugin"
	NotifySourceWebhook  = "webhook"
	NotifySourceOperator = "operator"

	// MaxNotifyDeliveries and NotifyDeliveryFloorPerSource are the D5
	// defaults of the notify design: at least the last 50 deliveries of each
	// source, up to 1000 in total. A source is the server, one plugin, one
	// inbound webhook or the operator's tests, so a once-a-day webhook keeps
	// the 50-attempt window its own ring gave it. Eviction takes the oldest
	// settled delivery of a source holding more than the floor; an unsettled
	// delivery is never evicted, since it is still owed a send.
	MaxNotifyDeliveries          = 1000
	NotifyDeliveryFloorPerSource = 50

	// MaxNotifyNoRouteDeliveries bounds the no_route rows on their own. They
	// answer "why was I not told", but they are not deliveries: they do not
	// count toward a source's floor, they go first when the total bound bites,
	// and past this many the oldest go even when the outbox has room, so an
	// unrouted chatty type (ssh.login, proxy.quota) cannot push out the
	// receipts of pages that did go out.
	MaxNotifyNoRouteDeliveries = 100
	// NotifyNoRouteCollapseWindow folds repeats of one unrouted event (same
	// source, event type and reason) into the row first written for it, so
	// the bounded no_route rows keep one line per unrouted type per hour
	// rather than a hundred copies of the chattiest one.
	NotifyNoRouteCollapseWindow = time.Hour
	// notifyNoRoutePersistEvery is how often a collapsed row's repeat count
	// is written. Between writes the count moves in memory only: a no_route
	// row is owed nothing, so a crash costs at most this much of a counter,
	// and an unrouted storm stops costing a bolt fsync on the emitter's path
	// per event.
	notifyNoRoutePersistEvery = time.Minute

	// MaxNotifyTitleBytes and MaxNotifyBodyBytes bound the message a delivery
	// stores and sends. Telegram refuses more than 4096 characters, Discord
	// 2000 and Bark rides an APNs payload of 4 KiB, so a longer message
	// mostly never arrived anyway; the bound keeps 1000 rows times a
	// plugin's arbitrary body out of state-hot.db and the Sent response.
	MaxNotifyTitleBytes = 512
	MaxNotifyBodyBytes  = 4096

	// MaxNotifyUnsettledPerSource bounds the deliveries one plugin may have
	// owed a send at once. A plugin's notify.send returns as soon as the
	// message is stored, so against a channel that is down a looping plugin
	// would otherwise grow the never-evicted unsettled set for the 2.5
	// minutes each retry schedule runs. Server events are never refused, and
	// inbound webhooks have their own firing limit.
	MaxNotifyUnsettledPerSource = 200

	// maxNotifyDigestLines bounds the persisted digest queue. The sweep
	// flushes it every 20 s, so reaching the bound means the sweep stopped;
	// the oldest lines go first.
	maxNotifyDigestLines = 500

	notifyKeyLayout = "2006-01-02T15:04:05.000000000Z"
)

// NotifyAttempt is the receipt of one send. Kind is a server-classified
// failure kind and Status the upstream HTTP status, never the transport error
// or the upstream body: both can carry the channel credential or text the
// remote side chose.
type NotifyAttempt struct {
	At         time.Time `json:"at"`
	OK         bool      `json:"ok"`
	Kind       string    `json:"kind,omitempty"`
	Status     int       `json:"status,omitempty"`
	DurationMS int64     `json:"duration_ms"`
}

// NotifyDelivery is one message to one channel. Title and Body are the
// rendered message, so the operator can see what was sent; channel config is
// never copied here.
type NotifyDelivery struct {
	ID        string `json:"id"`
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	Source    string `json:"source"`
	// SourceID names the plugin or webhook behind a plugin or webhook source.
	SourceID string `json:"source_id,omitempty"`
	// SourceRef is the inbound webhook's own delivery record, settled once
	// every delivery of the event has settled.
	SourceRef string `json:"source_ref,omitempty"`
	RuleID    string `json:"rule_id,omitempty"`
	RuleName  string `json:"rule_name,omitempty"`
	// Channel fields are a snapshot at plan time, so a renamed or deleted
	// channel still reads correctly in history.
	ChannelID   string `json:"channel_id,omitempty"`
	ChannelName string `json:"channel_name,omitempty"`
	ChannelKind string `json:"channel_kind,omitempty"`
	Role        string `json:"role,omitempty"`
	// FallbackFor names the channel whose failure this fallback delivery
	// stands in for.
	FallbackFor string `json:"fallback_for,omitempty"`
	// FallbackOf is the delivery a channel's critical fallback stands in for
	// (one failed delivery, linked so the Sent log can show both). A rule's
	// fallback, which stands in for every primary of the rule, leaves it
	// empty.
	FallbackOf    string          `json:"fallback_of,omitempty"`
	Outcome       string          `json:"outcome"`
	Reason        string          `json:"reason,omitempty"`
	Attempts      []NotifyAttempt `json:"attempts,omitempty"`
	NextAttemptAt time.Time       `json:"next_attempt_at,omitzero"`
	Redriven      bool            `json:"redriven,omitempty"`
	Title         string          `json:"title,omitempty"`
	Body          string          `json:"body,omitempty"`
	// Truncated is set when the message was cut to MaxNotifyTitleBytes and
	// MaxNotifyBodyBytes; what is stored is what was sent.
	Truncated bool      `json:"truncated,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	SettledAt time.Time `json:"settled_at,omitzero"`
	// Repeats counts the later occurrences a no_route row has folded in
	// (NotifyNoRouteCollapseWindow); LastSeenAt is the latest of them, and
	// Title and Body are its text.
	Repeats    int       `json:"repeats,omitempty"`
	LastSeenAt time.Time `json:"last_seen_at,omitzero"`
	// BarkLevel overrides a Bark channel's own interruption level for this
	// delivery; an incident escalation sends at critical. Other channel
	// kinds ignore it.
	BarkLevel string `json:"bark_level,omitempty"`
	// HeldUntil is set when the rule's quiet hours held the delivery; its
	// first attempt waits until then.
	HeldUntil time.Time `json:"held_until,omitzero"`
	// IncidentIDs names the incidents an incident message reports, so a
	// message quiet hours held can be judged again when the window ends.
	IncidentIDs []string `json:"incident_ids,omitempty"`
}

// Unsent reports a row that records a message nobody was sent: no rule
// routed it, or the server suppressed it. Such rows are bounded and folded
// together, apart from real deliveries.
func (d NotifyDelivery) Unsent() bool {
	return d.Outcome == NotifyOutcomeNoRoute || d.Outcome == NotifyOutcomeSuppressed
}

// sourceKey is what the per-source floor counts by.
func (d NotifyDelivery) sourceKey() string {
	return d.Source + "/" + d.SourceID
}

// noRouteKey is what repeats of one unrouted or suppressed event collapse
// by.
func (d NotifyDelivery) noRouteKey() string {
	return d.Outcome + "/" + d.Source + "/" + d.SourceID + "/" + d.EventType + "/" + d.Reason
}

// TruncateUTF8 cuts s to at most limit bytes without splitting a character,
// appending a marker when it cuts. It reports whether it cut.
func TruncateUTF8(s string, limit int) (string, bool) {
	if len(s) <= limit {
		return s, false
	}
	const marker = " [truncated]"
	if limit <= len(marker) {
		return "", true
	}
	cut := limit - len(marker)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + marker, true
}

// ClampNotifyText bounds a message to MaxNotifyTitleBytes and
// MaxNotifyBodyBytes. It is idempotent, so the store can apply it again to
// whatever the server already clamped.
func ClampNotifyText(title, body string) (string, string, bool) {
	t, cutTitle := TruncateUTF8(title, MaxNotifyTitleBytes)
	b, cutBody := TruncateUTF8(body, MaxNotifyBodyBytes)
	return t, b, cutTitle || cutBody
}

func clampNotifyDelivery(d NotifyDelivery) NotifyDelivery {
	var cut bool
	d.Title, d.Body, cut = ClampNotifyText(d.Title, d.Body)
	d.Truncated = d.Truncated || cut
	return d
}

// Settled reports whether the delivery has reached a terminal outcome.
func (d NotifyDelivery) Settled() bool {
	return d.Outcome != NotifyOutcomePlanned
}

// NotifyChannelHealth is the delivery health of one channel. It is not part of
// model.NotifyChannel: that record sits in the JSON state with an encrypted
// config, so moving health on it would rewrite the state file on every send.
type NotifyChannelHealth struct {
	ChannelID       string    `json:"channel_id"`
	LastAttemptAt   time.Time `json:"last_attempt_at,omitzero"`
	LastOKAt        time.Time `json:"last_ok_at,omitzero"`
	LastFailureAt   time.Time `json:"last_failure_at,omitzero"`
	LastFailureKind string    `json:"last_failure_kind,omitempty"`
	LastStatusCode  int       `json:"last_status_code,omitempty"`
	// ConsecutiveFailures counts deliveries that settled failed since the
	// last success. A transient failure that a retry recovers does not count.
	ConsecutiveFailures int `json:"consecutive_failures"`
	// FailingSince is when the current run of failures began; zero while the
	// channel is healthy.
	FailingSince time.Time `json:"failing_since,omitzero"`
	// Announced is set while notify.channel_failing has gone out for the
	// current run, so the first success sends notify.channel_ok.
	Announced   bool      `json:"announced,omitempty"`
	AnnouncedAt time.Time `json:"announced_at,omitzero"`
	// LastFallbackAt is when a critical message this channel failed was last
	// handed to its fallback channel (LastFallbackChannelID); Fallbacks
	// counts those hand-offs.
	LastFallbackAt        time.Time `json:"last_fallback_at,omitzero"`
	LastFallbackChannelID string    `json:"last_fallback_channel_id,omitempty"`
	Fallbacks             int       `json:"fallbacks,omitempty"`
}

// NotifyDigestLine is one queued line of the alert digest. The decision behind
// it is already on disk (the sing-box episode, the monitor history), so the
// line is stored too: a process killed before the sweep's flush would
// otherwise owe a page nobody sends.
type NotifyDigestLine struct {
	Key       string    `json:"key"`
	EventType string    `json:"event_type"`
	SortKey   string    `json:"sort_key,omitempty"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	Line      string    `json:"line"`
	QueuedAt  time.Time `json:"queued_at"`
}

// NotifyDeliveryFilter narrows NotifyDeliveries. Empty fields match anything.
type NotifyDeliveryFilter struct {
	Outcome   string
	ChannelID string
	EventType string
	EventID   string
	Source    string
	SourceID  string
	// Query matches title, body, event type, channel name or rule name,
	// case-insensitively.
	Query string
	Limit int
}

// notifyOutbox is the in-memory copy. With the hot store on it mirrors bolt
// and is loaded from it on first use; without it, it is the only copy.
type notifyOutbox struct {
	loaded     bool
	loadedFrom *BoltStateStore
	rows       map[string]NotifyDelivery
	// order holds row keys oldest first; keys sort as creation instants.
	order  []string
	health map[string]NotifyChannelHealth
	digest map[string]NotifyDigestLine
	// byEvent and unsettled index rows, so settling a delivery (which reads
	// every delivery of its event) and a drain pass (which reads every
	// unsettled one) do not walk up to MaxNotifyDeliveries rows under the
	// store lock.
	byEvent   map[string]map[string]struct{}
	unsettled map[string]struct{}
	// noRouteLatest maps a noRouteKey to the newest no_route row, the one a
	// repeat folds into. noRouteWritten is when each no_route row was last
	// written to bolt, which paces the writes of its repeat count.
	noRouteLatest  map[string]string
	noRouteWritten map[string]time.Time
}

func notifyDeliveryKey(d NotifyDelivery) string {
	return d.CreatedAt.UTC().Format(notifyKeyLayout) + "/" + d.ID
}

// notifyDeliveryBefore orders rows as their keys sort, without formatting
// the keys.
func notifyDeliveryBefore(a, b NotifyDelivery) bool {
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return a.CreatedAt.Before(b.CreatedAt)
	}
	return a.ID < b.ID
}

// NewNotifyDigestKey is a sortable key for a digest line queued at t.
func NewNotifyDigestKey(t time.Time, suffix string) string {
	return t.UTC().Format(notifyKeyLayout) + "/" + suffix
}

// notifyOutboxLocked returns the outbox, loading it from bolt the first time
// the hot store is seen. Rows written to memory before the hot store was
// enabled are carried into bolt rather than dropped. After Close the sidecar
// is gone and the outbox keeps working from memory, never from the JSON file.
func (s *Store) notifyOutboxLocked() *notifyOutbox {
	o := &s.notify
	if !o.loaded {
		o.rows = map[string]NotifyDelivery{}
		o.health = map[string]NotifyChannelHealth{}
		o.digest = map[string]NotifyDigestLine{}
		o.noRouteWritten = map[string]time.Time{}
		o.reindex()
		o.loaded = true
	}
	bs := s.runtimeBoltHot
	if bs == nil || o.loadedFrom == bs {
		return o
	}
	rows, health, digest, err := bs.LoadNotifyOutbox()
	if err != nil {
		// A bucket that cannot be read is a history that starts empty, not a
		// boot failure: notifications must still go out.
		rows, health, digest = nil, nil, nil
	}
	carry := notifyOutboxWrite{}
	for _, d := range o.rows {
		carry.putRows = append(carry.putRows, d)
	}
	for _, h := range o.health {
		carry.putHealth = append(carry.putHealth, h)
	}
	for _, l := range o.digest {
		carry.putDigest = append(carry.putDigest, l)
	}
	for _, d := range rows {
		if _, ok := o.rows[d.ID]; !ok {
			o.rows[d.ID] = d
		}
	}
	for _, h := range health {
		if _, ok := o.health[h.ChannelID]; !ok {
			o.health[h.ChannelID] = h
		}
	}
	for _, l := range digest {
		if _, ok := o.digest[l.Key]; !ok {
			o.digest[l.Key] = l
		}
	}
	o.reindex()
	o.loadedFrom = bs
	if !carry.empty() {
		_ = bs.WriteNotifyOutbox(carry)
	}
	return o
}

func (o *notifyOutbox) rebuildOrder() {
	o.order = o.order[:0]
	for _, d := range o.rows {
		o.order = append(o.order, notifyDeliveryKey(d))
	}
	sort.Strings(o.order)
}

// reindex rebuilds the order and every index from rows.
func (o *notifyOutbox) reindex() {
	o.byEvent = map[string]map[string]struct{}{}
	o.unsettled = map[string]struct{}{}
	o.noRouteLatest = map[string]string{}
	for _, d := range o.rows {
		o.indexLocked(d)
	}
	o.rebuildOrder()
}

// indexLocked adds a row, already in rows, to the indexes.
func (o *notifyOutbox) indexLocked(d NotifyDelivery) {
	ids := o.byEvent[d.EventID]
	if ids == nil {
		ids = map[string]struct{}{}
		o.byEvent[d.EventID] = ids
	}
	ids[d.ID] = struct{}{}
	if d.Settled() {
		delete(o.unsettled, d.ID)
	} else {
		o.unsettled[d.ID] = struct{}{}
	}
	if d.Unsent() {
		key := d.noRouteKey()
		if cur, ok := o.rows[o.noRouteLatest[key]]; !ok || !cur.CreatedAt.After(d.CreatedAt) {
			o.noRouteLatest[key] = d.ID
		}
	}
}

// unindexLocked removes a row from the indexes.
func (o *notifyOutbox) unindexLocked(d NotifyDelivery) {
	if ids := o.byEvent[d.EventID]; ids != nil {
		delete(ids, d.ID)
		if len(ids) == 0 {
			delete(o.byEvent, d.EventID)
		}
	}
	delete(o.unsettled, d.ID)
	if key := d.noRouteKey(); o.noRouteLatest[key] == d.ID {
		delete(o.noRouteLatest, key)
	}
}

func idFromNotifyKey(key string) string {
	if i := strings.LastIndexByte(key, '/'); i >= 0 {
		return key[i+1:]
	}
	return key
}

// commit writes w to bolt when the hot store is on. Memory is updated by the
// caller only after commit succeeds, so a failed write never leaves memory
// claiming what disk does not hold. The one exception is a no_route row's
// repeat count (RecordNotifyNoRoute), which is owed nothing.
func (s *Store) commitNotifyOutboxLocked(w notifyOutboxWrite) error {
	if w.empty() || s.runtimeBoltHot == nil {
		return nil
	}
	return s.runtimeBoltHot.WriteNotifyOutbox(w)
}

// evictionLocked picks the rows to drop so the outbox fits its bounds, given
// rows about to be added. The caller deletes them in the same write as the
// insert.
//
// no_route rows go first, oldest first: past MaxNotifyNoRouteDeliveries even
// when the outbox has room, and ahead of any delivery when it has none. Then
// the oldest settled delivery of a source holding more than its floor, and
// last, should every source be at its floor, the oldest settled delivery. An
// unsettled delivery is never evicted.
func (o *notifyOutbox) evictionLocked(adding []NotifyDelivery) []NotifyDelivery {
	added := map[string]bool{}
	newRows, newNoRoute := 0, 0
	for _, d := range adding {
		added[d.ID] = true
		if _, ok := o.rows[d.ID]; !ok {
			newRows++
			if d.Unsent() {
				newNoRoute++
			}
		}
	}
	excess := len(o.rows) + newRows - MaxNotifyDeliveries
	if excess <= 0 && newNoRoute == 0 {
		return nil
	}
	noRoute := newNoRoute
	perSource := map[string]int{}
	for _, d := range o.rows {
		if d.Unsent() {
			noRoute++
		} else {
			perSource[d.sourceKey()]++
		}
	}
	for _, d := range adding {
		if _, ok := o.rows[d.ID]; !ok && !d.Unsent() {
			perSource[d.sourceKey()]++
		}
	}
	excessNoRoute := noRoute - MaxNotifyNoRouteDeliveries
	if excess <= 0 && excessNoRoute <= 0 {
		return nil
	}
	var victims []NotifyDelivery
	taken := map[string]bool{}
	for _, key := range o.order {
		if excess <= 0 && excessNoRoute <= 0 {
			break
		}
		d := o.rows[idFromNotifyKey(key)]
		if !d.Unsent() || added[d.ID] {
			continue
		}
		taken[d.ID] = true
		victims = append(victims, d)
		excess--
		excessNoRoute--
	}
	pick := func(respectFloor bool) {
		for _, key := range o.order {
			if excess <= 0 {
				return
			}
			d := o.rows[idFromNotifyKey(key)]
			if taken[d.ID] || added[d.ID] || !d.Settled() || d.Unsent() {
				continue
			}
			if respectFloor && perSource[d.sourceKey()] <= NotifyDeliveryFloorPerSource {
				continue
			}
			taken[d.ID] = true
			perSource[d.sourceKey()]--
			victims = append(victims, d)
			excess--
		}
	}
	pick(true)
	// Every source is at its floor and the outbox is still over: there are
	// more than MaxNotifyDeliveries/floor sources, which no deployment has.
	// Take the oldest settled rows regardless.
	pick(false)
	return victims
}

func clampNotifyDeliveries(rows []NotifyDelivery) []NotifyDelivery {
	out := make([]NotifyDelivery, len(rows))
	for i, d := range rows {
		out[i] = clampNotifyDelivery(d)
	}
	return out
}

// RecordNotifyDeliveries stores new or replaced deliveries in one write,
// evicting what the bounds require in the same write.
func (s *Store) RecordNotifyDeliveries(rows []NotifyDelivery) error {
	if len(rows) == 0 {
		return nil
	}
	rows = clampNotifyDeliveries(rows)
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.notifyOutboxLocked()
	victims := o.evictionLocked(rows)
	w := notifyOutboxWrite{putRows: rows, delRows: victims}
	if err := s.commitNotifyOutboxLocked(w); err != nil {
		return err
	}
	o.applyLocked(w)
	return nil
}

// RecordNotifyNoRoute stores an event that reached no channel. A repeat of
// the same unrouted event (source, event type and reason) less than
// NotifyNoRouteCollapseWindow after the row first written for it folds into
// that row: the count goes up and the text becomes the latest. The folded
// row is written to bolt at most once per notifyNoRoutePersistEvery.
func (s *Store) RecordNotifyNoRoute(row NotifyDelivery) error {
	row.Outcome = NotifyOutcomeNoRoute
	return s.recordNotifyUnsent(row)
}

// RecordNotifySuppressed stores a message the server held back, with the
// reason, folded and bounded exactly like an unrouted event.
func (s *Store) RecordNotifySuppressed(row NotifyDelivery) error {
	row.Outcome = NotifyOutcomeSuppressed
	return s.recordNotifyUnsent(row)
}

func (s *Store) recordNotifyUnsent(row NotifyDelivery) error {
	row = clampNotifyDelivery(row)
	if row.SettledAt.IsZero() {
		row.SettledAt = row.CreatedAt
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.notifyOutboxLocked()
	if id, ok := o.noRouteLatest[row.noRouteKey()]; ok {
		first, ok := o.rows[id]
		if ok && !row.CreatedAt.Before(first.CreatedAt) && row.CreatedAt.Sub(first.CreatedAt) < NotifyNoRouteCollapseWindow {
			next := first
			next.Repeats++
			next.LastSeenAt = row.CreatedAt
			next.Title, next.Body, next.Truncated = row.Title, row.Body, row.Truncated
			if written, ok := o.noRouteWritten[id]; ok && row.CreatedAt.Sub(written) < notifyNoRoutePersistEvery {
				o.rows[id] = next
				return nil
			}
			w := notifyOutboxWrite{putRows: []NotifyDelivery{next}}
			if err := s.commitNotifyOutboxLocked(w); err != nil {
				return err
			}
			o.applyLocked(w)
			o.noRouteWritten[id] = row.CreatedAt
			return nil
		}
	}
	w := notifyOutboxWrite{putRows: []NotifyDelivery{row}, delRows: o.evictionLocked([]NotifyDelivery{row})}
	if err := s.commitNotifyOutboxLocked(w); err != nil {
		return err
	}
	o.applyLocked(w)
	o.noRouteWritten[row.ID] = row.CreatedAt
	return nil
}

// PutNotifyDelivery stores one delivery and, when health is non-nil, its
// channel's health, in one write.
func (s *Store) PutNotifyDelivery(row NotifyDelivery, health *NotifyChannelHealth) error {
	row = clampNotifyDelivery(row)
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.notifyOutboxLocked()
	w := notifyOutboxWrite{putRows: []NotifyDelivery{row}, delRows: o.evictionLocked([]NotifyDelivery{row})}
	if health != nil {
		w.putHealth = []NotifyChannelHealth{*health}
	}
	if err := s.commitNotifyOutboxLocked(w); err != nil {
		return err
	}
	o.applyLocked(w)
	return nil
}

func (o *notifyOutbox) applyLocked(w notifyOutboxWrite) {
	reorder := false
	for _, d := range w.delRows {
		if prev, ok := o.rows[d.ID]; ok {
			o.unindexLocked(prev)
			delete(o.rows, d.ID)
			delete(o.noRouteWritten, d.ID)
			reorder = true
		}
	}
	for _, d := range w.putRows {
		prev, ok := o.rows[d.ID]
		if ok {
			o.unindexLocked(prev)
		}
		if !ok || !prev.CreatedAt.Equal(d.CreatedAt) {
			reorder = true
		}
		o.rows[d.ID] = d
		o.indexLocked(d)
	}
	if reorder {
		o.rebuildOrder()
	}
	for _, id := range w.delHealth {
		delete(o.health, id)
	}
	for _, h := range w.putHealth {
		o.health[h.ChannelID] = h
	}
	for _, key := range w.delDigest {
		delete(o.digest, key)
	}
	for _, l := range w.putDigest {
		o.digest[l.Key] = l
	}
}

// NotifyDelivery returns one delivery by id.
func (s *Store) NotifyDelivery(id string) (NotifyDelivery, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.notifyOutboxLocked().rows[id]
	return cloneNotifyDelivery(d), ok
}

// NotifyDeliveries returns deliveries newest first, filtered and limited. An
// event id filter reads that event's rows from the index.
func (s *Store) NotifyDeliveries(f NotifyDeliveryFilter) []NotifyDelivery {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.notifyOutboxLocked()
	query := strings.ToLower(strings.TrimSpace(f.Query))
	candidates := o.order
	if f.EventID != "" {
		ids := o.byEvent[f.EventID]
		candidates = make([]string, 0, len(ids))
		for id := range ids {
			candidates = append(candidates, notifyDeliveryKey(o.rows[id]))
		}
		sort.Strings(candidates)
	}
	out := []NotifyDelivery{}
	for i := len(candidates) - 1; i >= 0; i-- {
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
		d := o.rows[idFromNotifyKey(candidates[i])]
		if f.Outcome != "" && d.Outcome != f.Outcome {
			continue
		}
		if f.ChannelID != "" && d.ChannelID != f.ChannelID {
			continue
		}
		if f.EventType != "" && d.EventType != f.EventType {
			continue
		}
		if f.EventID != "" && d.EventID != f.EventID {
			continue
		}
		if f.Source != "" && d.Source != f.Source {
			continue
		}
		if f.SourceID != "" && d.SourceID != f.SourceID {
			continue
		}
		if query != "" && !notifyDeliveryMatches(d, query) {
			continue
		}
		out = append(out, cloneNotifyDelivery(d))
	}
	return out
}

func notifyDeliveryMatches(d NotifyDelivery, query string) bool {
	for _, field := range []string{d.Title, d.Body, d.EventType, d.ChannelName, d.RuleName} {
		if strings.Contains(strings.ToLower(field), query) {
			return true
		}
	}
	return false
}

// UnsettledNotifyDeliveries returns deliveries still owed a send, oldest
// first.
func (s *Store) UnsettledNotifyDeliveries() []NotifyDelivery {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.notifyOutboxLocked()
	out := make([]NotifyDelivery, 0, len(o.unsettled))
	for id := range o.unsettled {
		out = append(out, cloneNotifyDelivery(o.rows[id]))
	}
	sort.Slice(out, func(i, j int) bool { return notifyDeliveryBefore(out[i], out[j]) })
	return out
}

// NotifyUnsettledCount is how many deliveries of one source are still owed a
// send.
func (s *Store) NotifyUnsettledCount(source, sourceID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.notifyOutboxLocked()
	n := 0
	for id := range o.unsettled {
		if d := o.rows[id]; d.Source == source && d.SourceID == sourceID {
			n++
		}
	}
	return n
}

// NotifyChannelHealth returns one channel's health.
func (s *Store) NotifyChannelHealth(channelID string) (NotifyChannelHealth, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.notifyOutboxLocked().health[channelID]
	return h, ok
}

// NotifyChannelHealths returns every channel's health keyed by channel id.
func (s *Store) NotifyChannelHealths() map[string]NotifyChannelHealth {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.notifyOutboxLocked()
	out := make(map[string]NotifyChannelHealth, len(o.health))
	for id, h := range o.health {
		out[id] = h
	}
	return out
}

// deleteNotifyChannelHealthLocked drops a deleted channel's health. Its
// deliveries stay: they are history and carry their own channel snapshot.
func (s *Store) deleteNotifyChannelHealthLocked(channelID string) error {
	o := s.notifyOutboxLocked()
	if _, ok := o.health[channelID]; !ok {
		return nil
	}
	w := notifyOutboxWrite{delHealth: []string{channelID}}
	if err := s.commitNotifyOutboxLocked(w); err != nil {
		return err
	}
	o.applyLocked(w)
	return nil
}

// QueueNotifyDigestLine stores a digest line until the sweep flushes it.
func (s *Store) QueueNotifyDigestLine(line NotifyDigestLine) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.notifyOutboxLocked()
	w := notifyOutboxWrite{putDigest: []NotifyDigestLine{line}}
	if len(o.digest) >= maxNotifyDigestLines {
		keys := make([]string, 0, len(o.digest))
		for key := range o.digest {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		w.delDigest = keys[:len(keys)-maxNotifyDigestLines+1]
	}
	if err := s.commitNotifyOutboxLocked(w); err != nil {
		return err
	}
	o.applyLocked(w)
	return nil
}

// NotifyDigestLines returns the queued digest lines, oldest first.
func (s *Store) NotifyDigestLines() []NotifyDigestLine {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.notifyOutboxLocked()
	out := make([]NotifyDigestLine, 0, len(o.digest))
	for _, l := range o.digest {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// RemoveNotifyDigestLines drops digest lines once their message is in the
// outbox.
func (s *Store) RemoveNotifyDigestLines(keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.notifyOutboxLocked()
	w := notifyOutboxWrite{delDigest: keys}
	if err := s.commitNotifyOutboxLocked(w); err != nil {
		return err
	}
	o.applyLocked(w)
	return nil
}

func cloneNotifyDelivery(d NotifyDelivery) NotifyDelivery {
	if d.Attempts != nil {
		d.Attempts = append([]NotifyAttempt(nil), d.Attempts...)
	}
	if d.IncidentIDs != nil {
		d.IncidentIDs = append([]string(nil), d.IncidentIDs...)
	}
	return d
}

// notifyOutboxWrite is one transaction's worth of outbox changes.
type notifyOutboxWrite struct {
	putRows   []NotifyDelivery
	delRows   []NotifyDelivery
	putHealth []NotifyChannelHealth
	delHealth []string
	putDigest []NotifyDigestLine
	delDigest []string
}

func (w notifyOutboxWrite) empty() bool {
	return len(w.putRows) == 0 && len(w.delRows) == 0 && len(w.putHealth) == 0 &&
		len(w.delHealth) == 0 && len(w.putDigest) == 0 && len(w.delDigest) == 0
}

// NotifyOutboxDurable reports whether the outbox survives a restart, which it
// does only on the bolt hot store.
func (s *Store) NotifyOutboxDurable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runtimeBoltHot != nil
}

// NotifyDeliveryCount is how many deliveries the outbox holds.
func (s *Store) NotifyDeliveryCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.notifyOutboxLocked().rows)
}
