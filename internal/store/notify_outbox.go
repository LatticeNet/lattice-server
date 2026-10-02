package store

import (
	"sort"
	"strings"
	"time"
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
	FallbackFor   string          `json:"fallback_for,omitempty"`
	Outcome       string          `json:"outcome"`
	Reason        string          `json:"reason,omitempty"`
	Attempts      []NotifyAttempt `json:"attempts,omitempty"`
	NextAttemptAt time.Time       `json:"next_attempt_at,omitzero"`
	Redriven      bool            `json:"redriven,omitempty"`
	Title         string          `json:"title,omitempty"`
	Body          string          `json:"body,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	SettledAt     time.Time       `json:"settled_at,omitzero"`
}

// sourceKey is what the per-source floor counts by.
func (d NotifyDelivery) sourceKey() string {
	return d.Source + "/" + d.SourceID
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
}

func notifyDeliveryKey(d NotifyDelivery) string {
	return d.CreatedAt.UTC().Format(notifyKeyLayout) + "/" + d.ID
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
	o.rebuildOrder()
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

func idFromNotifyKey(key string) string {
	if i := strings.LastIndexByte(key, '/'); i >= 0 {
		return key[i+1:]
	}
	return key
}

// commit writes w to bolt when the hot store is on. Memory is updated by the
// caller only after commit succeeds, so a failed write never leaves memory
// claiming what disk does not hold.
func (s *Store) commitNotifyOutboxLocked(w notifyOutboxWrite) error {
	if w.empty() || s.runtimeBoltHot == nil {
		return nil
	}
	return s.runtimeBoltHot.WriteNotifyOutbox(w)
}

// evictionLocked picks the rows to drop so the outbox fits its bound, given
// rows about to be added. The caller deletes them in the same write as the
// insert.
func (o *notifyOutbox) evictionLocked(adding []NotifyDelivery) []NotifyDelivery {
	total := len(o.rows)
	for _, d := range adding {
		if _, ok := o.rows[d.ID]; !ok {
			total++
		}
	}
	excess := total - MaxNotifyDeliveries
	if excess <= 0 {
		return nil
	}
	perSource := map[string]int{}
	for _, d := range o.rows {
		perSource[d.sourceKey()]++
	}
	for _, d := range adding {
		if _, ok := o.rows[d.ID]; !ok {
			perSource[d.sourceKey()]++
		}
	}
	var victims []NotifyDelivery
	taken := map[string]bool{}
	pick := func(respectFloor bool) {
		for _, key := range o.order {
			if excess == 0 {
				return
			}
			d := o.rows[idFromNotifyKey(key)]
			if taken[d.ID] || !d.Settled() {
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

// RecordNotifyDeliveries stores new or replaced deliveries in one write,
// evicting what the bound requires in the same write.
func (s *Store) RecordNotifyDeliveries(rows []NotifyDelivery) error {
	if len(rows) == 0 {
		return nil
	}
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

// PutNotifyDelivery stores one delivery and, when health is non-nil, its
// channel's health, in one write.
func (s *Store) PutNotifyDelivery(row NotifyDelivery, health *NotifyChannelHealth) error {
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
		if _, ok := o.rows[d.ID]; ok {
			delete(o.rows, d.ID)
			reorder = true
		}
	}
	for _, d := range w.putRows {
		prev, ok := o.rows[d.ID]
		if !ok || !prev.CreatedAt.Equal(d.CreatedAt) {
			reorder = true
		}
		o.rows[d.ID] = d
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

// NotifyDeliveries returns deliveries newest first, filtered and limited.
func (s *Store) NotifyDeliveries(f NotifyDeliveryFilter) []NotifyDelivery {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.notifyOutboxLocked()
	query := strings.ToLower(strings.TrimSpace(f.Query))
	out := []NotifyDelivery{}
	for i := len(o.order) - 1; i >= 0; i-- {
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
		d := o.rows[idFromNotifyKey(o.order[i])]
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
	out := []NotifyDelivery{}
	for _, key := range o.order {
		if d := o.rows[idFromNotifyKey(key)]; !d.Settled() {
			out = append(out, cloneNotifyDelivery(d))
		}
	}
	return out
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
