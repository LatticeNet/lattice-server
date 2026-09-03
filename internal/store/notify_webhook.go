package store

import (
	"errors"
	"sort"
	"time"
)

// NotifyWebhook is an operator-authored inbound entry point that turns an HTTP
// POST from an outside caller into a notification event.
//
// The type lives here rather than in the SDK model package because nothing
// outside this server needs it: a webhook is never sent to a node, never
// crosses the plugin ABI, and never appears in an agent payload. Keeping it
// server-local also keeps the SDK pin free of a change this slice would
// otherwise have to coordinate.
//
// The security-relevant shape is that a webhook is *authored*, not *declared by
// its caller*. EventType and the two templates are set by an operator holding
// notify:send; the caller of the public endpoint supplies only bounded data for
// the templates to interpolate. That split is what stops possession of a
// webhook URL and secret from becoming the ability to send the operator an
// arbitrary message.
type NotifyWebhook struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// EventType is what the existing notification rules match on. It is fixed by
	// the operator at authoring time; a caller cannot choose or override it, so a
	// webhook can only ever raise the one event its author intended.
	EventType string `json:"event_type"`
	// TitleTemplate and BodyTemplate are the operator's message shape. They may
	// interpolate {{data.<field>}} from the caller payload plus the platform
	// variables ({{event_type}}, {{webhook_name}}, {{received_at}}).
	TitleTemplate string `json:"title_template"`
	BodyTemplate  string `json:"body_template"`
	// SecretHash is a PBKDF2 hash, in the same encoding auth.HashSecret produces
	// for storage and node tokens. The plaintext secret is returned exactly once,
	// at creation and at each rotation, and is not recoverable afterwards: a
	// reader of the state file gets no working credential, which is a stronger
	// position than the reversible envelope NotifyChannel.Config carries.
	SecretHash string    `json:"secret_hash,omitempty"`
	Enabled    bool      `json:"enabled"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Delivery outcomes. A webhook fire is accepted or rejected synchronously, then
// fanned out asynchronously, so the record carries both halves.
const (
	// NotifyWebhookAccepted means the request authenticated and produced at least
	// one planned delivery.
	NotifyWebhookAccepted = "accepted"
	// NotifyWebhookNoRoute means the request authenticated but no enabled rule and
	// channel pair matched the event. This is the state production is in today
	// (zero channels, zero rules) and it is worth showing plainly rather than
	// reporting a success that reached nobody.
	NotifyWebhookNoRoute = "no_route"
	// NotifyWebhookRejected means the request never became an event: bad secret,
	// disabled webhook, oversized or malformed payload, or rate limited.
	NotifyWebhookRejected = "rejected"
	// NotifyWebhookFailed means deliveries were planned but every channel send
	// returned an error.
	NotifyWebhookFailed = "failed"
	// NotifyWebhookPartial means some channel sends succeeded and some failed.
	NotifyWebhookPartial = "partial"
)

// NotifyWebhookDelivery is one attempt against one webhook, retained in a
// bounded per-webhook ring so the console can answer "did my webhook work"
// without scanning the audit stream.
//
// This does not replace the audit trail, it complements it. The audit event is
// written synchronously and records the security decision: who called, from
// where, and whether the platform accepted it. That is the evidence record and
// it is append-only. But the audit event is necessarily written before the
// channel sends happen, because the sends are asynchronous and can take
// seconds; it therefore cannot say whether the operator's phone actually rang.
// This record is updated when the fan-out settles and carries that outcome.
type NotifyWebhookDelivery struct {
	ID        string `json:"id"`
	WebhookID string `json:"webhook_id"`
	EventType string `json:"event_type"`
	// Outcome is one of the NotifyWebhook* constants above.
	Outcome string `json:"outcome"`
	// Reason explains a rejection or failure in operator-readable terms. It never
	// contains caller-supplied text, only fixed strings chosen by this server, so
	// that a hostile caller cannot write into the console through it.
	Reason string `json:"reason,omitempty"`
	// Title and Body are the rendered message, retained so the operator can see
	// what would have been sent even when nothing was routed.
	Title string `json:"title,omitempty"`
	Body  string `json:"body,omitempty"`
	// SourceIP is the caller address as the server resolved it.
	SourceIP string `json:"source_ip,omitempty"`
	// Fields is the number of caller-supplied data fields accepted.
	Fields int `json:"fields"`
	// Bytes is the size of the caller payload.
	Bytes int `json:"bytes"`
	// Channels is the number of channel sends planned, and Delivered the number
	// that returned without error.
	Channels  int       `json:"channels"`
	Delivered int       `json:"delivered"`
	Test      bool      `json:"test,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// maxNotifyWebhookDeliveries bounds the retained history per webhook. The
// console shows recent attempts, not an archive; the durable record of who
// called and whether it was allowed is the audit stream, which has its own
// retention. Fifty is enough to cover a debugging session without letting a
// chatty caller grow the state file without limit.
const maxNotifyWebhookDeliveries = 50

func (s *Store) UpsertNotifyWebhook(hook NotifyWebhook) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	hook.UpdatedAt = time.Now().UTC()
	if hook.CreatedAt.IsZero() {
		hook.CreatedAt = hook.UpdatedAt
	}
	s.state.NotifyWebhooks[hook.ID] = hook
	return s.Save()
}

func (s *Store) NotifyWebhooks() []NotifyWebhook {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]NotifyWebhook, 0, len(s.state.NotifyWebhooks))
	for _, hook := range s.state.NotifyWebhooks {
		out = append(out, hook)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (s *Store) NotifyWebhook(id string) (NotifyWebhook, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hook, ok := s.state.NotifyWebhooks[id]
	return hook, ok
}

func (s *Store) DeleteNotifyWebhook(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.NotifyWebhooks[id]; !ok {
		return errors.New("webhook not found")
	}
	delete(s.state.NotifyWebhooks, id)
	delete(s.state.NotifyWebhookDeliveries, id)
	return s.Save()
}

// TouchNotifyWebhook records that a webhook authenticated successfully. It is
// separate from UpsertNotifyWebhook so a fire never rewrites operator-authored
// fields, and so a concurrent edit cannot be clobbered by an inbound request.
func (s *Store) TouchNotifyWebhook(id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	hook, ok := s.state.NotifyWebhooks[id]
	if !ok {
		return errors.New("webhook not found")
	}
	hook.LastUsedAt = at.UTC()
	s.state.NotifyWebhooks[id] = hook
	return s.Save()
}

// RecordNotifyWebhookDelivery appends an attempt and evicts the oldest beyond
// maxNotifyWebhookDeliveries.
func (s *Store) RecordNotifyWebhookDelivery(d NotifyWebhookDelivery) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now().UTC()
	}
	history := append(s.state.NotifyWebhookDeliveries[d.WebhookID], d)
	if len(history) > maxNotifyWebhookDeliveries {
		history = history[len(history)-maxNotifyWebhookDeliveries:]
	}
	s.state.NotifyWebhookDeliveries[d.WebhookID] = history
	return s.Save()
}

// SettleNotifyWebhookDelivery updates an already-recorded attempt with the
// outcome of the asynchronous channel fan-out. A delivery that has since been
// evicted, or whose webhook was deleted mid-flight, is silently dropped: the
// audit event still holds the security-relevant record.
func (s *Store) SettleNotifyWebhookDelivery(webhookID, deliveryID, outcome, reason string, delivered int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	history := s.state.NotifyWebhookDeliveries[webhookID]
	for i := range history {
		if history[i].ID != deliveryID {
			continue
		}
		history[i].Outcome = outcome
		history[i].Reason = reason
		history[i].Delivered = delivered
		s.state.NotifyWebhookDeliveries[webhookID] = history
		return s.Save()
	}
	return nil
}

// NotifyWebhookDeliveries returns the retained attempts for one webhook, newest
// first, capped at limit.
func (s *Store) NotifyWebhookDeliveries(webhookID string, limit int) []NotifyWebhookDelivery {
	s.mu.Lock()
	defer s.mu.Unlock()
	history := s.state.NotifyWebhookDeliveries[webhookID]
	out := make([]NotifyWebhookDelivery, 0, len(history))
	for i := len(history) - 1; i >= 0; i-- {
		if limit > 0 && len(out) >= limit {
			break
		}
		out = append(out, history[i])
	}
	return out
}
