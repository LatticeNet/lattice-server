package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/notify"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Inbound webhooks: an outside caller POSTs to a public endpoint and the result
// is an ordinary notification event that the existing rules route.
//
// The whole point of the design is that this is not a second delivery path. The
// handler's job ends at producing (eventType, title, body); from there it calls
// notifyEventTyped, so channel selection, rule matching, rule templates, the
// dispatcher, and every future improvement to any of those apply to a webhook
// event with no extra code. A webhook is a new *source* of events, not a new
// way to send.
//
// Trust boundary, stated once because everything below follows from it:
//
//	The operator authors the webhook. The caller supplies data.
//
// The operator picks the event type and both templates, and only an operator
// holding notify:send can change them. The caller supplies a bounded bag of
// scalar fields that the operator's templates may interpolate. A caller can
// therefore influence the *words inside a message the operator already chose to
// allow*, and nothing else: not which event fires, not which channels receive
// it, not whether a rule matches, not the message's shape.

// Webhook payload limits. These are deliberately small. The payload is text
// destined for a phone notification, not a data feed, and every byte accepted
// here is a byte an unauthenticated-until-verified caller can make the server
// parse.
const (
	// maxWebhookBodyBytes caps the request body. 8 KiB is generous for the
	// intended shape and two orders of magnitude below defaultJSONBodyLimit.
	maxWebhookBodyBytes = 8 << 10
	// maxWebhookFields caps how many data fields one call may carry.
	maxWebhookFields = 16
	// maxWebhookKeyLen and maxWebhookValueLen bound a single field.
	maxWebhookKeyLen   = 64
	maxWebhookValueLen = 512
	// maxWebhookTemplateLen bounds an operator-authored template. Operators are
	// trusted, but a template is rendered into a message body and stored, so it
	// still gets a ceiling rather than none.
	maxWebhookTemplateLen = 2048
	// maxWebhookDeliveryList caps what the deliveries endpoint returns.
	maxWebhookDeliveryList = 50
	// webhookSecretBytes is the entropy in a generated webhook secret. 32 random
	// bytes is the same budget storage access tokens get.
	webhookSecretBytes = 32
)

// notifyWebhookView is the secret-free projection of a webhook. It follows the
// notifyChannelView precedent: what is configured is visible, the credential
// never is. The secret is returned exactly once, by create and by rotate, in
// notifyWebhookSecretResponse.
type notifyWebhookView struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	EventType     string `json:"event_type"`
	TitleTemplate string `json:"title_template"`
	BodyTemplate  string `json:"body_template"`
	Enabled       bool   `json:"enabled"`
	// Path is the endpoint an operator gives the caller. It is a path rather
	// than an absolute URL because the server does not reliably know its own
	// external origin (it sits behind a proxy whose hostname it is never told);
	// the console joins it to the origin the operator is already browsing.
	Path string `json:"path"`
	// omitzero, not omitempty: encoding/json does not treat a zero time.Time as
	// empty, so omitempty ships "0001-01-01T00:00:00Z" and the console renders a
	// never-called webhook as having been called in year one.
	LastUsedAt time.Time `json:"last_used_at,omitzero"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// notifyWebhookSecretResponse carries the one and only look at a plaintext
// secret. There is no reveal endpoint: the hash is one-way, so a secret an
// operator loses is rotated, never recovered.
type notifyWebhookSecretResponse struct {
	notifyWebhookView
	Secret string `json:"secret"`
}

func notifyWebhookPath(webhookID string) string { return "/api/hooks/" + webhookID }

func toNotifyWebhookView(h store.NotifyWebhook) notifyWebhookView {
	return notifyWebhookView{
		ID:            h.ID,
		Name:          h.Name,
		EventType:     h.EventType,
		TitleTemplate: h.TitleTemplate,
		BodyTemplate:  h.BodyTemplate,
		Enabled:       h.Enabled,
		Path:          notifyWebhookPath(h.ID),
		LastUsedAt:    h.LastUsedAt,
		CreatedAt:     h.CreatedAt,
		UpdatedAt:     h.UpdatedAt,
	}
}

// refuseConfinedWebhookRead refuses a node-restricted principal on the webhook
// read surface.
//
// The write side already refuses these principals, on the grounds that a webhook
// routes fleet-wide events outward and a node-confined token minting one is a
// cross-node escape. The read side has the same problem and cannot be solved the
// usual way: a webhook has no node field, so unlike a monitor or a log source
// there is nothing to filter on. A confined principal reading this surface gets
// every webhook in the fleet, and from the delivery history the rendered message
// content and the external caller addresses too.
//
// Since such a principal cannot author, edit, rotate or delete a webhook anyway,
// a read-only window onto all of them is exposure with no workflow behind it.
// This matches the reasoning requireGlobalProxyScope already applies to
// subscription shares, which are fleet-wide objects for the same reason.
func (s *Server) refuseConfinedWebhookRead(w http.ResponseWriter, p principal, action string) bool {
	if !principalHasNodeRestriction(p) {
		return false
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:       id.New("audit"),
		Action:   action,
		Scope:    "notify:send",
		Decision: "deny",
		Reason:   "fleet-wide read refused for a node-restricted token",
	})
	writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "a webhook is a fleet-wide object with no node to confine it to; it requires a token without a server allowlist restriction"))
	return true
}

// handleNotifyWebhooks lists and upserts webhooks. It is gated on notify:send,
// the scope that already governs channel and rule administration: a webhook is
// a third object in the same notification system, and splitting it into its own
// scope would mean an operator who can already route any event to any channel
// needs a second grant to author a source for one.
func (s *Server) handleNotifyWebhooks(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if s.refuseConfinedWebhookRead(w, p, "notify.webhook.list") {
			return
		}
		hooks := s.store.NotifyWebhooks()
		views := make([]notifyWebhookView, 0, len(hooks))
		for _, h := range hooks {
			views = append(views, toNotifyWebhookView(h))
		}
		writeJSON(w, http.StatusOK, map[string]any{"webhooks": views})
	case http.MethodPost:
		// Same reasoning as notify channels: a webhook routes fleet-wide events
		// outward, so a node-confined token minting one is a cross-node escape,
		// not webhook administration.
		if s.refuseConfinedFleetWrite(w, p, "notify.webhook.upsert", "notify:send") {
			return
		}
		var req struct {
			ID            string `json:"id"`
			Name          string `json:"name"`
			EventType     string `json:"event_type"`
			TitleTemplate string `json:"title_template"`
			BodyTemplate  string `json:"body_template"`
			Enabled       *bool  `json:"enabled"`
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		hook, err := normalizeNotifyWebhook(req.ID, req.Name, req.EventType, req.TitleTemplate, req.BodyTemplate, req.Enabled)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		existing, found := s.store.NotifyWebhook(hook.ID)
		if req.ID != "" && !found {
			writeError(w, http.StatusNotFound, errors.New("webhook not found"))
			return
		}
		if found {
			// An edit never touches the credential or the usage record. Rotation is
			// its own endpoint so that changing a title template cannot silently
			// invalidate a caller that is working.
			hook.SecretHash = existing.SecretHash
			hook.CreatedAt = existing.CreatedAt
			hook.LastUsedAt = existing.LastUsedAt
			if err := s.store.UpsertNotifyWebhook(hook); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "notify.webhook.update", Scope: "notify:send", Metadata: map[string]string{"webhook_id": hook.ID, "event_type": hook.EventType}})
			writeJSON(w, http.StatusOK, toNotifyWebhookView(hook))
			return
		}
		secret, err := auth.NewRandomToken(webhookSecretBytes)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		hash, err := auth.HashSecret(secret)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		hook.SecretHash = hash
		if err := s.store.UpsertNotifyWebhook(hook); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "notify.webhook.create", Scope: "notify:send", Metadata: map[string]string{"webhook_id": hook.ID, "event_type": hook.EventType}})
		writeJSON(w, http.StatusOK, notifyWebhookSecretResponse{
			notifyWebhookView: toNotifyWebhookView(hook),
			Secret:            auth.FormatToken(hook.ID, secret),
		})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleDeleteNotifyWebhook(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if s.refuseConfinedFleetWrite(w, p, "notify.webhook.delete", "notify:send") {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if err := s.store.DeleteNotifyWebhook(strings.TrimSpace(req.ID)); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "notify.webhook.delete", Scope: "notify:send", Metadata: map[string]string{"webhook_id": req.ID}})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleRotateNotifyWebhookSecret mints a new secret and invalidates the old
// one immediately. There is no overlap window: a webhook has exactly one valid
// secret at a time, so an operator rotating after a leak knows the leaked value
// is dead the moment the call returns, rather than trusting a grace period.
func (s *Server) handleRotateNotifyWebhookSecret(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if s.refuseConfinedFleetWrite(w, p, "notify.webhook.rotate", "notify:send") {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	hook, found := s.store.NotifyWebhook(strings.TrimSpace(req.ID))
	if !found {
		writeError(w, http.StatusNotFound, errors.New("webhook not found"))
		return
	}
	secret, err := auth.NewRandomToken(webhookSecretBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	hash, err := auth.HashSecret(secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	hook.SecretHash = hash
	if err := s.store.UpsertNotifyWebhook(hook); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "notify.webhook.rotate", Scope: "notify:send", Metadata: map[string]string{"webhook_id": hook.ID}})
	writeJSON(w, http.StatusOK, notifyWebhookSecretResponse{
		notifyWebhookView: toNotifyWebhookView(hook),
		Secret:            auth.FormatToken(hook.ID, secret),
	})
}

// handleNotifyWebhookDeliveries returns the retained attempt history for one
// webhook, newest first.
func (s *Server) handleNotifyWebhookDeliveries(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if s.refuseConfinedWebhookRead(w, p, "notify.webhook.deliveries") {
		return
	}
	webhookID := strings.TrimSpace(r.URL.Query().Get("id"))
	if webhookID == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	if _, found := s.store.NotifyWebhook(webhookID); !found {
		writeError(w, http.StatusNotFound, errors.New("webhook not found"))
		return
	}
	limit := maxWebhookDeliveryList
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed < limit {
			limit = parsed
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"deliveries": s.store.NotifyWebhookDeliveries(webhookID, limit)})
}

// handleNotifyWebhookTest fires a webhook from the console without the caller
// needing the secret, so an operator can prove the whole path (event, rule,
// channel) before handing the URL out. It runs the identical code the public
// endpoint runs, because a test that takes a shortcut past rule matching proves
// only that the shortcut works.
func (s *Server) handleNotifyWebhookTest(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if s.refuseConfinedFleetWrite(w, p, "notify.webhook.test", "notify:send") {
		return
	}
	var req struct {
		ID   string            `json:"id"`
		Data map[string]string `json:"data"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	hook, found := s.store.NotifyWebhook(strings.TrimSpace(req.ID))
	if !found {
		writeError(w, http.StatusNotFound, errors.New("webhook not found"))
		return
	}
	raw := make(map[string]any, len(req.Data))
	for k, v := range req.Data {
		raw[k] = v
	}
	data, err := normalizeWebhookData(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	outcome := s.fireNotifyWebhook(hook, data, s.clientIP(r), 0, true)
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:       id.New("audit"),
		Action:   "notify.webhook.test",
		Scope:    "notify:send",
		Decision: "allow",
		Metadata: map[string]string{"webhook_id": hook.ID, "event_type": hook.EventType, "outcome": outcome.Outcome, "channels": strconv.Itoa(outcome.Channels)},
	})
	writeJSON(w, http.StatusOK, outcome)
}

// handleInboundWebhook is the public endpoint. It is registered without
// withAuth because its caller is by definition not a Lattice principal: it is a
// script, a router, a monitoring system, something holding one webhook's secret
// and nothing else.
//
// Authentication is a bearer credential in the Authorization header, in the
// same "<id>.<secret>" form and against the same PBKDF2 verifier that storage
// access tokens use. What an attacker who has only the URL can do: nothing. The
// URL carries the webhook id, which is not a secret and is not sufficient; they
// get 401, they get rate limited, and the attempt is audited with their source
// address. What an attacker who has the URL *and* the secret can do: cause that
// one webhook's event to fire, with their text landing in the operator's
// templates wherever the operator put a {{data.*}} placeholder. They cannot
// choose the event type, reach another webhook, enumerate channels, read any
// configuration, or send anything the operator's own template does not shape.
// The blast radius of a leaked secret is exactly one webhook, and rotation is
// one call.
//
// The secret rides a header rather than the path deliberately. A path token is
// written to every proxy access log, browser history entry and Referer header
// along the way, so "the URL" and "the credential" become the same object and
// the question "what can someone with the URL do" stops having a safe answer.
func (s *Server) handleInboundWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	webhookID := strings.TrimPrefix(r.URL.Path, "/api/hooks/")
	if webhookID == "" || strings.Contains(webhookID, "/") {
		writeError(w, http.StatusNotFound, errors.New("webhook not found"))
		return
	}
	sourceIP := s.clientIP(r)

	// Every authentication path below reaches a PBKDF2 derivation at production
	// cost, so the budget is spent HERE, before the work, not on the way out of a
	// failure.
	//
	// The storage-token pattern this otherwise follows charges only failed
	// attempts, so a caller with a working token never meets its limiter. That
	// shape has a hole: the branch where the id is real and the secret is wrong
	// runs the derivation as part of evaluating its own condition, so the check
	// that comes after it only decides the status code. An attacker who knows a
	// webhook id, which is deliberately not secret, could then buy an unbounded
	// number of 210k-iteration derivations. The same hole exists in
	// authorizeStorageToken and is reported separately; it is not fixed here
	// because that endpoint needs its own change and its own tests.
	//
	// So this limiter is checked up front and sized for real traffic instead. It
	// bounds GUESSES per address, which is what stops a brute force.
	if !s.webhookVerifyLimiter.Allow(sourceIP) {
		s.refuseInboundWebhook(w, r, webhookID, http.StatusTooManyRequests, "rate limited", errors.New("too many webhook attempts"))
		return
	}
	hook, ok := s.authenticateInboundWebhook(w, r, webhookID)
	if !ok {
		return
	}

	// Authenticated. A verified caller still cannot fire without limit: this
	// bucket is keyed by webhook rather than by address, because the thing being
	// protected is the operator's attention, and a legitimate-but-looping caller
	// floods it just as effectively as a hostile one.
	//
	// Everything past this line may write a delivery record, and a delivery
	// record costs a full state-file rewrite, so this budget is what bounds that
	// cost. Refusals above it are audited and nothing more.
	if !s.webhookFireLimiter.Allow(hook.ID) {
		s.refuseInboundWebhook(w, r, webhookID, http.StatusTooManyRequests, "webhook rate limited", errors.New("webhook is firing too often"))
		return
	}
	// Checked after the fire budget rather than before it, so a caller holding a
	// valid secret for a disabled webhook cannot spend delivery records freely.
	if !hook.Enabled {
		s.denyInboundWebhook(w, r, webhookID, sourceIP, http.StatusForbidden, "webhook disabled", errors.New("webhook is disabled"))
		return
	}

	data, size, err := decodeWebhookPayload(w, r)
	if err != nil {
		s.denyInboundWebhook(w, r, webhookID, sourceIP, http.StatusBadRequest, "invalid payload", err)
		return
	}
	if err := s.store.TouchNotifyWebhook(hook.ID, time.Now()); err != nil {
		s.logger.Printf("notify webhook touch: %v", err)
	}
	outcome := s.fireNotifyWebhook(hook, data, sourceIP, size, false)
	s.recordRequestAudit(r, model.AuditEvent{
		ID:       id.New("audit"),
		Action:   "notify.webhook.receive",
		Scope:    "notify:send",
		Decision: "allow",
		Reason:   outcome.Outcome,
		Metadata: map[string]string{
			"webhook_id": hook.ID,
			"event_type": hook.EventType,
			"fields":     strconv.Itoa(outcome.Fields),
			"bytes":      strconv.Itoa(size),
			"channels":   strconv.Itoa(outcome.Channels),
		},
	})
	// The response tells the caller the request was accepted and how many
	// deliveries it planned, and nothing else. It never names a channel, a rule
	// or the rendered message: the caller supplied data, it is not entitled to
	// read the operator's routing back out. "accepted with zero channels" is
	// still worth returning, because a caller wiring this up for the first time
	// otherwise cannot tell a working webhook from one nothing listens to.
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":       true,
		"outcome":  outcome.Outcome,
		"channels": outcome.Channels,
	})
}

// authenticateInboundWebhook verifies the caller's secret and returns the
// webhook it names.
//
// It exists as its own function so the derivation permit is held for exactly the
// derivation. Taking it in the handler and releasing it on handler return would
// make the semaphore cap concurrent *requests* rather than concurrent
// verification, which on a small host would refuse legitimate fires while they
// waited on template rendering and channel dispatch, work that costs nothing
// like a PBKDF2 pass.
func (s *Server) authenticateInboundWebhook(w http.ResponseWriter, r *http.Request, webhookID string) (store.NotifyWebhook, bool) {
	// What bounds the CPU is this, and it has to be a concurrency cap rather than
	// a second rate limit. One derivation costs about 20ms on a fast development
	// machine and around 500ms on a shared CI runner, so any requests-per-second
	// ceiling that is harmless on the first is a saturated core on the second: at
	// two guesses a second, a 500ms derivation is 100% of a core from a single
	// address, forever. Permits do not have that problem. N in flight is at most
	// N cores of demand whatever a derivation costs, on any host.
	//
	// Acquired without blocking: a caller arriving while the machine is already
	// busy verifying is refused immediately rather than queued, because queueing
	// here is how a flood turns into unbounded goroutines and memory.
	select {
	case s.secretVerifySlots <- struct{}{}:
		defer func() { <-s.secretVerifySlots }()
	default:
		s.refuseInboundWebhook(w, r, webhookID, http.StatusTooManyRequests, "rate limited", errors.New("too many webhook attempts"))
		return store.NotifyWebhook{}, false
	}

	presented := bearerToken(r)
	tokenID, secret, ok := auth.SplitToken(presented)
	if !ok {
		auth.DummyVerify(presented)
		s.refuseInboundWebhook(w, r, webhookID, http.StatusUnauthorized, "missing or malformed secret", errors.New("missing or invalid webhook secret"))
		return store.NotifyWebhook{}, false
	}
	hook, found := s.store.NotifyWebhook(webhookID)
	// The token must name the same webhook the path does. Comparing them costs
	// nothing and removes a class of confusion where a caller holding a valid
	// secret for webhook A fires webhook B by editing the URL.
	if !found || tokenID != webhookID {
		auth.DummyVerify(secret)
		s.refuseInboundWebhook(w, r, webhookID, http.StatusUnauthorized, "unknown webhook or mismatched secret", errors.New("missing or invalid webhook secret"))
		return store.NotifyWebhook{}, false
	}
	if !auth.VerifySecret(hook.SecretHash, secret) {
		s.refuseInboundWebhook(w, r, webhookID, http.StatusUnauthorized, "secret verification failed", errors.New("missing or invalid webhook secret"))
		return store.NotifyWebhook{}, false
	}
	return hook, true
}

// refuseInboundWebhook writes the error and audits the refusal, and does not
// touch the store.
//
// Every rejected attempt is audited, not just the interesting ones: the audit
// stream is where an operator answers "is someone probing my webhook", and that
// question is unanswerable if only successes are recorded. Audit has a WAL-backed
// append path, so this stays cheap.
//
// What it deliberately does NOT do is write a delivery record. That costs a full
// encrypted state-file rewrite with an fsync, taken under the store's global
// mutex, which would block unrelated API traffic. Reachable by an anonymous
// caller who knows only a webhook id, that is a control-plane availability hit,
// so refusals an unauthenticated caller can trigger leave the audit trail and
// nothing else.
func (s *Server) refuseInboundWebhook(w http.ResponseWriter, r *http.Request, webhookID string, status int, reason string, err error) {
	s.recordRequestAudit(r, model.AuditEvent{
		ID:       id.New("audit"),
		Action:   "notify.webhook.receive",
		Scope:    "notify:send",
		Decision: "deny",
		Reason:   reason,
		Metadata: map[string]string{"webhook_id": webhookID, "status": strconv.Itoa(status)},
	})
	writeError(w, status, err)
}

// denyInboundWebhook is refuseInboundWebhook plus a delivery record, for the
// refusals that happen after authentication and after the per-webhook fire
// budget. Those require a valid secret and are capped by that budget, so the
// cost of persisting them is bounded.
func (s *Server) denyInboundWebhook(w http.ResponseWriter, r *http.Request, webhookID, sourceIP string, status int, reason string, err error) {
	if recErr := s.store.RecordNotifyWebhookDelivery(store.NotifyWebhookDelivery{
		ID:        id.New("nwd"),
		WebhookID: webhookID,
		Outcome:   store.NotifyWebhookRejected,
		Reason:    reason,
		SourceIP:  sourceIP,
	}); recErr != nil {
		s.logger.Printf("notify webhook delivery record: %v", recErr)
	}
	s.refuseInboundWebhook(w, r, webhookID, status, reason, err)
}

// fireNotifyWebhook renders the operator's templates and hands the result to
// the ordinary event dispatcher. This is the single place a webhook becomes an
// event, shared by the public endpoint and the console test.
func (s *Server) fireNotifyWebhook(hook store.NotifyWebhook, data map[string]string, sourceIP string, size int, test bool) store.NotifyWebhookDelivery {
	vars := map[string]string{
		"event_type":   hook.EventType,
		"webhook_name": hook.Name,
		"webhook_id":   hook.ID,
		"received_at":  time.Now().UTC().Format(time.RFC3339),
	}
	for k, v := range data {
		vars["data."+k] = v
	}
	title := renderWebhookTemplate(hook.TitleTemplate, hook.Name, vars)
	body := renderWebhookTemplate(hook.BodyTemplate, "", vars)

	record := store.NotifyWebhookDelivery{
		ID:        id.New("nwd"),
		WebhookID: hook.ID,
		EventType: hook.EventType,
		Title:     title,
		Body:      body,
		SourceIP:  sourceIP,
		Fields:    len(data),
		Bytes:     size,
		Test:      test,
		CreatedAt: time.Now().UTC(),
	}

	// Plan here rather than inside notifyEventTyped so the count of planned
	// deliveries can be reported and recorded. Production today has zero channels
	// and zero rules, which makes "your webhook worked and reached nobody" the
	// single most likely first experience; it has to be legible rather than look
	// like a success.
	deliveries := s.planNotifyDeliveries(hook.EventType, title, body, s.store.EnabledNotifyChannels(), s.store.EnabledNotifyRules())
	channels := 0
	for _, d := range deliveries {
		channels += len(d.Channels)
	}
	record.Channels = channels
	if channels == 0 {
		record.Outcome = store.NotifyWebhookNoRoute
		record.Reason = "no enabled rule and channel matched this event type"
	} else {
		record.Outcome = store.NotifyWebhookAccepted
	}
	if err := s.store.RecordNotifyWebhookDelivery(record); err != nil {
		s.logger.Printf("notify webhook delivery record: %v", err)
	}
	if channels == 0 {
		return record
	}

	// Send asynchronously, as notifyEventTyped does, so a slow channel never
	// holds the caller's request open. The delivery record is settled when the
	// fan-out finishes, which is the outcome the audit event could not wait for.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		delivered := 0
		failed := 0
		for _, delivery := range deliveries {
			if len(delivery.Channels) == 0 {
				continue
			}
			for _, res := range notify.NewDispatcher(delivery.Channels...).Send(ctx, delivery.Message) {
				if res.Err != nil {
					failed++
					s.logger.Printf("notify webhook %s: %s delivery failed: %v", hook.ID, res.Kind, res.Err)
					continue
				}
				delivered++
			}
		}
		outcome := store.NotifyWebhookAccepted
		reason := ""
		switch {
		case delivered == 0 && failed > 0:
			outcome = store.NotifyWebhookFailed
			reason = fmt.Sprintf("all %d channel sends failed", failed)
		case failed > 0:
			outcome = store.NotifyWebhookPartial
			reason = fmt.Sprintf("%d of %d channel sends failed", failed, delivered+failed)
		}
		if err := s.store.SettleNotifyWebhookDelivery(hook.ID, record.ID, outcome, reason, delivered); err != nil {
			s.logger.Printf("notify webhook delivery settle: %v", err)
		}
	}()
	return record
}

// decodeWebhookPayload reads and validates the caller's body. The accepted
// shape is exactly {"data": {...}} of scalar fields, or an empty body for a
// caller that only needs to say "this happened".
func decodeWebhookPayload(w http.ResponseWriter, r *http.Request) (map[string]string, int, error) {
	defer r.Body.Close()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBodyBytes))
	size := len(body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, size, fmt.Errorf("payload exceeds %d bytes", maxWebhookBodyBytes)
		}
		// A read that failed for any other reason is a truncated or aborted
		// request, not an intentionally empty one. Returning what arrived so far
		// would let a caller fire the webhook by opening a request and dropping
		// it, so it is refused instead.
		return nil, size, errors.New("could not read the request body")
	}
	if len(bytes.TrimSpace(body)) == 0 {
		// An empty body is a valid ping: the webhook fires with no data, and the
		// operator's templates render from the platform variables alone.
		return map[string]string{}, size, nil
	}
	var envelope struct {
		Data map[string]any `json:"data"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&envelope); err != nil {
		return nil, size, errors.New(`body must be JSON of the form {"data":{"key":"value"}}`)
	}
	// Trailing content is refused rather than ignored, matching decodeJSONBody:
	// a caller that sends two documents must be told, not silently have the
	// second one dropped.
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, size, errors.New("body must be a single JSON object")
	}
	data, err := normalizeWebhookData(envelope.Data)
	if err != nil {
		return nil, size, err
	}
	return data, size, nil
}

// normalizeWebhookData enforces the caller's half of the contract: a bounded
// number of bounded, scalar, well-named fields.
func normalizeWebhookData(raw map[string]any) (map[string]string, error) {
	out := make(map[string]string, len(raw))
	if len(raw) > maxWebhookFields {
		return nil, fmt.Errorf("at most %d data fields are accepted, got %d", maxWebhookFields, len(raw))
	}
	// Sorted so an over-long value reports the same field every time rather than
	// whichever the map happened to yield first.
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		key := strings.TrimSpace(k)
		if err := validateWebhookFieldKey(key); err != nil {
			return nil, err
		}
		value, err := webhookScalarString(raw[k])
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", key, err)
		}
		value = sanitizeWebhookValue(value)
		if utf8.RuneCountInString(value) > maxWebhookValueLen {
			return nil, fmt.Errorf("field %q exceeds %d characters", key, maxWebhookValueLen)
		}
		out[key] = value
	}
	return out, nil
}

func validateWebhookFieldKey(key string) error {
	if key == "" {
		return errors.New("data field names must not be empty")
	}
	if len(key) > maxWebhookKeyLen {
		return fmt.Errorf("data field name %q exceeds %d characters", key, maxWebhookKeyLen)
	}
	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return fmt.Errorf("data field name %q may use letters, digits, underscore and hyphen only", key)
	}
	return nil
}

// webhookScalarString accepts the JSON scalars and refuses structure. Nested
// objects and arrays are rejected rather than flattened: the caller is filling
// in an operator's sentence, and there is no sentence a nested array belongs in.
func webhookScalarString(v any) (string, error) {
	switch value := v.(type) {
	case string:
		return value, nil
	case bool:
		return strconv.FormatBool(value), nil
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64), nil
	case nil:
		return "", nil
	default:
		return "", errors.New("value must be a string, number, boolean or null")
	}
}

// sanitizeWebhookValue strips what a caller must not be able to put into a
// notification: control characters, which corrupt a terminal or a log line, and
// template delimiters.
//
// The delimiters matter more than they look. This file renders in a single
// left-to-right pass, so a value containing "{{data.other}}" is never rescanned
// here. But the rendered title and body are then handed to planNotifyDeliveries,
// whose rule templates expand by repeated ReplaceAll over a map, and that pass
// would happily expand a placeholder the caller smuggled in. Removing the
// delimiters at the boundary closes it once, for that renderer and any future
// one, rather than depending on every downstream pass being careful.
func sanitizeWebhookValue(value string) string {
	value = strings.ReplaceAll(value, "{{", "")
	value = strings.ReplaceAll(value, "}}", "")
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		// Newline and tab survive; a notification body legitimately wraps.
		if r == '\n' || r == '\t' {
			b.WriteRune(r)
			continue
		}
		if r < 0x20 || r == 0x7f {
			b.WriteRune(' ')
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// renderWebhookTemplate expands {{name}} placeholders in one left-to-right pass.
//
// One pass is the security property, not an optimisation. The obvious
// implementation, looping over the variables calling ReplaceAll, feeds its own
// output back through every later replacement, so a value that contains a
// placeholder gets expanded and the caller has written template syntax the
// operator did not author. Scanning the template once and copying values in
// without rescanning them makes that impossible by construction.
//
// An unknown placeholder is left standing rather than emptied, so a template
// referring to a field the caller did not send says so in the message instead
// of silently producing a sentence with a hole in it.
func renderWebhookTemplate(tmpl, fallback string, vars map[string]string) string {
	tmpl = strings.TrimSpace(tmpl)
	if tmpl == "" {
		return fallback
	}
	var b strings.Builder
	b.Grow(len(tmpl))
	for i := 0; i < len(tmpl); {
		start := strings.Index(tmpl[i:], "{{")
		if start < 0 {
			b.WriteString(tmpl[i:])
			break
		}
		start += i
		b.WriteString(tmpl[i:start])
		end := strings.Index(tmpl[start+2:], "}}")
		if end < 0 {
			b.WriteString(tmpl[start:])
			break
		}
		end += start + 2
		name := strings.TrimSpace(tmpl[start+2 : end])
		if value, ok := vars[name]; ok {
			b.WriteString(value)
		} else {
			b.WriteString(tmpl[start : end+2])
		}
		i = end + 2
	}
	return b.String()
}

// normalizeNotifyWebhook validates the operator's half of the contract.
func normalizeNotifyWebhook(idValue, name, eventType, titleTemplate, bodyTemplate string, enabled *bool) (store.NotifyWebhook, error) {
	idValue = strings.TrimSpace(idValue)
	if idValue == "" {
		idValue = id.New("nwh")
	} else if err := validateNotifyID(idValue); err != nil {
		return store.NotifyWebhook{}, fmt.Errorf("id: %w", err)
	}
	// The id becomes a path segment on a public route, so it is held to a
	// stricter alphabet than validateNotifyID's "no control characters".
	for _, r := range idValue {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return store.NotifyWebhook{}, errors.New("id may use letters, digits, underscore and hyphen only")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return store.NotifyWebhook{}, errors.New("name is required")
	}
	if len(name) > 128 {
		return store.NotifyWebhook{}, errors.New("name is too long")
	}
	eventType = strings.TrimSpace(strings.ToLower(eventType))
	if eventType == "" {
		return store.NotifyWebhook{}, errors.New("event_type is required")
	}
	// "*" is a valid thing for a rule to *match*, but not a coherent thing for a
	// source to *emit*: a webhook that raises every event type at once would make
	// every rule fire, which is precisely the "caller chooses the routing" outcome
	// the design exists to prevent.
	if eventType == "*" {
		return store.NotifyWebhook{}, errors.New("event_type must name one event, not *")
	}
	if err := validateNotifyEventType(eventType); err != nil {
		return store.NotifyWebhook{}, err
	}
	titleTemplate = strings.TrimSpace(titleTemplate)
	bodyTemplate = strings.TrimSpace(bodyTemplate)
	if titleTemplate == "" {
		return store.NotifyWebhook{}, errors.New("title_template is required")
	}
	if len(titleTemplate) > maxWebhookTemplateLen || len(bodyTemplate) > maxWebhookTemplateLen {
		return store.NotifyWebhook{}, fmt.Errorf("templates must be under %d characters", maxWebhookTemplateLen)
	}
	return store.NotifyWebhook{
		ID:            idValue,
		Name:          name,
		EventType:     eventType,
		TitleTemplate: titleTemplate,
		BodyTemplate:  bodyTemplate,
		Enabled:       enabled == nil || *enabled,
	}, nil
}
