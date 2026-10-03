package server

import (
	"strconv"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// A link's cache misses spend plugin renders, and the variant space one valid
// link can ask for is large (fourteen targets, two produce flags, the agent
// classes and the formats), against a plugin pool of two workers and one
// cache shared by every link. Each link gets a render budget: a burst of
// shareRenderBudgetBurst and shareRenderBudgetPerHour after that. A request
// that would start a render past it answers the decoy; requests that join a
// running render or hit the cache spend nothing. The figures leave an
// ordinary link (a few client families, content that moves a few times an
// hour) far inside the budget.
//
// The budget is shared by everyone holding the link, so it must not let one
// holder lock the others out, and the decoy it answers looks to a real
// client like any other refusal: the client silently keeps its old config.
// Three rules keep the budget aimed at variant churn:
//
//   - A variant the link has already rendered successfully re-renders for
//     free once per content version. When the content moves, every client
//     already on the link gets the new content whatever the budget holds;
//     the free render settles that version for the variant, so a second
//     render of the same variant at the same version (an eviction, or a
//     failed free render retried) is charged. At most
//     shareRenderKnownVariants variants per link are remembered, so free
//     renders stay bounded by that number times the content moves, and
//     content moves are the provider's and the operator's, not the caller's.
//   - A failed render is refunded from a small allowance
//     (shareRenderRefundBurst, then shareRenderRefundsPerHour). Refunding
//     every failure would reopen the hole the budget closes: a variant that
//     fails or renders empty for this record fails every time, and each
//     attempt costs a plugin render.
//   - Exhaustion is visible: the share view reports the budget, and the
//     first refusal of each hour writes one audit event for the link outside
//     the refusal throttle. Rotating the token refills the budget.
const (
	shareRenderBudgetBurst    = 40
	shareRenderBudgetPerHour  = 60
	shareRenderRefundBurst    = 8
	shareRenderRefundsPerHour = 8
	shareRenderKnownVariants  = 16

	shareRenderBudgetExhaustedReason = "render budget exhausted; new renders are refused until it refills"
)

type shareRenderBudget struct {
	mu    sync.Mutex
	now   func() time.Time
	links map[string]*shareRenderBudgetLink
}

type shareRenderBudgetLink struct {
	tokens, refunds float64
	filled          time.Time
	// variants maps each variant this link rendered successfully to the
	// content version its last render was for.
	variants    map[string]string
	refused     int
	lastRefused time.Time
	announced   time.Time
}

// shareRenderTicket is a render the budget let start; settle closes it.
type shareRenderTicket struct {
	shareID, variant, version string
	charged                   bool
}

func newShareRenderBudget(now func() time.Time) *shareRenderBudget {
	return &shareRenderBudget{now: now, links: map[string]*shareRenderBudgetLink{}}
}

// shareRenderVariantKey is the part of a cache key that is not the link.
func shareRenderVariantKey(key subscriptionCacheKey) string {
	return key.Format + "|" + key.UAClass + "|" + key.Variant
}

// linkLocked returns the link's state, refilled to now.
func (b *shareRenderBudget) linkLocked(shareID string, now time.Time) *shareRenderBudgetLink {
	link := b.links[shareID]
	if link == nil {
		link = &shareRenderBudgetLink{tokens: shareRenderBudgetBurst, refunds: shareRenderRefundBurst, filled: now, variants: map[string]string{}}
		b.links[shareID] = link
	}
	if hours := now.Sub(link.filled).Hours(); hours > 0 {
		link.tokens = min(shareRenderBudgetBurst, link.tokens+hours*shareRenderBudgetPerHour)
		link.refunds = min(shareRenderRefundBurst, link.refunds+hours*shareRenderRefundsPerHour)
		link.filled = now
	}
	return link
}

// take decides whether a render of variant for the link may start, given the
// content version the source holds now ("" when unknown). When it refuses,
// announce reports the first refusal of the hour and refused the count so far.
func (b *shareRenderBudget) take(shareID, variant, version string) (ticket shareRenderTicket, ok, announce bool, refused int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	link := b.linkLocked(shareID, now)
	ticket = shareRenderTicket{shareID: shareID, variant: variant, version: version}
	if last, known := link.variants[variant]; known && version != "" && last != version {
		link.variants[variant] = version
		return ticket, true, false, link.refused
	}
	if link.tokens >= 1 {
		link.tokens--
		ticket.charged = true
		return ticket, true, false, link.refused
	}
	link.refused++
	link.lastRefused = now
	if link.announced.IsZero() || now.Sub(link.announced) >= time.Hour {
		link.announced = now
		announce = true
	}
	return ticket, false, announce, link.refused
}

// settle closes a ticket: a success remembers the variant and the version it
// rendered, a failure is refunded while the allowance lasts.
func (b *shareRenderBudget) settle(ticket shareRenderTicket, renderedVersion string, failed bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	link := b.links[ticket.shareID]
	if link == nil {
		return
	}
	if failed {
		link = b.linkLocked(ticket.shareID, b.now())
		if ticket.charged && link.refunds >= 1 {
			link.refunds--
			link.tokens = min(shareRenderBudgetBurst, link.tokens+1)
		}
		return
	}
	version := renderedVersion
	if version == "" {
		version = ticket.version
	}
	if _, known := link.variants[ticket.variant]; known || len(link.variants) < shareRenderKnownVariants {
		link.variants[ticket.variant] = version
	}
}

// shareRenderBudgetView is the budget as the share view reports it.
type shareRenderBudgetView struct {
	Remaining     int        `json:"remaining"`
	Burst         int        `json:"burst"`
	PerHour       int        `json:"per_hour"`
	Exhausted     bool       `json:"exhausted"`
	Refused       int        `json:"refused"`
	LastRefusedAt *time.Time `json:"last_refused_at,omitempty"`
}

// status reports a link's budget, or nil when the link has not rendered
// since the process started (its budget is then full).
func (b *shareRenderBudget) status(shareID string) *shareRenderBudgetView {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.links[shareID] == nil {
		return nil
	}
	link := b.linkLocked(shareID, b.now())
	view := &shareRenderBudgetView{Remaining: int(link.tokens), Burst: shareRenderBudgetBurst, PerHour: shareRenderBudgetPerHour,
		Exhausted: link.tokens < 1, Refused: link.refused}
	if !link.lastRefused.IsZero() {
		at := link.lastRefused
		view.LastRefusedAt = &at
	}
	return view
}

// reset gives a link a full budget again. Rotation calls it: a leaked token
// is how a link's budget gets burned, rotating is the operator's answer, and
// the rotation drops every cached body, so the link's real clients must be
// able to render again at once.
func (b *shareRenderBudget) reset(shareID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.links, shareID)
}

// forget drops the budgets of links that no longer exist.
func (b *shareRenderBudget) forget(exists func(string) bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for shareID := range b.links {
		if !exists(shareID) {
			delete(b.links, shareID)
		}
	}
}

// announceShareRenderBudgetExhausted writes the hourly exhaustion event for a
// link, off the request path. Every refusal is still audited through the
// refusal throttle with the requester's address; this one is about the link
// and is never folded away.
func (s *Server) announceShareRenderBudgetExhausted(share model.SubscriptionShare, refused int) {
	ev := model.AuditEvent{ID: id.New("audit"), Action: auditActionShareFetch, Decision: "deny", Reason: shareRenderBudgetExhaustedReason,
		Metadata: map[string]string{
			"share_id": share.ID, "slug": share.Slug, "refused": strconv.Itoa(refused),
			"burst": strconv.Itoa(shareRenderBudgetBurst), "per_hour": strconv.Itoa(shareRenderBudgetPerHour),
		}}
	s.shareRefusalAudits.Add(1)
	go func() {
		defer s.shareRefusalAudits.Done()
		s.recordAudit(ev)
	}()
}
