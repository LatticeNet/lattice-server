// Package ddns publishes a node's public IP to DNS when it changes. It is
// dependency-free: the Cloudflare provider talks to the Cloudflare API v4 over
// the standard library and the webhook provider posts a templated request, so
// the server keeps its zero-dependency footprint (no libdns).
package ddns

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/outbound"
)

// Record is a single DNS record to set.
type Record struct {
	Type   string // "A", "AAAA" or "CNAME"
	Name   string // fully-qualified record name, e.g. node.example.com
	IP     string // the address of an A or AAAA record
	Target string // the hostname a CNAME record points to
	TTL    int
	// Comment is what the record's comment should say. Nil leaves the
	// comment as it is. Providers that have no comments ignore it.
	Comment *Comment
}

// Provider sets DNS records for one backend (Cloudflare, webhook, ...).
type Provider interface {
	Kind() string
	SetRecord(ctx context.Context, r Record) error
}

// ExistingRecord is a record a provider already holds at a name.
type ExistingRecord struct {
	Type    string
	Content string
	Proxied bool
	Comment string
}

// Inspector reads back what a provider holds at a name. Cloudflare implements
// it; a webhook cannot be read back.
type Inspector interface {
	RecordsAt(ctx context.Context, name string) ([]ExistingRecord, error)
}

// Run is what one publish knows beyond the profile itself.
type Run struct {
	NodeName string    // the node's display name; the node id when it has none
	Lattice  string    // the control plane's public host
	Now      time.Time // the clock the comment's #time# and #date# read
	// RefreshComment rewrites a record's comment even when its address is
	// unchanged. Only an operator's "Run now" sets it, so a new template
	// applies at once while scheduled and heartbeat runs stay silent unless
	// an address moved.
	RefreshComment bool
}

func recordTTL(p model.DDNSProfile) int {
	if p.TTL > 0 {
		return p.TTL
	}
	return 60
}

// NewProvider builds the Provider described by a profile. The webhook provider
// is given the production SSRF guard; the Cloudflare provider targets the real
// API. Tests construct providers directly to bypass the guard / point at a mock.
func NewProvider(p model.DDNSProfile, client *http.Client) (Provider, error) {
	switch p.Provider {
	case model.DDNSProviderCloudflare:
		if p.CFAPIToken == "" {
			return nil, errors.New("cloudflare: cf_api_token is required")
		}
		return &Cloudflare{Token: p.CFAPIToken, Client: client}, nil
	case model.DDNSProviderWebhook:
		if p.WebhookURL == "" {
			return nil, errors.New("webhook: webhook_url is required")
		}
		return &Webhook{
			URL:     p.WebhookURL,
			Method:  p.WebhookMethod,
			Body:    p.WebhookBody,
			Headers: p.WebhookHeaders,
			Client:  client,
			Guard:   GuardOutbound,
		}, nil
	default:
		return nil, fmt.Errorf("unknown ddns provider %q", p.Provider)
	}
}

// Apply publishes a profile's records, retrying each up to MaxRetries times.
// An address profile pushes the node's current IPs to every domain, honoring
// EnableIPv4/EnableIPv6; a CNAME profile points every domain at CNAMETarget.
// It returns the joined error of all failed records (nil if all succeeded).
func Apply(ctx context.Context, p Provider, profile model.DDNSProfile, ipv4, ipv6 string, run Run) error {
	var comment *Comment
	if tmpl, ok := CommentTemplateFor(profile); ok {
		comment = &Comment{
			Template: tmpl,
			Vars: CommentVars{
				Node: run.NodeName, NodeID: profile.NodeID, Profile: profile.Name,
				Lattice: run.Lattice, Time: run.Now,
			},
			Refresh: run.RefreshComment,
		}
	}
	var errs []error
	seen := map[string]bool{}
	add := func(label string, err error) {
		// A conflict already names the record in plain words, and the A and
		// AAAA writes on one CNAME name fail with the same sentence, so it is
		// kept as it is and only once.
		var conflict *ConflictError
		if !errors.As(err, &conflict) {
			err = fmt.Errorf("%s: %w", label, err)
		}
		if seen[err.Error()] {
			return
		}
		seen[err.Error()] = true
		errs = append(errs, err)
	}
	ttl := recordTTL(profile)
	if IsCNAME(profile) {
		// A CNAME does not follow the node's address, so ipv4 and ipv6 and
		// the profile's address toggles play no part.
		for _, domain := range profile.Domains {
			if err := withRetry(profile.MaxRetries, func() error {
				return p.SetRecord(ctx, Record{Type: "CNAME", Name: domain, Target: profile.CNAMETarget, TTL: ttl, Comment: comment})
			}); err != nil {
				add("CNAME "+domain, err)
			}
		}
		return errors.Join(errs...)
	}
	for _, domain := range profile.Domains {
		if profile.EnableIPv4 && ipv4 != "" {
			if err := withRetry(profile.MaxRetries, func() error {
				return p.SetRecord(ctx, Record{Type: "A", Name: domain, IP: ipv4, TTL: ttl, Comment: comment})
			}); err != nil {
				add("A "+domain, err)
			}
		}
		if profile.EnableIPv6 && ipv6 != "" {
			if err := withRetry(profile.MaxRetries, func() error {
				return p.SetRecord(ctx, Record{Type: "AAAA", Name: domain, IP: ipv6, TTL: ttl, Comment: comment})
			}); err != nil {
				add("AAAA "+domain, err)
			}
		}
	}
	return errors.Join(errs...)
}

func withRetry(maxRetries int, fn func() error) error {
	attempts := maxRetries
	if attempts < 1 {
		attempts = 1
	}
	var err error
	for i := 0; i < attempts; i++ {
		if err = fn(); err == nil {
			return nil
		}
		// A conflicting record stays until a person removes it; asking
		// again only spends rate limit.
		var conflict *ConflictError
		if errors.As(err, &conflict) {
			return err
		}
	}
	return err
}

// GuardOutbound rejects URLs that resolve to loopback, private, link-local,
// unspecified, or cloud-metadata addresses. This blunts SSRF via an
// admin-configured webhook URL. It performs a real DNS lookup; callers that
// must reach loopback (tests) construct the provider without this guard.
func GuardOutbound(raw string) error {
	return outbound.GuardURL(raw)
}
