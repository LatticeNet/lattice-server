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

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/outbound"
)

// Record is a single DNS record to set.
type Record struct {
	Type string // "A" or "AAAA"
	Name string // fully-qualified record name, e.g. node.example.com
	IP   string
	TTL  int
}

// Provider sets DNS records for one backend (Cloudflare, webhook, ...).
type Provider interface {
	Kind() string
	SetRecord(ctx context.Context, r Record) error
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

// Apply pushes the node's current IPs to every domain in the profile, honoring
// EnableIPv4/EnableIPv6 and retrying each record up to MaxRetries times. It
// returns the joined error of all failed records (nil if all succeeded).
func Apply(ctx context.Context, p Provider, profile model.DDNSProfile, ipv4, ipv6 string) error {
	var errs []error
	ttl := recordTTL(profile)
	for _, domain := range profile.Domains {
		if profile.EnableIPv4 && ipv4 != "" {
			if err := withRetry(profile.MaxRetries, func() error {
				return p.SetRecord(ctx, Record{Type: "A", Name: domain, IP: ipv4, TTL: ttl})
			}); err != nil {
				errs = append(errs, fmt.Errorf("A %s: %w", domain, err))
			}
		}
		if profile.EnableIPv6 && ipv6 != "" {
			if err := withRetry(profile.MaxRetries, func() error {
				return p.SetRecord(ctx, Record{Type: "AAAA", Name: domain, IP: ipv6, TTL: ttl})
			}); err != nil {
				errs = append(errs, fmt.Errorf("AAAA %s: %w", domain, err))
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
