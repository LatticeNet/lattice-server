package proxycore

import (
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestVLESSRealityLinksRenderPlainAndBase64Subscriptions(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	profile := baseProfile()
	profile.AppliedSHA256 = strings.Repeat("a", 64)
	user := baseUser("alice", "Alice", "11111111-1111-4111-8111-111111111111", now.Add(-time.Hour))
	user.TrafficLimitBytes = 100
	user.UsedBytes = 40
	user.ExpiresAt = now.Add(24 * time.Hour)

	links, warnings, err := VLESSRealityLinks(user, []SubscriptionProfile{{Profile: profile, NodeName: "Node A"}}, []model.ProxyInbound{baseInbound()}, SubscriptionOptions{Now: now})
	if err != nil {
		t.Fatalf("VLESSRealityLinks returned error: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if len(links) != 1 {
		t.Fatalf("links len = %d, want 1: %v", len(links), links)
	}
	if strings.Contains(links[0], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") || strings.Contains(links[0], "sub-token-secret") || strings.Contains(links[0], "proxy-password-secret") {
		t.Fatalf("subscription link leaked control-plane secret: %s", links[0])
	}

	parsed, err := url.Parse(links[0])
	if err != nil {
		t.Fatalf("link did not parse: %v", err)
	}
	if parsed.Scheme != "vless" {
		t.Fatalf("scheme = %q, want vless", parsed.Scheme)
	}
	if got := parsed.User.Username(); got != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("uuid = %q", got)
	}
	if parsed.Hostname() != "jp1.dns.roobli.org" || parsed.Port() != "443" {
		t.Fatalf("host/port = %s", parsed.Host)
	}
	q := parsed.Query()
	for key, want := range map[string]string{
		"type":       model.ProxyTransportTCP,
		"encryption": "none",
		"security":   model.ProxySecurityReality,
		"flow":       "xtls-rprx-vision",
		"pbk":        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"sid":        "0123456789abcdef",
		"sni":        "cdn.example.com",
		"fp":         "chrome",
		"alpn":       "h2,http/1.1",
	} {
		if got := q.Get(key); got != want {
			t.Fatalf("query %s = %q, want %q; link=%s", key, got, want, links[0])
		}
	}
	if parsed.Fragment != "Node A - VLESS Reality 443" {
		t.Fatalf("fragment = %q", parsed.Fragment)
	}

	plain := PlainSubscription(links)
	if got := string(plain); !strings.HasSuffix(got, "\n") || strings.Count(got, "\n") != 1 {
		t.Fatalf("plain subscription should contain one trailing newline: %q", got)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(Base64Subscription(links)))
	if err != nil {
		t.Fatalf("base64 subscription did not decode: %v", err)
	}
	if string(decoded) != string(plain) {
		t.Fatalf("base64 decoded mismatch: got %q want %q", decoded, plain)
	}
	wantUserinfo := "upload=0; download=40; total=100; expire=" + strconv.FormatInt(user.ExpiresAt.Unix(), 10)
	if got := SubscriptionUserinfo(user); got != wantUserinfo {
		t.Fatalf("userinfo = %q, want %q", got, wantUserinfo)
	}
}

func TestVLESSRealityLinksSkipInactiveUsersAndUnappliedProfiles(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	profile := baseProfile()
	profile.AppliedSHA256 = strings.Repeat("a", 64)
	user := baseUser("alice", "Alice", "11111111-1111-4111-8111-111111111111", now.Add(-time.Hour))
	user.Enabled = false

	links, warnings, err := VLESSRealityLinks(user, []SubscriptionProfile{{Profile: profile}}, []model.ProxyInbound{baseInbound()}, SubscriptionOptions{Now: now})
	if err != nil {
		t.Fatalf("inactive user returned error: %v", err)
	}
	if len(links) != 0 || !strings.Contains(strings.Join(warnings, "\n"), "disabled") {
		t.Fatalf("inactive user should produce no links and a warning: links=%v warnings=%v", links, warnings)
	}

	user.Enabled = true
	profile.AppliedSHA256 = ""
	links, warnings, err = VLESSRealityLinks(user, []SubscriptionProfile{{Profile: profile}}, []model.ProxyInbound{baseInbound()}, SubscriptionOptions{Now: now})
	if err != nil {
		t.Fatalf("unapplied profile returned error: %v", err)
	}
	if len(links) != 0 || !strings.Contains(strings.Join(warnings, "\n"), "no applied config") {
		t.Fatalf("unapplied profile should produce no links and a warning: links=%v warnings=%v", links, warnings)
	}
}

func TestVLESSRealityLinksRejectUnsafePublicSubscriptionInputs(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	profile := baseProfile()
	profile.AppliedSHA256 = strings.Repeat("a", 64)
	profile.Hostname = "bad.example.com/path"
	user := baseUser("alice", "Alice", "11111111-1111-4111-8111-111111111111", now.Add(-time.Hour))
	_, _, err := VLESSRealityLinks(user, []SubscriptionProfile{{Profile: profile}}, []model.ProxyInbound{baseInbound()}, SubscriptionOptions{Now: now})
	if err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("unsafe hostname error = %v", err)
	}

	profile = baseProfile()
	profile.AppliedSHA256 = strings.Repeat("a", 64)
	inbound := baseInbound()
	inbound.RealityPublicKey = ""
	_, _, err = VLESSRealityLinks(user, []SubscriptionProfile{{Profile: profile}}, []model.ProxyInbound{inbound}, SubscriptionOptions{Now: now})
	if err == nil || !strings.Contains(err.Error(), "public key") {
		t.Fatalf("missing public key error = %v", err)
	}
}
