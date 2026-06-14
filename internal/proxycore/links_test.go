package proxycore

import (
	"encoding/base64"
	"encoding/json"
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

func TestVLESSRealitySubscriptionFormatsRenderSingBoxAndClash(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	profile := baseProfile()
	profile.AppliedSHA256 = strings.Repeat("a", 64)
	user := baseUser("alice", "Alice", "11111111-1111-4111-8111-111111111111", now.Add(-time.Hour))

	endpoints, warnings, err := VLESSRealityEndpoints(user, []SubscriptionProfile{{Profile: profile, NodeName: "Node A"}}, []model.ProxyInbound{baseInbound()}, SubscriptionOptions{Now: now})
	if err != nil {
		t.Fatalf("VLESSRealityEndpoints returned error: %v", err)
	}
	if len(warnings) != 0 || len(endpoints) != 1 {
		t.Fatalf("unexpected endpoint render: endpoints=%+v warnings=%v", endpoints, warnings)
	}

	singBoxBody, err := SingBoxClientSubscription(endpoints)
	if err != nil {
		t.Fatalf("SingBoxClientSubscription returned error: %v", err)
	}
	var singBox struct {
		Outbounds []struct {
			Type       string `json:"type"`
			Tag        string `json:"tag"`
			Server     string `json:"server"`
			ServerPort int    `json:"server_port"`
			UUID       string `json:"uuid"`
			Flow       string `json:"flow"`
			Network    string `json:"network"`
			TLS        struct {
				Enabled    bool     `json:"enabled"`
				ServerName string   `json:"server_name"`
				ALPN       []string `json:"alpn"`
				UTLS       struct {
					Enabled     bool   `json:"enabled"`
					Fingerprint string `json:"fingerprint"`
				} `json:"utls"`
				Reality struct {
					Enabled   bool   `json:"enabled"`
					PublicKey string `json:"public_key"`
					ShortID   string `json:"short_id"`
				} `json:"reality"`
			} `json:"tls"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(singBoxBody, &singBox); err != nil {
		t.Fatalf("sing-box subscription did not unmarshal: %v\n%s", err, singBoxBody)
	}
	if len(singBox.Outbounds) != 1 {
		t.Fatalf("outbounds len = %d, want 1", len(singBox.Outbounds))
	}
	out := singBox.Outbounds[0]
	if out.Type != model.ProxyProtocolVLESS || out.Tag != "Node A - VLESS Reality 443" || out.Server != "jp1.dns.roobli.org" || out.ServerPort != 443 {
		t.Fatalf("unexpected sing-box outbound: %+v", out)
	}
	if out.UUID != "11111111-1111-4111-8111-111111111111" || out.Flow != "xtls-rprx-vision" || out.Network != "tcp" {
		t.Fatalf("unexpected VLESS fields: %+v", out)
	}
	if !out.TLS.Enabled || out.TLS.ServerName != "cdn.example.com" || strings.Join(out.TLS.ALPN, ",") != "h2,http/1.1" {
		t.Fatalf("unexpected TLS fields: %+v", out.TLS)
	}
	if !out.TLS.UTLS.Enabled || out.TLS.UTLS.Fingerprint != "chrome" {
		t.Fatalf("unexpected uTLS fields: %+v", out.TLS.UTLS)
	}
	if !out.TLS.Reality.Enabled || out.TLS.Reality.PublicKey != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" || out.TLS.Reality.ShortID != "0123456789abcdef" {
		t.Fatalf("unexpected REALITY fields: %+v", out.TLS.Reality)
	}

	clashBody := string(ClashMetaSubscription(endpoints))
	for _, want := range []string{
		`proxies:`,
		`name: "Node A - VLESS Reality 443"`,
		`type: vless`,
		`server: "jp1.dns.roobli.org"`,
		`port: 443`,
		`uuid: "11111111-1111-4111-8111-111111111111"`,
		`network: tcp`,
		`tls: true`,
		`flow: "xtls-rprx-vision"`,
		`packet-encoding: xudp`,
		`encryption: ""`,
		`servername: "cdn.example.com"`,
		`client-fingerprint: "chrome"`,
		`reality-opts:`,
		`public-key: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"`,
		`short-id: "0123456789abcdef"`,
	} {
		if !strings.Contains(clashBody, want) {
			t.Fatalf("clash subscription missing %q:\n%s", want, clashBody)
		}
	}

	for _, leak := range []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sub-token-secret", "proxy-password-secret", `"sub_token"`} {
		if strings.Contains(string(singBoxBody), leak) || strings.Contains(clashBody, leak) {
			t.Fatalf("subscription format leaked %q:\nsing-box=%s\nclash=%s", leak, singBoxBody, clashBody)
		}
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

func TestVLESSRealityLinksIncludeAppliedXrayProfiles(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	profile := baseProfile()
	profile.Core = model.ProxyCoreXray
	profile.AppliedSHA256 = strings.Repeat("b", 64)
	inbound := baseInbound()
	inbound.Core = model.ProxyCoreXray
	user := baseUser("alice", "Alice", "11111111-1111-4111-8111-111111111111", now.Add(-time.Hour))

	links, warnings, err := VLESSRealityLinks(user, []SubscriptionProfile{{Profile: profile, NodeName: "Xray JP"}}, []model.ProxyInbound{inbound}, SubscriptionOptions{Now: now})
	if err != nil {
		t.Fatalf("VLESSRealityLinks returned error: %v", err)
	}
	if len(warnings) != 0 || len(links) != 1 {
		t.Fatalf("unexpected xray link render: links=%v warnings=%v", links, warnings)
	}
	if !strings.Contains(links[0], "vless://11111111-1111-4111-8111-111111111111@jp1.dns.roobli.org:443?") ||
		!strings.Contains(links[0], "#Xray%20JP%20-%20VLESS%20Reality%20443") {
		t.Fatalf("xray profile did not produce normal VLESS REALITY link: %s", links[0])
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
