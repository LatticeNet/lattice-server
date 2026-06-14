package proxycore

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

const (
	SubscriptionFormatBase64 = "base64"
	SubscriptionFormatPlain  = "plain"
)

// SubscriptionProfile is the small server-provided view needed to render links.
// It intentionally carries display-only node metadata, not Node secrets.
type SubscriptionProfile struct {
	Profile  model.ProxyNodeProfile
	NodeName string
}

type SubscriptionOptions struct {
	Now time.Time
}

// VLESSRealityLinks renders MVP VLESS+REALITY links for one subscriber across
// applied node profiles. It returns an empty slice for inactive users instead
// of an error so the public subscription endpoint can stay token-stable while
// enforcing expiry/quota server-side.
func VLESSRealityLinks(user model.ProxyUser, profiles []SubscriptionProfile, inbounds []model.ProxyInbound, opts SubscriptionOptions) ([]string, []string, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if reason := skipProxyUserReason(user, now); reason != "" {
		return []string{}, []string{"user " + user.ID + " has no active subscription links: " + reason}, nil
	}
	if !safeTagRe.MatchString(user.ID) {
		return nil, nil, fmt.Errorf("invalid proxy user id %q", user.ID)
	}
	if !uuidRe.MatchString(user.UUID) {
		return nil, nil, fmt.Errorf("proxy user %s has invalid uuid", user.ID)
	}

	byID, err := inboundMap(inbounds)
	if err != nil {
		return nil, nil, err
	}
	sortedProfiles := append([]SubscriptionProfile(nil), profiles...)
	sort.Slice(sortedProfiles, func(i, j int) bool {
		return sortedProfiles[i].Profile.NodeID < sortedProfiles[j].Profile.NodeID
	})

	links := []string{}
	warnings := []string{}
	for _, sp := range sortedProfiles {
		profile := sp.Profile
		if profile.Core != model.ProxyCoreSingbox {
			warnings = append(warnings, fmt.Sprintf("profile %s omitted: unsupported core %s", profile.NodeID, profile.Core))
			continue
		}
		if profile.AppliedSHA256 == "" {
			warnings = append(warnings, fmt.Sprintf("profile %s omitted: no applied config", profile.NodeID))
			continue
		}
		if profile.LastError != "" {
			warnings = append(warnings, fmt.Sprintf("profile %s omitted: last apply error is not clear", profile.NodeID))
			continue
		}
		host := strings.TrimSpace(profile.Hostname)
		if host == "" {
			warnings = append(warnings, fmt.Sprintf("profile %s omitted: hostname is required for subscriptions", profile.NodeID))
			continue
		}
		if err := validateSubscriptionHost(host); err != nil {
			return nil, nil, fmt.Errorf("profile %s hostname: %w", profile.NodeID, err)
		}
		for _, inboundID := range profile.InboundIDs {
			inbound, ok := byID[inboundID]
			if !ok {
				return nil, nil, fmt.Errorf("profile %s references missing inbound %q", profile.NodeID, inboundID)
			}
			if !userAppliesToInbound(user, inboundID) {
				continue
			}
			link, err := vlessRealityLink(user, sp, inbound, host)
			if err != nil {
				return nil, nil, err
			}
			links = append(links, link)
		}
	}
	sort.Strings(links)
	return links, warnings, nil
}

func vlessRealityLink(user model.ProxyUser, sp SubscriptionProfile, inbound model.ProxyInbound, host string) (string, error) {
	if err := validateVLESSRealityInbound(inbound); err != nil {
		return "", err
	}
	if inbound.RealityPublicKey == "" || !realityKeyRe.MatchString(inbound.RealityPublicKey) {
		return "", fmt.Errorf("inbound %s has invalid reality public key", inbound.ID)
	}
	if len(inbound.RealityShortIDs) == 0 {
		return "", fmt.Errorf("inbound %s requires at least one reality short id", inbound.ID)
	}
	shortID := strings.ToLower(strings.TrimSpace(inbound.RealityShortIDs[0]))
	if shortID == "" || !realityShortIDRe.MatchString(shortID) || len(shortID)%2 != 0 {
		return "", fmt.Errorf("inbound %s has invalid reality short id %q", inbound.ID, inbound.RealityShortIDs[0])
	}
	values := url.Values{}
	values.Set("type", model.ProxyTransportTCP)
	values.Set("encryption", "none")
	values.Set("security", model.ProxySecurityReality)
	values.Set("flow", "xtls-rprx-vision")
	values.Set("pbk", inbound.RealityPublicKey)
	values.Set("sid", shortID)
	if inbound.SNI != "" {
		if err := validateHostToken(inbound.SNI); err != nil {
			return "", fmt.Errorf("inbound %s sni: %w", inbound.ID, err)
		}
		values.Set("sni", inbound.SNI)
	}
	fingerprint := strings.TrimSpace(inbound.Fingerprint)
	if fingerprint == "" {
		fingerprint = "chrome"
	}
	if strings.ContainsFunc(fingerprint, isUnsafeControl) {
		return "", fmt.Errorf("inbound %s fingerprint contains control characters", inbound.ID)
	}
	values.Set("fp", fingerprint)
	if len(inbound.ALPN) > 0 {
		values.Set("alpn", strings.Join(cleanStringList(inbound.ALPN), ","))
	}
	label := subscriptionLabel(sp, inbound)
	return "vless://" + strings.ToLower(user.UUID) + "@" + net.JoinHostPort(host, strconv.Itoa(inbound.Port)) + "?" + values.Encode() + "#" + url.PathEscape(label), nil
}

func subscriptionLabel(sp SubscriptionProfile, inbound model.ProxyInbound) string {
	node := strings.TrimSpace(sp.NodeName)
	if node == "" {
		node = strings.TrimSpace(sp.Profile.NodeID)
	}
	name := strings.TrimSpace(inbound.Name)
	if name == "" || name == inbound.ID {
		return node
	}
	return node + " - " + name
}

func validateSubscriptionHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("host is required")
	}
	if strings.ContainsFunc(host, isUnsafeControl) {
		return fmt.Errorf("host contains control characters")
	}
	if addr, err := netip.ParseAddr(host); err == nil && addr.IsValid() {
		return nil
	}
	if len(host) > 253 {
		return fmt.Errorf("host is too long")
	}
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return fmt.Errorf("host has an empty label")
	}
	if strings.ContainsAny(host, "/\\\"'`$;&|<>(){}[]@?#%:, ") {
		return fmt.Errorf("host contains unsafe characters: %q", host)
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return fmt.Errorf("host has an empty label")
		}
		if len(label) > 63 {
			return fmt.Errorf("host label is too long")
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("host label has invalid hyphen placement")
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return fmt.Errorf("host contains unsupported character %q", r)
		}
	}
	return nil
}

func PlainSubscription(links []string) []byte {
	if len(links) == 0 {
		return []byte{}
	}
	return []byte(strings.Join(links, "\n") + "\n")
}

func Base64Subscription(links []string) []byte {
	plain := PlainSubscription(links)
	if len(plain) == 0 {
		return []byte{}
	}
	return []byte(base64.StdEncoding.EncodeToString(plain))
}

func SubscriptionUserinfo(user model.ProxyUser) string {
	expire := int64(0)
	if !user.ExpiresAt.IsZero() {
		expire = user.ExpiresAt.Unix()
	}
	total := user.TrafficLimitBytes
	if total < 0 {
		total = 0
	}
	download := user.UsedBytes
	if download < 0 {
		download = 0
	}
	return fmt.Sprintf("upload=0; download=%d; total=%d; expire=%d", download, total, expire)
}
