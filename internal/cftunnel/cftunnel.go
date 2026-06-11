// Package cftunnel renders a cloudflared tunnel config.yml from a tunnel
// profile. cloudflared dials out to Cloudflare's edge, so a node behind NAT can
// expose HTTP/SSH/TCP services with no inbound ports. Generating the config is
// dependency-free (hand-rendered YAML with validated fields); the tunnel
// credentials stay node-local.
package cftunnel

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
)

// hostnameRe loosely validates a DNS hostname.
var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)

// tunnelIDRe bounds the tunnel id / credentials path to safe characters.
var tunnelIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// GenerateConfig renders a cloudflared config.yml for the profile. A catch-all
// 404 rule is always appended (cloudflared requires the last rule to have no
// hostname).
func GenerateConfig(p model.TunnelProfile) (string, error) {
	if !tunnelIDRe.MatchString(p.TunnelID) {
		return "", fmt.Errorf("invalid tunnel id %q", p.TunnelID)
	}
	credFile := p.CredentialsFile
	if credFile == "" {
		credFile = fmt.Sprintf("/etc/cloudflared/%s.json", p.TunnelID)
	}
	if strings.ContainsAny(credFile, "\n\r") {
		return "", fmt.Errorf("invalid credentials file path")
	}
	if len(p.Ingress) == 0 {
		return "", fmt.Errorf("at least one ingress rule is required")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "tunnel: %s\n", p.TunnelID)
	fmt.Fprintf(&b, "credentials-file: %s\n", credFile)
	fmt.Fprintf(&b, "ingress:\n")
	for _, rule := range p.Ingress {
		if !hostnameRe.MatchString(rule.Hostname) {
			return "", fmt.Errorf("invalid ingress hostname %q", rule.Hostname)
		}
		if err := validateService(rule.Service); err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "  - hostname: %s\n", rule.Hostname)
		if rule.Path != "" {
			if strings.ContainsAny(rule.Path, "\n\r ") {
				return "", fmt.Errorf("invalid ingress path %q", rule.Path)
			}
			fmt.Fprintf(&b, "    path: %s\n", rule.Path)
		}
		fmt.Fprintf(&b, "    service: %s\n", rule.Service)
	}
	fmt.Fprintf(&b, "  - service: http_status:404\n")
	return b.String(), nil
}

func validateService(service string) error {
	if service == "" {
		return fmt.Errorf("ingress service is required")
	}
	if strings.ContainsAny(service, "\n\r ") {
		return fmt.Errorf("invalid service %q", service)
	}
	// cloudflared special form, e.g. http_status:404
	if strings.HasPrefix(service, "http_status:") {
		return nil
	}
	u, err := url.Parse(service)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid service url %q", service)
	}
	switch u.Scheme {
	case "http", "https", "ssh", "rdp", "tcp", "unix":
		return nil
	default:
		return fmt.Errorf("unsupported service scheme %q", u.Scheme)
	}
}
