package proxycore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
)

// LineChainRealityClientFingerprint is the reviewed strict-alpha uTLS profile
// bound into every canonical line-chain fragment.
const LineChainRealityClientFingerprint = "chrome"

type LineChainOutboundOptions struct {
	Tag               string
	SourceInboundTag  string
	Server            string
	ServerPort        int
	UUID              string
	Flow              string
	SNI               string
	RealityPublicKey  string
	RealityShortID    string
	ClientFingerprint string
}

type LineChainFragment struct {
	JSON   string
	SHA256 string
}

type lineChainFragmentJSON struct {
	Outbounds []lineChainOutbound `json:"outbounds"`
	Route     lineChainRoute      `json:"route"`
}

type lineChainOutbound struct {
	Type       string             `json:"type"`
	Tag        string             `json:"tag"`
	Server     string             `json:"server"`
	ServerPort int                `json:"server_port"`
	UUID       string             `json:"uuid"`
	Flow       string             `json:"flow,omitempty"`
	TLS        lineChainClientTLS `json:"tls"`
}

type lineChainClientTLS struct {
	Enabled    bool                   `json:"enabled"`
	ServerName string                 `json:"server_name"`
	UTLS       lineChainClientUTLS    `json:"utls"`
	Reality    lineChainClientReality `json:"reality"`
}

type lineChainClientUTLS struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint"`
}

type lineChainClientReality struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id"`
}

type lineChainRoute struct {
	Rules []lineChainRouteRule `json:"rules"`
}

type lineChainRouteRule struct {
	Inbound  []string `json:"inbound"`
	Action   string   `json:"action"`
	Outbound string   `json:"outbound"`
}

// RenderLineChainFragment renders the narrow E3 partial config: exactly one
// VLESS+REALITY outbound and one route from the source inbound.
func RenderLineChainFragment(opts LineChainOutboundOptions) (LineChainFragment, error) {
	if !safeTagRe.MatchString(strings.TrimSpace(opts.Tag)) || !safeTagRe.MatchString(strings.TrimSpace(opts.SourceInboundTag)) {
		return LineChainFragment{}, errors.New("line chain tags are invalid")
	}
	if strings.TrimSpace(opts.Server) == "" || net.ParseIP(strings.TrimSpace(opts.Server)) == nil {
		if err := validateHostToken(strings.TrimSpace(opts.Server)); err != nil {
			return LineChainFragment{}, fmt.Errorf("line chain server: %w", err)
		}
	}
	if opts.ServerPort < 1 || opts.ServerPort > 65535 {
		return LineChainFragment{}, fmt.Errorf("line chain server port %d is invalid", opts.ServerPort)
	}
	if !uuidRe.MatchString(strings.TrimSpace(opts.UUID)) {
		return LineChainFragment{}, errors.New("line chain UUID credential is invalid")
	}
	if err := validateHostToken(strings.TrimSpace(opts.SNI)); err != nil {
		return LineChainFragment{}, fmt.Errorf("line chain SNI: %w", err)
	}
	if !realityKeyRe.MatchString(strings.TrimSpace(opts.RealityPublicKey)) {
		return LineChainFragment{}, errors.New("line chain REALITY public key is invalid")
	}
	if !realityShortIDRe.MatchString(strings.TrimSpace(opts.RealityShortID)) || len(strings.TrimSpace(opts.RealityShortID))%2 != 0 {
		return LineChainFragment{}, errors.New("line chain REALITY short id is invalid")
	}
	if opts.ClientFingerprint != LineChainRealityClientFingerprint {
		return LineChainFragment{}, errors.New("line chain REALITY client fingerprint is invalid")
	}
	fragment := lineChainFragmentJSON{
		Outbounds: []lineChainOutbound{{
			Type: modelProxyProtocolVLESS(), Tag: strings.TrimSpace(opts.Tag),
			Server: strings.TrimSpace(opts.Server), ServerPort: opts.ServerPort,
			UUID: strings.ToLower(strings.TrimSpace(opts.UUID)), Flow: strings.TrimSpace(opts.Flow),
			TLS: lineChainClientTLS{
				Enabled: true, ServerName: strings.TrimSpace(opts.SNI),
				UTLS:    lineChainClientUTLS{Enabled: true, Fingerprint: opts.ClientFingerprint},
				Reality: lineChainClientReality{Enabled: true, PublicKey: strings.TrimSpace(opts.RealityPublicKey), ShortID: strings.TrimSpace(opts.RealityShortID)},
			},
		}},
		Route: lineChainRoute{Rules: []lineChainRouteRule{{
			Inbound: []string{strings.TrimSpace(opts.SourceInboundTag)}, Action: "route", Outbound: strings.TrimSpace(opts.Tag),
		}}},
	}
	raw, err := json.MarshalIndent(fragment, "", "  ")
	if err != nil {
		return LineChainFragment{}, fmt.Errorf("marshal line chain fragment: %w", err)
	}
	raw = append(raw, '\n')
	sum := sha256.Sum256(raw)
	return LineChainFragment{JSON: string(raw), SHA256: hex.EncodeToString(sum[:])}, nil
}

// Kept local to avoid leaking the private renderer structs while retaining the
// SDK's canonical protocol spelling.
func modelProxyProtocolVLESS() string { return "vless" }
