package proxycore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

type xrayConfig struct {
	Log       xrayLog        `json:"log"`
	Inbounds  []xrayInbound  `json:"inbounds"`
	Outbounds []xrayOutbound `json:"outbounds"`
	Routing   xrayRouting    `json:"routing"`
}

type xrayLog struct {
	LogLevel string `json:"loglevel"`
}

type xrayInbound struct {
	Tag            string               `json:"tag"`
	Listen         string               `json:"listen"`
	Port           int                  `json:"port"`
	Protocol       string               `json:"protocol"`
	Settings       xrayVLESSSettings    `json:"settings"`
	StreamSettings xrayStreamSettings   `json:"streamSettings"`
	Sniffing       xraySniffingSettings `json:"sniffing,omitempty"`
}

type xrayVLESSSettings struct {
	Clients    []xrayVLESSClient `json:"clients"`
	Decryption string            `json:"decryption"`
}

type xrayVLESSClient struct {
	ID    string `json:"id"`
	Email string `json:"email,omitempty"`
	Flow  string `json:"flow,omitempty"`
}

type xrayStreamSettings struct {
	Network         string              `json:"network"`
	Security        string              `json:"security"`
	RealitySettings xrayRealitySettings `json:"realitySettings"`
}

type xrayRealitySettings struct {
	Show        bool     `json:"show"`
	Dest        string   `json:"dest"`
	Xver        int      `json:"xver"`
	ServerNames []string `json:"serverNames,omitempty"`
	PrivateKey  string   `json:"privateKey"`
	ShortIDs    []string `json:"shortIds"`
	MaxTimeDiff int64    `json:"maxTimeDiff,omitempty"`
}

type xraySniffingSettings struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride,omitempty"`
}

type xrayOutbound struct {
	Protocol string `json:"protocol"`
	Tag      string `json:"tag"`
}

type xrayRouting struct {
	DomainStrategy string      `json:"domainStrategy"`
	Rules          []xrayRoute `json:"rules"`
}

type xrayRoute struct {
	Type        string   `json:"type"`
	OutboundTag string   `json:"outboundTag"`
	Protocol    []string `json:"protocol,omitempty"`
}

// RenderXrayConfigJSON renders a canonical xray config for one node profile.
// MVP support intentionally matches the sing-box slice: VLESS over TCP with
// REALITY only. Unsupported protocols/transports fail closed.
func RenderXrayConfigJSON(profile model.ProxyNodeProfile, inbounds []model.ProxyInbound, users []model.ProxyUser, opts RenderOptions) (Artifact, error) {
	cfg, warnings, err := RenderXrayConfig(profile, inbounds, users, opts)
	if err != nil {
		return Artifact{}, err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return Artifact{}, fmt.Errorf("marshal xray config: %w", err)
	}
	data = append(data, '\n')
	sum := sha256.Sum256(data)
	path := strings.TrimSpace(profile.ConfigPath)
	if path == "" {
		path = DefaultXrayConfigPath
	}
	return Artifact{
		Core:         model.ProxyCoreXray,
		ConfigJSON:   string(data),
		ConfigSHA256: hex.EncodeToString(sum[:]),
		ConfigPath:   path,
		Warnings:     warnings,
	}, nil
}

// RenderXrayConfig builds the in-memory xray config from server-owned intent
// models. It uses structs rather than templates so operator input cannot break
// JSON syntax.
func RenderXrayConfig(profile model.ProxyNodeProfile, inbounds []model.ProxyInbound, users []model.ProxyUser, opts RenderOptions) (xrayConfig, []string, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := validateProfileForCore(profile, model.ProxyCoreXray); err != nil {
		return xrayConfig{}, nil, err
	}
	byID, err := inboundMap(inbounds)
	if err != nil {
		return xrayConfig{}, nil, err
	}
	selected, err := selectedInbounds(profile.InboundIDs, byID)
	if err != nil {
		return xrayConfig{}, nil, err
	}

	rendered := make([]xrayInbound, 0, len(selected))
	warnings := []string{}
	usedPorts := map[string]string{}
	for _, inbound := range selected {
		listen := strings.TrimSpace(profile.ListenIP)
		if listen == "" {
			listen = strings.TrimSpace(inbound.Listen)
		}
		if listen == "" {
			listen = DefaultListenAddress
		}
		if err := validateListenAddress(listen); err != nil {
			return xrayConfig{}, nil, fmt.Errorf("inbound %s: %w", inbound.ID, err)
		}
		portKey := net.JoinHostPort(listen, strconv.Itoa(inbound.Port))
		if previous := usedPorts[portKey]; previous != "" {
			return xrayConfig{}, nil, fmt.Errorf("inbound %s conflicts with %s on %s", inbound.ID, previous, portKey)
		}
		usedPorts[portKey] = inbound.ID

		xrayInbound, skipped, err := renderXrayVLESSRealityInbound(inbound, listen, users, now)
		if err != nil {
			return xrayConfig{}, nil, err
		}
		warnings = append(warnings, skipped...)
		rendered = append(rendered, xrayInbound)
	}

	return xrayConfig{
		Log:       xrayLog{LogLevel: "warning"},
		Inbounds:  rendered,
		Outbounds: []xrayOutbound{{Protocol: "freedom", Tag: defaultOutboundTag}},
		Routing: xrayRouting{
			DomainStrategy: "AsIs",
			Rules:          []xrayRoute{},
		},
	}, warnings, nil
}

func renderXrayVLESSRealityInbound(inbound model.ProxyInbound, listen string, users []model.ProxyUser, now time.Time) (xrayInbound, []string, error) {
	if err := validateVLESSRealityInboundForCore(inbound, model.ProxyCoreXray); err != nil {
		return xrayInbound{}, nil, err
	}
	eligible, warnings, err := eligibleVLESSUsers(inbound.ID, users, now)
	if err != nil {
		return xrayInbound{}, nil, err
	}
	if len(eligible) == 0 {
		return xrayInbound{}, nil, fmt.Errorf("inbound %s has no eligible VLESS users", inbound.ID)
	}
	if _, err := parseRealityDest(inbound.RealityDest); err != nil {
		return xrayInbound{}, nil, fmt.Errorf("inbound %s reality_dest: %w", inbound.ID, err)
	}
	clients := make([]xrayVLESSClient, 0, len(eligible))
	for _, user := range eligible {
		clients = append(clients, xrayVLESSClient{
			ID:    user.UUID,
			Email: user.ID,
			Flow:  user.Flow,
		})
	}
	serverNames := []string{}
	if inbound.SNI != "" {
		if err := validateHostToken(inbound.SNI); err != nil {
			return xrayInbound{}, nil, fmt.Errorf("inbound %s sni: %w", inbound.ID, err)
		}
		serverNames = append(serverNames, inbound.SNI)
	}
	return xrayInbound{
		Tag:      inbound.ID,
		Listen:   listen,
		Port:     inbound.Port,
		Protocol: model.ProxyProtocolVLESS,
		Settings: xrayVLESSSettings{
			Clients:    clients,
			Decryption: "none",
		},
		StreamSettings: xrayStreamSettings{
			Network:  model.ProxyTransportTCP,
			Security: model.ProxySecurityReality,
			RealitySettings: xrayRealitySettings{
				Show:        false,
				Dest:        inbound.RealityDest,
				Xver:        0,
				ServerNames: serverNames,
				PrivateKey:  inbound.RealityPrivateKey,
				ShortIDs:    cleanStringList(inbound.RealityShortIDs),
				MaxTimeDiff: 60000,
			},
		},
	}, warnings, nil
}
