package proxycore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestRenderXrayVLESSRealityConfig(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	profile := baseProfile()
	profile.Core = model.ProxyCoreXray
	inbound := baseInbound()
	inbound.Core = model.ProxyCoreXray

	artifact, err := RenderXrayConfigJSON(profile, []model.ProxyInbound{inbound}, []model.ProxyUser{
		baseUser("alice", "Alice", "11111111-1111-1111-1111-111111111111", now.Add(-3*time.Hour)),
		baseUser("bob", "Bob", "22222222-2222-2222-2222-222222222222", now.Add(-2*time.Hour)),
		{
			ID: "disabled", Name: "Disabled", Enabled: false,
			UUID:       "33333333-3333-3333-3333-333333333333",
			InboundIDs: []string{"in-reality-443"},
			Status:     model.ProxyUserStatusActive,
			CreatedAt:  now.Add(-1 * time.Hour),
		},
	}, RenderOptions{Now: now})
	if err != nil {
		t.Fatalf("RenderXrayConfigJSON returned error: %v", err)
	}
	if artifact.Core != model.ProxyCoreXray {
		t.Fatalf("artifact core = %q", artifact.Core)
	}
	if artifact.ConfigPath != DefaultXrayConfigPath {
		t.Fatalf("config path = %q, want default %q", artifact.ConfigPath, DefaultXrayConfigPath)
	}
	wantSum := sha256.Sum256([]byte(artifact.ConfigJSON))
	if artifact.ConfigSHA256 != hex.EncodeToString(wantSum[:]) {
		t.Fatalf("config sha mismatch: got %s", artifact.ConfigSHA256)
	}
	for _, leak := range []string{"sub-token-secret", "proxy-password-secret"} {
		if strings.Contains(artifact.ConfigJSON, leak) {
			t.Fatalf("non-render credential leaked into config JSON: %q", leak)
		}
	}

	var parsed struct {
		Log struct {
			LogLevel string `json:"loglevel"`
		} `json:"log"`
		Inbounds []struct {
			Tag      string `json:"tag"`
			Listen   string `json:"listen"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Settings struct {
				Decryption string `json:"decryption"`
				Clients    []struct {
					ID    string `json:"id"`
					Email string `json:"email"`
					Flow  string `json:"flow"`
				} `json:"clients"`
			} `json:"settings"`
			StreamSettings struct {
				Network         string `json:"network"`
				Security        string `json:"security"`
				RealitySettings struct {
					Dest        string   `json:"dest"`
					ServerNames []string `json:"serverNames"`
					PrivateKey  string   `json:"privateKey"`
					ShortIDs    []string `json:"shortIds"`
					MaxTimeDiff int64    `json:"maxTimeDiff"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
		Outbounds []struct {
			Protocol string `json:"protocol"`
			Tag      string `json:"tag"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(artifact.ConfigJSON), &parsed); err != nil {
		t.Fatalf("rendered JSON did not unmarshal: %v\n%s", err, artifact.ConfigJSON)
	}
	if parsed.Log.LogLevel != "warning" {
		t.Fatalf("loglevel = %q", parsed.Log.LogLevel)
	}
	if len(parsed.Inbounds) != 1 {
		t.Fatalf("inbounds len = %d, want 1", len(parsed.Inbounds))
	}
	in := parsed.Inbounds[0]
	if in.Tag != "in-reality-443" || in.Listen != "::" || in.Port != 443 || in.Protocol != model.ProxyProtocolVLESS {
		t.Fatalf("unexpected inbound: %+v", in)
	}
	if in.Settings.Decryption != "none" || len(in.Settings.Clients) != 2 {
		t.Fatalf("unexpected VLESS settings: %+v", in.Settings)
	}
	if in.Settings.Clients[0].ID != "11111111-1111-1111-1111-111111111111" ||
		in.Settings.Clients[0].Email != "alice" ||
		in.Settings.Clients[0].Flow != "xtls-rprx-vision" {
		t.Fatalf("unexpected first client: %+v", in.Settings.Clients[0])
	}
	if in.StreamSettings.Network != model.ProxyTransportTCP || in.StreamSettings.Security != model.ProxySecurityReality {
		t.Fatalf("unexpected stream settings: %+v", in.StreamSettings)
	}
	reality := in.StreamSettings.RealitySettings
	if reality.Dest != "www.microsoft.com:443" ||
		reality.PrivateKey != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ||
		strings.Join(reality.ShortIDs, ",") != "0123456789abcdef" ||
		strings.Join(reality.ServerNames, ",") != "cdn.example.com" ||
		reality.MaxTimeDiff != 60000 {
		t.Fatalf("unexpected REALITY settings: %+v", reality)
	}
	if len(parsed.Outbounds) != 1 || parsed.Outbounds[0].Protocol != "freedom" || parsed.Outbounds[0].Tag != "direct" {
		t.Fatalf("unexpected outbounds: %+v", parsed.Outbounds)
	}
	if !strings.Contains(strings.Join(artifact.Warnings, "\n"), "disabled") {
		t.Fatalf("warnings %v did not include disabled user", artifact.Warnings)
	}
}

func TestRenderXrayUsesProfileOverrides(t *testing.T) {
	profile := baseProfile()
	profile.Core = model.ProxyCoreXray
	profile.ListenIP = "10.66.0.9"
	profile.ConfigPath = "/etc/xray/config.json"
	inbound := baseInbound()
	inbound.Core = model.ProxyCoreXray
	inbound.Listen = "127.0.0.1"

	artifact, err := RenderXrayConfigJSON(profile, []model.ProxyInbound{inbound}, []model.ProxyUser{
		baseUser("alice", "Alice", "11111111-1111-1111-1111-111111111111", time.Now()),
	}, RenderOptions{Now: time.Now()})
	if err != nil {
		t.Fatalf("RenderXrayConfigJSON returned error: %v", err)
	}
	if artifact.ConfigPath != profile.ConfigPath {
		t.Fatalf("config path = %q, want %q", artifact.ConfigPath, profile.ConfigPath)
	}
	if !strings.Contains(artifact.ConfigJSON, `"listen": "10.66.0.9"`) {
		t.Fatalf("profile listen override not rendered:\n%s", artifact.ConfigJSON)
	}
}

func TestRenderXrayRejectsUnsupportedOrMismatchedInputs(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	user := baseUser("alice", "Alice", "11111111-1111-1111-1111-111111111111", now)

	tests := []struct {
		name    string
		profile model.ProxyNodeProfile
		inbound model.ProxyInbound
		want    string
	}{
		{
			name: "profile core mismatch",
			profile: func() model.ProxyNodeProfile {
				p := baseProfile()
				p.Core = model.ProxyCoreSingbox
				return p
			}(),
			inbound: func() model.ProxyInbound {
				in := baseInbound()
				in.Core = model.ProxyCoreXray
				return in
			}(),
			want: "renderer requires xray",
		},
		{
			name: "inbound core mismatch",
			profile: func() model.ProxyNodeProfile {
				p := baseProfile()
				p.Core = model.ProxyCoreXray
				return p
			}(),
			inbound: baseInbound(),
			want:    "renderer requires xray",
		},
		{
			name: "unsupported transport",
			profile: func() model.ProxyNodeProfile {
				p := baseProfile()
				p.Core = model.ProxyCoreXray
				return p
			}(),
			inbound: func() model.ProxyInbound {
				in := baseInbound()
				in.Core = model.ProxyCoreXray
				in.Transport = model.ProxyTransportWS
				return in
			}(),
			want: "unsupported transport",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RenderXrayConfigJSON(tt.profile, []model.ProxyInbound{tt.inbound}, []model.ProxyUser{user}, RenderOptions{Now: now})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}
