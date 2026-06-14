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

func TestRenderSingBoxVLESSRealityConfig(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	artifact, err := RenderSingBoxConfigJSON(baseProfile(), []model.ProxyInbound{baseInbound()}, []model.ProxyUser{
		baseUser("alice", "Alice", "11111111-1111-1111-1111-111111111111", now.Add(-3*time.Hour)),
		{
			ID: "bob", Name: "Bob", Enabled: true,
			UUID:       "22222222-2222-2222-2222-222222222222",
			InboundIDs: []string{"in-reality-443"},
			Status:     model.ProxyUserStatusActive,
			CreatedAt:  now.Add(-2 * time.Hour),
		},
		{
			ID: "disabled", Name: "Disabled", Enabled: false,
			UUID:       "33333333-3333-3333-3333-333333333333",
			InboundIDs: []string{"in-reality-443"},
			Status:     model.ProxyUserStatusActive,
			CreatedAt:  now.Add(-1 * time.Hour),
		},
		{
			ID: "expired", Name: "Expired", Enabled: true,
			UUID:       "44444444-4444-4444-4444-444444444444",
			InboundIDs: []string{"in-reality-443"},
			Status:     model.ProxyUserStatusActive,
			ExpiresAt:  now.Add(-time.Second),
			CreatedAt:  now.Add(-30 * time.Minute),
		},
		{
			ID: "quota", Name: "Quota", Enabled: true,
			UUID:              "55555555-5555-5555-5555-555555555555",
			InboundIDs:        []string{"in-reality-443"},
			Status:            model.ProxyUserStatusActive,
			TrafficLimitBytes: 10,
			UsedBytes:         10,
			CreatedAt:         now.Add(-20 * time.Minute),
		},
		{
			ID: "other-inbound", Name: "Other", Enabled: true,
			UUID:       "66666666-6666-6666-6666-666666666666",
			InboundIDs: []string{"other"},
			Status:     model.ProxyUserStatusActive,
			CreatedAt:  now.Add(-10 * time.Minute),
		},
	}, RenderOptions{Now: now})
	if err != nil {
		t.Fatalf("RenderSingBoxConfigJSON returned error: %v", err)
	}

	if artifact.ConfigPath != DefaultSingBoxConfigPath {
		t.Fatalf("config path = %q, want default %q", artifact.ConfigPath, DefaultSingBoxConfigPath)
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
	for _, snippet := range []string{
		`"type": "vless"`,
		`"listen": "::"`,
		`"listen_port": 443`,
		`"private_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`,
		`"server": "www.microsoft.com"`,
		`"server_port": 443`,
		`"short_id": [`,
		`"0123456789abcdef"`,
		`"final": "direct"`,
	} {
		if !strings.Contains(artifact.ConfigJSON, snippet) {
			t.Fatalf("config JSON missing %q:\n%s", snippet, artifact.ConfigJSON)
		}
	}

	var parsed struct {
		Inbounds []struct {
			Type       string `json:"type"`
			Tag        string `json:"tag"`
			Listen     string `json:"listen"`
			ListenPort int    `json:"listen_port"`
			Users      []struct {
				Name string `json:"name"`
				UUID string `json:"uuid"`
				Flow string `json:"flow"`
			} `json:"users"`
			TLS struct {
				ServerName string   `json:"server_name"`
				ALPN       []string `json:"alpn"`
				Reality    struct {
					Handshake struct {
						Server     string `json:"server"`
						ServerPort int    `json:"server_port"`
					} `json:"handshake"`
				} `json:"reality"`
			} `json:"tls"`
		} `json:"inbounds"`
		Outbounds []struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		} `json:"outbounds"`
		Route struct {
			Final string `json:"final"`
		} `json:"route"`
	}
	if err := json.Unmarshal([]byte(artifact.ConfigJSON), &parsed); err != nil {
		t.Fatalf("rendered JSON did not unmarshal: %v\n%s", err, artifact.ConfigJSON)
	}
	if len(parsed.Inbounds) != 1 {
		t.Fatalf("inbounds len = %d, want 1", len(parsed.Inbounds))
	}
	in := parsed.Inbounds[0]
	if in.Type != model.ProxyProtocolVLESS || in.Tag != "in-reality-443" || in.Listen != "::" || in.ListenPort != 443 {
		t.Fatalf("unexpected inbound: %+v", in)
	}
	if len(in.Users) != 2 {
		t.Fatalf("eligible users len = %d, want 2; warnings=%v", len(in.Users), artifact.Warnings)
	}
	if in.Users[0].Name != "Alice" || in.Users[0].UUID != "11111111-1111-1111-1111-111111111111" || in.Users[0].Flow != "xtls-rprx-vision" {
		t.Fatalf("unexpected first user: %+v", in.Users[0])
	}
	if in.Users[1].Name != "Bob" || in.Users[1].UUID != "22222222-2222-2222-2222-222222222222" {
		t.Fatalf("unexpected second user: %+v", in.Users[1])
	}
	if in.TLS.ServerName != "cdn.example.com" || strings.Join(in.TLS.ALPN, ",") != "h2,http/1.1" {
		t.Fatalf("unexpected TLS metadata: %+v", in.TLS)
	}
	if in.TLS.Reality.Handshake.Server != "www.microsoft.com" || in.TLS.Reality.Handshake.ServerPort != 443 {
		t.Fatalf("unexpected REALITY handshake: %+v", in.TLS.Reality.Handshake)
	}
	if len(parsed.Outbounds) != 1 || parsed.Outbounds[0].Type != "direct" || parsed.Route.Final != "direct" {
		t.Fatalf("unexpected outbound/route: %+v %+v", parsed.Outbounds, parsed.Route)
	}
	for _, want := range []string{"disabled", "expired", "over_quota"} {
		if !strings.Contains(strings.Join(artifact.Warnings, "\n"), want) {
			t.Fatalf("warnings %v did not include %q", artifact.Warnings, want)
		}
	}
}

func TestRenderSingBoxUsesProfileOverrides(t *testing.T) {
	profile := baseProfile()
	profile.ListenIP = "10.66.0.9"
	profile.ConfigPath = "/opt/lattice/sing-box.json"
	inbound := baseInbound()
	inbound.Listen = "127.0.0.1"

	artifact, err := RenderSingBoxConfigJSON(profile, []model.ProxyInbound{inbound}, []model.ProxyUser{
		baseUser("alice", "Alice", "11111111-1111-1111-1111-111111111111", time.Now()),
	}, RenderOptions{Now: time.Now()})
	if err != nil {
		t.Fatalf("RenderSingBoxConfigJSON returned error: %v", err)
	}
	if artifact.ConfigPath != profile.ConfigPath {
		t.Fatalf("config path = %q, want %q", artifact.ConfigPath, profile.ConfigPath)
	}
	if !strings.Contains(artifact.ConfigJSON, `"listen": "10.66.0.9"`) {
		t.Fatalf("profile listen override not rendered:\n%s", artifact.ConfigJSON)
	}
}

func TestRenderSingBoxRejectsUnsupportedOrUnsafeInputs(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	user := baseUser("alice", "Alice", "11111111-1111-1111-1111-111111111111", now)

	tests := []struct {
		name    string
		profile model.ProxyNodeProfile
		inbound model.ProxyInbound
		users   []model.ProxyUser
		want    string
	}{
		{
			name: "unsupported core",
			profile: func() model.ProxyNodeProfile {
				p := baseProfile()
				p.Core = model.ProxyCoreXray
				return p
			}(),
			inbound: baseInbound(),
			users:   []model.ProxyUser{user},
			want:    "unsupported proxy core",
		},
		{
			name:    "unsupported protocol",
			profile: baseProfile(),
			inbound: func() model.ProxyInbound {
				in := baseInbound()
				in.Protocol = model.ProxyProtocolTrojan
				return in
			}(),
			users: []model.ProxyUser{user},
			want:  "unsupported protocol",
		},
		{
			name: "unsafe config path rejected",
			profile: func() model.ProxyNodeProfile {
				p := baseProfile()
				p.ConfigPath = "/etc/sing-box/config.json;touch /tmp/pwn"
				return p
			}(),
			inbound: baseInbound(),
			users:   []model.ProxyUser{user},
			want:    "config_path contains unsafe shell characters",
		},
		{
			name:    "unsupported transport with ignored path",
			profile: baseProfile(),
			inbound: func() model.ProxyInbound {
				in := baseInbound()
				in.Transport = model.ProxyTransportWS
				in.Path = "/ws"
				return in
			}(),
			users: []model.ProxyUser{user},
			want:  "unsupported transport",
		},
		{
			name:    "tcp path host rejected",
			profile: baseProfile(),
			inbound: func() model.ProxyInbound {
				in := baseInbound()
				in.Path = "/not-used"
				return in
			}(),
			users: []model.ProxyUser{user},
			want:  "cannot set path/host",
		},
		{
			name:    "empty short id rejected",
			profile: baseProfile(),
			inbound: func() model.ProxyInbound {
				in := baseInbound()
				in.RealityShortIDs = []string{""}
				return in
			}(),
			users: []model.ProxyUser{user},
			want:  "empty reality short id",
		},
		{
			name:    "unsafe alpn rejected",
			profile: baseProfile(),
			inbound: func() model.ProxyInbound {
				in := baseInbound()
				in.ALPN = []string{"h2\nx"}
				return in
			}(),
			users: []model.ProxyUser{user},
			want:  "unsafe alpn",
		},
		{
			name:    "bad listen rejected",
			profile: baseProfile(),
			inbound: func() model.ProxyInbound {
				in := baseInbound()
				in.Listen = "example.com"
				return in
			}(),
			users: []model.ProxyUser{user},
			want:  "listen address must be an IP address",
		},
		{
			name:    "bad uuid rejected",
			profile: baseProfile(),
			inbound: baseInbound(),
			users: []model.ProxyUser{func() model.ProxyUser {
				u := user
				u.UUID = "not-a-uuid"
				return u
			}()},
			want: "invalid uuid",
		},
		{
			name:    "no eligible users rejected",
			profile: baseProfile(),
			inbound: baseInbound(),
			users: []model.ProxyUser{func() model.ProxyUser {
				u := user
				u.Enabled = false
				return u
			}()},
			want: "no eligible VLESS users",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RenderSingBoxConfigJSON(tt.profile, []model.ProxyInbound{tt.inbound}, tt.users, RenderOptions{Now: now})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestRenderSingBoxRejectsDuplicatePortsAndUUIDs(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	profile := baseProfile()
	profile.InboundIDs = []string{"in-reality-443", "in-reality-alt"}
	first := baseInbound()
	second := baseInbound()
	second.ID = "in-reality-alt"

	_, err := RenderSingBoxConfigJSON(profile, []model.ProxyInbound{first, second}, []model.ProxyUser{
		baseUser("alice", "Alice", "11111111-1111-1111-1111-111111111111", now),
	}, RenderOptions{Now: now})
	if err == nil || !strings.Contains(err.Error(), "conflicts with") {
		t.Fatalf("duplicate listen/port error = %v", err)
	}

	second.Port = 8443
	_, err = RenderSingBoxConfigJSON(profile, []model.ProxyInbound{first, second}, []model.ProxyUser{
		baseUser("alice", "Alice", "11111111-1111-1111-1111-111111111111", now),
		baseUser("alice2", "Alice 2", "11111111-1111-1111-1111-111111111111", now.Add(time.Second)),
	}, RenderOptions{Now: now})
	if err == nil || !strings.Contains(err.Error(), "duplicates uuid") {
		t.Fatalf("duplicate uuid error = %v", err)
	}
}

func baseProfile() model.ProxyNodeProfile {
	return model.ProxyNodeProfile{
		ID:         "profile-n1",
		NodeID:     "node-1",
		Core:       model.ProxyCoreSingbox,
		InboundIDs: []string{"in-reality-443"},
		Hostname:   "jp1.dns.roobli.org",
	}
}

func baseInbound() model.ProxyInbound {
	return model.ProxyInbound{
		ID:                "in-reality-443",
		Name:              "VLESS Reality 443",
		Core:              model.ProxyCoreSingbox,
		Protocol:          model.ProxyProtocolVLESS,
		Transport:         model.ProxyTransportTCP,
		Security:          model.ProxySecurityReality,
		Listen:            "::",
		Port:              443,
		SNI:               "cdn.example.com",
		ALPN:              []string{"h2", "http/1.1"},
		RealityPrivateKey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RealityPublicKey:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		RealityShortIDs:   []string{"0123456789abcdef"},
		RealityDest:       "www.microsoft.com:443",
		Enabled:           true,
	}
}

func baseUser(id, name, uuid string, createdAt time.Time) model.ProxyUser {
	return model.ProxyUser{
		ID:        id,
		Name:      name,
		Enabled:   true,
		UUID:      uuid,
		Password:  "proxy-password-secret",
		SubToken:  "sub-token-secret",
		Status:    model.ProxyUserStatusActive,
		CreatedAt: createdAt,
	}
}
