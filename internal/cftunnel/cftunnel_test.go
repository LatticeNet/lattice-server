package cftunnel

import (
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestGenerateConfig(t *testing.T) {
	cfg, err := GenerateConfig(model.TunnelProfile{
		TunnelID: "my-tunnel-123",
		Ingress: []model.TunnelIngress{
			{Hostname: "app.example.com", Service: "http://localhost:8088"},
			{Hostname: "ssh.example.com", Service: "ssh://localhost:22"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"tunnel: my-tunnel-123",
		"credentials-file: /etc/cloudflared/my-tunnel-123.json",
		"hostname: app.example.com",
		"service: http://localhost:8088",
		"hostname: ssh.example.com",
		"service: ssh://localhost:22",
		"service: http_status:404",
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("config missing %q:\n%s", want, cfg)
		}
	}
	// catch-all must be last
	if !strings.HasSuffix(strings.TrimSpace(cfg), "service: http_status:404") {
		t.Fatalf("catch-all must be last:\n%s", cfg)
	}
}

func TestGenerateConfigValidation(t *testing.T) {
	cases := []model.TunnelProfile{
		{TunnelID: "bad id with spaces", Ingress: []model.TunnelIngress{{Hostname: "a.com", Service: "http://x"}}},
		{TunnelID: "t", Ingress: []model.TunnelIngress{{Hostname: "not a host", Service: "http://x"}}},
		{TunnelID: "t", Ingress: []model.TunnelIngress{{Hostname: "a.com", Service: "ftp://x"}}},
		{TunnelID: "t", Ingress: []model.TunnelIngress{{Hostname: "a.com", Service: "http://x\nevil: y"}}},
		{TunnelID: "t"}, // no ingress
	}
	for i, p := range cases {
		if _, err := GenerateConfig(p); err == nil {
			t.Fatalf("case %d should have failed validation", i)
		}
	}
}
