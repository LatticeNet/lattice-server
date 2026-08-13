package proxycore

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRenderLineChainFragmentIsDeterministicAndNarrow(t *testing.T) {
	opts := LineChainOutboundOptions{
		Tag: "lattice-chain-a-b", SourceInboundTag: "source-b", Server: "target.example.com", ServerPort: 443,
		UUID: "11111111-1111-4111-8111-111111111111", Flow: "xtls-rprx-vision", SNI: "target.example.com",
		RealityPublicKey: "abcdefghijklmnop", RealityShortID: "aabbccdd", ClientFingerprint: "chrome",
	}
	first, err := RenderLineChainFragment(opts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderLineChainFragment(opts)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.SHA256 == "" {
		t.Fatalf("renderer is not deterministic: first=%+v second=%+v", first, second)
	}
	for _, forbidden := range []string{`"inbounds"`, `"listen"`, `"dns"`, `"experimental"`, `"_lattice"`} {
		if strings.Contains(first.JSON, forbidden) {
			t.Fatalf("fragment contains forbidden field %s: %s", forbidden, first.JSON)
		}
	}
	var decoded struct {
		Outbounds []json.RawMessage `json:"outbounds"`
		Route     struct {
			Rules []json.RawMessage `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal([]byte(first.JSON), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Outbounds) != 1 || len(decoded.Route.Rules) != 1 {
		t.Fatalf("fragment shape is not one outbound/one route: %s", first.JSON)
	}
	var outbound struct {
		TLS struct {
			UTLS struct {
				Enabled     bool   `json:"enabled"`
				Fingerprint string `json:"fingerprint"`
			} `json:"utls"`
		} `json:"tls"`
	}
	if err := json.Unmarshal(decoded.Outbounds[0], &outbound); err != nil {
		t.Fatal(err)
	}
	if !outbound.TLS.UTLS.Enabled || outbound.TLS.UTLS.Fingerprint != "chrome" {
		t.Fatalf("REALITY uTLS authority is missing: %s", first.JSON)
	}
}

func TestRenderLineChainFragmentBindsEveryExecutionInput(t *testing.T) {
	base := LineChainOutboundOptions{
		Tag: "lattice-chain-a-b", SourceInboundTag: "source-b", Server: "target.example.com", ServerPort: 443,
		UUID: "11111111-1111-4111-8111-111111111111", Flow: "xtls-rprx-vision", SNI: "target.example.com",
		RealityPublicKey: "abcdefghijklmnop", RealityShortID: "aabbccdd", ClientFingerprint: "chrome",
	}
	original, err := RenderLineChainFragment(base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []LineChainOutboundOptions{base, base, base, base, base, base, base, base}
	mutations[0].Tag = "lattice-chain-a-c"
	mutations[1].SourceInboundTag = "source-c"
	mutations[2].Server = "other.example.com"
	mutations[3].ServerPort = 8443
	mutations[4].UUID = "22222222-2222-4222-8222-222222222222"
	mutations[5].SNI = "other.example.com"
	mutations[6].RealityPublicKey = "ponmlkjihgfedcba"
	mutations[7].RealityShortID = "eeff0011"
	for i, mutation := range mutations {
		got, err := RenderLineChainFragment(mutation)
		if err != nil {
			t.Fatalf("mutation %d: %v", i, err)
		}
		if got.SHA256 == original.SHA256 {
			t.Fatalf("mutation %d did not change digest", i)
		}
	}
}

func TestRenderLineChainFragmentRejectsUnreviewedClientFingerprint(t *testing.T) {
	opts := LineChainOutboundOptions{
		Tag: "lattice-chain-a-b", SourceInboundTag: "source-b", Server: "target.example.com", ServerPort: 443,
		UUID: "11111111-1111-4111-8111-111111111111", Flow: "xtls-rprx-vision", SNI: "target.example.com",
		RealityPublicKey: "abcdefghijklmnop", RealityShortID: "aabbccdd",
	}
	for _, fingerprint := range []string{"", "firefox", " chrome "} {
		opts.ClientFingerprint = fingerprint
		if _, err := RenderLineChainFragment(opts); err == nil {
			t.Fatalf("fingerprint %q unexpectedly accepted", fingerprint)
		}
	}
}
