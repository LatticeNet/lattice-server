package server

import (
	"strconv"
	"testing"
)

// The cache is keyed on this classification rather than on the raw header. The
// header is caller-controlled, so keying on it directly would let anyone mint
// unlimited distinct cache entries by varying a string they choose.
func TestClassifyClientUAIsBounded(t *testing.T) {
	seen := map[string]bool{}
	for _, ua := range []string{
		"Surge/2000", "Loon/700", "Quantumult%20X/1.0.30", "Stash/2.0",
		"Shadowrocket/1900", "clash-verge/1.0", "sing-box/1.24", "Egern/1.0",
		"curl/8.0", "", "totally unknown agent",
	} {
		seen[classifyClientUA(ua)] = true
	}
	for i := 0; i < 1000; i++ {
		seen[classifyClientUA("random-"+strconv.Itoa(i))] = true
	}
	if len(seen) > 12 {
		t.Fatalf("classification produced %d classes; it must be bounded", len(seen))
	}
	if classifyClientUA("random-1") != classifyClientUA("random-2") {
		t.Fatal("unrecognized agents must collapse into one class")
	}
}

func TestClassifyClientUAKnownFamilies(t *testing.T) {
	cases := map[string]string{
		"Surge/2000 CFNetwork":  "surge",
		"Loon/700":              "loon",
		"Quantumult%20X/1.0.30": "quantumultx",
		"Stash/2.0":             "stash",
		"Shadowrocket/1900":     "shadowrocket",
		"clash-verge/1.0":       "clash",
		"sing-box/1.24.2":       "singbox",
		"Egern/1.0":             "egern",
		"curl/8.0":              "other",
		"":                      "other",
	}
	for ua, want := range cases {
		if got := classifyClientUA(ua); got != want {
			t.Fatalf("classifyClientUA(%q) = %q, want %q", ua, got, want)
		}
	}
}

// The classification must not depend on the caller's capitalization, or the same
// client would occupy several cache slots.
func TestClassifyClientUAIsCaseInsensitive(t *testing.T) {
	if classifyClientUA("SURGE/2000") != classifyClientUA("surge/2000") {
		t.Fatal("classification is case sensitive")
	}
}
