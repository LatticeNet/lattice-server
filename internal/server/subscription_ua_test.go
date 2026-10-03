package server

import (
	"encoding/json"
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
		"clash-verge/1.0":       "clashmeta",
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

// Every Clash family client that runs the mihomo core must get ClashMeta:
// legacy Clash cannot express VLESS or Hysteria2, which is what this fleet
// runs. Only a client that names Clash and nothing newer stays legacy, and a
// Stash agent that also names Clash stays Stash.
func TestClassifyClientUAModernClashClients(t *testing.T) {
	cases := map[string]string{
		"clash-verge/v2.2.3":                           "clashmeta",
		"Clash-Verge/v1.3.8":                           "clashmeta",
		"FlClash/v0.8.80 clash-verge Platform/android": "clashmeta",
		"FlClash/v0.8.80":                              "clashmeta",
		"mihomo/1.18.10":                               "clashmeta",
		"ClashMetaForAndroid/2.11.1.Meta":              "clashmeta",
		"ClashX Meta/v1.4.0":                           "clashmeta",
		"clash.meta":                                   "clashmeta",
		"clash-nyanpasu/v1.6.1":                        "clashmeta",
		"ClashforWindows/0.20.39":                      "clash",
		"ClashX/1.118.0":                               "clash",
		"Stash/2.4.6 Clash/1.9.0":                      "stash",
		"Clash Meta for Android/2.10":                  "clashmeta",
		// "meta" without clash decides nothing: these keep their own family.
		"Loon/3.2 metadata":            "loon",
		"Egern/1.4 meta":               "egern",
		"Go-http-client metaprobe/1.0": "other",
	}
	for ua, want := range cases {
		if got := classifyClientUA(ua); got != want {
			t.Errorf("classifyClientUA(%q) = %q, want %q", ua, got, want)
		}
	}
}

// A plugin released before clashmeta existed maps an unknown class to the URI
// list. It must keep receiving clash for those clients until it knows better,
// so the new class never makes a deployed plugin's answer worse.
func TestPluginRenderPayloadKeepsReleasedPluginsOnTheirOldClass(t *testing.T) {
	payload, err := subscriptionRenderPayload("rec", "base64", "clashmeta", shareRenderVariant{}, "raw")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if got["ua_class"] != "clash" {
		t.Fatalf("ua_class = %v, want clash for a released plugin", got["ua_class"])
	}
	if _, ok := got["target"]; ok {
		t.Fatalf("a request without a target grew one: %v", got)
	}
}
