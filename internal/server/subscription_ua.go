package server

import "strings"

// subscriptionUAClasses is the fixed set classifyClientUA may return. Keeping it
// as data makes the boundedness of the classification checkable rather than a
// property someone has to re-derive from the function body.
//
// Order is part of the data: the first needle that matches wins. The
// clashmeta needles sit ahead of plain clash because every modern Clash
// client is a mihomo (Clash.Meta) client and says so somewhere in its agent:
// Clash Verge Rev sends clash-verge/<version>, FlClash sends FlClash, the core
// itself sends mihomo, and the Meta builds carry "meta" (ClashX Meta, Clash
// Meta for Android, clash.meta). Legacy Clash cannot carry VLESS or
// Hysteria2, so classifying these clients as clash handed them a document
// with no proxies in it. Stash stays ahead of both: its agent also names
// Clash. The needles follow upstream Sub-Store's user-agent table.
//
// "meta" alone is too common a substring to decide a family: it counts only
// in an agent that also names clash (with), so an agent such as
// "Loon/3.2 metadata" or a metrics scraper is not handed a ClashMeta
// document.
var subscriptionUAClasses = []struct{ needle, with, class string }{
	{"quantumult", "", "quantumultx"},
	{"shadowrocket", "", "shadowrocket"},
	{"sing-box", "", "singbox"},
	{"surge", "", "surge"},
	{"stash", "", "stash"},
	{"clash-verge", "", "clashmeta"},
	{"flclash", "", "clashmeta"},
	{"mihomo", "", "clashmeta"},
	{"nyanpasu", "", "clashmeta"},
	{"meta", "clash", "clashmeta"},
	{"clash", "", "clash"},
	{"egern", "", "egern"},
	{"loon", "", "loon"},
}

// classifyClientUA maps a client User-Agent onto a bounded set.
//
// The output cache is keyed on this rather than on the raw header because the
// header is caller-controlled: keying on it directly would let anyone mint
// unlimited distinct cache entries by varying a string they choose, turning the
// cache into a memory amplifier. The conversion only ever depends on the family
// anyway, so nothing is lost by collapsing the rest.
func classifyClientUA(header string) string {
	lower := strings.ToLower(header)
	for _, known := range subscriptionUAClasses {
		if strings.Contains(lower, known.needle) && (known.with == "" || strings.Contains(lower, known.with)) {
			return known.class
		}
	}
	return "other"
}

// pluginUAClass is the class the Sub-Store plugin receives in its render
// payload. The plugins released before clashmeta existed map an unknown class
// to the URI list, which would turn a mihomo client's legacy Clash document
// into a list it cannot import, so those plugins keep receiving clash for
// clashmeta clients, exactly what they received before. The cache key keeps
// the real class, so the two families never share an entry, and a plugin that
// knows the new class reads the core's resolved target instead (ua_target).
func pluginUAClass(class string) string {
	if class == "clashmeta" {
		return "clash"
	}
	return class
}
