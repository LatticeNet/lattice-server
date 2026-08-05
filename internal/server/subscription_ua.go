package server

import "strings"

// subscriptionUAClasses is the fixed set classifyClientUA may return. Keeping it
// as data makes the boundedness of the classification checkable rather than a
// property someone has to re-derive from the function body.
var subscriptionUAClasses = []struct{ needle, class string }{
	{"quantumult", "quantumultx"},
	{"shadowrocket", "shadowrocket"},
	{"sing-box", "singbox"},
	{"surge", "surge"},
	{"stash", "stash"},
	{"clash", "clash"},
	{"egern", "egern"},
	{"loon", "loon"},
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
		if strings.Contains(lower, known.needle) {
			return known.class
		}
	}
	return "other"
}
