package server

import (
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/proxycore"
)

// The core decides, before any render, which client a request is for and how
// the document travels. A link serves each client its own native document,
// and the base64 envelope is applied only to a URI list: a base64-wrapped
// YAML, JSON or Surge profile is a document no client can read, and that is
// what every share left at "automatic" used to serve.
//
// The plugin still renders, and a record that pins its own target still wins
// over a header (the plugin enforces that). The core cannot see the pin, so
// it treats a target derived from the User-Agent as probable rather than
// known, and only ever uses it to keep the envelope off a document it is
// sure is not a URI list, or to label the response when the plugin did not
// say which target it rendered.

// subscriptionUATargets maps a client class to the engine target that client
// imports natively. It mirrors the plugin's own table and adds clashmeta,
// which released plugins do not know yet; see pluginUAClass.
var subscriptionUATargets = map[string]string{
	"surge":        "Surge",
	"loon":         "Loon",
	"quantumultx":  "QX",
	"stash":        "Stash",
	"shadowrocket": "Shadowrocket",
	"clashmeta":    "ClashMeta",
	"clash":        "Clash",
	"singbox":      "sing-box",
	"egern":        "Egern",
}

// shareRenderPlan is what the core decided about one request.
type shareRenderPlan struct {
	// Format is what the source is asked for. For a plugin source it is the
	// envelope, base64 or plain. For a core proxy-user source it is the
	// document itself (plain, base64, sing-box or clash-meta).
	Format string
	// UAClass is the class the render and the cache key see. Once the URL has
	// named the client, the agent cannot change the bytes, so it collapses to
	// "other" and every agent shares one entry.
	UAClass string
	// Variant carries the explicit render parameters, with Target filled when
	// the URL named a client through target, platform, or a format that only
	// one client reads (sing-box, clash, clash-meta).
	Variant shareRenderVariant
	// Target is the client the core believes it is serving, and TargetKnown
	// says whether the URL said so (known) or the agent suggested it
	// (probable, a pinned record may override it).
	Target      string
	TargetKnown bool
	// CoreUser is a core proxy-user source's user, resolved once for the
	// request so the render reads the identity policy once. Nil for a plugin
	// source, and nil when the user no longer resolves, which the render
	// refuses.
	CoreUser *model.ProxyUser
}

// formatImpliedTarget names the client a format value can only mean. Before
// this, ?format=clash and ?format=clash-meta passed the core's validation and
// then failed in the plugin, so a plugin share answered the decoy.
func formatImpliedTarget(format string) string {
	switch format {
	case proxycore.SubscriptionFormatSingBox:
		return "sing-box"
	case proxycore.SubscriptionFormatClash, proxycore.SubscriptionFormatClashMeta:
		return "ClashMeta"
	default:
		return ""
	}
}

// planShareRender decides the plan for one request. format is the normalized
// format (the share's default when the URL gave none), native says no format
// was chosen anywhere, clientClass is the agent's class and variant holds the
// URL's explicit parameters.
func planShareRender(kind, format string, native bool, clientClass string, variant shareRenderVariant) shareRenderPlan {
	if variant.Target == "" {
		variant.Target = formatImpliedTarget(format)
	}
	if kind == model.ShareSourceCoreProxyUser {
		return planCoreShareRender(format, native, clientClass, variant)
	}
	plan := shareRenderPlan{Variant: variant, UAClass: clientClass}
	if variant.Target != "" {
		plan.UAClass = "other"
		plan.Target, plan.TargetKnown = variant.Target, true
	} else {
		plan.Target = subscriptionUATargets[clientClass]
		plan.Variant.UATarget = plan.Target
	}
	plan.Format = proxycore.SubscriptionFormatPlain
	if format == proxycore.SubscriptionFormatBase64 && (plan.Target == "" || plan.Target == "URI") {
		plan.Format = proxycore.SubscriptionFormatBase64
	}
	return plan
}

// planCoreShareRender picks the document a core proxy-user share produces.
// Proxycore can write a URI list (plain or base64), a sing-box profile and a
// ClashMeta profile; a client that reads none of those keeps the base64 URI
// list it always received. A format the operator or the URL chose is the
// document; only when nothing was chosen does the agent decide.
func planCoreShareRender(format string, native bool, clientClass string, variant shareRenderVariant) shareRenderPlan {
	plan := shareRenderPlan{UAClass: "other", Format: format}
	target, known := variant.Target, variant.Target != ""
	if !known && native {
		target = subscriptionUATargets[clientClass]
	}
	switch target {
	case "ClashMeta", "Clash", "Stash":
		plan.Format = proxycore.SubscriptionFormatClashMeta
	case "sing-box":
		plan.Format = proxycore.SubscriptionFormatSingBox
	case "":
	default:
		if format != proxycore.SubscriptionFormatPlain {
			plan.Format = proxycore.SubscriptionFormatBase64
		}
	}
	plan.Target, plan.TargetKnown = target, known
	return plan
}

// shareWireContentType labels the response from what the core decided. A
// base64 envelope and a URI list are text. Otherwise the target decides: the
// one the plugin reports it rendered when it says (validated against the
// target allowlist by the caller), else the plan's own. It never echoes a
// type the source chose, so a source cannot make the control plane's origin
// serve markup.
func shareWireContentType(plan shareRenderPlan, reportedTarget string) string {
	if plan.Format == proxycore.SubscriptionFormatBase64 || plan.Format == proxycore.SubscriptionFormatPlain {
		target := plan.Target
		if reportedTarget != "" {
			target = reportedTarget
		}
		if plan.Format == proxycore.SubscriptionFormatBase64 {
			target = ""
		}
		return subscriptionResponseContentType(plan.Format, target)
	}
	return subscriptionResponseContentType(plan.Format, "")
}

// reportedRenderTarget accepts the target a plugin says it rendered only when
// it is one of the bounded client targets.
func reportedRenderTarget(value string) string {
	value = strings.TrimSpace(value)
	if subscriptionShareTargets[value] {
		return value
	}
	return ""
}
