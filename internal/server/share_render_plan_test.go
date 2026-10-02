package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// A plugin share serves each client its native document, and the base64
// envelope only ever wraps a URI list. "automatic" used to normalize to base64
// and wrap every target, so YAML, JSON and Surge profiles reached clients as
// base64 text none of them could read, and V2Ray (already base64) was wrapped
// twice.
func TestPlanShareRenderPluginEnvelopes(t *testing.T) {
	cases := []struct {
		name        string
		format      string
		native      bool
		class       string
		target      string
		wantFormat  string
		wantClass   string
		wantTarget  string
		wantKnown   bool
		wantUAHint  string
		wantVariant string
	}{
		{name: "native mihomo client", format: "base64", native: true, class: "clashmeta",
			wantFormat: "plain", wantClass: "clashmeta", wantTarget: "ClashMeta", wantUAHint: "ClashMeta"},
		{name: "native unknown client keeps the base64 URI list", format: "base64", native: true, class: "other",
			wantFormat: "base64", wantClass: "other"},
		{name: "explicit base64 never wraps a YAML target", format: "base64", class: "surge", target: "ClashMeta",
			wantFormat: "plain", wantClass: "other", wantTarget: "ClashMeta", wantKnown: true, wantVariant: "t=ClashMeta"},
		{name: "URI target keeps base64", format: "base64", native: true, class: "surge", target: "URI",
			wantFormat: "base64", wantClass: "other", wantTarget: "URI", wantKnown: true, wantVariant: "t=URI"},
		{name: "plain URI list stays plain", format: "plain", class: "other", target: "URI",
			wantFormat: "plain", wantClass: "other", wantTarget: "URI", wantKnown: true, wantVariant: "t=URI"},
		{name: "V2Ray is not wrapped a second time", format: "base64", native: true, class: "other", target: "V2Ray",
			wantFormat: "plain", wantClass: "other", wantTarget: "V2Ray", wantKnown: true, wantVariant: "t=V2Ray"},
		{name: "format sing-box names the client", format: "sing-box", class: "surge",
			wantFormat: "plain", wantClass: "other", wantTarget: "sing-box", wantKnown: true, wantVariant: "t=sing-box"},
		{name: "format clash serves ClashMeta instead of failing in the plugin", format: "clash", class: "other",
			wantFormat: "plain", wantClass: "other", wantTarget: "ClashMeta", wantKnown: true, wantVariant: "t=ClashMeta"},
		{name: "explicit plain with a Surge agent", format: "plain", class: "surge",
			wantFormat: "plain", wantClass: "surge", wantTarget: "Surge", wantUAHint: "Surge"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := planShareRender(model.ShareSourcePlugin, tc.format, tc.native, tc.class, shareRenderVariant{Target: tc.target})
			if plan.Format != tc.wantFormat || plan.UAClass != tc.wantClass || plan.Target != tc.wantTarget || plan.TargetKnown != tc.wantKnown {
				t.Fatalf("plan = %+v, want format %s class %s target %s known %v", plan, tc.wantFormat, tc.wantClass, tc.wantTarget, tc.wantKnown)
			}
			if plan.Variant.UATarget != tc.wantUAHint || plan.Variant.cacheToken() != tc.wantVariant {
				t.Fatalf("variant = %+v token %q, want hint %q token %q", plan.Variant, plan.Variant.cacheToken(), tc.wantUAHint, tc.wantVariant)
			}
		})
	}
}

// A core proxy-user share produces what proxycore can write. A chosen format
// is the document; only with nothing chosen does the agent pick, and a client
// proxycore cannot serve natively keeps the base64 URI list.
func TestPlanShareRenderCoreDocuments(t *testing.T) {
	cases := []struct {
		name   string
		format string
		native bool
		class  string
		target string
		want   string
	}{
		{"native sing-box client", "base64", true, "singbox", "", "sing-box"},
		{"native mihomo client", "base64", true, "clashmeta", "", "clash-meta"},
		{"native Stash client", "base64", true, "stash", "", "clash-meta"},
		{"native unknown client", "base64", true, "other", "", "base64"},
		{"native Surge client keeps the URI list", "base64", true, "surge", "", "base64"},
		{"chosen plain beats the agent", "plain", false, "singbox", "", "plain"},
		{"target ClashMeta beats the share format", "base64", false, "other", "ClashMeta", "clash-meta"},
		{"target sing-box", "plain", false, "other", "sing-box", "sing-box"},
		{"target URI with plain", "plain", false, "other", "URI", "plain"},
		{"target proxycore cannot write", "plain", false, "other", "Surge", "plain"},
		{"target proxycore cannot write, base64", "base64", false, "other", "Loon", "base64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := planShareRender(model.ShareSourceCoreProxyUser, tc.format, tc.native, tc.class, shareRenderVariant{Target: tc.target})
			if plan.Format != tc.want || plan.UAClass != "other" || plan.Variant.cacheToken() != "" {
				t.Fatalf("plan = %+v, want document %s, class other and no variant", plan, tc.want)
			}
		})
	}
}

func TestShareWireContentTypeFollowsTheResolvedTarget(t *testing.T) {
	probable := planShareRender(model.ShareSourcePlugin, "base64", true, "clashmeta", shareRenderVariant{})
	if got := shareWireContentType(probable, ""); !strings.HasPrefix(got, "text/yaml") {
		t.Fatalf("mihomo client labelled %q", got)
	}
	// A record pinned to sing-box wins over the agent; the plugin says so.
	if got := shareWireContentType(probable, reportedRenderTarget("sing-box")); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("plugin-reported sing-box labelled %q", got)
	}
	// Whatever a plugin reports outside the bounded target set changes nothing.
	for _, junk := range []string{"text/html", "<script>", "clash", " "} {
		if got := shareWireContentType(probable, reportedRenderTarget(junk)); !strings.HasPrefix(got, "text/yaml") {
			t.Fatalf("reported target %q relabelled the response as %q", junk, got)
		}
	}
	uri := planShareRender(model.ShareSourcePlugin, "base64", true, "other", shareRenderVariant{})
	if got := shareWireContentType(uri, reportedRenderTarget("ClashMeta")); !strings.HasPrefix(got, "text/plain") {
		t.Fatalf("a base64 envelope labelled %q", got)
	}
	core := planShareRender(model.ShareSourceCoreProxyUser, "base64", false, "other", shareRenderVariant{Target: "ClashMeta"})
	if got := shareWireContentType(core, ""); !strings.HasPrefix(got, "text/yaml") {
		t.Fatalf("core ClashMeta document labelled %q", got)
	}
	coreSurge := planShareRender(model.ShareSourceCoreProxyUser, "base64", false, "other", shareRenderVariant{Target: "Surge"})
	if got := shareWireContentType(coreSurge, ""); !strings.HasPrefix(got, "text/plain") {
		t.Fatalf("core base64 list for Surge labelled %q", got)
	}
}

// End to end through the handler: the plugin is asked for the bare document
// for a mihomo agent, the released plugin still hears clash, and the label
// comes from the core.
func TestPluginShareServesNativeDocumentToMihomoClients(t *testing.T) {
	s, st := newShareTestServer(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	s.now = func() time.Time { return now }
	token := strings.Repeat("a", 32)
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "s1", Slug: "team", Token: token, Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "rec"}})
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "rec", Raw: "nodes", FetchedAt: now}); err != nil {
		t.Fatal(err)
	}
	var gotFormat, gotClass string
	var gotVariant shareRenderVariant
	reported := ""
	s.subscriptionRender = func(_ context.Context, share model.SubscriptionShare, format, uaClass string, variant shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		gotFormat, gotClass, gotVariant = format, uaClass, variant
		epoch, _ := s.subscriptionSnapshotEpoch(share.Source.PluginID, share.Source.SubscriptionID, snap)
		return renderedSubscription{Body: []byte("proxies:\n  - {name: a, type: vless}\n"), ContentType: "text/html", Target: reported,
			RevalidationVersion: subscriptionRevalidationVersion(snap), SourceEpoch: epoch, FetchedAt: snap.FetchedAt}, nil
	}
	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest("/sub/team/"+token, "clash-verge/v2.2.3"))
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/yaml") {
		t.Fatalf("response code %d type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if gotFormat != "plain" || gotClass != "clashmeta" || gotVariant.UATarget != "ClashMeta" || gotVariant.Target != "" {
		t.Fatalf("render saw format %q class %q variant %+v", gotFormat, gotClass, gotVariant)
	}
	payload, err := subscriptionRenderPayload("rec", gotFormat, gotClass, gotVariant, "nodes")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(payload, []byte(`"ua_class":"clash"`)) || !bytes.Contains(payload, []byte(`"ua_target":"ClashMeta"`)) {
		t.Fatalf("plugin payload = %s", payload)
	}

	// A plugin that reports the record's pinned target relabels within the
	// allowlist; one that reports anything else cannot.
	s.subscriptionCache.InvalidateShare("s1")
	reported = "sing-box"
	rec = httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest("/sub/team/"+token, "clash-verge/v2.2.3"))
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("reported sing-box labelled %q", got)
	}
	s.subscriptionCache.InvalidateShare("s1")
	reported = "text/html"
	rec = httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest("/sub/team/"+token, "clash-verge/v2.2.3"))
	if got := rec.Header().Get("Content-Type"); strings.Contains(got, "html") || !strings.HasPrefix(got, "text/yaml") {
		t.Fatalf("reported junk labelled %q", got)
	}
}

// A core share used to ignore ?target= and the agent while labelling the
// body by ?target=, so ?target=ClashMeta returned a base64 URI list marked
// text/yaml. It now writes the document the client reads, and labels it as
// what it is.
func TestCoreShareServesTheDocumentTheClientReads(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	createProxyPlanFixtures(t, handler, cookies, csrf, "node-a")
	profile, ok := st.ProxyNodeProfile("node-a")
	if !ok {
		t.Fatal("proxy node profile not found")
	}
	profile.AppliedSHA256 = strings.Repeat("a", 64)
	profile.LastError = ""
	if err := st.UpsertProxyNodeProfile(profile); err != nil {
		t.Fatal(err)
	}
	subURL := publishProxyUserShare(t, st, "alice", "alice-team", "sub-token-secret-abcdefghijklmnopqrstuvwxyz")
	fetch := func(path, ua string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("User-Agent", ua)
		req.RemoteAddr = "192.0.2.50:4000"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	for _, tc := range []struct {
		name, path, ua, wantType, wantPrefix string
	}{
		{"explicit ClashMeta", subURL + "?target=ClashMeta", "curl/8", "text/yaml", "proxies:"},
		{"native mihomo client", subURL, "clash-verge/v2.2.3", "text/yaml", "proxies:"},
		{"native sing-box client", subURL, "SFA/1.11 (sing-box 1.11.0)", "application/json", "{"},
		{"unknown client keeps base64", subURL, "curl/8", "text/plain", "dmxlc3M6"},
		{"chosen plain beats the agent", subURL + "?format=plain", "clash-verge/v2.2.3", "text/plain", "vless://"},
	} {
		rec := fetch(tc.path, tc.ua)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", tc.name, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, tc.wantType) {
			t.Fatalf("%s: Content-Type %q, want %s", tc.name, got, tc.wantType)
		}
		if body := strings.TrimSpace(rec.Body.String()); !strings.HasPrefix(body, tc.wantPrefix) {
			t.Fatalf("%s: body starts %q, want %q", tc.name, body[:min(len(body), 40)], tc.wantPrefix)
		}
	}
}
