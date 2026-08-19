package server

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// updateSubWireGolden regenerates testdata/subscription_wire_golden.txt.
//
// Regenerating is only ever correct when the externally visible behaviour of
// /sub/ was deliberately changed. Folding the subscription route into the
// publishing plane is not such a change, so a diff here during that work means
// the refactor stopped being a refactor.
var updateSubWireGolden = flag.Bool("update-sub-golden", false, "rewrite the /sub/ wire golden file")

// goldenShareToken is synthetic. The live share's token is deliberately absent
// from this repository: the proof that production keeps serving is that the
// route, the format negotiation, the cache keying and the audit shape are
// unchanged, none of which depend on the token's value.
const goldenShareToken = "gggggggggggggggggggggggggggggggg"

const (
	goldenDisabledToken = "dddddddddddddddddddddddddddddddd"
	goldenExpiredToken  = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	goldenCoreToken     = "cccccccccccccccccccccccccccccccc"
)

// goldenSubServer reproduces the shape of the one share that exists in
// production: slug cd-self, a plugin source, no default format, enabled, no
// expiry. Two extra shares cover the disabled and expired denials, and one core
// proxy-user share covers renderShare's other branch.
func goldenSubServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	s, st := newShareTestServer(t)

	now := time.Unix(1_700_000_000, 0).UTC()
	s.now = func() time.Time { return now }
	past := now.Add(-time.Hour)

	const pluginID = "latticenet.sub-store"
	const subscriptionID = "imported-file-for-cdcd-self-use"

	mustUpsertShare(t, st, model.SubscriptionShare{
		ID: "share_golden", Slug: "cd-self", Token: goldenShareToken, Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: pluginID, SubscriptionID: subscriptionID},
	})
	mustUpsertShare(t, st, model.SubscriptionShare{
		ID: "share_off", Slug: "off", Token: goldenDisabledToken, Enabled: false,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: pluginID, SubscriptionID: subscriptionID},
	})
	mustUpsertShare(t, st, model.SubscriptionShare{
		ID: "share_old", Slug: "old", Token: goldenExpiredToken, Enabled: true, ExpiresAt: &past,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: pluginID, SubscriptionID: subscriptionID},
	})
	mustUpsertShare(t, st, model.SubscriptionShare{
		ID: "share_core", Slug: "core", Token: goldenCoreToken, Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourceCoreProxyUser, ProxyUserID: "nobody"},
	})

	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{
		PluginID: pluginID, SubscriptionID: subscriptionID, Raw: "golden-nodes", FetchedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		return model.SubscriptionSnapshot{Raw: "golden-nodes", FetchedAt: now}, nil
	}
	// The render echoes every input the core derived from the request. A refactor
	// that perturbs format negotiation, UA classification or variant parsing
	// changes these bytes, which is the point.
	s.subscriptionRender = func(_ context.Context, share model.SubscriptionShare, format, uaClass string,
		variant shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		epoch, _ := s.subscriptionSnapshotEpoch(share.Source.PluginID, share.Source.SubscriptionID, snap)
		body := fmt.Sprintf("share=%s format=%s ua=%s target=%s iup=%t py=%t raw=%s",
			share.ID, format, uaClass, variant.Target, variant.IncludeUnsupported, variant.PrettyYAML, snap.Raw)
		return renderedSubscription{
			Body: []byte(body), ContentType: "text/plain; charset=utf-8",
			Userinfo:            "upload=1; download=2; total=3",
			RevalidationVersion: subscriptionRevalidationVersion(snap),
			SourceVersion:       "v-golden", SourceEpoch: epoch, FetchedAt: snap.FetchedAt,
		}, nil
	}
	return s, st
}

// subWireCase is one request in the matrix.
type subWireCase struct {
	name   string
	method string
	path   string
	ua     string
	host   string
}

// subWireCases covers what a client, a prober and a plugin author can each reach:
// the serving paths with every render parameter, and every denial shape.
func subWireCases() []subWireCase {
	ok := "/sub/cd-self/" + goldenShareToken
	return []subWireCase{
		{name: "bare", method: http.MethodGet, path: ok, ua: "Surge/2000"},
		{name: "no user agent", method: http.MethodGet, path: ok},
		{name: "curl", method: http.MethodGet, path: ok, ua: "curl/8"},
		{name: "clash ua", method: http.MethodGet, path: ok, ua: "ClashforWindows/0.20.39"},
		{name: "explicit format plain", method: http.MethodGet, path: ok + "?format=plain", ua: "curl/8"},
		{name: "target stash", method: http.MethodGet, path: ok + "?target=Stash", ua: "curl/8"},
		{name: "target singbox", method: http.MethodGet, path: ok + "?target=sing-box", ua: "curl/8"},
		{name: "platform alias", method: http.MethodGet, path: ok + "?platform=Stash", ua: "curl/8"},
		{name: "include unsupported", method: http.MethodGet, path: ok + "?target=Stash&includeUnsupportedProxy=1", ua: "curl/8"},
		{name: "pretty yaml", method: http.MethodGet, path: ok + "?target=Stash&prettyYaml=1", ua: "curl/8"},
		{name: "no flow", method: http.MethodGet, path: ok + "?noFlow=1", ua: "curl/8"},
		{name: "other host", method: http.MethodGet, path: ok, ua: "curl/8", host: "somewhere.else.example"},

		{name: "deny unknown token", method: http.MethodGet, path: "/sub/cd-self/" + strings.Repeat("z", 32), ua: "curl/8"},
		{name: "deny wrong slug", method: http.MethodGet, path: "/sub/nope/" + goldenShareToken, ua: "curl/8"},
		{name: "deny disabled", method: http.MethodGet, path: "/sub/off/" + goldenDisabledToken, ua: "curl/8"},
		{name: "deny expired", method: http.MethodGet, path: "/sub/old/" + goldenExpiredToken, ua: "curl/8"},
		{name: "deny bad format", method: http.MethodGet, path: ok + "?format=xml", ua: "curl/8"},
		{name: "deny bad target", method: http.MethodGet, path: ok + "?target=EvilClient", ua: "curl/8"},
		{name: "deny post", method: http.MethodPost, path: ok, ua: "curl/8"},
		{name: "deny head", method: http.MethodHead, path: ok, ua: "curl/8"},
		{name: "deny single segment", method: http.MethodGet, path: "/sub/" + goldenShareToken, ua: "curl/8"},
		{name: "deny three segments", method: http.MethodGet, path: "/sub/a/b/c", ua: "curl/8"},
		{name: "deny bare prefix", method: http.MethodGet, path: "/sub/", ua: "curl/8"},
		{name: "deny uppercase slug", method: http.MethodGet, path: "/sub/CD-Self/" + goldenShareToken, ua: "curl/8"},
		{name: "deny traversal", method: http.MethodGet, path: "/sub/../" + goldenShareToken, ua: "curl/8"},
		{name: "deny empty render", method: http.MethodGet, path: "/sub/core/" + goldenCoreToken, ua: "curl/8"},
	}
}

// transcribe renders one response as stable text: status, every header with its
// value, and the body. Nothing is summarised, so any wire change shows up as a
// diff rather than as a hash mismatch nobody can read.
func transcribe(rec *httptest.ResponseRecorder) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  status: %d\n", rec.Code)
	names := make([]string, 0, len(rec.Header()))
	for name := range rec.Header() {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		value := strings.Join(rec.Header().Values(name), "|")
		// The request id is unique per request by design and says nothing about
		// the response, so only its presence is pinned.
		if name == "X-Lattice-Request-Id" {
			value = "<per-request>"
		}
		fmt.Fprintf(&b, "  header %s: %q\n", name, value)
	}
	fmt.Fprintf(&b, "  body: %q\n", stripRequestID(rec.Body.String()))
	return b.String()
}

// transcribeAudit records what the operator sees. The token hash keeps its key
// but loses its value: the shape is the invariant, and a digest of a synthetic
// token proves nothing worth pinning.
func transcribeAudit(events []model.AuditEvent) string {
	lines := make([]string, 0, len(events))
	for _, ev := range events {
		var b strings.Builder
		fmt.Fprintf(&b, "  audit %s/%s", ev.Action, ev.Decision)
		if ev.Reason != "" {
			fmt.Fprintf(&b, " reason=%s", ev.Reason)
		}
		keys := make([]string, 0, len(ev.Metadata))
		for k := range ev.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			value := ev.Metadata[k]
			if k == "token_sha256" {
				value = "<redacted>"
			}
			fmt.Fprintf(&b, " %s=%s", k, value)
		}
		lines = append(lines, b.String())
	}
	// One request produces one event here, but sorting keeps the transcript
	// stable if that ever stops being true.
	sort.Strings(lines)
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// TestSubscriptionShareWireTranscriptIsGolden is the proof that /sub/ is
// untouched.
//
// It drives the real mux, so route registration and the subscription rate limit
// are inside the boundary rather than bypassed, and it records the complete
// response plus the audit trail for every request shape a client or a prober can
// send. The golden file was recorded before the publishing plane existed. If
// folding /sub/ onto that plane is genuinely a refactor, this file does not move
// by one byte; if it moves, the already-issued subscription URL in someone's
// proxy client is what moved.
func TestSubscriptionShareWireTranscriptIsGolden(t *testing.T) {
	s, st := goldenSubServer(t)
	handler := s.Handler()

	var b strings.Builder
	// AuditEvents sorts newest-first and ties are not broken deterministically,
	// so new events are identified by id rather than by position.
	seen := map[string]bool{}
	for _, ev := range st.AuditEvents() {
		seen[ev.ID] = true
	}
	for i, tc := range subWireCases() {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		if tc.ua != "" {
			req.Header.Set("User-Agent", tc.ua)
		}
		if tc.host != "" {
			req.Host = tc.host
		}
		// A distinct client per case keeps the shared subscription limiter from
		// turning later cases into rate-limit denials.
		req.RemoteAddr = fmt.Sprintf("192.0.2.%d:5000", i+1)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		fmt.Fprintf(&b, "case %s\n", tc.name)
		b.WriteString(transcribe(rec))

		var fresh []model.AuditEvent
		for _, ev := range st.AuditEvents() {
			if !seen[ev.ID] {
				seen[ev.ID] = true
				fresh = append(fresh, ev)
			}
		}
		b.WriteString(transcribeAudit(fresh))
		b.WriteString("\n")
	}
	got := b.String()

	goldenPath := filepath.Join("testdata", "subscription_wire_golden.txt")
	if *updateSubWireGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", goldenPath)
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v (regenerate with -update-sub-golden)", err)
	}
	if got != string(want) {
		t.Fatalf("the /sub/ wire output changed.\n%s", firstDiff(string(want), got))
	}
}

// firstDiff points at the line that moved instead of printing two large blobs.
func firstDiff(want, got string) string {
	wantLines := strings.Split(want, "\n")
	gotLines := strings.Split(got, "\n")
	for i := 0; i < len(wantLines) || i < len(gotLines); i++ {
		var wl, gl string
		if i < len(wantLines) {
			wl = wantLines[i]
		}
		if i < len(gotLines) {
			gl = gotLines[i]
		}
		if wl != gl {
			return fmt.Sprintf("first difference at line %d:\n want: %s\n  got: %s", i+1, wl, gl)
		}
	}
	return "files differ only in trailing content"
}
