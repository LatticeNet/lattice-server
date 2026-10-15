package server

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/notify"
	"github.com/LatticeNet/lattice-server/internal/store"
)

var updateNotifyIcons = flag.Bool("update-notify-icons", false, "rewrite notifyicons/icons.json, the icon set scripts/notify-icons renders, from the catalogue")

// notifyIconSize is the edge of every icon, in pixels; scripts/notify-icons
// renders at the same size.
const notifyIconSize = 180

const notifyIconManifestPath = "notifyicons/icons.json"

type notifyIconManifestEntry struct {
	File string `json:"file"`
	Icon string `json:"icon"`
	Tone string `json:"tone"`
}

// catalogueNotifyIcons is every icon the catalogue can produce, one per
// (glyph, tone), sorted by file name.
func catalogueNotifyIcons() []notifyIconManifestEntry {
	presentations := []notifyPresentation{notifyPluginMessagePattern.notifyPresentation, notifyWebhookEntry.notifyPresentation}
	for _, e := range notifyCatalogueTypes {
		presentations = append(presentations, e.notifyPresentation)
	}
	seen := map[string]bool{}
	var out []notifyIconManifestEntry
	for _, p := range presentations {
		file := notifyIconFile(p.Icon, p.tone())
		if !seen[file] {
			seen[file] = true
			out = append(out, notifyIconManifestEntry{File: file, Icon: p.Icon, Tone: p.tone()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out
}

const regenerateNotifyIcons = "regenerate: go test ./internal/server -run '^TestNotifyIconManifestMatchesCatalogue$' -update-notify-icons, then npm ci && npm run generate in scripts/notify-icons"

// The manifest scripts/notify-icons renders from is exactly the catalogue's
// icon set.
func TestNotifyIconManifestMatchesCatalogue(t *testing.T) {
	want := catalogueNotifyIcons()
	if *updateNotifyIcons {
		data, err := json.MarshalIndent(want, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(notifyIconManifestPath, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	data, err := os.ReadFile(notifyIconManifestPath)
	if err != nil {
		t.Fatalf("%v; %s", err, regenerateNotifyIcons)
	}
	var got []notifyIconManifestEntry
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%s is out of date with the catalogue:\n got  %v\n want %v\n%s", notifyIconManifestPath, got, want, regenerateNotifyIcons)
	}
}

// Every (glyph, tone) the catalogue can produce is embedded as a decodable
// 180 px square PNG, and nothing else is.
func TestNotifyIconsCoverCatalogue(t *testing.T) {
	want := catalogueNotifyIcons()
	expected := map[string]bool{}
	var missing []string
	for _, e := range want {
		expected[e.File] = true
		data, ok := notifyIcons[e.File]
		if !ok {
			missing = append(missing, e.File)
			continue
		}
		img, err := png.Decode(bytes.NewReader(data))
		if err != nil {
			t.Errorf("%s does not decode as PNG: %v", e.File, err)
			continue
		}
		if b := img.Bounds(); b.Dx() != notifyIconSize || b.Dy() != notifyIconSize {
			t.Errorf("%s is %dx%d, want %dx%d", e.File, b.Dx(), b.Dy(), notifyIconSize, notifyIconSize)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("icons the catalogue can produce but notifyicons/ lacks: %v; %s", missing, regenerateNotifyIcons)
	}
	for name := range notifyIcons {
		if !expected[name] {
			t.Errorf("notifyicons/%s is embedded but no catalogue entry produces it; %s", name, regenerateNotifyIcons)
		}
	}
}

func fetchNotifyIcon(handler http.Handler, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

// /notify-icons/ serves the embedded icons without a session, cached for a
// year as immutable, and answers 404 for any other name, any dot segment and
// any extra segment, without a listing.
func TestNotifyIconRoute(t *testing.T) {
	_, handler, _ := newInventoryServer(t)

	for _, e := range catalogueNotifyIcons() {
		rec := fetchNotifyIcon(handler, http.MethodGet, notifyIconPathPrefix+e.File)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", e.File, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != "image/png" {
			t.Fatalf("%s: Content-Type %q", e.File, got)
		}
		if got := rec.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
			t.Fatalf("%s: Cache-Control %q", e.File, got)
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Fatalf("%s: the security headers must still apply, X-Content-Type-Options %q", e.File, got)
		}
		if _, err := png.Decode(rec.Body); err != nil {
			t.Fatalf("%s: served bytes do not decode: %v", e.File, err)
		}
	}

	head := fetchNotifyIcon(handler, http.MethodHead, notifyIconPathPrefix+"server-off-critical.png")
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Length") == "" {
		t.Fatalf("HEAD: %d with %d bytes, Content-Length %q", head.Code, head.Body.Len(), head.Header().Get("Content-Length"))
	}
	if rec := fetchNotifyIcon(handler, http.MethodPost, notifyIconPathPrefix+"server-off-critical.png"); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rec.Code)
	}

	for _, target := range []string{
		"/notify-icons/",
		"/notify-icons/no-such-icon.png",
		"/notify-icons/server-off-quiet.png",
		"/notify-icons/icons.json",
		"/notify-icons/../index.html",
		"/notify-icons/..%2findex.html",
		"/notify-icons/%2e%2e/index.html",
		"/notify-icons/..",
		"/notify-icons/./server-off-critical.png",
		"/notify-icons/a/../server-off-critical.png",
		"/notify-icons/notifyicons/server-off-critical.png",
		"/notify-icons/server-off-critical.png/",
		"/notify-icons//server-off-critical.png",
	} {
		rec := fetchNotifyIcon(handler, http.MethodGet, target)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: want 404, got %d (Location %q)", target, rec.Code, rec.Header().Get("Location"))
		}
		if strings.Contains(rec.Body.String(), ".png") {
			t.Errorf("%s: the 404 lists files: %q", target, rec.Body.String())
		}
	}
}

// barkPushRecorder is a fake Bark server recording the fields of each push,
// from the JSON body or, when it refuses /push, from the GET fallback.
type barkPushRecorder struct {
	mu     sync.Mutex
	pushes []map[string]string
}

func newBarkPushRecorder(t *testing.T, refusePush bool) (*httptest.Server, *barkPushRecorder) {
	t.Helper()
	rec := &barkPushRecorder{}
	srv := newLocalOIDCTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fields := map[string]string{}
		if r.URL.Path == "/push" {
			if refusePush {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewDecoder(r.Body).Decode(&fields)
			fields["via"] = "json"
		} else {
			for k := range r.URL.Query() {
				fields[k] = r.URL.Query().Get(k)
			}
			fields["via"] = "get"
		}
		rec.mu.Lock()
		rec.pushes = append(rec.pushes, fields)
		rec.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

func (b *barkPushRecorder) only(t *testing.T) map[string]string {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.pushes) != 1 {
		t.Fatalf("want one push, got %v", b.pushes)
	}
	return b.pushes[0]
}

// sendThroughFakeBark makes srv send for real through buildChannel and
// notify.Bark, with the fake Bark's client in place of the outbound policy
// client, which refuses a loopback address.
func sendThroughFakeBark(srv *Server, bark *httptest.Server) {
	srv.notifySend = func(ctx context.Context, c model.NotifyChannel, msg notify.Message) error {
		built, err := buildChannel(c.Kind, c.Config)
		if err != nil {
			return err
		}
		b, ok := built.(notify.Bark)
		if !ok {
			return built.Send(ctx, msg)
		}
		b.Client = bark.Client()
		return b.Send(ctx, msg)
	}
}

func newBarkPresentationServer(t *testing.T, publicURL string) (*Server, http.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, PublicURL: publicURL, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	return srv, srv.Handler(), st
}

// A node.offline push goes out under the Nodes group with the
// server-off-critical icon, on the JSON push and on the GET fallback; a
// channel the operator gave its own group keeps it; without a public URL no
// icon is sent.
func TestBarkPushCarriesCategoryGroupAndIcon(t *testing.T) {
	const wantIcon = "https://lattice.example.com/notify-icons/server-off-critical.png"
	cases := []struct {
		name       string
		publicURL  string
		group      string
		refusePush bool
		wantGroup  string
		wantIcon   string
		wantVia    string
	}{
		{"json push", "https://lattice.example.com/", "", false, "Nodes", wantIcon, "json"},
		{"get fallback", "https://lattice.example.com", "", true, "Nodes", wantIcon, "get"},
		{"default group written out", "https://lattice.example.com", notify.BarkDefaultGroup, false, "Nodes", wantIcon, "json"},
		{"operator group", "https://lattice.example.com", "ops", false, "ops", wantIcon, "json"},
		{"operator group on get fallback", "https://lattice.example.com", "ops", true, "ops", wantIcon, "get"},
		{"no public url", "", "", false, "Nodes", "", "json"},
		{"no public url on get fallback", "", "", true, "Nodes", "", "get"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bark, pushes := newBarkPushRecorder(t, c.refusePush)
			srv, handler, st := newBarkPresentationServer(t, c.publicURL)
			cfg := map[string]string{"base_url": bark.URL, "key": "devkey"}
			if c.group != "" {
				cfg["group"] = c.group
			}
			if err := st.UpsertNotifyChannel(model.NotifyChannel{ID: "nc-bark", Name: "Phone", Kind: "bark", Enabled: true, Config: cfg}); err != nil {
				t.Fatal(err)
			}
			sendThroughFakeBark(srv, bark)
			srv.notifyEventTyped(EventNodeOffline, "Node offline: hk-1", "hk-1 missed three heartbeats")
			waitOutboxSettled(t, srv)

			got := pushes.only(t)
			if got["via"] != c.wantVia || got["group"] != c.wantGroup {
				t.Fatalf("push = %v, want group %q via %s", got, c.wantGroup, c.wantVia)
			}
			icon, hasIcon := got["icon"]
			if c.wantIcon == "" {
				if hasIcon {
					t.Fatalf("no public URL, yet the push carries icon %q", icon)
				}
				return
			}
			if icon != c.wantIcon {
				t.Fatalf("icon = %q, want %q", icon, c.wantIcon)
			}
			// The URL the phone is given is one this server answers.
			u, err := url.Parse(icon)
			if err != nil {
				t.Fatal(err)
			}
			if rec := fetchNotifyIcon(handler, http.MethodGet, u.Path); rec.Code != http.StatusOK {
				t.Fatalf("the pushed icon %s is not served: %d", u.Path, rec.Code)
			}
			if rows := st.NotifyDeliveries(store.NotifyDeliveryFilter{}); len(rows) != 1 || rows[0].Outcome != store.NotifyOutcomeSent {
				t.Fatalf("deliveries = %+v", rows)
			}
		})
	}
}

// A stored channel's test push is presented like any other: the
// Notifications group and the quiet flask icon.
func TestBarkChannelTestCarriesCategoryGroupAndIcon(t *testing.T) {
	bark, pushes := newBarkPushRecorder(t, false)
	srv, handler, st := newBarkPresentationServer(t, "https://lattice.example.com")
	if err := st.UpsertNotifyChannel(model.NotifyChannel{ID: "nc-bark", Name: "Phone", Kind: "bark", Enabled: true, Config: map[string]string{"base_url": bark.URL, "key": "devkey"}}); err != nil {
		t.Fatal(err)
	}
	sendThroughFakeBark(srv, bark)
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/notify/channels/test", `{"id":"nc-bark"}`, cookies, csrf)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("test: %d %s", res.StatusCode, readAll(t, res))
	}
	res.Body.Close()
	got := pushes.only(t)
	if got["group"] != "Notifications" || got["icon"] != "https://lattice.example.com/notify-icons/flask-conical-quiet.png" {
		t.Fatalf("test push = %v", got)
	}
}

// Other channel kinds are unchanged in this slice: the message they get has
// neither group nor icon.
func TestNonBarkChannelsGetNoPresentation(t *testing.T) {
	srv, _, _ := newBarkPresentationServer(t, "https://lattice.example.com")
	for _, kind := range []string{"telegram", "discord", "webhook"} {
		m := srv.presentNotifyMessage(kind, notify.Message{Title: "t", Body: "b"}, EventNodeOffline, store.NotifySourceServer)
		if m.Group != "" || m.Icon != "" {
			t.Fatalf("%s got presentation %+v", kind, m)
		}
	}
	m := srv.presentNotifyMessage("bark", notify.Message{Title: "t", Body: "b"}, "plugin.latticenet.sub-store.message", store.NotifySourcePlugin)
	if m.Group != "Plugins" || m.Icon != "https://lattice.example.com/notify-icons/puzzle-quiet.png" {
		t.Fatalf("plugin push = %+v", m)
	}
	m = srv.presentNotifyMessage("bark", notify.Message{Title: "t", Body: "b"}, "deploy.finished", store.NotifySourceWebhook)
	if m.Group != "Webhooks" || m.Icon != "https://lattice.example.com/notify-icons/webhook-quiet.png" {
		t.Fatalf("webhook push = %+v", m)
	}
}

// The send that stands in when the store refuses the outbox write presents a
// push the same way as the outbox does.
func TestBarkUnrecordedSendCarriesCategoryGroupAndIcon(t *testing.T) {
	bark, pushes := newBarkPushRecorder(t, false)
	srv, _, st := newBarkPresentationServer(t, "https://lattice.example.com")
	if err := st.UpsertNotifyChannel(model.NotifyChannel{ID: "nc-bark", Name: "Phone", Kind: "bark", Enabled: true, Config: map[string]string{"base_url": bark.URL, "key": "devkey"}}); err != nil {
		t.Fatal(err)
	}
	sendThroughFakeBark(srv, bark)
	srv.sendUnrecorded(srv.planNotifyEvent(EventServiceDown, "sing-box down on hk-1", "probe failed three times", notifyEnqueue{source: store.NotifySourceServer}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if left := srv.notifyDeliveries.wait(ctx); left > 0 {
		t.Fatalf("%d unrecorded sends still running", left)
	}
	got := pushes.only(t)
	if got["group"] != "Services" || got["icon"] != "https://lattice.example.com/notify-icons/power-off-critical.png" {
		t.Fatalf("unrecorded push = %v", got)
	}
}

// A type only an operator webhook defines is presented as a webhook event
// whatever source raised it; an exact type is never looked up among the
// webhooks.
func TestBarkPresentationOfAWebhookType(t *testing.T) {
	srv, _, st := newBarkPresentationServer(t, "https://lattice.example.com")
	if err := st.UpsertNotifyWebhook(store.NotifyWebhook{ID: "wh-deploy", Name: "Deploys", EventType: "deploy.finished", TitleTemplate: "t", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	m := srv.presentNotifyMessage("bark", notify.Message{Title: "t"}, "deploy.finished", store.NotifySourceServer)
	if m.Group != "Webhooks" || m.Icon != "https://lattice.example.com/notify-icons/webhook-quiet.png" {
		t.Fatalf("webhook type push = %+v", m)
	}
	m = srv.presentNotifyMessage("bark", notify.Message{Title: "t"}, "not.a.webhook", store.NotifySourceServer)
	if m.Group != "General" || m.Icon != "https://lattice.example.com/notify-icons/bell-quiet.png" {
		t.Fatalf("unknown type push = %+v", m)
	}
}
