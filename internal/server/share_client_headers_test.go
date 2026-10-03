package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestCanonicalSubscriptionUserinfo(t *testing.T) {
	cases := map[string]string{
		"upload=455727941; download=8231525376; total=107374182400; expire=1799999999": "upload=455727941; download=8231525376; total=107374182400; expire=1799999999",
		"total=3;upload=1;download=2":             "upload=1; download=2; total=3",
		"Upload = 1 ; DOWNLOAD=2":                 "upload=1; download=2",
		"upload=1; plan=gold; download=2":         "upload=1; download=2",
		"upload=1.5; download=2":                  "download=2",
		"upload=-1; download=2":                   "download=2",
		"upload=007":                              "upload=7",
		"upload=0":                                "upload=0",
		"upload=1\r\nX-Injected: yes":             "",
		"expire=":                                 "",
		"nothing a client reads":                  "",
		"":                                        "",
		"upload=99999999999999999999999":          "",
		"upload=1; upload=2":                      "upload=2",
		"download=0; total=0; expire=0; upload=0": "upload=0; download=0; total=0; expire=0",
		"upload=1;;; download=2; =3; total":       "upload=1; download=2",
	}
	for in, want := range cases {
		if got := canonicalSubscriptionUserinfo(in); got != want {
			t.Errorf("canonicalSubscriptionUserinfo(%q) = %q, want %q", in, got, want)
		}
	}
}

// A link advertises its refresh period and a profile name to the client: two
// hours unless the operator set the share's own, and the share's slug.
func TestLinkAdvertisesItsIntervalAndTitle(t *testing.T) {
	s, st := newShareTestServer(t)
	share := mustCreateShare(t, s)
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "s", Raw: "nodes", FetchedAt: s.now()}); err != nil {
		t.Fatal(err)
	}
	s.subscriptionRender = func(_ context.Context, share model.SubscriptionShare, _, _ string, _ shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		epoch, _ := s.subscriptionSnapshotEpoch(share.Source.PluginID, share.Source.SubscriptionID, snap)
		return renderedSubscription{Body: []byte("vless://a\n"), Userinfo: "total=3; upload=1; plan=gold",
			RevalidationVersion: subscriptionRevalidationVersion(snap), SourceEpoch: epoch, FetchedAt: snap.FetchedAt}, nil
	}
	fetch := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.handleSubscriptionShare(rec, shareRequest("/sub/team/"+share.Token, "clash-verge/v2"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		return rec
	}
	rec := fetch()
	if rec.Header().Get("Profile-Update-Interval") != "2" ||
		rec.Header().Get("Content-Disposition") != `attachment; filename="team"; filename*=UTF-8''team` ||
		rec.Header().Get("Subscription-Userinfo") != "upload=1; total=3" {
		t.Fatalf("headers = %v", rec.Header())
	}

	if res := patchShare(t, s, share.ID, `{"update_interval_hours": 6}`); res.Code != http.StatusOK {
		t.Fatalf("patch = %d %s", res.Code, res.Body.String())
	} else {
		var view shareView
		if err := json.Unmarshal(res.Body.Bytes(), &view); err != nil || view.UpdateIntervalHours != 6 {
			t.Fatalf("view = %+v err %v", view, err)
		}
	}
	if got := fetch().Header().Get("Profile-Update-Interval"); got != "6" {
		t.Fatalf("interval after patch = %q", got)
	}
	for _, bad := range []string{`{"update_interval_hours": 169}`, `{"update_interval_hours": -1}`} {
		if res := patchShare(t, s, share.ID, bad); res.Code != http.StatusBadRequest {
			t.Fatalf("%s answered %d", bad, res.Code)
		}
	}
	if res := patchShare(t, s, share.ID, `{"update_interval_hours": 0}`); res.Code != http.StatusOK {
		t.Fatalf("clear = %d", res.Code)
	}
	if got := fetch().Header().Get("Profile-Update-Interval"); got != "2" {
		t.Fatalf("interval after clearing = %q", got)
	}
	stored, _ := st.SubscriptionShare(share.ID)
	if _, ok := stored.Extra[shareExtraUpdateInterval]; ok {
		t.Fatalf("clearing left the field behind: %v", stored.Extra)
	}
}

func TestCreateShareTakesAnInterval(t *testing.T) {
	s, _ := newShareTestServer(t)
	rec := postShare(t, s, `{"slug":"family","source":{"kind":"plugin","plugin_id":"p","subscription_id":"s"},"update_interval_hours":12}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	var view shareView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil || view.UpdateIntervalHours != 12 {
		t.Fatalf("view = %+v err %v", view, err)
	}
	if rec := postShare(t, s, `{"slug":"other","source":{"kind":"plugin","plugin_id":"p","subscription_id":"s"},"update_interval_hours":1000}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("an out-of-range interval was accepted: %d", rec.Code)
	}
}

// The interval rides in the share's Extra map until the SDK has a field for
// it, so it has to survive both persistence paths and a reopen.
func TestShareIntervalSurvivesPersistence(t *testing.T) {
	for _, hot := range []bool{false, true} {
		dir := t.TempDir()
		cipher, err := secret.NewAESGCM([]byte("0123456789abcdef0123456789abcdef"))
		if err != nil {
			t.Fatal(err)
		}
		open := func() *store.Store {
			st, err := store.OpenWithCipher(filepath.Join(dir, "state.json"), cipher)
			if err != nil {
				t.Fatal(err)
			}
			if hot {
				if err := st.EnableRuntimeBoltHotStore(filepath.Join(dir, "state-hot.db")); err != nil {
					t.Fatal(err)
				}
			}
			return st
		}
		st := open()
		share, err := withShareUpdateIntervalHours(model.SubscriptionShare{ID: "sh1", Slug: "one", Token: "persisted-token-0123456789abcdef", Enabled: true}, 9)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.UpsertSubscriptionShare(share); err != nil {
			t.Fatal(err)
		}
		if err := st.Save(); err != nil {
			t.Fatal(err)
		}
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
		reopened := open()
		got, ok := reopened.SubscriptionShare("sh1")
		if !ok || shareUpdateIntervalHours(got) != 9 {
			t.Fatalf("hot=%v: after reopen ok=%v interval=%d extra=%v", hot, ok, shareUpdateIntervalHours(got), got.Extra)
		}
		_ = reopened.Close()
	}
}
