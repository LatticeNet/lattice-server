package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// Publishing a route makes content publicly reachable, so the scope that grants
// it is a security boundary. Merging two schemes into one plane must not hand
// any scope the power to publish something it could not publish before, and the
// only way that stays true is if each origin keeps the scope it already had.
func TestPublishingScopesAreUnchangedPerOrigin(t *testing.T) {
	cases := []struct {
		origin string
		admin  string
		read   string
	}{
		{originKV, "kv:admin", "kv:read"},
		{originStatic, "static:admin", "static:read"},
		// Shares were gated on proxy:admin before the plane existed and still
		// are. Folding them in must not make kv:admin able to publish proxy
		// configuration, nor proxy:admin able to publish a storage bucket.
		{originPlugin, "proxy:admin", "proxy:admin"},
	}
	for _, tc := range cases {
		if got := publishingAdminScope(tc.origin); got != tc.admin {
			t.Errorf("publishingAdminScope(%q) = %q, want %q", tc.origin, got, tc.admin)
		}
		if got := publishingReadScope(tc.origin); got != tc.read {
			t.Errorf("publishingReadScope(%q) = %q, want %q", tc.origin, got, tc.read)
		}
	}
	// The storage API's own helpers must resolve to the same answer, so there is
	// one place that decides who may publish rather than two that agree today.
	if storageAdminScope(originKV) != publishingAdminScope(originKV) {
		t.Error("storage and publishing disagree on the kv admin scope")
	}
	if storageAdminScope(originStatic) != publishingAdminScope(originStatic) {
		t.Error("storage and publishing disagree on the static admin scope")
	}
}

// A share is reachable at a reserved mount on any hostname. That is what /sub/
// has always done, and it is the fact an issued subscription URL depends on.
func TestShareProjectsOntoTheReservedMountOnAnyHost(t *testing.T) {
	s, st := newShareTestServer(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	s.now = func() time.Time { return now }
	mustUpsertShare(t, st, model.SubscriptionShare{
		ID: "share_1", Slug: "cd-self", Token: strings.Repeat("a", 32), Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "sub"},
	})

	records := s.publishingRecords(originPlugin)
	if len(records) != 1 {
		t.Fatalf("got %d plugin records, want 1", len(records))
	}
	record := records[0]
	if record.PathPrefix != "sub/cd-self" {
		t.Errorf("path prefix = %q, want sub/cd-self", record.PathPrefix)
	}
	if record.Hostname != "" || !record.Reserved || record.ShareID != "share_1" {
		t.Errorf("unexpected record: %+v", record)
	}
	for _, host := range []string{"lattice.example", "somewhere.else.example", ""} {
		if _, ok := s.publishingRecordForRequest(originPlugin, host, "/sub/cd-self/"+strings.Repeat("a", 32)); !ok {
			t.Errorf("share route did not match on host %q", host)
		}
	}
	// A path that is not under the mount is not this record's business.
	if _, ok := s.publishingRecordForRequest(originPlugin, "lattice.example", "/other/thing"); ok {
		t.Error("share route matched a path outside its mount")
	}
}

// Enabled and the expiry are route facts, so the plane stops answering for them
// rather than leaving each origin to remember on its own.
func TestDisabledAndExpiredSharesLeaveThePlane(t *testing.T) {
	s, st := newShareTestServer(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	s.now = func() time.Time { return now }
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	token := strings.Repeat("a", 32)

	mustUpsertShare(t, st, model.SubscriptionShare{ID: "off", Slug: "off", Token: token, Enabled: false})
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "old", Slug: "old", Token: token, Enabled: true, ExpiresAt: &past})
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "live", Slug: "live", Token: token, Enabled: true, ExpiresAt: &future})

	for _, slug := range []string{"off", "old"} {
		if _, ok := s.publishingRecordForRequest(originPlugin, "any.example", "/sub/"+slug+"/"+token); ok {
			t.Errorf("slug %q still routes", slug)
		}
	}
	if _, ok := s.publishingRecordForRequest(originPlugin, "any.example", "/sub/live/"+token); !ok {
		t.Error("an enabled, unexpired share stopped routing")
	}
	// Listing still shows all three: an operator has to be able to see the route
	// that stopped serving, or the console cannot explain why it stopped.
	if got := len(s.publishingRecords(originPlugin)); got != 3 {
		t.Errorf("listed %d records, want all 3 including the off and expired ones", got)
	}
}

// The merged console page reads one endpoint. It must not become a way to see
// routes the per-origin APIs would have refused to list.
func TestPublishingRecordsListFiltersByOriginScope(t *testing.T) {
	s, st := newShareTestServer(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	s.now = func() time.Time { return now }

	mustUpsertShare(t, st, model.SubscriptionShare{
		ID: "share_1", Slug: "cd-self", Token: strings.Repeat("a", 32), Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "sub"},
	})
	if err := st.UpsertStorageBucket(model.StorageBucket{ID: "kv_b", Kind: originKV, Name: "b"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertStorageBinding(model.StorageBinding{
		ID: "bind_1", Kind: originKV, Bucket: "b", Hostname: "kv.example", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	list := func(scopes ...string) (origins []string, byOrigin map[string]int) {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/publishing/records", nil)
		s.handlePublishingRecords(rec, req, principal{Principal: rbac.Principal{ActorID: "a", Scopes: scopes}})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		var out struct {
			Records []publishingRecordView `json:"records"`
			Origins []string               `json:"origins"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		byOrigin = map[string]int{}
		for _, r := range out.Records {
			byOrigin[r.Origin]++
		}
		return out.Origins, byOrigin
	}

	origins, byOrigin := list("kv:read")
	if byOrigin[originPlugin] != 0 {
		t.Error("a kv reader was shown the subscription route")
	}
	if byOrigin[originKV] != 1 {
		t.Errorf("a kv reader saw %d kv routes, want 1", byOrigin[originKV])
	}
	if len(origins) != 1 || origins[0] != originKV {
		t.Errorf("visible origins = %v, want [kv]", origins)
	}

	origins, byOrigin = list("proxy:admin")
	if byOrigin[originKV] != 0 {
		t.Error("a proxy admin was shown a kv storage route")
	}
	if byOrigin[originPlugin] != 1 {
		t.Errorf("a proxy admin saw %d plugin routes, want 1", byOrigin[originPlugin])
	}
	if len(origins) != 1 || origins[0] != originPlugin {
		t.Errorf("visible origins = %v, want [plugin]", origins)
	}

	// No scopes at all is an empty list rather than an error, but the empty
	// origins list is what tells the console it is looking at a permission
	// boundary and not at an empty product.
	origins, byOrigin = list()
	if len(byOrigin) != 0 || len(origins) != 0 {
		t.Errorf("an unscoped caller saw records %v origins %v", byOrigin, origins)
	}
}

// The reserved mount and a storage binding are matched by the same resolver, so
// the longest-prefix rule storage bindings already relied on has to survive the
// move onto the plane.
func TestPublishingLongestPrefixStillWins(t *testing.T) {
	s, st := newShareTestServer(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	s.now = func() time.Time { return now }

	for _, b := range []model.StorageBinding{
		{ID: "bind_root", Kind: originStatic, Bucket: "root", Hostname: "site.example", Enabled: true},
		{ID: "bind_docs", Kind: originStatic, Bucket: "docs", Hostname: "site.example", PathPrefix: "docs", Enabled: true},
		{ID: "bind_off", Kind: originStatic, Bucket: "off", Hostname: "site.example", PathPrefix: "docs/api", Enabled: false},
	} {
		if err := st.UpsertStorageBinding(b); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		path string
		want string
	}{
		{"/index.html", "root"},
		{"/docs/guide.html", "docs"},
		// The deepest prefix is disabled, so the next best answers rather than
		// the request falling through to a 404.
		{"/docs/api/spec.html", "docs"},
	}
	for _, tc := range cases {
		record, ok := s.publishingRecordForRequest(originStatic, "site.example", tc.path)
		if !ok || record.Bucket != tc.want {
			t.Errorf("%s resolved to %q (ok=%v), want %q", tc.path, record.Bucket, ok, tc.want)
		}
	}
	// A different host is not this binding's business.
	if _, ok := s.publishingRecordForRequest(originStatic, "other.example", "/index.html"); ok {
		t.Error("a static binding answered on a hostname it was not bound to")
	}
}
