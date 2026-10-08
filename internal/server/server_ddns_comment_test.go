package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/ddns/cffake"
)

const frontierCNAMEError = "frontier.nat.aaitr.roobli.org already has a CNAME record pointing to nat-us-28tz.aproxy.top; a name cannot hold both. Remove that record in Cloudflare or use another name."

type ddnsSaveResponse struct {
	ID            string   `json:"id"`
	CommentMode   string   `json:"comment_mode"`
	RecordComment string   `json:"record_comment"`
	LastError     string   `json:"last_error"`
	Warnings      []string `json:"warnings"`
}

func saveDDNS(t *testing.T, handler http.Handler, body string, cookies []*http.Cookie, csrf string) (int, ddnsSaveResponse, string) {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/ddns", body, cookies, csrf)
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var out ddnsSaveResponse
	_ = json.Unmarshal(raw, &out)
	return res.StatusCode, out, string(raw)
}

func listDDNS(t *testing.T, handler http.Handler, cookies []*http.Cookie) []ddnsSaveResponse {
	t.Helper()
	res := doJSON(t, handler, http.MethodGet, "/api/ddns", "", cookies, "")
	defer res.Body.Close()
	var views []ddnsSaveResponse
	if err := json.NewDecoder(res.Body).Decode(&views); err != nil {
		t.Fatal(err)
	}
	return views
}

// The edit form prefills itself from the list view, so a comment setting the
// view withheld would be reset by every edit.
func TestDDNSViewReturnsCommentSettings(t *testing.T) {
	_, handler, st := newDDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	code, made, raw := saveDDNS(t, handler,
		`{"name":"cf","node_id":"n1","provider":"cloudflare","domains":["a.example.com"],"cf_api_token":"t","enable_ipv4":true,"comment_mode":"custom","record_comment":"Lattice #node# #ip#"}`, cookies, csrf)
	if code != http.StatusOK {
		t.Fatalf("create: %d %s", code, raw)
	}
	views := listDDNS(t, handler, cookies)
	if len(views) != 1 || views[0].CommentMode != "custom" || views[0].RecordComment != "Lattice #node# #ip#" {
		t.Fatalf("list view lost the comment settings: %+v", views)
	}
	if ev := auditByActionAndScope(t, st, "ddns.create", "ddns:admin"); ev.Metadata["comment_mode"] != "custom" {
		t.Fatalf("create audit metadata: %+v", ev.Metadata)
	}

	code, _, raw = saveDDNS(t, handler,
		`{"id":"`+made.ID+`","name":"cf","node_id":"n1","provider":"cloudflare","domains":["a.example.com"],"enable_ipv4":true}`, cookies, csrf)
	if code != http.StatusOK {
		t.Fatalf("update: %d %s", code, raw)
	}
	if ev := auditByActionAndScope(t, st, "ddns.update", "ddns:admin"); ev.Metadata["comment_mode"] != "default" {
		t.Fatalf("an update without a mode is the default mode, audit says %+v", ev.Metadata)
	}
}

func TestDDNSSaveRejectsBadCommentTemplate(t *testing.T) {
	_, handler, st := newDDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	cases := map[string]string{
		"#host#":         `"comment_mode":"custom","record_comment":"on #host#"`,
		"single line":    `"comment_mode":"custom","record_comment":"one\ntwo"`,
		"limit is 200":   `"comment_mode":"custom","record_comment":"` + strings.Repeat("x", 201) + `"`,
		"custom or none": `"comment_mode":"shout"`,
	}
	for want, fields := range cases {
		code, _, raw := saveDDNS(t, handler,
			`{"name":"cf","node_id":"n1","provider":"cloudflare","domains":["a.example.com"],"cf_api_token":"t","enable_ipv4":true,`+fields+`}`, cookies, csrf)
		if code != http.StatusBadRequest || !strings.Contains(raw, want) {
			t.Fatalf("%s: got %d %s, want 400 mentioning %q", fields, code, raw, want)
		}
	}
	code, _, raw := saveDDNS(t, handler,
		`{"name":"cf","node_id":"n1","provider":"cloudflare","domains":["a.example.com"],"cf_api_token":"t","enable_ipv4":true,"comment_mode":"custom","record_comment":"on #host#"}`, cookies, csrf)
	if code != http.StatusBadRequest || !strings.Contains(raw, "#node#") || !strings.Contains(raw, "#lattice#") {
		t.Fatalf("the refusal should name the allowed placeholders: %d %s", code, raw)
	}
	if n := len(st.DDNSProfiles()); n != 0 {
		t.Fatalf("a refused template was stored: %d profiles", n)
	}
}

// "Run now" applies a changed template at once even though the address did
// not move; the sweep, which runs on its own, never rewrites only a comment.
func TestDDNSRunNowRewritesCommentButSweepDoesNot(t *testing.T) {
	srv, handler, st, fake := newDDNSServerWithCloudflare(t)
	cookies, csrf := loginSession(t, handler)
	clock := time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	srv.now = func() time.Time { return clock }
	if err := st.UpsertNode(model.Node{ID: "n1", Name: "tokyo-1", PublicIP: "203.0.113.40"}); err != nil {
		t.Fatal(err)
	}
	fake.Seed(cffake.Record{Type: "A", Name: "a.example.com", Content: "203.0.113.40", TTL: 60, Comment: "set by an older template"})

	code, made, raw := saveDDNS(t, handler,
		`{"name":"home","node_id":"n1","provider":"cloudflare","domains":["a.example.com"],"cf_api_token":"t","enable_ipv4":true,"comment_mode":"custom","record_comment":"Lattice #node# since #date#"}`, cookies, csrf)
	if code != http.StatusOK {
		t.Fatalf("create: %d %s", code, raw)
	}

	srv.sweepDDNSOnce()
	if got := fake.Find("a.example.com", "A"); got[0].Comment != "set by an older template" {
		t.Fatalf("a scheduled run rewrote only the comment: %+v", got[0])
	}
	if n := len(fake.Writes()); n != 0 {
		t.Fatalf("a scheduled run with the address unchanged wrote %d times", n)
	}

	res := doJSON(t, handler, http.MethodPost, "/api/ddns/run", `{"id":"`+made.ID+`"}`, cookies, csrf)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("run now: %d", res.StatusCode)
	}
	got := fake.Find("a.example.com", "A")
	if len(got) != 1 || got[0].Comment != "Lattice tokyo-1 since 2026-10-08" || got[0].Content != "203.0.113.40" {
		t.Fatalf("run now did not apply the template: %+v", got)
	}
}

// A profile stored before comments existed behaves as the default mode.
func TestDDNSOldProfileGetsDefaultComment(t *testing.T) {
	_, handler, st, fake := newDDNSServerWithCloudflare(t)
	cookies, csrf := loginSession(t, handler)
	if err := st.UpsertNode(model.Node{ID: "n1", Name: "tokyo-1", PublicIP: "203.0.113.41"}); err != nil {
		t.Fatal(err)
	}
	old := model.DDNSProfile{ID: "ddns_old", Name: "old", NodeID: "n1", Provider: model.DDNSProviderCloudflare,
		Domains: []string{"old.example.com"}, EnableIPv4: true, CFAPIToken: "t"}
	if err := st.UpsertDDNSProfile(old); err != nil {
		t.Fatal(err)
	}
	res := doJSON(t, handler, http.MethodPost, "/api/ddns/run", `{"id":"ddns_old"}`, cookies, csrf)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("run now: %d", res.StatusCode)
	}
	got := fake.Find("old.example.com", "A")
	if len(got) != 1 || !strings.HasPrefix(got[0].Comment, "Lattice DDNS for tokyo-1, ") {
		t.Fatalf("old profile record: %+v", got)
	}
}

// The real failure: a profile's name already holds a CNAME. The row used to
// say only that nothing was written; last_error now says what is in the way.
func TestDDNSCNAMEConflictIsAPlainLastError(t *testing.T) {
	_, handler, st, fake := newDDNSServerWithCloudflare(t)
	cookies, csrf := loginSession(t, handler)
	if err := st.UpsertNode(model.Node{ID: "n1", Name: "frontier", PublicIP: "203.0.113.42"}); err != nil {
		t.Fatal(err)
	}
	fake.Seed(cffake.Record{Type: "CNAME", Name: "frontier.nat.aaitr.roobli.org", Content: "nat-us-28tz.aproxy.top", TTL: 1})
	code, made, raw := saveDDNS(t, handler,
		`{"name":"frontier","node_id":"n1","provider":"cloudflare","domains":["frontier.nat.aaitr.roobli.org"],"cf_api_token":"t","enable_ipv4":true}`, cookies, csrf)
	if code != http.StatusOK {
		t.Fatalf("create: %d %s", code, raw)
	}
	res := doJSON(t, handler, http.MethodPost, "/api/ddns/run", `{"id":"`+made.ID+`"}`, cookies, csrf)
	res.Body.Close()
	if res.StatusCode != http.StatusBadGateway {
		t.Fatalf("run now against a CNAME: %d", res.StatusCode)
	}
	views := listDDNS(t, handler, cookies)
	if len(views) != 1 || views[0].LastError != frontierCNAMEError {
		t.Fatalf("last_error\n got %+v\nwant %s", views, frontierCNAMEError)
	}
}

// Saving warns, without refusing, about a CNAME already on the name and about
// a node behind NAT, whose public IP is only where its traffic leaves.
func TestDDNSSaveWarnings(t *testing.T) {
	srv, handler, st, fake := newDDNSServerWithCloudflare(t)
	cookies, csrf := loginSession(t, handler)
	if err := st.UpsertNode(model.Node{ID: "n1", Name: "frontier", PublicIP: "203.0.113.43"}); err != nil {
		t.Fatal(err)
	}
	fake.Seed(cffake.Record{Type: "CNAME", Name: "frontier.nat.aaitr.roobli.org", Content: "nat-us-28tz.aproxy.top", TTL: 1})
	setTestInventory(srv, &model.SingBoxInventory{NodeID: "n1", At: time.Now(), Network: "nat", ProviderEdge: "nat-us-28tz.aproxy.top",
		Nodes: []model.SingBoxNode{{Name: "in", Protocol: "vless", Port: "443"}}})

	code, made, raw := saveDDNS(t, handler,
		`{"name":"frontier","node_id":"n1","provider":"cloudflare","domains":["frontier.nat.aaitr.roobli.org","clean.example.com"],"cf_api_token":"t","enable_ipv4":true}`, cookies, csrf)
	if code != http.StatusOK {
		t.Fatalf("a warning must not refuse the save: %d %s", code, raw)
	}
	if len(made.Warnings) != 2 {
		t.Fatalf("want a NAT and a CNAME warning, got %q", made.Warnings)
	}
	nat, cname := made.Warnings[0], made.Warnings[1]
	if !strings.Contains(nat, "frontier is behind NAT and is reached through nat-us-28tz.aproxy.top") || !strings.Contains(nat, "only where its traffic leaves") {
		t.Fatalf("NAT warning: %q", nat)
	}
	if cname != frontierCNAMEError {
		t.Fatalf("CNAME warning\n got %q\nwant %q", cname, frontierCNAMEError)
	}
	if n := len(st.DDNSProfiles()); n != 1 {
		t.Fatalf("profile not saved: %d", n)
	}

	// Warnings belong to the save answer, never to the list.
	if strings.Contains(listRaw(t, handler, cookies), "warnings") {
		t.Fatal("the list view carries warnings")
	}

	// A direct node and a clean name: nothing to warn about.
	setTestInventory(srv, nil)
	code, _, raw = saveDDNS(t, handler,
		`{"id":"`+made.ID+`","name":"frontier","node_id":"n1","provider":"cloudflare","domains":["clean.example.com"],"enable_ipv4":true}`, cookies, csrf)
	if code != http.StatusOK || strings.Contains(raw, "warnings") {
		t.Fatalf("clean save: %d %s", code, raw)
	}

	// A name outside every zone the credential can see is worth saying too.
	code, warned, raw := saveDDNS(t, handler,
		`{"id":"`+made.ID+`","name":"frontier","node_id":"n1","provider":"cloudflare","domains":["x.unknown.net"],"enable_ipv4":true}`, cookies, csrf)
	if code != http.StatusOK || len(warned.Warnings) != 1 || !strings.Contains(warned.Warnings[0], "could not read the existing records for x.unknown.net") {
		t.Fatalf("unknown zone: %d %s", code, raw)
	}
}

func listRaw(t *testing.T, handler http.Handler, cookies []*http.Cookie) string {
	t.Helper()
	res := doJSON(t, handler, http.MethodGet, "/api/ddns", "", cookies, "")
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	return string(raw)
}
