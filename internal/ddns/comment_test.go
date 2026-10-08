package ddns

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/ddns/cffake"
)

var commentClock = time.Date(2026, 10, 8, 9, 30, 45, 0, time.UTC)

func fakeCloudflare(t *testing.T) (*cffake.Server, *Cloudflare) {
	t.Helper()
	fake := cffake.New(t, "example.com", "roobli.org")
	return fake, &Cloudflare{Token: "t", BaseURL: fake.URL, Client: fake.Client()}
}

func commentRun() Run {
	return Run{NodeName: "tokyo-1", Lattice: "lattice.example.com", Now: commentClock}
}

func TestRenderCommentFillsEveryPlaceholder(t *testing.T) {
	tmpl := "#node#|#node_id#|#profile#|#domain#|#type#|#ip#|#old_ip#|#time#|#date#|#lattice#"
	got := RenderComment(tmpl, CommentVars{
		Node: "tokyo-1", NodeID: "node_7", Profile: "home", Lattice: "lat.io",
		Time: commentClock.In(time.FixedZone("UTC+8", 8*3600)), Domain: "a.io", Type: "AAAA",
		IP: "2001:db8::2", OldIP: "2001:db8::1",
	})
	want := "tokyo-1|node_7|home|a.io|AAAA|2001:db8::2|2001:db8::1|2026-10-08 09:30Z|2026-10-08|lat.io"
	if got != want {
		t.Fatalf("rendered\n got %q\nwant %q", got, want)
	}
	if RenderComment(DefaultCommentTemplate, CommentVars{Node: "tokyo-1", Time: commentClock}) != "Lattice DDNS for tokyo-1, 2026-10-08 09:30Z" {
		t.Fatalf("default template rendered %q", RenderComment(DefaultCommentTemplate, CommentVars{Node: "tokyo-1", Time: commentClock}))
	}
}

// Cloudflare Free refuses a comment over 100 characters or with a line break,
// so the rendered text is cut to 100 characters, never inside a multi-byte
// character, and a node name carrying a newline is flattened.
func TestRenderCommentIsOneLineOfAtMostOneHundredCharacters(t *testing.T) {
	long := RenderComment("#node# "+strings.Repeat("节点", 80), CommentVars{Node: "东京\n一号"})
	if !utf8.ValidString(long) {
		t.Fatalf("cut inside a character: %q", long)
	}
	if n := utf8.RuneCountInString(long); n > MaxCommentRunes {
		t.Fatalf("rendered %d characters, limit %d", n, MaxCommentRunes)
	}
	if utf8.RuneCountInString(long) != MaxCommentRunes {
		t.Fatalf("a long comment should be cut to exactly %d characters, got %d", MaxCommentRunes, utf8.RuneCountInString(long))
	}
	if strings.ContainsAny(long, "\r\n") {
		t.Fatalf("rendered comment has a line break: %q", long)
	}
	if !strings.HasPrefix(long, "东京 一号 节点") {
		t.Fatalf("unexpected start: %q", long)
	}
}

func TestValidateCommentSettings(t *testing.T) {
	ok := []model.DDNSProfile{
		{},
		{CommentMode: model.DDNSCommentDefault},
		{CommentMode: model.DDNSCommentNone, RecordComment: "#bogus#"},
		{CommentMode: model.DDNSCommentCustom, RecordComment: "Lattice #node# #ip# (was #old_ip#) via #lattice# on #date#"},
		{CommentMode: model.DDNSCommentCustom, RecordComment: "issue #42 is fixed"},
	}
	for _, p := range ok {
		if err := ValidateCommentSettings(p); err != nil {
			t.Fatalf("%+v rejected: %v", p, err)
		}
	}
	bad := map[string]model.DDNSProfile{
		"unknown placeholder #host#": {CommentMode: model.DDNSCommentCustom, RecordComment: "on #host#"},
		"single line":                {CommentMode: model.DDNSCommentCustom, RecordComment: "a\nb"},
		"limit is 200":               {CommentMode: model.DDNSCommentCustom, RecordComment: strings.Repeat("x", 201)},
		"required":                   {CommentMode: model.DDNSCommentCustom, RecordComment: "  "},
		"default, custom or none":    {CommentMode: "loud"},
	}
	for want, p := range bad {
		err := ValidateCommentSettings(p)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%+v: got %v, want an error mentioning %q", p, err, want)
		}
	}
	err := ValidateCommentSettings(bad["unknown placeholder #host#"])
	for _, name := range CommentPlaceholders {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("the error should list the allowed placeholders, %s missing: %v", name, err)
		}
	}
}

// A profile saved before comments existed has no mode and no template. It
// gets the default template on create.
func TestApplyOldProfileWritesDefaultComment(t *testing.T) {
	fake, cf := fakeCloudflare(t)
	profile := model.DDNSProfile{Name: "home", NodeID: "node_7", Domains: []string{"a.example.com"}, EnableIPv4: true}
	if err := Apply(context.Background(), cf, profile, "203.0.113.5", "", commentRun()); err != nil {
		t.Fatal(err)
	}
	recs := fake.Find("a.example.com", "A")
	if len(recs) != 1 || recs[0].Comment != "Lattice DDNS for tokyo-1, 2026-10-08 09:30Z" || recs[0].Proxied {
		t.Fatalf("created %+v", recs)
	}
}

// The update used to PUT type/name/content/ttl with proxied=false, which
// turned off proxying on a record the operator had orange-clouded.
func TestCloudflareUpdateKeepsProxied(t *testing.T) {
	fake, cf := fakeCloudflare(t)
	fake.Seed(cffake.Record{Type: "A", Name: "web.example.com", Content: "203.0.113.1", TTL: 1, Proxied: true})
	profile := model.DDNSProfile{Domains: []string{"web.example.com"}, EnableIPv4: true, TTL: 120}
	if err := Apply(context.Background(), cf, profile, "203.0.113.2", "", commentRun()); err != nil {
		t.Fatal(err)
	}
	recs := fake.Find("web.example.com", "A")
	if len(recs) != 1 || recs[0].Content != "203.0.113.2" || !recs[0].Proxied || recs[0].TTL != 1 {
		t.Fatalf("after update %+v", recs)
	}
}

// In none mode Lattice never sets or changes the comment. The old update
// wiped a comment the operator had written by hand.
func TestCloudflareNoneModeKeepsHandSetComment(t *testing.T) {
	fake, cf := fakeCloudflare(t)
	fake.Seed(cffake.Record{Type: "A", Name: "a.example.com", Content: "203.0.113.1", TTL: 60, Comment: "home router, ask before moving"})
	profile := model.DDNSProfile{Domains: []string{"a.example.com"}, EnableIPv4: true, CommentMode: model.DDNSCommentNone}
	run := commentRun()
	run.RefreshComment = true
	if err := Apply(context.Background(), cf, profile, "203.0.113.9", "", run); err != nil {
		t.Fatal(err)
	}
	recs := fake.Find("a.example.com", "A")
	if len(recs) != 1 || recs[0].Content != "203.0.113.9" || recs[0].Comment != "home router, ask before moving" {
		t.Fatalf("after update %+v", recs)
	}

	// None mode on create writes no comment at all.
	if err := Apply(context.Background(), cf, model.DDNSProfile{Domains: []string{"b.example.com"}, EnableIPv4: true, CommentMode: model.DDNSCommentNone}, "203.0.113.9", "", run); err != nil {
		t.Fatal(err)
	}
	for _, w := range fake.Writes() {
		if _, sent := w.Body["comment"]; sent {
			t.Fatalf("none mode sent a comment: %s %v", w.Method, w.Body)
		}
	}
}

// An address change rewrites the comment with the old and new address.
func TestCloudflareAddressChangeRewritesComment(t *testing.T) {
	fake, cf := fakeCloudflare(t)
	fake.Seed(cffake.Record{Type: "A", Name: "a.example.com", Content: "203.0.113.1", TTL: 60, Comment: "old"})
	profile := model.DDNSProfile{Domains: []string{"a.example.com"}, EnableIPv4: true, CommentMode: model.DDNSCommentCustom, RecordComment: "#old_ip# -> #ip#"}
	if err := Apply(context.Background(), cf, profile, "203.0.113.2", "", commentRun()); err != nil {
		t.Fatal(err)
	}
	if recs := fake.Find("a.example.com", "A"); recs[0].Comment != "203.0.113.1 -> 203.0.113.2" {
		t.Fatalf("comment %q", recs[0].Comment)
	}
}

// With the address unchanged, only an operator's "Run now" rewrites the
// comment; scheduled and heartbeat runs write nothing.
func TestCloudflareUnchangedAddressRewritesCommentOnlyOnRefresh(t *testing.T) {
	fake, cf := fakeCloudflare(t)
	fake.Seed(cffake.Record{Type: "A", Name: "a.example.com", Content: "203.0.113.1", TTL: 60, Comment: "Lattice DDNS for tokyo-1, 2026-10-01 00:00Z"})
	profile := model.DDNSProfile{Domains: []string{"a.example.com"}, EnableIPv4: true, CommentMode: model.DDNSCommentCustom, RecordComment: "managed by #lattice#"}

	if err := Apply(context.Background(), cf, profile, "203.0.113.1", "", commentRun()); err != nil {
		t.Fatal(err)
	}
	if n := len(fake.Writes()); n != 0 {
		t.Fatalf("a scheduled run with nothing moved wrote %d times", n)
	}

	run := commentRun()
	run.RefreshComment = true
	if err := Apply(context.Background(), cf, profile, "203.0.113.1", "", run); err != nil {
		t.Fatal(err)
	}
	recs := fake.Find("a.example.com", "A")
	if recs[0].Comment != "managed by lattice.example.com" || recs[0].Content != "203.0.113.1" {
		t.Fatalf("after run now %+v", recs[0])
	}
	writes := fake.Writes()
	if len(writes) != 1 || writes[0].Method != http.MethodPatch {
		t.Fatalf("run now should send one PATCH, got %+v", writes)
	}

	// Already saying the right thing: even run now writes nothing.
	if err := Apply(context.Background(), cf, profile, "203.0.113.1", "", run); err != nil {
		t.Fatal(err)
	}
	if n := len(fake.Writes()); n != 1 {
		t.Fatalf("an up-to-date comment was rewritten: %d writes", n)
	}
}

// The real case: frontier.nat.aaitr.roobli.org is a CNAME to a NAT provider
// edge, so Cloudflare refuses an A record there with 81054. The operator must
// read what is in the way, once, and the refusal is not retried.
func TestCloudflareCNAMEConflictSaysWhatIsInTheWay(t *testing.T) {
	fake, cf := fakeCloudflare(t)
	fake.Seed(cffake.Record{Type: "CNAME", Name: "frontier.nat.aaitr.roobli.org", Content: "nat-us-28tz.aproxy.top", TTL: 1})
	profile := model.DDNSProfile{Domains: []string{"frontier.nat.aaitr.roobli.org"}, EnableIPv4: true, EnableIPv6: true, MaxRetries: 3}
	err := Apply(context.Background(), cf, profile, "203.0.113.5", "2001:db8::5", commentRun())
	want := "frontier.nat.aaitr.roobli.org already has a CNAME record pointing to nat-us-28tz.aproxy.top; a name cannot hold both. Remove that record in Cloudflare or use another name."
	if err == nil || err.Error() != want {
		t.Fatalf("error\n got %v\nwant %s", err, want)
	}
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("not a ConflictError: %T", err)
	}
	if n := len(fake.Writes()); n != 2 {
		t.Fatalf("want one refused create per family and no retries, got %d writes", n)
	}
}

func TestCloudflareRecordsAt(t *testing.T) {
	fake, cf := fakeCloudflare(t)
	fake.Seed(cffake.Record{Type: "CNAME", Name: "x.example.com", Content: "edge.example.net", TTL: 1})
	got, err := cf.RecordsAt(context.Background(), "x.example.com")
	if err != nil {
		t.Fatal(err)
	}
	blocker, ok := BlockingRecord(got)
	if !ok || blocker.Type != "CNAME" || blocker.Content != "edge.example.net" {
		t.Fatalf("records at name: %+v", got)
	}
	if _, err := cf.RecordsAt(context.Background(), "x.other.net"); err == nil || !strings.Contains(err.Error(), "no cloudflare zone") {
		t.Fatalf("a name outside every zone: %v", err)
	}
}
