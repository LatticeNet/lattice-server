package ddns

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/ddns/cffake"
)

const (
	frontierName   = "frontier.nat.aaitr.roobli.org"
	frontierTarget = "nat-us-28tz.aproxy.top"
)

func cnameProfile(mode string) model.DDNSProfile {
	return model.DDNSProfile{
		ID: "ddns_baioum5vmvw66ups", Name: "frontier", NodeID: "node_frontier",
		Provider: model.DDNSProviderCloudflare, Domains: []string{frontierName},
		RecordType: model.DDNSRecordCNAME, CNAMETarget: frontierTarget,
		EnableIPv4: true, EnableIPv6: true, TTL: 60, CFAPIToken: "t", CommentMode: mode,
	}
}

func onlyRecord(t *testing.T, fake *cffake.Server, name string) cffake.Record {
	t.Helper()
	got := fake.Find(name, "")
	if len(got) != 1 {
		t.Fatalf("records at %s: %+v", name, got)
	}
	return got[0]
}

// The operator made the CNAME by hand. Lattice adopts it: a run with the same
// target writes nothing, even when Cloudflare spells the target with a
// trailing dot or in another case.
func TestCNAMEAdoptsSameTargetWithoutWriting(t *testing.T) {
	for _, content := range []string{frontierTarget, "NAT-US-28TZ.aproxy.top."} {
		fake, cf := fakeCloudflare(t)
		fake.Seed(cffake.Record{Type: "CNAME", Name: frontierName, Content: content, TTL: 1, Proxied: false, Comment: "made by hand"})
		if err := Apply(context.Background(), cf, cnameProfile(""), "47.148.162.50", "", commentRun()); err != nil {
			t.Fatalf("%s: %v", content, err)
		}
		if n := len(fake.Writes()); n != 0 {
			t.Fatalf("%s: adopting a CNAME already at the target wrote %d times: %+v", content, n, fake.Writes())
		}
		if rec := onlyRecord(t, fake, frontierName); rec.Comment != "made by hand" || rec.Content != content {
			t.Fatalf("%s: adopted record changed: %+v", content, rec)
		}
	}
}

// A CNAME that points elsewhere is retargeted in place: the content changes,
// the operator's proxy setting stays, and in mode none the comment is not
// sent at all.
func TestCNAMERetargetsKeepingProxiedAndComment(t *testing.T) {
	fake, cf := fakeCloudflare(t)
	fake.Seed(cffake.Record{Type: "CNAME", Name: frontierName, Content: "nat-us-old.aproxy.top", TTL: 1, Proxied: true, Comment: "operator note"})
	if err := Apply(context.Background(), cf, cnameProfile(model.DDNSCommentNone), "", "", commentRun()); err != nil {
		t.Fatal(err)
	}
	rec := onlyRecord(t, fake, frontierName)
	if rec.Type != "CNAME" || rec.Content != frontierTarget || !rec.Proxied || rec.Comment != "operator note" {
		t.Fatalf("retargeted record: %+v", rec)
	}
	writes := fake.Writes()
	if len(writes) != 1 || writes[0].Method != "PATCH" {
		t.Fatalf("want one PATCH, got %+v", writes)
	}
	if _, sent := writes[0].Body["comment"]; sent {
		t.Fatalf("mode none sent a comment: %+v", writes[0].Body)
	}
	if string(writes[0].Body["ttl"]) != "1" {
		t.Fatalf("a proxied record keeps automatic TTL, sent %s", writes[0].Body["ttl"])
	}
}

// With no record on the name, the CNAME is created unproxied and carries the
// rendered comment, where #target# is the target and #ip# is empty.
func TestCNAMECreatesUnproxiedWithComment(t *testing.T) {
	fake, cf := fakeCloudflare(t)
	profile := cnameProfile(model.DDNSCommentCustom)
	profile.RecordComment = "#node# #type# to #target# ip=[#ip#]"
	if err := Apply(context.Background(), cf, profile, "47.148.162.50", "2001:db8::1", commentRun()); err != nil {
		t.Fatal(err)
	}
	rec := onlyRecord(t, fake, frontierName)
	if rec.Type != "CNAME" || rec.Content != frontierTarget || rec.Proxied || rec.TTL != 60 {
		t.Fatalf("created record: %+v", rec)
	}
	if want := "tokyo-1 CNAME to " + frontierTarget + " ip=[]"; rec.Comment != want {
		t.Fatalf("comment\n got %q\nwant %q", rec.Comment, want)
	}
	if len(fake.Find(frontierName, "A")) != 0 || len(fake.Find(frontierName, "AAAA")) != 0 {
		t.Fatal("a CNAME profile wrote an address record")
	}
}

// An A record on the name stops the CNAME. Nothing is deleted or written, the
// error names the record in plain words, and it is not retried.
func TestCNAMEConflictWithAddressRecordDeletesNothing(t *testing.T) {
	fake, cf := fakeCloudflare(t)
	fake.Seed(cffake.Record{Type: "A", Name: frontierName, Content: "1.2.3.4", TTL: 60})
	profile := cnameProfile("")
	profile.MaxRetries = 3
	err := Apply(context.Background(), cf, profile, "", "", commentRun())
	want := frontierName + " already has an A record (1.2.3.4); a name cannot hold a CNAME and other records. Remove it in Cloudflare, then run again."
	if err == nil || err.Error() != want {
		t.Fatalf("error\n got %v\nwant %s", err, want)
	}
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("not a ConflictError: %T", err)
	}
	if n := len(fake.Writes()); n != 0 {
		t.Fatalf("a conflict wrote %d times", n)
	}
	if rec := onlyRecord(t, fake, frontierName); rec.Type != "A" || rec.Content != "1.2.3.4" {
		t.Fatalf("the A record changed: %+v", rec)
	}

	fake.Seed(cffake.Record{Type: "AAAA", Name: frontierName, Content: "2001:db8::9", TTL: 60})
	err = Apply(context.Background(), cf, profile, "", "", commentRun())
	if err == nil || !strings.Contains(err.Error(), "an A record (1.2.3.4) and an AAAA record (2001:db8::9)") || !strings.Contains(err.Error(), "Remove them in Cloudflare") {
		t.Fatalf("two blockers: %v", err)
	}
}

// "Run now" rewrites the comment of a CNAME already at the target, as it does
// for an address record; a scheduled run does not.
func TestCNAMERunNowRefreshesCommentOnly(t *testing.T) {
	fake, cf := fakeCloudflare(t)
	fake.Seed(cffake.Record{Type: "CNAME", Name: frontierName, Content: frontierTarget, TTL: 1, Proxied: true, Comment: "made by hand"})
	profile := cnameProfile(model.DDNSCommentCustom)
	profile.RecordComment = "Lattice #node# to #target#"
	if err := Apply(context.Background(), cf, profile, "", "", commentRun()); err != nil {
		t.Fatal(err)
	}
	if n := len(fake.Writes()); n != 0 {
		t.Fatalf("a scheduled run rewrote only the comment: %d writes", n)
	}
	run := commentRun()
	run.RefreshComment = true
	if err := Apply(context.Background(), cf, profile, "", "", run); err != nil {
		t.Fatal(err)
	}
	rec := onlyRecord(t, fake, frontierName)
	if rec.Comment != "Lattice tokyo-1 to "+frontierTarget || rec.Content != frontierTarget || !rec.Proxied {
		t.Fatalf("refreshed record: %+v", rec)
	}
}

func TestValidateRecordSettings(t *testing.T) {
	ok := cnameProfile("")
	if err := ValidateRecordSettings(ok); err != nil {
		t.Fatalf("valid cname profile refused: %v", err)
	}
	for _, typ := range []string{"", model.DDNSRecordAddress} {
		p := ok
		p.RecordType, p.CNAMETarget, p.Provider = typ, "not a host", model.DDNSProviderWebhook
		if err := ValidateRecordSettings(p); err != nil {
			t.Fatalf("an address profile's leftover target was checked: %v", err)
		}
	}
	cases := []struct {
		name string
		edit func(*model.DDNSProfile)
		want string
	}{
		{"webhook", func(p *model.DDNSProfile) { p.Provider = model.DDNSProviderWebhook }, "needs the cloudflare provider"},
		{"unknown type", func(p *model.DDNSProfile) { p.RecordType = "mx" }, "record_type must be address or cname"},
		{"empty", func(p *model.DDNSProfile) { p.CNAMETarget = " " }, "cname_target is required"},
		{"ipv4", func(p *model.DDNSProfile) { p.CNAMETarget = "40.160.254.9" }, "not an IP address"},
		{"ipv6", func(p *model.DDNSProfile) { p.CNAMETarget = "2001:db8::1" }, "not an IP address"},
		{"same name", func(p *model.DDNSProfile) { p.CNAMETarget = "Frontier.nat.aaitr.roobli.org." }, "a record cannot point into the names it publishes"},
		{"under own name", func(p *model.DDNSProfile) { p.CNAMETarget = "edge." + frontierName }, "a record cannot point into the names it publishes"},
		{"single label", func(p *model.DDNSProfile) { p.CNAMETarget = "localhost" }, "fully qualified"},
		{"empty label", func(p *model.DDNSProfile) { p.CNAMETarget = "a..aproxy.top" }, "empty label"},
		{"hyphen", func(p *model.DDNSProfile) { p.CNAMETarget = "-nat.aproxy.top" }, "starts or ends with a hyphen"},
		{"bad character", func(p *model.DDNSProfile) { p.CNAMETarget = "nat us.aproxy.top" }, "only letters, digits"},
		{"long label", func(p *model.DDNSProfile) { p.CNAMETarget = strings.Repeat("a", 64) + ".aproxy.top" }, "longer than 63"},
		{"long name", func(p *model.DDNSProfile) { p.CNAMETarget = strings.Repeat(strings.Repeat("a", 60)+".", 5) + "top" }, "at most 253"},
	}
	for _, c := range cases {
		p := ok
		c.edit(&p)
		p.CNAMETarget = NormalizeHost(p.CNAMETarget)
		err := ValidateRecordSettings(p)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: got %v, want an error mentioning %q", c.name, err, c.want)
		}
	}
	// A sibling of the profile's name is not under it.
	p := ok
	p.CNAMETarget = "other.nat.aaitr.roobli.org"
	if err := ValidateRecordSettings(p); err != nil {
		t.Fatalf("a sibling name was refused as a loop: %v", err)
	}
	if err := ValidateCommentTemplate("Lattice #node# via #target#"); err != nil {
		t.Fatalf("#target# refused in a custom template: %v", err)
	}
	if got := NormalizeHost(" NAT-us-28tz.aproxy.top. "); got != frontierTarget {
		t.Fatalf("NormalizeHost = %q", got)
	}
}

func TestCNAMEInSync(t *testing.T) {
	fake, cf := fakeCloudflare(t)
	profile := cnameProfile("")
	if in, err := CNAMEInSync(context.Background(), cf, profile); err != nil || in {
		t.Fatalf("no record: in=%v err=%v", in, err)
	}
	fake.Seed(cffake.Record{Type: "CNAME", Name: frontierName, Content: "elsewhere.aproxy.top"})
	if in, _ := CNAMEInSync(context.Background(), cf, profile); in {
		t.Fatal("a CNAME to another target counted as in sync")
	}
	profile.CNAMETarget = "elsewhere.aproxy.top"
	if in, err := CNAMEInSync(context.Background(), cf, profile); err != nil || !in {
		t.Fatalf("matching CNAME: in=%v err=%v", in, err)
	}
}
