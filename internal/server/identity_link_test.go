package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

const (
	idlOwnerUUID  = "5b2c7d1e-3f4a-4b5c-8d6e-7f8091a2b3c4"
	idlOwnerPass  = "Own3rP4ssw0rdSecretXy"
	idlAliceUUID  = "aaaaaaaa-1111-4aaa-8aaa-aaaaaaaaaaaa"
	idlAlicePass  = "al1cePassw0rdSecretAb"
	idlBobUUID    = "bbbbbbbb-2222-4bbb-8bbb-bbbbbbbbbbbb"
	idlAliceEmail = "alice-private@example.com"
)

// identityLinkFixture is one server with a node carrying two adopted lines
// (vless reality and trojan, each reporting its owner's credential in its
// share URL), their client templates synced, and two identities: alice on
// both lines and bob on the vless line, each with the applied credential the
// node would hold after their plan_add applied.
type identityLinkFixture struct {
	srv      *Server
	vless    Line
	trojan   Line
	admin    principal
	converts []string
}

func newIdentityLinkFixture(t *testing.T) *identityLinkFixture {
	t.Helper()
	srv := newLinemetaTestServer(t, mustOpenStore(t))
	if err := srv.store.UpsertNode(model.Node{ID: "node-a", Name: "Tokyo 1", PublicIP: "203.0.113.5"}); err != nil {
		t.Fatal(err)
	}
	srv.singboxInvMu.Lock()
	srv.singboxInv = map[string]model.SingBoxInventory{"node-a": {NodeID: "node-a", At: srv.now(), Status: "ok", Nodes: []model.SingBoxNode{
		{Name: "VLESS-REALITY-443.json", Protocol: "vless", Network: "tcp", Address: "203.0.113.5", Port: "443",
			ShareURL: "vless://" + idlOwnerUUID + "@203.0.113.5:443?encryption=none&security=reality&flow=xtls-rprx-vision&type=tcp&sni=www.example.com&pbk=Zm9vYmFyYmF6cXV4&fp=chrome#owner-reality"},
		{Name: "Trojan-8443.json", Protocol: "trojan", Network: "tcp", Address: "203.0.113.5", Port: "8443",
			ShareURL: "trojan://" + idlOwnerPass + "@203.0.113.5:8443?type=tcp&security=tls&sni=t.example.com#owner-trojan"},
	}}}
	srv.singboxInvMu.Unlock()
	srv.invalidateLineReadModel()
	if err := srv.syncLineClientTemplates(srv.now()); err != nil {
		t.Fatal(err)
	}
	f := &identityLinkFixture{srv: srv, admin: principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"vpncore:admin"}}}}
	groups, _ := srv.lineReadModel()
	f.vless = findLine(t, groups, "node-a", "VLESS-REALITY-443.json")
	f.trojan = findLine(t, groups, "node-a", "Trojan-8443.json")
	if _, ok := srv.store.LineClientTemplate(f.vless.LineHashID); !ok {
		t.Fatal("vless template not synced")
	}
	alice := VpnUser{ID: "vpnuser_alice", Email: idlAliceEmail, Enabled: true, Credentials: []VpnCredential{
		{Protocol: "vless", UUID: idlAliceUUID, Flow: "xtls-rprx-vision"}, {Protocol: "trojan", Password: idlAlicePass}}}
	alice.Bindings = []LineBinding{f.applied(t, alice, f.vless), f.applied(t, alice, f.trojan)}
	bob := VpnUser{ID: "vpnuser_bob", Email: "bob@example.com", Enabled: true, Credentials: []VpnCredential{
		{Protocol: "vless", UUID: idlBobUUID, Flow: "xtls-rprx-vision"}}}
	bob.Bindings = []LineBinding{f.applied(t, bob, f.vless)}
	for _, u := range []VpnUser{alice, bob} {
		if err := srv.putVpnUser(u); err != nil {
			t.Fatal(err)
		}
	}
	srv.identityLinkConvert = func(_ context.Context, entries []string, variant shareRenderVariant) (renderedSubscription, error) {
		f.converts = append(f.converts, strings.Join(entries, "\n"))
		return renderedSubscription{Body: []byte("proxies:\n# " + variant.Target + "\n" + strings.Join(entries, "\n")), Target: variant.Target}, nil
	}
	return f
}

// applied is the binding a plan_add that applied on the node leaves behind.
func (f *identityLinkFixture) applied(t *testing.T, u VpnUser, ln Line) LineBinding {
	t.Helper()
	payload, err := lineUserCredential(u, strings.ToLower(ln.Type), userLineName(u.ID, ln.LineUUID))
	if err != nil {
		t.Fatal(err)
	}
	sha, err := lineUserCredentialSHA(payload)
	if err != nil {
		t.Fatal(err)
	}
	return LineBinding{LineHashID: ln.LineHashID, Enabled: true, AppliedCredentialSHA256: sha}
}

func (f *identityLinkFixture) issue(t *testing.T, userID string) (string, string) {
	t.Helper()
	if _, err := f.srv.issueIdentityLink(f.admin, userID, identityLinkWriteRequest{}); err != nil {
		t.Fatal(err)
	}
	u, _ := f.srv.getVpnUser(userID)
	return u.Link.Slug, u.SubID
}

type idlResponse struct {
	status int
	body   string
	header http.Header
}

func (f *identityLinkFixture) fetch(t *testing.T, slug, token, query string, headers ...string) idlResponse {
	t.Helper()
	path := "/sub/" + slug + "/" + token
	if query != "" {
		path += "?" + query
	}
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	f.srv.handleSubscriptionShare(rec, req)
	raw, _ := io.ReadAll(rec.Result().Body)
	return idlResponse{status: rec.Code, body: string(raw), header: rec.Result().Header}
}

func decoyLike(t *testing.T, f *identityLinkFixture, r idlResponse) {
	t.Helper()
	decoy := f.fetch(t, "nope", strings.Repeat("Z", 43), "")
	if r.status != decoy.status || r.body != decoy.body {
		t.Fatalf("want the identical decoy (%d %q), got %d %q", decoy.status, decoy.body, r.status, r.body)
	}
}

// Leak table row 1 and row 14: two identities on one line each get only
// their own credential; neither body carries the line owner's credential,
// the other identity's, or anybody's email.
func TestIdentityLinksServeEachIdentityOnlyItsOwnCredential(t *testing.T) {
	f := newIdentityLinkFixture(t)
	aliceSlug, aliceToken := f.issue(t, "vpnuser_alice")
	bobSlug, bobToken := f.issue(t, "vpnuser_bob")

	alice := f.fetch(t, aliceSlug, aliceToken, "format=plain")
	if alice.status != http.StatusOK {
		t.Fatalf("alice: %d %s", alice.status, alice.body)
	}
	lines := strings.Split(strings.TrimSpace(alice.body), "\n")
	if len(lines) != 2 || !strings.Contains(alice.body, idlAliceUUID+"@203.0.113.5:443") || !strings.Contains(alice.body, "trojan://"+idlAlicePass+"@203.0.113.5:8443") {
		t.Fatalf("alice must get her two lines with her own credentials:\n%s", alice.body)
	}
	bob := f.fetch(t, bobSlug, bobToken, "format=plain")
	if bob.status != http.StatusOK || strings.Count(strings.TrimSpace(bob.body), "\n") != 0 || !strings.Contains(bob.body, idlBobUUID+"@") {
		t.Fatalf("bob must get his one line:\n%d %s", bob.status, bob.body)
	}
	for name, body := range map[string]string{"alice": alice.body, "bob": bob.body} {
		for _, foreign := range []string{idlOwnerUUID, idlOwnerPass, idlAliceEmail, "bob@example.com"} {
			if strings.Contains(body, foreign) {
				t.Fatalf("%s's body carries %q:\n%s", name, foreign, body)
			}
		}
	}
	if strings.Contains(alice.body, idlBobUUID) || strings.Contains(bob.body, idlAliceUUID) || strings.Contains(bob.body, idlAlicePass) {
		t.Fatal("one identity's body carries the other's credential")
	}
	// Entry names are node and line names.
	if !strings.Contains(alice.body, "#Tokyo%201%20VLESS-REALITY-443") {
		t.Fatalf("entry label should name node and line: %s", alice.body)
	}

	// The default answer is the base64 URI list, with the link headers.
	plainDefault := f.fetch(t, aliceSlug, aliceToken, "")
	decoded, err := base64.StdEncoding.DecodeString(plainDefault.body)
	if err != nil || string(decoded) != alice.body {
		t.Fatalf("the default answer must be the base64 of the URI list: %v", err)
	}
	if plainDefault.header.Get("Profile-Update-Interval") != "2" || plainDefault.header.Get("Cache-Control") != "no-store" ||
		plainDefault.header.Get("ETag") == "" || plainDefault.header.Get("Content-Disposition") == "" {
		t.Fatalf("link headers missing: %v", plainDefault.header)
	}
	// Leak table row 9: no request parameter selects another identity.
	other := f.fetch(t, aliceSlug, aliceToken, "format=plain&user_id=vpnuser_bob&identity=vpnuser_bob")
	if other.body != alice.body {
		t.Fatal("a request parameter changed whose lines a link serves")
	}
	// A conditional request with the served validator gets a 304.
	again := f.fetch(t, aliceSlug, aliceToken, "", "If-None-Match", plainDefault.header.Get("ETag"))
	if again.status != http.StatusNotModified {
		t.Fatalf("a matching validator must answer 304, got %d", again.status)
	}
}

// Leak table row 5: the quota header is this identity's own, per request.
func TestIdentityLinkUserinfoIsPerIdentityAndPerRequest(t *testing.T) {
	f := newIdentityLinkFixture(t)
	aliceSlug, aliceToken := f.issue(t, "vpnuser_alice")
	bobSlug, bobToken := f.issue(t, "vpnuser_bob")
	alice, _ := f.srv.getVpnUser("vpnuser_alice")
	alice.QuotaBytes = 10 << 30
	expiry := time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)
	alice.ExpiresAt = expiry
	if err := f.srv.putVpnUser(alice); err != nil {
		t.Fatal(err)
	}
	if err := f.srv.store.UpsertProxyUser(model.ProxyUser{ID: "vpnuser_alice", Name: "alice", UsedBytes: 3 << 30}); err != nil {
		t.Fatal(err)
	}
	a := f.fetch(t, aliceSlug, aliceToken, "")
	want := "upload=0; download=3221225472; total=10737418240; expire=1798848000"
	if got := a.header.Get("Subscription-Userinfo"); got != want {
		t.Fatalf("alice userinfo = %q, want %q", got, want)
	}
	b := f.fetch(t, bobSlug, bobToken, "")
	if got := b.header.Get("Subscription-Userinfo"); got != "upload=0; download=0; total=0; expire=0" {
		t.Fatalf("bob userinfo = %q", got)
	}
	if err := f.srv.store.UpsertProxyUser(model.ProxyUser{ID: "vpnuser_alice", Name: "alice", UsedBytes: 4 << 30}); err != nil {
		t.Fatal(err)
	}
	if got := f.fetch(t, aliceSlug, aliceToken, "").header.Get("Subscription-Userinfo"); !strings.Contains(got, "download=4294967296") {
		t.Fatalf("the quota header must move on the next request: %q", got)
	}
	if got := f.fetch(t, aliceSlug, aliceToken, "noFlow=1").header.Get("Subscription-Userinfo"); got != "" {
		t.Fatalf("noFlow must suppress the header: %q", got)
	}
}

// The answer table: placeholder for a suspended, expired, over-quota or
// disabled identity (with an exhausted quota header), a placeholder for an
// identity with no line yet, and the decoy when bound lines exist but none
// can be served now.
func TestIdentityLinkAnswersByIdentityState(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(t *testing.T, f *identityLinkFixture, u *VpnUser)
		message string
	}{
		{name: "disabled", mutate: func(_ *testing.T, _ *identityLinkFixture, u *VpnUser) { u.Enabled = false }, message: "Disabled by the operator"},
		{name: "operator suspension", mutate: func(_ *testing.T, f *identityLinkFixture, u *VpnUser) {
			u.Suspension = &VpnSuspension{Reason: vpnSuspendReasonOperator, By: "op", Since: f.srv.now()}
		}, message: "Suspended by the operator"},
		{name: "expired", mutate: func(_ *testing.T, f *identityLinkFixture, u *VpnUser) { u.ExpiresAt = f.srv.now().Add(-48 * time.Hour) }, message: "Expired on "},
		{name: "over quota", mutate: func(t *testing.T, f *identityLinkFixture, u *VpnUser) {
			u.QuotaBytes = 1 << 30
			if err := f.srv.store.UpsertProxyUser(model.ProxyUser{ID: u.ID, Name: "alice", UsedBytes: 2 << 30}); err != nil {
				t.Fatal(err)
			}
		}, message: "Quota used: 2.0 GiB of 1.0 GiB"},
		{name: "no lines yet", mutate: func(_ *testing.T, _ *identityLinkFixture, u *VpnUser) { u.Bindings = nil }, message: "No lines assigned yet"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newIdentityLinkFixture(t)
			slug, token := f.issue(t, "vpnuser_alice")
			u, _ := f.srv.getVpnUser("vpnuser_alice")
			tc.mutate(t, f, &u)
			if err := f.srv.putVpnUser(u); err != nil {
				t.Fatal(err)
			}
			r := f.fetch(t, slug, token, "format=plain")
			if r.status != http.StatusOK || strings.Count(strings.TrimSpace(r.body), "\n") != 0 {
				t.Fatalf("want a one-entry placeholder, got %d %s", r.status, r.body)
			}
			// Leak table row 10: the placeholder carries no real host and
			// no credential.
			if !strings.Contains(r.body, identityLinkPlaceholderUUID+"@"+identityLinkPlaceholderHost) ||
				strings.Contains(r.body, idlAliceUUID) || strings.Contains(r.body, idlAlicePass) || strings.Contains(r.body, "203.0.113.5") {
				t.Fatalf("placeholder body is wrong: %s", r.body)
			}
			name, err := url.PathUnescape(strings.TrimSpace(r.body[strings.Index(r.body, "#")+1:]))
			if err != nil || !strings.Contains(name, tc.message) {
				t.Fatalf("placeholder must name the reason %q: %q (%v)", tc.message, name, err)
			}
			if tc.name != "no lines yet" {
				info := userinfoFields(t, r.header.Get("Subscription-Userinfo"))
				if info["total"] == 0 || info["download"] < info["total"] {
					t.Fatalf("a suspended identity's header must read as used up: %v", info)
				}
			}
		})
	}

	t.Run("bound but nothing servable answers the decoy", func(t *testing.T) {
		f := newIdentityLinkFixture(t)
		slug, token := f.issue(t, "vpnuser_bob")
		bob, _ := f.srv.getVpnUser("vpnuser_bob")
		bob.Bindings[0].AppliedCredentialSHA256 = ""
		if err := f.srv.putVpnUser(bob); err != nil {
			t.Fatal(err)
		}
		decoyLike(t, f, f.fetch(t, slug, token, ""))
	})
}

// userinfoFields parses a Subscription-Userinfo value.
func userinfoFields(t *testing.T, info string) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for _, part := range strings.Split(info, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			t.Fatalf("userinfo %q: %v", info, err)
		}
		out[k] = n
	}
	return out
}

// Leak table row 3: a line whose node does not hold the identity's current
// credential is left out, with its reason, whether the binding was made
// without a plan or the credential was rotated since the plan applied.
func TestIdentityLinkLeavesOutLinesWithoutTheCurrentCredential(t *testing.T) {
	f := newIdentityLinkFixture(t)
	slug, token := f.issue(t, "vpnuser_alice")
	if _, err := f.srv.vpnUserRotateCredential(f.admin, mustJSON(t, map[string]string{"user_id": "vpnuser_alice", "protocol": "trojan"})); err != nil {
		t.Fatal(err)
	}
	u, _ := f.srv.getVpnUser("vpnuser_alice")
	r := f.fetch(t, slug, token, "format=plain")
	if r.status != http.StatusOK || strings.Contains(r.body, "trojan://") || !strings.Contains(r.body, idlAliceUUID) {
		t.Fatalf("a rotated, unapplied trojan credential must leave its line out: %s", r.body)
	}
	status := f.srv.identityLinkStatus(u)
	if len(status.Included) != 1 || len(status.Excluded) != 1 || status.Excluded[0].Reason != identityLineRotationPending || status.Excluded[0].Fix != identityFixPlanUpdate {
		t.Fatalf("status must name the rotation: %+v", status)
	}
	// A binding with no applied plan behind it (bind) is out too.
	u.Bindings[0].AppliedCredentialSHA256 = ""
	if err := f.srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	u, _ = f.srv.getVpnUser("vpnuser_alice")
	status = f.srv.identityLinkStatus(u)
	reasons := map[string]bool{}
	for _, line := range status.Excluded {
		reasons[line.Reason] = true
	}
	if !reasons[identityLineNotApplied] || status.Answer != identityAnswerDecoy || status.AnswerReason != identityReasonTransientEmpty {
		t.Fatalf("a bind-only line must be out and nothing left must answer the decoy: %+v", status)
	}
	// The fix it names is one the line-user path accepts for a bound
	// identity: plan_add refuses a bound user, plan_update files.
	for _, line := range status.Excluded {
		if line.Reason != identityLineNotApplied {
			continue
		}
		if line.Fix != identityFixPlanUpdate {
			t.Fatalf("a never-applied bound line must name plan_update, got %q", line.Fix)
		}
		request, _ := json.Marshal(map[string]string{"user_id": u.ID, "line_hash_id": line.LineHashID})
		if _, err := f.srv.vpnUserLinePlan(f.admin, request, lineUserOpAdd); err == nil || !strings.Contains(err.Error(), "plan_update instead") {
			t.Fatalf("plan_add must refuse a bound line: %v", err)
		}
		if _, err := f.srv.vpnUserLinePlan(f.admin, request, lineUserOpUpdate); err != nil {
			t.Fatalf("the named fix must file: %v", err)
		}
	}
}

// A line whose service is down, on which the identity is parked, whose
// template dropped a parameter, or that the central proxy model manages is
// left out of the identity's link, each with its reason and fix, and the
// other line still serves.
func TestIdentityLinkLeavesOutLinesByServiceParkingTemplateAndManagement(t *testing.T) {
	excluded := func(t *testing.T, f *identityLinkFixture) map[string]identityLinkLine {
		t.Helper()
		u, _ := f.srv.getVpnUser("vpnuser_alice")
		content := f.srv.identityLinkContent(u)
		out := map[string]identityLinkLine{}
		for _, line := range content.Excluded {
			out[line.LineHashID] = line
		}
		if len(content.Entries) == 0 {
			t.Fatalf("no line left in alice's link: %+v", content.Excluded)
		}
		return out
	}
	t.Run("service down", func(t *testing.T) {
		f := newIdentityLinkFixture(t)
		if _, _, err := f.srv.store.UpsertSingBoxLiveness(store.SingBoxLiveness{NodeID: "node-a", State: serviceStateRunning, ReceivedAt: f.srv.now()}); err != nil {
			t.Fatal(err)
		}
		unbound := false
		editSingBoxLine(t, f.srv, "node-a", "VLESS-REALITY-443.json", func(n *model.SingBoxNode) { n.PortBound = &unbound })
		got := excluded(t, f)
		if line := got[f.vless.LineHashID]; len(got) != 1 || line.Reason != identityLineServiceDown || line.Fix != identityFixCheckService {
			t.Fatalf("exclusions %+v", got)
		}
	})
	t.Run("parked", func(t *testing.T) {
		f := newIdentityLinkFixture(t)
		editSingBoxLine(t, f.srv, "node-a", "VLESS-REALITY-443.json", func(n *model.SingBoxNode) {
			n.Metadata = map[string]string{singBoxParkedUsersKey: "1", singBoxParkedNamesKey: `["` + userLineName("vpnuser_alice", f.vless.LineUUID) + `"]`}
		})
		got := excluded(t, f)
		if line := got[f.vless.LineHashID]; len(got) != 1 || line.Reason != identityLineParked || line.Fix != identityFixResume {
			t.Fatalf("exclusions %+v", got)
		}
	})
	t.Run("lossy template", func(t *testing.T) {
		f := newIdentityLinkFixture(t)
		editSingBoxLine(t, f.srv, "node-a", "Trojan-8443.json", func(n *model.SingBoxNode) {
			n.ShareURL = strings.Replace(n.ShareURL, "#owner", "&obfs-password=x#owner", 1)
		})
		// A changed template is taken on the second sync that sees it.
		for i := 0; i < 2; i++ {
			if err := f.srv.syncLineClientTemplates(f.srv.now()); err != nil {
				t.Fatal(err)
			}
		}
		got := excluded(t, f)
		if line := got[f.trojan.LineHashID]; len(got) != 1 || line.Reason != identityLineTemplateLossy || line.Detail != "obfs-password" {
			t.Fatalf("exclusions %+v", got)
		}
	})
	t.Run("managed", func(t *testing.T) {
		f := newIdentityLinkFixture(t)
		if err := f.srv.store.UpsertProxyInbound(model.ProxyInbound{ID: "in-managed", Name: "managed", Core: model.ProxyCoreSingbox, Protocol: "vless", Port: 9443, Enabled: true}); err != nil {
			t.Fatal(err)
		}
		if err := f.srv.store.UpsertProxyNodeProfile(model.ProxyNodeProfile{NodeID: "node-a", Core: model.ProxyCoreSingbox, InboundIDs: []string{"in-managed"}}); err != nil {
			t.Fatal(err)
		}
		f.srv.invalidateLineReadModel()
		groups, _ := f.srv.lineReadModel()
		managed := findLine(t, groups, "node-a", "in-managed")
		if !managed.Managed {
			t.Fatalf("line %+v is not managed", managed)
		}
		u, _ := f.srv.getVpnUser("vpnuser_alice")
		u.Bindings = append(u.Bindings, LineBinding{LineHashID: managed.LineHashID, Enabled: true})
		if err := f.srv.putVpnUser(u); err != nil {
			t.Fatal(err)
		}
		got := excluded(t, f)
		if line := got[managed.LineHashID]; len(got) != 1 || line.Reason != identityLineManaged {
			t.Fatalf("exclusions %+v", got)
		}
	})
}

// Leak table rows 7 and 8, and rotation: a rotated or revoked token, and a
// deleted identity's token, answer the identical decoy at once.
func TestIdentityLinkRotationRevocationAndDeleteRevokeAtOnce(t *testing.T) {
	f := newIdentityLinkFixture(t)
	slug, oldToken := f.issue(t, "vpnuser_alice")
	if r := f.fetch(t, slug, oldToken, ""); r.status != http.StatusOK {
		t.Fatalf("fresh link: %d", r.status)
	}
	if _, err := f.srv.rotateIdentityLink(f.admin, "vpnuser_alice"); err != nil {
		t.Fatal(err)
	}
	decoyLike(t, f, f.fetch(t, slug, oldToken, ""))
	u, _ := f.srv.getVpnUser("vpnuser_alice")
	newToken := u.SubID
	if newToken == oldToken || f.fetch(t, slug, newToken, "").status != http.StatusOK {
		t.Fatal("the rotated link must serve its new token")
	}
	// A converted body cached under the old token's link does not outlive it.
	if f.fetch(t, slug, newToken, "target=ClashMeta").status != http.StatusOK || f.srv.identityLinkCache.Len() == 0 {
		t.Fatal("convert should have cached a body")
	}
	if _, err := f.srv.revokeIdentityLink(f.admin, "vpnuser_alice"); err != nil {
		t.Fatal(err)
	}
	decoyLike(t, f, f.fetch(t, slug, newToken, ""))
	if f.srv.identityLinkCache.Len() != 0 {
		t.Fatal("revocation must drop the link's cached bodies")
	}
	// An identity write that read before the rotation cannot put the old
	// token back.
	slugB, tokenB := f.issue(t, "vpnuser_bob")
	stale, _ := f.srv.getVpnUser("vpnuser_bob")
	if _, err := f.srv.rotateIdentityLink(f.admin, "vpnuser_bob"); err != nil {
		t.Fatal(err)
	}
	stale.Comment = "edited from a stale read"
	if err := f.srv.putVpnUser(stale); err != nil {
		t.Fatal(err)
	}
	decoyLike(t, f, f.fetch(t, slugB, tokenB, ""))
	// Delete: the record and its token go in one write.
	bob, _ := f.srv.getVpnUser("vpnuser_bob")
	if f.fetch(t, slugB, bob.SubID, "").status != http.StatusOK {
		t.Fatal("bob's rotated link should serve before the delete")
	}
	if _, err := f.srv.vpnCoreUsersAdminDispatch(context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, f.admin), "delete", []byte(`{"id":"vpnuser_bob"}`)); err != nil {
		// The delete refuses while the identity is still on an adopted line;
		// unbind first the way an operator would.
		bob.Bindings = nil
		if err := f.srv.putVpnUser(bob); err != nil {
			t.Fatal(err)
		}
		if err := f.srv.deleteVpnUser("vpnuser_bob"); err != nil {
			t.Fatal(err)
		}
	}
	decoyLike(t, f, f.fetch(t, slugB, bob.SubID, ""))
}

// Leak table row 7: a token that a share and an identity link both held
// would answer neither, and a disabled or expired link answers the decoy.
func TestIdentityLinkTokensFollowTheOneMatchRule(t *testing.T) {
	f := newIdentityLinkFixture(t)
	slug, token := f.issue(t, "vpnuser_alice")
	if err := f.srv.store.UpsertSubscriptionShare(model.SubscriptionShare{ID: "share-dup", Slug: "dup", Token: token, Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: subStorePluginID, SubscriptionID: "x"}}); err != nil {
		t.Fatal(err)
	}
	decoyLike(t, f, f.fetch(t, slug, token, ""))
	if err := f.srv.store.DeleteSubscriptionShare("share-dup"); err != nil {
		t.Fatal(err)
	}
	if f.fetch(t, slug, token, "").status != http.StatusOK {
		t.Fatal("the link must serve again once its token is unique")
	}
	decoyLike(t, f, f.fetch(t, "u-wrongslug", token, ""))
	enabled := false
	if _, err := f.srv.updateIdentityLink(f.admin, "vpnuser_alice", identityLinkWriteRequest{Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	decoyLike(t, f, f.fetch(t, slug, token, ""))
}

// Leak table rows 4 and 6: a converted document is keyed by the identity and
// its own content, and the converter is handed one identity's entries only.
func TestIdentityLinkConvertedDocumentsStayPerIdentity(t *testing.T) {
	f := newIdentityLinkFixture(t)
	aliceSlug, aliceToken := f.issue(t, "vpnuser_alice")
	bobSlug, bobToken := f.issue(t, "vpnuser_bob")
	a := f.fetch(t, aliceSlug, aliceToken, "", "User-Agent", "clash-verge/v2.2.3")
	b := f.fetch(t, bobSlug, bobToken, "", "User-Agent", "clash-verge/v2.2.3")
	if a.status != http.StatusOK || b.status != http.StatusOK || !strings.Contains(a.body, "# ClashMeta") {
		t.Fatalf("mihomo clients get the converted ClashMeta document: %d %s / %d", a.status, a.body, b.status)
	}
	if a.header.Get("Content-Type") != "text/yaml; charset=utf-8" {
		t.Fatalf("content type = %q", a.header.Get("Content-Type"))
	}
	if strings.Contains(a.body, idlBobUUID) || strings.Contains(b.body, idlAliceUUID) {
		t.Fatal("a converted document carries another identity's credential")
	}
	for _, call := range f.converts {
		if strings.Contains(call, idlAliceUUID) && strings.Contains(call, idlBobUUID) {
			t.Fatal("one convert call was handed two identities' entries")
		}
	}
	calls := len(f.converts)
	f.fetch(t, aliceSlug, aliceToken, "", "User-Agent", "clash-verge/v2.2.3")
	if len(f.converts) != calls {
		t.Fatal("an unchanged identity must be served from cache")
	}
	// A suspension changes the content, so the cached body is unreachable.
	u, _ := f.srv.getVpnUser("vpnuser_alice")
	u.Enabled = false
	if err := f.srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	after := f.fetch(t, aliceSlug, aliceToken, "", "User-Agent", "clash-verge/v2.2.3")
	if strings.Contains(after.body, idlAliceUUID) || !strings.Contains(after.body, identityLinkPlaceholderUUID) {
		t.Fatalf("a suspended identity must never get its cached nodes: %s", after.body)
	}

	// Without a converter the base64 URI list is served, and says so.
	f.srv.identityLinkConvert = nil
	fallback := f.fetch(t, bobSlug, bobToken, "target=ClashMeta")
	if fallback.status != http.StatusOK || fallback.header.Get("X-Lattice-Subscription-Fallback") == "" || fallback.header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("fallback must be labelled: %d %v", fallback.status, fallback.header)
	}
	if decoded, err := base64.StdEncoding.DecodeString(fallback.body); err != nil || !strings.Contains(string(decoded), idlBobUUID) {
		t.Fatalf("fallback must be the base64 URI list: %v", err)
	}
}

// A request made after the identity changed never joins a convert started
// for its older entries: a suspension while a slow convert of the real nodes
// is running answers the placeholder at once, and the request made before
// the suspension still gets the body it asked for.
func TestIdentityLinkConvertNeverHandsAFlightToANewerVersion(t *testing.T) {
	f := newIdentityLinkFixture(t)
	slug, token := f.issue(t, "vpnuser_alice")
	started, release := make(chan struct{}), make(chan struct{})
	var startOnce, releaseOnce sync.Once
	releaseConvert := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseConvert()
	f.srv.identityLinkConvert = func(ctx context.Context, entries []string, variant shareRenderVariant) (renderedSubscription, error) {
		joined := strings.Join(entries, "\n")
		if strings.Contains(joined, idlAliceUUID) {
			startOnce.Do(func() { close(started) })
			select {
			case <-release:
			case <-ctx.Done():
				return renderedSubscription{}, ctx.Err()
			}
		}
		return renderedSubscription{Body: []byte("proxies:\n# " + variant.Target + "\n" + joined), Target: variant.Target}, nil
	}
	type answer struct {
		status int
		body   string
	}
	fetch := func(out chan<- answer) {
		req := httptest.NewRequest(http.MethodGet, "/sub/"+slug+"/"+token, nil)
		req.Header.Set("User-Agent", "clash-verge/v2.2.3")
		rec := httptest.NewRecorder()
		f.srv.handleSubscriptionShare(rec, req)
		out <- answer{status: rec.Code, body: rec.Body.String()}
	}

	before := make(chan answer, 1)
	go fetch(before)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the convert of the real nodes never started")
	}
	u, _ := f.srv.getVpnUser("vpnuser_alice")
	u.Enabled = false
	if err := f.srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	after := make(chan answer, 1)
	go fetch(after)
	select {
	case got := <-after:
		if got.status != http.StatusOK || strings.Contains(got.body, idlAliceUUID) || !strings.Contains(got.body, identityLinkPlaceholderUUID) {
			t.Fatalf("a suspended identity must get the placeholder, got %d %s", got.status, got.body)
		}
	case <-time.After(5 * time.Second):
		releaseConvert()
		<-before
		got := <-after
		t.Fatalf("the request after the suspension waited on the convert of the real nodes and got %d %s", got.status, got.body)
	}
	releaseConvert()
	if got := <-before; got.status != http.StatusOK || !strings.Contains(got.body, idlAliceUUID) {
		t.Fatalf("the request made before the suspension gets its own body: %d %s", got.status, got.body)
	}
}

// Leak table rows 11, 12 and 13: the token never reaches the audit trail or
// a status read, managing a link needs vpncore:admin in core whatever the
// manifest says, and the token itself comes only through the reveal gate.
func TestIdentityLinkOperatorSurfaceKeepsTheTokenBehindTheGate(t *testing.T) {
	h := newRevealHarness(t)
	now := h.srv.now()
	if err := h.srv.putVpnUser(VpnUser{ID: "vpnuser_alice", Email: idlAliceEmail, Enabled: true,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: idlAliceUUID}}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	res := doJSON(t, h.handler, http.MethodPost, "/api/vpn/users/vpnuser_alice/link", `{}`, h.cookies, h.csrf)
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("issue: %d %s", res.StatusCode, raw)
	}
	u, _ := h.srv.getVpnUser("vpnuser_alice")
	if u.Link == nil || u.SubID == "" || strings.Contains(string(raw), u.SubID) {
		t.Fatalf("issue must store a link and not answer with its token: %s", raw)
	}
	var status identityLinkStatusView
	if err := json.Unmarshal(raw, &status); err != nil || !status.Issued || status.Answer != identityAnswerPlaceholder || status.AnswerReason != identityReasonNoLines {
		t.Fatalf("status after issue: %+v %v", status, err)
	}
	res = doJSON(t, h.handler, http.MethodPost, "/api/vpn/users/vpnuser_alice/link", `{}`, h.cookies, h.csrf)
	if res.StatusCode != http.StatusConflict || apiErrorCodeOf(t, idlReadAll(res)) != apiErrorLinkAlreadyIssued {
		t.Fatalf("a second issue must be refused with %s", apiErrorLinkAlreadyIssued)
	}
	for _, path := range []string{"/api/vpn/users/vpnuser_alice/link"} {
		res := doJSON(t, h.handler, http.MethodGet, path, "", h.cookies, h.csrf)
		body := idlReadAll(res)
		if res.StatusCode != http.StatusOK || strings.Contains(string(body), u.SubID) {
			t.Fatalf("GET %s: %d, or the token leaked: %s", path, res.StatusCode, body)
		}
	}
	checkRevealDoor(t, h, revealDoor{name: "identity link", method: http.MethodPost, path: "/api/vpn/users/vpnuser_alice/link/reveal",
		body: `{}`, scopes: []string{"vpncore:admin"}, secret: u.SubID, action: auditActionIdentityLinkReveal, objectKey: "identity_id"})

	// A read scope cannot see or manage the link.
	_, reader := h.token([]string{"vpncore:read"}, false)
	res = doBearerJSON(t, h.handler, http.MethodGet, "/api/vpn/users/vpnuser_alice/link", "", reader)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a read token must not read link status: %d", res.StatusCode)
	}
	res.Body.Close()
	// The RPC door re-checks vpncore:admin in core: a principal the gateway
	// let through on a misdeclared scope still gets nothing.
	limited := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, principal{Principal: rbac.Principal{ActorID: "op2", Scopes: []string{"substore:admin"}}})
	for _, method := range []string{"link_get", "link_reveal", "link_rotate", "link_issue", "link_set", "link_revoke"} {
		if _, err := h.srv.vpnCoreUsersAdminDispatch(limited, method, []byte(`{"user_id":"vpnuser_alice"}`)); err == nil || !strings.Contains(err.Error(), "HTTP 403") {
			t.Fatalf("%s without vpncore:admin must be refused with 403, got %v", method, err)
		}
	}
	// Rotation through the RPC door audits both hashes and neither token.
	admin := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"vpncore:admin"}}})
	if _, err := h.srv.vpnCoreUsersAdminDispatch(admin, "link_rotate", []byte(`{"user_id":"vpnuser_alice"}`)); err != nil {
		t.Fatal(err)
	}
	rotated, _ := h.srv.getVpnUser("vpnuser_alice")
	for _, ev := range h.srv.store.AuditEvents() {
		for _, v := range ev.Metadata {
			if strings.Contains(v, u.SubID) || strings.Contains(v, rotated.SubID) {
				t.Fatalf("the audit trail holds a link token: %+v", ev)
			}
		}
	}
	// The projected publishing row exists while the link does and carries
	// no token.
	res = doJSON(t, h.handler, http.MethodGet, "/api/publishing/records", "", h.cookies, h.csrf)
	body := idlReadAll(res)
	if !strings.Contains(string(body), `"identity_id":"vpnuser_alice"`) || strings.Contains(string(body), rotated.SubID) {
		t.Fatalf("publishing must list the identity link without its token: %s", body)
	}
}

func idlReadAll(res *http.Response) []byte {
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	return raw
}

// Renaming a link moves its URL and refuses a slug another link holds; the
// slug check runs outside the store lock, so this also proves a rename does
// not deadlock on it.
func TestIdentityLinkRenameMovesTheURLAndRefusesATakenSlug(t *testing.T) {
	f := newIdentityLinkFixture(t)
	oldSlug, token := f.issue(t, "vpnuser_alice")
	bobSlug, _ := f.issue(t, "vpnuser_bob")
	taken := bobSlug
	if _, err := f.srv.updateIdentityLink(f.admin, "vpnuser_alice", identityLinkWriteRequest{Slug: &taken}); err == nil || !strings.Contains(err.Error(), "already uses this slug") {
		t.Fatalf("a slug another link holds must be refused, got %v", err)
	}
	renamed := "alice-phone"
	interval := 6
	if _, err := f.srv.updateIdentityLink(f.admin, "vpnuser_alice", identityLinkWriteRequest{Slug: &renamed, UpdateIntervalHours: &interval}); err != nil {
		t.Fatal(err)
	}
	decoyLike(t, f, f.fetch(t, oldSlug, token, ""))
	r := f.fetch(t, renamed, token, "")
	if r.status != http.StatusOK || r.header.Get("Profile-Update-Interval") != "6" {
		t.Fatalf("the renamed link must serve with its own refresh period: %d %v", r.status, r.header)
	}
}
