package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// subStoreSvcLog is a logger sink that background renders may write to
// while a test reads it.
type subStoreSvcLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *subStoreSvcLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *subStoreSvcLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

type subStoreSvcHarness struct {
	srv *Server
	st  *store.Store
	log *subStoreSvcLog
	// body is what the Sub-Store record renders to.
	body string
}

// subStoreSvcAdmin is an operator with the scopes the services ask for.
var subStoreSvcAdmin = principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"proxy:admin", "substore:admin", "network:plan", "network:apply"}}}

func newSubStoreSvcHarness(t *testing.T) *subStoreSvcHarness {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	sink := &subStoreSvcLog{}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, PublicURL: "https://lattice.example/",
		DisableRenewalScheduler: true, Logger: log.New(sink, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	h := &subStoreSvcHarness{srv: srv, st: st, log: sink, body: "vless://PLAINTEXT-MARKER@node.example:443#one\n"}
	// The registry serves a core service only while its owning plugin is
	// active; no plugin is installed here, so stand in for the lifecycle.
	srv.pluginRPC.SetOwnerActive(func(string) bool { return true })
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	srv.now = func() time.Time { return now }
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{
		PluginID: subStorePluginID, SubscriptionID: "rec", Raw: "nodes", FetchedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	srv.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		return model.SubscriptionSnapshot{Raw: "nodes", FetchedAt: now}, nil
	}
	srv.subscriptionRender = func(_ context.Context, share model.SubscriptionShare, _, _ string,
		_ shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		epoch, _ := srv.subscriptionSnapshotEpoch(share.Source.PluginID, share.Source.SubscriptionID, snap)
		return renderedSubscription{Body: []byte(h.body), ContentType: "text/plain; charset=utf-8",
			SourceEpoch: epoch, FetchedAt: snap.FetchedAt, RevalidationVersion: subscriptionRevalidationVersion(snap)}, nil
	}
	return h
}

// call reaches a service the way the plugin gateway does: the operator's
// principal on the context, and the call marked as the operator's own.
func (h *subStoreSvcHarness) call(p principal, service, method, body string) ([]byte, error) {
	ctx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, p)
	return h.srv.callCoreServiceForOperator(ctx, service, method, []byte(body))
}

func (h *subStoreSvcHarness) mustCall(t *testing.T, service, method, body string) []byte {
	t.Helper()
	out, err := h.call(subStoreSvcAdmin, service, method, body)
	if err != nil {
		t.Fatalf("%s %s: %v %s", service, method, err, subStoreSvcErrBody(err))
	}
	return out
}

func (h *subStoreSvcHarness) createShare(t *testing.T, body string) subStoreShareRow {
	t.Helper()
	var reply subStoreSvcShareReply
	if err := json.Unmarshal(h.mustCall(t, subStoreSharesService, "create", body), &reply); err != nil {
		t.Fatal(err)
	}
	return reply.Share
}

func (h *subStoreSvcHarness) fetch(path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.srv.handleSubscriptionShare(rec, shareRequest(path, "curl/8"))
	return rec
}

func subStoreSvcErrStatus(err error) int {
	var opErr *pluginOperationError
	if errors.As(err, &opErr) {
		return opErr.StatusCode
	}
	return 0
}

func subStoreSvcErrBody(err error) string {
	var opErr *pluginOperationError
	if errors.As(err, &opErr) {
		return string(opErr.Body)
	}
	return ""
}

// auditFor returns the audit events of one action for one share.
func (h *subStoreSvcHarness) auditFor(action, shareID string) []model.AuditEvent {
	var out []model.AuditEvent
	for _, ev := range h.st.AuditEvents() {
		if ev.Action == action && ev.Metadata["share_id"] == shareID {
			out = append(out, ev)
		}
	}
	return out
}

// Create, update, archive, restore, archive again and purge, each through the
// service, each audited once, with the share's operator fields kept and no
// token, path or URL in any reply.
func TestSubStoreSharesLifecycleRoundTrip(t *testing.T) {
	h := newSubStoreSvcHarness(t)
	if err := h.srv.putVpnUser(VpnUser{ID: "vpnuser_alice", Email: "alice@example.com", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	var replies []string
	call := func(method, body string) []byte {
		out := h.mustCall(t, subStoreSharesService, method, body)
		replies = append(replies, string(out))
		return out
	}
	var created subStoreSvcShareReply
	if err := json.Unmarshal(call("create", `{"subscription_id":"rec","slug":"alice-phone","display_name":"Alice phone",
		"remark":"line one\nline two","icon":{"url":"https://icons.example.com/a.png","color":"#3b82f6","fit":"cover"},
		"tags":["family","mobile"],"default_format":"plain","update_interval_hours":6,"identity_id":"vpnuser_alice"}`), &created); err != nil {
		t.Fatal(err)
	}
	row := created.Share
	if row.ShareID == "" || row.Slug != "alice-phone" || row.DisplayName != "Alice phone" || row.Remark != "line one\nline two" ||
		row.Icon == nil || row.Icon.Fit != "cover" || len(row.Tags) != 2 || row.IdentityID != "vpnuser_alice" ||
		row.UpdateIntervalHours != 6 || !row.Enabled || row.SubscriptionID != "rec" || row.ArchivedAt != nil {
		t.Fatalf("created row = %+v", row)
	}
	stored, ok := h.st.SubscriptionShare(row.ShareID)
	if !ok || stored.Token == "" || stored.Source.PluginID != subStorePluginID || stored.Source.Kind != model.ShareSourcePlugin {
		t.Fatalf("stored share = %+v", stored)
	}
	token := stored.Token
	if len(h.auditFor(auditActionShareCreate, row.ShareID)) != 1 {
		t.Fatal("create was not audited once")
	}

	var updated subStoreSvcShareReply
	if err := json.Unmarshal(call("update", `{"share_id":"`+row.ShareID+`","display_name":"Alice tablet","tags":["family"],
		"order":7,"clear_icon":true,"identity_id":"vpnuser_alice"}`), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Share.DisplayName != "Alice tablet" || len(updated.Share.Tags) != 1 || updated.Share.Order != 7 || updated.Share.Icon != nil ||
		updated.Share.Remark != "line one\nline two" {
		t.Fatalf("updated row = %+v", updated.Share)
	}
	if evs := h.auditFor(auditActionShareUpdate, row.ShareID); len(evs) != 1 || evs[0].Metadata["fields"] != "display_name,icon,tags,order" {
		t.Fatalf("update audit = %+v", evs)
	}

	var archived subStoreSvcShareReply
	if err := json.Unmarshal(call("archive", `{"share_id":"`+row.ShareID+`"}`), &archived); err != nil {
		t.Fatal(err)
	}
	if archived.Share.ArchivedAt == nil {
		t.Fatal("archive did not stamp archived_at")
	}
	// Archiving twice changes nothing and records nothing.
	call("archive", `{"share_id":"`+row.ShareID+`"}`)
	if len(h.auditFor(auditActionShareArchive, row.ShareID)) != 1 {
		t.Fatal("archive was not audited exactly once")
	}
	listed := func(includeArchived bool) []subStoreShareRow {
		body := `{}`
		if includeArchived {
			body = `{"include_archived":true}`
		}
		var result struct {
			Shares []subStoreShareRow `json:"shares"`
		}
		if err := json.Unmarshal(call("list", body), &result); err != nil {
			t.Fatal(err)
		}
		return result.Shares
	}
	if rows := listed(false); len(rows) != 0 {
		t.Fatalf("an archived share is listed as live: %+v", rows)
	}
	if rows := listed(true); len(rows) != 1 || rows[0].ArchivedAt == nil || rows[0].DisplayName != "Alice tablet" {
		t.Fatalf("include_archived list = %+v", rows)
	}

	var restored subStoreSvcShareReply
	if err := json.Unmarshal(call("restore", `{"share_id":"`+row.ShareID+`"}`), &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Share.ArchivedAt != nil {
		t.Fatal("restore left archived_at set")
	}
	if after, _ := h.st.SubscriptionShare(row.ShareID); after.Token != token {
		t.Fatal("restore changed the token; the holders' link must work again")
	}
	if len(h.auditFor(auditActionShareRestore, row.ShareID)) != 1 {
		t.Fatal("restore was not audited")
	}

	call("archive", `{"share_id":"`+row.ShareID+`"}`)
	call("purge", `{"share_id":"`+row.ShareID+`"}`)
	if _, ok := h.st.SubscriptionShare(row.ShareID); ok {
		t.Fatal("purge left the share")
	}
	if len(h.auditFor(auditActionSharePurge, row.ShareID)) != 1 {
		t.Fatal("purge was not audited")
	}

	for _, reply := range replies {
		if strings.Contains(reply, token) || strings.Contains(reply, "/sub/") || strings.Contains(reply, "lattice.example") || strings.Contains(reply, `"revealed"`) {
			t.Fatalf("a reply outside the reveal gate carries the link: %s", reply)
		}
	}
	for _, ev := range h.st.AuditEvents() {
		for _, v := range ev.Metadata {
			if strings.Contains(v, token) {
				t.Fatalf("the audit trail holds the token: %+v", ev)
			}
		}
	}
}

// Every method is refused without an operator, without proxy:admin, to a
// node-restricted operator, and to a call that did not come straight from
// the gateway; and each state-dependent refusal names its conflict.
func TestSubStoreSharesRefusals(t *testing.T) {
	h := newSubStoreSvcHarness(t)
	row := h.createShare(t, `{"subscription_id":"rec","slug":"team"}`)
	shareBody := `{"share_id":"` + row.ShareID + `"}`

	limited := principal{Principal: rbac.Principal{ActorID: "op2", Scopes: []string{"substore:admin"}}}
	confined := principal{Principal: rbac.Principal{ActorID: "op3", Scopes: []string{"proxy:admin"}, ServerAllowlist: []string{"node-1"}}}
	for _, method := range []string{"create", "update", "rotate", "set_enabled", "archive", "restore", "purge", "reorder"} {
		for name, p := range map[string]principal{"substore:admin only": limited, "node-restricted": confined} {
			if _, err := h.call(p, subStoreSharesService, method, shareBody); subStoreSvcErrStatus(err) != http.StatusForbidden {
				t.Fatalf("%s %s: want 403, got %v", name, method, err)
			}
		}
		if _, err := h.srv.callCoreServiceForOperator(context.Background(), subStoreSharesService, method, []byte(shareBody)); subStoreSvcErrStatus(err) != http.StatusForbidden {
			t.Fatalf("%s without an operator principal: want 403, got %v", method, err)
		}
		// A plugin method that reaches the service through rpc.call while it
		// serves the operator carries the principal but not the gateway mark.
		ctx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, subStoreSvcAdmin)
		if _, err := h.srv.subStoreSharesRPC(ctx, method, []byte(shareBody)); subStoreSvcErrStatus(err) != http.StatusForbidden {
			t.Fatalf("%s through rpc.call: want 403, got %v", method, err)
		}
	}
	if len(h.auditFor(auditActionShareRotate, row.ShareID))+len(h.auditFor(auditActionShareArchive, row.ShareID)) != 0 {
		t.Fatal("a refused call changed a share")
	}

	refused := func(method, body string, status int, contains string) {
		t.Helper()
		_, err := h.call(subStoreSvcAdmin, subStoreSharesService, method, body)
		if subStoreSvcErrStatus(err) != status || !strings.Contains(subStoreSvcErrBody(err), contains) {
			t.Fatalf("%s %s: want %d mentioning %q, got %v %s", method, body, status, contains, err, subStoreSvcErrBody(err))
		}
	}
	refused("purge", shareBody, http.StatusConflict, "archive share")
	refused("restore", shareBody, http.StatusConflict, "not archived")
	refused("create", `{"subscription_id":"rec","slug":"team"}`, http.StatusConflict, "slug already exists")
	refused("create", `{"subscription_id":"rec","slug":"Bad Slug"}`, http.StatusBadRequest, "slug")
	refused("create", `{"slug":"no-record"}`, http.StatusBadRequest, "subscription_id")
	refused("create", `{"subscription_id":"rec","slug":"ghost","identity_id":"vpnuser_nobody"}`, http.StatusBadRequest, "identity")
	refused("create", `{"subscription_id":"rec","slug":"tags","tags":["a","a"]}`, http.StatusBadRequest, "twice")
	refused("create", `{"subscription_id":"rec","slug":"icon","icon":{"url":"http://insecure.example/a.png"}}`, http.StatusBadRequest, "icon")
	refused("create", `{"subscription_id":"rec","slug":"past","expires_at":"2020-01-01T00:00:00Z"}`, http.StatusBadRequest, "future")
	refused("create", `{"subscription_id":"rec","slug":"extra","token":"chosen"}`, http.StatusBadRequest, "unknown field")
	refused("update", `{"share_id":"`+row.ShareID+`","identity_id":"vpnuser_bob"}`, http.StatusConflict, "identity is fixed")
	refused("update", `{"share_id":"`+row.ShareID+`"}`, http.StatusBadRequest, "no field")
	refused("update", `{"share_id":"`+row.ShareID+`","display_name":"bad\u0007name"}`, http.StatusBadRequest, "display_name")
	refused("update", `{"share_id":"missing"}`, http.StatusNotFound, "not found")
	refused("set_enabled", shareBody, http.StatusBadRequest, "enabled is required")

	// A share of another source is not this service's to touch.
	mustUpsertShare(t, h.st, model.SubscriptionShare{ID: "sh-core", Slug: "core", Token: strings.Repeat("d", 43), Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourceCoreProxyUser, ProxyUserID: "pu-1"}})
	refused("archive", `{"share_id":"sh-core"}`, http.StatusNotFound, "not found")

	h.mustCall(t, subStoreSharesService, "archive", shareBody)
	refused("update", `{"share_id":"`+row.ShareID+`","display_name":"x"}`, http.StatusConflict, "archived")
	refused("rotate", shareBody, http.StatusConflict, "archived")
	refused("set_enabled", `{"share_id":"`+row.ShareID+`","enabled":false}`, http.StatusConflict, "archived")
}

// Rotation mints a new token; the old one then gets the decoy, byte for byte
// what an unknown token gets, and the new one serves.
func TestSubStoreShareRotateOldTokenGetsDecoy(t *testing.T) {
	h := newSubStoreSvcHarness(t)
	row := h.createShare(t, `{"subscription_id":"rec","slug":"team"}`)
	before, _ := h.st.SubscriptionShare(row.ShareID)
	if res := h.fetch("/sub/team/" + before.Token); res.Code != http.StatusOK || res.Body.String() != h.body {
		t.Fatalf("before rotation: %d %q", res.Code, res.Body.String())
	}

	var rotated subStoreSvcShareReply
	if err := json.Unmarshal(h.mustCall(t, subStoreSharesService, "rotate", `{"share_id":"`+row.ShareID+`"}`), &rotated); err != nil {
		t.Fatal(err)
	}
	after, _ := h.st.SubscriptionShare(row.ShareID)
	if after.Token == before.Token || rotated.Share.RotatedAt == nil {
		t.Fatal("rotate did not mint a new token")
	}
	old := h.fetch("/sub/team/" + before.Token)
	unknown := h.fetch("/sub/team/" + strings.Repeat("z", len(before.Token)))
	if old.Code != unknown.Code || old.Body.String() != unknown.Body.String() || old.Code == http.StatusOK {
		t.Fatalf("old token got %d %q; an unknown token gets %d %q", old.Code, old.Body.String(), unknown.Code, unknown.Body.String())
	}
	if res := h.fetch("/sub/team/" + after.Token); res.Code != http.StatusOK || res.Body.String() != h.body {
		t.Fatalf("new token: %d %q", res.Code, res.Body.String())
	}
	evs := h.auditFor(auditActionShareRotate, row.ShareID)
	if len(evs) != 1 || evs[0].Metadata["old_token_sha256"] != proxySubTokenAuditHash(before.Token) ||
		evs[0].Metadata["new_token_sha256"] != proxySubTokenAuditHash(after.Token) {
		t.Fatalf("rotate audit = %+v", evs)
	}
}

// An archived share answers like a deleted one; restored, the same link
// serves again. A disabled share stops answering at once.
func TestSubStoreShareArchivedAndDisabledAreNotServed(t *testing.T) {
	h := newSubStoreSvcHarness(t)
	row := h.createShare(t, `{"subscription_id":"rec","slug":"team"}`)
	share, _ := h.st.SubscriptionShare(row.ShareID)
	path := "/sub/team/" + share.Token
	unknown := h.fetch("/sub/team/" + strings.Repeat("z", len(share.Token)))
	if res := h.fetch(path); res.Code != http.StatusOK {
		t.Fatalf("live share: %d", res.Code)
	}

	h.mustCall(t, subStoreSharesService, "archive", `{"share_id":"`+row.ShareID+`"}`)
	if res := h.fetch(path); res.Code != unknown.Code || res.Body.String() != unknown.Body.String() {
		t.Fatalf("an archived share was served: %d %q", res.Code, res.Body.String())
	}
	h.mustCall(t, subStoreSharesService, "restore", `{"share_id":"`+row.ShareID+`"}`)
	if res := h.fetch(path); res.Code != http.StatusOK || res.Body.String() != h.body {
		t.Fatalf("a restored share is not served: %d", res.Code)
	}

	h.mustCall(t, subStoreSharesService, "set_enabled", `{"share_id":"`+row.ShareID+`","enabled":false}`)
	if res := h.fetch(path); res.Code != unknown.Code || res.Body.String() != unknown.Body.String() {
		t.Fatalf("a disabled share was served from cache: %d %q", res.Code, res.Body.String())
	}
	if evs := h.auditFor(auditActionShareUpdate, row.ShareID); len(evs) != 1 || evs[0].Metadata["enabled"] != "false" {
		t.Fatalf("set_enabled audit = %+v", evs)
	}
	h.mustCall(t, subStoreSharesService, "set_enabled", `{"share_id":"`+row.ShareID+`","enabled":true}`)
	if res := h.fetch(path); res.Code != http.StatusOK {
		t.Fatalf("a re-enabled share is not served: %d", res.Code)
	}
}

// Reorder takes every live share once and stores that order in one write.
func TestSubStoreSharesReorder(t *testing.T) {
	h := newSubStoreSvcHarness(t)
	a := h.createShare(t, `{"subscription_id":"rec","slug":"a"}`)
	b := h.createShare(t, `{"subscription_id":"rec","slug":"b"}`)
	c := h.createShare(t, `{"subscription_id":"rec","slug":"c"}`)
	if a.Order != 0 || b.Order != 1 || c.Order != 2 {
		t.Fatalf("new shares are not appended in order: %d %d %d", a.Order, b.Order, c.Order)
	}
	archived := h.createShare(t, `{"subscription_id":"rec","slug":"gone"}`)
	h.mustCall(t, subStoreSharesService, "archive", `{"share_id":"`+archived.ShareID+`"}`)

	var reply struct {
		Shares []subStoreShareRow `json:"shares"`
	}
	if err := json.Unmarshal(h.mustCall(t, subStoreSharesService, "reorder",
		`{"share_ids":["`+c.ShareID+`","`+a.ShareID+`","`+b.ShareID+`"]}`), &reply); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{c.ShareID: 0, a.ShareID: 1, b.ShareID: 2}
	for i, row := range reply.Shares {
		stored, _ := h.st.SubscriptionShare(row.ShareID)
		if want[row.ShareID] != i || row.Order != i || stored.Order != i {
			t.Fatalf("row %d = %+v, stored order %d", i, row, stored.Order)
		}
	}
	reorders := 0
	for _, ev := range h.st.AuditEvents() {
		if ev.Action == auditActionShareReorder {
			reorders++
			if ev.Metadata["moved"] != "3" || ev.Metadata["shares"] != "3" {
				t.Fatalf("reorder audit = %+v", ev)
			}
		}
	}
	if reorders != 1 {
		t.Fatalf("reorder audited %d times", reorders)
	}
	for _, body := range []string{
		`{"share_ids":["` + c.ShareID + `","` + a.ShareID + `"]}`,
		`{"share_ids":["` + c.ShareID + `","` + a.ShareID + `","` + a.ShareID + `"]}`,
		`{"share_ids":["` + c.ShareID + `","` + a.ShareID + `","` + archived.ShareID + `"]}`,
	} {
		if _, err := h.call(subStoreSvcAdmin, subStoreSharesService, "reorder", body); subStoreSvcErrStatus(err) != http.StatusBadRequest {
			t.Fatalf("reorder %s: want 400, got %v", body, err)
		}
	}
}

// The fleet-feed guard of the REST create holds here too.
func TestSubStoreSharesCreateKeepsFleetFeedGuard(t *testing.T) {
	h := newSubStoreSvcHarness(t)
	doc := `{"version":1,"records":[{"id":"fleet","name":"Everyone","source":"vpn-core"}]}`
	if err := h.st.PutKV(model.KVEntry{Bucket: usageSubStoreKVBucket, Key: usageSubStoreRecordsKey, Value: doc}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.call(subStoreSvcAdmin, subStoreSharesService, "create", `{"subscription_id":"fleet","slug":"everyone"}`); subStoreSvcErrStatus(err) != http.StatusBadRequest ||
		!strings.Contains(subStoreSvcErrBody(err), apiErrorFleetFeedFlagRequired) {
		t.Fatalf("a fleet feed share without the flag: %v %s", err, subStoreSvcErrBody(err))
	}
	row := h.createShare(t, `{"subscription_id":"fleet","slug":"everyone","publishes_fleet_credentials":true}`)
	stored, _ := h.st.SubscriptionShare(row.ShareID)
	if !shareFleetCredentials(stored) {
		t.Fatal("the flag was not stored on the share")
	}
}
