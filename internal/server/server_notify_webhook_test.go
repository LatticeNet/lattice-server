package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// createTestWebhook authors a webhook through the API and returns its view plus
// the one-time secret.
func createTestWebhook(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, body string) (string, string) {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/notify/webhooks", body, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create webhook failed: %d", res.StatusCode)
	}
	var created struct {
		ID     string `json:"id"`
		Path   string `json:"path"`
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.Secret == "" {
		t.Fatal("create must return the one-time secret")
	}
	if created.Path != "/api/hooks/"+created.ID {
		t.Fatalf("unexpected path %q for id %q", created.Path, created.ID)
	}
	return created.ID, created.Secret
}

func fireWebhook(t *testing.T, handler http.Handler, webhookID, secret, body string) *http.Response {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/hooks/"+webhookID, reader)
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Result()
}

// TestNotifyWebhookLifecycle covers the operator's path: author, see the URL,
// list without the secret, rotate, delete.
func TestNotifyWebhookLifecycle(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	id, secret := createTestWebhook(t, handler, cookies, csrf,
		`{"name":"Backup done","event_type":"backup.finished","title_template":"Backup {{data.host}}","body_template":"{{data.detail}}"}`)

	list := doJSON(t, handler, http.MethodGet, "/api/notify/webhooks", "", cookies, "")
	defer list.Body.Close()
	rawBytes, err := io.ReadAll(list.Body)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(rawBytes)
	// The list is the place a leak would show up, so assert on the whole body
	// rather than on a parsed field: neither the plaintext secret nor the stored
	// hash may appear anywhere in it.
	if strings.Contains(raw, secret) {
		t.Fatal("webhook list leaked the plaintext secret")
	}
	if strings.Contains(raw, "secret_hash") || strings.Contains(raw, "pbkdf2") {
		t.Fatalf("webhook list leaked credential material: %s", raw)
	}
	if !strings.Contains(raw, "/api/hooks/"+id) {
		t.Fatalf("webhook list missing the callable path: %s", raw)
	}

	rotate := doJSON(t, handler, http.MethodPost, "/api/notify/webhooks/rotate", `{"id":"`+id+`"}`, cookies, csrf)
	defer rotate.Body.Close()
	if rotate.StatusCode != http.StatusOK {
		t.Fatalf("rotate failed: %d", rotate.StatusCode)
	}
	var rotated struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(rotate.Body).Decode(&rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.Secret == secret || rotated.Secret == "" {
		t.Fatal("rotate must mint a different secret")
	}
	// Rotation has no overlap window: the old secret must be dead immediately.
	if res := fireWebhook(t, handler, id, secret, ""); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("rotated-away secret still works: %d", res.StatusCode)
	}
	if res := fireWebhook(t, handler, id, rotated.Secret, ""); res.StatusCode != http.StatusAccepted {
		t.Fatalf("new secret rejected: %d", res.StatusCode)
	}

	del := doJSON(t, handler, http.MethodPost, "/api/notify/webhooks/delete", `{"id":"`+id+`"}`, cookies, csrf)
	defer del.Body.Close()
	if del.StatusCode != http.StatusOK {
		t.Fatalf("delete failed: %d", del.StatusCode)
	}
	if res := fireWebhook(t, handler, id, rotated.Secret, ""); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("deleted webhook still fires: %d", res.StatusCode)
	}
}

// TestInboundWebhookRejectsWithoutSecret is the central authentication claim:
// possession of the URL alone buys nothing.
func TestInboundWebhookRejectsWithoutSecret(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	id, secret := createTestWebhook(t, handler, cookies, csrf,
		`{"name":"Probe","event_type":"probe.fired","title_template":"Probe"}`)

	cases := []struct {
		name      string
		presented string
	}{
		{"no header at all", ""},
		{"empty bearer", " "},
		{"unsplittable token", "not-a-token"},
		{"right shape, wrong secret", id + ".wrongsecretwrongsecret"},
		{"valid secret, wrong webhook in token", "nwh_other." + strings.SplitN(secret, ".", 2)[1]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := fireWebhook(t, handler, id, tc.presented, "")
			if res.StatusCode != http.StatusUnauthorized && res.StatusCode != http.StatusTooManyRequests {
				t.Fatalf("expected 401 (or 429 once the attempt budget is spent), got %d", res.StatusCode)
			}
			res.Body.Close()
		})
	}
}

// TestInboundWebhookAuditsEveryAttempt proves a delivery is auditable, in both
// directions: an accepted fire and a refused one both leave a record naming the
// webhook.
func TestInboundWebhookAuditsEveryAttempt(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	id, secret := createTestWebhook(t, handler, cookies, csrf,
		`{"name":"Audited","event_type":"audited.event","title_template":"Audited"}`)

	if res := fireWebhook(t, handler, id, secret, ""); res.StatusCode != http.StatusAccepted {
		t.Fatalf("accepted fire returned %d", res.StatusCode)
	}
	if res := fireWebhook(t, handler, id, id+".definitelywrongsecret", ""); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("refused fire returned %d", res.StatusCode)
	}

	var allow, deny int
	for _, ev := range st.AuditEvents() {
		if ev.Action != "notify.webhook.receive" {
			continue
		}
		if ev.Metadata["webhook_id"] != id {
			t.Fatalf("audit event does not name the webhook: %+v", ev.Metadata)
		}
		switch ev.Decision {
		case "allow":
			allow++
		case "deny":
			deny++
			if ev.Reason == "" {
				t.Fatal("a refusal must record why")
			}
		}
		if ev.Metadata["source_ip"] == "" {
			t.Fatal("a webhook attempt must record its source address")
		}
	}
	if allow != 1 || deny != 1 {
		t.Fatalf("expected one allow and one deny audit record, got allow=%d deny=%d", allow, deny)
	}
}

// TestInboundWebhookCallerCannotChooseRouting is the authorization claim. The
// caller sends fields that collide with every platform variable and every
// operator-controlled name; none of it may change the event type, the template,
// or the routing.
func TestInboundWebhookCallerCannotChooseRouting(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	channel := doJSON(t, handler, http.MethodPost, "/api/notify/channels",
		`{"name":"sink","kind":"webhook","config":{"url":"https://example.com/sink"}}`, cookies, csrf)
	defer channel.Body.Close()
	var ch struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(channel.Body).Decode(&ch); err != nil {
		t.Fatal(err)
	}
	// One rule, bound to one event type. A caller who could pick the event type
	// could reach it; a caller who cannot, cannot.
	rule := doJSON(t, handler, http.MethodPost, "/api/notify/rules",
		`{"name":"only-secret-events","event_types":["secret.event"],"channel_ids":["`+ch.ID+`"]}`, cookies, csrf)
	defer rule.Body.Close()
	if rule.StatusCode != http.StatusOK {
		t.Fatalf("rule create failed: %d", rule.StatusCode)
	}

	id, secret := createTestWebhook(t, handler, cookies, csrf,
		`{"name":"Public hook","event_type":"public.event","title_template":"From {{data.who}}","body_template":"{{data.detail}}"}`)

	body := `{"data":{"who":"caller","detail":"hello","event_type":"secret.event","title":"pwned","body":"pwned","channel_ids":"` + ch.ID + `"}}`
	res := fireWebhook(t, handler, id, secret, body)
	defer res.Body.Close()
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("fire failed: %d", res.StatusCode)
	}

	deliveries := st.NotifyWebhookDeliveries(id, 10)
	if len(deliveries) != 1 {
		t.Fatalf("expected one delivery record, got %d", len(deliveries))
	}
	got := deliveries[0]
	if got.EventType != "public.event" {
		t.Fatalf("caller changed the event type to %q", got.EventType)
	}
	// The rule listens only for secret.event, so nothing may have been routed.
	if got.Channels != 0 || got.Outcome != store.NotifyWebhookNoRoute {
		t.Fatalf("caller reached a channel it must not: channels=%d outcome=%s", got.Channels, got.Outcome)
	}
	if got.Title != "From caller" || got.Body != "hello" {
		t.Fatalf("caller-supplied fields did not land in the operator's template: %q / %q", got.Title, got.Body)
	}
}

// TestWebhookTemplateInjection is the injection claim. A caller value that
// itself contains template syntax must never be expanded, in this renderer or
// in the rule renderer downstream.
func TestWebhookTemplateInjection(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	id, secret := createTestWebhook(t, handler, cookies, csrf,
		`{"name":"Inject","event_type":"inject.test","title_template":"{{data.first}}","body_template":"{{data.first}} / {{data.second}}"}`)

	body := `{"data":{"first":"{{data.second}}","second":"SECRET-VALUE"}}`
	res := fireWebhook(t, handler, id, secret, body)
	defer res.Body.Close()
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("fire failed: %d", res.StatusCode)
	}
	deliveries := st.NotifyWebhookDeliveries(id, 1)
	if len(deliveries) != 1 {
		t.Fatalf("expected one delivery, got %d", len(deliveries))
	}
	if strings.Contains(deliveries[0].Title, "SECRET-VALUE") {
		t.Fatalf("caller value was re-expanded as a template: %q", deliveries[0].Title)
	}
	if strings.Contains(deliveries[0].Title, "{{") {
		t.Fatalf("template delimiters survived sanitisation: %q", deliveries[0].Title)
	}
}

// TestRenderWebhookTemplateSinglePass pins the renderer directly, including the
// unknown-placeholder behaviour the handler depends on.
func TestRenderWebhookTemplateSinglePass(t *testing.T) {
	vars := map[string]string{
		"data.a":     "{{data.b}}",
		"data.b":     "expanded",
		"event_type": "e.t",
	}
	cases := []struct{ tmpl, want string }{
		{"{{data.a}}", "{{data.b}}"},
		{"x {{data.b}} y", "x expanded y"},
		{"{{event_type}}", "e.t"},
		{"{{data.missing}}", "{{data.missing}}"},
		{"no placeholders", "no placeholders"},
		{"unclosed {{data.b", "unclosed {{data.b"},
		{"{{data.b}}{{data.b}}", "expandedexpanded"},
		{"{{ data.b }}", "expanded"},
	}
	for _, tc := range cases {
		if got := renderWebhookTemplate(tc.tmpl, "fallback", vars); got != tc.want {
			t.Errorf("renderWebhookTemplate(%q) = %q, want %q", tc.tmpl, got, tc.want)
		}
	}
	if got := renderWebhookTemplate("  ", "fallback", vars); got != "fallback" {
		t.Errorf("empty template should fall back, got %q", got)
	}
}

// TestWebhookPayloadLimits pins the caps on what a caller may send.
func TestWebhookPayloadLimits(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	id, secret := createTestWebhook(t, handler, cookies, csrf,
		`{"name":"Limits","event_type":"limits.test","title_template":"t"}`)

	tooManyFields := new(strings.Builder)
	tooManyFields.WriteString(`{"data":{`)
	for i := 0; i < maxWebhookFields+1; i++ {
		if i > 0 {
			tooManyFields.WriteString(",")
		}
		tooManyFields.WriteString(`"k`)
		tooManyFields.WriteString(string(rune('a' + i)))
		tooManyFields.WriteString(`":"v"`)
	}
	tooManyFields.WriteString(`}}`)

	cases := []struct {
		name string
		body string
	}{
		{"too many fields", tooManyFields.String()},
		{"nested object", `{"data":{"k":{"nested":true}}}`},
		{"array value", `{"data":{"k":[1,2,3]}}`},
		{"oversized value", `{"data":{"k":"` + strings.Repeat("x", maxWebhookValueLen+1) + `"}}`},
		{"bad field name", `{"data":{"has space":"v"}}`},
		{"unknown envelope key", `{"event_type":"attacker.chosen"}`},
		{"oversized body", `{"data":{"k":"` + strings.Repeat("y", maxWebhookBodyBytes+16) + `"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := fireWebhook(t, handler, id, secret, tc.body)
			defer res.Body.Close()
			if res.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", res.StatusCode)
			}
		})
	}

	// Scalars other than string are accepted and stringified, and an empty body
	// is a valid ping.
	for _, ok := range []string{`{"data":{"count":42,"ok":true,"note":null}}`, ``, `{}`} {
		res := fireWebhook(t, handler, id, secret, ok)
		if res.StatusCode != http.StatusAccepted {
			t.Fatalf("body %q should be accepted, got %d", ok, res.StatusCode)
		}
		res.Body.Close()
	}
}

// TestInboundWebhookRoutesThroughExistingRules is the integration claim: a
// webhook event is matched by an ordinary rule and reaches an ordinary channel,
// with the rule's own template applied on top.
func TestInboundWebhookRoutesThroughExistingRules(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNotifyChannel(model.NotifyChannel{ID: "ch-hook", Name: "Hook sink", Kind: "webhook", Config: map[string]string{"url": "https://example.com/sink"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNotifyRule(model.NotifyRule{ID: "rule-hook", Name: "Hook", EventTypes: []string{"deploy.finished"}, ChannelIDs: []string{"ch-hook"}, TitleTemplate: "[{{event_type}}] {{title}}", BodyTemplate: "{{body}}", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	hook := store.NotifyWebhook{ID: "nwh-deploy", Name: "Deploy", EventType: "deploy.finished", TitleTemplate: "Deploy of {{data.service}}", BodyTemplate: "version {{data.version}}", Enabled: true}
	if err := st.UpsertNotifyWebhook(hook); err != nil {
		t.Fatal(err)
	}

	record := srv.fireNotifyWebhook(hook, map[string]string{"service": "api", "version": "1.4.2"}, "203.0.113.9", 64, false)
	if record.Outcome != store.NotifyWebhookAccepted {
		t.Fatalf("expected the event to route, got %s (%s)", record.Outcome, record.Reason)
	}
	if record.Channels != 1 {
		t.Fatalf("expected one planned channel, got %d", record.Channels)
	}
	if record.Title != "Deploy of api" || record.Body != "version 1.4.2" {
		t.Fatalf("webhook template not applied: %q / %q", record.Title, record.Body)
	}

	// The rule's template wraps the webhook's rendered message, proving the
	// webhook is a source feeding the existing pipeline rather than a path beside it.
	deliveries := srv.planNotifyDeliveries(hook.EventType, record.Title, record.Body, st.EnabledNotifyChannels(), st.EnabledNotifyRules())
	if len(deliveries) != 1 {
		t.Fatalf("expected one delivery, got %d", len(deliveries))
	}
	if deliveries[0].Message.Title != "[deploy.finished] Deploy of api" {
		t.Fatalf("rule template not applied over the webhook message: %q", deliveries[0].Message.Title)
	}
}

// TestNotifyWebhookRequiresScope pins the admin surface to notify:send. A
// principal without it may neither read the definitions nor author one.
func TestNotifyWebhookRequiresScope(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	id, _ := createTestWebhook(t, handler, cookies, csrf,
		`{"name":"Scoped","event_type":"scoped.event","title_template":"t"}`)

	token := createPAT(t, handler, cookies, csrf, []string{"node:read"}, nil)
	for _, path := range []string{"/api/notify/webhooks", "/api/notify/webhooks/deliveries?id=" + id} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s should be forbidden without notify:send, got %d", path, rec.Code)
		}
	}
}

// TestNotifyWebhookRejectsWildcardEventType pins the rule that a source may not
// emit "*". A webhook that raised every event type would make every rule fire,
// which is the caller-chooses-routing outcome the design forbids.
func TestNotifyWebhookRejectsWildcardEventType(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/notify/webhooks",
		`{"name":"Wildcard","event_type":"*","title_template":"t"}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for a wildcard event type, got %d", res.StatusCode)
	}
}

// TestNotifyWebhookNeverCalledOmitsTimestamp pins a bug the console found: a
// zero time.Time is not "empty" to encoding/json, so `omitempty` shipped
// "0001-01-01T00:00:00Z" and a webhook nothing had ever called rendered as
// having been called in year one. The tag has to be omitzero.
func TestNotifyWebhookNeverCalledOmitsTimestamp(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	id, secret := createTestWebhook(t, handler, cookies, csrf,
		`{"name":"Untouched","event_type":"untouched.event","title_template":"t"}`)

	read := func() string {
		t.Helper()
		res := doJSON(t, handler, http.MethodGet, "/api/notify/webhooks", "", cookies, "")
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}

	if raw := read(); strings.Contains(raw, "0001-01-01") {
		t.Fatalf("a never-called webhook must omit last_used_at, got: %s", raw)
	} else if strings.Contains(raw, "last_used_at") {
		t.Fatalf("last_used_at should be absent before the first call, got: %s", raw)
	}

	if res := fireWebhook(t, handler, id, secret, ""); res.StatusCode != http.StatusAccepted {
		t.Fatalf("fire returned %d", res.StatusCode)
	}
	// After a real call it must be present and not the zero value.
	raw := read()
	if !strings.Contains(raw, "last_used_at") || strings.Contains(raw, "0001-01-01") {
		t.Fatalf("last_used_at should carry the call time after a fire, got: %s", raw)
	}
}
