package server

import (
	"net/http"
	"testing"
)

// TestNotifyScopeSplit pins the 2026-09 split of the flat notify:send scope.
//
// Before it, one scope covered both dispatching a message and rewriting the
// routing fabric, so a token minted for a script that sends alerts could also
// register a channel pointing at itself with a wildcard rule and receive
// fleet-wide security telemetry. After it, notify:send authorizes dispatch
// only (the test-send endpoint) and notify:admin governs channels, rules and
// inbound webhooks.
//
// The test drives both tokens across both halves. Without the split (all
// routes on notify:send) the send-only token reaches every management route,
// which is the regression this test exists to catch. Backward compat is the
// asymmetry pinned here: a notify:send-only token keeps dispatch and loses
// management, and neither scope implies the other. Wildcard grants ("*",
// "notify:*"), including the bootstrap admin's "*", satisfy both.
func TestNotifyScopeSplit(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	sendOnly := createPAT(t, handler, cookies, csrf, []string{"notify:send"}, nil)
	adminOnly := createPAT(t, handler, cookies, csrf, []string{"notify:admin"}, nil)

	do := func(token, method, path, body string) int {
		res := doBearerJSON(t, handler, method, path, body, token)
		res.Body.Close()
		return res.StatusCode
	}

	// Dispatch: notify:send passes the gate (an empty channel config fails
	// validation with 400, which proves the scope check was already behind
	// us); notify:admin does not imply dispatch.
	if code := do(sendOnly, http.MethodPost, "/api/notify/test", `{"channel":"webhook"}`); code != http.StatusBadRequest {
		t.Fatalf("notify:send must keep dispatch (expected 400 past the gate), got %d", code)
	}
	if code := do(adminOnly, http.MethodPost, "/api/notify/test", `{"channel":"webhook"}`); code != http.StatusForbidden {
		t.Fatalf("notify:admin must not imply dispatch, got %d", code)
	}

	// Management: every channel, rule and webhook route refuses the
	// send-only token at the scope gate.
	management := []struct{ method, path, body string }{
		{http.MethodGet, "/api/notify/channels", ""},
		{http.MethodPost, "/api/notify/channels", `{}`},
		{http.MethodPost, "/api/notify/channels/delete", `{}`},
		{http.MethodGet, "/api/notify/rules", ""},
		{http.MethodPost, "/api/notify/rules", `{}`},
		{http.MethodPost, "/api/notify/rules/delete", `{}`},
		{http.MethodGet, "/api/notify/webhooks", ""},
		{http.MethodPost, "/api/notify/webhooks", `{}`},
		{http.MethodPost, "/api/notify/webhooks/delete", `{}`},
		{http.MethodPost, "/api/notify/webhooks/rotate", `{}`},
		{http.MethodGet, "/api/notify/webhooks/deliveries?id=x", ""},
		{http.MethodPost, "/api/notify/webhooks/test", `{}`},
	}
	for _, m := range management {
		if code := do(sendOnly, m.method, m.path, m.body); code != http.StatusForbidden {
			t.Errorf("%s %s: notify:send-only token must lose management, got %d", m.method, m.path, code)
		}
		if code := do(adminOnly, m.method, m.path, m.body); code == http.StatusForbidden {
			t.Errorf("%s %s: notify:admin token must pass the scope gate (any non-403), got 403", m.method, m.path)
		}
	}

	// The admin token actually manages: a real channel round-trips.
	created := doBearerJSON(t, handler, http.MethodPost, "/api/notify/channels",
		`{"name":"split-check","kind":"webhook","config":{"url":"https://example.invalid/hook"}}`, adminOnly)
	created.Body.Close()
	if created.StatusCode != http.StatusOK {
		t.Fatalf("notify:admin channel create failed: %d", created.StatusCode)
	}
}
