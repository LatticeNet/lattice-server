package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// revealHarness is one server with an operator session, a fresh step-up
// grant for it, and helpers for the four principals every reveal door is
// tested against: a session without step-up, a session with it, a token
// without secrets:reveal and a token with it.
type revealHarness struct {
	t       *testing.T
	srv     *Server
	handler http.Handler
	cookies []*http.Cookie
	csrf    string
	grant   string
}

func newRevealHarness(t *testing.T) *revealHarness {
	t.Helper()
	srv, handler := newManageTestServer(t)
	cookies, csrf := loginSession(t, handler)
	return &revealHarness{t: t, srv: srv, handler: handler, cookies: cookies, csrf: csrf}
}

// stepUp issues a grant to the harness session directly, the way the TOTP
// and passkey endpoints do after a second factor.
func (h *revealHarness) stepUp() string {
	h.t.Helper()
	if h.grant != "" {
		return h.grant
	}
	user, ok := h.srv.store.UserByUsername("admin")
	if !ok {
		h.t.Fatal("admin user missing")
	}
	sessionID := ""
	for _, cookie := range h.cookies {
		if cookie.Name == "lattice_session" {
			sessionID = cookie.Value
		}
	}
	if sessionID == "" {
		h.t.Fatal("login did not return a session cookie")
	}
	grant, _, err := h.srv.issueStepUpGrant(principal{Principal: rbac.Principal{ActorID: user.ID}, sessionID: sessionID})
	if err != nil {
		h.t.Fatal(err)
	}
	h.grant = grant
	return grant
}

// token mints an API token from the session. withReveal adds
// secrets:reveal through its own door, which needs the step-up grant.
func (h *revealHarness) token(scopes []string, withReveal bool) (string, string) {
	h.t.Helper()
	body := map[string]any{"name": "reveal-test", "scopes": scopes, "server_allowlist": []string{}}
	if withReveal {
		body["scopes"] = append(append([]string(nil), scopes...), rbac.SecretRevealScope)
		body["step_up_grant"] = h.stepUp()
	}
	res := doJSON(h.t, h.handler, http.MethodPost, "/api/tokens", string(mustJSON(h.t, body)), h.cookies, h.csrf)
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		h.t.Fatalf("token create: %d %s", res.StatusCode, raw)
	}
	var out struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		h.t.Fatal(err)
	}
	return out.ID, out.Token
}

// withGrant adds step_up_grant to a JSON object body.
func withGrant(t *testing.T, body, grant string) string {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal([]byte(body), &fields); err != nil {
		t.Fatal(err)
	}
	fields["step_up_grant"] = grant
	return string(mustJSON(t, fields))
}

func apiErrorCodeOf(t *testing.T, raw []byte) string {
	t.Helper()
	var out model.APIErrorResponse
	_ = json.Unmarshal(raw, &out)
	return out.Error.Code
}

// revealDoor is one endpoint that hands out secret material.
type revealDoor struct {
	name   string
	method string
	path   string
	body   string
	// scopes is what a token needs besides secrets:reveal to reach the door.
	scopes []string
	// secret is a string that appears in the answer only when it reveals.
	secret string
	// action is the audit action an allowed reveal records.
	action string
	// objectKey is the metadata key naming the object in the audit event.
	objectKey string
}

// checkRevealDoor runs the four principals against one door.
func checkRevealDoor(t *testing.T, h *revealHarness, door revealDoor) {
	t.Helper()
	do := func(body, token string, session bool) (int, []byte) {
		var res *http.Response
		if session {
			res = doJSON(t, h.handler, door.method, door.path, body, h.cookies, h.csrf)
		} else {
			res = doBearerJSON(t, h.handler, door.method, door.path, body, token)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		return res.StatusCode, raw
	}

	status, raw := do(door.body, "", true)
	if status != http.StatusForbidden || apiErrorCodeOf(t, raw) != apiErrorStepUpRequired {
		t.Fatalf("%s: session without step-up: want 403 %s, got %d %s", door.name, apiErrorStepUpRequired, status, raw)
	}
	if strings.Contains(string(raw), door.secret) {
		t.Fatalf("%s: a refusal carried the secret", door.name)
	}

	status, raw = do(withGrant(t, door.body, h.stepUp()), "", true)
	if status != http.StatusOK || !strings.Contains(string(raw), door.secret) {
		t.Fatalf("%s: session with step-up: want 200 with the secret, got %d %s", door.name, status, raw)
	}

	_, plain := h.token(door.scopes, false)
	status, raw = do(door.body, plain, false)
	if status != http.StatusForbidden || apiErrorCodeOf(t, raw) != apiErrorRevealScopeRequired {
		t.Fatalf("%s: token without secrets:reveal: want 403 %s, got %d %s", door.name, apiErrorRevealScopeRequired, status, raw)
	}
	if strings.Contains(string(raw), door.secret) {
		t.Fatalf("%s: a token refusal carried the secret", door.name)
	}

	tokenID, revealToken := h.token(door.scopes, true)
	status, raw = do(door.body, revealToken, false)
	if status != http.StatusOK || !strings.Contains(string(raw), door.secret) {
		t.Fatalf("%s: token with secrets:reveal: want 200 with the secret, got %d %s", door.name, status, raw)
	}
	found := false
	for _, ev := range h.srv.store.AuditEvents() {
		if ev.Action == door.action && ev.Decision == "allow" && ev.Metadata["via"] == revealViaToken && ev.Metadata["token_id"] == tokenID {
			if door.objectKey != "" && ev.Metadata[door.objectKey] == "" {
				t.Fatalf("%s: the token reveal audit does not name the object (%s): %+v", door.name, door.objectKey, ev.Metadata)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("%s: a token reveal must write an audit event naming the token %s", door.name, tokenID)
	}
	for _, ev := range h.srv.store.AuditEvents() {
		for _, v := range ev.Metadata {
			if strings.Contains(v, door.secret) {
				t.Fatalf("%s: the audit trail holds the secret: %+v", door.name, ev)
			}
		}
	}
}

func seedRevealLine(t *testing.T, h *revealHarness) string {
	t.Helper()
	enrollNamedNodeToken(t, h.handler, h.cookies, h.csrf, "node-a", "Node A")
	enableSingBox(t, h.srv, "node-a")
	h.srv.singboxInvMu.Lock()
	h.srv.singboxInv = map[string]model.SingBoxInventory{"node-a": {NodeID: "node-a", Status: "ok", Nodes: []model.SingBoxNode{{
		Name: "VLESS-REALITY-31001.json", Protocol: "vless", ListenHost: "0.0.0.0", Port: "31001", Address: "203.0.113.10",
		SNI: "www.example.com", ShareURL: "vless://11111111-1111-4111-8111-111111111111@example.test:31001?encryption=none#alice",
		UserKnown: true, UserCount: 1,
	}}}}
	h.srv.singboxInvMu.Unlock()
	h.srv.invalidateLineReadModel()
	groups, _ := h.srv.lineReadModel()
	if len(groups) != 1 || len(groups[0].Lines) != 1 {
		t.Fatalf("unexpected line groups: %+v", groups)
	}
	return groups[0].Lines[0].LineHashID
}

func TestEveryRevealDoorAsksTheOneGate(t *testing.T) {
	t.Run("vpn identity credentials", func(t *testing.T) {
		h := newRevealHarness(t)
		now := h.srv.now()
		if err := h.srv.putVpnUser(VpnUser{ID: "vpn-user-a", Email: "alice@example.com", Enabled: true,
			Credentials: []VpnCredential{{Protocol: "vless", UUID: "22222222-2222-4222-8222-222222222222"}},
			SubID:       strings.Repeat("s", 43), CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
		checkRevealDoor(t, h, revealDoor{name: "credentials", method: http.MethodPost, path: "/api/proxy/users/reveal-credentials",
			body: `{"id":"vpn-user-a"}`, scopes: []string{"proxy:admin"}, secret: "22222222-2222-4222-8222-222222222222",
			action: "vpn.user.credentials.reveal", objectKey: "user_id"})
		// The subscription token is the link's, revealed through its own door.
		res := doJSON(t, h.handler, http.MethodPost, "/api/proxy/users/reveal-credentials", withGrant(t, `{"id":"vpn-user-a"}`, h.stepUp()), h.cookies, h.csrf)
		raw, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if strings.Contains(string(raw), strings.Repeat("s", 43)) || strings.Contains(string(raw), "sub_id") {
			t.Fatalf("a credential reveal must not carry the subscription token: %s", raw)
		}
	})

	t.Run("adopted line share url", func(t *testing.T) {
		h := newRevealHarness(t)
		lineHash := seedRevealLine(t, h)
		checkRevealDoor(t, h, revealDoor{name: "line", method: http.MethodPost, path: "/api/proxy/managed/reveal-line",
			body: `{"node_id":"node-a","line_hash_id":"` + lineHash + `"}`, scopes: []string{"proxy:admin"},
			secret: "11111111-1111-4111-8111-111111111111", action: "singbox.line.reveal", objectKey: "line_hash_id"})
	})

	t.Run("knock sequence", func(t *testing.T) {
		h := newRevealHarness(t)
		seedAgentUpdateNode(t, h.srv.store)
		enrolSSHGuard(t, h.srv.store, "node-a")
		seedArmApproval(t, h.srv.store, "approval_arm", "node-a", model.ApprovalApplied, knockTestPorts, time.Now().UTC())
		checkRevealDoor(t, h, revealDoor{name: "knock", method: http.MethodPost, path: "/api/sshguard/knock/reveal",
			body: `{"node_id":"node-a"}`, scopes: []string{"sshguard:admin", "network:plan"}, secret: "23853",
			action: "sshguard.knock.reveal", objectKey: "approval_id"})
	})

	t.Run("task script", func(t *testing.T) {
		h := newRevealHarness(t)
		seedAgentUpdateNode(t, h.srv.store)
		if err := h.srv.store.CreateTask(model.Task{ID: "task-secret", Targets: []string{"node-a"}, Interpreter: "sh",
			Script: "echo reveal-marker-7f3a", Status: "queued", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		checkRevealDoor(t, h, revealDoor{name: "task script", method: http.MethodPost, path: "/api/tasks/reveal-script",
			body: `{"id":"task-secret"}`, scopes: []string{"task:read"}, secret: "reveal-marker-7f3a",
			action: "task.script.reveal", objectKey: "task_id"})
	})

	t.Run("machine console link", func(t *testing.T) {
		h := newRevealHarness(t)
		if err := h.srv.store.UpsertNode(model.Node{ID: "node-a", Name: "node-a"}); err != nil {
			t.Fatal(err)
		}
		create := doJSON(t, h.handler, http.MethodPost, "/api/machines",
			`{"node_id":"node-a","vendor":"DMIT","console_url":"https://console.example.com/secret-9c1"}`, h.cookies, h.csrf)
		var created machineView
		if err := json.NewDecoder(create.Body).Decode(&created); err != nil {
			t.Fatal(err)
		}
		create.Body.Close()
		checkRevealDoor(t, h, revealDoor{name: "machine link", method: http.MethodPost, path: "/api/machines/reveal-link",
			body: `{"id":"` + created.ID + `","kind":"console"}`, scopes: []string{"inventory:admin"}, secret: "secret-9c1",
			action: "inventory.link.reveal", objectKey: "machine_id"})
	})
}

// secrets:reveal is held only by naming it, granted only by a full
// administrator's session after step-up, and never to a user account.
func TestSecretRevealIsGrantedOnlyThroughItsOwnDoor(t *testing.T) {
	h := newRevealHarness(t)
	create := func(body map[string]any, cookies bool, bearer string) (int, []byte) {
		var res *http.Response
		if cookies {
			res = doJSON(t, h.handler, http.MethodPost, "/api/tokens", string(mustJSON(t, body)), h.cookies, h.csrf)
		} else {
			res = doBearerJSON(t, h.handler, http.MethodPost, "/api/tokens", string(mustJSON(t, body)), bearer)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		return res.StatusCode, raw
	}

	status, raw := create(map[string]any{"name": "r", "scopes": []string{"proxy:admin", "secrets:reveal"}}, true, "")
	if status != http.StatusForbidden || apiErrorCodeOf(t, raw) != apiErrorStepUpRequired {
		t.Fatalf("a reveal grant without step-up: want 403 %s, got %d %s", apiErrorStepUpRequired, status, raw)
	}

	// A token holding everything, secrets:reveal and token:admin included,
	// still cannot mint another reveal token.
	_, full := h.token([]string{"*"}, true)
	status, raw = create(map[string]any{"name": "r2", "scopes": []string{"secrets:reveal"}, "step_up_grant": h.stepUp()}, false, full)
	if status != http.StatusForbidden || apiErrorCodeOf(t, raw) != apiErrorRevealGrantRefused {
		t.Fatalf("a token minting a reveal token: want 403 %s, got %d %s", apiErrorRevealGrantRefused, status, raw)
	}

	// "*" on a token does not reveal: the scope is explicit-only.
	_, star := h.token([]string{"*"}, false)
	if err := h.srv.putVpnUser(VpnUser{ID: "vpn-user-a", Email: "a@example.com", Enabled: true, Credentials: []VpnCredential{{Protocol: "trojan", Password: "pw-0d9e-secret"}}}); err != nil {
		t.Fatal(err)
	}
	res := doBearerJSON(t, h.handler, http.MethodPost, "/api/proxy/users/reveal-credentials", `{"id":"vpn-user-a"}`, star)
	raw, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden || strings.Contains(string(raw), "pw-0d9e-secret") {
		t.Fatalf("a * token must not reveal: %d %s", res.StatusCode, raw)
	}

	// A user account can never carry it.
	userBody := map[string]any{"username": "agent-ops", "password": "a long enough password 123", "scopes": []string{"proxy:admin", "secrets:reveal"}}
	res = doJSON(t, h.handler, http.MethodPost, "/api/users", string(mustJSON(t, userBody)), h.cookies, h.csrf)
	raw, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(raw), "API tokens only") {
		t.Fatalf("a user with secrets:reveal: want 400, got %d %s", res.StatusCode, raw)
	}

	// The grant is named in the trail.
	granted := false
	for _, ev := range h.srv.store.AuditEvents() {
		if ev.Action == "token.create" && ev.Decision != "deny" && ev.Metadata["grants_secret_reveal"] == "true" {
			granted = true
		}
	}
	if !granted {
		t.Fatal("minting a reveal token must be audited as such")
	}
}
