package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

const testAdminPass = "correct horse battery staple"

// loginSession logs in as admin and returns the cookies plus CSRF token.
func loginSession(t *testing.T, handler http.Handler) ([]*http.Cookie, string) {
	t.Helper()
	body := bytes.NewBufferString(`{"username":"admin","password":"` + testAdminPass + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/login", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login failed: %d", res.StatusCode)
	}
	var out struct {
		CSRF string `json:"csrf_token"`
	}
	json.NewDecoder(res.Body).Decode(&out)
	return res.Cookies(), out.CSRF
}

func newTestServer(t *testing.T) (http.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass})
	if err != nil {
		t.Fatal(err)
	}
	return srv.Handler(), st
}

func createPAT(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf string, scopes []string, allowlist []string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"name":             "test-token",
		"scopes":           scopes,
		"server_allowlist": allowlist,
	})
	if err != nil {
		t.Fatal(err)
	}
	res := doJSON(t, handler, http.MethodPost, "/api/tokens", string(body), cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("token create failed: %d", res.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Token == "" {
		t.Fatal("missing token")
	}
	return out.Token
}

func doJSON(t *testing.T, handler http.Handler, method, path, body string, cookies []*http.Cookie, csrf string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		req.Header.Set("X-Lattice-CSRF", csrf)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Result()
}

func doBearerJSON(t *testing.T, handler http.Handler, method, path, body, token string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Result()
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func auditByActionAndScope(t *testing.T, st *store.Store, action, scope string) model.AuditEvent {
	t.Helper()
	for _, ev := range st.AuditEvents() {
		if ev.Action == action && ev.Scope == scope {
			return ev
		}
	}
	t.Fatalf("missing audit event action=%q scope=%q in %+v", action, scope, st.AuditEvents())
	return model.AuditEvent{}
}

func assertResponseAuditCorrelation(t *testing.T, st *store.Store, res *http.Response, action, scope string) {
	t.Helper()
	requestID := res.Header.Get(requestIDHeader)
	if requestID == "" {
		t.Fatalf("%s response missing request id", action)
	}
	assertAuditCorrelation(t, st, requestID, action, scope)
}

func assertRecorderAuditCorrelation(t *testing.T, st *store.Store, rec *httptest.ResponseRecorder, action, scope string) {
	t.Helper()
	requestID := rec.Header().Get(requestIDHeader)
	if requestID == "" {
		t.Fatalf("%s response missing request id", action)
	}
	assertAuditCorrelation(t, st, requestID, action, scope)
}

func assertAuditCorrelation(t *testing.T, st *store.Store, requestID, action, scope string) {
	t.Helper()
	sawAction := false
	for _, ev := range st.AuditEvents() {
		if ev.Action != action || ev.Scope != scope {
			continue
		}
		sawAction = true
		if ev.CorrelationID == requestID {
			return
		}
	}
	if sawAction {
		t.Fatalf("%s audit did not include request id %q in %+v", action, requestID, st.AuditEvents())
	}
	t.Fatalf("missing audit event action=%q scope=%q in %+v", action, scope, st.AuditEvents())
}

func errorBodyFromResponse(t *testing.T, res *http.Response) model.APIErrorResponse {
	t.Helper()
	defer res.Body.Close()
	var out model.APIErrorResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode api error: %v", err)
	}
	return out
}

func TestClientJSONDecoderRejectsUnknownAndTrailingFields(t *testing.T) {
	handler, _ := newTestServer(t)
	cases := []struct {
		name string
		body string
	}{
		{
			name: "unknown field",
			body: `{"username":"admin","password":"` + testAdminPass + `","forward_compat":true}`,
		},
		{
			name: "trailing value",
			body: `{"username":"admin","password":"` + testAdminPass + `"} {}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := doJSON(t, handler, http.MethodPost, "/api/login", tc.body, nil, "")
			if res.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected strict client body rejection, got %d", res.StatusCode)
			}
			errBody := errorBodyFromResponse(t, res)
			if errBody.Error.Code != model.APIErrorBadRequest {
				t.Fatalf("expected bad_request code, got %+v", errBody.Error)
			}
			if errBody.Error.Message != "invalid request body" {
				t.Fatalf("decoder details must not leak, got %q", errBody.Error.Message)
			}
		})
	}
}

func TestSuccessfulResponsesIncludeRequestID(t *testing.T) {
	handler, st := newTestServer(t)

	health := doJSON(t, handler, http.MethodGet, "/api/health", "", nil, "")
	health.Body.Close()
	if health.StatusCode != http.StatusOK {
		t.Fatalf("health failed: %d", health.StatusCode)
	}
	healthID := health.Header.Get("X-Lattice-Request-ID")
	if !strings.HasPrefix(healthID, "req_") {
		t.Fatalf("expected health request id, got %q", healthID)
	}

	loginBody := `{"username":"admin","password":"` + testAdminPass + `"}`
	login := doJSON(t, handler, http.MethodPost, "/api/login", loginBody, nil, "")
	login.Body.Close()
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login failed: %d", login.StatusCode)
	}
	loginID := login.Header.Get("X-Lattice-Request-ID")
	if !strings.HasPrefix(loginID, "req_") {
		t.Fatalf("expected login request id, got %q", loginID)
	}
	if loginID == healthID {
		t.Fatalf("request ids should be per-request, got %q twice", loginID)
	}
	assertResponseAuditCorrelation(t, st, login, "login", "")
}

func TestAuthorizationAuditUsesRequestID(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"kv:read"}, nil)

	routeDenied := doBearerJSON(t, handler, http.MethodGet, "/api/nodes", "", token)
	routeDenied.Body.Close()
	if routeDenied.StatusCode != http.StatusForbidden {
		t.Fatalf("expected route-level authorization denial, got %d", routeDenied.StatusCode)
	}
	routeRequestID := routeDenied.Header.Get("X-Lattice-Request-ID")
	if routeRequestID == "" {
		t.Fatal("route-level denial missing request id")
	}
	routeAudit := auditByActionAndScope(t, st, "GET /api/nodes", "node:read")
	if routeAudit.CorrelationID != routeRequestID {
		t.Fatalf("route audit correlation_id %q != request id %q", routeAudit.CorrelationID, routeRequestID)
	}

	handlerDenied := doBearerJSON(t, handler, http.MethodGet, "/api/tasks", "", token)
	handlerDenied.Body.Close()
	if handlerDenied.StatusCode != http.StatusForbidden {
		t.Fatalf("expected handler-level authorization denial, got %d", handlerDenied.StatusCode)
	}
	handlerRequestID := handlerDenied.Header.Get("X-Lattice-Request-ID")
	if handlerRequestID == "" {
		t.Fatal("handler-level denial missing request id")
	}
	handlerAudit := auditByActionAndScope(t, st, "authorize.scope", "task:read")
	if handlerAudit.CorrelationID != handlerRequestID {
		t.Fatalf("handler audit correlation_id %q != request id %q", handlerAudit.CorrelationID, handlerRequestID)
	}
}

func TestRemainingPrivilegedAllowAuditsUseRequestID(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	kvPut := doJSON(t, handler, http.MethodPost, "/api/kv",
		`{"bucket":"audit","key":"setting","value":"on"}`, cookies, csrf)
	kvPut.Body.Close()
	if kvPut.StatusCode != http.StatusOK {
		t.Fatalf("kv put failed: %d", kvPut.StatusCode)
	}
	assertResponseAuditCorrelation(t, st, kvPut, "kv.put", "kv:write")

	staticPut := doJSON(t, handler, http.MethodPost, "/api/static",
		`{"bucket":"site","path":"/index.html","content":"hello","content_type":"text/html"}`, cookies, csrf)
	staticPut.Body.Close()
	if staticPut.StatusCode != http.StatusOK {
		t.Fatalf("static put failed: %d", staticPut.StatusCode)
	}
	assertResponseAuditCorrelation(t, st, staticPut, "static.put", "static:write")

	workerUpsert := doJSON(t, handler, http.MethodPost, "/api/workers",
		`{"name":"audit-worker","source":"hello {{path}}","capabilities":["worker:route"],"public":false}`, cookies, csrf)
	workerUpsert.Body.Close()
	if workerUpsert.StatusCode != http.StatusOK {
		t.Fatalf("worker upsert failed: %d", workerUpsert.StatusCode)
	}
	assertResponseAuditCorrelation(t, st, workerUpsert, "worker.upsert", "worker:deploy")

	notifyTest := doJSON(t, handler, http.MethodPost, "/api/notify/test",
		`{"channel":"webhook","config":{"url":"http://127.0.0.1:1/blocked"},"title":"audit","body":"test"}`, cookies, csrf)
	notifyTest.Body.Close()
	if notifyTest.StatusCode != http.StatusBadGateway {
		t.Fatalf("notify test should fail at outbound guard after auditing, got %d", notifyTest.StatusCode)
	}
	assertResponseAuditCorrelation(t, st, notifyTest, "notify.test", "notify:send")

	notifyCreate := doJSON(t, handler, http.MethodPost, "/api/notify/channels",
		`{"name":"audit-channel","kind":"telegram","config":{"token":"SECRET","chat_id":"123"}}`, cookies, csrf)
	if notifyCreate.StatusCode != http.StatusOK {
		notifyCreate.Body.Close()
		t.Fatalf("notify channel create failed: %d", notifyCreate.StatusCode)
	}
	var notifyOut struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(notifyCreate.Body).Decode(&notifyOut); err != nil {
		notifyCreate.Body.Close()
		t.Fatal(err)
	}
	notifyCreate.Body.Close()
	assertResponseAuditCorrelation(t, st, notifyCreate, "notify.channel.create", "notify:send")

	notifyDelete := doJSON(t, handler, http.MethodPost, "/api/notify/channels/delete",
		string(mustJSON(t, map[string]string{"id": notifyOut.ID})), cookies, csrf)
	notifyDelete.Body.Close()
	if notifyDelete.StatusCode != http.StatusOK {
		t.Fatalf("notify channel delete failed: %d", notifyDelete.StatusCode)
	}
	assertResponseAuditCorrelation(t, st, notifyDelete, "notify.channel.delete", "notify:send")

	monitorCreate := doJSON(t, handler, http.MethodPost, "/api/monitors",
		`{"name":"audit-monitor","type":"tcp","target":"example.com:443","assign_all":true}`, cookies, csrf)
	if monitorCreate.StatusCode != http.StatusOK {
		monitorCreate.Body.Close()
		t.Fatalf("monitor create failed: %d", monitorCreate.StatusCode)
	}
	var monitorOut struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(monitorCreate.Body).Decode(&monitorOut); err != nil {
		monitorCreate.Body.Close()
		t.Fatal(err)
	}
	monitorCreate.Body.Close()
	assertResponseAuditCorrelation(t, st, monitorCreate, "monitor.create", "monitor:admin")

	monitorDelete := doJSON(t, handler, http.MethodPost, "/api/monitors/delete",
		string(mustJSON(t, map[string]string{"id": monitorOut.ID})), cookies, csrf)
	monitorDelete.Body.Close()
	if monitorDelete.StatusCode != http.StatusOK {
		t.Fatalf("monitor delete failed: %d", monitorDelete.StatusCode)
	}
	assertResponseAuditCorrelation(t, st, monitorDelete, "monitor.delete", "monitor:admin")

	ddnsCreate := doJSON(t, handler, http.MethodPost, "/api/ddns",
		`{"name":"audit-delete-ddns","node_id":"audit-node","provider":"webhook","domains":["delete.example.com"],"enable_ipv4":true,"webhook_url":"https://dns.example.com/update"}`, cookies, csrf)
	if ddnsCreate.StatusCode != http.StatusOK {
		ddnsCreate.Body.Close()
		t.Fatalf("ddns create failed: %d", ddnsCreate.StatusCode)
	}
	var ddnsOut struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(ddnsCreate.Body).Decode(&ddnsOut); err != nil {
		ddnsCreate.Body.Close()
		t.Fatal(err)
	}
	ddnsCreate.Body.Close()

	ddnsDelete := doJSON(t, handler, http.MethodPost, "/api/ddns/delete",
		string(mustJSON(t, map[string]string{"id": ddnsOut.ID})), cookies, csrf)
	ddnsDelete.Body.Close()
	if ddnsDelete.StatusCode != http.StatusOK {
		t.Fatalf("ddns delete failed: %d", ddnsDelete.StatusCode)
	}
	assertResponseAuditCorrelation(t, st, ddnsDelete, "ddns.delete", "ddns:admin")

	tokenCreate := doJSON(t, handler, http.MethodPost, "/api/tokens",
		`{"name":"audit-revoke","scopes":["node:read"]}`, cookies, csrf)
	if tokenCreate.StatusCode != http.StatusOK {
		tokenCreate.Body.Close()
		t.Fatalf("token create failed: %d", tokenCreate.StatusCode)
	}
	var tokenOut struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(tokenCreate.Body).Decode(&tokenOut); err != nil {
		tokenCreate.Body.Close()
		t.Fatal(err)
	}
	tokenCreate.Body.Close()

	tokenRevoke := doJSON(t, handler, http.MethodPost, "/api/tokens/revoke",
		string(mustJSON(t, map[string]string{"token_id": tokenOut.ID})), cookies, csrf)
	tokenRevoke.Body.Close()
	if tokenRevoke.StatusCode != http.StatusOK {
		t.Fatalf("token revoke failed: %d", tokenRevoke.StatusCode)
	}
	assertResponseAuditCorrelation(t, st, tokenRevoke, "token.revoke", "token:admin")

	tunnelCreate := doJSON(t, handler, http.MethodPost, "/api/tunnels",
		`{"name":"audit-delete-tunnel","node_id":"audit-node","tunnel_id":"tun-delete","ingress":[{"hostname":"delete.example.com","service":"http://localhost:8088"}]}`, cookies, csrf)
	if tunnelCreate.StatusCode != http.StatusOK {
		tunnelCreate.Body.Close()
		t.Fatalf("tunnel create failed: %d", tunnelCreate.StatusCode)
	}
	var tunnelOut struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(tunnelCreate.Body).Decode(&tunnelOut); err != nil {
		tunnelCreate.Body.Close()
		t.Fatal(err)
	}
	tunnelCreate.Body.Close()
	assertResponseAuditCorrelation(t, st, tunnelCreate, "tunnel.create", "tunnel:admin")

	tunnelDelete := doJSON(t, handler, http.MethodPost, "/api/tunnels/delete",
		string(mustJSON(t, map[string]string{"id": tunnelOut.ID})), cookies, csrf)
	tunnelDelete.Body.Close()
	if tunnelDelete.StatusCode != http.StatusOK {
		t.Fatalf("tunnel delete failed: %d", tunnelDelete.StatusCode)
	}
	assertResponseAuditCorrelation(t, st, tunnelDelete, "tunnel.delete", "tunnel:admin")

	nftPlan := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan",
		`{"node_id":"audit-node","public_tcp":[443]}`, cookies, csrf)
	if nftPlan.StatusCode != http.StatusOK {
		nftPlan.Body.Close()
		t.Fatalf("nft plan failed: %d", nftPlan.StatusCode)
	}
	var approvalOut struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(nftPlan.Body).Decode(&approvalOut); err != nil {
		nftPlan.Body.Close()
		t.Fatal(err)
	}
	nftPlan.Body.Close()

	approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": approvalOut.ID, "queue_apply": false})), cookies, csrf)
	approve.Body.Close()
	if approve.StatusCode != http.StatusOK {
		t.Fatalf("network approval failed: %d", approve.StatusCode)
	}
	assertResponseAuditCorrelation(t, st, approve, "network.nft.approve", "network:apply")

	logout := doJSON(t, handler, http.MethodPost, "/api/logout", "{}", cookies, csrf)
	logout.Body.Close()
	if logout.StatusCode != http.StatusOK {
		t.Fatalf("logout failed: %d", logout.StatusCode)
	}
	assertResponseAuditCorrelation(t, st, logout, "logout", "")
}

func TestPrivilegedAllowAuditUsesRequestID(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	enroll := doJSON(t, handler, http.MethodPost, "/api/nodes/enroll-token",
		`{"node_id":"audit-node","name":"Audit Node"}`, cookies, csrf)
	enroll.Body.Close()
	if enroll.StatusCode != http.StatusOK {
		t.Fatalf("enroll failed: %d", enroll.StatusCode)
	}
	enrollRequestID := enroll.Header.Get("X-Lattice-Request-ID")
	if enrollRequestID == "" {
		t.Fatal("enroll response missing request id")
	}
	enrollAudit := auditByActionAndScope(t, st, "node.enroll", "node:admin")
	if enrollAudit.CorrelationID != enrollRequestID {
		t.Fatalf("node enroll audit correlation_id %q != request id %q", enrollAudit.CorrelationID, enrollRequestID)
	}

	task := doJSON(t, handler, http.MethodPost, "/api/tasks",
		`{"targets":["audit-node"],"interpreter":"sh","script":"echo ok"}`, cookies, csrf)
	task.Body.Close()
	if task.StatusCode != http.StatusOK {
		t.Fatalf("task create failed: %d", task.StatusCode)
	}
	taskRequestID := task.Header.Get("X-Lattice-Request-ID")
	if taskRequestID == "" {
		t.Fatal("task create response missing request id")
	}
	taskAudit := auditByActionAndScope(t, st, "task.create", "task:run")
	if taskAudit.CorrelationID != taskRequestID {
		t.Fatalf("task create audit correlation_id %q != request id %q", taskAudit.CorrelationID, taskRequestID)
	}

	tokenCreate := doJSON(t, handler, http.MethodPost, "/api/tokens",
		`{"name":"audit-token","scopes":["node:read"]}`, cookies, csrf)
	tokenCreate.Body.Close()
	if tokenCreate.StatusCode != http.StatusOK {
		t.Fatalf("token create failed: %d", tokenCreate.StatusCode)
	}
	tokenRequestID := tokenCreate.Header.Get("X-Lattice-Request-ID")
	if tokenRequestID == "" {
		t.Fatal("token create response missing request id")
	}
	tokenAudit := auditByActionAndScope(t, st, "token.create", "token:admin")
	if tokenAudit.CorrelationID != tokenRequestID {
		t.Fatalf("token create audit correlation_id %q != request id %q", tokenAudit.CorrelationID, tokenRequestID)
	}

	nftPlan := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan",
		`{"node_id":"audit-node","public_tcp":[443]}`, cookies, csrf)
	nftPlan.Body.Close()
	if nftPlan.StatusCode != http.StatusOK {
		t.Fatalf("nft plan failed: %d", nftPlan.StatusCode)
	}
	nftRequestID := nftPlan.Header.Get("X-Lattice-Request-ID")
	if nftRequestID == "" {
		t.Fatal("nft plan response missing request id")
	}
	nftAudit := auditByActionAndScope(t, st, "network.nft.plan", "network:plan")
	if nftAudit.CorrelationID != nftRequestID {
		t.Fatalf("nft plan audit correlation_id %q != request id %q", nftAudit.CorrelationID, nftRequestID)
	}

	ddnsCreate := doJSON(t, handler, http.MethodPost, "/api/ddns",
		`{"name":"audit-ddns","node_id":"audit-node","provider":"webhook","domains":["audit.example.com"],"enable_ipv4":true,"webhook_url":"https://dns.example.com/update"}`, cookies, csrf)
	ddnsCreate.Body.Close()
	if ddnsCreate.StatusCode != http.StatusOK {
		t.Fatalf("ddns create failed: %d", ddnsCreate.StatusCode)
	}
	ddnsRequestID := ddnsCreate.Header.Get("X-Lattice-Request-ID")
	if ddnsRequestID == "" {
		t.Fatal("ddns create response missing request id")
	}
	ddnsAudit := auditByActionAndScope(t, st, "ddns.create", "ddns:admin")
	if ddnsAudit.CorrelationID != ddnsRequestID {
		t.Fatalf("ddns create audit correlation_id %q != request id %q", ddnsAudit.CorrelationID, ddnsRequestID)
	}

	tunnelCreate := doJSON(t, handler, http.MethodPost, "/api/tunnels",
		`{"name":"audit-tunnel","node_id":"audit-node","tunnel_id":"tun-audit","ingress":[{"hostname":"app.example.com","service":"http://localhost:8088"}]}`, cookies, csrf)
	if tunnelCreate.StatusCode != http.StatusOK {
		tunnelCreate.Body.Close()
		t.Fatalf("tunnel create failed: %d", tunnelCreate.StatusCode)
	}
	var tunnelOut struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(tunnelCreate.Body).Decode(&tunnelOut); err != nil {
		tunnelCreate.Body.Close()
		t.Fatal(err)
	}
	tunnelCreate.Body.Close()
	tunnelPlan := doJSON(t, handler, http.MethodPost, "/api/tunnels/plan",
		string(mustJSON(t, map[string]string{"id": tunnelOut.ID})), cookies, csrf)
	tunnelPlan.Body.Close()
	if tunnelPlan.StatusCode != http.StatusOK {
		t.Fatalf("tunnel plan failed: %d", tunnelPlan.StatusCode)
	}
	tunnelRequestID := tunnelPlan.Header.Get("X-Lattice-Request-ID")
	if tunnelRequestID == "" {
		t.Fatal("tunnel plan response missing request id")
	}
	tunnelAudit := auditByActionAndScope(t, st, "tunnel.plan", "tunnel:admin")
	if tunnelAudit.CorrelationID != tunnelRequestID {
		t.Fatalf("tunnel plan audit correlation_id %q != request id %q", tunnelAudit.CorrelationID, tunnelRequestID)
	}

	if err := st.UpsertNode(model.Node{
		ID:                 "audit-node",
		Name:               "Audit Node",
		WireGuardIP:        "10.66.0.1",
		WireGuardPublicKey: wgKey(1),
		WireGuardPort:      51820,
	}); err != nil {
		t.Fatal(err)
	}
	wireGuardPlan := doJSON(t, handler, http.MethodPost, "/api/network/wireguard/plan",
		`{"node_id":"audit-node"}`, cookies, csrf)
	wireGuardPlan.Body.Close()
	if wireGuardPlan.StatusCode != http.StatusOK {
		t.Fatalf("wireguard plan failed: %d", wireGuardPlan.StatusCode)
	}
	wireGuardRequestID := wireGuardPlan.Header.Get("X-Lattice-Request-ID")
	if wireGuardRequestID == "" {
		t.Fatal("wireguard plan response missing request id")
	}
	wireGuardAudit := auditByActionAndScope(t, st, "network.wireguard.plan", "network:plan")
	if wireGuardAudit.CorrelationID != wireGuardRequestID {
		t.Fatalf("wireguard plan audit correlation_id %q != request id %q", wireGuardAudit.CorrelationID, wireGuardRequestID)
	}
}

func TestAPIErrorEnvelopeHasStableMachineFields(t *testing.T) {
	handler, _ := newTestServer(t)
	res := doJSON(t, handler, http.MethodPost, "/api/login",
		`{"username":"admin","password":"wrong-password"}`, nil, "")
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized login, got %d", res.StatusCode)
	}

	var out struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if out.Error.Code != "unauthorized" {
		t.Fatalf("expected unauthorized code, got %q", out.Error.Code)
	}
	if out.Error.Message != "invalid credentials" {
		t.Fatalf("expected sanitized message, got %q", out.Error.Message)
	}
	if out.Error.RequestID == "" {
		t.Fatal("expected request id in error envelope")
	}
	if got := res.Header.Get("X-Lattice-Request-ID"); got != out.Error.RequestID {
		t.Fatalf("expected response request id header %q to match envelope %q", got, out.Error.RequestID)
	}
}

func TestAPIErrorEnvelopeRedactsServerSideFailures(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		wantCode    string
		wantMessage string
	}{
		{
			name:        "internal",
			status:      http.StatusInternalServerError,
			wantCode:    "internal_error",
			wantMessage: "internal server error",
		},
		{
			name:        "upstream",
			status:      http.StatusBadGateway,
			wantCode:    "bad_gateway",
			wantMessage: "upstream service error",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeError(rec, tc.status, errors.New("provider failed at /var/lib/lattice/state.json with token=secret-value"))
			res := rec.Result()
			defer res.Body.Close()

			var out model.APIErrorResponse
			if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
				t.Fatal(err)
			}
			if out.Error.Code != tc.wantCode {
				t.Fatalf("expected code %q, got %q", tc.wantCode, out.Error.Code)
			}
			if out.Error.Message != tc.wantMessage {
				t.Fatalf("expected redacted message %q, got %q", tc.wantMessage, out.Error.Message)
			}
			if strings.Contains(out.Error.Message, "/var/lib") || strings.Contains(out.Error.Message, "secret-value") {
				t.Fatalf("server-side error leaked implementation detail: %q", out.Error.Message)
			}
		})
	}
}

func TestCapabilityDenialUsesStableErrorCode(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"kv:read"}, nil)

	res := doBearerJSON(t, handler, http.MethodPost, "/api/kv",
		`{"bucket":"default","key":"a","value":"b"}`, token)
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected forbidden for missing kv:write, got %d", res.StatusCode)
	}
	var out model.APIErrorResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Error.Code != "capability_denied" {
		t.Fatalf("expected capability_denied code, got %q", out.Error.Code)
	}
}

// Admin (scope "*") can create a task: the previously-buggy static:write gate
// is gone, so task:run alone (via the route) is sufficient.
func TestTaskCreateNoLongerRequiresStaticWrite(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/tasks",
		`{"targets":["n1"],"interpreter":"sh","script":"echo hi"}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("task create should succeed for admin, got %d", res.StatusCode)
	}
}

func TestTaskCreateRejectsUnsafeParameters(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	longScript := strings.Repeat("x", 64*1024+1)

	cases := []struct {
		name string
		body string
	}{
		{name: "unsupported interpreter", body: `{"targets":["n1"],"interpreter":"perl","script":"echo hi"}`},
		{name: "too much timeout", body: `{"targets":["n1"],"interpreter":"sh","script":"echo hi","timeout_sec":601}`},
		{name: "negative timeout", body: `{"targets":["n1"],"interpreter":"sh","script":"echo hi","timeout_sec":-1}`},
		{name: "too much output", body: `{"targets":["n1"],"interpreter":"sh","script":"echo hi","output_limit":262145}`},
		{name: "negative output", body: `{"targets":["n1"],"interpreter":"sh","script":"echo hi","output_limit":-1}`},
		{name: "oversize script", body: string(mustJSON(t, map[string]any{"targets": []string{"n1"}, "interpreter": "sh", "script": longScript}))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := doJSON(t, handler, http.MethodPost, "/api/tasks", tc.body, cookies, csrf)
			defer res.Body.Close()
			if res.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected unsafe task create to be rejected, got %d", res.StatusCode)
			}
		})
	}
}

func TestKVRejectsSlashInKey(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/kv",
		`{"bucket":"default","key":"a/b","value":"x"}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("slash in key should be rejected, got %d", res.StatusCode)
	}
}

func TestStaticRejectsSlashInBucket(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/static",
		`{"bucket":"a/b","path":"index.html","content":"x"}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("slash in bucket should be rejected, got %d", res.StatusCode)
	}
}

// A session minted against one store must remain valid when a fresh server is
// constructed over the same store (i.e. across a restart).
func TestSessionSurvivesServerRestart(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv1, _ := New(Options{Store: st, AdminPassword: testAdminPass})
	h1 := srv1.Handler()
	cookies, _ := loginSession(t, h1)

	srv2, _ := New(Options{Store: st, AdminPassword: testAdminPass})
	h2 := srv2.Handler()
	res := doJSON(t, h2, http.MethodGet, "/api/me", "", cookies, "")
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("session should survive restart, got %d", res.StatusCode)
	}
}

func TestLogoutInvalidatesSession(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/logout", "{}", cookies, csrf)
	res.Body.Close()
	after := doJSON(t, handler, http.MethodGet, "/api/me", "", cookies, "")
	defer after.Body.Close()
	if after.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session should be dead after logout, got %d", after.StatusCode)
	}
}

// Full PAT lifecycle: create -> use via bearer -> revoke -> rejected.
func TestPATCreateUseAndRevoke(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	create := doJSON(t, handler, http.MethodPost, "/api/tokens",
		`{"name":"ci","scopes":["node:read"]}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("token create failed: %d", create.StatusCode)
	}
	var created struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	json.NewDecoder(create.Body).Decode(&created)
	if created.Token == "" {
		t.Fatal("expected token credential")
	}

	// Use the bearer token on a node:read endpoint.
	req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
	req.Header.Set("Authorization", "Bearer "+created.Token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("bearer token should access node:read, got %d", rec.Result().StatusCode)
	}

	// Bearer must be denied a scope it lacks (task:run).
	req = httptest.NewRequest(http.MethodPost, "/api/tasks", bytes.NewBufferString(`{"targets":["n"],"script":"x"}`))
	req.Header.Set("Authorization", "Bearer "+created.Token)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("bearer without task:run should be forbidden, got %d", rec.Result().StatusCode)
	}

	// Revoke, then the same token must be rejected.
	rev := doJSON(t, handler, http.MethodPost, "/api/tokens/revoke",
		`{"token_id":"`+created.ID+`"}`, cookies, csrf)
	rev.Body.Close()
	req = httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
	req.Header.Set("Authorization", "Bearer "+created.Token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token must be rejected, got %d", rec.Result().StatusCode)
	}
}

// The token list must never expose secrets or hashes.
func TestTokenListHidesHash(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	doJSON(t, handler, http.MethodPost, "/api/tokens", `{"name":"x","scopes":["node:read"]}`, cookies, csrf).Body.Close()
	res := doJSON(t, handler, http.MethodGet, "/api/tokens", "", cookies, "")
	defer res.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(res.Body)
	if bytes.Contains(buf.Bytes(), []byte("token_hash")) || bytes.Contains(buf.Bytes(), []byte("pbkdf2")) {
		t.Fatalf("token list leaked secret material: %s", buf.String())
	}
}

func TestNodeListHidesTokenHash(t *testing.T) {
	handler, st := newTestServer(t)
	if err := st.UpsertNode(model.Node{ID: "n1", Name: "node one", TokenHash: "pbkdf2-sha256$210000$salt$hash"}); err != nil {
		t.Fatal(err)
	}
	cookies, _ := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodGet, "/api/nodes", "", cookies, "")
	defer res.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(res.Body)
	if bytes.Contains(buf.Bytes(), []byte("token_hash")) || bytes.Contains(buf.Bytes(), []byte("pbkdf2")) {
		t.Fatalf("node list leaked token hash: %s", buf.String())
	}
}

func TestPATServerAllowlistFiltersNodeList(t *testing.T) {
	handler, st := newTestServer(t)
	st.UpsertNode(model.Node{ID: "node-a", Name: "allowed"})
	st.UpsertNode(model.Node{ID: "node-b", Name: "denied"})
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"node:read"}, []string{"node-a"})

	res := doBearerJSON(t, handler, http.MethodGet, "/api/nodes", "", token)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("node list failed: %d", res.StatusCode)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(res.Body)
	if !bytes.Contains(buf.Bytes(), []byte("node-a")) || bytes.Contains(buf.Bytes(), []byte("node-b")) {
		t.Fatalf("allowlisted token saw wrong nodes: %s", buf.String())
	}
}

func TestPATServerAllowlistAppliesToTaskTargets(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"task:run"}, []string{"node-a"})

	res := doBearerJSON(t, handler, http.MethodPost, "/api/tasks", `{"targets":["node-b"],"script":"echo nope"}`, token)
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("allowlisted token must not queue task on node-b, got %d", res.StatusCode)
	}
}

func TestTaskReadAndRunScopesAreSeparated(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	doJSON(t, handler, http.MethodPost, "/api/tasks", `{"targets":["node-a"],"script":"echo allowed"}`, cookies, csrf).Body.Close()
	doJSON(t, handler, http.MethodPost, "/api/tasks", `{"targets":["node-b"],"script":"echo denied"}`, cookies, csrf).Body.Close()
	if err := st.AddTaskResult(model.TaskResult{TaskID: "task-a", NodeID: "node-a", ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddTaskResult(model.TaskResult{TaskID: "task-b", NodeID: "node-b", ExitCode: 0}); err != nil {
		t.Fatal(err)
	}

	readToken := createPAT(t, handler, cookies, csrf, []string{"task:read"}, []string{"node-a"})
	writeToken := createPAT(t, handler, cookies, csrf, []string{"task:run"}, []string{"node-a"})

	create := doBearerJSON(t, handler, http.MethodPost, "/api/tasks", `{"targets":["node-a"],"script":"echo nope"}`, readToken)
	create.Body.Close()
	if create.StatusCode != http.StatusForbidden {
		t.Fatalf("task:read token must not create tasks, got %d", create.StatusCode)
	}

	list := doBearerJSON(t, handler, http.MethodGet, "/api/tasks", "", readToken)
	defer list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("task:read token should list tasks, got %d", list.StatusCode)
	}
	var tasks []map[string]any
	if err := json.NewDecoder(list.Body).Decode(&tasks); err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 {
		t.Fatalf("task:read token should see one allowlisted task, got %+v", tasks)
	}
	targets, ok := tasks[0]["targets"].([]any)
	if !ok || len(targets) != 1 || targets[0] != "node-a" {
		t.Fatalf("task:read token saw wrong task targets: %+v", tasks)
	}

	results := doBearerJSON(t, handler, http.MethodGet, "/api/task-results", "", readToken)
	defer results.Body.Close()
	if results.StatusCode != http.StatusOK {
		t.Fatalf("task:read token should list task results, got %d", results.StatusCode)
	}
	var visibleResults []map[string]any
	if err := json.NewDecoder(results.Body).Decode(&visibleResults); err != nil {
		t.Fatal(err)
	}
	if len(visibleResults) != 1 || visibleResults[0]["node_id"] != "node-a" {
		t.Fatalf("task:read token saw wrong results: %+v", visibleResults)
	}

	readWithRun := doBearerJSON(t, handler, http.MethodGet, "/api/tasks", "", writeToken)
	readWithRun.Body.Close()
	if readWithRun.StatusCode != http.StatusForbidden {
		t.Fatalf("task:run token must not read tasks, got %d", readWithRun.StatusCode)
	}
	resultsWithRun := doBearerJSON(t, handler, http.MethodGet, "/api/task-results", "", writeToken)
	resultsWithRun.Body.Close()
	if resultsWithRun.StatusCode != http.StatusForbidden {
		t.Fatalf("task:run token must not read task results, got %d", resultsWithRun.StatusCode)
	}
}

func TestPATServerAllowlistFiltersTasks(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	doJSON(t, handler, http.MethodPost, "/api/tasks", `{"targets":["node-a"],"script":"echo allowed"}`, cookies, csrf).Body.Close()
	doJSON(t, handler, http.MethodPost, "/api/tasks", `{"targets":["node-b"],"script":"echo denied"}`, cookies, csrf).Body.Close()
	token := createPAT(t, handler, cookies, csrf, []string{"task:read"}, []string{"node-a"})

	res := doBearerJSON(t, handler, http.MethodGet, "/api/tasks", "", token)
	defer res.Body.Close()
	var tasks []map[string]any
	if err := json.NewDecoder(res.Body).Decode(&tasks); err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 {
		t.Fatalf("allowlisted token should see one task, got %+v", tasks)
	}
	targets, ok := tasks[0]["targets"].([]any)
	if !ok || len(targets) != 1 || targets[0] != "node-a" {
		t.Fatalf("allowlisted token saw wrong task targets: %+v", tasks)
	}
}

func TestPATServerAllowlistAppliesToWireGuardPlanBody(t *testing.T) {
	handler, st := newTestServer(t)
	st.UpsertNode(model.Node{ID: "node-a", Name: "allowed", WireGuardIP: "10.66.0.1", WireGuardPublicKey: wgKey(1)})
	st.UpsertNode(model.Node{ID: "node-b", Name: "denied", WireGuardIP: "10.66.0.2", WireGuardPublicKey: wgKey(2)})
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"network:plan"}, []string{"node-a"})

	res := doBearerJSON(t, handler, http.MethodPost, "/api/network/wireguard/plan", `{"node_id":"node-b"}`, token)
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("allowlisted token must not plan wireguard for node-b, got %d", res.StatusCode)
	}
}

func TestPATServerAllowlistPreventsFleetMonitorDelete(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	create := doJSON(t, handler, http.MethodPost, "/api/monitors",
		`{"name":"fleet","type":"tcp","target":"example.com:443","assign_all":true}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("monitor create failed: %d", create.StatusCode)
	}
	var mon struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(create.Body).Decode(&mon); err != nil {
		t.Fatal(err)
	}
	token := createPAT(t, handler, cookies, csrf, []string{"monitor:admin"}, []string{"node-a"})

	res := doBearerJSON(t, handler, http.MethodPost, "/api/monitors/delete", `{"id":"`+mon.ID+`"}`, token)
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("restricted token must not delete fleet monitor, got %d", res.StatusCode)
	}
}

func TestLoginRateLimited(t *testing.T) {
	handler, _ := newTestServer(t)
	limited := false
	for i := 0; i < 20; i++ {
		res := doJSON(t, handler, http.MethodPost, "/api/login", `{"username":"admin","password":"wrong"}`, nil, "")
		code := res.StatusCode
		res.Body.Close()
		if code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("expected login to be rate limited after repeated attempts")
	}
}
