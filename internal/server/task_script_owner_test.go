package server

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/sshguard"
)

// scriptRevealView is the reveal-script answer.
type scriptRevealView struct {
	OK              bool   `json:"ok"`
	ID              string `json:"id"`
	Interpreter     string `json:"interpreter"`
	Script          string `json:"script"`
	ScriptSHA256    string `json:"script_sha256"`
	ScriptSizeBytes int    `json:"script_size_bytes"`
}

// sessionStepUpGrant issues a step-up grant to the admin session in cookies,
// the way the TOTP and passkey endpoints do after a second factor.
func sessionStepUpGrant(t *testing.T, srv *Server, cookies []*http.Cookie) string {
	t.Helper()
	user, ok := srv.store.UserByUsername("admin")
	if !ok {
		t.Fatal("admin user missing")
	}
	sessionID := ""
	for _, cookie := range cookies {
		if cookie.Name == "lattice_session" {
			sessionID = cookie.Value
		}
	}
	grant, _, err := srv.issueStepUpGrant(principal{Principal: rbac.Principal{ActorID: user.ID}, sessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

// revealScopeToken mints an API token carrying scopes plus secrets:reveal,
// confined to allowlist when it is not empty.
func revealScopeToken(t *testing.T, srv *Server, handler http.Handler, cookies []*http.Cookie, csrf string, scopes, allowlist []string) string {
	t.Helper()
	if allowlist == nil {
		allowlist = []string{}
	}
	body := map[string]any{
		"name":             "reveal-owner",
		"scopes":           append(append([]string(nil), scopes...), rbac.SecretRevealScope),
		"server_allowlist": allowlist,
		"step_up_grant":    sessionStepUpGrant(t, srv, cookies),
	}
	res := doJSON(t, handler, http.MethodPost, "/api/tokens", string(mustJSON(t, body)), cookies, csrf)
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("token create: %d %s", res.StatusCode, raw)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out.Token
}

func revealTaskScriptAs(t *testing.T, handler http.Handler, taskID, token string) (int, []byte) {
	t.Helper()
	res := doBearerJSON(t, handler, http.MethodPost, "/api/tasks/reveal-script", `{"id":"`+taskID+`"}`, token)
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	return res.StatusCode, raw
}

// expectScriptOwnerRefusal asserts the owner-scope refusal: 403 with its
// code, a message naming the scope, and no trace of the secret.
func expectScriptOwnerRefusal(t *testing.T, handler http.Handler, taskID, token, secret, scope string) {
	t.Helper()
	status, raw := revealTaskScriptAs(t, handler, taskID, token)
	if status != http.StatusForbidden || apiErrorCodeOf(t, raw) != apiErrorRevealScriptOwnerScopeRequired {
		t.Fatalf("want 403 %s, got %d %s", apiErrorRevealScriptOwnerScopeRequired, status, raw)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("the owner-scope refusal carried the secret")
	}
	var out model.APIErrorResponse
	_ = json.Unmarshal(raw, &out)
	if !strings.Contains(out.Error.Message, scope) {
		t.Fatalf("the refusal must name %q: %q", scope, out.Error.Message)
	}
}

func expectScriptRevealed(t *testing.T, handler http.Handler, taskID, token, secret string) scriptRevealView {
	t.Helper()
	status, raw := revealTaskScriptAs(t, handler, taskID, token)
	if status != http.StatusOK {
		t.Fatalf("want 200, got %d %s", status, raw)
	}
	var out scriptRevealView
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if !out.OK || !strings.Contains(out.Script, secret) {
		t.Fatalf("the allowed reveal did not return the script: %+v", out)
	}
	return out
}

// createOwnedTask stores a task produced by approval, as approve would queue it.
func createOwnedTask(t *testing.T, srv *Server, taskID string, approval model.Approval, script string) {
	t.Helper()
	if err := srv.store.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.CreateTask(model.Task{ID: taskID, ApprovalID: approval.ID, Targets: []string{approval.NodeID},
		Interpreter: "sh", Script: script, Status: model.TaskQueued, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
}

// seedPluginTask stores a task shaped like pluginTaskHost.Enqueue's, with the
// given actor, on node-a, carrying plugin-marker-48c0.
func seedPluginTask(t *testing.T, srv *Server, taskID, actorID string, approval model.Approval) {
	t.Helper()
	seedAgentUpdateNode(t, srv.store)
	if err := srv.store.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.CreateTask(model.Task{ID: taskID, ApprovalID: approval.ID, ActorID: actorID, Targets: []string{approval.NodeID},
		Interpreter: "sh", Script: "echo plugin-marker-48c0\n", Status: model.TaskQueued, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
}

// Every task kind whose script core renders with a credential another
// surface owns asks for that surface's reveal scope on top of task:read and
// the reveal gate. Without the owner check each of these reveals the secret
// to a task:read token holding secrets:reveal.
func TestTaskScriptRevealAsksTheOwningSurface(t *testing.T) {
	cases := []struct {
		name string
		// seed returns the task, its node, and a string that appears in the
		// script only because the script carries the secret.
		seed        func(t *testing.T, h *revealHarness) (taskID, nodeID, secret string)
		ownerScopes []string
		// alsoAllowed are other scope sets the owning door accepts.
		alsoAllowed [][]string
		scope       string
		// unrestricted: the owner scope counts only without a server
		// allowlist restriction. Otherwise it is checked on the node, and a
		// token confined to that node passes.
		unrestricted bool
	}{
		{
			name: "line-user apply on an adopted line",
			seed: func(t *testing.T, h *revealHarness) (string, string, string) {
				line, u := seedLineUserFixture(t, h.srv)
				u.Bindings = nil
				if err := h.srv.putVpnUser(u); err != nil {
					t.Fatal(err)
				}
				add := filePlan(t, h.srv, lineUserOpAdd, u.ID, line.LineHashID)
				if err := approvePlan(t, h.srv, add); err != nil {
					t.Fatal(err)
				}
				tasks := tasksFor(h.srv, add.ID)
				if len(tasks) != 1 {
					t.Fatalf("approve queued %d tasks", len(tasks))
				}
				return tasks[0].ID, line.NodeID, u.Credentials[0].UUID
			},
			ownerScopes: []string{"proxy:admin"}, scope: "proxy:admin", unrestricted: true,
		},
		{
			name: "line-user apply on a managed line",
			seed: func(t *testing.T, h *revealHarness) (string, string, string) {
				line, u := seedManagedLineUserFixture(t, h.srv)
				add := filePlan(t, h.srv, lineUserOpAdd, u.ID, line.LineHashID)
				if err := approvePlan(t, h.srv, add); err != nil {
					t.Fatal(err)
				}
				tasks := tasksFor(h.srv, add.ID)
				if len(tasks) != 1 {
					t.Fatalf("approve queued %d tasks", len(tasks))
				}
				return tasks[0].ID, line.NodeID, "super-secret-reality-private-key"
			},
			ownerScopes: []string{"proxy:admin"}, scope: "proxy:admin", unrestricted: true,
		},
		{
			name: "managed-line rollout apply",
			seed: func(t *testing.T, h *revealHarness) (string, string, string) {
				seedManagedLineNode(t, h.srv, "node-a", realityInventoryLines())
				seedManagedLineUser(t, h.srv)
				approval, _ := compileApproval(t, h.srv)
				script := h.srv.managedLineApplyScript(approval)
				// The fragment, with the user's UUID and the REALITY key, is
				// embedded base64-encoded.
				_, rest, ok := strings.Cut(script, "FRAG_B64='")
				fragment, _, _ := strings.Cut(rest, "'")
				if !ok || fragment == "" {
					t.Fatalf("managed-line script has no fragment:\n%s", script)
				}
				createOwnedTask(t, h.srv, "task-managed-line", approval, script)
				return "task-managed-line", "node-a", fragment
			},
			ownerScopes: []string{"proxy:admin"}, scope: "proxy:admin", unrestricted: true,
		},
		{
			name: "proxy config apply",
			seed: func(t *testing.T, h *revealHarness) (string, string, string) {
				seedAgentUpdateNode(t, h.srv.store)
				createOwnedTask(t, h.srv, "task-proxycore",
					model.Approval{ID: "approval-proxycore", NodeID: "node-a", Plugin: proxyCorePlugin, Status: model.ApprovalApproved},
					"set -e\ncat > /etc/sing-box/config.json <<'EOF'\n{\"users\":[{\"uuid\":\"33333333-3333-4333-8333-333333333333\"}]}\nEOF\n")
				return "task-proxycore", "node-a", "33333333-3333-4333-8333-333333333333"
			},
			ownerScopes: []string{"proxy:admin"}, scope: "proxy:admin", unrestricted: true,
		},
		{
			name: "sing-box user sync",
			seed: func(t *testing.T, h *revealHarness) (string, string, string) {
				lineHash := seedRevealLine(t, h)
				now := h.srv.now()
				if err := h.srv.putVpnUser(VpnUser{ID: "vpn-user-a", Email: "alice@example.com", Enabled: true,
					Credentials: []VpnCredential{{Protocol: "vless", UUID: "44444444-4444-4444-8444-444444444444", Flow: "xtls-rprx-vision"}},
					CreatedAt:   now, UpdatedAt: now}); err != nil {
					t.Fatal(err)
				}
				res := doJSON(t, h.handler, http.MethodPost, "/api/proxy/managed/users",
					`{"node_id":"node-a","line_hash_id":"`+lineHash+`","bind_user_ids":["vpn-user-a"]}`, h.cookies, h.csrf)
				raw, _ := io.ReadAll(res.Body)
				res.Body.Close()
				var out struct {
					TaskID string `json:"task_id"`
				}
				if err := json.Unmarshal(raw, &out); err != nil || res.StatusCode != http.StatusOK || out.TaskID == "" {
					t.Fatalf("users bind: %d %s", res.StatusCode, raw)
				}
				return out.TaskID, "node-a", "44444444-4444-4444-8444-444444444444"
			},
			ownerScopes: []string{"proxy:admin"}, scope: "proxy:admin", unrestricted: true,
		},
		{
			name: "SSH Guard apply",
			seed: func(t *testing.T, h *revealHarness) (string, string, string) {
				seedAgentUpdateNode(t, h.srv.store)
				enrolSSHGuard(t, h.srv.store, "node-a")
				seedArmApproval(t, h.srv.store, "approval-arm", "node-a", model.ApprovalApproved, knockTestPorts, time.Now().UTC())
				approval, _ := h.srv.store.Approval("approval-arm")
				script, err := sshguard.ApplyScriptFromPlan(approval.Plan)
				if err != nil {
					t.Fatal(err)
				}
				createOwnedTask(t, h.srv, "task-sshguard", approval, script)
				return "task-sshguard", "node-a", strconv.Itoa(knockTestPorts[0])
			},
			ownerScopes: []string{"sshguard:read", "network:plan"}, scope: "sshguard:read",
			alsoAllowed: [][]string{{"sshguard:admin", "network:plan"}},
		},
		{
			name: "task whose approval is gone",
			seed: func(t *testing.T, h *revealHarness) (string, string, string) {
				seedAgentUpdateNode(t, h.srv.store)
				if err := h.srv.store.CreateTask(model.Task{ID: "task-orphan", ApprovalID: "approval-gone", Targets: []string{"node-a"},
					Interpreter: "sh", Script: "echo orphan-marker-2d7e\n", Status: model.TaskQueued, CreatedAt: time.Now().UTC()}); err != nil {
					t.Fatal(err)
				}
				return "task-orphan", "node-a", "orphan-marker-2d7e"
			},
			ownerScopes: []string{"*"}, scope: "*", unrestricted: true,
		},
		{
			// A renderer nobody classified fails closed.
			name: "approval plugin nobody classified",
			seed: func(t *testing.T, h *revealHarness) (string, string, string) {
				seedAgentUpdateNode(t, h.srv.store)
				createOwnedTask(t, h.srv, "task-unclassified",
					model.Approval{ID: "approval-unclassified", NodeID: "node-a", Plugin: "brand-new-renderer", Status: model.ApprovalApproved},
					"echo unclassified-marker-61af\n")
				return "task-unclassified", "node-a", "unclassified-marker-61af"
			},
			ownerScopes: []string{"*"}, scope: "*", unrestricted: true,
		},
		{
			// A plugin may be named like a listed core label. The enqueuer
			// recorded on the task wins over the label's listing.
			name: "plugin task under a core label",
			seed: func(t *testing.T, h *revealHarness) (string, string, string) {
				seedPluginTask(t, h.srv, "task-plugin", "plugin:selfdns",
					model.Approval{ID: "approval-plugin-label", NodeID: "node-a", Plugin: "selfdns", Status: model.ApprovalApproved})
				return "task-plugin", "node-a", "plugin-marker-48c0"
			},
			ownerScopes: []string{"*"}, scope: "*", unrestricted: true,
		},
		{
			// The approval alone says plugin operation (Service and Method),
			// so the script is the plugin's even under a core label.
			name: "plugin operation approval under a core label",
			seed: func(t *testing.T, h *revealHarness) (string, string, string) {
				seedPluginTask(t, h.srv, "task-plugin-op", "admin",
					model.Approval{ID: "approval-plugin-op", NodeID: "node-a", Plugin: "selfdns", Service: "dns", Method: "apply", Status: model.ApprovalApproved})
				return "task-plugin-op", "node-a", "plugin-marker-48c0"
			},
			ownerScopes: []string{"*"}, scope: "*", unrestricted: true,
		},
		{
			name: "rerun of a plugin task",
			seed: func(t *testing.T, h *revealHarness) (string, string, string) {
				seedPluginTask(t, h.srv, "task-plugin-source", "plugin:selfdns",
					model.Approval{ID: "approval-plugin-source", NodeID: "node-a", Plugin: "selfdns", Status: model.ApprovalApproved})
				source, _ := h.srv.store.Task("task-plugin-source")
				rerun := source
				rerun.ID, rerun.ApprovalID, rerun.ActorID, rerun.RerunOfTaskID = "task-plugin-rerun", "", "admin", source.ID
				if err := h.srv.store.CreateTask(rerun); err != nil {
					t.Fatal(err)
				}
				return "task-plugin-rerun", "node-a", "plugin-marker-48c0"
			},
			ownerScopes: []string{"*"}, scope: "*", unrestricted: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRevealHarness(t)
			taskID, nodeID, secret := tc.seed(t, h)
			if task, ok := h.srv.store.Task(taskID); !ok || !strings.Contains(task.Script, secret) {
				t.Fatalf("control failed: the task script should carry the secret (found=%v)", ok)
			}
			mint := func(scopes, allowlist []string) string {
				return revealScopeToken(t, h.srv, h.handler, h.cookies, h.csrf, append([]string{"task:read"}, scopes...), allowlist)
			}

			expectScriptOwnerRefusal(t, h.handler, taskID, mint(nil, nil), secret, tc.scope)
			denied := false
			for _, ev := range h.srv.store.AuditEvents() {
				if ev.Action == "task.script.reveal" && ev.Decision == "deny" && ev.Metadata["task_id"] == taskID && strings.Contains(ev.Scope, tc.scope) {
					denied = true
				}
			}
			if !denied {
				t.Fatal("the owner-scope refusal must be audited under task.script.reveal with the scope it asked for")
			}
			if tc.unrestricted {
				// The owning object is fleet-wide: the scope on a token confined
				// to this node is not the scope its own door asks for.
				expectScriptOwnerRefusal(t, h.handler, taskID, mint(tc.ownerScopes, []string{nodeID}), secret, tc.scope)
			} else {
				expectScriptRevealed(t, h.handler, taskID, mint(tc.ownerScopes, []string{nodeID}), secret)
			}
			expectScriptRevealed(t, h.handler, taskID, mint(tc.ownerScopes, nil), secret)
			for _, scopes := range tc.alsoAllowed {
				expectScriptRevealed(t, h.handler, taskID, mint(scopes, nil), secret)
			}

			// A full administrator's session with step-up is unchanged.
			res := doJSON(t, h.handler, http.MethodPost, "/api/tasks/reveal-script",
				withGrant(t, `{"id":"`+taskID+`"}`, h.stepUp()), h.cookies, h.csrf)
			raw, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode != http.StatusOK || !strings.Contains(string(raw), secret) {
				t.Fatalf("admin session with step-up: want 200 with the script, got %d", res.StatusCode)
			}
		})
	}
}

// A script that carries no other surface's credential keeps the old gate:
// task:read and the reveal gate, nothing more. That covers an approval kind
// with no secret in its script, and a direct sing-box add and user list,
// whose arguments are the author's own and which are not the user sync's
// `sb --json user add|del`.
func TestTaskScriptRevealOwnerGateLeavesOtherScriptsAlone(t *testing.T) {
	h := newRevealHarness(t)
	seedAgentUpdateNode(t, h.srv.store)
	createOwnedTask(t, h.srv, "task-nft",
		model.Approval{ID: "approval-nft", NodeID: "node-a", Plugin: "nft", Status: model.ApprovalApproved},
		"echo nft-marker-5c1d\n")
	if err := h.srv.store.CreateTask(model.Task{ID: "task-direct", Targets: []string{"node-a"}, Interpreter: "sh",
		Script: "sb --json add reality 443\nsb --json user list 'VLESS-REALITY-31001.json'\necho direct-marker-9e2b\n", Status: model.TaskQueued, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	reader := revealScopeToken(t, h.srv, h.handler, h.cookies, h.csrf, []string{"task:read"}, nil)
	expectScriptRevealed(t, h.handler, "task-nft", reader, "nft-marker-5c1d")
	expectScriptRevealed(t, h.handler, "task-direct", reader, "direct-marker-9e2b")
}

// coreApplyScriptPlugins reads, from the renderers' own source, every plugin
// core renders an apply script for: the case labels of the switches on
// approval.Plugin and the operands of approval.Plugin == X in
// applyScriptFor, applyScriptForWithServer and approveApprovalCore. Labels
// come back as spelled (an identifier or a quoted literal).
func coreApplyScriptPlugins(t *testing.T) map[string]bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "server.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	isPluginField := func(e ast.Expr) bool { return types.ExprString(e) == "approval.Plugin" }
	found := map[string]bool{}
	// applyScriptFor is both a function and a method; both are scanned.
	renderers := map[string]bool{"applyScriptFor": true, "applyScriptForWithServer": true, "approveApprovalCore": true}
	seen := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !renderers[fn.Name.Name] {
			continue
		}
		seen[fn.Name.Name] = true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.SwitchStmt:
				if n.Tag == nil || !isPluginField(n.Tag) {
					return true
				}
				for _, stmt := range n.Body.List {
					for _, label := range stmt.(*ast.CaseClause).List {
						found[types.ExprString(label)] = true
					}
				}
			case *ast.BinaryExpr:
				if n.Op == token.EQL && isPluginField(n.X) {
					found[types.ExprString(n.Y)] = true
				}
			}
			return true
		})
	}
	if len(seen) != len(renderers) {
		t.Fatalf("renderers found in server.go: %v, want all of %v", seen, renderers)
	}
	return found
}

// Every plugin core renders an apply script for has its reveal classified:
// the owner scope when its script carries another surface's credential, or
// a listing in revealableApprovalScripts when it carries none. The listing is
// checked the other way too, so an entry cannot outlive its renderer. A label
// that misses both is admin-only (TestUnclassifiedApprovalScriptIsAdminOnly),
// so a miss here costs reveal access, never a secret.
func TestEveryCoreApplyScriptIsClassifiedForReveal(t *testing.T) {
	// labels maps each label, as the renderers spell it, to its value and to
	// the owner scope its reveal needs; "" means listed as carrying no secret.
	labels := map[string]struct{ plugin, scope string }{
		"witnessPlugin":            {witnessPlugin, "notify:admin"},
		"singBoxLineUserPlugin":    {singBoxLineUserPlugin, "proxy:admin"},
		"singBoxManagedLinePlugin": {singBoxManagedLinePlugin, "proxy:admin"},
		"proxyCorePlugin":          {proxyCorePlugin, "proxy:admin"},
		"sshGuardPlugin":           {sshGuardPlugin, "sshguard:read,network:plan"},
		// Refused outright before the owner check; unlisted, so admin-only
		// should one ever reach it.
		"lineChainPlugin":       {lineChainPlugin, "*"},
		"singBoxLineMetaPlugin": {singBoxLineMetaPlugin, ""},
		"agentUpdatePlugin":     {agentUpdatePlugin, ""},
		`"selfdns"`:             {"selfdns", ""},
		`"cftunnel"`:            {"cftunnel", ""},
		`"wireguard"`:           {"wireguard", ""},
		`"nftpolicy"`:           {"nftpolicy", ""},
		`"nft"`:                 {"nft", ""},
	}
	found := coreApplyScriptPlugins(t)
	if !found["witnessPlugin"] || !found[`"cftunnel"`] {
		t.Fatalf("the source scan found too little, so it is not reading the renderers: %v", found)
	}
	rendered := map[string]bool{}
	for label := range found {
		c, ok := labels[label]
		if !ok {
			t.Errorf("core renders an apply script for %s, which is not classified for reveal: it is admin-only until "+
				"approvalScriptOwner names its owner or revealableApprovalScripts lists it, and either way it belongs here", label)
			continue
		}
		rendered[c.plugin] = true
	}
	for label, c := range labels {
		if !found[label] {
			t.Errorf("%s is classified here, but no renderer names it any more", label)
		}
		owner, owned := approvalScriptOwner(model.Approval{Plugin: c.plugin, NodeID: "node-a"})
		if c.scope == "" {
			if owned {
				t.Errorf("%s should be listed in revealableApprovalScripts, but its reveal needs %s", label, owner.scope)
			}
			continue
		}
		if !owned || owner.scope != c.scope {
			t.Errorf("%s: reveal owner scope %q, want %q", label, owner.scope, c.scope)
		}
	}
	for plugin := range revealableApprovalScripts {
		if !rendered[plugin] {
			t.Errorf("revealableApprovalScripts lists %q, which no core renderer writes a script for", plugin)
		}
	}
}

// An approval plugin nobody classified, and a task a plugin enqueued, are
// revealable by a full administrator and nobody else, however many other
// scopes a principal holds. A plugin named like a listed core label gets no
// listing from the name.
func TestUnclassifiedApprovalScriptIsAdminOnly(t *testing.T) {
	everything := principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{
		"task:read", "proxy:admin", "vpncore:admin", "notify:admin", "sshguard:admin", "network:plan",
		"dns:admin", "netpolicy:admin", "tunnel:admin", "node:admin", "netguard:admin",
	}}}
	admin := principal{Principal: rbac.Principal{ActorID: "root", Scopes: []string{"*"}}}
	confinedAdmin := principal{Principal: rbac.Principal{ActorID: "root", Scopes: []string{"*"}, ServerAllowlist: []string{"node-a"}}}

	unclassified, ok := approvalScriptOwner(model.Approval{Plugin: "brand-new-renderer", NodeID: "node-a"})
	if !ok {
		t.Fatal("an unclassified approval plugin must have an owner")
	}
	pluginTask, ok := pluginTaskScriptOwner("selfdns")
	if !ok {
		t.Fatal("a plugin task must have an owner even when the plugin is named like a listed core label")
	}
	for name, owner := range map[string]taskScriptOwner{"unclassified approval plugin": unclassified, "plugin task": pluginTask} {
		if owner.scope != "*" || owner.allows(everything) || !owner.allows(admin) || owner.allows(confinedAdmin) {
			t.Errorf("%s: scope %q, every-other-scope=%v admin=%v confined admin=%v; want *, false, true, false",
				name, owner.scope, owner.allows(everything), owner.allows(admin), owner.allows(confinedAdmin))
		}
	}
}

// An SSH Guard approval with no node fails closed. rbac.Allows reads an
// empty node as any node, so without the check a principal confined to some
// other node would read the knock sequence.
func TestSSHGuardScriptOwnerFailsClosedWithoutANode(t *testing.T) {
	confined := principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"sshguard:read", "network:plan"}, ServerAllowlist: []string{"node-b"}}}
	unconfined := principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"sshguard:read", "network:plan"}}}
	noNode, ok := approvalScriptOwner(model.Approval{Plugin: sshGuardPlugin})
	if !ok {
		t.Fatal("an SSH Guard approval must have an owner")
	}
	if noNode.allows(confined) || noNode.allows(unconfined) {
		t.Fatalf("an SSH Guard approval with no node must refuse everyone: confined=%v unconfined=%v",
			noNode.allows(confined), noNode.allows(unconfined))
	}
	// Control: the same principals pass for an approval naming their node.
	withNode, _ := approvalScriptOwner(model.Approval{Plugin: sshGuardPlugin, NodeID: "node-b"})
	if !withNode.allows(confined) || !withNode.allows(unconfined) {
		t.Fatal("control failed: sshguard:read and network:plan on the approval's node should pass")
	}
}
