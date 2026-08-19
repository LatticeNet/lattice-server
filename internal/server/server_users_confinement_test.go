package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func loginAs(t *testing.T, h http.Handler, username, password string) []*http.Cookie {
	t.Helper()
	rec := authedPost(t, h, nil, "", "/api/login", `{"username":"`+username+`","password":"`+password+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("login as %s failed: %d %s", username, rec.Code, rec.Body.String())
	}
	return rec.Result().Cookies()
}

func nodeIDsVisibleTo(t *testing.T, h http.Handler, cookies []*http.Cookie) []string {
	t.Helper()
	rec := authedGet(t, h, cookies, "/api/nodes")
	if rec.Code != http.StatusOK {
		t.Fatalf("list nodes: %d %s", rec.Code, rec.Body.String())
	}
	var out []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode nodes: %v (body %s)", err, rec.Body.String())
	}
	ids := make([]string, 0, len(out))
	for _, n := range out {
		ids = append(ids, n.ID)
	}
	return ids
}

func seedNodes(t *testing.T, st *store.Store, ids ...string) {
	t.Helper()
	for _, nodeID := range ids {
		if err := st.UpsertNode(model.Node{ID: nodeID, Name: nodeID}); err != nil {
			t.Fatalf("seed node %s: %v", nodeID, err)
		}
	}
}

// The point of the whole change. A confined account has to be confined when a
// human logs into it, not only when an API token carries the same field. Before
// this, model.User had no allowlist and the session principal was built with an
// empty one, which rbac.Allows reads as every node.
func TestAConfinedOperatorSessionSeesOnlyItsOwnNodes(t *testing.T) {
	h, st := newTestServer(t)
	seedNodes(t, st, "node-a", "node-b")
	adminCookies, csrf := loginSession(t, h)

	rec := authedPost(t, h, adminCookies, csrf, "/api/users",
		`{"username":"scoped","password":"`+testAdminPass+`","scopes":["node:read"],"server_allowlist":["node-a"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create confined user: %d %s", rec.Code, rec.Body.String())
	}

	// The admin is unconfined and still sees both, so a difference below is
	// confinement and not an empty fleet.
	if got := nodeIDsVisibleTo(t, h, adminCookies); len(got) != 2 {
		t.Fatalf("admin sees %v, want both nodes", got)
	}

	scopedCookies := loginAs(t, h, "scoped", testAdminPass)
	got := nodeIDsVisibleTo(t, h, scopedCookies)
	if len(got) != 1 || got[0] != "node-a" {
		t.Fatalf("confined operator sees %v, want only node-a", got)
	}
}

// An account created without the field keeps reaching everything, which is what
// every existing account is on the upgrade.
func TestAnUnconfinedOperatorStillSeesEveryNode(t *testing.T) {
	h, st := newTestServer(t)
	seedNodes(t, st, "node-a", "node-b")
	adminCookies, csrf := loginSession(t, h)

	rec := authedPost(t, h, adminCookies, csrf, "/api/users",
		`{"username":"open","password":"`+testAdminPass+`","scopes":["node:read"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create user: %d %s", rec.Code, rec.Body.String())
	}
	if got := nodeIDsVisibleTo(t, h, loginAs(t, h, "open", testAdminPass)); len(got) != 2 {
		t.Fatalf("unconfined operator sees %v, want both nodes", got)
	}
}

// Narrowing an account's reach is privilege-reducing, so it has to invalidate
// the sessions minted before it. Otherwise the operator keeps the tab they
// already had open and stays unconfined for as long as they do not log out.
func TestConfiningAnAccountEndsItsExistingSessions(t *testing.T) {
	h, st := newTestServer(t)
	seedNodes(t, st, "node-a", "node-b")
	adminCookies, csrf := loginSession(t, h)

	rec := authedPost(t, h, adminCookies, csrf, "/api/users",
		`{"username":"scoped","password":"`+testAdminPass+`","scopes":["node:read"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create user: %d %s", rec.Code, rec.Body.String())
	}
	var created userView
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	scopedCookies := loginAs(t, h, "scoped", testAdminPass)
	if got := nodeIDsVisibleTo(t, h, scopedCookies); len(got) != 2 {
		t.Fatalf("precondition: unconfined operator should see both, saw %v", got)
	}

	rec = authedPost(t, h, adminCookies, csrf, "/api/users/update",
		`{"id":"`+created.ID+`","scopes":["node:read"],"server_allowlist":["node-a"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("confine user: %d %s", rec.Code, rec.Body.String())
	}

	if rec := authedGet(t, h, scopedCookies, "/api/nodes"); rec.Code == http.StatusOK {
		t.Fatal("the session minted before confinement still works")
	}
}

// Confinement is what makes an administrator unable to administer users, so
// confining the last unconfined one leaves nobody who can undo it, including
// them: the account keeps "*" and still cannot reach the endpoint.
func TestRefusesToConfineTheLastUnrestrictedAdministrator(t *testing.T) {
	h, st := newTestServer(t)
	seedNodes(t, st, "node-a")
	adminCookies, csrf := loginSession(t, h)

	var admin model.User
	for _, u := range st.Users() {
		if hasWildcardScope(u.Scopes) {
			admin = u
		}
	}
	if admin.ID == "" {
		t.Fatal("no wildcard admin in a fresh store")
	}

	rec := authedPost(t, h, adminCookies, csrf, "/api/users/update",
		`{"id":"`+admin.ID+`","scopes":["*"],"server_allowlist":["node-a"]}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("confining the last unrestricted admin returned %d, want 409: %s", rec.Code, rec.Body.String())
	}

	// And it did not half-apply.
	after, _ := st.User(admin.ID)
	if len(after.ServerAllowlist) != 0 {
		t.Fatalf("refused but still wrote the allowlist: %v", after.ServerAllowlist)
	}

	// With a second unconfined administrator present it is recoverable, so it
	// goes through.
	rec = authedPost(t, h, adminCookies, csrf, "/api/users",
		`{"username":"admin2","password":"`+testAdminPass+`","scopes":["*"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create second admin: %d %s", rec.Code, rec.Body.String())
	}
	rec = authedPost(t, h, adminCookies, csrf, "/api/users/update",
		`{"id":"`+admin.ID+`","scopes":["*"],"server_allowlist":["node-a"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("confining an admin with a peer left returned %d: %s", rec.Code, rec.Body.String())
	}
}

// The trap in making update apply the field: every other reason to update a
// user (a scope change, a password reset) sends no allowlist, and treating that
// as "no confinement" would quietly widen the account back to the whole fleet.
// Absent means unchanged; an explicit empty list is how you widen on purpose.
func TestAnUpdateThatOmitsTheAllowlistLeavesConfinementAlone(t *testing.T) {
	h, st := newTestServer(t)
	seedNodes(t, st, "node-a", "node-b")
	adminCookies, csrf := loginSession(t, h)

	rec := authedPost(t, h, adminCookies, csrf, "/api/users",
		`{"username":"scoped","password":"`+testAdminPass+`","scopes":["node:read"],"server_allowlist":["node-a"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created userView
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	// A password reset, carrying no allowlist at all.
	rec = authedPost(t, h, adminCookies, csrf, "/api/users/update",
		`{"id":"`+created.ID+`","scopes":["node:read"],"password":"another correct horse battery"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	after, _ := st.User(created.ID)
	if len(after.ServerAllowlist) != 1 || after.ServerAllowlist[0] != "node-a" {
		t.Fatalf("a password reset changed the confinement to %v", after.ServerAllowlist)
	}

	// An explicit empty list widens on purpose.
	rec = authedPost(t, h, adminCookies, csrf, "/api/users/update",
		`{"id":"`+created.ID+`","scopes":["node:read"],"server_allowlist":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("widen: %d %s", rec.Code, rec.Body.String())
	}
	after, _ = st.User(created.ID)
	if len(after.ServerAllowlist) != 0 {
		t.Fatalf("an explicit empty list did not widen: %v", after.ServerAllowlist)
	}
}

// The console reads its own confinement from /api/me and uses it to decide what
// a principal may grant. That worked for a token and silently reported "every
// node" for a confined human, because the session principal had no allowlist to
// report.
func TestMeReportsAConfinedOperatorsOwnAllowlist(t *testing.T) {
	h, st := newTestServer(t)
	seedNodes(t, st, "node-a", "node-b")
	adminCookies, csrf := loginSession(t, h)

	rec := authedPost(t, h, adminCookies, csrf, "/api/users",
		`{"username":"scoped","password":"`+testAdminPass+`","scopes":["node:read"],"server_allowlist":["node-a"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}

	rec = authedGet(t, h, loginAs(t, h, "scoped", testAdminPass), "/api/me")
	if rec.Code != http.StatusOK {
		t.Fatalf("me: %d %s", rec.Code, rec.Body.String())
	}
	var me struct {
		ServerAllowlist []string `json:"server_allowlist"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if len(me.ServerAllowlist) != 1 || me.ServerAllowlist[0] != "node-a" {
		t.Fatalf("me reported allowlist %v, want [node-a]", me.ServerAllowlist)
	}
}
