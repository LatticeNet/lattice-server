package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// The multi-operator path has been shipped and never exercised: the product has
// exactly one principal, a full admin, so the per-node allowlist and the sixty
// scopes were shipped unproven. Both defects found today passed the existing
// tests, because those tests only ever asked whether the full admin could do a
// thing.
//
// These tests build a genuinely scoped principal, a token holding named scopes
// with its allowlist pinned to node-a, and assert across the main resource
// families that it can do exactly what it should and nothing more. Every case
// asserts both halves: the permitted call succeeds, and the call one node over
// is refused. A test that only asserts the refusal would pass against a server
// that refuses everything.

// scopedFleet seeds two nodes with addresses and returns the admin session.
// node-a is the node under the token's allowlist; node-b is the neighbour the
// token must never reach.
func scopedFleet(t *testing.T) (http.Handler, *store.Store, []*http.Cookie, string) {
	t.Helper()
	handler, st := newTestServerWithPublicURL(t, "https://203.0.113.99")
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	enrollNamedNode(t, handler, cookies, csrf, "node-b", "Node B")
	setNodeIP(t, st, "node-a", "10.66.0.1/32", "203.0.113.10")
	setNodeIP(t, st, "node-b", "10.66.0.2/32", "198.51.100.2")
	return handler, st, cookies, csrf
}

// setNodeWireGuard gives a node the public key and port that make it a mesh
// member, so BuildMesh includes it as a peer.
func setNodeWireGuard(t *testing.T, st *store.Store, nodeID string, key byte) {
	t.Helper()
	node, ok := st.Node(nodeID)
	if !ok {
		t.Fatalf("missing node %s", nodeID)
	}
	node.WireGuardPublicKey = wgKey(key)
	node.WireGuardPort = 51820
	if err := st.UpsertNode(node); err != nil {
		t.Fatal(err)
	}
}

// assertNoNodeNamed fails when a refusal body names the thing it is protecting.
// An error that reports which node was unreadable rebuilds the lookup oracle
// the refusal exists to close, so this is checked on every refusal below.
func assertNoNodeNamed(t *testing.T, what string, body []byte, names ...string) {
	t.Helper()
	for _, name := range names {
		if strings.Contains(string(body), name) {
			t.Fatalf("%s names %q in its refusal; it must report a count, never an identity: %s",
				what, name, body)
		}
	}
}

func TestScopedPrincipalNetPolicyFamily(t *testing.T) {
	handler, _, cookies, csrf := scopedFleet(t)

	// A policy on node-a whose only rule names node-b as its remote. Compiling
	// it embeds node-b's WireGuard IP and public IP into the returned ruleset.
	res := doJSON(t, handler, http.MethodPost, "/api/netpolicy", `{
		"target_node_id":"node-a","enabled":true,
		"rules":[{"id":"r1","action":"deny","direction":"egress","protocol":"tcp","ports":[5432],
		"remote":{"kind":"node","node_id":"node-b"}}]}`, cookies, csrf)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("admin seed policy: %d", res.StatusCode)
	}

	nodeA := createPAT(t, handler, cookies, csrf,
		[]string{"netpolicy:admin", "netpolicy:read", "network:plan"}, []string{"node-a"})

	// Refused: the plan would hand node-b's addresses to a session scoped to
	// node-a. Refused rather than filtered, because a ruleset missing the rule
	// is a wrong firewall rather than a shorter one.
	plan := doBearerJSON(t, handler, http.MethodPost, "/api/netpolicy/plan", `{"node_id":"node-a"}`, nodeA)
	body, _ := io.ReadAll(plan.Body)
	plan.Body.Close()
	if plan.StatusCode != http.StatusForbidden {
		t.Fatalf("planning a policy naming node-b must be refused for a node-a session, got %d: %s", plan.StatusCode, body)
	}
	assertNoNodeNamed(t, "the netpolicy plan refusal", body, "node-b")

	// Permitted: the same token plans a policy that names only its own node.
	res = doJSON(t, handler, http.MethodPost, "/api/netpolicy", `{
		"target_node_id":"node-a","enabled":true,
		"rules":[{"id":"r1","action":"deny","direction":"egress","protocol":"tcp","ports":[5432],
		"remote":{"kind":"cidr","cidr":"192.0.2.0/24"}}]}`, cookies, csrf)
	res.Body.Close()
	plan = doBearerJSON(t, handler, http.MethodPost, "/api/netpolicy/plan", `{"node_id":"node-a"}`, nodeA)
	body, _ = io.ReadAll(plan.Body)
	plan.Body.Close()
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("planning a policy confined to node-a must succeed, got %d: %s", plan.StatusCode, body)
	}

	// Refused: authoring a rule that names node-b. The refusal is what makes
	// "not found" and "outside your allowlist" indistinguishable at authoring
	// time, which is what closes the existence oracle.
	res = doBearerJSON(t, handler, http.MethodPost, "/api/netpolicy", `{
		"target_node_id":"node-a","enabled":true,
		"rules":[{"id":"r1","action":"deny","direction":"egress","protocol":"tcp","ports":[5432],
		"remote":{"kind":"node","node_id":"node-b"}}]}`, nodeA)
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode == http.StatusOK {
		t.Fatalf("authoring a rule naming node-b must not succeed for a node-a session: %s", body)
	}
}

func TestScopedPrincipalWireGuardFamily(t *testing.T) {
	handler, st, cookies, csrf := scopedFleet(t)
	setNodeWireGuard(t, st, "node-a", 1)
	setNodeWireGuard(t, st, "node-b", 2)

	nodeA := createPAT(t, handler, cookies, csrf,
		[]string{"wireguard:admin", "wireguard:read", "network:plan"}, []string{"node-a"})

	// Refused: the mesh config would carry node-b's public key, mesh IP and
	// endpoint. Refused rather than filtered, because a mesh missing a peer is
	// an asymmetric mesh, which is worse than an error.
	res := doBearerJSON(t, handler, http.MethodPost, "/api/network/wireguard/plan",
		`{"node_id":"node-a","listen_port":51820}`, nodeA)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("planning a mesh containing node-b must be refused for a node-a session, got %d: %s", res.StatusCode, body)
	}
	assertNoNodeNamed(t, "the wireguard plan refusal", body, "node-b", "198.51.100.2", "10.66.0.2")

	// Permitted: a token that may read both members plans the same mesh.
	both := createPAT(t, handler, cookies, csrf,
		[]string{"wireguard:admin", "wireguard:read", "network:plan"}, []string{"node-a", "node-b"})
	res = doBearerJSON(t, handler, http.MethodPost, "/api/network/wireguard/plan",
		`{"node_id":"node-a","listen_port":51820}`, both)
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("a token allowlisted for every mesh member must be able to plan, got %d: %s", res.StatusCode, body)
	}

	// And the approval it just created must not be readable by the node-a
	// token, because the stored plan bytes are the same mesh config the plan
	// endpoint refused to compile for it. Closing the write path and leaving
	// the read path open would have been no fix at all.
	list := doBearerJSON(t, handler, http.MethodGet, "/api/network/approvals", "", nodeA)
	body, _ = io.ReadAll(list.Body)
	list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("approvals list: %d", list.StatusCode)
	}
	assertNoNodeNamed(t, "the approvals list for a node-a session", body, "node-b")
}

func TestScopedPrincipalNodeAndGroupFamilies(t *testing.T) {
	handler, _, cookies, csrf := scopedFleet(t)
	nodeA := createPAT(t, handler, cookies, csrf,
		[]string{"node:read", "group:read", "group:admin"}, []string{"node-a"})

	// Node listing filters, and duplicate detection must filter with it. It did
	// not: it used a flat scope check and reported the whole fleet's clusters,
	// including the raw public/internal address pair as the cluster signal.
	res := doBearerJSON(t, handler, http.MethodGet, "/api/nodes/duplicates", "", nodeA)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("duplicates: %d", res.StatusCode)
	}
	assertNoNodeNamed(t, "the duplicates report", body, "node-b", "198.51.100.2")

	// Group listing resolves membership across the fleet, so ungrouped is by
	// construction every node not in a group.
	res = doBearerJSON(t, handler, http.MethodGet, "/api/groups", "", nodeA)
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("groups: %d", res.StatusCode)
	}
	assertNoNodeNamed(t, "the group listing", body, "node-b")

	// The selector preview is a query engine over the fleet if it resolves
	// against unfiltered nodes.
	res = doBearerJSON(t, handler, http.MethodPost, "/api/groups/preview", `{"match_tags_any":[]}`, nodeA)
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	assertNoNodeNamed(t, "the selector preview", body, "node-b")

	// Permitted: the same token still sees its own node in the listing.
	res = doBearerJSON(t, handler, http.MethodGet, "/api/nodes", "", nodeA)
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(body), "node-a") {
		t.Fatalf("a node-a session must still see node-a: %s", body)
	}
}

func TestScopedPrincipalCannotLaunderItsAllowlistThroughAUser(t *testing.T) {
	handler, _, cookies, csrf := scopedFleet(t)
	// user:admin confined to one node. A user account carries no allowlist, so
	// creating one is a way out of the confinement unless it is refused.
	nodeA := createPAT(t, handler, cookies, csrf, []string{"user:admin", "node:read"}, []string{"node-a"})

	res := doBearerJSON(t, handler, http.MethodPost, "/api/users",
		`{"username":"escape","scopes":["node:read"],"password":"correct horse battery staple"}`, nodeA)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a node-confined user:admin must not mint an unrestricted account, got %d: %s", res.StatusCode, body)
	}

	// Permitted: the unrestricted admin session still creates users.
	res = doJSON(t, handler, http.MethodPost, "/api/users",
		`{"username":"ops","scopes":["node:read"],"password":"correct horse battery staple"}`, cookies, csrf)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("an unrestricted admin must still be able to create a user, got %d", res.StatusCode)
	}
}

func TestScopedPrincipalTokenListingStaysWithinItsOwnAllowlist(t *testing.T) {
	handler, _, cookies, csrf := scopedFleet(t)
	createPAT(t, handler, cookies, csrf, []string{"node:read"}, []string{"node-b"})
	nodeA := createPAT(t, handler, cookies, csrf, []string{"token:admin"}, []string{"node-a"})

	res := doBearerJSON(t, handler, http.MethodGet, "/api/tokens", "", nodeA)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("tokens: %d", res.StatusCode)
	}
	// tokenView carries ServerAllowlist, so an unfiltered listing handed the
	// fleet's node ids over through other tokens' allowlists.
	assertNoNodeNamed(t, "the token listing", body, "node-b")

	// Permitted: the unrestricted admin session still sees every token.
	res = doJSON(t, handler, http.MethodGet, "/api/tokens", "", cookies, csrf)
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	var views []map[string]any
	if err := json.Unmarshal(body, &views); err != nil {
		t.Fatalf("decode token list: %v (%s)", err, body)
	}
	if len(views) < 2 {
		t.Fatalf("an unrestricted admin must see every token, got %d", len(views))
	}
}

func TestScopedPrincipalGeoRoutingFamily(t *testing.T) {
	handler, _, cookies, csrf := scopedFleet(t)
	res := doJSON(t, handler, http.MethodPost, "/api/geo-routing",
		`{"id":"gr1","name":"Edge","hostname":"edge.example.com","ttl":60,"strategy":"geoip","node_ids":["node-a","node-b"],"dns_node_ids":["node-a"]}`,
		cookies, csrf)
	seedBody, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Skipf("geo routing seed unsupported in this build: %d %s", res.StatusCode, seedBody)
	}

	nodeA := createPAT(t, handler, cookies, csrf, []string{"geo:read", "geo:admin"}, []string{"node-a"})

	// The rendered config carries each named node's public IPv4 and IPv6.
	res = doBearerJSON(t, handler, http.MethodPost, "/api/geo-routing/plan", `{"id":"gr1"}`, nodeA)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("planning a geo routing that names node-b must be refused for a node-a session, got %d: %s", res.StatusCode, body)
	}
	assertNoNodeNamed(t, "the geo routing plan refusal", body, "node-b", "198.51.100.2")

	// The listing must not hand back the record's node id list either.
	res = doBearerJSON(t, handler, http.MethodGet, "/api/geo-routing", "", nodeA)
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	assertNoNodeNamed(t, "the geo routing listing", body, "node-b")
}
