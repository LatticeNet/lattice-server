package server

import (
	"encoding/json"
	"net/http"
	"reflect"
	"sort"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Design 32 S3a: outbound policy targets. One node, several nodes, a group
// and the whole fleet are all one GroupNetPolicy that expands and merges by
// priority; scope_group_id stays an alias; a manual NetPolicy converts into a
// selector-scoped policy in one reviewed plan.

type outboundPolicyView struct {
	ID            string                `json:"id"`
	Name          string                `json:"name"`
	ScopeGroupID  string                `json:"scope_group_id"`
	Scope         *model.TargetSelector `json:"scope"`
	Target        model.TargetSelector  `json:"target"`
	TargetNodeIDs []string              `json:"target_node_ids"`
	Rules         []model.GroupNetRule  `json:"rules"`
	Enabled       bool                  `json:"enabled"`
	Priority      int                   `json:"priority"`
}

type outboundPlanOut struct {
	Affected []struct {
		NodeID     string `json:"node_id"`
		ApprovalID string `json:"approval_id"`
		PlanSHA    string `json:"plan_sha"`
	} `json:"affected"`
	Conflicts []struct {
		NodeID string `json:"node_id"`
		Reason string `json:"reason"`
	} `json:"conflicts"`
	Orphaned []string `json:"orphaned"`
}

// outboundFleet enrolls nodes with addresses and returns the session.
func outboundFleet(t *testing.T, ids ...string) (http.Handler, *store.Store, []*http.Cookie, string) {
	t.Helper()
	handler, st := newTestServerWithPublicURL(t, "https://203.0.113.99")
	cookies, csrf := loginSession(t, handler)
	for i, id := range ids {
		enrollNamedNodeToken(t, handler, cookies, csrf, id, id)
		setNodeIP(t, st, id, "10.66.0."+string(rune('1'+i))+"/32", "203.0.113."+string(rune('1'+i)))
	}
	return handler, st, cookies, csrf
}

func postPolicy(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, body string) (int, outboundPolicyView, string) {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/group-policies", body, cookies, csrf)
	raw := readBody(t, res)
	var view outboundPolicyView
	if res.StatusCode == http.StatusOK {
		if err := json.Unmarshal([]byte(raw), &view); err != nil {
			t.Fatal(err)
		}
	}
	return res.StatusCode, view, raw
}

func planOutbound(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf string) outboundPlanOut {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/group-policies/plan", "{}", cookies, csrf)
	raw := readBody(t, res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("group plan = %d %s", res.StatusCode, raw)
	}
	var out outboundPlanOut
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func affectedNodes(plan outboundPlanOut) []string {
	out := make([]string, 0, len(plan.Affected))
	for _, a := range plan.Affected {
		out = append(out, a.NodeID)
	}
	sort.Strings(out)
	return out
}

const allowHTTPS = `"rules":[{"id":"https","action":"allow","direction":"egress","protocol":"tcp","ports":[443],"remote":{"kind":"any"}}]`

// The S3a test row: a group-target policy and a three-node policy are each one
// GroupNetPolicy and plan every member.
func TestOutboundPolicyGroupAndThreeNodeTargetsPlanEveryMember(t *testing.T) {
	handler, st, cookies, csrf := outboundFleet(t, "n1", "n2", "n3", "n4", "n5")
	web := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"name":"Web","slug":"web","members":["n1","n2"]}`, cookies, csrf))

	code, group, raw := postPolicy(t, handler, cookies, csrf, `{"name":"web egress","scope":{"groups":["`+web.ID+`"]},"enabled":true,`+allowHTTPS+`}`)
	if code != http.StatusOK {
		t.Fatalf("group-target policy = %d %s", code, raw)
	}
	code, three, raw := postPolicy(t, handler, cookies, csrf, `{"scope":{"nodes":["n5","n3","n4"]},"enabled":true,`+allowHTTPS+`}`)
	if code != http.StatusOK {
		t.Fatalf("three-node policy = %d %s", code, raw)
	}
	if got := st.GroupPolicies(); len(got) != 2 {
		t.Fatalf("two targets must be two GroupNetPolicy documents, got %d", len(got))
	}
	if len(st.NetPolicies()) != 0 {
		t.Fatal("authoring must not write a NetPolicy per node")
	}
	if group.ScopeGroupID != web.ID || !reflect.DeepEqual(group.Target, model.TargetSelector{Groups: []string{web.ID}}) {
		t.Fatalf("one-group scope must mirror scope_group_id: %+v", group)
	}
	if !reflect.DeepEqual(three.Target.Nodes, []string{"n3", "n4", "n5"}) || three.ScopeGroupID != "" {
		t.Fatalf("three-node scope stored as %+v / %q", three.Target, three.ScopeGroupID)
	}
	if !reflect.DeepEqual(three.TargetNodeIDs, []string{"n3", "n4", "n5"}) || !reflect.DeepEqual(group.TargetNodeIDs, []string{"n1", "n2"}) {
		t.Fatalf("views must resolve their targets: %v / %v", three.TargetNodeIDs, group.TargetNodeIDs)
	}

	plan := planOutbound(t, handler, cookies, csrf)
	if got := affectedNodes(plan); !reflect.DeepEqual(got, []string{"n1", "n2", "n3", "n4", "n5"}) {
		t.Fatalf("plan must cover every member of both targets, got %v (conflicts %+v)", got, plan.Conflicts)
	}
	for _, a := range plan.Affected {
		np, ok := st.NetPolicy(a.NodeID)
		if !ok || !np.GroupDerived || a.ApprovalID == "" {
			t.Fatalf("%s: want a group-derived policy and an approval, got %+v %v", a.NodeID, np, a.ApprovalID)
		}
	}
}

// A stored scope_group_id policy reads as a one-group selector, in the view,
// the plan and the approve freshness check.
func TestOutboundPolicyStoredScopeGroupIDReadsAsOneGroupSelector(t *testing.T) {
	handler, st, cookies, csrf := outboundFleet(t, "n1", "n2", "n3")
	web := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"name":"Web","slug":"web","members":["n1","n2"]}`, cookies, csrf))
	if err := st.UpsertGroupPolicy(model.GroupNetPolicy{
		ID: "gnp_old", ScopeGroupID: web.ID, Enabled: true,
		Rules: []model.GroupNetRule{{ID: "r1", Action: "allow", Direction: "egress", Protocol: "tcp", Ports: []int{443}, Remote: model.NetEndpoint{Kind: model.NetRefAny}}},
	}); err != nil {
		t.Fatal(err)
	}

	res := doJSON(t, handler, http.MethodGet, "/api/group-policies", "", cookies, csrf)
	var list struct {
		Policies []outboundPolicyView `json:"policies"`
	}
	if err := json.Unmarshal([]byte(readBody(t, res)), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Policies) != 1 {
		t.Fatalf("want the stored policy, got %+v", list.Policies)
	}
	view := list.Policies[0]
	if view.Scope != nil {
		t.Fatalf("reading must not rewrite the stored document, scope = %+v", view.Scope)
	}
	if !reflect.DeepEqual(view.Target, model.TargetSelector{Groups: []string{web.ID}}) || !reflect.DeepEqual(view.TargetNodeIDs, []string{"n1", "n2"}) {
		t.Fatalf("stored scope_group_id must read as the one-group selector: %+v", view)
	}

	plan := planOutbound(t, handler, cookies, csrf)
	if got := affectedNodes(plan); !reflect.DeepEqual(got, []string{"n1", "n2"}) {
		t.Fatalf("stored policy must plan its group's members, got %v", got)
	}
	approval, _ := st.Approval(plan.Affected[0].ApprovalID)
	approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": false, "plan_sha256": planSHA256(approval.Plan)})),
		cookies, csrf)
	if approve.StatusCode != http.StatusOK {
		t.Fatalf("approving a stored-alias plan = %d %s", approve.StatusCode, readBody(t, approve))
	}
	approve.Body.Close()

	// A write naming only scope_group_id, the old client's shape, keeps working.
	code, written, raw := postPolicy(t, handler, cookies, csrf, `{"scope_group_id":"`+web.ID+`","enabled":true,`+allowHTTPS+`}`)
	if code != http.StatusOK || !reflect.DeepEqual(written.Target, model.TargetSelector{Groups: []string{web.ID}}) || written.ScopeGroupID != web.ID {
		t.Fatalf("alias write = %d %s", code, raw)
	}
}

// A selector-scoped plan is held to the same approve-time freshness as a
// group one: dropping a node from the target makes its pending plan stale.
func TestOutboundPolicySelectorApprovalGoesStaleWhenTheTargetChanges(t *testing.T) {
	handler, st, cookies, csrf := outboundFleet(t, "n1", "n2")
	code, view, raw := postPolicy(t, handler, cookies, csrf, `{"scope":{"nodes":["n1","n2"]},"enabled":true,`+allowHTTPS+`}`)
	if code != http.StatusOK {
		t.Fatalf("create = %d %s", code, raw)
	}
	plan := planOutbound(t, handler, cookies, csrf)
	var n2Approval string
	for _, a := range plan.Affected {
		if a.NodeID == "n2" {
			n2Approval = a.ApprovalID
		}
	}
	approval, ok := st.Approval(n2Approval)
	if !ok {
		t.Fatalf("no approval for n2: %+v", plan.Affected)
	}
	if code, _, raw := postPolicy(t, handler, cookies, csrf, `{"id":"`+view.ID+`","scope":{"nodes":["n1"]},"enabled":true,`+allowHTTPS+`}`); code != http.StatusOK {
		t.Fatalf("narrow = %d %s", code, raw)
	}
	approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": n2Approval, "queue_apply": false, "plan_sha256": planSHA256(approval.Plan)})),
		cookies, csrf)
	if approve.StatusCode != http.StatusConflict {
		t.Fatalf("a plan for a node the policy no longer targets must be stale, got %d %s", approve.StatusCode, readBody(t, approve))
	}
	approve.Body.Close()
	// The re-plan reports n2 as orphaned rather than silently dropping it.
	if replan := planOutbound(t, handler, cookies, csrf); !reflect.DeepEqual(replan.Orphaned, []string{"n2"}) {
		t.Fatalf("n2 must be reported orphaned, got %+v", replan.Orphaned)
	}
}

func TestOutboundPolicyScopeValidation(t *testing.T) {
	handler, _, cookies, csrf := outboundFleet(t, "n1", "n2")
	web := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"name":"Web","slug":"web","members":["n1"]}`, cookies, csrf))
	cases := map[string]string{
		"no target":                     `{"enabled":true}`,
		"empty scope":                   `{"scope":{},"enabled":true}`,
		"alias disagrees with scope":    `{"scope_group_id":"` + web.ID + `","scope":{"nodes":["n1"]},"enabled":true}`,
		"whole fleet with nodes":        `{"scope":{"all":true,"nodes":["n1"]},"enabled":true}`,
		"whole fleet with groups":       `{"scope":{"all":true,"groups":["` + web.ID + `"]},"enabled":true}`,
		"unknown node":                  `{"scope":{"nodes":["ghost"]},"enabled":true}`,
		"unknown group":                 `{"scope":{"groups":["grp_ghost"]},"enabled":true}`,
		"unknown excluded node":         `{"scope":{"all":true,"exclude":["ghost"]},"enabled":true}`,
		"exclude with only nodes":       `{"scope":{"nodes":["n1","n2"],"exclude":["n2"]},"enabled":true}`,
		"unknown remote group":          `{"scope":{"nodes":["n1"]},"enabled":true,"rules":[{"id":"r","action":"allow","direction":"egress","protocol":"tcp","ports":[22],"remote":{"kind":"group","group_id":"grp_ghost"}}]}`,
		"alias naming an unknown group": `{"scope_group_id":"grp_ghost","enabled":true}`,
	}
	for name, body := range cases {
		if code, _, raw := postPolicy(t, handler, cookies, csrf, body); code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d %s", name, code, raw)
		}
	}
	// The whole fleet minus one node is a valid target.
	code, view, raw := postPolicy(t, handler, cookies, csrf, `{"scope":{"all":true,"exclude":["n2"]},"enabled":true,`+allowHTTPS+`}`)
	if code != http.StatusOK || !reflect.DeepEqual(view.TargetNodeIDs, []string{"n1"}) {
		t.Fatalf("whole fleet minus n2 = %d %s", code, raw)
	}
}

// Scope rule (design 32 D1, applied to outbound policy): a node-restricted
// principal may target only explicit nodes it administers; a group or
// whole-fleet selector, a remote group, and an edit or delete of a policy
// whose stored scope has either need an unrestricted principal. Expansion of
// a stored selector happens at an unrestricted planner's plan, so a confined
// author's group target would otherwise grow past its allowlist with no write.
func TestOutboundPolicyRestrictedPrincipalScope(t *testing.T) {
	handler, st, cookies, csrf := outboundFleet(t, "n1", "n2")
	inReach := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"name":"In","slug":"in","members":["n1"]}`, cookies, csrf))
	confined := createPAT(t, handler, cookies, csrf, []string{"netpolicy:admin", "netpolicy:read"}, []string{"n1"})

	post := func(body string) (int, string) {
		res := doBearerJSON(t, handler, http.MethodPost, "/api/group-policies", body, confined)
		raw := readBody(t, res)
		var out struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal([]byte(raw), &out)
		return res.StatusCode, out.ID
	}
	refused := map[string]string{
		"group it fully reaches": `{"scope":{"groups":["` + inReach.ID + `"]},"enabled":true}`,
		"group by alias":         `{"scope_group_id":"` + inReach.ID + `","enabled":true}`,
		"whole fleet":            `{"scope":{"all":true},"enabled":true}`,
		"node outside allowlist": `{"scope":{"nodes":["n2"]},"enabled":true}`,
		"unknown node":           `{"scope":{"nodes":["ghost"]},"enabled":true}`,
		"remote group":           `{"scope":{"nodes":["n1"]},"enabled":true,"rules":[{"id":"r","action":"allow","direction":"egress","protocol":"tcp","ports":[22],"remote":{"kind":"group","group_id":"` + inReach.ID + `"}}]}`,
		"unreadable remote node": `{"scope":{"nodes":["n1"]},"enabled":true,"rules":[{"id":"r","action":"allow","direction":"egress","protocol":"tcp","ports":[22],"remote":{"kind":"node","node_id":"n2"}}]}`,
	}
	for name, body := range refused {
		if code, _ := post(body); code != http.StatusForbidden {
			t.Errorf("%s: confined token want 403, got %d", name, code)
		}
	}
	if n := len(st.GroupPolicies()); n != 0 {
		t.Fatalf("refused writes must not land, found %d", n)
	}

	code, ownID := post(`{"scope":{"nodes":["n1"]},"enabled":true,` + allowHTTPS + `}`)
	if code != http.StatusOK {
		t.Fatalf("confined token must target its own node, got %d", code)
	}

	// An unrestricted operator's group policy is out of the confined token's
	// reach to edit or delete, even narrowing it to n1.
	_, fleet, _ := postPolicy(t, handler, cookies, csrf, `{"scope":{"groups":["`+inReach.ID+`"]},"enabled":true,`+allowHTTPS+`}`)
	if code, _ := post(`{"id":"` + fleet.ID + `","scope":{"nodes":["n1"]},"enabled":true}`); code != http.StatusForbidden {
		t.Fatalf("confined token must not rewrite a group-scoped policy, got %d", code)
	}
	if gp, _ := st.GroupPolicy(fleet.ID); gp.Scope == nil || len(gp.Scope.Groups) != 1 {
		t.Fatalf("the refused edit must not land: %+v", gp)
	}
	del := func(id string) int {
		res := doBearerJSON(t, handler, http.MethodPost, "/api/group-policies/delete", `{"id":"`+id+`"}`, confined)
		res.Body.Close()
		return res.StatusCode
	}
	if code := del(fleet.ID); code != http.StatusForbidden {
		t.Fatalf("confined token must not delete a group-scoped policy, got %d", code)
	}
	if code := del(ownID); code != http.StatusOK {
		t.Fatalf("confined token must delete its own node policy, got %d", code)
	}
}

// Removing a node from the fleet strips it from every outbound policy scope,
// so a deleted node never comes back as a target.
func TestNodeDeleteStripsOutboundPolicyScopes(t *testing.T) {
	_, st, _, _ := outboundFleet(t, "n1", "n2")
	if err := st.UpsertGroupPolicy(model.GroupNetPolicy{ID: "gnp_s", Enabled: true,
		Scope: &model.TargetSelector{Nodes: []string{"n1", "n2"}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertGroupPolicy(model.GroupNetPolicy{ID: "gnp_x", Enabled: true,
		Scope: &model.TargetSelector{All: true, Exclude: []string{"n2"}}}); err != nil {
		t.Fatal(err)
	}
	report, _, err := st.DeleteNode("n2")
	if err != nil {
		t.Fatal(err)
	}
	if report.GroupPolicyScopesStripped != 2 {
		t.Fatalf("cascade report counted %d scopes, want 2", report.GroupPolicyScopesStripped)
	}
	s, _ := st.GroupPolicy("gnp_s")
	x, _ := st.GroupPolicy("gnp_x")
	if !reflect.DeepEqual(s.Scope.Nodes, []string{"n1"}) || len(x.Scope.Exclude) != 0 || !x.Scope.All {
		t.Fatalf("scopes after delete: %+v / %+v", s.Scope, x.Scope)
	}
}

// The group-pair matrix stays a view of group-targeted policies: every group
// in a policy's selector is a row.
func TestNetPolicyMatrixReadsSelectorGroups(t *testing.T) {
	handler, _, cookies, csrf := outboundFleet(t, "n1", "n2", "n3")
	a := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups", `{"name":"A","slug":"a","members":["n1"]}`, cookies, csrf))
	b := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups", `{"name":"B","slug":"b","members":["n2"]}`, cookies, csrf))
	c := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups", `{"name":"C","slug":"c","members":["n3"]}`, cookies, csrf))
	if code, _, raw := postPolicy(t, handler, cookies, csrf, `{"scope":{"groups":["`+a.ID+`","`+b.ID+`"]},"enabled":true,"rules":[{"id":"r","action":"allow","direction":"egress","protocol":"tcp","ports":[22],"remote":{"kind":"group","group_id":"`+c.ID+`"}}]}`); code != http.StatusOK {
		t.Fatalf("create = %d %s", code, raw)
	}
	res := doJSON(t, handler, http.MethodGet, "/api/netpolicy/matrix", "", cookies, csrf)
	var out struct {
		Cells []struct {
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"cells"`
	}
	if err := json.Unmarshal([]byte(readBody(t, res)), &out); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, cell := range out.Cells {
		got[cell.From+">"+cell.To] = true
	}
	if !got[a.ID+">"+c.ID] || !got[b.ID+">"+c.ID] || len(got) != 2 {
		t.Fatalf("matrix cells %+v, want A>C and B>C", out.Cells)
	}
}
