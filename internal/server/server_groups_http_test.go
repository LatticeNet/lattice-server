package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// groupHTTPView mirrors the JSON of groupView (embedded Group + resolved members
// + rollup) for decoding in tests.
type groupHTTPView struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Slug            string   `json:"slug"`
	Color           string   `json:"color"`
	Members         []string `json:"members"`
	ResolvedMembers []string `json:"resolved_members"`
	Rollup          struct {
		Total, Online, Offline, Disabled int
	} `json:"rollup"`
}

func setNodeMeta(t *testing.T, st *store.Store, nodeID string, mutate func(*model.Node)) {
	t.Helper()
	n, ok := st.Node(nodeID)
	if !ok {
		t.Fatalf("missing node %s", nodeID)
	}
	mutate(&n)
	if err := st.UpsertNode(n); err != nil {
		t.Fatal(err)
	}
}

func decodeGroup(t *testing.T, res *http.Response) groupHTTPView {
	t.Helper()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d", res.StatusCode)
	}
	var g groupHTTPView
	if err := json.NewDecoder(res.Body).Decode(&g); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestGroupCRUDHTTP(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")
	enrollNamedNodeToken(t, handler, cookies, csrf, "node-b", "Node B")
	setNodeMeta(t, st, "node-a", func(n *model.Node) { n.Online = true })

	// Create a group with one explicit member.
	created := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"name":"Web tier","slug":"web","color":"sky","members":["node-a"]}`, cookies, csrf))
	if created.ID == "" || !strings.HasPrefix(created.ID, "grp_") {
		t.Fatalf("expected minted grp_ id, got %q", created.ID)
	}
	if len(created.ResolvedMembers) != 1 || created.ResolvedMembers[0] != "node-a" {
		t.Fatalf("expected resolved member node-a, got %+v", created.ResolvedMembers)
	}
	if created.Rollup.Total != 1 || created.Rollup.Online != 1 {
		t.Fatalf("bad rollup: %+v", created.Rollup)
	}

	// List shows the group plus the ungrouped bucket (node-b).
	listRes := doJSON(t, handler, http.MethodGet, "/api/groups", "", cookies, csrf)
	defer listRes.Body.Close()
	if listRes.StatusCode != http.StatusOK {
		t.Fatalf("list failed: %d", listRes.StatusCode)
	}
	var list struct {
		Groups    []groupHTTPView `json:"groups"`
		Ungrouped struct {
			ResolvedMembers []string `json:"resolved_members"`
		} `json:"ungrouped"`
	}
	if err := json.NewDecoder(listRes.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list.Groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(list.Groups))
	}
	if len(list.Ungrouped.ResolvedMembers) != 1 || list.Ungrouped.ResolvedMembers[0] != "node-b" {
		t.Fatalf("expected node-b ungrouped, got %+v", list.Ungrouped.ResolvedMembers)
	}

	// Add node-b via the members endpoint.
	updated := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups/members",
		`{"group_id":"`+created.ID+`","add":["node-b"],"remove":["node-a"]}`, cookies, csrf))
	if len(updated.ResolvedMembers) != 1 || updated.ResolvedMembers[0] != "node-b" {
		t.Fatalf("expected member swap to node-b, got %+v", updated.ResolvedMembers)
	}

	// Slug is immutable on update: attempting to change it is silently kept.
	editRes := doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"id":"`+created.ID+`","name":"Web","slug":"changed","color":"violet"}`, cookies, csrf)
	edited := decodeGroup(t, editRes)
	if edited.Slug != "web" {
		t.Fatalf("slug should be immutable, got %q", edited.Slug)
	}
	if edited.Color != "violet" {
		t.Fatalf("color update lost: %q", edited.Color)
	}

	// Delete.
	delRes := doJSON(t, handler, http.MethodPost, "/api/groups/delete",
		`{"id":"`+created.ID+`"}`, cookies, csrf)
	delRes.Body.Close()
	if delRes.StatusCode != http.StatusOK {
		t.Fatalf("delete failed: %d", delRes.StatusCode)
	}
	if len(st.Groups()) != 0 {
		t.Fatalf("group not deleted: %+v", st.Groups())
	}
}

func TestGroupSeedAndPreview(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	for _, id := range []string{"n1", "n2", "n3"} {
		enrollNamedNodeToken(t, handler, cookies, csrf, id, id)
	}
	setNodeMeta(t, st, "n1", func(n *model.Node) { n.Tags = []string{"prod"}; n.Role = "edge" })
	setNodeMeta(t, st, "n2", func(n *model.Node) { n.Tags = []string{"prod"}; n.Role = "edge" })
	setNodeMeta(t, st, "n3", func(n *model.Node) { n.Tags = []string{"solo"}; n.Role = "db" })

	// Selector preview: role=edge matches n1+n2 only (no write).
	prevRes := doJSON(t, handler, http.MethodPost, "/api/groups/preview",
		`{"match_roles":["edge"]}`, cookies, csrf)
	defer prevRes.Body.Close()
	var prev struct {
		NodeIDs []string `json:"node_ids"`
		Count   int      `json:"count"`
	}
	if err := json.NewDecoder(prevRes.Body).Decode(&prev); err != nil {
		t.Fatal(err)
	}
	if prev.Count != 2 || len(prev.NodeIDs) != 2 {
		t.Fatalf("expected 2 edge nodes, got %+v", prev)
	}
	if len(st.Groups()) != 0 {
		t.Fatal("preview must not persist groups")
	}

	// Seed: 'prod' tag (shared by 2) + roles edge/db become groups; 'solo' tag
	// (only 1 node) does not.
	seedRes := doJSON(t, handler, http.MethodPost, "/api/groups/seed", "{}", cookies, csrf)
	defer seedRes.Body.Close()
	var seed struct{ Created, Skipped int }
	if err := json.NewDecoder(seedRes.Body).Decode(&seed); err != nil {
		t.Fatal(err)
	}
	slugs := map[string]bool{}
	for _, g := range st.Groups() {
		slugs[g.Slug] = true
	}
	if !slugs["tag-prod"] || !slugs["role-edge"] || !slugs["role-db"] {
		t.Fatalf("expected tag-prod/role-edge/role-db seeded, got %v", slugs)
	}
	if slugs["tag-solo"] {
		t.Fatal("a tag on a single node should not be seeded")
	}

	// Idempotent: a second seed creates nothing.
	seed2Res := doJSON(t, handler, http.MethodPost, "/api/groups/seed", "{}", cookies, csrf)
	defer seed2Res.Body.Close()
	var seed2 struct{ Created, Skipped int }
	json.NewDecoder(seed2Res.Body).Decode(&seed2)
	if seed2.Created != 0 {
		t.Fatalf("re-seed should create 0, got %d", seed2.Created)
	}
}

func TestGroupPolicyPlanExpandsAndGuardsClobber(t *testing.T) {
	handler, st := newTestServerWithPublicURL(t, "https://203.0.113.99")
	cookies, csrf := loginSession(t, handler)
	for _, id := range []string{"web1", "db1", "mon1"} {
		enrollNamedNodeToken(t, handler, cookies, csrf, id, id)
	}
	setNodeIP(t, st, "web1", "10.66.0.1/32", "203.0.113.10")
	setNodeIP(t, st, "db1", "10.66.0.2/32", "203.0.113.20")
	setNodeIP(t, st, "mon1", "10.66.0.3/32", "203.0.113.30")

	web := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"name":"Web","slug":"web","members":["web1"]}`, cookies, csrf))
	db := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"name":"DB","slug":"db","members":["db1"]}`, cookies, csrf))
	mon := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"name":"Mon","slug":"mon","members":["mon1"]}`, cookies, csrf))

	// mon1 has a MANUALLY-authored per-node policy that must not be clobbered.
	manual := doJSON(t, handler, http.MethodPost, "/api/netpolicy",
		`{"target_node_id":"mon1","enabled":true,"rules":[{"id":"m1","action":"allow","direction":"egress","protocol":"any","remote":{"kind":"any"}}]}`,
		cookies, csrf)
	manual.Body.Close()
	if manual.StatusCode != http.StatusOK {
		t.Fatalf("manual netpolicy create failed: %d", manual.StatusCode)
	}

	// Group policy: web -> db allow tcp 5432; and a mon-scoped policy that would
	// target mon1 (the clobber-guard case).
	gpWeb := doJSON(t, handler, http.MethodPost, "/api/group-policies",
		`{"scope_group_id":"`+web.ID+`","enabled":true,"priority":0,"rules":[{"id":"r1","action":"allow","direction":"egress","protocol":"tcp","ports":[5432],"remote":{"kind":"group","group_id":"`+db.ID+`"}}]}`,
		cookies, csrf)
	gpWeb.Body.Close()
	if gpWeb.StatusCode != http.StatusOK {
		t.Fatalf("group policy create failed: %d", gpWeb.StatusCode)
	}
	gpMon := doJSON(t, handler, http.MethodPost, "/api/group-policies",
		`{"scope_group_id":"`+mon.ID+`","enabled":true,"priority":0,"rules":[{"id":"r1","action":"allow","direction":"egress","protocol":"tcp","ports":[9100],"remote":{"kind":"group","group_id":"`+web.ID+`"}}]}`,
		cookies, csrf)
	gpMon.Body.Close()
	if gpMon.StatusCode != http.StatusOK {
		t.Fatalf("mon group policy create failed: %d", gpMon.StatusCode)
	}

	// Plan: web1 materializes a group-derived policy + approval; mon1 is a
	// conflict (manual policy present) and must be left intact.
	planRes := doJSON(t, handler, http.MethodPost, "/api/group-policies/plan", "{}", cookies, csrf)
	defer planRes.Body.Close()
	if planRes.StatusCode != http.StatusOK {
		t.Fatalf("group plan failed: %d", planRes.StatusCode)
	}
	var plan struct {
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
	if err := json.NewDecoder(planRes.Body).Decode(&plan); err != nil {
		t.Fatal(err)
	}

	affected := map[string]string{}
	for _, a := range plan.Affected {
		affected[a.NodeID] = a.PlanSHA
	}
	if _, ok := affected["web1"]; !ok {
		t.Fatalf("web1 should be affected, got %+v", plan.Affected)
	}
	if affected["web1"] == "" {
		t.Fatal("web1 plan SHA should be populated (membership-sensitive)")
	}
	// web1's materialized policy is group-derived and fans the db group to db1.
	wp, ok := st.NetPolicy("web1")
	if !ok || !wp.GroupDerived {
		t.Fatalf("web1 policy should be group-derived: ok=%v policy=%+v", ok, wp)
	}
	foundDB := false
	for _, rule := range wp.Rules {
		if rule.Remote.Kind == model.NetRefNode && rule.Remote.NodeID == "db1" {
			foundDB = true
		}
	}
	if !foundDB {
		t.Fatalf("web1 group rule should fan out to db1, got %+v", wp.Rules)
	}

	// Clobber-guard: mon1 reported as a conflict, manual policy preserved.
	conflicted := false
	for _, c := range plan.Conflicts {
		if c.NodeID == "mon1" {
			conflicted = true
		}
	}
	if !conflicted {
		t.Fatalf("mon1 should be a conflict (manual policy present), got %+v", plan.Conflicts)
	}
	mp, ok := st.NetPolicy("mon1")
	if !ok || mp.GroupDerived {
		t.Fatalf("mon1 manual policy must be preserved (not group-derived): %+v", mp)
	}
	if len(mp.Rules) != 1 || mp.Rules[0].ID != "m1" {
		t.Fatalf("mon1 manual rule was clobbered: %+v", mp.Rules)
	}

	// An approval was queued for the affected node.
	approvals := st.Approvals()
	if len(approvals) == 0 {
		t.Fatal("expected at least one approval from the group plan")
	}
}

func TestGroupPolicyPlanReportsSelectorImpactAndRejectsStaleSelectorApproval(t *testing.T) {
	handler, st := newTestServerWithPublicURL(t, "https://203.0.113.99")
	cookies, csrf := loginSession(t, handler)
	for _, id := range []string{"web1", "web2", "db1"} {
		enrollNamedNodeToken(t, handler, cookies, csrf, id, id)
	}
	setNodeIP(t, st, "web1", "10.66.0.1/32", "203.0.113.10")
	setNodeIP(t, st, "web2", "10.66.0.2/32", "203.0.113.20")
	setNodeIP(t, st, "db1", "10.66.0.3/32", "203.0.113.30")
	setNodeMeta(t, st, "web1", func(n *model.Node) { n.Tags = []string{"web"} })
	setNodeMeta(t, st, "web2", func(n *model.Node) { n.Tags = []string{"web"} })

	web := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"name":"Web","slug":"web","members":["web1"],"selector":{"match_tags_any":["web"]}}`, cookies, csrf))
	db := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"name":"DB","slug":"db","members":["db1"]}`, cookies, csrf))

	gpWeb := doJSON(t, handler, http.MethodPost, "/api/group-policies",
		`{"scope_group_id":"`+web.ID+`","enabled":true,"priority":0,"rules":[{"id":"r1","action":"allow","direction":"egress","protocol":"tcp","ports":[5432],"remote":{"kind":"group","group_id":"`+db.ID+`"}}]}`,
		cookies, csrf)
	gpWeb.Body.Close()
	if gpWeb.StatusCode != http.StatusOK {
		t.Fatalf("group policy create failed: %d", gpWeb.StatusCode)
	}

	planRes := doJSON(t, handler, http.MethodPost, "/api/group-policies/plan", "{}", cookies, csrf)
	defer planRes.Body.Close()
	if planRes.StatusCode != http.StatusOK {
		t.Fatalf("group plan failed: %d", planRes.StatusCode)
	}
	var plan struct {
		Affected []struct {
			NodeID     string `json:"node_id"`
			ApprovalID string `json:"approval_id"`
			PlanSHA    string `json:"plan_sha"`
		} `json:"affected"`
		SelectorImpacts []struct {
			GroupID           string   `json:"group_id"`
			GroupName         string   `json:"group_name"`
			Uses              []string `json:"uses"`
			PolicyIDs         []string `json:"policy_ids"`
			ExplicitMemberIDs []string `json:"explicit_member_ids"`
			SelectorMemberIDs []string `json:"selector_member_ids"`
			ResolvedMemberIDs []string `json:"resolved_member_ids"`
		} `json:"selector_impacts"`
	}
	if err := json.NewDecoder(planRes.Body).Decode(&plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.SelectorImpacts) != 1 {
		t.Fatalf("expected one selector impact, got %+v", plan.SelectorImpacts)
	}
	impact := plan.SelectorImpacts[0]
	if impact.GroupID != web.ID || impact.GroupName != "Web" {
		t.Fatalf("unexpected selector impact group: %+v", impact)
	}
	if strings.Join(impact.Uses, ",") != "scope" {
		t.Fatalf("selector impact should mark scope use, got %+v", impact.Uses)
	}
	if strings.Join(impact.ExplicitMemberIDs, ",") != "web1" {
		t.Fatalf("explicit members = %+v, want web1", impact.ExplicitMemberIDs)
	}
	if strings.Join(impact.SelectorMemberIDs, ",") != "web2" {
		t.Fatalf("selector-added members = %+v, want web2", impact.SelectorMemberIDs)
	}
	if strings.Join(impact.ResolvedMemberIDs, ",") != "web1,web2" {
		t.Fatalf("resolved members = %+v, want web1/web2", impact.ResolvedMemberIDs)
	}

	affected := map[string]string{}
	for _, a := range plan.Affected {
		affected[a.NodeID] = a.ApprovalID
	}
	web2ApprovalID := affected["web2"]
	if web2ApprovalID == "" {
		t.Fatalf("selector-added web2 should receive a per-node approval, got %+v", plan.Affected)
	}

	approval, ok := st.Approval(web2ApprovalID)
	if !ok {
		t.Fatalf("missing web2 approval %s", web2ApprovalID)
	}

	// Change the selector facts after planning. web2 is no longer in the Web
	// group, so the stale approval must be rejected instead of applying an
	// outdated plan.
	setNodeMeta(t, st, "web2", func(n *model.Node) { n.Tags = nil })
	approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{
			"approval_id": web2ApprovalID,
			"queue_apply": false,
			"plan_sha256": planSHA256(approval.Plan),
		})),
		cookies, csrf)
	defer approve.Body.Close()
	if approve.StatusCode != http.StatusConflict {
		t.Fatalf("stale selector approval should be rejected with 409, got %d", approve.StatusCode)
	}
	var errOut model.APIErrorResponse
	if err := json.NewDecoder(approve.Body).Decode(&errOut); err != nil {
		t.Fatal(err)
	}
	if errOut.Error.Code != model.APIErrorApprovalStale || !strings.Contains(errOut.Error.Message, "re-plan") {
		t.Fatalf("unexpected stale approval error: %+v", errOut)
	}
}

func TestNetPolicyMatrixHTTP(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNodeToken(t, handler, cookies, csrf, "web1", "web1")
	enrollNamedNodeToken(t, handler, cookies, csrf, "db1", "db1")

	web := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"name":"Web","slug":"web","members":["web1"]}`, cookies, csrf))
	db := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"name":"DB","slug":"db","members":["db1"]}`, cookies, csrf))
	_ = st

	gp := doJSON(t, handler, http.MethodPost, "/api/group-policies",
		`{"scope_group_id":"`+web.ID+`","enabled":true,"priority":0,"rules":[{"id":"r1","action":"allow","direction":"egress","protocol":"tcp","ports":[5432],"remote":{"kind":"group","group_id":"`+db.ID+`"}}]}`,
		cookies, csrf)
	gp.Body.Close()
	if gp.StatusCode != http.StatusOK {
		t.Fatalf("group policy create failed: %d", gp.StatusCode)
	}

	matRes := doJSON(t, handler, http.MethodGet, "/api/netpolicy/matrix?direction=egress", "", cookies, csrf)
	defer matRes.Body.Close()
	if matRes.StatusCode != http.StatusOK {
		t.Fatalf("matrix failed: %d", matRes.StatusCode)
	}
	var mat struct {
		Direction string `json:"direction"`
		Cells     []struct {
			From, To, Action string
			RuleCount        int `json:"rule_count"`
			Mixed            bool
		} `json:"cells"`
	}
	if err := json.NewDecoder(matRes.Body).Decode(&mat); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range mat.Cells {
		if c.From == web.ID && c.To == db.ID {
			found = true
			if c.Action != "allow" || c.RuleCount != 1 || c.Mixed {
				t.Fatalf("bad web->db cell: %+v", c)
			}
		}
	}
	if !found {
		t.Fatalf("expected a web->db matrix cell, got %+v", mat.Cells)
	}
}
