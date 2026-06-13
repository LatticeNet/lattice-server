package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/netpolicy"
)

func TestNetPolicyCRUDAndGraph(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	enrollNamedNode(t, handler, cookies, csrf, "node-b", "Node B")

	create := doJSON(t, handler, http.MethodPost, "/api/netpolicy", `{
		"target_node_id":"node-a",
		"enabled":true,
		"rules":[{
			"comment":"deny db\ncontrol",
			"action":"deny",
			"direction":"egress",
			"protocol":"tcp",
			"ports":[1234,22,1234],
			"remote":{"kind":"node","node_id":"node-b"}
		}]
	}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create policy failed: %d", create.StatusCode)
	}
	var view struct {
		TargetNodeID   string          `json:"target_node_id"`
		TargetNodeName string          `json:"target_node_name"`
		Rules          []model.NetRule `json:"rules"`
	}
	if err := json.NewDecoder(create.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	if view.TargetNodeID != "node-a" || view.TargetNodeName != "Node A" || len(view.Rules) != 1 {
		t.Fatalf("bad view: %+v", view)
	}
	if strings.Contains(view.Rules[0].Comment, "\n") || len(view.Rules[0].Ports) != 2 || view.Rules[0].Ports[0] != 22 || view.Rules[0].Ports[1] != 1234 {
		t.Fatalf("rule was not normalized: %+v", view.Rules[0])
	}
	if stored, ok := st.NetPolicy("node-a"); !ok || stored.ID != "node-a" || stored.Rules[0].Remote.NodeID != "node-b" {
		t.Fatalf("policy not stored: ok=%v stored=%+v", ok, stored)
	}

	graphRes := doJSON(t, handler, http.MethodGet, "/api/netpolicy/graph", "", cookies, "")
	defer graphRes.Body.Close()
	if graphRes.StatusCode != http.StatusOK {
		t.Fatalf("graph failed: %d", graphRes.StatusCode)
	}
	var graph netpolicy.Graph
	if err := json.NewDecoder(graphRes.Body).Decode(&graph); err != nil {
		t.Fatal(err)
	}
	if len(graph.Edges) != 1 || graph.Edges[0].From != "node-a" || graph.Edges[0].To != "node-b" || graph.Edges[0].Action != model.NetRuleDeny {
		t.Fatalf("bad graph edges: %+v", graph.Edges)
	}

	del := doJSON(t, handler, http.MethodPost, "/api/netpolicy/delete", `{"target_node_id":"node-a"}`, cookies, csrf)
	defer del.Body.Close()
	if del.StatusCode != http.StatusOK {
		t.Fatalf("delete failed: %d", del.StatusCode)
	}
	if _, ok := st.NetPolicy("node-a"); ok {
		t.Fatal("policy should be deleted")
	}
}

func TestNetPolicyRejectsInvalidRule(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")

	res := doJSON(t, handler, http.MethodPost, "/api/netpolicy", `{
		"target_node_id":"node-a",
		"enabled":true,
		"rules":[{
			"action":"deny",
			"direction":"egress",
			"protocol":"any",
			"ports":[53],
			"remote":{"kind":"cidr","cidr":"2001:db8::/32"}
		}]
	}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid policy should be rejected, got %d", res.StatusCode)
	}
}

func TestNetPolicyAllowlistEnforced(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	enrollNamedNode(t, handler, cookies, csrf, "node-b", "Node B")

	adminA := createPAT(t, handler, cookies, csrf, []string{"netpolicy:read", "netpolicy:admin"}, []string{"node-a"})
	denied := doBearerJSON(t, handler, http.MethodPost, "/api/netpolicy", `{
		"target_node_id":"node-b",
		"enabled":true,
		"rules":[{"action":"deny","direction":"egress","protocol":"tcp","ports":[22],"remote":{"kind":"any"}}]
	}`, adminA)
	defer denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("allowlisted token must not write node-b policy, got %d", denied.StatusCode)
	}

	allowed := doBearerJSON(t, handler, http.MethodPost, "/api/netpolicy", `{
		"target_node_id":"node-a",
		"enabled":true,
		"rules":[{"action":"deny","direction":"egress","protocol":"tcp","ports":[22],"remote":{"kind":"any"}}]
	}`, adminA)
	defer allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("allowlisted token should write node-a policy, got %d", allowed.StatusCode)
	}

	list := doBearerJSON(t, handler, http.MethodGet, "/api/netpolicy", "", adminA)
	defer list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list failed: %d", list.StatusCode)
	}
	var out struct {
		Policies []struct {
			TargetNodeID string `json:"target_node_id"`
		} `json:"policies"`
	}
	if err := json.NewDecoder(list.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Policies) != 1 || out.Policies[0].TargetNodeID != "node-a" {
		t.Fatalf("list did not filter by allowlist: %+v", out.Policies)
	}
}
