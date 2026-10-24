package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Converting a manual policy keeps its rules, retires the manual document and
// produces one reviewed plan whose ruleset is the one the manual policy
// compiled to.
func TestConvertManualPolicyKeepsItsRules(t *testing.T) {
	handler, st, cookies, csrf := outboundFleet(t, "n1", "n2")
	manual := doJSON(t, handler, http.MethodPost, "/api/netpolicy", `{"target_node_id":"n1","enabled":true,"rules":[
		{"id":"m1","comment":"db","action":"allow","direction":"egress","protocol":"tcp","ports":[5432],"remote":{"kind":"node","node_id":"n2"}},
		{"id":"m2","action":"deny","direction":"egress","protocol":"udp","ports":[123],"remote":{"kind":"any"},"disabled":true},
		{"id":"m3","action":"allow","direction":"egress","protocol":"any","remote":{"kind":"cidr","cidr":"192.0.2.0/24"}}]}`, cookies, csrf)
	if manual.StatusCode != http.StatusOK {
		t.Fatalf("manual policy = %d %s", manual.StatusCode, readBody(t, manual))
	}
	manual.Body.Close()
	before, _ := st.NetPolicy("n1")
	planRes := doJSON(t, handler, http.MethodPost, "/api/netpolicy/plan", `{"node_id":"n1"}`, cookies, csrf)
	var manualPlan struct {
		Plan string `json:"plan"`
	}
	if err := json.Unmarshal([]byte(readBody(t, planRes)), &manualPlan); err != nil || manualPlan.Plan == "" {
		t.Fatalf("manual plan failed: %v", err)
	}

	res := doJSON(t, handler, http.MethodPost, "/api/netpolicy/convert", `{"target_node_id":"n1","name":"n1 egress"}`, cookies, csrf)
	raw := readBody(t, res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("convert = %d %s", res.StatusCode, raw)
	}
	var out struct {
		GroupPolicy outboundPolicyView `json:"group_policy"`
		Approval    *struct {
			ID   string `json:"id"`
			Plan string `json:"plan"`
		} `json:"approval"`
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	gp, ok := st.GroupPolicy(out.GroupPolicy.ID)
	if !ok || gp.Name != "n1 egress" || !gp.Enabled {
		t.Fatalf("converted policy not stored: %+v", gp)
	}
	if !reflect.DeepEqual(gp.TargetScope(), model.TargetSelector{Nodes: []string{"n1"}}) {
		t.Fatalf("converted target = %+v, want the one node", gp.TargetScope())
	}
	if len(gp.Rules) != len(before.Rules) {
		t.Fatalf("converted %d rules, manual had %d", len(gp.Rules), len(before.Rules))
	}
	for i, r := range before.Rules {
		g := gp.Rules[i]
		if g.ID != r.ID || g.Comment != r.Comment || g.Action != r.Action || g.Direction != r.Direction || g.Protocol != r.Protocol ||
			fmt.Sprint(g.Ports) != fmt.Sprint(r.Ports) || g.Remote != r.Remote || g.Disabled != r.Disabled {
			t.Fatalf("rule %d changed in conversion: %+v -> %+v", i, r, g)
		}
	}
	after, ok := st.NetPolicy("n1")
	if !ok || !after.GroupDerived {
		t.Fatalf("the manual document must be retired into the group-derived one: %+v", after)
	}
	if out.Approval == nil || out.Approval.ID == "" {
		t.Fatal("conversion must produce one reviewed plan")
	}
	if out.Approval.Plan != manualPlan.Plan {
		t.Fatalf("the converted plan must compile to the manual ruleset\nmanual:\n%s\nconverted:\n%s", manualPlan.Plan, out.Approval.Plan)
	}
	approval, _ := st.Approval(out.Approval.ID)
	approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": false, "plan_sha256": planSHA256(approval.Plan)})),
		cookies, csrf)
	if approve.StatusCode != http.StatusOK {
		t.Fatalf("the conversion plan must approve, got %d %s", approve.StatusCode, readBody(t, approve))
	}
	approve.Body.Close()
	if !auditActionSeen(st, "network.policy.convert") {
		t.Fatal("conversion must be audited")
	}

	again := doJSON(t, handler, http.MethodPost, "/api/netpolicy/convert", `{"target_node_id":"n1"}`, cookies, csrf)
	if again.StatusCode != http.StatusConflict {
		t.Fatalf("converting a group-derived document must be refused, got %d", again.StatusCode)
	}
	again.Body.Close()
}

func TestConvertManualPolicyRefusals(t *testing.T) {
	handler, st, cookies, csrf := outboundFleet(t, "n1", "n2", "n3")
	put := func(body string) {
		t.Helper()
		res := doJSON(t, handler, http.MethodPost, "/api/netpolicy", body, cookies, csrf)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("manual policy = %d %s", res.StatusCode, readBody(t, res))
		}
		res.Body.Close()
	}
	convert := func(node string) (int, string) {
		res := doJSON(t, handler, http.MethodPost, "/api/netpolicy/convert", `{"target_node_id":"`+node+`"}`, cookies, csrf)
		return res.StatusCode, readBody(t, res)
	}

	// A policy that cannot produce a plan (an inbound rule) is not converted,
	// and nothing is stored: the conversion is one reviewed plan or nothing.
	put(`{"target_node_id":"n1","enabled":true,"rules":[{"id":"in","action":"allow","direction":"ingress","protocol":"tcp","ports":[22],"remote":{"kind":"any"}}]}`)
	if code, raw := convert("n1"); code != http.StatusConflict || !strings.Contains(raw, "ingress") {
		t.Fatalf("inbound rule: want 409 naming the cause, got %d %s", code, raw)
	}
	if len(st.GroupPolicies()) != 0 {
		t.Fatal("a refused conversion must store nothing")
	}
	if np, _ := st.NetPolicy("n1"); np.GroupDerived {
		t.Fatal("a refused conversion must leave the manual document")
	}

	// No policy, no conversion.
	if code, _ := convert("n3"); code != http.StatusNotFound {
		t.Fatalf("no policy: want 404, got %d", code)
	}

	// A disabled manual policy converts into a disabled policy with no plan,
	// and the manual document is removed.
	put(`{"target_node_id":"n2","enabled":false,"rules":[{"id":"x","action":"allow","direction":"egress","protocol":"tcp","ports":[443],"remote":{"kind":"any"}}]}`)
	code, raw := convert("n2")
	if code != http.StatusOK {
		t.Fatalf("disabled convert = %d %s", code, raw)
	}
	var out struct {
		GroupPolicy outboundPolicyView `json:"group_policy"`
		Approval    json.RawMessage    `json:"approval"`
	}
	_ = json.Unmarshal([]byte(raw), &out)
	if out.GroupPolicy.Enabled || string(out.Approval) != "null" {
		t.Fatalf("disabled policy must convert disabled with no plan: %s", raw)
	}
	if _, ok := st.NetPolicy("n2"); ok {
		t.Fatal("the disabled manual document must be retired")
	}

	// A confined token converts only a policy on a node it administers.
	confined := createPAT(t, handler, cookies, csrf, []string{"netpolicy:admin", "netpolicy:read"}, []string{"n3"})
	res := doBearerJSON(t, handler, http.MethodPost, "/api/netpolicy/convert", `{"target_node_id":"n1"}`, confined)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("confined convert of another node: want 403, got %d", res.StatusCode)
	}
	res.Body.Close()
}
