package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func enrollNamedNode(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, nodeID, name string) {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/nodes/enroll-token",
		`{"node_id":"`+nodeID+`","name":"`+name+`"}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("enroll %s failed: %d", nodeID, res.StatusCode)
	}
}

func TestNFTInputsPersistAndPlanFromStoredState(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")

	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs", `{
		"node_id":"node-a",
		"interface_name":"ens3",
		"wireguard_cidr":"10.66.0.9/24",
		"public_tcp":[443,80,443],
		"public_udp":[53],
		"wireguard_tcp":[9100,22],
		"wireguard_udp":[51820]
	}`, cookies, csrf)
	defer save.Body.Close()
	if save.StatusCode != http.StatusOK {
		t.Fatalf("save nft inputs failed: %d", save.StatusCode)
	}
	var view struct {
		NodeID        string `json:"node_id"`
		NodeName      string `json:"node_name"`
		InterfaceName string `json:"interface_name"`
		WireGuardCIDR string `json:"wireguard_cidr"`
		PublicTCP     []int  `json:"public_tcp"`
		PublicUDP     []int  `json:"public_udp"`
	}
	if err := json.NewDecoder(save.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	if view.NodeID != "node-a" || view.NodeName != "Node A" || view.InterfaceName != "ens3" {
		t.Fatalf("bad view: %+v", view)
	}
	if view.WireGuardCIDR != "10.66.0.0/24" || strings.Join(intsToStrings(view.PublicTCP), ",") != "80,443" || strings.Join(intsToStrings(view.PublicUDP), ",") != "53" {
		t.Fatalf("inputs were not normalized: %+v", view)
	}

	stored, ok := st.NFTInputs("node-a")
	if !ok {
		t.Fatal("stored nft inputs missing")
	}
	if stored.ID != "node-a" || stored.InterfaceName != "ens3" || stored.WireGuardCIDR != "10.66.0.0/24" {
		t.Fatalf("bad stored inputs: %+v", stored)
	}

	plan := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan", `{"node_id":"node-a"}`, cookies, csrf)
	defer plan.Body.Close()
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("plan from stored inputs failed: %d", plan.StatusCode)
	}
	var approval model.Approval
	if err := json.NewDecoder(plan.Body).Decode(&approval); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`iifname "ens3" tcp dport { 80, 443 }`,
		`iifname "ens3" udp dport { 53 }`,
		`elements = { 10.66.0.0/24 }`,
	} {
		if !strings.Contains(approval.Plan, want) {
			t.Fatalf("plan missing %q:\n%s", want, approval.Plan)
		}
	}
}

func TestNFTInputsAllowlistEnforced(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	enrollNamedNode(t, handler, cookies, csrf, "node-b", "Node B")

	token := createPAT(t, handler, cookies, csrf, []string{"network:plan"}, []string{"node-a"})
	deniedSave := doBearerJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
		`{"node_id":"node-b","public_tcp":[443]}`, token)
	defer deniedSave.Body.Close()
	if deniedSave.StatusCode != http.StatusForbidden {
		t.Fatalf("allowlisted token must not save node-b inputs, got %d", deniedSave.StatusCode)
	}

	allowedSave := doBearerJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
		`{"node_id":"node-a","public_tcp":[443]}`, token)
	defer allowedSave.Body.Close()
	if allowedSave.StatusCode != http.StatusOK {
		t.Fatalf("allowlisted token should save node-a inputs, got %d", allowedSave.StatusCode)
	}

	list := doBearerJSON(t, handler, http.MethodGet, "/api/network/nft/inputs", `{}`, token)
	defer list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list failed: %d", list.StatusCode)
	}
	var out struct {
		Inputs []struct {
			NodeID string `json:"node_id"`
		} `json:"inputs"`
	}
	if err := json.NewDecoder(list.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Inputs) != 1 || out.Inputs[0].NodeID != "node-a" {
		t.Fatalf("list did not filter by node allowlist: %+v", out.Inputs)
	}
}

func intsToStrings(values []int) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, strconv.Itoa(v))
	}
	return out
}
