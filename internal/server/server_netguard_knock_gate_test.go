package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// knockGateDetail reads the reality detail the way the plugin does and the
// same record embedded in the review, and checks that the two agree.
func knockGateDetail(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, nodeID string) map[string]any {
	t.Helper()
	res := doJSON(t, handler, http.MethodGet, "/api/netguard/reality?node_id="+nodeID, "", cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("reality detail: %d", res.StatusCode)
	}
	var detail struct {
		Node map[string]any `json:"node"`
	}
	if err := json.NewDecoder(res.Body).Decode(&detail); err != nil {
		t.Fatal(err)
	}
	review := doJSON(t, handler, http.MethodGet, "/api/netguard/review?node_id="+nodeID, "", cookies, csrf)
	defer review.Body.Close()
	if review.StatusCode != http.StatusOK {
		t.Fatalf("review: %d", review.StatusCode)
	}
	var out struct {
		Review struct {
			Reality map[string]any `json:"reality"`
		} `json:"review"`
	}
	if err := json.NewDecoder(review.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"knock_gate", "knock_gated_ports"} {
		a, _ := json.Marshal(detail.Node[key])
		b, _ := json.Marshal(out.Review.Reality[key])
		if string(a) != string(b) {
			t.Fatalf("%s differs between the detail (%s) and the review (%s)", key, a, b)
		}
	}
	return detail.Node
}

func portsOf(t *testing.T, raw any) []int {
	t.Helper()
	list, ok := raw.([]any)
	if !ok {
		t.Fatalf("knock_gated_ports is %T, want a list", raw)
	}
	out := make([]int, 0, len(list))
	for _, v := range list {
		out = append(out, int(v.(float64)))
	}
	return out
}

func TestNetGuardRealityDetailCarriesTheKnockGate(t *testing.T) {
	now := time.Date(2026, 9, 4, 6, 30, 0, 0, time.UTC)
	_, handler, st, cookies, csrf := newGuardRealityServerForTest(t, newGuardRealityTestClock(now))
	token := setupAdoptedNetGuardNode(t, handler, st, cookies, csrf)

	// No table in the report: no gate, and no ports claimed.
	plain := guardRealityFixture("node-a", now.Add(-time.Minute))
	plain.SSHD = keyOnlySSHD(now.Add(-time.Minute))
	if resp := postGuardRealityForTest(t, handler, token, "node-a", plain); resp.code != http.StatusOK {
		t.Fatalf("post reality: %d %s", resp.code, resp.body)
	}
	node := knockGateDetail(t, handler, cookies, csrf, "node-a")
	if node["knock_gate"] != false {
		t.Fatalf("no lattice_knock table means no gate: %v", node)
	}
	if _, ok := node["knock_gated_ports"]; ok {
		t.Fatalf("no gate must not list ports: %v", node)
	}

	// The table is there and SSH Guard never armed this node: the gate is
	// read the way SSH Guard builds one, over the ports sshd reports.
	foreign := guardRealityFixture("node-a", now)
	foreign.ForeignTables = []string{"inet docker", "inet lattice_knock"}
	foreign.SSHD = keyOnlySSHD(now)
	foreign.SSHD.Ports = []int{22, 3434}
	if resp := postGuardRealityForTest(t, handler, token, "node-a", foreign); resp.code != http.StatusOK {
		t.Fatalf("post reality: %d %s", resp.code, resp.body)
	}
	node = knockGateDetail(t, handler, cookies, csrf, "node-a")
	if node["knock_gate"] != true {
		t.Fatalf("the report lists inet lattice_knock: %v", node)
	}
	if got := portsOf(t, node["knock_gated_ports"]); len(got) != 2 || got[0] != 22 || got[1] != 3434 {
		t.Fatalf("a foreign gate covers what sshd listens on, got %v", got)
	}

	// An applied arm governs the scope: its plan gated 22 and the alternate
	// port, whatever sshd reports today.
	seedArmApproval(t, st, "arm_knock", "node-a", model.ApprovalApplied, knockTestPorts, now.Add(-time.Hour))
	node = knockGateDetail(t, handler, cookies, csrf, "node-a")
	if node["knock_gate"] != true {
		t.Fatalf("the gate is still on the node: %v", node)
	}
	if got := portsOf(t, node["knock_gated_ports"]); len(got) != 2 || got[0] != 22 || got[1] != 58394 {
		t.Fatalf("the arm plan's gated ports govern, got %v", got)
	}
	raw, _ := json.Marshal(node)
	for _, port := range knockTestPorts {
		if strings.Contains(string(raw), strconv.Itoa(port)) {
			t.Fatalf("the knock sequence must never reach the reality detail: %s", raw)
		}
	}

}

func TestNetGuardRealityDetailKnockGateWithoutScope(t *testing.T) {
	now := time.Date(2026, 9, 4, 6, 30, 0, 0, time.UTC)
	_, handler, _, cookies, csrf := newGuardRealityServerForTest(t, newGuardRealityTestClock(now))
	token := enrollNamedNodeToken(t, handler, cookies, csrf, "node-b", "Node B")

	// The table is there, nothing of ours armed it, and the agent proved no
	// sshd facts: the gate is reported and its scope is left unclaimed rather
	// than guessed.
	blind := guardRealityFixture("node-b", now)
	blind.ForeignTables = []string{"inet lattice_knock"}
	if resp := postGuardRealityForTest(t, handler, token, "node-b", blind); resp.code != http.StatusOK {
		t.Fatalf("post reality: %d %s", resp.code, resp.body)
	}
	node := knockGateDetail(t, handler, cookies, csrf, "node-b")
	if node["knock_gate"] != true {
		t.Fatalf("the table is listed: %v", node)
	}
	if _, ok := node["knock_gated_ports"]; ok {
		t.Fatalf("no plan and no sshd facts means no port claim: %v", node)
	}
}
