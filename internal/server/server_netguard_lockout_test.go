package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/netguard"
)

// The end-to-end version of the lockout hole: the fleet's shell daemon is not
// always on 22, and until the lint could read a node's reported reality it had
// no way to know. The node-side apply cannot catch this either, because its
// selfcheck is an outbound connection that a default-drop input chain does not
// touch: the watchdog disarms and the operator loses the box permanently.
func TestNetGuardPlanBlocksWhenRealitySaysSSHMoved(t *testing.T) {
	handler, _ := newTestServerWithPublicURL(t, "https://203.0.113.99")
	cookies, csrf := loginSession(t, handler)
	token := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	// A baseline that opens 22 and 443. On a node whose sshd is on 22 this is
	// safe, and the lint must keep saying so.
	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
		`{"node_id":"node-a","public_tcp":[22,443]}`, cookies, csrf)
	defer save.Body.Close()
	adopt := doJSON(t, handler, http.MethodPost, "/api/netguard/nodes/adopt", `{"node_id":"node-a"}`, cookies, csrf)
	defer adopt.Body.Close()
	if adopt.StatusCode != http.StatusOK {
		t.Fatalf("adopt: %d", adopt.StatusCode)
	}

	// The node reports: sshd is on 2222, and 22 is not listening at all.
	reality := model.GuardNodeReality{
		NodeID:      "node-a",
		CollectedAt: time.Now().UTC().Add(-time.Minute),
		Listeners: []model.GuardListener{
			{Protocol: "tcp", Port: 2222, Address: "203.0.113.10", Process: "sshd(701)"},
			{Protocol: "tcp", Port: 443, Address: "203.0.113.10", Process: "caddy(910)"},
		},
		Interfaces: []model.GuardInterface{{Name: "ens3", Addresses: []string{"203.0.113.10/24"}, Up: true}},
		ManagedSHA: strings.Repeat("b", 64),
	}
	if posted := postGuardRealityForTest(t, handler, token, "node-a", reality); posted.code != http.StatusOK {
		t.Fatalf("post guard reality = %d: %s", posted.code, posted.body)
	}

	blocked := doJSON(t, handler, http.MethodPost, "/api/netguard/plan", `{"node_id":"node-a"}`, cookies, csrf)
	defer blocked.Body.Close()
	if blocked.StatusCode != http.StatusConflict {
		t.Fatalf("a plan that drops the reported sshd port = %d, want 409", blocked.StatusCode)
	}
	var blockedRes struct {
		Findings []netguard.Finding `json:"findings"`
	}
	if err := json.NewDecoder(blocked.Body).Decode(&blockedRes); err != nil {
		t.Fatal(err)
	}
	if !hasFinding(blockedRes.Findings, netguard.FindingLockoutRiskSSH) {
		t.Fatalf("findings = %+v", blockedRes.Findings)
	}
	if hasFinding(blockedRes.Findings, netguard.FindingManagementPortAssumed) {
		t.Fatalf("the port was reported, not assumed: %+v", blockedRes.Findings)
	}
	// The message has to name the port the operator must open, or the block is
	// just an obstacle rather than a diagnosis.
	for _, finding := range blockedRes.Findings {
		if finding.Code == netguard.FindingLockoutRiskSSH && !strings.Contains(finding.Message, "tcp/2222") {
			t.Fatalf("lockout message must name the real port: %q", finding.Message)
		}
	}

	// A second node with the same reported sshd port, whose plan opens it: the
	// lint clears, and with evidence in hand it emits nothing at all.
	tokenB := enrollNamedNodeToken(t, handler, cookies, csrf, "node-b", "Node B")
	saveB := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
		`{"node_id":"node-b","public_tcp":[2222,443]}`, cookies, csrf)
	defer saveB.Body.Close()
	adoptB := doJSON(t, handler, http.MethodPost, "/api/netguard/nodes/adopt", `{"node_id":"node-b"}`, cookies, csrf)
	defer adoptB.Body.Close()
	if adoptB.StatusCode != http.StatusOK {
		t.Fatalf("adopt node-b: %d", adoptB.StatusCode)
	}
	realityB := reality
	realityB.NodeID = "node-b"
	if posted := postGuardRealityForTest(t, handler, tokenB, "node-b", realityB); posted.code != http.StatusOK {
		t.Fatalf("post guard reality node-b = %d: %s", posted.code, posted.body)
	}
	ok := doJSON(t, handler, http.MethodPost, "/api/netguard/plan", `{"node_id":"node-b"}`, cookies, csrf)
	defer ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("a plan that opens the reported sshd port = %d, want 200", ok.StatusCode)
	}
	var okRes struct {
		Findings []netguard.Finding `json:"findings"`
	}
	if err := json.NewDecoder(ok.Body).Decode(&okRes); err != nil {
		t.Fatal(err)
	}
	if len(okRes.Findings) != 0 {
		t.Fatalf("a plan checked against reported reality must be clean: %+v", okRes.Findings)
	}
}

// The review method is the read-side preview: an operator has to be able to see
// the ruleset and its lockout verdict without creating an approval first.
func TestNetGuardReviewPreviewsRulesetAndFindings(t *testing.T) {
	handler, _ := newTestServerWithPublicURL(t, "https://203.0.113.99")
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")

	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
		`{"node_id":"node-a","public_tcp":[7443]}`, cookies, csrf)
	defer save.Body.Close()
	adopt := doJSON(t, handler, http.MethodPost, "/api/netguard/nodes/adopt", `{"node_id":"node-a"}`, cookies, csrf)
	defer adopt.Body.Close()

	res := doJSON(t, handler, http.MethodGet, "/api/netguard/review?node_id=node-a", "", cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("review = %d", res.StatusCode)
	}
	var out struct {
		Review struct {
			Ruleset      string             `json:"ruleset"`
			Findings     []netguard.Finding `json:"findings"`
			CompileError string             `json:"compile_error"`
			DriftState   string             `json:"drift_state"`
		} `json:"review"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Review.CompileError != "" {
		t.Fatalf("compile error: %s", out.Review.CompileError)
	}
	if !strings.Contains(out.Review.Ruleset, "table inet lattice_guard") {
		t.Fatalf("review must carry the rendered ruleset:\n%s", out.Review.Ruleset)
	}
	if !netguard.Blocking(out.Review.Findings) {
		t.Fatalf("review must surface the lockout block before an approval exists: %+v", out.Review.Findings)
	}
	// Nothing was applied and nothing was reported, so drift is unknown. This
	// must never read as in_sync.
	if out.Review.DriftState != netGuardDriftUnknown {
		t.Fatalf("drift_state = %q", out.Review.DriftState)
	}
}

// The fleet posture question: "which of my nodes drifted" has to be answerable
// in one request, or no UI will ask it.
func TestNetGuardRealityListCarriesFleetPosture(t *testing.T) {
	now := time.Now().UTC()
	_, handler, _, cookies, csrf := newGuardRealityServerForTest(t, newGuardRealityTestClock(now))
	token := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")
	enrollNamedNode(t, handler, cookies, csrf, "node-b", "Node B")

	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
		`{"node_id":"node-a","public_tcp":[22]}`, cookies, csrf)
	defer save.Body.Close()
	adopt := doJSON(t, handler, http.MethodPost, "/api/netguard/nodes/adopt", `{"node_id":"node-a"}`, cookies, csrf)
	defer adopt.Body.Close()

	reality := guardRealityFixture("node-a", now.Add(-time.Minute))
	if posted := postGuardRealityForTest(t, handler, token, "node-a", reality); posted.code != http.StatusOK {
		t.Fatalf("post guard reality = %d: %s", posted.code, posted.body)
	}

	rows := fetchRealityRows(t, handler, cookies, csrf)
	nodeA, nodeB := rows["node-a"], rows["node-b"]

	if nodeA.NodeName != "Node A" || nodeB.NodeName != "Node B" {
		t.Fatalf("posture rows must name their nodes: %+v %+v", nodeA, nodeB)
	}
	// node-a reported but has never been applied, so its drift is unknown, not
	// in_sync. This is the assertion that matters most in the whole file.
	if nodeA.SnapshotStatus != "fresh" || nodeA.DriftState != netGuardDriftUnknown {
		t.Fatalf("node-a = %+v", nodeA)
	}
	if !nodeA.HasBinding || !nodeA.Managed {
		t.Fatalf("node-a should be a managed, bound node: %+v", nodeA)
	}
	// node-b has never reported and has no binding at all.
	if nodeB.SnapshotStatus != "unknown" || nodeB.DriftState != netGuardDriftUnknown || nodeB.HasBinding {
		t.Fatalf("node-b = %+v", nodeB)
	}
	if nodeB.ListenerCount != nil {
		t.Fatalf("a node that never reported must not carry counts: %+v", nodeB)
	}
}

// Drift is the whole point of the feature: a managed table that no longer
// matches what Lattice installed has to be visible from the fleet list.
func TestNetGuardRealityListReportsDriftAndInSync(t *testing.T) {
	now := time.Now().UTC()
	srv, handler, _, cookies, csrf := newGuardRealityServerForTest(t, newGuardRealityTestClock(now))
	token := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
		`{"node_id":"node-a","public_tcp":[22]}`, cookies, csrf)
	defer save.Body.Close()
	adopt := doJSON(t, handler, http.MethodPost, "/api/netguard/nodes/adopt", `{"node_id":"node-a"}`, cookies, csrf)
	defer adopt.Body.Close()

	// Pretend an apply recorded what it installed.
	binding, ok := srv.store.NodeGuardBinding("node-a")
	if !ok {
		t.Fatal("binding missing after adopt")
	}
	applied := strings.Repeat("a", 64)
	binding.AppliedTableSHA = applied
	binding.LastAppliedAt = now.Add(-time.Hour)
	if _, err := srv.store.UpsertNodeGuardBinding(binding); err != nil {
		t.Fatalf("record applied sha: %v", err)
	}

	// The node reports the same hash: in sync.
	inSync := guardRealityFixture("node-a", now.Add(-time.Minute))
	inSync.ManagedSHA = applied
	if posted := postGuardRealityForTest(t, handler, token, "node-a", inSync); posted.code != http.StatusOK {
		t.Fatalf("post = %d: %s", posted.code, posted.body)
	}
	if row := fetchRealityRows(t, handler, cookies, csrf)["node-a"]; row.DriftState != netGuardDriftInSync {
		t.Fatalf("matching hashes must read in_sync: %+v", row)
	}

	// Someone edited the table on the box: drift.
	drifted := guardRealityFixture("node-a", now.Add(-30*time.Second))
	drifted.ManagedSHA = strings.Repeat("c", 64)
	if posted := postGuardRealityForTest(t, handler, token, "node-a", drifted); posted.code != http.StatusOK {
		t.Fatalf("post = %d: %s", posted.code, posted.body)
	}
	row := fetchRealityRows(t, handler, cookies, csrf)["node-a"]
	if row.DriftState != netGuardDriftDetected {
		t.Fatalf("a changed managed table must read drift: %+v", row)
	}
	if row.AppliedTableSHA != applied {
		t.Fatalf("the posture row must carry what Lattice applied so the two hashes can be shown side by side: %+v", row)
	}
}

func fetchRealityRows(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf string) map[string]guardRealitySummary {
	t.Helper()
	res := doJSON(t, handler, http.MethodGet, "/api/netguard/reality", "", cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("reality list = %d", res.StatusCode)
	}
	var out guardRealityListResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	rows := make(map[string]guardRealitySummary, len(out.Nodes))
	for _, node := range out.Nodes {
		rows[node.NodeID] = node
	}
	return rows
}
