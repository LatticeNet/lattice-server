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
		`{"node_id":"node-a","interface_name":"ens3","public_tcp":[22,443]}`, cookies, csrf)
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
		`{"node_id":"node-b","interface_name":"ens3","public_tcp":[2222,443]}`, cookies, csrf)
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
// An observe-only binding is not an adoption. The port plan writes one for
// every node it looks at, so "already adopted" on its mere existence would
// force an operator to delete the record before adopting the node it
// describes. Adoption replaces it with the managed legacy baseline; a second
// adoption of a managed node is still the conflict it always was.
func TestNetGuardAdoptReplacesAnObserveOnlyBinding(t *testing.T) {
	handler, st := newTestServerWithPublicURL(t, "https://203.0.113.99")
	cookies, csrf := loginSession(t, handler)
	enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
		`{"node_id":"node-a","interface_name":"ens3","public_tcp":[22,443]}`, cookies, csrf)
	defer save.Body.Close()
	observe, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "node-a", Managed: false})
	if err != nil {
		t.Fatalf("seed observe-only binding: %v", err)
	}

	adopt := doJSON(t, handler, http.MethodPost, "/api/netguard/nodes/adopt", `{"node_id":"node-a"}`, cookies, csrf)
	defer adopt.Body.Close()
	if adopt.StatusCode != http.StatusOK {
		t.Fatalf("adopting over an observe-only binding = %d, want 200", adopt.StatusCode)
	}
	managed, ok := st.NodeGuardBinding("node-a")
	if !ok || !managed.Managed || len(managed.GroupIDs) != 1 {
		t.Fatalf("adoption must leave a managed binding on the legacy group, got ok=%v %+v", ok, managed)
	}
	if managed.Version != observe.Version+1 {
		t.Fatalf("adoption replaces the record in place: version %d want %d", managed.Version, observe.Version+1)
	}

	again := doJSON(t, handler, http.MethodPost, "/api/netguard/nodes/adopt", `{"node_id":"node-a"}`, cookies, csrf)
	defer again.Body.Close()
	if again.StatusCode != http.StatusConflict {
		t.Fatalf("adopting a managed node = %d, want 409", again.StatusCode)
	}
}

// Adoption reuses the observe-only record's version for its upsert, so it is
// now an optimistic-concurrency write like every other binding upsert in the
// file. A version bump between the read and the write must surface as the
// same 409 the sibling handlers return, not as a raw 500. The handler produces
// that bump itself when the record references the legacy group and carries a
// plan sha: storing the group invalidates the binding.
func TestNetGuardAdoptReportsBindingVersionConflictAs409(t *testing.T) {
	handler, st := newTestServerWithPublicURL(t, "https://203.0.113.99")
	cookies, csrf := loginSession(t, handler)
	enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
		`{"node_id":"node-a","interface_name":"ens3","public_tcp":[22,443]}`, cookies, csrf)
	defer save.Body.Close()
	_, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{
		NodeID:      "node-a",
		Managed:     false,
		GroupIDs:    []string{netguard.LegacyGroupPrefix + "node-a"},
		LastPlanSHA: "sha256:stale-observe-only-plan",
	})
	if err != nil {
		t.Fatalf("seed observe-only binding: %v", err)
	}

	adopt := doJSON(t, handler, http.MethodPost, "/api/netguard/nodes/adopt", `{"node_id":"node-a"}`, cookies, csrf)
	defer adopt.Body.Close()
	if adopt.StatusCode != http.StatusConflict {
		t.Fatalf("adopt over a binding whose version moved = %d, want 409", adopt.StatusCode)
	}
	var body model.APIErrorResponse
	if err := json.NewDecoder(adopt.Body).Decode(&body); err != nil {
		t.Fatalf("decode adopt error: %v", err)
	}
	if !strings.Contains(body.Error.Message, "version conflict") {
		t.Fatalf("adopt conflict message = %q, want the store's version conflict message", body.Error.Message)
	}
}

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

// The eth0 assumption end to end: no NFTInputs interface, so the public zone
// resolves to eth0, on a node that reports ens17. Twelve fleet nodes look like
// this. The plan opens the real sshd port, so the port check is happy; the
// interface check is what has to refuse it.
func TestNetGuardPlanBlocksWhenThePublicInterfaceIsNotOnTheNode(t *testing.T) {
	handler, st := newTestServerWithPublicURL(t, "https://203.0.113.99")
	cookies, csrf := loginSession(t, handler)
	token := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")
	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
		`{"node_id":"node-a","public_tcp":[22]}`, cookies, csrf)
	defer save.Body.Close()
	adopt := doJSON(t, handler, http.MethodPost, "/api/netguard/nodes/adopt", `{"node_id":"node-a"}`, cookies, csrf)
	defer adopt.Body.Close()
	if adopt.StatusCode != http.StatusOK {
		t.Fatalf("adopt: %d", adopt.StatusCode)
	}
	reality := model.GuardNodeReality{
		NodeID:      "node-a",
		CollectedAt: time.Now().UTC().Add(-time.Minute),
		Listeners:   []model.GuardListener{{Protocol: "tcp", Port: 22, Address: "0.0.0.0", Process: "sshd(701)"}},
		Interfaces: []model.GuardInterface{
			{Name: "lo", Up: true},
			{Name: "ens17", Addresses: []string{"203.0.113.10/24"}, Up: true},
		},
	}
	if posted := postGuardRealityForTest(t, handler, token, "node-a", reality); posted.code != http.StatusOK {
		t.Fatalf("post guard reality = %d: %s", posted.code, posted.body)
	}

	blocked := doJSON(t, handler, http.MethodPost, "/api/netguard/plan", `{"node_id":"node-a"}`, cookies, csrf)
	defer blocked.Body.Close()
	if blocked.StatusCode != http.StatusConflict {
		t.Fatalf("a plan on an interface the node does not have = %d, want 409", blocked.StatusCode)
	}
	var blockedRes struct {
		Findings []netguard.Finding `json:"findings"`
	}
	if err := json.NewDecoder(blocked.Body).Decode(&blockedRes); err != nil {
		t.Fatal(err)
	}
	if !hasFinding(blockedRes.Findings, netguard.FindingInterfaceMissing) {
		t.Fatalf("findings = %+v", blockedRes.Findings)
	}
	if hasFinding(blockedRes.Findings, netguard.FindingLockoutRiskSSH) {
		t.Fatalf("the port check is satisfied here; only the interface may block: %+v", blockedRes.Findings)
	}
	if len(st.Approvals()) != 0 {
		t.Fatalf("a blocked plan must not file an approval: %+v", st.Approvals())
	}

	// The review preview must say the same thing, or an operator reads a clean
	// preview and then watches the plan refuse.
	review := doJSON(t, handler, http.MethodGet, "/api/netguard/review?node_id=node-a", "", cookies, csrf)
	defer review.Body.Close()
	var out netGuardReviewResponse
	if err := json.NewDecoder(review.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !hasFinding(out.Review.Findings, netguard.FindingInterfaceMissing) {
		t.Fatalf("review findings = %+v", out.Review.Findings)
	}
}

// The same hole with no evidence at all: a freshly enrolled node, or one on an
// agent too old to report interfaces, has never said what interfaces it has.
// The public zone still resolves to eth0. The lint cannot confirm eth0 exists,
// and "cannot confirm" fails closed: 409, no approval, until the operator
// accepts the lockout risk on purpose.
func TestNetGuardPlanBlocksWhenTheNodeHasNeverReportedInterfaces(t *testing.T) {
	handler, st := newTestServerWithPublicURL(t, "https://203.0.113.99")
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
		`{"node_id":"node-a","public_tcp":[22]}`, cookies, csrf)
	defer save.Body.Close()
	adopt := doJSON(t, handler, http.MethodPost, "/api/netguard/nodes/adopt", `{"node_id":"node-a"}`, cookies, csrf)
	defer adopt.Body.Close()
	if adopt.StatusCode != http.StatusOK {
		t.Fatalf("adopt: %d", adopt.StatusCode)
	}

	// No reality posted: nil reality on the lint side.
	blocked := doJSON(t, handler, http.MethodPost, "/api/netguard/plan", `{"node_id":"node-a"}`, cookies, csrf)
	defer blocked.Body.Close()
	if blocked.StatusCode != http.StatusConflict {
		t.Fatalf("a plan on eth0 for a node that never reported = %d, want 409", blocked.StatusCode)
	}
	var blockedRes struct {
		Findings []netguard.Finding `json:"findings"`
	}
	if err := json.NewDecoder(blocked.Body).Decode(&blockedRes); err != nil {
		t.Fatal(err)
	}
	if !hasFinding(blockedRes.Findings, netguard.FindingInterfaceUnverified) {
		t.Fatalf("findings = %+v", blockedRes.Findings)
	}
	if hasFinding(blockedRes.Findings, netguard.FindingInterfaceMissing) || hasFinding(blockedRes.Findings, netguard.FindingLockoutRiskSSH) {
		t.Fatalf("only the unverified interface may block here: %+v", blockedRes.Findings)
	}
	if len(st.Approvals()) != 0 {
		t.Fatalf("a blocked plan must not file an approval: %+v", st.Approvals())
	}

	// The review preview says the same thing.
	review := doJSON(t, handler, http.MethodGet, "/api/netguard/review?node_id=node-a", "", cookies, csrf)
	defer review.Body.Close()
	var out netGuardReviewResponse
	if err := json.NewDecoder(review.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !hasFinding(out.Review.Findings, netguard.FindingInterfaceUnverified) {
		t.Fatalf("review findings = %+v", out.Review.Findings)
	}

	// The only way past is the same explicit, audited flag as every other
	// lockout finding.
	accepted := doJSON(t, handler, http.MethodPost, "/api/netguard/plan",
		`{"node_id":"node-a","accept_lockout_risk":true}`, cookies, csrf)
	defer accepted.Body.Close()
	if accepted.StatusCode != http.StatusOK {
		t.Fatalf("accepting the lockout risk = %d, want 200", accepted.StatusCode)
	}
	if len(st.Approvals()) != 1 {
		t.Fatalf("an accepted plan must file exactly one approval: %+v", st.Approvals())
	}
}

// Review used to demand a stored binding, so every one of the fleet's 33 nodes
// answered "adopt it first" and server-side suggestions never ran for anyone.
// An unbound node now compiles as an empty observe-only binding: the review
// says intent cannot be compiled, suggestions still say which listeners have
// no allow, nothing is written, and planning stays impossible.
func TestNetGuardReviewRunsForUnboundAndLegacyNodes(t *testing.T) {
	handler, st := newTestServerWithPublicURL(t, "https://203.0.113.99")
	cookies, csrf := loginSession(t, handler)
	token := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")
	reality := model.GuardNodeReality{
		NodeID:      "node-a",
		CollectedAt: time.Now().UTC().Add(-time.Minute),
		Listeners:   []model.GuardListener{{Protocol: "tcp", Port: 22, Address: "0.0.0.0", Process: "sshd(701)"}},
		Interfaces:  []model.GuardInterface{{Name: "ens17", Addresses: []string{"203.0.113.10/24"}, Up: true}},
	}
	if posted := postGuardRealityForTest(t, handler, token, "node-a", reality); posted.code != http.StatusOK {
		t.Fatalf("post guard reality = %d: %s", posted.code, posted.body)
	}

	res := doJSON(t, handler, http.MethodGet, "/api/netguard/review?node_id=node-a", "", cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("review of an unbound node = %d, want 200", res.StatusCode)
	}
	var out netGuardReviewResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Review.Node.Source != netGuardSourceUnbound || out.Review.Node.Binding.Managed {
		t.Fatalf("an unbound node must review as an unbound observe-only intent: %+v", out.Review.Node)
	}
	if !strings.Contains(out.Review.CompileError, "observe-only") || out.Review.Ruleset != "" {
		t.Fatalf("no intent means no ruleset: error=%q ruleset=%q", out.Review.CompileError, out.Review.Ruleset)
	}
	var missingAllow bool
	for _, suggestion := range out.Review.Suggestions {
		if suggestion.Code == netguard.SuggestionListenerMissingAllow && suggestion.Port == 22 {
			missingAllow = true
		}
	}
	if !missingAllow {
		t.Fatalf("suggestions must run against reality with no intent: %+v", out.Review.Suggestions)
	}
	if _, ok := st.NodeGuardBinding("node-a"); ok {
		t.Fatal("review must not create a binding record")
	}

	// Planning from the synthesised binding stays impossible.
	plan := doJSON(t, handler, http.MethodPost, "/api/netguard/plan", `{"node_id":"node-a"}`, cookies, csrf)
	defer plan.Body.Close()
	if plan.StatusCode != http.StatusBadRequest {
		t.Fatalf("plan for an unbound node = %d, want 400", plan.StatusCode)
	}
	if _, ok := st.NodeGuardBinding("node-a"); ok || len(st.Approvals()) != 0 {
		t.Fatal("a refused plan must leave no binding and no approval behind")
	}

	// A legacy node (NFT inputs, never adopted) is the same case.
	enrollNamedNode(t, handler, cookies, csrf, "node-b", "Node B")
	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
		`{"node_id":"node-b","interface_name":"ens3","public_tcp":[22]}`, cookies, csrf)
	defer save.Body.Close()
	legacy := doJSON(t, handler, http.MethodGet, "/api/netguard/review?node_id=node-b", "", cookies, csrf)
	defer legacy.Body.Close()
	if legacy.StatusCode != http.StatusOK {
		t.Fatalf("review of a legacy node = %d, want 200", legacy.StatusCode)
	}
	if _, ok := st.NodeGuardBinding("node-b"); ok {
		t.Fatal("review of a legacy node must not adopt it")
	}
}
