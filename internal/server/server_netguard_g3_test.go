package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func setupAdoptedNetGuardNode(t *testing.T, handler http.Handler, st *store.Store, cookies []*http.Cookie, csrf string) string {
	t.Helper()
	token := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")
	inputs := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
		`{"node_id":"node-a","interface_name":"ens3","public_tcp":[22]}`, cookies, csrf)
	defer inputs.Body.Close()
	if inputs.StatusCode != http.StatusOK {
		t.Fatalf("save nft inputs: %d", inputs.StatusCode)
	}
	adopt := doJSON(t, handler, http.MethodPost, "/api/netguard/nodes/adopt", `{"node_id":"node-a"}`, cookies, csrf)
	defer adopt.Body.Close()
	if adopt.StatusCode != http.StatusOK {
		t.Fatalf("adopt netguard node: %d", adopt.StatusCode)
	}
	if _, ok := st.NodeGuardBinding("node-a"); !ok {
		t.Fatal("adopt did not persist a guard binding")
	}
	return token
}

func TestNetGuardReviewProjection(t *testing.T) {
	now := time.Date(2026, 8, 13, 6, 30, 0, 0, time.UTC)
	_, handler, st, cookies, csrf := newGuardRealityServerForTest(t, &now)
	token := setupAdoptedNetGuardNode(t, handler, st, cookies, csrf)
	if err := st.UpsertGuardZone(model.GuardZone{ID: "corp", Name: "corp", CIDRs: []string{"10.20.0.0/16"}}); err != nil {
		t.Fatal(err)
	}
	group, _ := st.SecurityGroup("sg-legacy-node-a")
	group.Rules = append(group.Rules, model.GuardRule{
		ID: "corp-admin", Action: model.NetRuleAllow, Direction: model.NetDirIngress,
		Protocol: model.NetProtoTCP, Ports: []model.GuardPortRange{{From: 8443, To: 8443}},
		Remote: model.NetEndpoint{Kind: model.NetRefZone, ZoneID: "corp"},
	})
	if _, err := st.UpsertSecurityGroup(group); err != nil {
		t.Fatal(err)
	}

	binding, _ := st.NodeGuardBinding("node-a")
	binding.AppliedTableSHA = strings.Repeat("b", 64)
	stored, err := st.UpsertNodeGuardBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	reality := guardRealityFixture("node-a", now.Add(-time.Minute))
	reality.ManagedSHA = strings.Repeat("a", 64)
	posted := postGuardRealityForTest(t, handler, token, "node-a", reality)
	if posted.code != http.StatusOK {
		t.Fatalf("post reality: %d %s", posted.code, posted.body)
	}

	res := doJSON(t, handler, http.MethodGet, "/api/netguard/review?node_id=node-a", "", cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("review projection: %d", res.StatusCode)
	}
	var out netGuardReviewResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Review.Node.NodeID != "node-a" || out.Review.Node.Source != netGuardSourceStored {
		t.Fatalf("wrong node projection: %+v", out.Review.Node)
	}
	foundGroup, foundCorpZone := false, false
	for _, view := range out.Review.Node.Groups {
		if view.ID == group.ID {
			foundGroup = true
		}
	}
	for _, zone := range out.Review.Node.Zones {
		if zone.ID == "corp" && len(zone.CIDRs) == 1 && zone.CIDRs[0] == "10.20.0.0/16" {
			foundCorpZone = true
		}
	}
	if !foundGroup || !foundCorpZone {
		t.Fatalf("review omitted compiled group/zone dependency: groups=%+v zones=%+v", out.Review.Node.Groups, out.Review.Node.Zones)
	}
	if out.Review.Reality.SnapshotStatus != "fresh" || out.Review.Reality.Reality == nil {
		t.Fatalf("wrong reality projection: %+v", out.Review.Reality)
	}
	if out.Review.DriftState != netGuardDriftDetected {
		t.Fatalf("drift state = %q, want %q", out.Review.DriftState, netGuardDriftDetected)
	}
	foundDrift := false
	for _, suggestion := range out.Review.Suggestions {
		if suggestion.Code == "managed_table_drift" {
			foundDrift = true
		}
	}
	if !foundDrift {
		t.Fatalf("review omitted managed-table drift suggestion: %+v", out.Review.Suggestions)
	}
	if out.Review.ReplanInput.NodeID != "node-a" || out.Review.ReplanInput.AcceptLockoutRisk {
		t.Fatalf("wrong re-plan input: %+v", out.Review.ReplanInput)
	}
	after, _ := st.NodeGuardBinding("node-a")
	if after.Version != stored.Version {
		t.Fatalf("read projection mutated binding version: before=%d after=%d", stored.Version, after.Version)
	}
	withoutRead := createPAT(t, handler, cookies, csrf, []string{"network:plan"}, []string{"node-a"})
	denied := doBearerJSON(t, handler, http.MethodGet, "/api/netguard/review?node_id=node-a", "", withoutRead)
	defer denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("review without netguard:read = %d, want 403", denied.StatusCode)
	}
}

func TestNetGuardBindingOperationalStateIsServerAuthoritative(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	setupAdoptedNetGuardNode(t, handler, st, cookies, csrf)

	appliedAt := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	binding, _ := st.NodeGuardBinding("node-a")
	binding.LastPlanSHA = strings.Repeat("1", 64)
	binding.LastAppliedAt = appliedAt
	binding.LastError = "previous apply failed"
	binding.AppliedTableSHA = strings.Repeat("2", 64)
	binding, err := st.UpsertNodeGuardBinding(binding)
	if err != nil {
		t.Fatal(err)
	}

	forged := `{"node_id":"node-a","managed":true,"version":` + strconv.FormatInt(binding.Version, 10) +
		`,"group_ids":["sg-legacy-node-a"],"last_plan_sha":"` + strings.Repeat("a", 64) +
		`","last_applied_at":"2030-01-01T00:00:00Z","last_error":"forged","applied_table_sha":"` + strings.Repeat("b", 64) + `"}`
	res := doJSON(t, handler, http.MethodPost, "/api/netguard/bindings", forged, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("binding upsert: %d", res.StatusCode)
	}
	kept, _ := st.NodeGuardBinding("node-a")
	if kept.LastPlanSHA != strings.Repeat("1", 64) || !kept.LastAppliedAt.Equal(appliedAt) ||
		kept.LastError != "previous apply failed" || kept.AppliedTableSHA != strings.Repeat("2", 64) {
		t.Fatalf("client overwrote operational state: %+v", kept)
	}

	changedBody := `{"node_id":"node-a","managed":false,"version":` + strconv.FormatInt(kept.Version, 10) +
		`,"group_ids":["sg-legacy-node-a"],"last_plan_sha":"` + strings.Repeat("c", 64) + `"}`
	changedRes := doJSON(t, handler, http.MethodPost, "/api/netguard/bindings", changedBody, cookies, csrf)
	defer changedRes.Body.Close()
	if changedRes.StatusCode != http.StatusOK {
		t.Fatalf("changed binding upsert: %d", changedRes.StatusCode)
	}
	changed, _ := st.NodeGuardBinding("node-a")
	if changed.LastPlanSHA != "" || !strings.Contains(changed.LastError, "binding changed") {
		t.Fatalf("intent change did not invalidate the server plan state: %+v", changed)
	}
	if !changed.LastAppliedAt.Equal(appliedAt) || changed.AppliedTableSHA != strings.Repeat("2", 64) {
		t.Fatalf("intent change erased the last applied anchor: %+v", changed)
	}
}

func TestNetGuardPlanPersistsBindingPlanSHA(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	setupAdoptedNetGuardNode(t, handler, st, cookies, csrf)

	res := doJSON(t, handler, http.MethodPost, "/api/netguard/plan",
		`{"node_id":"node-a","accept_lockout_risk":true}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("netguard plan: %d", res.StatusCode)
	}
	var out struct {
		Approval model.Approval `json:"approval"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	binding, _ := st.NodeGuardBinding("node-a")
	if binding.LastPlanSHA == "" || binding.LastPlanSHA != approvalPlanSHA(out.Approval) || binding.LastError != "" {
		t.Fatalf("plan hash not persisted exactly: binding=%+v approval=%+v", binding, out.Approval)
	}
}

func TestNetGuardStalePlanCannotApprove(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	setupAdoptedNetGuardNode(t, handler, st, cookies, csrf)

	planRes := doJSON(t, handler, http.MethodPost, "/api/netguard/plan",
		`{"node_id":"node-a","accept_lockout_risk":true}`, cookies, csrf)
	defer planRes.Body.Close()
	if planRes.StatusCode != http.StatusOK {
		t.Fatalf("netguard plan: %d", planRes.StatusCode)
	}
	var planned struct {
		Approval model.Approval `json:"approval"`
	}
	if err := json.NewDecoder(planRes.Body).Decode(&planned); err != nil {
		t.Fatal(err)
	}
	binding, _ := st.NodeGuardBinding("node-a")
	change := `{"node_id":"node-a","managed":false,"version":` + strconv.FormatInt(binding.Version, 10) +
		`,"group_ids":["sg-legacy-node-a"]}`
	changed := doJSON(t, handler, http.MethodPost, "/api/netguard/bindings", change, cookies, csrf)
	defer changed.Body.Close()
	if changed.StatusCode != http.StatusOK {
		t.Fatalf("change binding: %d", changed.StatusCode)
	}

	approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		`{"approval_id":"`+planned.Approval.ID+`","queue_apply":true,"plan_sha256":"`+approvalPlanSHA(planned.Approval)+`"}`,
		cookies, csrf)
	defer approve.Body.Close()
	if approve.StatusCode != http.StatusConflict {
		t.Fatalf("stale netguard approval = %d, want 409", approve.StatusCode)
	}
	stored, _ := st.Approval(planned.Approval.ID)
	if stored.Status != model.ApprovalPending {
		t.Fatalf("stale approval changed status: %+v", stored)
	}
}

func TestNetGuardReferencedDependencyChangesInvalidatePlan(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, st *store.Store) func(t *testing.T)
	}{
		{
			name: "attached group rules",
			prepare: func(t *testing.T, st *store.Store) func(t *testing.T) {
				group, _ := st.SecurityGroup("sg-legacy-node-a")
				return func(t *testing.T) {
					group.Rules[0].Ports[0] = model.GuardPortRange{From: 2222, To: 2222}
					if _, err := st.UpsertSecurityGroup(group); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
		{
			name: "referenced zone",
			prepare: func(t *testing.T, st *store.Store) func(t *testing.T) {
				zone := model.GuardZone{ID: "corp", Name: "corp", CIDRs: []string{"10.20.0.0/16"}}
				if err := st.UpsertGuardZone(zone); err != nil {
					t.Fatal(err)
				}
				group, _ := st.SecurityGroup("sg-legacy-node-a")
				group.Rules = append(group.Rules, model.GuardRule{
					ID: "corp-admin", Action: model.NetRuleAllow, Direction: model.NetDirIngress,
					Protocol: model.NetProtoTCP, Ports: []model.GuardPortRange{{From: 8443, To: 8443}},
					Remote: model.NetEndpoint{Kind: model.NetRefZone, ZoneID: zone.ID},
				})
				if _, err := st.UpsertSecurityGroup(group); err != nil {
					t.Fatal(err)
				}
				return func(t *testing.T) {
					zone.CIDRs = []string{"10.30.0.0/16"}
					if err := st.UpsertGuardZone(zone); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
		{
			name: "referenced node address",
			prepare: func(t *testing.T, st *store.Store) func(t *testing.T) {
				peer := model.Node{ID: "node-b", Name: "Node B", PublicIP: "8.8.8.8"}
				if err := st.UpsertNode(peer); err != nil {
					t.Fatal(err)
				}
				group, _ := st.SecurityGroup("sg-legacy-node-a")
				group.Rules = append(group.Rules, model.GuardRule{
					ID: "peer-admin", Action: model.NetRuleAllow, Direction: model.NetDirIngress,
					Protocol: model.NetProtoTCP, Ports: []model.GuardPortRange{{From: 8443, To: 8443}},
					Remote: model.NetEndpoint{Kind: model.NetRefNode, NodeID: peer.ID},
				})
				if _, err := st.UpsertSecurityGroup(group); err != nil {
					t.Fatal(err)
				}
				return func(t *testing.T) {
					peer.PublicIP = "1.1.1.1"
					if err := st.UpsertNode(peer); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, handler, st := newInventoryServer(t)
			cookies, csrf := loginSession(t, handler)
			setupAdoptedNetGuardNode(t, handler, st, cookies, csrf)
			mutate := tc.prepare(t, st)
			approval := planNetGuardApproval(t, handler, cookies, csrf)
			before, _ := st.NodeGuardBinding("node-a")
			mutate(t)
			invalidated, _ := st.NodeGuardBinding("node-a")
			if invalidated.LastPlanSHA != "" || invalidated.Version <= before.Version ||
				!strings.Contains(invalidated.LastError, "dependency changed") {
				t.Fatalf("dependency mutation did not atomically invalidate plan anchor: before=%+v after=%+v", before, invalidated)
			}

			approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
				`{"approval_id":"`+approval.ID+`","queue_apply":false,"plan_sha256":"`+approvalPlanSHA(approval)+`"}`,
				cookies, csrf)
			defer approve.Body.Close()
			if approve.StatusCode != http.StatusConflict {
				t.Fatalf("dependency-stale approval = %d, want 409", approve.StatusCode)
			}
			stored, _ := st.Approval(approval.ID)
			if stored.Status != model.ApprovalPending {
				t.Fatalf("dependency-stale approval changed status: %+v", stored)
			}
		})
	}
}

func TestNetGuardApprovalRequiresManagedSHACapabilityBeforeQueue(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	setupAdoptedNetGuardNode(t, handler, st, cookies, csrf)
	approval := planNetGuardApproval(t, handler, cookies, csrf)
	body := `{"approval_id":"` + approval.ID + `","queue_apply":true,"plan_sha256":"` + approvalPlanSHA(approval) + `"}`

	blocked := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve", body, cookies, csrf)
	blockedData, err := io.ReadAll(blocked.Body)
	blocked.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if blocked.StatusCode != http.StatusConflict || !strings.Contains(string(blockedData), netGuardManagedSHACapability) {
		t.Fatalf("incompatible agent approval = %d, want capability conflict", blocked.StatusCode)
	}
	if len(st.Tasks()) != 0 {
		t.Fatalf("incompatible agent queued a host task: %+v", st.Tasks())
	}
	stored, _ := st.Approval(approval.ID)
	if stored.Status != model.ApprovalPending {
		t.Fatalf("capability failure changed approval: %+v", stored)
	}

	srv.replaceAgentCapabilities("node-a", []string{netGuardManagedSHACapability})
	allowed := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve", body, cookies, csrf)
	defer allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK || len(st.Tasks()) != 1 {
		t.Fatalf("capable agent approval = %d tasks=%+v", allowed.StatusCode, st.Tasks())
	}
}

func TestAgentHeartbeatNegotiatesNetGuardManagedSHACapability(t *testing.T) {
	srv, handler, _ := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	token := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")
	capable := doAgentRaw(t, handler, http.MethodPost, "/api/agent/hello",
		`{"node_id":"node-a","version":"0.3.3","capabilities":["`+netGuardManagedSHACapability+`"]}`, token)
	if capable.Code != http.StatusOK || !srv.agentHasCapability("node-a", netGuardManagedSHACapability) {
		t.Fatalf("capable heartbeat = %d capability=%v", capable.Code, srv.agentHasCapability("node-a", netGuardManagedSHACapability))
	}
	legacy := doAgentRaw(t, handler, http.MethodPost, "/api/agent/hello",
		`{"node_id":"node-a","version":"0.3.3"}`, token)
	if legacy.Code != http.StatusOK || srv.agentHasCapability("node-a", netGuardManagedSHACapability) {
		t.Fatalf("legacy heartbeat did not clear capability: status=%d capability=%v", legacy.Code, srv.agentHasCapability("node-a", netGuardManagedSHACapability))
	}
}

func TestQueuedNetGuardTaskIsWithheldAfterAgentCapabilityDowngrade(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	token := setupAdoptedNetGuardNode(t, handler, st, cookies, csrf)
	approval := planNetGuardApproval(t, handler, cookies, csrf)
	srv.replaceAgentCapabilities("node-a", []string{netGuardManagedSHACapability})
	approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		`{"approval_id":"`+approval.ID+`","queue_apply":true,"plan_sha256":"`+approvalPlanSHA(approval)+`"}`,
		cookies, csrf)
	approve.Body.Close()
	if approve.StatusCode != http.StatusOK || len(st.Tasks()) != 1 {
		t.Fatalf("queue capable netguard task: status=%d tasks=%+v", approve.StatusCode, st.Tasks())
	}

	legacy := doAgentRaw(t, handler, http.MethodPost, "/api/agent/metrics",
		`{"node_id":"node-a","version":"0.3.2","metrics":{}}`, token)
	if legacy.Code != http.StatusOK || srv.agentHasCapability("node-a", netGuardManagedSHACapability) {
		t.Fatalf("legacy heartbeat did not clear capability: status=%d", legacy.Code)
	}
	blocked := doAgentRaw(t, handler, http.MethodGet, "/api/agent/tasks?node_id=node-a", "", token)
	if blocked.Code != http.StatusOK {
		t.Fatalf("legacy task poll: %d %s", blocked.Code, blocked.Body.String())
	}
	var blockedTasks []agentTaskView
	if err := json.Unmarshal(blocked.Body.Bytes(), &blockedTasks); err != nil {
		t.Fatal(err)
	}
	if len(blockedTasks) != 0 {
		t.Fatalf("legacy agent received capability-gated task: %+v", blockedTasks)
	}
	queued, _ := st.Task(st.Tasks()[0].ID)
	if queued.Status != model.TaskQueued {
		t.Fatalf("withheld task was mutated: %+v", queued)
	}

	capable := doAgentRaw(t, handler, http.MethodPost, "/api/agent/metrics",
		`{"node_id":"node-a","version":"0.3.3","capabilities":["`+netGuardManagedSHACapability+`"],"metrics":{}}`, token)
	if capable.Code != http.StatusOK {
		t.Fatalf("capable heartbeat: %d %s", capable.Code, capable.Body.String())
	}
	allowedReq := httptest.NewRequest(http.MethodGet, "/api/agent/tasks?node_id=node-a", nil)
	allowedReq.Header.Set("Authorization", "Bearer "+token)
	allowedReq.Header.Set(agentCapabilitiesHeader, netGuardManagedSHACapability)
	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, allowedReq)
	if allowed.Code != http.StatusOK {
		t.Fatalf("capable task poll: %d %s", allowed.Code, allowed.Body.String())
	}
	var allowedTasks []agentTaskView
	if err := json.Unmarshal(allowed.Body.Bytes(), &allowedTasks); err != nil {
		t.Fatal(err)
	}
	if len(allowedTasks) != 1 || !allowedTasks[0].DurableResult || !strings.Contains(allowedTasks[0].Script, "--guard-managed-sha") {
		t.Fatalf("capable agent did not receive netguard task: %+v", allowedTasks)
	}
	leasedID := allowedTasks[0].LeaseID
	legacyRetry := doAgentRaw(t, handler, http.MethodGet, "/api/agent/tasks?node_id=node-a", "", token)
	if legacyRetry.Code != http.StatusOK {
		t.Fatalf("legacy redelivery poll: %d %s", legacyRetry.Code, legacyRetry.Body.String())
	}
	if err := json.Unmarshal(legacyRetry.Body.Bytes(), &blockedTasks); err != nil {
		t.Fatal(err)
	}
	if len(blockedTasks) != 0 {
		t.Fatalf("capability downgrade received an existing netguard lease: %+v", blockedTasks)
	}
	allowedAgain := httptest.NewRecorder()
	handler.ServeHTTP(allowedAgain, allowedReq.Clone(allowedReq.Context()))
	if allowedAgain.Code != http.StatusOK {
		t.Fatalf("capable redelivery poll: %d %s", allowedAgain.Code, allowedAgain.Body.String())
	}
	var redelivered []agentTaskView
	if err := json.Unmarshal(allowedAgain.Body.Bytes(), &redelivered); err != nil {
		t.Fatal(err)
	}
	if len(redelivered) != 1 || redelivered[0].LeaseID != leasedID {
		t.Fatalf("capability recovery changed lease: first=%+v redelivered=%+v", allowedTasks, redelivered)
	}
	zeroFinished := fmt.Sprintf(
		`{"node_id":"node-a","result":{"task_id":%q,"lease_id":%q,"exit_code":0}}`,
		allowedTasks[0].ID, leasedID,
	)
	rejected := doAgentRaw(t, handler, http.MethodPost, "/api/agent/task-result", zeroFinished, token)
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("netguard result without finished_at = %d %s, want 400", rejected.Code, rejected.Body.String())
	}
}

func TestNetGuardActionRetainsLegacyAutoApprovalPrefix(t *testing.T) {
	rule := approvalAutoRule{ActionPrefix: "apply-ruleset"}
	if !rule.matches(model.Approval{Plugin: "nft", Action: netGuardApprovalAction}) {
		t.Fatalf("existing apply-ruleset prefix stopped matching %q", netGuardApprovalAction)
	}
	if netGuardApprovalAction == "apply-ruleset" {
		t.Fatal("netguard action must remain distinguishable from legacy nft")
	}
}

func TestLegacyNFTApplyOnAdoptedNodeRemainsCompatible(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	token := setupAdoptedNetGuardNode(t, handler, st, cookies, csrf)
	before, _ := st.NodeGuardBinding("node-a")

	plan := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan", `{"node_id":"node-a"}`, cookies, csrf)
	defer plan.Body.Close()
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("legacy nft plan: %d", plan.StatusCode)
	}
	var approval model.Approval
	if err := json.NewDecoder(plan.Body).Decode(&approval); err != nil {
		t.Fatal(err)
	}
	if isNetGuardApproval(approval) || approval.Action != "apply-ruleset" {
		t.Fatalf("legacy plan was misclassified: %+v", approval)
	}
	approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		`{"approval_id":"`+approval.ID+`","queue_apply":true,"plan_sha256":"`+approvalPlanSHA(approval)+`"}`,
		cookies, csrf)
	defer approve.Body.Close()
	if approve.StatusCode != http.StatusOK {
		t.Fatalf("legacy nft approve: %d", approve.StatusCode)
	}
	leased, err := st.LeaseTasks("node-a", 10)
	if err != nil || len(leased) != 1 {
		t.Fatalf("legacy nft lease: tasks=%+v err=%v", leased, err)
	}
	if strings.Contains(leased[0].Script, "--guard-managed-sha") {
		t.Fatalf("legacy nft task requires unreleased agent helper:\n%s", leased[0].Script)
	}
	posted := postNetGuardTaskResult(t, handler, token, leased[0], model.TaskResult{ExitCode: 0, Stdout: "lattice nft: applied\n"})
	if posted.Code != http.StatusOK {
		t.Fatalf("legacy nft result: %d %s", posted.Code, posted.Body.String())
	}
	after, _ := st.NodeGuardBinding("node-a")
	if after.Version != before.Version || after.LastAppliedAt != before.LastAppliedAt || after.AppliedTableSHA != before.AppliedTableSHA {
		t.Fatalf("legacy nft result mutated netguard binding: before=%+v after=%+v", before, after)
	}
}

func TestNetGuardApplyResultPersistsCanonicalSHA(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	token := setupAdoptedNetGuardNode(t, handler, st, cookies, csrf)
	approval, task := planApproveAndLeaseNetGuard(t, srv, handler, st, cookies, csrf)
	managedSHA := strings.Repeat("a", 64)
	finishedAt := time.Date(2026, 8, 13, 7, 0, 0, 0, time.UTC)
	result := model.TaskResult{
		ExitCode:   0,
		Stdout:     "lattice nft: applied\n" + netGuardManagedSHAResultPrefix + managedSHA + "\n",
		FinishedAt: finishedAt,
	}
	posted := postNetGuardTaskResult(t, handler, token, task, result)
	if posted.Code != http.StatusOK {
		t.Fatalf("post netguard result: %d %s", posted.Code, posted.Body.String())
	}
	binding, _ := st.NodeGuardBinding(approval.NodeID)
	if binding.AppliedTableSHA != managedSHA || !binding.LastAppliedAt.Equal(finishedAt) || binding.LastError != "" {
		t.Fatalf("canonical apply state not persisted: %+v", binding)
	}
	storedApproval, _ := st.Approval(approval.ID)
	if storedApproval.Status != model.ApprovalApplied {
		t.Fatalf("approval status = %q, want applied", storedApproval.Status)
	}
	results := st.Results()
	storedTask, _ := st.Task(task.ID)
	if len(results) != 1 || results[0].LeaseID != "" || storedTask.Status != model.TaskFinished {
		t.Fatalf("atomic result/task transition incomplete: results=%+v task=%+v", results, storedTask)
	}
	replayed := postNetGuardTaskResult(t, handler, token, task, result)
	if replayed.Code != http.StatusOK || len(st.Results()) != 1 {
		t.Fatalf("identical durable result replay was not idempotent: status=%d results=%+v", replayed.Code, st.Results())
	}
	wrongLease := task
	wrongLease.LeaseID = "lease_wrong"
	conflict := postNetGuardTaskResult(t, handler, token, wrongLease, result)
	if conflict.Code != http.StatusConflict || len(st.Results()) != 1 {
		t.Fatalf("result replay with a different lease was accepted: status=%d results=%+v", conflict.Code, st.Results())
	}
	script := applyScriptForWithServer(approval, "https://control.example")
	for _, want := range []string{"--guard-managed-sha", netGuardManagedSHAResultPrefix} {
		if !strings.Contains(script, want) {
			t.Fatalf("apply script does not emit canonical result %q:\n%s", want, script)
		}
	}
}

func TestNetGuardApplyResultRejectsStalePlan(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	token := setupAdoptedNetGuardNode(t, handler, st, cookies, csrf)
	approval, task := planApproveAndLeaseNetGuard(t, srv, handler, st, cookies, csrf)
	binding, _ := st.NodeGuardBinding(approval.NodeID)
	binding.LastPlanSHA = strings.Repeat("f", 64)
	if _, err := st.UpsertNodeGuardBinding(binding); err != nil {
		t.Fatal(err)
	}
	result := model.TaskResult{ExitCode: 0, Stdout: netGuardManagedSHAResultPrefix + strings.Repeat("a", 64)}
	posted := postNetGuardTaskResult(t, handler, token, task, result)
	if posted.Code != http.StatusOK {
		t.Fatalf("post stale netguard result: %d %s", posted.Code, posted.Body.String())
	}
	stale, _ := st.NodeGuardBinding(approval.NodeID)
	if stale.AppliedTableSHA != "" || stale.LastAppliedAt.IsZero() == false || !strings.Contains(stale.LastError, "stale netguard plan") {
		t.Fatalf("stale result changed current apply state: %+v", stale)
	}
	storedApproval, _ := st.Approval(approval.ID)
	if storedApproval.Status != model.ApprovalRejected || !strings.Contains(storedApproval.Reason, "stale netguard plan") {
		t.Fatalf("stale approval not closed honestly: %+v", storedApproval)
	}
}

func TestNetGuardApplyResultRejectsDependencyChangedAfterQueue(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	token := setupAdoptedNetGuardNode(t, handler, st, cookies, csrf)
	approval, task := planApproveAndLeaseNetGuard(t, srv, handler, st, cookies, csrf)

	group, _ := st.SecurityGroup("sg-legacy-node-a")
	group.Rules[0].Ports[0] = model.GuardPortRange{From: 2222, To: 2222}
	if _, err := st.UpsertSecurityGroup(group); err != nil {
		t.Fatal(err)
	}
	posted := postNetGuardTaskResult(t, handler, token, task, model.TaskResult{
		ExitCode: 0,
		Stdout:   netGuardManagedSHAResultPrefix + strings.Repeat("a", 64),
	})
	if posted.Code != http.StatusOK {
		t.Fatalf("post dependency-stale result: %d %s", posted.Code, posted.Body.String())
	}
	binding, _ := st.NodeGuardBinding("node-a")
	if binding.AppliedTableSHA != "" || !strings.Contains(binding.LastError, "dependency changed") {
		t.Fatalf("dependency-stale result looked applied: %+v", binding)
	}
	storedApproval, _ := st.Approval(approval.ID)
	if storedApproval.Status != model.ApprovalRejected || !strings.Contains(storedApproval.Reason, "dependency changed") {
		t.Fatalf("dependency-stale approval not rejected: %+v", storedApproval)
	}
}

func TestNetGuardApplyResultPersistsFailure(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	token := setupAdoptedNetGuardNode(t, handler, st, cookies, csrf)
	approval, task := planApproveAndLeaseNetGuard(t, srv, handler, st, cookies, csrf)
	result := model.TaskResult{ExitCode: 1, Error: "exit status 1", Stderr: "nft apply failed"}
	posted := postNetGuardTaskResult(t, handler, token, task, result)
	if posted.Code != http.StatusOK {
		t.Fatalf("post failed netguard result: %d %s", posted.Code, posted.Body.String())
	}
	failed, _ := st.NodeGuardBinding(approval.NodeID)
	if failed.AppliedTableSHA != "" || !strings.Contains(failed.LastError, "nft apply failed") {
		t.Fatalf("failure was not persisted: %+v", failed)
	}
}

func TestNetGuardApplyResultRequiresCanonicalSHA(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	token := setupAdoptedNetGuardNode(t, handler, st, cookies, csrf)
	approval, task := planApproveAndLeaseNetGuard(t, srv, handler, st, cookies, csrf)
	result := model.TaskResult{ExitCode: 0, Stdout: "lattice nft: applied and verified\n"}
	posted := postNetGuardTaskResult(t, handler, token, task, result)
	if posted.Code != http.StatusOK {
		t.Fatalf("post hashless netguard result: %d %s", posted.Code, posted.Body.String())
	}
	failed, _ := st.NodeGuardBinding(approval.NodeID)
	if failed.AppliedTableSHA != "" || !strings.Contains(failed.LastError, "did not return the canonical") {
		t.Fatalf("missing canonical SHA looked successful: %+v", failed)
	}
}

func TestNetGuardApplyResultPersistenceFailureIsNotAcknowledged(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	st, err := store.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)
	token := setupAdoptedNetGuardNode(t, handler, st, cookies, csrf)
	approval, task := planApproveAndLeaseNetGuard(t, srv, handler, st, cookies, csrf)
	beforeBinding, _ := st.NodeGuardBinding("node-a")

	if err := os.Mkdir(statePath+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(statePath+".tmp", "block"), []byte("block atomic rename"), 0o600); err != nil {
		t.Fatal(err)
	}
	posted := postNetGuardTaskResult(t, handler, token, task, model.TaskResult{
		ExitCode: 0,
		Stdout:   netGuardManagedSHAResultPrefix + strings.Repeat("a", 64),
	})
	if posted.Code != http.StatusInternalServerError {
		t.Fatalf("persistence failure = %d, want 500: %s", posted.Code, posted.Body.String())
	}
	if got := st.Results(); len(got) != 0 {
		t.Fatalf("failed atomic commit retained terminal result: %+v", got)
	}
	storedTask, _ := st.Task(task.ID)
	if storedTask.Status != model.TaskLeased {
		t.Fatalf("failed atomic commit made task terminal: %+v", storedTask)
	}
	afterBinding, _ := st.NodeGuardBinding("node-a")
	if afterBinding.Version != beforeBinding.Version || afterBinding.AppliedTableSHA != "" || !afterBinding.LastAppliedAt.IsZero() {
		t.Fatalf("failed atomic commit partially updated binding: before=%+v after=%+v", beforeBinding, afterBinding)
	}
	storedApproval, _ := st.Approval(approval.ID)
	if storedApproval.Status != model.ApprovalApproved {
		t.Fatalf("failed atomic commit partially updated approval: %+v", storedApproval)
	}
}

func planNetGuardApproval(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf string) model.Approval {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/netguard/plan",
		`{"node_id":"node-a","accept_lockout_risk":true}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("netguard plan: %d", res.StatusCode)
	}
	var out struct {
		Approval model.Approval `json:"approval"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.Approval
}

func planApproveAndLeaseNetGuard(t *testing.T, srv *Server, handler http.Handler, st *store.Store, cookies []*http.Cookie, csrf string) (model.Approval, model.Task) {
	t.Helper()
	approval := planNetGuardApproval(t, handler, cookies, csrf)
	srv.replaceAgentCapabilities(approval.NodeID, []string{netGuardManagedSHACapability})
	approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		`{"approval_id":"`+approval.ID+`","queue_apply":true,"plan_sha256":"`+approvalPlanSHA(approval)+`"}`,
		cookies, csrf)
	defer approve.Body.Close()
	if approve.StatusCode != http.StatusOK {
		t.Fatalf("approve netguard plan: %d", approve.StatusCode)
	}
	leased, err := st.LeaseTasks(approval.NodeID, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range leased {
		if task.ApprovalID == approval.ID {
			return approval, task
		}
	}
	t.Fatalf("no leased task for approval %s: %+v", approval.ID, leased)
	return model.Approval{}, model.Task{}
}

func postNetGuardTaskResult(t *testing.T, handler http.Handler, token string, task model.Task, result model.TaskResult) *httptest.ResponseRecorder {
	t.Helper()
	result.TaskID = task.ID
	result.LeaseID = task.LeaseID
	if result.FinishedAt.IsZero() {
		result.FinishedAt = time.Date(2026, 8, 13, 7, 30, 0, 0, time.UTC)
	}
	payload, err := json.Marshal(map[string]any{
		"node_id": task.LeasedBy,
		"result":  result,
	})
	if err != nil {
		t.Fatal(err)
	}
	return doAgentRaw(t, handler, http.MethodPost, "/api/agent/task-result", string(payload), token)
}
