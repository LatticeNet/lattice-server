package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func decodeNodeDeleteSummary(t *testing.T, res *http.Response) nodeDeleteSummary {
	t.Helper()
	defer res.Body.Close()
	var out nodeDeleteSummary
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	return out
}

// TestNodeDeletePlanIsNonMutating verifies the /plan endpoint reports the
// would-delete counts (here: the node's DDNS profile) without removing the node.
func TestNodeDeletePlanIsNonMutating(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, _ := enrollNode(t, handler, cookies, csrf)

	if err := st.UpsertDDNSProfile(model.DDNSProfile{ID: "ddns-1", NodeID: nodeID, Provider: model.DDNSProviderCloudflare}); err != nil {
		t.Fatalf("seed ddns: %v", err)
	}

	res := doJSON(t, handler, http.MethodPost, "/api/nodes/delete/plan", `{"node_id":"`+nodeID+`"}`, cookies, csrf)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("plan status = %d", res.StatusCode)
	}
	summary := decodeNodeDeleteSummary(t, res)
	if summary.Mutated {
		t.Fatal("plan reported mutated=true")
	}
	if !summary.Found {
		t.Fatal("plan reported found=false")
	}
	if summary.DDNSProfiles != 1 {
		t.Fatalf("plan ddns_profiles = %d want 1", summary.DDNSProfiles)
	}
	// The node must still exist after a plan.
	if _, ok := st.Node(nodeID); !ok {
		t.Fatal("plan deleted the node")
	}
}

// TestNodeDeleteRemovesNodeAndAudits verifies a delete returns the summary,
// removes the node and its resources, and records exactly one node.delete audit
// event with metadata. The /plan endpoint records no audit.
func TestNodeDeleteRemovesNodeAndAudits(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, _ := enrollNode(t, handler, cookies, csrf)

	if err := st.UpsertDDNSProfile(model.DDNSProfile{ID: "ddns-1", NodeID: nodeID, Provider: model.DDNSProviderCloudflare}); err != nil {
		t.Fatalf("seed ddns: %v", err)
	}

	// A plan first: it must not write an audit row.
	planRes := doJSON(t, handler, http.MethodPost, "/api/nodes/delete/plan", `{"node_id":"`+nodeID+`"}`, cookies, csrf)
	planRes.Body.Close()
	if planRes.StatusCode != http.StatusOK {
		t.Fatalf("plan status = %d", planRes.StatusCode)
	}
	auditBefore := countDeleteAudits(st, nodeID)

	res := doJSON(t, handler, http.MethodPost, "/api/nodes/delete", `{"node_id":"`+nodeID+`"}`, cookies, csrf)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d", res.StatusCode)
	}
	summary := decodeNodeDeleteSummary(t, res)
	if !summary.Mutated {
		t.Fatal("delete reported mutated=false")
	}
	if summary.DDNSProfiles != 1 {
		t.Fatalf("delete ddns_profiles = %d want 1", summary.DDNSProfiles)
	}

	if _, ok := st.Node(nodeID); ok {
		t.Fatal("node survived delete")
	}
	if len(st.DDNSProfilesForNode(nodeID)) != 0 {
		t.Fatal("ddns survived delete")
	}

	// Exactly one node.delete audit row was added by the delete (plan added none).
	if got := countDeleteAudits(st, nodeID); got != auditBefore+1 {
		t.Fatalf("node.delete audit count = %d want %d", got, auditBefore+1)
	}
	ev := lastDeleteAudit(st, nodeID)
	if ev.Scope != "node:admin" {
		t.Fatalf("audit scope = %q want node:admin", ev.Scope)
	}
	if ev.Metadata["ddns"] != "1" {
		t.Fatalf("audit metadata ddns = %q want 1", ev.Metadata["ddns"])
	}

	// Idempotent: a second delete returns 404.
	res2 := doJSON(t, handler, http.MethodPost, "/api/nodes/delete", `{"node_id":"`+nodeID+`"}`, cookies, csrf)
	res2.Body.Close()
	if res2.StatusCode != http.StatusNotFound {
		t.Fatalf("second delete status = %d want 404", res2.StatusCode)
	}
}

// TestNodeDeleteRequiresAuthAndCSRF verifies the destructive endpoints reject
// unauthenticated and CSRF-less requests and validate the body.
func TestNodeDeleteRequiresAuthAndCSRF(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, _ := enrollNode(t, handler, cookies, csrf)

	// No session at all -> 401.
	noAuth := doJSON(t, handler, http.MethodPost, "/api/nodes/delete", `{"node_id":"`+nodeID+`"}`, nil, "")
	noAuth.Body.Close()
	if noAuth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d want 401", noAuth.StatusCode)
	}

	// Session cookie but missing CSRF header on an unsafe method -> 403.
	noCSRF := doJSON(t, handler, http.MethodPost, "/api/nodes/delete", `{"node_id":"`+nodeID+`"}`, cookies, "")
	noCSRF.Body.Close()
	if noCSRF.StatusCode != http.StatusForbidden {
		t.Fatalf("missing-csrf status = %d want 403", noCSRF.StatusCode)
	}

	// GET is rejected (POST-only convention).
	wrongMethod := doJSON(t, handler, http.MethodGet, "/api/nodes/delete", ``, cookies, csrf)
	wrongMethod.Body.Close()
	if wrongMethod.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d want 405", wrongMethod.StatusCode)
	}

	// Empty body -> 400.
	empty := doJSON(t, handler, http.MethodPost, "/api/nodes/delete", `{}`, cookies, csrf)
	empty.Body.Close()
	if empty.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty-body status = %d want 400", empty.StatusCode)
	}

	// Unknown node -> 404.
	unknown := doJSON(t, handler, http.MethodPost, "/api/nodes/delete", `{"node_id":"node-ghost"}`, cookies, csrf)
	unknown.Body.Close()
	if unknown.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown-node status = %d want 404", unknown.StatusCode)
	}

	// All rejections left the node intact.
	if _, ok := st.Node(nodeID); !ok {
		t.Fatal("node was deleted by a rejected request")
	}
}

func countDeleteAudits(st interface {
	AuditEvents() []model.AuditEvent
}, nodeID string) int {
	n := 0
	for _, ev := range st.AuditEvents() {
		if ev.Action == "node.delete" && ev.NodeID == nodeID {
			n++
		}
	}
	return n
}

func lastDeleteAudit(st interface {
	AuditEvents() []model.AuditEvent
}, nodeID string) model.AuditEvent {
	var last model.AuditEvent
	for _, ev := range st.AuditEvents() {
		if ev.Action == "node.delete" && ev.NodeID == nodeID {
			last = ev
		}
	}
	return last
}
