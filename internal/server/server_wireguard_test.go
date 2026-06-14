package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func wgKey(b byte) string {
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = b
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func TestWireGuardPlanApproveApply(t *testing.T) {
	handler, st := newTestServer(t)
	st.UpsertNode(model.Node{ID: "n1", Name: "hub", WireGuardIP: "10.66.0.1", WireGuardPublicKey: wgKey(1), WireGuardPort: 51820})
	st.UpsertNode(model.Node{ID: "n2", Name: "tokyo", WireGuardIP: "10.66.0.2", WireGuardPublicKey: wgKey(2), WireGuardEndpoint: "1.2.3.4:51820"})
	cookies, csrf := loginSession(t, handler)

	plan := doJSON(t, handler, http.MethodPost, "/api/network/wireguard/plan", `{"node_id":"n1"}`, cookies, csrf)
	defer plan.Body.Close()
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("plan failed: %d", plan.StatusCode)
	}
	var approval struct {
		ID   string `json:"id"`
		Plan string `json:"plan"`
	}
	json.NewDecoder(plan.Body).Decode(&approval)
	if !bytes.Contains([]byte(approval.Plan), []byte("[Interface]")) || !bytes.Contains([]byte(approval.Plan), []byte("10.66.0.2/32")) {
		t.Fatalf("plan missing expected content:\n%s", approval.Plan)
	}

	// approve + queue apply
	appr := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": true, "plan_sha256": planSHA256(approval.Plan)})), cookies, csrf)
	appr.Body.Close()
	if appr.StatusCode != http.StatusOK {
		t.Fatalf("approve failed: %d", appr.StatusCode)
	}

	// The queued internal task should carry a wireguard apply script, while the
	// control-plane task view only exposes script metadata.
	tasks := st.Tasks()
	if len(tasks) != 1 || !bytes.Contains([]byte(tasks[0].Script), []byte("wg-quick up wg0")) {
		t.Fatalf("expected wireguard apply task: %+v", tasks)
	}
	if !bytes.Contains([]byte(tasks[0].Script), []byte("LATTICE_WG_PRIVATE_KEY")) {
		t.Fatalf("expected private-key placeholder substitution in apply task")
	}
}
