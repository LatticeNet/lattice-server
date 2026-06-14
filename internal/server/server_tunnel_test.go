package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

func TestTunnelLifecycleAndApply(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	create := doJSON(t, handler, http.MethodPost, "/api/tunnels",
		`{"name":"edge","node_id":"n1","tunnel_id":"tun-abc","ingress":[{"hostname":"app.example.com","service":"http://localhost:8088"}]}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("tunnel create failed: %d", create.StatusCode)
	}
	var tun struct {
		ID string `json:"id"`
	}
	json.NewDecoder(create.Body).Decode(&tun)

	// invalid ingress should be rejected
	bad := doJSON(t, handler, http.MethodPost, "/api/tunnels",
		`{"name":"x","node_id":"n1","tunnel_id":"t","ingress":[{"hostname":"nope","service":"ftp://x"}]}`, cookies, csrf)
	bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid ingress, got %d", bad.StatusCode)
	}

	plan := doJSON(t, handler, http.MethodPost, "/api/tunnels/plan", `{"id":"`+tun.ID+`"}`, cookies, csrf)
	defer plan.Body.Close()
	var approval struct {
		ID   string `json:"id"`
		Plan string `json:"plan"`
	}
	json.NewDecoder(plan.Body).Decode(&approval)
	if !bytes.Contains([]byte(approval.Plan), []byte("tunnel: tun-abc")) {
		t.Fatalf("plan missing tunnel config:\n%s", approval.Plan)
	}

	appr := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": true, "plan_sha256": planSHA256(approval.Plan)})), cookies, csrf)
	appr.Body.Close()
	if appr.StatusCode != http.StatusOK {
		t.Fatalf("approve failed: %d", appr.StatusCode)
	}

	tasks := st.Tasks()
	if len(tasks) != 1 ||
		!bytes.Contains([]byte(tasks[0].Script), []byte("/etc/cloudflared/config.yml")) ||
		!bytes.Contains([]byte(tasks[0].Script), []byte("cloudflared")) {
		t.Fatalf("expected cloudflared apply task: %+v", tasks)
	}
}
