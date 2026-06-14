package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
)

// planSHA256 is the test-side equivalent of the dashboard's client-computed
// sha256(plan) value.
func planSHA256(plan string) string {
	sum := sha256.Sum256([]byte(plan))
	return hex.EncodeToString(sum[:])
}

// TestApprovePlanHashBinding verifies C15/iter-025: pending high-risk approvals
// require plan_sha256, and the hash must match the stored plan so a plan changed
// between review and approval is rejected.
func TestApprovePlanHashBinding(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	// Create an approval via an nft plan.
	plan := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan",
		`{"node_id":"pn1","public_tcp":[443]}`, cookies, csrf)
	if plan.StatusCode != http.StatusOK {
		plan.Body.Close()
		t.Fatalf("nft plan: %d", plan.StatusCode)
	}
	var created struct {
		ID   string `json:"id"`
		Plan string `json:"plan"`
	}
	json.NewDecoder(plan.Body).Decode(&created)
	plan.Body.Close()
	if created.ID == "" || created.Plan == "" {
		t.Fatalf("expected approval id+plan, got %+v", created)
	}
	correct := planSHA256(created.Plan)

	// Missing hash -> 400 Bad Request, not approved.
	missing := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": created.ID})), cookies, csrf)
	missing.Body.Close()
	if missing.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing plan hash should be rejected with 400, got %d", missing.StatusCode)
	}

	// Wrong hash → 409 Conflict, not approved.
	bad := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": created.ID, "plan_sha256": "deadbeef"})), cookies, csrf)
	bad.Body.Close()
	if bad.StatusCode != http.StatusConflict {
		t.Fatalf("mismatched plan hash should be rejected with 409, got %d", bad.StatusCode)
	}

	// Correct hash → 200.
	ok := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": created.ID, "plan_sha256": correct})), cookies, csrf)
	ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("matching plan hash should approve, got %d", ok.StatusCode)
	}

	// Already-decided approvals stay idempotent even if a retry omits the hash.
	retry := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": created.ID})), cookies, csrf)
	retry.Body.Close()
	if retry.StatusCode != http.StatusOK {
		t.Fatalf("approved retry without hash should remain idempotent, got %d", retry.StatusCode)
	}
}
