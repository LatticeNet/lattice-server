package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
)

// TestApprovePlanHashBinding verifies C15: when the client supplies plan_sha256,
// it must match the stored plan, so a plan that changed between review and
// approval is rejected; an absent or correct hash approves as before.
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
	sum := sha256.Sum256([]byte(created.Plan))
	correct := hex.EncodeToString(sum[:])

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
}
