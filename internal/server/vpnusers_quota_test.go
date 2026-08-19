package server

import (
	"encoding/json"
	"testing"
)

// An edit that never mentions the quota must not remove it.
//
// `quota_bytes` was a plain int64 on the write request while `enabled` and
// `expires_at` beside it were pointers, so the one field that could not tell
// "not supplied" from "set to zero" was the one whose zero value means
// unlimited. Renaming a quota'd account, or saving the form with the quota box
// left empty, wrote 0 over the stored limit and silently lifted the cap. The
// operator was editing a display name and had no reason to look at the quota.

func createQuotaUser(t *testing.T, srv *Server, email string, quota int64) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"email":       email,
		"quota_bytes": quota,
		"credentials": []map[string]string{{"protocol": "vless", "uuid": "11111111-1111-4111-8111-111111111111"}},
	})
	raw, err := srv.vpnUserCreate(body)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var created struct {
		User struct {
			ID         string `json:"id"`
			QuotaBytes int64  `json:"quota_bytes"`
		} `json:"user"`
	}
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.User.ID == "" {
		t.Fatalf("create returned no id: %s", raw)
	}
	if created.User.QuotaBytes != quota {
		t.Fatalf("create did not store the quota: want %d got %d", quota, created.User.QuotaBytes)
	}
	return created.User.ID
}

func quotaOf(t *testing.T, srv *Server, id string) int64 {
	t.Helper()
	for _, u := range srv.listVpnUsers() {
		if u.ID == id {
			return u.QuotaBytes
		}
	}
	t.Fatalf("user %q vanished", id)
	return 0
}

func TestAnEditThatDoesNotMentionQuotaLeavesItAlone(t *testing.T) {
	srv := newLinesTestServer(t)
	const quota = int64(5 << 30)
	id := createQuotaUser(t, srv, "alice@example.com", quota)

	// The rename an operator actually performs: no quota field in the payload.
	body, _ := json.Marshal(map[string]any{"id": id, "email": "alice@example.com", "name": "Alice"})
	if _, err := srv.vpnUserUpdate(body); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := quotaOf(t, srv, id); got != quota {
		t.Fatalf("an edit that never mentioned the quota changed it: want %d got %d", quota, got)
	}
}

func TestAnEditWithANullQuotaLeavesItAlone(t *testing.T) {
	srv := newLinesTestServer(t)
	const quota = int64(5 << 30)
	id := createQuotaUser(t, srv, "bob@example.com", quota)

	// A client that sends the key with no value is also saying "unchanged",
	// which is what an empty number input serialises to once it stops
	// coercing blank to zero.
	body, _ := json.Marshal(map[string]any{"id": id, "email": "bob@example.com", "quota_bytes": nil})
	if _, err := srv.vpnUserUpdate(body); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := quotaOf(t, srv, id); got != quota {
		t.Fatalf("a null quota removed the limit: want %d got %d", quota, got)
	}
}

func TestQuotaIsStillRemovableOnPurpose(t *testing.T) {
	srv := newLinesTestServer(t)
	id := createQuotaUser(t, srv, "carol@example.com", 5<<30)

	// The guard must not make the cap permanent: an explicit zero still clears
	// it. This is the case that separates "unset" from "set to zero".
	body, _ := json.Marshal(map[string]any{"id": id, "email": "carol@example.com", "quota_bytes": 0})
	if _, err := srv.vpnUserUpdate(body); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := quotaOf(t, srv, id); got != 0 {
		t.Fatalf("an explicit zero did not clear the quota: got %d", got)
	}
}

func TestQuotaCanStillBeChanged(t *testing.T) {
	srv := newLinesTestServer(t)
	id := createQuotaUser(t, srv, "dave@example.com", 5<<30)

	const raised = int64(20 << 30)
	body, _ := json.Marshal(map[string]any{"id": id, "email": "dave@example.com", "quota_bytes": raised})
	if _, err := srv.vpnUserUpdate(body); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := quotaOf(t, srv, id); got != raised {
		t.Fatalf("quota was not raised: want %d got %d", raised, got)
	}
}
