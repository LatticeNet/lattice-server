package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The second-order risk in narrowing the read. A confined operator now sees a
// filtered copy of a group, so if they open it and save it back, a plain
// read-modify-write deletes the members they were never shown. That turns an
// authorization fix into silent data loss, which is worse than the disclosure
// it closed: the disclosure is recoverable, the membership is not.
//
// Written at the merge gate. The carry-back is implemented and was explained in
// the commit message, but nothing exercised it, and a preservation rule nobody
// tests is one refactor away from becoming a delete.
func TestAConfinedOperatorSavingAGroupDoesNotDeleteMembersTheyCannotSee(t *testing.T) {
	handler, st := newTestServer(t)
	st.UpsertNode(model.Node{ID: "node-a", Name: "allowed"})
	st.UpsertNode(model.Node{ID: "node-b", Name: "denied"})
	cookies, csrf := loginSession(t, handler)

	// An unconfined admin creates a group spanning both nodes.
	rec := authedPost(t, handler, cookies, csrf, "/api/groups",
		`{"name":"mixed","slug":"mixed","members":["node-a","node-b"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create group: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	token := createPAT(t, handler, cookies, csrf, []string{"group:admin", "group:read"}, []string{"node-a"})

	// The confined operator saves the group back exactly as their own narrowed
	// copy shows it: node-a only, because node-b was filtered out of their read.
	res := doBearerJSON(t, handler, http.MethodPost, "/api/groups",
		`{"id":"`+created.ID+`","name":"mixed","slug":"mixed","members":["node-a"]}`, token)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body := new(bytes.Buffer)
		body.ReadFrom(res.Body)
		t.Fatalf("a confined operator saving their own view was refused: %d %s", res.StatusCode, body.String())
	}

	stored, ok := st.Group(created.ID)
	if !ok {
		t.Fatal("group vanished")
	}
	seen := map[string]bool{}
	for _, m := range stored.Members {
		seen[m] = true
	}
	if !seen["node-b"] {
		t.Fatalf("saving as a confined operator deleted the member they could not see: %v", stored.Members)
	}
	if !seen["node-a"] {
		t.Fatalf("the member they could see did not survive: %v", stored.Members)
	}
}
