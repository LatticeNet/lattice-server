package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

type groupUseOut struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Label string `json:"label"`
	Role  string `json:"role"`
}

// A node group lists every outbound policy that names it, and deleting it is
// refused with a message that names them.
func TestNodeGroupUsedByAndDeleteRefusalNameTheUsers(t *testing.T) {
	handler, st, cookies, csrf := outboundFleet(t, "n1", "n2", "n3")
	web := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"name":"Web","slug":"web","members":["n1"]}`, cookies, csrf))
	db := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"name":"DB","slug":"db","members":["n2"]}`, cookies, csrf))
	idle := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"name":"Idle","slug":"idle","members":["n3"]}`, cookies, csrf))

	_, target, _ := postPolicy(t, handler, cookies, csrf, `{"name":"web egress","scope":{"groups":["`+web.ID+`","`+idle.ID+`"]},"enabled":true}`)
	_, remote, _ := postPolicy(t, handler, cookies, csrf, `{"scope":{"nodes":["n3"]},"enabled":true,"rules":[{"id":"r","action":"allow","direction":"egress","protocol":"tcp","ports":[5432],"remote":{"kind":"group","group_id":"`+db.ID+`"}}]}`)

	usedBy := func(groupID string) []groupUseOut {
		res := doJSON(t, handler, http.MethodGet, "/api/groups/used-by?id="+groupID, "", cookies, csrf)
		raw := readBody(t, res)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("used-by = %d %s", res.StatusCode, raw)
		}
		var out struct {
			UsedBy []groupUseOut `json:"used_by"`
		}
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			t.Fatal(err)
		}
		return out.UsedBy
	}
	if got := usedBy(web.ID); len(got) != 1 || got[0] != (groupUseOut{Kind: "outbound_policy", ID: target.ID, Label: "web egress", Role: "target"}) {
		t.Fatalf("web used by %+v", got)
	}
	if got := usedBy(db.ID); len(got) != 1 || got[0].Kind != "outbound_policy" || got[0].ID != remote.ID || got[0].Role != "remote" || got[0].Label == "" {
		t.Fatalf("db used by %+v", got)
	}

	del := func(groupID string) (int, string) {
		res := doJSON(t, handler, http.MethodPost, "/api/groups/delete", `{"id":"`+groupID+`"}`, cookies, csrf)
		return res.StatusCode, readBody(t, res)
	}
	code, raw := del(web.ID)
	if code != http.StatusConflict || !strings.Contains(raw, "web egress") {
		t.Fatalf("deleting a target group: want 409 naming the policy, got %d %s", code, raw)
	}
	// A group named only as a remote was deletable before, which left a rule
	// pointing at nothing. It is in use now too.
	code, raw = del(db.ID)
	if code != http.StatusConflict || !strings.Contains(raw, remote.ID) && !strings.Contains(raw, "n3") {
		t.Fatalf("deleting a remote group: want 409 naming the policy, got %d %s", code, raw)
	}
	if _, ok := st.Group(db.ID); !ok {
		t.Fatal("the refused delete must keep the group")
	}

	// Once nothing names it, the group deletes.
	none := doJSON(t, handler, http.MethodPost, "/api/group-policies/delete", `{"id":"`+remote.ID+`"}`, cookies, csrf)
	none.Body.Close()
	if code, raw := del(db.ID); code != http.StatusOK {
		t.Fatalf("an unused group must delete, got %d %s", code, raw)
	}
}
