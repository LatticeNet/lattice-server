package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Design 32 R6 for the outbound policy editor: a refused save names the
// request field at fault, and a save that names a stale version is refused
// with version_conflict instead of overwriting the newer policy.

func apiErrorOf(t *testing.T, raw string) model.APIError {
	t.Helper()
	var out model.APIErrorResponse
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("error body %q: %v", raw, err)
	}
	return out.Error
}

func TestOutboundPolicyRefusedSaveNamesTheField(t *testing.T) {
	handler, _, cookies, csrf := outboundFleet(t, "n1", "n2")
	web := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups", `{"name":"Web","slug":"web","members":["n1","n2"]}`, cookies, csrf))
	rule := `{"id":"r","action":"allow","direction":"egress","protocol":"tcp","ports":[443],"remote":{"kind":"any"}}`
	cases := []struct {
		name, body, field string
	}{
		{"no target", `{"enabled":true}`, "scope"},
		{"fleet and nodes", `{"scope":{"all":true,"nodes":["n1"]},"enabled":true}`, "scope.all"},
		{"exclude without a group", `{"scope":{"nodes":["n1"],"exclude":["n2"]},"enabled":true}`, "scope.exclude"},
		// The path names the element as sent: the sorted check meets n1
		// first, which the request sent second.
		{"target and excluded", `{"scope":{"nodes":["n1"],"groups":["` + web.ID + `"],"exclude":["n2","n1"]},"enabled":true}`, "scope.exclude[1]"},
		{"unknown node", `{"scope":{"nodes":["n2","ghost"]},"enabled":true}`, "scope.nodes[1]"},
		{"unknown exclusion", `{"scope":{"groups":["` + web.ID + `"],"exclude":["ghost"]},"enabled":true}`, "scope.exclude[0]"},
		{"unknown group", `{"scope":{"groups":["grp_ghost"]},"enabled":true}`, "scope.groups[0]"},
		{"unknown group by alias", `{"scope_group_id":"grp_ghost","enabled":true}`, "scope_group_id"},
		{"long name", `{"name":"` + strings.Repeat("x", maxOutboundPolicyNameLen+1) + `","scope":{"nodes":["n1"]},"enabled":true}`, "name"},
		{"bad action", `{"scope":{"nodes":["n1"]},"enabled":true,"rules":[` + rule + `,{"id":"s","action":"maybe","direction":"egress","remote":{"kind":"any"}}]}`, "rules[1].action"},
		{"bad direction", `{"scope":{"nodes":["n1"]},"enabled":true,"rules":[{"id":"s","action":"allow","direction":"sideways","remote":{"kind":"any"}}]}`, "rules[0].direction"},
		{"unknown remote group", `{"scope":{"nodes":["n1"]},"enabled":true,"rules":[{"id":"s","action":"allow","direction":"egress","remote":{"kind":"group","group_id":"grp_ghost"}}]}`, "rules[0].remote.group_id"},
		{"duplicate rule id", `{"scope":{"nodes":["n1"]},"enabled":true,"rules":[` + rule + `,` + rule + `]}`, "rules[1].id"},
		{"unknown policy", `{"id":"gnp_ghost","scope":{"nodes":["n1"]},"enabled":true}`, "id"},
	}
	for _, tc := range cases {
		code, _, raw := postPolicy(t, handler, cookies, csrf, tc.body)
		if code != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", tc.name, code, raw)
			continue
		}
		if got := apiErrorOf(t, raw); got.Field != tc.field || got.Message == "" {
			t.Errorf("%s: field %q (%s), want %q", tc.name, got.Field, got.Message, tc.field)
		}
	}

	// A confined token's scope refusal names the field it is about; a
	// delete, whose request has no scope, names none.
	confined := createPAT(t, handler, cookies, csrf, []string{"netpolicy:admin", "netpolicy:read"}, []string{"n1"})
	res := doBearerJSON(t, handler, http.MethodPost, "/api/group-policies", `{"scope":{"groups":["`+web.ID+`"]},"enabled":true}`, confined)
	if raw := readBody(t, res); res.StatusCode != http.StatusForbidden || apiErrorOf(t, raw).Field != "scope" {
		t.Fatalf("confined group target = %d %s, want 403 naming scope", res.StatusCode, raw)
	}
	_, fleet, _ := postPolicy(t, handler, cookies, csrf, `{"scope":{"groups":["`+web.ID+`"]},"enabled":true}`)
	res = doBearerJSON(t, handler, http.MethodPost, "/api/group-policies/delete", `{"id":"`+fleet.ID+`"}`, confined)
	if raw := readBody(t, res); res.StatusCode != http.StatusForbidden || apiErrorOf(t, raw).Field != "" {
		t.Fatalf("confined delete = %d %s, want 403 naming no field", res.StatusCode, raw)
	}
}

func TestOutboundPolicyStaleSaveIsAVersionConflict(t *testing.T) {
	handler, st, cookies, csrf := outboundFleet(t, "n1")
	type versioned struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Version int64  `json:"version"`
	}
	save := func(body string) (int, versioned, string) {
		res := doJSON(t, handler, http.MethodPost, "/api/group-policies", body, cookies, csrf)
		raw := readBody(t, res)
		var out versioned
		_ = json.Unmarshal([]byte(raw), &out)
		return res.StatusCode, out, raw
	}
	code, created, raw := save(`{"name":"one","scope":{"nodes":["n1"]},"enabled":true}`)
	if code != http.StatusOK || created.Version != 1 {
		t.Fatalf("create = %d %s, want version 1", code, raw)
	}
	code, edited, raw := save(`{"id":"` + created.ID + `","version":1,"name":"two","scope":{"nodes":["n1"]},"enabled":true}`)
	if code != http.StatusOK || edited.Version != 2 {
		t.Fatalf("edit at the read version = %d %s, want version 2", code, raw)
	}
	code, _, raw = save(`{"id":"` + created.ID + `","version":1,"name":"stale","scope":{"nodes":["n1"]},"enabled":true}`)
	if code != http.StatusConflict || apiErrorOf(t, raw).Code != model.APIErrorVersionConflict {
		t.Fatalf("stale edit = %d %s, want 409 version_conflict", code, raw)
	}
	if gp, _ := st.GroupPolicy(created.ID); gp.Name != "two" || gp.Version != 2 {
		t.Fatalf("the stale save must not land: %+v", gp)
	}
	// The list carries the version an editor sends back.
	res := doJSON(t, handler, http.MethodGet, "/api/group-policies", "", cookies, csrf)
	var list struct {
		Policies []versioned `json:"policies"`
	}
	if err := json.Unmarshal([]byte(readBody(t, res)), &list); err != nil || len(list.Policies) != 1 || list.Policies[0].Version != 2 {
		t.Fatalf("list = %+v %v", list, err)
	}
	// A client that sends no version is not checked.
	if code, out, raw := save(`{"id":"` + created.ID + `","name":"unversioned","scope":{"nodes":["n1"]},"enabled":true}`); code != http.StatusOK || out.Version != 3 {
		t.Fatalf("unversioned edit = %d %s", code, raw)
	}
}
