package server

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// postBody posts body and returns the status and the response text.
func postBody(t *testing.T, handler http.Handler, path, body string, cookies []*http.Cookie, csrf string) (int, string) {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, path, body, cookies, csrf)
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(raw)
}

const publicForwardBody = `{
	"name":"public dns","node_id":"n1","exposure":"public",
	"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]%s
}`

// Design 32 S5b: a public deployment with a forward zone, refused since S0,
// saves once it names its clients, and the refusal without them, and every
// refused list, lands on allowed_clients. An external engine takes none.
func TestDNSDeploymentAllowedClients(t *testing.T) {
	_, handler, _ := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)

	code, body := postBody(t, handler, "/api/dns/deployments", strings.Replace(publicForwardBody, "%s", "", 1), cookies, csrf)
	if refusal := apiErrorOf(t, body); code != http.StatusBadRequest || refusal.Field != "allowed_clients" || !strings.Contains(refusal.Message, "open resolver") {
		t.Fatalf("a public forward deployment without clients = %d %s, want 400 on allowed_clients", code, body)
	}

	code, body = postBody(t, handler, "/api/dns/deployments", strings.Replace(publicForwardBody, "%s", `,"allowed_clients":["203.0.113.0/24","2001:DB8::/32","203.0.113.0/24"]`, 1), cookies, csrf)
	if code != http.StatusOK {
		t.Fatalf("a public forward deployment that names its clients = %d %s, want 200", code, body)
	}
	var saved struct {
		ID             string   `json:"id"`
		AllowedClients []string `json:"allowed_clients"`
		OpenResolver   bool     `json:"open_resolver"`
	}
	if err := json.Unmarshal([]byte(body), &saved); err != nil {
		t.Fatal(err)
	}
	if want := []string{"203.0.113.0/24", "2001:db8::/32"}; !slices.Equal(saved.AllowedClients, want) || saved.OpenResolver {
		t.Fatalf("saved %+v, want canonical %v and no open resolver flag", saved, want)
	}

	for _, tc := range []struct {
		clients string
		field   string
		says    string
	}{
		{`["10.0.0.0/8","0.0.0.0/0"]`, "allowed_clients[1]", "reopens"},
		{`["::/0"]`, "allowed_clients[0]", "reopens"},
		{`["10.0.0.1/8"]`, "allowed_clients[0]", "host bits"},
	} {
		code, body := postBody(t, handler, "/api/dns/deployments", strings.Replace(publicForwardBody, "%s", `,"allowed_clients":`+tc.clients, 1), cookies, csrf)
		if refusal := apiErrorOf(t, body); code != http.StatusBadRequest || refusal.Field != tc.field || !strings.Contains(refusal.Message, tc.says) {
			t.Fatalf("%s = %d %s, want 400 on %s saying %q", tc.clients, code, body, tc.field, tc.says)
		}
	}

	external := strings.Replace(externalDNSBody, `"exposure":"public",`, `"exposure":"public","allowed_clients":["203.0.113.0/24"],`, 1)
	code, body = postBody(t, handler, "/api/dns/deployments", external, cookies, csrf)
	if refusal := apiErrorOf(t, body); code != http.StatusBadRequest || refusal.Field != "allowed_clients" {
		t.Fatalf("an external engine with allowed clients = %d %s, want 400 on allowed_clients", code, body)
	}
}

// The plan of a public forward deployment that names its clients carries the
// acl and says it limits answers, not reachability, and the approval gate,
// which judges the plan, lets it through.
func TestDNSPlanWithAllowedClientsIsNotAnOpenResolver(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs", `{
		"node_id":"n1","interface_name":"ens3","wireguard_cidr":"10.66.0.0/24","public_tcp":[22]
	}`, cookies, csrf)
	save.Body.Close()
	seedNodeReality(t, st, "n1", 22, "ens3")
	code, body := postBody(t, handler, "/api/dns/deployments", strings.Replace(publicForwardBody, "%s", `,"allowed_clients":["203.0.113.0/24"]`, 1), cookies, csrf)
	if code != http.StatusOK {
		t.Fatalf("save: %d %s", code, body)
	}
	var saved struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &saved); err != nil {
		t.Fatal(err)
	}
	planRes := doJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+saved.ID+`"}`, cookies, csrf)
	approval := decodeDNSPlan(t, planRes)
	planRes.Body.Close()
	for _, want := range []string{
		"  acl {\n    allow net 203.0.113.0/24\n    block\n  }\n",
		"## Allowed clients\n- 203.0.113.0/24\n",
		"not who can reach the port",
		"public UDP/53",
	} {
		if !strings.Contains(approval.Plan, want) {
			t.Fatalf("plan missing %q:\n%s", want, approval.Plan)
		}
	}
	if code, body := approveStatus(t, handler, cookies, csrf, approval); code != http.StatusOK {
		t.Fatalf("approving a public forward plan with an acl = %d %s, want 200", code, body)
	}
}
