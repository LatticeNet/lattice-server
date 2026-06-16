package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func nodeTokenAuthOK(t *testing.T, handler http.Handler, nodeID, token string) bool {
	t.Helper()
	res := doBearerJSON(t, handler, http.MethodGet, "/api/agent/tasks?node_id="+nodeID, "", token)
	defer res.Body.Close()
	return res.StatusCode == http.StatusOK
}

func TestNodeTokenRotationAndRevocation(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	nodeID, old := enrollNode(t, handler, cookies, csrf)
	if !nodeTokenAuthOK(t, handler, nodeID, old) {
		t.Fatal("freshly enrolled token must authenticate")
	}

	res := doJSON(t, handler, http.MethodPost, "/api/nodes/rotate-token", `{"node_id":"`+nodeID+`"}`, cookies, csrf)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("rotate: %d", res.StatusCode)
	}
	var rot struct {
		Token string `json:"token"`
	}
	json.NewDecoder(res.Body).Decode(&rot)
	res.Body.Close()
	if rot.Token == "" || rot.Token == old {
		t.Fatalf("rotate must return a new token, got %q (old %q)", rot.Token, old)
	}
	if nodeTokenAuthOK(t, handler, nodeID, old) {
		t.Fatal("rotated-away token must no longer authenticate")
	}
	if !nodeTokenAuthOK(t, handler, nodeID, rot.Token) {
		t.Fatal("new rotated token must authenticate")
	}

	res = doJSON(t, handler, http.MethodPost, "/api/nodes/disable", `{"node_id":"`+nodeID+`","disabled":true}`, cookies, csrf)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("disable: %d", res.StatusCode)
	}
	res.Body.Close()
	if nodeTokenAuthOK(t, handler, nodeID, rot.Token) {
		t.Fatal("a disabled node's token must be refused")
	}

	res = doJSON(t, handler, http.MethodPost, "/api/nodes/disable", `{"node_id":"`+nodeID+`","disabled":false}`, cookies, csrf)
	res.Body.Close()
	if !nodeTokenAuthOK(t, handler, nodeID, rot.Token) {
		t.Fatal("re-enabled node's token must authenticate again")
	}
}

func TestNodeEnrollResponseUsesPublicURL(t *testing.T) {
	handler, _ := newTestServerWithPublicURL(t, "https://lattice.example.com/")
	cookies, csrf := loginSession(t, handler)

	res := doJSON(t, handler, http.MethodPost, "/api/nodes/enroll-token", `{"node_id":"node-a","name":"Node A"}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("enroll: %d", res.StatusCode)
	}
	var out struct {
		NodeID    string `json:"node_id"`
		Token     string `json:"token"`
		ServerURL string `json:"server_url"`
		Command   string `json:"command"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.ServerURL != "https://lattice.example.com" {
		t.Fatalf("server_url = %q", out.ServerURL)
	}
	for _, want := range []string{
		"lattice-agent -server 'https://lattice.example.com'",
		"-node-id 'node-a'",
		"-token '" + out.Token + "'",
	} {
		if !strings.Contains(out.Command, want) {
			t.Fatalf("command missing %q:\n%s", want, out.Command)
		}
	}
}
