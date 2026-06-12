package server

import (
	"encoding/json"
	"net/http"
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
