package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/LatticeNet/lattice-server/internal/auth"
)

func resetAgentAuthCacheForTest() {
	agentNodeSecretCache.mu.Lock()
	defer agentNodeSecretCache.mu.Unlock()
	agentNodeSecretCache.entries = map[agentAuthCacheKey]agentAuthCacheEntry{}
}

func enrollNodeForAuthCacheTest(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, nodeID string) string {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/nodes/enroll-token", `{"node_id":"`+nodeID+`","name":"`+nodeID+`"}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("enroll %s failed: %d", nodeID, res.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Token == "" {
		t.Fatal("expected node token")
	}
	return out.Token
}

func TestAgentAuthCacheDoesNotBypassDisabledNode(t *testing.T) {
	resetAgentAuthCacheForTest()
	t.Cleanup(resetAgentAuthCacheForTest)
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID := "cache-disabled-node"
	nodeToken := enrollNodeForAuthCacheTest(t, handler, cookies, csrf, nodeID)

	first := doAgentRaw(t, handler, http.MethodGet, "/api/agent/terminal/sessions?node_id="+nodeID, "", nodeToken)
	if first.Code != http.StatusOK {
		t.Fatalf("initial auth status = %d (%s)", first.Code, first.Body.String())
	}

	node, ok := st.Node(nodeID)
	if !ok {
		t.Fatal("node missing")
	}
	node.Disabled = true
	if err := st.UpsertNode(node); err != nil {
		t.Fatal(err)
	}

	second := doAgentRaw(t, handler, http.MethodGet, "/api/agent/terminal/sessions?node_id="+nodeID, "", nodeToken)
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("disabled node auth status = %d (%s)", second.Code, second.Body.String())
	}
}

func TestAgentAuthCacheInvalidatesWhenTokenHashChanges(t *testing.T) {
	resetAgentAuthCacheForTest()
	t.Cleanup(resetAgentAuthCacheForTest)
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID := "cache-rotated-node"
	nodeToken := enrollNodeForAuthCacheTest(t, handler, cookies, csrf, nodeID)

	first := doAgentRaw(t, handler, http.MethodGet, "/api/agent/terminal/sessions?node_id="+nodeID, "", nodeToken)
	if first.Code != http.StatusOK {
		t.Fatalf("initial auth status = %d (%s)", first.Code, first.Body.String())
	}

	replacementToken := "replacement-node-token"
	replacementHash, err := auth.HashSecret(replacementToken)
	if err != nil {
		t.Fatal(err)
	}
	node, ok := st.Node(nodeID)
	if !ok {
		t.Fatal("node missing")
	}
	node.TokenHash = replacementHash
	if err := st.UpsertNode(node); err != nil {
		t.Fatal(err)
	}

	oldToken := doAgentRaw(t, handler, http.MethodGet, "/api/agent/terminal/sessions?node_id="+nodeID, "", nodeToken)
	if oldToken.Code != http.StatusUnauthorized {
		t.Fatalf("old token after rotation status = %d (%s)", oldToken.Code, oldToken.Body.String())
	}

	newToken := doAgentRaw(t, handler, http.MethodGet, "/api/agent/terminal/sessions?node_id="+nodeID, "", replacementToken)
	if newToken.Code != http.StatusOK {
		t.Fatalf("replacement token status = %d (%s)", newToken.Code, newToken.Body.String())
	}
}
