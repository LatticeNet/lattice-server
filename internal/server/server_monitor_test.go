package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// enrollNode logs in as admin and enrolls a node, returning its id and token.
func enrollNode(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf string) (string, string) {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/nodes/enroll-token", `{"node_id":"mon-node","name":"mn"}`, cookies, csrf)
	defer res.Body.Close()
	var out struct {
		NodeID string `json:"node_id"`
		Token  string `json:"token"`
	}
	json.NewDecoder(res.Body).Decode(&out)
	if out.Token == "" {
		t.Fatal("expected node token")
	}
	return out.NodeID, out.Token
}

func TestMonitorLifecycleAndAgentRoundTrip(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, nodeToken := enrollNode(t, handler, cookies, csrf)

	// create a tcp monitor assigned to all nodes
	create := doJSON(t, handler, http.MethodPost, "/api/monitors",
		`{"name":"web","type":"tcp","target":"example.com:443","assign_all":true,"interval_sec":15}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create failed: %d", create.StatusCode)
	}
	var mon struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	json.NewDecoder(create.Body).Decode(&mon)
	if !mon.Enabled {
		t.Fatal("monitor should default to enabled")
	}

	// agent fetches its assigned monitors with its node token
	areq, _ := http.NewRequest(http.MethodGet, "/api/agent/monitors?node_id="+nodeID, nil)
	areq.Header.Set("Authorization", "Bearer "+nodeToken)
	arec := serveReq(handler, areq)
	if arec.Code != http.StatusOK {
		t.Fatalf("agent monitors fetch failed: %d", arec.Code)
	}
	if !bytes.Contains(arec.Body.Bytes(), []byte(mon.ID)) {
		t.Fatalf("assigned monitor not returned to agent: %s", arec.Body.String())
	}

	// agent reports a result
	body := `{"node_id":"` + nodeID + `","result":{"monitor_id":"` + mon.ID + `","success":true,"latency_ms":12.5}}`
	rres := doAgentRaw(t, handler, http.MethodPost, "/api/agent/monitor-result", body, nodeToken)
	if rres.Code != http.StatusOK {
		t.Fatalf("monitor result ingest failed: %d (%s)", rres.Code, rres.Body.String())
	}

	// operator reads results
	results := doJSON(t, handler, http.MethodGet, "/api/monitors/results?monitor_id="+mon.ID, "", cookies, "")
	defer results.Body.Close()
	rbuf := new(bytes.Buffer)
	rbuf.ReadFrom(results.Body)
	if !bytes.Contains(rbuf.Bytes(), []byte("12.5")) {
		t.Fatalf("expected stored latency in results: %s", rbuf.String())
	}

	// delete
	doJSON(t, handler, http.MethodPost, "/api/monitors/delete", `{"id":"`+mon.ID+`"}`, cookies, csrf).Body.Close()
	list := doJSON(t, handler, http.MethodGet, "/api/monitors", "", cookies, "")
	defer list.Body.Close()
	var mons []map[string]any
	json.NewDecoder(list.Body).Decode(&mons)
	if len(mons) != 0 {
		t.Fatalf("expected no monitors after delete, got %d", len(mons))
	}
}

func TestMonitorRejectsICMP(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/monitors",
		`{"name":"p","type":"icmp","target":"1.1.1.1","assign_all":true}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("icmp should be rejected for now, got %d", res.StatusCode)
	}
}

func serveReq(handler http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func doRaw(t *testing.T, handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	return serveReq(handler, req)
}

func doAgentRaw(t *testing.T, handler http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return serveReq(handler, req)
}
