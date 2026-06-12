package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestNotifyChannelCRUDHidesSecret(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	create := doJSON(t, handler, http.MethodPost, "/api/notify/channels",
		`{"name":"tg","kind":"telegram","config":{"token":"SECRET-TOKEN","chat_id":"123"}}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create failed: %d", create.StatusCode)
	}
	list := doJSON(t, handler, http.MethodGet, "/api/notify/channels", "", cookies, "")
	defer list.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(list.Body)
	if bytes.Contains(buf.Bytes(), []byte("SECRET-TOKEN")) {
		t.Fatalf("channel list leaked secret: %s", buf.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte("config_keys")) || !bytes.Contains(buf.Bytes(), []byte("chat_id")) {
		t.Fatalf("expected config_keys with key names: %s", buf.String())
	}
}

func TestNotifyChannelRejectsBadConfig(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	// telegram without token/chat must be rejected by eager construction.
	res := doJSON(t, handler, http.MethodPost, "/api/notify/channels",
		`{"name":"bad","kind":"telegram","config":{}}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad telegram config, got %d", res.StatusCode)
	}
}

// captureNotify swaps emitNotify for a synchronous recorder.
type captureNotify struct {
	mu     sync.Mutex
	titles []string
}

func (c *captureNotify) hook() func(string, string) {
	return func(title, body string) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.titles = append(c.titles, title)
	}
}

func TestMonitorDownAndRecoveryAlerts(t *testing.T) {
	srv, handler, _ := newDDNSServer(t) // reuses *Server accessor
	cap := &captureNotify{}
	srv.emitNotify = cap.hook()
	cookies, csrf := loginSession(t, handler)
	nodeID, nodeToken := enrollNode(t, handler, cookies, csrf)
	create := doJSON(t, handler, http.MethodPost, "/api/monitors",
		`{"name":"web","type":"tcp","target":"x:443","assign_all":true}`, cookies, csrf)
	var mon struct {
		ID string `json:"id"`
	}
	json.NewDecoder(create.Body).Decode(&mon)
	create.Body.Close()

	report := func(success bool, errMsg string) {
		body := `{"node_id":"` + nodeID + `","result":{"monitor_id":"` + mon.ID + `","success":` + boolStr(success) + `,"error":"` + errMsg + `"}}`
		doAgentRaw(t, handler, http.MethodPost, "/api/agent/monitor-result", body, nodeToken)
	}
	report(true, "")              // first success: no transition
	report(false, "conn refused") // down alert
	report(true, "")              // recovery alert

	cap.mu.Lock()
	defer cap.mu.Unlock()
	if len(cap.titles) != 2 {
		t.Fatalf("expected 2 alerts (down, recovery), got %v", cap.titles)
	}
	if cap.titles[0] != "🔴 Monitor down" || cap.titles[1] != "✅ Monitor recovered" {
		t.Fatalf("unexpected alert sequence: %v", cap.titles)
	}
}

func TestAgentEventSSHLogin(t *testing.T) {
	srv, handler, st := newDDNSServer(t)
	cap := &captureNotify{}
	srv.emitNotify = cap.hook()
	cookies, csrf := loginSession(t, handler)
	nodeID, nodeToken := enrollNode(t, handler, cookies, csrf)
	body := `{"node_id":"` + nodeID + `","kind":"ssh_login","user":"alice","address":"203.0.113.5","method":"publickey"}`
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/event", body, nodeToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("event ingest failed: %d", rec.Code)
	}
	assertRecorderAuditCorrelation(t, st, rec, "ssh.login", "")
	cap.mu.Lock()
	defer cap.mu.Unlock()
	if len(cap.titles) != 1 || cap.titles[0] != "🔐 SSH login" {
		t.Fatalf("expected SSH login alert, got %v", cap.titles)
	}
	// confirm it was audited
	audit := doJSON(t, handler, http.MethodGet, "/api/audit", "", cookies, "")
	defer audit.Body.Close()
	abuf := new(bytes.Buffer)
	abuf.ReadFrom(audit.Body)
	if !bytes.Contains(abuf.Bytes(), []byte("ssh.login")) {
		t.Fatalf("expected ssh.login audit event")
	}
	_ = httptest.NewRecorder
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
