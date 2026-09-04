package notify

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTelegramSend(t *testing.T) {
	var gotPath, gotBody string
	srv := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	tg := Telegram{Token: "T", ChatID: "123", BaseURL: srv.URL, Client: srv.Client()}
	if err := tg.Send(context.Background(), Message{Title: "hi", Body: "there"}); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/botT/sendMessage" {
		t.Fatalf("unexpected path %q", gotPath)
	}
	if !strings.Contains(gotBody, "chat_id=123") || !strings.Contains(gotBody, "hi") {
		t.Fatalf("unexpected body %q", gotBody)
	}
}

func TestWebhookAndDiscordSend(t *testing.T) {
	hits := 0
	srv := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	if err := (Webhook{URL: srv.URL, Client: srv.Client()}).Send(context.Background(), Message{Title: "a", Body: "b"}); err != nil {
		t.Fatal(err)
	}
	if err := (Discord{WebhookURL: srv.URL, Client: srv.Client()}).Send(context.Background(), Message{Body: "b"}); err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Fatalf("expected 2 deliveries, got %d", hits)
	}
}

func TestUpstreamErrorPropagates(t *testing.T) {
	srv := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	err := (Webhook{URL: srv.URL, Client: srv.Client()}).Send(context.Background(), Message{Body: "x"})
	if err == nil {
		t.Fatal("expected upstream 500 to surface as error")
	}
}

func TestWebhookBlocksInternalByPolicy(t *testing.T) {
	err := (Webhook{URL: "http://127.0.0.1:1/never"}).Send(context.Background(), Message{Body: "x"})
	if err == nil || !strings.Contains(err.Error(), "blocked address") {
		t.Fatalf("expected policy block for loopback webhook, got %v", err)
	}
}

func TestDiscordBlocksInternalByPolicy(t *testing.T) {
	err := (Discord{WebhookURL: "http://169.254.169.254/latest"}).Send(context.Background(), Message{Body: "x"})
	if err == nil || !strings.Contains(err.Error(), "blocked address") {
		t.Fatalf("expected policy block for metadata webhook, got %v", err)
	}
}

func TestDispatcherIsolatesFailures(t *testing.T) {
	ok := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer ok.Close()
	d := NewDispatcher(
		Webhook{URL: ok.URL, Client: ok.Client()},
		Webhook{URL: "http://127.0.0.1:1/never", Client: &http.Client{}},
	)
	results := d.Send(context.Background(), Message{Body: "hello"})
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Err != nil {
		t.Fatalf("first channel should succeed: %v", results[0].Err)
	}
	if results[1].Err == nil {
		t.Fatal("second channel should fail independently")
	}
}

func newLocalHTTPTestServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable in this environment: %v", err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener = ln
	srv.Start()
	return srv
}

func TestMissingConfigErrors(t *testing.T) {
	if err := (Telegram{}).Send(context.Background(), Message{}); err == nil {
		t.Fatal("telegram without token/chat should error")
	}
	if err := (Bark{}).Send(context.Background(), Message{}); err == nil {
		t.Fatal("bark without base/key should error")
	}
}

func TestBarkSendPostsJSONPush(t *testing.T) {
	var gotPath, gotType string
	var got map[string]string
	srv := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.Method + " " + r.URL.Path
		gotType = r.Header.Get("Content-Type")
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	b := Bark{BaseURL: srv.URL + "/", Key: "devkey", Level: "timeSensitive", URL: "https://lattice.example/alerts", Client: srv.Client()}
	if err := b.Send(context.Background(), Message{Title: "service down", Body: "sing-box on hkg"}); err != nil {
		t.Fatal(err)
	}
	if gotPath != "POST /push" {
		t.Fatalf("expected POST /push, got %q", gotPath)
	}
	if gotType != "application/json" {
		t.Fatalf("expected JSON content type, got %q", gotType)
	}
	want := map[string]string{
		"device_key": "devkey",
		"title":      "service down",
		"body":       "sing-box on hkg",
		"level":      "timeSensitive",
		"group":      BarkDefaultGroup,
		"url":        "https://lattice.example/alerts",
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("push body %s = %q, want %q (full: %v)", k, got[k], v, got)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("unexpected extra push fields: %v", got)
	}
}

func TestBarkDefaultsLevelGroupAndTitle(t *testing.T) {
	var got map[string]string
	srv := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	b := Bark{BaseURL: srv.URL, Key: "devkey", Client: srv.Client()}
	if err := b.Send(context.Background(), Message{Body: "x"}); err != nil {
		t.Fatal(err)
	}
	if got["level"] != BarkDefaultLevel || got["group"] != BarkDefaultGroup || got["title"] != "Lattice" {
		t.Fatalf("expected defaults active/lattice/Lattice, got %v", got)
	}
	if _, present := got["url"]; present {
		t.Fatalf("empty url must be omitted, got %v", got)
	}
}

func TestBarkFallsBackToPathFormOnMethodNotAllowed(t *testing.T) {
	var requests []string
	srv := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.RequestURI())
		if r.URL.Path == "/push" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	b := Bark{BaseURL: srv.URL, Key: "devkey", Group: "ops", Client: srv.Client()}
	if err := b.Send(context.Background(), Message{Title: "a b", Body: "c/d"}); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 2 || requests[0] != "POST /push" {
		t.Fatalf("expected POST then GET fallback, got %v", requests)
	}
	if requests[1] != "GET /devkey/a%20b/c%2Fd?group=ops&level=active" {
		t.Fatalf("unexpected fallback request %q", requests[1])
	}
}

func TestBarkDoesNotFallBackOnOtherErrors(t *testing.T) {
	hits := 0
	srv := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Error(w, `{"code":400,"message":"failed to get device token"}`, http.StatusBadRequest)
	}))
	defer srv.Close()
	b := Bark{BaseURL: srv.URL, Key: "bogus", Client: srv.Client()}
	err := b.Send(context.Background(), Message{Body: "x"})
	if err == nil || !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("expected 400 to surface, got %v", err)
	}
	if hits != 1 {
		t.Fatalf("400 must not trigger the GET fallback, got %d requests", hits)
	}
}

func TestBarkBlocksPrivateBaseURLByPolicy(t *testing.T) {
	for _, base := range []string{"http://10.0.0.5:7001", "http://100.64.0.9", "http://127.0.0.1:1"} {
		err := (Bark{BaseURL: base, Key: "devkey"}).Send(context.Background(), Message{Body: "x"})
		if err == nil || !strings.Contains(err.Error(), "blocked address") {
			t.Fatalf("%s: expected policy block for private bark base_url, got %v", base, err)
		}
	}
}
