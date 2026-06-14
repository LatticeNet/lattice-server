package notify

import (
	"context"
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
