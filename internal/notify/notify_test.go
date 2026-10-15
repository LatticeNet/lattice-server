package notify

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// barkCapture records each request a fake Bark server receives: the JSON push
// body, or the query of the GET fallback.
type barkCapture struct {
	mu    sync.Mutex
	push  map[string]string
	query map[string]string
	paths []string
}

func newBarkCaptureServer(t *testing.T, refusePush bool) (*httptest.Server, *barkCapture) {
	t.Helper()
	got := &barkCapture{}
	srv := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.mu.Lock()
		defer got.mu.Unlock()
		got.paths = append(got.paths, r.Method+" "+r.URL.Path)
		if r.URL.Path == "/push" {
			if refusePush {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewDecoder(r.Body).Decode(&got.push)
			w.WriteHeader(http.StatusOK)
			return
		}
		got.query = map[string]string{}
		for k := range r.URL.Query() {
			got.query[k] = r.URL.Query().Get(k)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

// The message's group and icon reach both forms of the push: the JSON body
// and the GET fallback's query.
func TestBarkSendsMessageGroupAndIcon(t *testing.T) {
	const icon = "https://lattice.example.com/notify-icons/server-off-critical.png"
	msg := Message{Title: "Node offline", Body: "hk-1", Group: "Nodes", Icon: icon}

	srv, got := newBarkCaptureServer(t, false)
	if err := (Bark{BaseURL: srv.URL, Key: "devkey", Client: srv.Client()}).Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	if got.push["group"] != "Nodes" || got.push["icon"] != icon {
		t.Fatalf("JSON push = %v, want group Nodes and icon %s", got.push, icon)
	}

	srv, got = newBarkCaptureServer(t, true)
	if err := (Bark{BaseURL: srv.URL, Key: "devkey", Client: srv.Client()}).Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	if len(got.paths) != 2 || got.query["group"] != "Nodes" || got.query["icon"] != icon {
		t.Fatalf("GET fallback = %v %v, want group Nodes and icon %s", got.paths, got.query, icon)
	}
}

// A group the operator configured is kept; the default group, written out or
// left empty, gives way to the message's group. No icon means no icon field.
func TestBarkGroupPrecedence(t *testing.T) {
	cases := []struct{ configured, message, want string }{
		{"ops", "Nodes", "ops"},
		{BarkDefaultGroup, "Nodes", "Nodes"},
		{"", "Nodes", "Nodes"},
		{"", "", BarkDefaultGroup},
		{"ops", "", "ops"},
	}
	for _, c := range cases {
		for _, refusePush := range []bool{false, true} {
			srv, got := newBarkCaptureServer(t, refusePush)
			b := Bark{BaseURL: srv.URL, Key: "devkey", Group: c.configured, Client: srv.Client()}
			if err := b.Send(context.Background(), Message{Body: "x", Group: c.message}); err != nil {
				t.Fatal(err)
			}
			fields := got.push
			if refusePush {
				fields = got.query
			}
			if fields["group"] != c.want {
				t.Fatalf("configured %q, message %q, GET fallback %t: group %q, want %q", c.configured, c.message, refusePush, fields["group"], c.want)
			}
			if _, present := fields["icon"]; present {
				t.Fatalf("a message without an icon must not send one: %v", fields)
			}
		}
	}
}
