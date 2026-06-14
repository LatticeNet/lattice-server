package ddns

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestWebhookHeaderSemantics guards C16: operator-supplied headers must be
// applied with correct HTTP semantics. A "Host" header must set the actual
// request Host (req.Host), and "Content-Length" must be ignored (net/http owns
// it). Hop-by-hop headers are also dropped. Ordinary headers still pass through.
func TestWebhookHeaderSemantics(t *testing.T) {
	var gotHost, gotCL, gotConn, gotXTest string
	srv := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// r.Host reflects the wire Host line, i.e. the client's req.Host.
		gotHost = r.Host
		// A manually-set Content-Length would surface in r.ContentLength /
		// the header; net/http should have computed it from the body instead.
		gotCL = r.Header.Get("Content-Length")
		gotConn = r.Header.Get("Connection")
		gotXTest = r.Header.Get("X-Test")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := &Webhook{
		URL:    srv.URL + "/update",
		Method: "POST",
		Body:   "payload-body",
		// Host must map to req.Host; Content-Length and Connection must be
		// dropped; X-Test must pass through. Key casing is intentionally mixed
		// to confirm case-insensitive matching.
		Headers: "host: example.com\nContent-Length: 999\nCONNECTION: close\nX-Test: keep-me",
		Client:  srv.Client(),
	}
	if err := wh.SetRecord(context.Background(), Record{Type: "A", Name: "n.example.com", IP: "1.2.3.4"}); err != nil {
		t.Fatal(err)
	}

	if gotHost != "example.com" {
		t.Fatalf("Host header should set req.Host: got %q, want %q", gotHost, "example.com")
	}
	// The forged Content-Length (999) must not survive; net/http reports the
	// real body length (12 = len("payload-body")), never the operator's value.
	if gotCL == "999" {
		t.Fatalf("forged Content-Length must be ignored, got %q", gotCL)
	}
	if gotConn == "close" {
		t.Fatalf("hop-by-hop Connection header must be dropped, got %q", gotConn)
	}
	if gotXTest != "keep-me" {
		t.Fatalf("ordinary header X-Test should pass through, got %q", gotXTest)
	}
}

// TestApplyHeadersDirect exercises applyHeaders on a bare request so the Host
// and Content-Length handling is verified without a network round-trip.
func TestApplyHeadersDirect(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://orig.invalid/path", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	applyHeaders(req, "Host: example.com\nContent-Length: 999\nTransfer-Encoding: chunked\nAuthorization: Bearer xyz")

	if req.Host != "example.com" {
		t.Fatalf("req.Host = %q, want %q", req.Host, "example.com")
	}
	if got := req.Header.Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length must not be set via headers, got %q", got)
	}
	if got := req.Header.Get("Transfer-Encoding"); got != "" {
		t.Fatalf("Transfer-Encoding (hop-by-hop) must be dropped, got %q", got)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer xyz" {
		t.Fatalf("ordinary Authorization header should be set, got %q", got)
	}
	// Host must NOT leak into the header map (only req.Host is authoritative).
	if got := req.Header.Get("Host"); got != "" {
		t.Fatalf("Host should map to req.Host, not the header map, got %q", got)
	}
}
