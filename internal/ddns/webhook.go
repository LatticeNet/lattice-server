package ddns

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Webhook delivers DNS updates to an arbitrary HTTP endpoint. The URL and body
// support the templates #ip#, #domain#, and #type#. Because the URL is
// operator-supplied, Guard (when set) is consulted before each request to block
// SSRF to internal addresses.
type Webhook struct {
	URL     string
	Method  string
	Body    string
	Headers string // "Key: Value" per line
	Client  *http.Client
	Guard   func(rawURL string) error
}

func (w *Webhook) Kind() string { return "webhook" }

func (w *Webhook) SetRecord(ctx context.Context, r Record) error {
	target := templateDDNS(w.URL, r)
	if w.Guard != nil {
		if err := w.Guard(target); err != nil {
			return err
		}
	}
	method := strings.ToUpper(strings.TrimSpace(w.Method))
	if method == "" {
		method = http.MethodPost
	}
	var bodyReader io.Reader
	if w.Body != "" {
		bodyReader = strings.NewReader(templateDDNS(w.Body, r))
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bodyReader)
	if err != nil {
		return err
	}
	applyHeaders(req, w.Headers)
	client := w.Client
	if client == nil {
		client = defaultClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// applyHeaders parses the operator-supplied "Key: Value" lines and applies them
// to req with correct HTTP semantics:
//
//   - "Host" maps to req.Host (Header.Set("Host", ...) is silently ignored by
//     net/http and would never change the actual request Host/SNI).
//   - "Content-Length" is dropped — net/http derives it from the body; a manual
//     value can corrupt the request.
//   - Hop-by-hop headers ("Connection", "Transfer-Encoding") are dropped — they
//     govern a single transport hop and must not be forwarded by a client.
//   - Everything else is set verbatim via Header.Set.
//
// Header keys are matched case-insensitively (HTTP header names are
// case-insensitive). This changes only header semantics; the SSRF guard and
// IP-pinned dialer in the caller are untouched.
func applyHeaders(req *http.Request, headers string) {
	for _, line := range strings.Split(headers, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch strings.ToLower(k) {
		case "host":
			// Setting the Host header has no effect via Header.Set; net/http
			// uses req.Host (falling back to the URL host) for the wire Host
			// line and TLS SNI, so assign it directly.
			req.Host = v
		case "content-length", "connection", "transfer-encoding":
			// Skip: managed by net/http or hop-by-hop only.
			continue
		default:
			req.Header.Set(k, v)
		}
	}
}

func templateDDNS(s string, r Record) string {
	rep := strings.NewReplacer("#ip#", r.IP, "#domain#", r.Name, "#type#", r.Type)
	return rep.Replace(s)
}
