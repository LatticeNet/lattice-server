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
	for _, line := range strings.Split(w.Headers, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
	}
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

func templateDDNS(s string, r Record) string {
	rep := strings.NewReplacer("#ip#", r.IP, "#domain#", r.Name, "#type#", r.Type)
	return rep.Replace(s)
}
