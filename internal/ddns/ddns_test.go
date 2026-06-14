package ddns

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// cfMock returns a Cloudflare-API-shaped test server that records the last
// create/update it received.
func cfMock(t *testing.T) (*httptest.Server, *struct {
	created *cfRecord
	updated *cfRecord
}) {
	t.Helper()
	state := &struct {
		created *cfRecord
		updated *cfRecord
	}{}
	existing := map[string]cfRecord{} // name+type -> record
	mux := http.NewServeMux()
	mux.HandleFunc("/zones", func(w http.ResponseWriter, r *http.Request) {
		writeCF(w, []cfZone{{ID: "zone1", Name: "example.com"}})
	})
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			key := r.URL.Query().Get("name") + r.URL.Query().Get("type")
			if rec, ok := existing[key]; ok {
				writeCF(w, []cfRecord{rec})
			} else {
				writeCF(w, []cfRecord{})
			}
		case http.MethodPost:
			var rec cfRecord
			json.NewDecoder(r.Body).Decode(&rec)
			rec.ID = "newrec"
			state.created = &rec
			writeCF(w, rec)
		}
	})
	mux.HandleFunc("/zones/zone1/dns_records/", func(w http.ResponseWriter, r *http.Request) {
		var rec cfRecord
		json.NewDecoder(r.Body).Decode(&rec)
		state.updated = &rec
		writeCF(w, rec)
	})
	srv := newLocalHTTPTestServer(t, mux)
	t.Cleanup(srv.Close)
	return srv, state
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

func writeCF(w http.ResponseWriter, result any) {
	raw, _ := json.Marshal(result)
	json.NewEncoder(w).Encode(cfEnvelope{Success: true, Result: raw})
}

func TestCloudflareCreatesRecord(t *testing.T) {
	srv, state := cfMock(t)
	cf := &Cloudflare{Token: "t", BaseURL: srv.URL, Client: srv.Client()}
	err := cf.SetRecord(context.Background(), Record{Type: "A", Name: "node.example.com", IP: "1.2.3.4", TTL: 60})
	if err != nil {
		t.Fatal(err)
	}
	if state.created == nil || state.created.Content != "1.2.3.4" || state.created.Name != "node.example.com" {
		t.Fatalf("expected record created with new IP, got %+v", state.created)
	}
	if state.created.Proxied {
		t.Fatal("DDNS records must not be proxied")
	}
}

func TestCloudflareZoneNotFound(t *testing.T) {
	srv, _ := cfMock(t)
	cf := &Cloudflare{Token: "t", BaseURL: srv.URL, Client: srv.Client()}
	err := cf.SetRecord(context.Background(), Record{Type: "A", Name: "node.other.org", IP: "1.2.3.4"})
	if err == nil || !strings.Contains(err.Error(), "no cloudflare zone") {
		t.Fatalf("expected zone-not-found error, got %v", err)
	}
}

func TestWebhookTemplating(t *testing.T) {
	var gotURL, gotBody, gotAuth string
	srv := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		gotAuth = r.Header.Get("Authorization")
		buf := new(strings.Builder)
		io.Copy(buf, r.Body)
		gotBody = buf.String()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	wh := &Webhook{
		URL:     srv.URL + "/update?ip=#ip#",
		Method:  "POST",
		Body:    `{"domain":"#domain#","type":"#type#","ip":"#ip#"}`,
		Headers: "Authorization: Bearer xyz",
		Client:  srv.Client(),
	}
	if err := wh.SetRecord(context.Background(), Record{Type: "AAAA", Name: "n.example.com", IP: "2001:db8::1"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotURL, "ip=2001:db8::1") {
		t.Fatalf("url not templated: %s", gotURL)
	}
	if !strings.Contains(gotBody, `"domain":"n.example.com"`) || !strings.Contains(gotBody, `"type":"AAAA"`) {
		t.Fatalf("body not templated: %s", gotBody)
	}
	if gotAuth != "Bearer xyz" {
		t.Fatalf("header not set: %s", gotAuth)
	}
}

func TestGuardOutboundBlocksInternal(t *testing.T) {
	for _, bad := range []string{
		"http://127.0.0.1/x", "http://localhost/x", "http://169.254.169.254/latest",
		"http://[::1]/x", "ftp://example.com", "http://10.0.0.5/x",
	} {
		if err := GuardOutbound(bad); err == nil {
			t.Fatalf("expected %q to be blocked", bad)
		}
	}
}

func TestApplyHonorsToggles(t *testing.T) {
	rec := &recorder{}
	profile := model.DDNSProfile{Domains: []string{"a.example.com"}, EnableIPv4: true, EnableIPv6: false, MaxRetries: 1}
	if err := Apply(context.Background(), rec, profile, "1.2.3.4", "2001:db8::1"); err != nil {
		t.Fatal(err)
	}
	if len(rec.records) != 1 || rec.records[0].Type != "A" {
		t.Fatalf("expected only an A record, got %+v", rec.records)
	}
}

func TestApplyRetries(t *testing.T) {
	rec := &recorder{failTimes: 2}
	profile := model.DDNSProfile{Domains: []string{"a.example.com"}, EnableIPv4: true, MaxRetries: 3}
	if err := Apply(context.Background(), rec, profile, "1.2.3.4", ""); err != nil {
		t.Fatalf("should succeed within retry budget: %v", err)
	}
	if rec.attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", rec.attempts)
	}
}

type recorder struct {
	records   []Record
	attempts  int
	failTimes int
}

func (r *recorder) Kind() string { return "recorder" }
func (r *recorder) SetRecord(ctx context.Context, rec Record) error {
	r.attempts++
	if r.failTimes > 0 {
		r.failTimes--
		return context.DeadlineExceeded
	}
	r.records = append(r.records, rec)
	return nil
}
