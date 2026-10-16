package ddns

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// answerEvery returns a Cloudflare client whose every request is answered
// with status and body.
func answerEvery(t *testing.T, status int, body string) *Cloudflare {
	t.Helper()
	srv := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return &Cloudflare{Token: "secret-cf-token", BaseURL: srv.URL, Client: srv.Client()}
}

// A refusal quotes Cloudflare's codes and messages and nothing else from the
// reply: no documentation link, no error chain, no messages list, and never
// the token. At most five errors are quoted, each message at most 200 bytes
// on one line, and the rest are counted.
func TestCloudflareRefusalQuotesOnlyItsCodesAndMessages(t *testing.T) {
	long := strings.Repeat("x", 300) + "\nsecond line"
	body := fmt.Sprintf(`{"success":false,"errors":[
		{"code":10000,"message":"Authentication error","documentation_url":"https://developers.cloudflare.com/raw-marker","error_chain":[{"code":1,"message":"chain-marker"}]},
		{"code":9109,"message":%q},
		{"code":1003,"message":"e3 <a & b>"},
		{"code":1004,"message":"e4"},
		{"code":1005,"message":"e5"},
		{"code":1006,"message":"e6"},
		{"code":1007,"message":"e7"}
	],"messages":["messages-marker"],"result":null}`, long)
	cf := answerEvery(t, http.StatusForbidden, body)

	err := cf.SetRecord(context.Background(), Record{Type: "A", Name: "home.example.com", IP: "203.0.113.10", TTL: 60})
	want := `cloudflare: api error (status 403): [{"code":10000,"message":"Authentication error"},` +
		`{"code":9109,"message":"` + strings.Repeat("x", 197) + `..."},` +
		`{"code":1003,"message":"e3 <a & b>"},{"code":1004,"message":"e4"},{"code":1005,"message":"e5"},` +
		`{"message":"2 more not shown"}]`
	if err == nil || err.Error() != want {
		t.Fatalf("refusal:\n got %v\nwant %s", err, want)
	}
	for _, leak := range []string{"raw-marker", "chain-marker", "messages-marker", "secret-cf-token", "second line"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("the refusal carries %q from the reply: %s", leak, err)
		}
	}
	if got := Classify(err); got != FailureProvider {
		t.Fatalf("a refusal classified as %v", got)
	}
}

// A reply that is not Cloudflare's envelope, such as an error page from its
// edge, is named by its status alone; one without an error list says so.
func TestCloudflareAnswerWithoutErrorsIsNamedByStatus(t *testing.T) {
	cases := []struct {
		status     int
		body, want string
	}{
		{http.StatusBadGateway, "<html>cloudflare edge raw-marker</html>", "cloudflare: status 502, undecodable body"},
		{http.StatusBadRequest, `{"success":false,"errors":null,"result":null}`, "cloudflare: api error (status 400) with no error list"},
	}
	for _, c := range cases {
		cf := answerEvery(t, c.status, c.body)
		err := cf.SetRecord(context.Background(), Record{Type: "A", Name: "home.example.com", IP: "203.0.113.10", TTL: 60})
		if err == nil || err.Error() != c.want {
			t.Fatalf("status %d: got %v, want %q", c.status, err, c.want)
		}
		if got := Classify(err); got != FailureProvider {
			t.Fatalf("status %d classified as %v", c.status, got)
		}
	}
}

// A name no zone of the token holds is a setting the operator changes, as is
// a profile missing what its provider needs.
func TestMissingSettingsAreConfigErrors(t *testing.T) {
	srv, _ := cfMock(t)
	cf := &Cloudflare{Token: "t", BaseURL: srv.URL, Client: srv.Client()}
	err := cf.SetRecord(context.Background(), Record{Type: "A", Name: "home.other.org", IP: "203.0.113.10", TTL: 60})
	if err == nil || err.Error() != `no cloudflare zone found for "home.other.org"` || Classify(err) != FailureConfig {
		t.Fatalf("unknown zone: %v (%v)", err, Classify(err))
	}
	for _, p := range []model.DDNSProfile{
		{Provider: model.DDNSProviderCloudflare},
		{Provider: model.DDNSProviderWebhook},
		{Provider: "route53"},
	} {
		if _, err := NewProvider(p, nil); err == nil || Classify(err) != FailureConfig {
			t.Fatalf("provider %q: %v (%v)", p.Provider, err, Classify(err))
		}
	}
}

// Apply joins one error per record. The whole failure is internal when any
// part is, so no part's text is shown; otherwise a provider failure outranks
// a setting, and a setting outranks a conflict.
func TestClassifyTakesTheLeastReadablePart(t *testing.T) {
	conflict := &ConflictError{Name: "home.example.com", Type: "A", Existing: []ExistingRecord{{Type: "CNAME", Content: "edge.example.net"}}}
	refused := fmt.Errorf("A home.example.com: %w", &cfAPIError{Status: 403, Items: []cfErrorItem{{Code: 10000, Message: "Authentication error"}}})
	config := fmt.Errorf("AAAA home.example.com: %w", &ConfigError{msg: "no cloudflare zone found"})
	internal := fmt.Errorf("AAAA home.example.com: %w", errors.New("dial tcp 10.9.8.7:443: connect: connection refused"))
	cases := []struct {
		name string
		err  error
		want Failure
	}{
		{"conflict", conflict, FailureConflict},
		{"refusal", refused, FailureProvider},
		{"setting", config, FailureConfig},
		{"transport", internal, FailureInternal},
		{"two conflicts", errors.Join(conflict, &ConflictError{Name: "b.example.com", Type: "A"}), FailureConflict},
		{"conflict and setting", errors.Join(conflict, config), FailureConfig},
		{"setting and refusal", errors.Join(config, refused), FailureProvider},
		{"refusal and transport", errors.Join(refused, internal), FailureInternal},
		{"conflict and transport", errors.Join(conflict, internal), FailureInternal},
		{"wrapped conflict and transport", fmt.Errorf("run: %w", errors.Join(conflict, internal)), FailureInternal},
		{"wrapped refusal and setting", fmt.Errorf("run: %w", errors.Join(refused, config)), FailureProvider},
	}
	for _, c := range cases {
		if got := Classify(c.err); got != c.want {
			t.Fatalf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
