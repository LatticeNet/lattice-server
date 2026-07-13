package outbound

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGuardURLBlocksInternalAndSpecialUseTargets(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1/",
		"http://[::1]/",
		"http://10.0.0.1/",
		"http://169.254.169.254/latest",
		"http://100.64.0.1/",
		"ftp://example.com/",
	} {
		if err := GuardURL(raw); err == nil {
			t.Fatalf("expected %q to be blocked", raw)
		}
	}
}

func TestOperatorClientRejectsCrossOriginRedirect(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/secret", http.StatusFound)
	}))
	defer source.Close()

	_, err := NewOperatorClient(0).Get(source.URL + "/secret")
	if err == nil || !strings.Contains(err.Error(), "original origin") {
		t.Fatalf("expected cross-origin redirect rejection, got %v", err)
	}
}

func TestGuardURLReportsBlockedAddress(t *testing.T) {
	err := GuardURL("http://127.0.0.1/")
	if err == nil || !strings.Contains(err.Error(), "blocked address") {
		t.Fatalf("expected blocked address error, got %v", err)
	}
}

func TestGuardOperatorURLAllowsExplicitPrivateTargetsAndRejectsUnsafeShapes(t *testing.T) {
	allowed := []string{
		"http://127.0.0.1:3000/secret",
		"http://[::1]:3000/secret",
		"https://10.0.0.5/secret",
		"https://100.64.0.5/secret",
		"https://203.0.113.10/secret",
	}
	for _, raw := range allowed {
		if err := GuardOperatorURL(raw); err != nil {
			t.Fatalf("expected operator target %q to be allowed, got %v", raw, err)
		}
	}

	rejected := []string{
		"http://10.0.0.5/secret",
		"https://169.254.169.254/latest/meta-data",
		"https://user:pass@10.0.0.5/secret",
		"https://10.0.0.5/",
		"https://10.0.0.5/secret?token=x",
		"https://10.0.0.5/secret#fragment",
		"https://10.0.0.5/a/../secret",
		"ftp://10.0.0.5/secret",
	}
	for _, raw := range rejected {
		if err := GuardOperatorURL(raw); err == nil {
			t.Fatalf("expected operator target %q to be rejected", raw)
		}
	}
}

func TestGuardOperatorTargetBindingStaysOnApprovedOriginAndPath(t *testing.T) {
	base := "https://10.0.0.5/secret-token"
	for _, target := range []string{
		base,
		base + "/api/utils/env",
		base + "/api/sub/name",
	} {
		if err := GuardOperatorTargetBinding(base, target); err != nil {
			t.Fatalf("expected target %q to stay bound: %v", target, err)
		}
	}
	for _, target := range []string{
		"https://10.0.0.5/other/api",
		"https://10.0.0.6/secret-token/api",
		"http://127.0.0.1:3000/secret-token/api",
	} {
		if err := GuardOperatorTargetBinding(base, target); err == nil {
			t.Fatalf("expected target %q to escape binding", target)
		}
	}
}
