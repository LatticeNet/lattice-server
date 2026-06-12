package outbound

import (
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

func TestGuardURLReportsBlockedAddress(t *testing.T) {
	err := GuardURL("http://127.0.0.1/")
	if err == nil || !strings.Contains(err.Error(), "blocked address") {
		t.Fatalf("expected blocked address error, got %v", err)
	}
}
