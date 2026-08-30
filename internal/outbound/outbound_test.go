package outbound

import (
	"net"
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

// A NAT64 address carries an IPv4 address in its low 32 bits (RFC 6052,
// 64:ff9b::/96). On a host behind a NAT64 gateway - which is what an IPv6-only
// network gives you - dialling one reaches that IPv4 address, so the guard has
// to judge it as the address it reaches rather than as the IPv6 address it is
// written as. None of Go's loopback/private predicates fire on the IPv6 form.
func TestNAT64AddressesAreJudgedAsTheIPv4TheyReach(t *testing.T) {
	blocked := []string{
		"64:ff9b::7f00:1",    // 127.0.0.1
		"64:ff9b::a00:1",     // 10.0.0.1
		"64:ff9b::c0a8:101",  // 192.168.1.1
		"64:ff9b::ac10:1",    // 172.16.0.1
		"64:ff9b::a9fe:a9fe", // 169.254.169.254, the cloud metadata service
		"64:ff9b::",          // 0.0.0.0
	}
	for _, raw := range blocked {
		if !isBlockedIP(net.ParseIP(raw)) {
			t.Errorf("egress guard allowed %s, which reaches %s", raw, embeddedNAT64IPv4(net.ParseIP(raw)))
		}
	}
	// The operator client is permissive about private space on purpose, but the
	// metadata service is never a legitimate operator endpoint.
	if !isBlockedOperatorIP(net.ParseIP("64:ff9b::a9fe:a9fe")) {
		t.Error("operator guard allowed a NAT64 route to the metadata service")
	}
	// A NAT64 address for a public IPv4 host is a legitimate destination and
	// must still be reachable, or IPv6-only deployments lose all egress.
	if isBlockedIP(net.ParseIP("64:ff9b::808:808")) { // 8.8.8.8
		t.Error("egress guard blocked a NAT64 route to a public address")
	}
	// Addresses outside the well-known prefix are not NAT64 and must not be
	// reinterpreted: 2001:db8::7f00:1 is documentation space, not loopback.
	if got := embeddedNAT64IPv4(net.ParseIP("2001:db8::7f00:1")); got != nil {
		t.Errorf("treated a non-NAT64 address as NAT64: %s", got)
	}
}
