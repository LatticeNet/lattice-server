package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"
)

const maxRedirects = 5

var blockedSpecialUsePrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// NewClient returns an HTTP client for operator-configured outbound webhooks.
// It validates both the requested URL and the actual dial target so DNS rebinding
// and redirects cannot turn an allowed hostname into an internal-address request.
func NewClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: NewTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("too many redirects")
			}
			return GuardURL(req.URL.String())
		},
	}
}

// NewOperatorClient permits an explicitly operator-selected private service
// target while preserving scheme, URL-shape, redirect, DNS, and dial checks.
// It is intentionally separate from NewClient: callers need a stronger,
// system-only capability to use it.
func NewOperatorClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: NewOperatorTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("too many redirects")
			}
			if len(via) > 0 && !sameOrigin(via[0].URL, req.URL) {
				return errors.New("operator target redirect must stay on the original origin")
			}
			return GuardOperatorURL(req.URL.String())
		},
	}
}

// NewTransport returns a guarded transport with proxy support disabled. Letting
// arbitrary environment proxies handle webhook traffic would let a proxy reach
// networks the local guard intentionally blocks.
func NewTransport() http.RoundTripper {
	return newGuardedTransport(GuardURL, resolveAllowed)
}

// NewOperatorTransport allows private and loopback HTTPS destinations, and
// loopback-only HTTP, while still rejecting metadata/link-local and special
// address classes at both URL validation and dial time.
func NewOperatorTransport() http.RoundTripper {
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if err := GuardOperatorURL(req.URL.String()); err != nil {
			return nil, err
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.Proxy = nil
		tr.DisableKeepAlives = true
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			targets, err := resolveOperatorTargetForScheme(ctx, host, port, req.URL.Scheme)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, target := range targets {
				conn, err := dialer.DialContext(ctx, network, target)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, fmt.Errorf("no resolved addresses for %q", host)
		}
		return tr.RoundTrip(req)
	})
}

func newGuardedTransport(guard func(string) error, resolve func(context.Context, string, string) ([]string, error)) http.RoundTripper {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		targets, err := resolve(ctx, host, port)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, target := range targets {
			conn, err := dialer.DialContext(ctx, network, target)
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("no resolved addresses for %q", host)
	}
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if err := guard(req.URL.String()); err != nil {
			return nil, err
		}
		return tr.RoundTrip(req)
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// GuardURL rejects outbound HTTP(S) targets that point at local, private,
// link-local, multicast, unspecified, or cloud metadata addresses.
func GuardURL(raw string) error {
	u, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	if u.URL.Scheme != "http" && u.URL.Scheme != "https" {
		return fmt.Errorf("unsupported scheme %q", u.URL.Scheme)
	}
	host := u.URL.Hostname()
	if host == "" {
		return errors.New("missing host")
	}
	port := u.URL.Port()
	if port == "" {
		if u.URL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	_, err = resolveAllowed(context.Background(), host, port)
	return err
}

// GuardOperatorURL validates an operator-selected API endpoint. Unlike
// GuardURL it deliberately permits private and loopback HTTPS destinations;
// cleartext HTTP is restricted to loopback. Secret-bearing endpoints must keep
// credentials out of authority/query/fragment and use a non-root path.
func GuardOperatorURL(raw string) error {
	u, err := parseOperatorURL(raw)
	if err != nil {
		return err
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	_, err = resolveOperatorTargetForScheme(context.Background(), u.Hostname(), port, u.Scheme)
	return err
}

// GuardOperatorTargetBinding requires target to stay on the exact origin and
// below the secret-bearing base path selected for this invocation. It does not
// replace GuardOperatorURL's DNS and address checks; the broker applies both.
func GuardOperatorTargetBinding(baseRaw, targetRaw string) error {
	base, err := parseOperatorURL(baseRaw)
	if err != nil {
		return fmt.Errorf("invalid bound operator target: %w", err)
	}
	target, err := parseOperatorURL(targetRaw)
	if err != nil {
		return err
	}
	if !sameOrigin(base, target) {
		return errors.New("operator target is outside the invocation-bound origin")
	}
	basePath := strings.TrimSuffix(path.Clean(base.Path), "/")
	targetPath := path.Clean(target.Path)
	if targetPath != basePath && !strings.HasPrefix(targetPath, basePath+"/") {
		return errors.New("operator target is outside the invocation-bound path")
	}
	return nil
}

func resolveAllowed(ctx context.Context, host, port string) ([]string, error) {
	return resolveWithPolicy(ctx, host, port, func(ip net.IP) bool { return !isBlockedIP(ip) })
}

func resolveOperatorTargetForScheme(ctx context.Context, host, port, scheme string) ([]string, error) {
	return resolveWithPolicy(ctx, host, port, func(ip net.IP) bool {
		if isBlockedOperatorIP(ip) {
			return false
		}
		return scheme != "http" || ip.IsLoopback()
	})
}

func resolveWithPolicy(ctx context.Context, host, port string, allowed func(net.IP) bool) ([]string, error) {
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %q: %w", host, err)
		}
		for _, addr := range addrs {
			ips = append(ips, addr.IP)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve %q: no addresses", host)
	}
	targets := make([]string, 0, len(ips))
	for _, ip := range ips {
		if !allowed(ip) {
			return nil, fmt.Errorf("blocked address %s for host %q", ip, host)
		}
		targets = append(targets, net.JoinHostPort(ip.String(), port))
	}
	return targets, nil
}

func parseOperatorURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, errors.New("missing host")
	}
	if u.User != nil {
		return nil, errors.New("operator target must not include credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("operator target must not include query or fragment")
	}
	if u.Path == "" || u.Path == "/" {
		return nil, errors.New("operator target must include a non-root path")
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return nil, errors.New("operator target path must not contain dot segments")
		}
	}
	if port := u.Port(); port != "" {
		if _, err := net.LookupPort("tcp", port); err != nil {
			return nil, errors.New("operator target port is invalid")
		}
	}
	return u, nil
}

func isBlockedOperatorIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	return ip.Equal(net.ParseIP("169.254.169.254")) || ip.Equal(net.ParseIP("255.255.255.255"))
}

func sameOrigin(a, b *url.URL) bool {
	return a != nil && b != nil && strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) && effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsPrivate() {
		return true
	}
	if ip.Equal(net.ParseIP("169.254.169.254")) {
		return true
	}
	addr, ok := netip.AddrFromSlice(ip)
	if ok {
		addr = addr.Unmap()
		for _, prefix := range blockedSpecialUsePrefixes {
			if prefix.Contains(addr) {
				return true
			}
		}
	}
	return false
}
