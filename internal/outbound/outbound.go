package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
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

// NewTransport returns a guarded transport with proxy support disabled. Letting
// arbitrary environment proxies handle webhook traffic would let a proxy reach
// networks the local guard intentionally blocks.
func NewTransport() http.RoundTripper {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		targets, err := resolveAllowed(ctx, host, port)
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
		if err := GuardURL(req.URL.String()); err != nil {
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

func resolveAllowed(ctx context.Context, host, port string) ([]string, error) {
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
		if isBlockedIP(ip) {
			return nil, fmt.Errorf("blocked address %s for host %q", ip, host)
		}
		targets = append(targets, net.JoinHostPort(ip.String(), port))
	}
	return targets, nil
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
