package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/outbound"
)

// A tls monitor watches one endpoint's certificate expiry. It is the one
// monitor type the server evaluates itself: the endpoints worth watching are
// the operator's own service front doors (the first is the dnsproxy DoH
// listener at dns.roobli.org:8443), which no Lattice agent runs and which the
// control plane can reach directly. Results are stored with an empty NodeID
// and feed the same monitor.down / monitor.recovered notifications as an
// agent's tcp and http probes.
const (
	// tlsMonitorSweepTick is how often the sweep looks for a due monitor. The
	// per-monitor cadence is IntervalSec; this only bounds the delay before a
	// due monitor runs.
	tlsMonitorSweepTick = 60 * time.Second
	// tlsMonitorDefaultInterval is the cadence for a certificate watch that
	// does not name one. Expiry moves on the scale of days, so an hour is
	// already far more often than the value can change.
	tlsMonitorDefaultInterval = time.Hour
	// tlsMonitorDefaultThresholdDays is the default warning window.
	tlsMonitorDefaultThresholdDays = 14
	// tlsMonitorMaxThresholdDays bounds the operator's window to something a
	// certificate lifetime can satisfy.
	tlsMonitorMaxThresholdDays = 825
	tlsMonitorDefaultTimeout   = 10 * time.Second
)

// normalizeTLSMonitor validates a tls monitor on the create path. It carries no
// node assignment: the server, not an agent, dials the target.
func normalizeTLSMonitor(req model.Monitor) (model.Monitor, error) {
	if req.AssignAll || len(req.NodeIDs) > 0 {
		return model.Monitor{}, fieldErrorf("node_ids", "tls monitors are evaluated by the server: leave assign_all false and node_ids empty")
	}
	host, port, err := splitTLSTarget(req.Target)
	if err != nil {
		return model.Monitor{}, err
	}
	req.Target = net.JoinHostPort(host, port)
	if req.ThresholdDays == 0 {
		req.ThresholdDays = tlsMonitorDefaultThresholdDays
	}
	if req.ThresholdDays < 1 || req.ThresholdDays > tlsMonitorMaxThresholdDays {
		return model.Monitor{}, fieldErrorf("threshold_days", "threshold_days must be between 1 and %d", tlsMonitorMaxThresholdDays)
	}
	if req.IntervalSec <= 0 {
		req.IntervalSec = int(tlsMonitorDefaultInterval / time.Second)
	}
	if req.TimeoutSec <= 0 {
		req.TimeoutSec = int(tlsMonitorDefaultTimeout / time.Second)
	}
	return req, nil
}

// splitTLSTarget accepts host:port only. A URL would invite the assumption that
// the probe speaks the protocol behind the port; it does not, it reads the
// certificate the endpoint presents at handshake.
func splitTLSTarget(target string) (string, string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(target))
	if err != nil {
		return "", "", errors.New("tls monitor target must be host:port")
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", "", errors.New("tls monitor target must be host:port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", "", errors.New("tls monitor target port must be between 1 and 65535")
	}
	return host, strconv.Itoa(n), nil
}

func (s *Server) startTLSMonitorSweep() {
	go func() {
		for {
			time.Sleep(tlsMonitorSweepTick)
			s.sweepTLSMonitorsOnce(context.Background())
		}
	}()
}

// sweepTLSMonitorsOnce probes every enabled tls monitor whose interval has
// elapsed and returns how many it probed.
func (s *Server) sweepTLSMonitorsOnce(ctx context.Context) int {
	probed := 0
	now := s.now()
	for _, mon := range s.store.Monitors() {
		if mon.Type != model.MonitorTypeTLS || !mon.Enabled {
			continue
		}
		prior, hadPrior, err := s.store.MonitorLatest(mon.ID, "")
		if err != nil {
			s.logger.Printf("tls monitor %s (%s): read latest: %v", mon.Name, mon.Target, err)
			continue
		}
		if hadPrior && now.Before(prior.At.Add(tlsMonitorInterval(mon))) {
			continue
		}
		if err := s.runTLSMonitor(ctx, mon); err != nil {
			s.logger.Printf("tls monitor %s (%s): %v", mon.Name, mon.Target, err)
		}
		probed++
	}
	return probed
}

func tlsMonitorInterval(mon model.Monitor) time.Duration {
	if mon.IntervalSec > 0 {
		return time.Duration(mon.IntervalSec) * time.Second
	}
	return tlsMonitorDefaultInterval
}

// runTLSMonitor probes one monitor, stores the result and notifies on a
// transition, exactly as the agent ingest path does for tcp and http.
func (s *Server) runTLSMonitor(ctx context.Context, mon model.Monitor) error {
	result := s.evaluateTLSMonitor(ctx, mon)
	out, err := s.store.AddMonitorResult(result)
	if err != nil {
		return err
	}
	if out.Stored() {
		s.notifyMonitorTransition("", result, out.PriorFailStreak)
	}
	return nil
}

// evaluateTLSMonitor dials the target, reads the leaf certificate and judges
// it. A handshake that never completed is a failure with the dial error. A
// completed handshake always records CertNotAfter, whatever the verdict, since
// reading the expiry is what the probe is for. The run then fails when the
// target is a host name the leaf does not cover (SNI already asked for that
// name; the reason names the host and the names the certificate carries), and
// when fewer than the threshold's days remain, an expired certificate
// included. A target named by IP address is not name-checked: most
// certificates carry no address.
func (s *Server) evaluateTLSMonitor(ctx context.Context, mon model.Monitor) model.MonitorResult {
	now := s.now()
	result := model.MonitorResult{MonitorID: mon.ID, At: now}
	timeout := time.Duration(mon.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = tlsMonitorDefaultTimeout
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	started := time.Now()
	leaf, err := s.readTLSLeaf(dialCtx, mon.Target)
	result.LatencyMs = float64(time.Since(started).Microseconds()) / 1000
	if err != nil {
		result.Error = err.Error()
		return result
	}
	notAfter := leaf.NotAfter
	result.CertNotAfter = notAfter.UTC()
	var problems []string
	if host, _, err := splitTLSTarget(mon.Target); err == nil && net.ParseIP(host) == nil {
		if leaf.VerifyHostname(host) != nil {
			problems = append(problems, fmt.Sprintf("the certificate does not cover %s (it names %s)", host, certificateNames(leaf)))
		}
	}
	threshold := mon.ThresholdDays
	if threshold <= 0 {
		threshold = tlsMonitorDefaultThresholdDays
	}
	remaining := notAfter.Sub(now)
	if remaining < time.Duration(threshold)*24*time.Hour {
		problems = append(problems, fmt.Sprintf("certificate expires %s, %s (threshold %d days)",
			notAfter.UTC().Format(time.RFC3339), humanizeCertRemaining(remaining), threshold))
	}
	if len(problems) > 0 {
		result.Error = strings.Join(problems, "; ")
		return result
	}
	result.Success = true
	return result
}

// certificateNamesShown bounds how many of a certificate's DNS names a failure
// lists, so a certificate for hundreds of names does not fill the result.
const certificateNamesShown = 5

// certificateNames lists the leaf's DNS names for a failure reason.
func certificateNames(leaf *x509.Certificate) string {
	names := leaf.DNSNames
	if len(names) == 0 {
		return "no DNS names"
	}
	if len(names) <= certificateNamesShown {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:certificateNamesShown], ", "), len(names)-certificateNamesShown)
}

// humanizeCertRemaining says how far the expiry is in whole days, in the
// direction it actually lies.
func humanizeCertRemaining(remaining time.Duration) string {
	days := int(remaining.Hours() / 24)
	if remaining < 0 {
		return fmt.Sprintf("expired %d days ago", -days)
	}
	return fmt.Sprintf("in %d days", days)
}

// readTLSLeaf dials the target and returns the leaf certificate.
//
// The handshake deliberately does not verify the chain (InsecureSkipVerify).
// This probe exists to read an expiry, and a verifying handshake refuses in
// exactly the cases the operator most needs the number for: a certificate that
// has already expired, or one whose chain is incomplete. Nothing is sent over
// this connection and nothing read from it is trusted. The probe asserts two
// things about the leaf, after the handshake and without refusing it: its
// not-after against the operator's threshold, and, on a host-name target, that
// it names that host. Neither stops the expiry being read.
func (s *Server) readTLSLeaf(ctx context.Context, target string) (*x509.Certificate, error) {
	host, port, err := splitTLSTarget(target)
	if err != nil {
		return nil, err
	}
	addrs, err := s.tlsMonitorTargets(ctx, host, port)
	if err != nil {
		return nil, err
	}
	var lastErr error
	dialer := &net.Dialer{}
	for _, addr := range addrs {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			lastErr = err
			continue
		}
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: host,
			// See the doc comment: expiry is read, trust is not asserted.
			InsecureSkipVerify: true, // #nosec G402 -- an expiry probe asserts no trust, see the doc comment
			MinVersion:         tls.VersionTLS12,
		})
		err = tlsConn.HandshakeContext(ctx)
		if err != nil {
			_ = tlsConn.Close()
			lastErr = err
			continue
		}
		chain := tlsConn.ConnectionState().PeerCertificates
		_ = tlsConn.Close()
		if len(chain) == 0 {
			lastErr = errors.New("handshake presented no certificate")
			continue
		}
		return chain[0], nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no address for %q", host)
	}
	return nil, lastErr
}

// defaultTLSMonitorTargets is the production address policy: the same classes
// GuardURL refuses (loopback, private, link-local, the metadata endpoint) are
// refused here, so a monitor target cannot be pointed at the control plane's
// own network.
func defaultTLSMonitorTargets(ctx context.Context, host, port string) ([]string, error) {
	return outbound.ResolveAllowed(ctx, host, port)
}
