package server

import (
	"context"
	"crypto/tls"
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
		return model.Monitor{}, errors.New("tls monitors are evaluated by the server: leave assign_all false and node_ids empty")
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
		return model.Monitor{}, fmt.Errorf("threshold_days must be between 1 and %d", tlsMonitorMaxThresholdDays)
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
		prior, hadPrior := s.store.LastMonitorResultForNode(mon.ID, "")
		if hadPrior && now.Before(prior.At.Add(tlsMonitorInterval(mon))) {
			continue
		}
		if err := s.runTLSMonitor(ctx, mon, prior, hadPrior); err != nil {
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
func (s *Server) runTLSMonitor(ctx context.Context, mon model.Monitor, prior model.MonitorResult, hadPrior bool) error {
	result := s.evaluateTLSMonitor(ctx, mon)
	if err := s.store.AddMonitorResult(result); err != nil {
		return err
	}
	s.notifyMonitorTransition("", result, prior, hadPrior)
	return nil
}

// evaluateTLSMonitor dials the target, reads the leaf certificate and judges
// its not-after against the monitor's threshold. A handshake that never
// completed is a failure with the dial error; a handshake that completed
// always records CertNotAfter, whether or not the threshold passed.
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
	notAfter, err := s.readTLSLeafNotAfter(dialCtx, mon.Target)
	result.LatencyMs = float64(time.Since(started).Microseconds()) / 1000
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.CertNotAfter = notAfter.UTC()
	threshold := mon.ThresholdDays
	if threshold <= 0 {
		threshold = tlsMonitorDefaultThresholdDays
	}
	remaining := notAfter.Sub(now)
	if remaining < time.Duration(threshold)*24*time.Hour {
		result.Error = fmt.Sprintf("certificate expires %s, %s (threshold %d days)",
			notAfter.UTC().Format(time.RFC3339), humanizeCertRemaining(remaining), threshold)
		return result
	}
	result.Success = true
	return result
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

// readTLSLeafNotAfter dials the target and returns the leaf certificate's
// not-after.
//
// The handshake deliberately does not verify the chain (InsecureSkipVerify).
// This probe exists to read an expiry, and a verifying handshake refuses in
// exactly the cases the operator most needs the number for: a certificate that
// has already expired, or one whose chain is incomplete. Nothing is sent over
// this connection and nothing read from it is trusted; the only value taken is
// the leaf's not-after, which the operator then compares against a threshold.
func (s *Server) readTLSLeafNotAfter(ctx context.Context, target string) (time.Time, error) {
	host, port, err := splitTLSTarget(target)
	if err != nil {
		return time.Time{}, err
	}
	addrs, err := s.tlsMonitorTargets(ctx, host, port)
	if err != nil {
		return time.Time{}, err
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
			InsecureSkipVerify: true, //nolint:gosec // expiry probe, see doc comment
			MinVersion:         tls.VersionTLS12,
		})
		err = tlsConn.HandshakeContext(ctx)
		if err != nil {
			tlsConn.Close()
			lastErr = err
			continue
		}
		chain := tlsConn.ConnectionState().PeerCertificates
		tlsConn.Close()
		if len(chain) == 0 {
			lastErr = errors.New("handshake presented no certificate")
			continue
		}
		return chain[0].NotAfter, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no address for %q", host)
	}
	return time.Time{}, lastErr
}

// defaultTLSMonitorTargets is the production address policy: the same classes
// GuardURL refuses (loopback, private, link-local, the metadata endpoint) are
// refused here, so a monitor target cannot be pointed at the control plane's
// own network.
func defaultTLSMonitorTargets(ctx context.Context, host, port string) ([]string, error) {
	return outbound.ResolveAllowed(ctx, host, port)
}
