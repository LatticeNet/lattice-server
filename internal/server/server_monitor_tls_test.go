package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// tlsTestListener serves a self-signed certificate expiring at notAfter and
// returns the address it listens on.
func tlsTestListener(t *testing.T, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dns.test.invalid"},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"dns.test.invalid"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = conn.(*tls.Conn).Handshake()
				conn.Close()
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

type notifyRecorder struct {
	mu   sync.Mutex
	sent []string
}

func (n *notifyRecorder) record(title, body string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, title+" | "+body)
}

func (n *notifyRecorder) all() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.sent...)
}

// newTLSMonitorServer builds a server whose tls probe reaches addr whatever
// host the monitor names, with a clock the test drives.
//
// The background loops stay off. Every field below is installed after New()
// returns, so a sweeper goroutine started inside New() would read s.now while
// the test writes it and the race detector would (correctly) fail the test.
// These tests drive sweepTLSMonitorsOnce themselves and need no loop running.
func newTLSMonitorServer(t *testing.T, addr *string, now *time.Time) (*Server, http.Handler, *notifyRecorder) {
	t.Helper()
	srv, handler, _ := newDNSServerWithOptions(t, Options{DisableRenewalScheduler: true})
	srv.now = func() time.Time { return *now }
	srv.tlsMonitorTargets = func(ctx context.Context, host, port string) ([]string, error) {
		if *addr == "" {
			return nil, errors.New("no listener")
		}
		return []string{*addr}, nil
	}
	rec := &notifyRecorder{}
	srv.emitNotify = rec.record
	return srv, handler, rec
}

func createTLSMonitor(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, body string) monitorView {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/monitors", body, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create tls monitor failed: %d", res.StatusCode)
	}
	var out monitorView
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTLSMonitorWatchesCertificateExpiry(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	addr := ""
	srv, handler, rec := newTLSMonitorServer(t, &addr, &now)
	cookies, csrf := loginSession(t, handler)

	addr = tlsTestListener(t, now.Add(60*24*time.Hour))
	mon := createTLSMonitor(t, handler, cookies, csrf,
		`{"name":"dns doh cert","type":"tls","target":"dns.test.invalid:8443","threshold_days":14,"interval_sec":3600}`)
	if mon.ThresholdDays != 14 {
		t.Fatalf("threshold_days = %d, want 14", mon.ThresholdDays)
	}
	if mon.AssignAll || len(mon.NodeIDs) != 0 {
		t.Fatalf("a tls monitor carries no node assignment: %+v", mon)
	}

	// The list view carries the threshold so the console can show it.
	listed := doJSON(t, handler, http.MethodGet, "/api/monitors", "", cookies, "")
	defer listed.Body.Close()
	var views []monitorView
	if err := json.NewDecoder(listed.Body).Decode(&views); err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].ThresholdDays != 14 {
		t.Fatalf("list should report threshold_days: %+v", views)
	}

	// A server-evaluated monitor must never be handed to an agent.
	nodeID, nodeToken := enrollNode(t, handler, cookies, csrf)
	areq, _ := http.NewRequest(http.MethodGet, "/api/agent/monitors?node_id="+nodeID, nil)
	areq.Header.Set("Authorization", "Bearer "+nodeToken)
	arec := serveReq(handler, areq)
	if strings.Contains(arec.Body.String(), mon.ID) {
		t.Fatalf("tls monitor was handed to an agent: %s", arec.Body.String())
	}

	if probed := srv.sweepTLSMonitorsOnce(context.Background()); probed != 1 {
		t.Fatalf("probed = %d, want 1", probed)
	}
	results := srv.store.MonitorResults(mon.ID)
	if len(results) != 1 {
		t.Fatalf("results = %+v, want one", results)
	}
	first := results[0]
	if !first.Success {
		t.Fatalf("a certificate 60 days out should pass a 14 day threshold: %+v", first)
	}
	if first.NodeID != "" {
		t.Fatalf("a server-evaluated result carries no node: %+v", first)
	}
	if !first.CertNotAfter.Equal(now.Add(60 * 24 * time.Hour).UTC().Truncate(time.Second)) {
		t.Fatalf("cert_not_after = %s, want the leaf's not-after", first.CertNotAfter)
	}
	if len(rec.all()) != 0 {
		t.Fatalf("a first passing probe should not notify: %+v", rec.all())
	}

	// The certificate is replaced by one inside the threshold: the watch fails
	// and the existing monitor.down notification fires.
	now = now.Add(2 * time.Hour)
	addr = tlsTestListener(t, now.Add(5*24*time.Hour))
	if probed := srv.sweepTLSMonitorsOnce(context.Background()); probed != 1 {
		t.Fatalf("second sweep probed = %d, want 1", probed)
	}
	results = srv.store.MonitorResults(mon.ID)
	if len(results) != 2 {
		t.Fatalf("results = %+v, want two", results)
	}
	second := results[1]
	if second.Success {
		t.Fatalf("a certificate 5 days out must fail a 14 day threshold: %+v", second)
	}
	if !strings.Contains(second.Error, "in 5 days") || !strings.Contains(second.Error, "threshold 14 days") {
		t.Fatalf("error should say how close the expiry is: %q", second.Error)
	}
	if second.CertNotAfter.IsZero() {
		t.Fatalf("a completed handshake always records the expiry: %+v", second)
	}
	sent := rec.all()
	if len(sent) != 1 || !strings.Contains(sent[0], "Monitor down") {
		t.Fatalf("expected one monitor.down notification, got %+v", sent)
	}
	if !strings.Contains(sent[0], "dns.test.invalid:8443") {
		t.Fatalf("a server-evaluated alert names its target: %q", sent[0])
	}

	// Back to a healthy certificate: the recovery notification fires.
	now = now.Add(2 * time.Hour)
	addr = tlsTestListener(t, now.Add(90*24*time.Hour))
	if probed := srv.sweepTLSMonitorsOnce(context.Background()); probed != 1 {
		t.Fatalf("third sweep probed = %d, want 1", probed)
	}
	sent = rec.all()
	if len(sent) != 2 || !strings.Contains(sent[1], "Monitor recovered") {
		t.Fatalf("expected a monitor.recovered notification, got %+v", sent)
	}
}

func TestTLSMonitorSkipsUntilIntervalElapses(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	addr := ""
	srv, handler, _ := newTLSMonitorServer(t, &addr, &now)
	cookies, csrf := loginSession(t, handler)
	addr = tlsTestListener(t, now.Add(60*24*time.Hour))
	mon := createTLSMonitor(t, handler, cookies, csrf,
		`{"name":"cert","type":"tls","target":"dns.test.invalid:8443","interval_sec":3600}`)
	if mon.ThresholdDays != tlsMonitorDefaultThresholdDays {
		t.Fatalf("threshold_days = %d, want the %d day default", mon.ThresholdDays, tlsMonitorDefaultThresholdDays)
	}
	srv.sweepTLSMonitorsOnce(context.Background())
	now = now.Add(10 * time.Minute)
	if probed := srv.sweepTLSMonitorsOnce(context.Background()); probed != 0 {
		t.Fatalf("probed = %d before the interval elapsed, want 0", probed)
	}
	if got := len(srv.store.MonitorResults(mon.ID)); got != 1 {
		t.Fatalf("results = %d, want the single first probe", got)
	}
}

func TestTLSMonitorUnreachableTargetFails(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	addr := ""
	srv, handler, rec := newTLSMonitorServer(t, &addr, &now)
	cookies, csrf := loginSession(t, handler)
	// A listener that is closed before the probe runs: the handshake never
	// completes, so there is no expiry to record.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = dead.Addr().String()
	dead.Close()
	mon := createTLSMonitor(t, handler, cookies, csrf,
		`{"name":"cert","type":"tls","target":"dns.test.invalid:8443","threshold_days":14}`)
	srv.sweepTLSMonitorsOnce(context.Background())
	results := srv.store.MonitorResults(mon.ID)
	if len(results) != 1 || results[0].Success {
		t.Fatalf("an unreachable target must fail: %+v", results)
	}
	if !results[0].CertNotAfter.IsZero() {
		t.Fatalf("no handshake means no expiry: %+v", results[0])
	}
	sent := rec.all()
	if len(sent) != 1 || !strings.Contains(sent[0], "Monitor down") {
		t.Fatalf("a first failing probe notifies: %+v", sent)
	}
}

func TestTLSMonitorCreateValidation(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	addr := ""
	_, handler, _ := newTLSMonitorServer(t, &addr, &now)
	cookies, csrf := loginSession(t, handler)
	cases := map[string]string{
		"assigned to nodes": `{"name":"c","type":"tls","target":"dns.test.invalid:8443","assign_all":true}`,
		"url target":        `{"name":"c","type":"tls","target":"https://dns.test.invalid:8443"}`,
		"no port":           `{"name":"c","type":"tls","target":"dns.test.invalid"}`,
		"bad port":          `{"name":"c","type":"tls","target":"dns.test.invalid:0"}`,
		"huge threshold":    `{"name":"c","type":"tls","target":"dns.test.invalid:8443","threshold_days":100000}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			res := doJSON(t, handler, http.MethodPost, "/api/monitors", body, cookies, csrf)
			defer res.Body.Close()
			if res.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", res.StatusCode)
			}
		})
	}
}

func TestTLSMonitorIsDeletable(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	addr := ""
	srv, handler, _ := newTLSMonitorServer(t, &addr, &now)
	cookies, csrf := loginSession(t, handler)
	mon := createTLSMonitor(t, handler, cookies, csrf,
		`{"name":"cert","type":"tls","target":"dns.test.invalid:8443"}`)
	res := doJSON(t, handler, http.MethodPost, "/api/monitors/delete", `{"id":"`+mon.ID+`"}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d, want 200", res.StatusCode)
	}
	if _, ok := srv.store.Monitor(mon.ID); ok {
		t.Fatalf("monitor %s survived its delete", mon.ID)
	}
}
