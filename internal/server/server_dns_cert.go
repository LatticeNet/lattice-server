package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// "Measure this certificate" (design 32 S5c). An external engine's record
// carries a certificate expiry the operator typed, which nothing checks. The
// action turns the DoT and DoH listeners the operator names into tls checks,
// which the server dials on its own schedule and which feed Expiring, and
// links them to the deployment, so its sheet shows the measured expiry and
// says so, and falls back to the typed date while nothing has been measured.
//
// The checks are ordinary operator checks: they are edited, paused and
// deleted under Monitoring, and deleting the deployment leaves them. The link
// is the deployment's CertMonitorIDs, written only by
// store.LinkDNSCertMonitors, in the same write that stores the new checks.
//
// A tls check has no source node: the control plane evaluates it
// (server_monitor_tls.go). Measuring from a chosen vantage point is what a
// dns check (S5a) does for its resolver's certificate.

const (
	dnsCertSourceMeasured = "measured"
	dnsCertSourceTyped    = "typed"
)

// dnsCertCheckView is one linked tls check the caller may read. CertNotAfter
// and MeasuredAt come from its newest result that completed a handshake.
type dnsCertCheckView struct {
	MonitorID     string    `json:"monitor_id"`
	Name          string    `json:"name"`
	Target        string    `json:"target"`
	ThresholdDays int       `json:"threshold_days"`
	Enabled       bool      `json:"enabled"`
	CertNotAfter  time.Time `json:"cert_not_after,omitzero"`
	MeasuredAt    time.Time `json:"measured_at,omitzero"`
}

// dnsCertExpiryView is the expiry the sheet shows and where it comes from:
// the soonest one an enabled linked check measured, or else the typed date.
type dnsCertExpiryView struct {
	NotAfter  time.Time `json:"not_after"`
	Source    string    `json:"source"`
	MonitorID string    `json:"monitor_id,omitempty"`
}

// dnsCertViews reads the linked checks the caller may read and the expiry the
// sheet shows. A check is skipped when it was deleted since it was linked, or
// no longer dials an endpoint the record lists (its hostname on a recorded tcp
// port): after the hostname or the listeners change, or someone edits the
// check's target, its reading is of another endpoint. Such a check stays an
// ordinary check under Monitoring. A caller who cannot read the checks gets
// the typed date, which is what the sheet then says it shows.
func (s *Server) dnsCertViews(p principal, dep model.DNSDeployment) ([]dnsCertCheckView, *dnsCertExpiryView) {
	endpoints := map[string]bool{}
	for _, l := range dep.Listeners {
		if l.Protocol == "tcp" && dep.Hostname != "" {
			endpoints[strings.ToLower(net.JoinHostPort(dep.Hostname, strconv.Itoa(l.Port)))] = true
		}
	}
	var checks []dnsCertCheckView
	var expiry *dnsCertExpiryView
	for _, monitorID := range dep.CertMonitorIDs {
		mon, ok := s.store.Monitor(monitorID)
		if !ok || mon.Type != model.MonitorTypeTLS || !endpoints[strings.ToLower(mon.Target)] || !monitorVisibleToPrincipal(p, "monitor:read", mon) {
			continue
		}
		view := dnsCertCheckView{MonitorID: mon.ID, Name: mon.Name, Target: mon.Target, ThresholdDays: mon.ThresholdDays, Enabled: mon.Enabled}
		rec, measured, err := s.store.NewestMonitorResult(mon.ID, "", func(r store.MonitorResultRecord) bool {
			return !r.CertNotAfter.IsZero()
		})
		if err != nil {
			s.logger.Printf("dns deployment %s: read certificate check %s: %v", dep.ID, mon.ID, err)
		}
		if err == nil && measured {
			view.CertNotAfter, view.MeasuredAt = rec.CertNotAfter.UTC(), rec.At.UTC()
			// A paused check's last reading is history, as Expiring treats it.
			if mon.Enabled && (expiry == nil || view.CertNotAfter.Before(expiry.NotAfter)) {
				expiry = &dnsCertExpiryView{NotAfter: view.CertNotAfter, Source: dnsCertSourceMeasured, MonitorID: mon.ID}
			}
		}
		checks = append(checks, view)
	}
	if expiry == nil && !dep.CertNotAfter.IsZero() {
		expiry = &dnsCertExpiryView{NotAfter: dep.CertNotAfter.UTC(), Source: dnsCertSourceTyped}
	}
	return checks, expiry
}

type dnsMeasureCertRequest struct {
	ID string `json:"id"`
	// Ports are the recorded tcp listeners that speak DoT or DoH. The
	// record says which ports the engine listens on, not which of them
	// speak TLS, so the caller names them.
	Ports []int `json:"ports"`
	// ThresholdDays is the warning window of the checks created; zero is
	// the tls check default. A check that already exists keeps its own.
	ThresholdDays int `json:"threshold_days,omitempty"`
}

// POST /api/dns/measure-cert creates one tls check per named listener of an
// external engine, at hostname:port, and links them to the deployment in one
// write. An authored tls check on exactly that endpoint is linked rather than
// duplicated, so measuring again, or after a write that failed, creates
// nothing twice.
//
// It writes both a monitor and a deployment, so it takes what each write takes
// on its own: dns:admin on the deployment's node, as a save does, and the rule
// for creating a tls check by hand, monitor:admin on a token with no node
// allowlist. The checks dial the record's hostname, never an address, so SNI
// asks for that name and the probe holds the certificate to it.
func (s *Server) handleDNSMeasureCert(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req dnsMeasureCertRequest
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, fieldErrorf("id", "id is required"))
		return
	}
	dep, ok := s.store.DNSDeployment(req.ID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("dns deployment not found"))
		return
	}
	if !s.requireNodeScope(w, p, "dns:admin", dep.NodeID) {
		return
	}
	// The same rule as creating a tls check by hand: it has no node to be
	// confined to, so a token that may only touch some nodes may not.
	if principalHasNodeRestriction(p) || !rbac.Allows(p.Principal, "monitor:admin", "") {
		writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "measuring a certificate creates server-evaluated tls checks, which takes monitor:admin on a token with no node allowlist"))
		return
	}
	if dep.Engine != model.DNSEngineExternal {
		writeError(w, http.StatusBadRequest, fieldErrorf("id", "%s is a CoreDNS deployment, which serves no DoT or DoH: only an external engine's certificate is measured", dep.Name))
		return
	}
	if err := dnsCertHostname(dep); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ports, err := dnsCertPorts(dep, req.Ports)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	s.monitorSaves.Lock()
	defer s.monitorSaves.Unlock()
	monitors := s.store.Monitors()
	var create []model.Monitor
	var link []string
	for _, port := range ports {
		target := net.JoinHostPort(dep.Hostname, strconv.Itoa(port))
		if existing, ok := authoredTLSCheckOn(monitors, target, dep.CertMonitorIDs); ok {
			link = append(link, existing)
			continue
		}
		mon, err := normalizeTLSMonitor(model.Monitor{
			Name:          fmt.Sprintf("%s certificate (%s)", dep.Name, target),
			Type:          model.MonitorTypeTLS,
			Target:        target,
			ThresholdDays: req.ThresholdDays,
		})
		if err != nil {
			// A threshold refusal names its field; the target is the
			// record's hostname on a port the request named.
			writeError(w, http.StatusBadRequest, fieldError("ports", err))
			return
		}
		mon.ID = id.New("mon")
		mon.Version = 1
		mon.Enabled = true
		mon.Alert = model.MonitorAlertDown
		create = append(create, mon)
	}
	// The record the checks were built from and authorized against must be
	// the one linked: a save in between could have moved it to another node
	// or hostname.
	updated, err := s.store.LinkDNSCertMonitors(dep.ID, dep.UpdatedAt, create, link)
	switch {
	case errors.Is(err, store.ErrDNSDeploymentNotFound):
		writeError(w, http.StatusNotFound, errors.New("dns deployment not found"))
		return
	case errors.Is(err, store.ErrDNSDeploymentNotExternal), errors.Is(err, store.ErrDNSDeploymentChanged), errors.Is(err, store.ErrDNSCertMonitorGone):
		writeError(w, http.StatusConflict, fmt.Errorf("the deployment or a check changed while measuring; measure again: %w", err))
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	created := make([]string, 0, len(create))
	for _, mon := range create {
		created = append(created, mon.ID)
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "monitor.create", Scope: "monitor:admin", Metadata: map[string]string{
			"monitor_id": mon.ID, "type": mon.Type, "alert": mon.Alert, "dns_id": dep.ID,
		}})
	}
	portList := make([]string, 0, len(ports))
	for _, port := range ports {
		portList = append(portList, strconv.Itoa(port))
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), NodeID: dep.NodeID, Action: "dns.cert.measure", Scope: "dns:admin", Metadata: map[string]string{
		"dns_id": dep.ID, "ports": strings.Join(portList, ","), "created": strings.Join(created, ","), "linked": strings.Join(link, ","),
	}})
	writeJSON(w, http.StatusOK, map[string]any{
		"deployment": s.toDNSDeploymentView(p, updated),
		"created":    created,
		"linked":     link,
	})
}

// dnsCertHostname refuses a record whose certificate cannot be held to a
// name: one with no hostname, or with an address in its place. A save
// requires a hostname, so this is a record stored some other way.
func dnsCertHostname(dep model.DNSDeployment) error {
	host := strings.TrimSpace(dep.Hostname)
	if host == "" {
		return fmt.Errorf("%s records no hostname: a certificate is checked against the name the resolver answers at, so set hostname on the record first", dep.Name)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return fmt.Errorf("%s records the address %s as its hostname: a certificate is checked against a name, so set hostname to the name the resolver answers at", dep.Name, host)
	}
	return nil
}

// dnsCertPorts checks the requested ports against the recorded tcp
// listeners and returns them once each, in the order given.
func dnsCertPorts(dep model.DNSDeployment, requested []int) ([]int, error) {
	recorded := []int{}
	for _, l := range dep.Listeners {
		if l.Protocol == "tcp" {
			recorded = append(recorded, l.Port)
		}
	}
	if len(requested) == 0 {
		return nil, fieldErrorf("ports", "name the listeners that speak DoT or DoH: the record says which ports %s listens on, not which of them speak TLS (tcp listeners recorded: %s)", dep.Name, joinPorts(recorded))
	}
	out := make([]int, 0, len(requested))
	for i, port := range requested {
		if !slices.Contains(recorded, port) {
			return nil, fieldErrorf(fieldIndex("ports", i), "tcp/%d is not a recorded listener of %s; record it first (tcp listeners recorded: %s)", port, dep.Name, joinPorts(recorded))
		}
		if !slices.Contains(out, port) {
			out = append(out, port)
		}
	}
	return out, nil
}

func joinPorts(ports []int) string {
	if len(ports) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, strconv.Itoa(port))
	}
	return strings.Join(parts, ", ")
}

// authoredTLSCheckOn finds an authored tls check on exactly target, host
// compared case-insensitively, preferring one already linked.
func authoredTLSCheckOn(monitors []model.Monitor, target string, linked []string) (string, bool) {
	found := ""
	for _, mon := range monitors {
		if mon.Type != model.MonitorTypeTLS || !store.MonitorOwnerOf(mon).Authored() || !strings.EqualFold(mon.Target, target) {
			continue
		}
		if slices.Contains(linked, mon.ID) {
			return mon.ID, true
		}
		if found == "" {
			found = mon.ID
		}
	}
	return found, found != ""
}
