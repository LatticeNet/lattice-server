package server

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// An external DNS engine is a resolver the operator runs and Lattice only
// observes (the first is dnsproxy on the malibu host, which the operator uses
// from everywhere and must not be disturbed). The record names the node, the
// hostname, the listener set the engine owns and the certificate expiry the
// operator typed in. Nothing is ever rendered, applied or published for it:
// plan and publish refuse with errDNSExternalObservedOnly, the node-IP publish
// path skips it, and the only server behaviour it triggers is a read-time
// comparison of the recorded listener set with the node's guard reality,
// which produces findings and never an action.

var errDNSExternalObservedOnly = errors.New(`dns engine "external" is observed only: Lattice never renders, applies or publishes anything for it`)

const (
	dnsDriftOK      = "ok"
	dnsDriftDrift   = "drift"
	dnsDriftUnknown = "unknown"
)

// dnsDriftView is the read-time verdict on an external engine's listener set.
// Findings are sentences for the console; the server never acts on them.
type dnsDriftView struct {
	Status             string     `json:"status"`
	Findings           []string   `json:"findings"`
	RealityCollectedAt *time.Time `json:"reality_collected_at,omitempty"`
}

func (s *Server) normalizeExternalDNSDeployment(req, existing model.DNSDeployment, hadExisting bool) (model.DNSDeployment, error) {
	if req.ID == "" {
		req.ID = id.New("dns")
	}
	if req.Hostname == "" {
		return model.DNSDeployment{}, errors.New("external dns engine requires the hostname it answers at")
	}
	host, err := normalizeDNSName(req.Hostname, false, false)
	if err != nil {
		return model.DNSDeployment{}, fmt.Errorf("invalid hostname: %w", err)
	}
	if !strings.Contains(host, ".") {
		return model.DNSDeployment{}, errors.New("hostname must be a fully qualified domain")
	}
	req.Hostname = host
	// The record is an observation of a service Lattice does not own, so it
	// must not carry the means to change that service's DNS record either.
	if strings.TrimSpace(req.CFAPIToken) != "" || strings.TrimSpace(req.DDNSProfileID) != "" {
		return model.DNSDeployment{}, errors.New("external dns engine does not publish records; drop cf_api_token and ddns_profile_id")
	}
	listeners, err := normalizeDNSListeners(req.Listeners)
	if err != nil {
		return model.DNSDeployment{}, err
	}
	req.Listeners = s.recordDNSListenerOwners(req.NodeID, listeners, existing.Listeners)
	req.EnableTCP, req.EnableUDP = false, false
	for _, l := range req.Listeners {
		switch l.Protocol {
		case "tcp":
			req.EnableTCP = true
		case "udp":
			req.EnableUDP = true
		}
	}
	if req.ListenPort == 0 {
		req.ListenPort = req.Listeners[0].Port
	}
	if req.ListenPort < 1 || req.ListenPort > 65535 {
		return model.DNSDeployment{}, errors.New("listen_port must be between 1 and 65535")
	}
	req.Exposure = strings.TrimSpace(strings.ToLower(req.Exposure))
	if req.Exposure == "" {
		req.Exposure = model.DNSExposurePublic
	}
	if req.Exposure != model.DNSExposureMesh && req.Exposure != model.DNSExposurePublic {
		return model.DNSDeployment{}, fmt.Errorf("unsupported dns exposure %q", req.Exposure)
	}
	// Zones are optional documentation of what the engine serves.
	if len(req.Zones) > 0 {
		zones, err := normalizeDNSZones(req.Zones)
		if err != nil {
			return model.DNSDeployment{}, err
		}
		req.Zones = zones
	} else {
		req.Zones = nil
	}
	if !req.CertNotAfter.IsZero() {
		req.CertNotAfter = req.CertNotAfter.UTC()
	}
	req.PublishIPv4, req.PublishIPv6 = false, false
	req.RecordTTL = 0
	req.CFAPIToken, req.DDNSProfileID = "", ""
	req.EngineVersion, req.LastIPv4, req.LastIPv6 = "", "", ""
	req.LastAppliedAt, req.LastPublishedAt = time.Time{}, time.Time{}
	req.LastError, req.LastPublishError = "", ""
	if hadExisting {
		req.CreatedAt = existing.CreatedAt
	}
	if req.Disabled {
		req.Status = model.DNSStatusDisabled
	} else {
		req.Status = model.DNSStatusObserved
	}
	return req, nil
}

// normalizeDNSListeners validates and canonicalises the operator's listener
// claim: lowercase protocol, port range, no duplicates, sorted by port then
// protocol. Process is not the operator's to set; it is dropped here and
// recorded from reality by recordDNSListenerOwners.
func normalizeDNSListeners(input []model.DNSListener) ([]model.DNSListener, error) {
	if len(input) == 0 {
		return nil, errors.New("external dns engine requires at least one listener (protocol and port)")
	}
	seen := map[string]bool{}
	out := make([]model.DNSListener, 0, len(input))
	for i, l := range input {
		proto := strings.TrimSpace(strings.ToLower(l.Protocol))
		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("listener %d: protocol must be tcp or udp", i+1)
		}
		if l.Port < 1 || l.Port > 65535 {
			return nil, fmt.Errorf("listener %d: port must be between 1 and 65535", i+1)
		}
		key := fmt.Sprintf("%s/%d", proto, l.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, model.DNSListener{Protocol: proto, Port: l.Port})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Protocol < out[j].Protocol
	})
	return out, nil
}

// recordDNSListenerOwners stamps each claimed listener with the process the
// node's guard reality reports on that socket. A node that has never
// reported keeps whatever a previous write recorded; a node whose report
// lacks the socket records an empty owner, which the drift check will name.
func (s *Server) recordDNSListenerOwners(nodeID string, listeners, previous []model.DNSListener) []model.DNSListener {
	snapshot, ok := s.store.GuardRealitySnapshot(nodeID)
	prior := map[string]string{}
	for _, l := range previous {
		prior[fmt.Sprintf("%s/%d", l.Protocol, l.Port)] = l.Process
	}
	out := make([]model.DNSListener, 0, len(listeners))
	for _, l := range listeners {
		key := fmt.Sprintf("%s/%d", l.Protocol, l.Port)
		if !ok {
			l.Process = prior[key]
		} else {
			l.Process = guardListenerOwner(snapshot.Reality.Listeners, l.Protocol, l.Port)
		}
		out = append(out, l)
	}
	return out
}

// guardListenerOwner returns the process name reality reports on
// protocol/port, or "" when nothing listens there. A socket bound on several
// addresses (:: and 0.0.0.0) appears more than once; the first named owner wins.
func guardListenerOwner(listeners []model.GuardListener, protocol string, port int) string {
	for _, gl := range listeners {
		if strings.EqualFold(gl.Protocol, protocol) && gl.Port == port && gl.Process != "" {
			return gl.Process
		}
	}
	return ""
}

func guardHasListener(listeners []model.GuardListener, protocol string, port int) bool {
	for _, gl := range listeners {
		if strings.EqualFold(gl.Protocol, protocol) && gl.Port == port {
			return true
		}
	}
	return false
}

// dnsExternalDrift compares the recorded listener set with the node's latest
// guard reality. It is computed on every read and produces findings only.
func (s *Server) dnsExternalDrift(dep model.DNSDeployment, now time.Time) *dnsDriftView {
	nodeName := dep.NodeID
	if n, ok := s.store.Node(dep.NodeID); ok && n.Name != "" {
		nodeName = n.Name
	}
	snapshot, ok := s.store.GuardRealitySnapshot(dep.NodeID)
	if !ok {
		return &dnsDriftView{
			Status:   dnsDriftUnknown,
			Findings: []string{fmt.Sprintf("%s has never reported its listeners, so the recorded listener set cannot be checked", nodeName)},
		}
	}
	collected := snapshot.Reality.CollectedAt.UTC()
	view := &dnsDriftView{Status: dnsDriftOK, Findings: []string{}, RealityCollectedAt: &collected}
	freshness, _ := guardRealityFreshness(snapshot, now)
	stamp := collected.Format(time.RFC3339)
	for _, l := range dep.Listeners {
		if !guardHasListener(snapshot.Reality.Listeners, l.Protocol, l.Port) {
			view.Findings = append(view.Findings, fmt.Sprintf("%s/%d is not listening on %s (reality collected %s)", l.Protocol, l.Port, nodeName, stamp))
			continue
		}
		owner := guardListenerOwner(snapshot.Reality.Listeners, l.Protocol, l.Port)
		if l.Process != "" && owner != "" && owner != l.Process {
			view.Findings = append(view.Findings, fmt.Sprintf("%s/%d on %s is owned by %s, recorded as %s", l.Protocol, l.Port, nodeName, owner, l.Process))
		}
	}
	if len(view.Findings) > 0 {
		view.Status = dnsDriftDrift
	}
	if freshness == "stale" {
		view.Findings = append(view.Findings, fmt.Sprintf("%s's reality is stale (collected %s); the comparison above may be out of date", nodeName, stamp))
		if view.Status == dnsDriftOK {
			view.Status = dnsDriftUnknown
		}
	}
	return view
}
