package server

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// The dns check method of design 32 S5a: a resolver endpoint as the target,
// a question and an expected answer. The rules shared with the agents
// (endpoint forms, names, types, canonical values) live in lattice-sdk
// model/monitor_dns.go; this file applies them to saves and adds the
// destination rule of monitor_checks.go.

// errDNSFieldsKinds is the answer to a dns field on a check of another kind.
var errDNSFieldsKinds = errors.New("dns_name, dns_type, dns_expect and dns_expect_rcode apply to dns checks only")

// monitorDNSFieldSet is the path of the first dns field mon sets, empty
// when it sets none.
func monitorDNSFieldSet(name, typ string, expect []string, rcode string) string {
	switch {
	case name != "":
		return "dns_name"
	case typ != "":
		return "dns_type"
	case len(expect) > 0:
		return "dns_expect"
	case rcode != "":
		return "dns_expect_rcode"
	}
	return ""
}

// refuseDNSFields refuses a dns field on a check of another kind.
func refuseDNSFields(mon model.Monitor) error {
	if path := monitorDNSFieldSet(mon.DNSName, mon.DNSType, mon.DNSExpect, mon.DNSExpectRcode); path != "" {
		return fieldError(path, errDNSFieldsKinds)
	}
	return nil
}

// normalizeDNSTarget is a resolver endpoint in canonical form
// (model.DNSResolver.String). checkHost applies the destination rules to
// its host, as normalizeHTTPMonitor does: a create does, an edit does not,
// since the target cannot change (the agent judges the resolved address at
// dial time either way).
func normalizeDNSTarget(raw string, checkHost bool) (string, error) {
	r, err := model.ParseDNSResolver(raw)
	if err != nil {
		return "", err
	}
	if checkHost {
		if err := checkMonitorHost(r.Host); err != nil {
			return "", err
		}
	}
	return r.String(), nil
}

// normalizeDNSQuestion checks a dns check's question and judgement and
// stores them in canonical form: the name without the trailing dot, the
// type in upper case (A when empty), the expected values deduplicated in
// the form an agent compares them in, and the expected code empty for
// NOERROR. A name that must not resolve takes no expected values.
func normalizeDNSQuestion(mon *model.Monitor) error {
	name, err := model.NormalizeDNSName(mon.DNSName)
	if err != nil {
		return fieldError("dns_name", err)
	}
	typ, err := model.NormalizeDNSType(mon.DNSType)
	if err != nil {
		return fieldError("dns_type", err)
	}
	rcode, err := model.NormalizeDNSExpectRcode(mon.DNSExpectRcode)
	if err != nil {
		return fieldError("dns_expect_rcode", err)
	}
	if len(mon.DNSExpect) > model.MonitorDNSExpectMax {
		return fieldErrorf("dns_expect", "dns_expect holds %d values, at most %d", len(mon.DNSExpect), model.MonitorDNSExpectMax)
	}
	var expect []string
	for i, raw := range mon.DNSExpect {
		v, err := model.CanonicalDNSValue(typ, raw)
		if err != nil {
			return fieldError(fieldIndex("dns_expect", i), err)
		}
		if !slices.Contains(expect, v) {
			expect = append(expect, v)
		}
	}
	if rcode == model.DNSRcodeNXDomain && len(expect) > 0 {
		return fieldErrorf("dns_expect", "a name expected not to resolve (NXDOMAIN) has no expected values")
	}
	mon.DNSName, mon.DNSType, mon.DNSExpect, mon.DNSExpectRcode = name, typ, expect, rcode
	return nil
}

// normalizeDNSMonitor checks a dns check: a resolver endpoint target (a
// node target waits for the dnsproxy engine), no packets, status set or
// headers, and its question.
func normalizeDNSMonitor(mon *model.Monitor, checkHost bool) error {
	if mon.TargetNode != "" {
		return fieldErrorf("target_node", "a dns check's target is a resolver endpoint (https://host/path, tls://host, udp://host or tcp://host); target_node applies to %s checks", monitorKindList(monitorNodeTargetKinds))
	}
	if mon.Packets != 0 {
		return fieldError("packets", errMonitorPacketsKinds)
	}
	if mon.ExpectStatus != "" {
		return fieldErrorf("expect_status", "expect_status and headers apply to http checks only")
	}
	if len(mon.Headers) > 0 {
		return fieldErrorf("headers", "expect_status and headers apply to http checks only")
	}
	target, err := normalizeDNSTarget(mon.Target, checkHost)
	if err != nil {
		return fieldError("target", err)
	}
	mon.Target = target
	return normalizeDNSQuestion(mon)
}

// applyDNSUpdate applies an edit's dns fields to next, the edited copy of
// mon, and notes each one that changed. Empty dns fields echoed by an
// editor on a check of another kind change nothing; set ones are refused
// there. The question is checked whole after the edit.
func applyDNSUpdate(mon model.Monitor, next *model.Monitor, req model.MonitorUpdate, note func(string, bool)) error {
	if mon.Type != model.MonitorTypeDNS {
		var expect []string
		if req.DNSExpect != nil {
			expect = *req.DNSExpect
		}
		deref := func(v *string) string {
			if v == nil {
				return ""
			}
			return strings.TrimSpace(*v)
		}
		if path := monitorDNSFieldSet(deref(req.DNSName), deref(req.DNSType), expect, deref(req.DNSExpectRcode)); path != "" {
			return fieldError(path, errDNSFieldsKinds)
		}
		return nil
	}
	if req.DNSName == nil && req.DNSType == nil && req.DNSExpect == nil && req.DNSExpectRcode == nil {
		return nil
	}
	if req.DNSName != nil {
		next.DNSName = *req.DNSName
	}
	if req.DNSType != nil {
		next.DNSType = *req.DNSType
	}
	if req.DNSExpect != nil {
		next.DNSExpect = slices.Clone(*req.DNSExpect)
	}
	if req.DNSExpectRcode != nil {
		next.DNSExpectRcode = *req.DNSExpectRcode
	}
	if err := normalizeDNSQuestion(next); err != nil {
		return err
	}
	note("dns_name", next.DNSName != mon.DNSName)
	note("dns_type", next.DNSType != mon.DNSType)
	note("dns_expect", !slices.Equal(next.DNSExpect, mon.DNSExpect))
	note("dns_expect_rcode", next.DNSExpectRcode != mon.DNSExpectRcode)
	return nil
}

// dnsCertNotAfter is the certificate expiry a DoH or DoT check reads now:
// the soonest of each running source's newest reading, so a resolver whose
// certificate one vantage point still sees unrenewed reads as expiring.
func (s *Server) dnsCertNotAfter(mon model.Monitor) (time.Time, bool) {
	var sources []string
	if mon.AssignAll {
		for _, n := range s.store.Nodes() {
			sources = append(sources, n.ID)
		}
	} else {
		sources = mon.NodeIDs
	}
	var soonest time.Time
	for _, nodeID := range sources {
		if !monitorPairAssigned(mon, nodeID) {
			continue
		}
		rec, ok, err := s.store.NewestMonitorResult(mon.ID, nodeID, func(r store.MonitorResultRecord) bool {
			return !r.CertNotAfter.IsZero()
		})
		if err != nil || !ok {
			continue
		}
		if soonest.IsZero() || rec.CertNotAfter.Before(soonest) {
			soonest = rec.CertNotAfter
		}
	}
	return soonest, !soonest.IsZero()
}

// monitorCreateKinds is the answer to a kind a create does not know.
var monitorCreateKinds = fmt.Sprintf("only %s monitors are supported", monitorKindList([]string{
	model.MonitorTypeTCP, model.MonitorTypeHTTP, model.MonitorTypeICMP, model.MonitorTypeBeacon, model.MonitorTypeDNS, model.MonitorTypeTLS,
}))
