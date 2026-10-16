package store

import (
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// A publish outcome sets only the publish-status fields, on the deployment as
// stored now. A failed publish keeps the addresses last published, an outcome
// for a deployment that was deleted, moved to another hostname or switched to
// the external engine meanwhile is dropped.
func TestRecordDNSPublishWritesOnlyTheStatusFields(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	base := model.DNSDeployment{
		ID: "d1", Name: "edited", NodeID: "n1", Engine: model.DNSEngineCoreDNS, RecordTTL: 300,
		Hostname: "dns.example.com", PublishIPv4: true, LastIPv4: "198.51.100.1",
		Status: model.DNSStatusRunning, LastError: "apply status",
	}
	if err := s.UpsertDNSDeployment(base); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 16, 1, 0, 0, 0, time.UTC)

	if err := s.RecordDNSPublish("d1", DNSPublishOutcome{At: t0, Hostname: "dns.example.com", IPv4: "203.0.113.9", Err: "A dns.example.com: refused"}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.DNSDeployment("d1")
	if got.LastPublishError != "A dns.example.com: refused" || !got.LastPublishedAt.Equal(t0) || got.LastIPv4 != "198.51.100.1" {
		t.Fatalf("failed publish: %+v", got)
	}
	if got.Name != "edited" || got.RecordTTL != 300 || got.Status != model.DNSStatusRunning || got.LastError != "apply status" {
		t.Fatalf("a publish outcome changed fields it does not own: %+v", got)
	}

	t1 := t0.Add(time.Minute)
	if err := s.RecordDNSPublish("d1", DNSPublishOutcome{At: t1, Hostname: "dns.example.com", IPv4: "203.0.113.9", IPv6: "2001:db8::9"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.DNSDeployment("d1"); got.LastPublishError != "" || !got.LastPublishedAt.Equal(t1) || got.LastIPv4 != "203.0.113.9" || got.LastIPv6 != "2001:db8::9" {
		t.Fatalf("successful publish: %+v", got)
	}

	moved := base
	moved.ID, moved.Hostname = "d2", "new.example.com"
	external := base
	external.ID, external.Engine = "d3", model.DNSEngineExternal
	for _, dep := range []model.DNSDeployment{moved, external} {
		if err := s.UpsertDNSDeployment(dep); err != nil {
			t.Fatal(err)
		}
		if err := s.RecordDNSPublish(dep.ID, DNSPublishOutcome{At: t1, Hostname: "dns.example.com", IPv4: "203.0.113.9"}); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.DNSDeployment(dep.ID); !got.LastPublishedAt.IsZero() || got.LastIPv4 != "198.51.100.1" {
			t.Fatalf("%s: an outcome for another hostname or engine landed: %+v", dep.ID, got)
		}
	}

	if err := s.RecordDNSPublish("gone", DNSPublishOutcome{At: t1, Hostname: "dns.example.com", IPv4: "203.0.113.9"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.DNSDeployment("gone"); ok {
		t.Fatal("a publish outcome created a deployment")
	}
}
