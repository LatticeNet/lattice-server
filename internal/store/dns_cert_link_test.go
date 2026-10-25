package store

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func tlsCheck(id, target string) model.Monitor {
	return model.Monitor{ID: id, Name: id, Type: model.MonitorTypeTLS, Target: target, Enabled: true, Version: 1}
}

// Measuring an external engine's certificate creates its checks and links
// them in one write; a save of the deployment, which reads, edits and writes
// the whole record, keeps the link whatever it carries.
func TestLinkDNSCertMonitorsCreatesAndLinksInOneWrite(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	external := model.DNSDeployment{ID: "d1", Name: "dnsproxy", NodeID: "n1", Engine: model.DNSEngineExternal, Hostname: "dns.example.com"}
	if err := s.UpsertDNSDeployment(external); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertMonitor(tlsCheck("mon_old", "dns.example.com:853")); err != nil {
		t.Fatal(err)
	}

	read, _ := s.DNSDeployment("d1")
	got, err := s.LinkDNSCertMonitors("d1", read.UpdatedAt, []model.Monitor{tlsCheck("mon_new", "dns.example.com:8443")}, []string{"mon_old"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"mon_old", "mon_new"}; !slices.Equal(got.CertMonitorIDs, want) {
		t.Fatalf("linked %v, want %v", got.CertMonitorIDs, want)
	}
	if mon, ok := s.Monitor("mon_new"); !ok || mon.CreatedAt.IsZero() || mon.Target != "dns.example.com:8443" {
		t.Fatalf("the new check is stored: %+v %v", mon, ok)
	}

	// An operator save that carries a stale list, or none, keeps the link.
	edit := external
	edit.Name = "renamed"
	edit.CertMonitorIDs = []string{"mon_forged"}
	if err := s.UpsertDNSDeployment(edit); err != nil {
		t.Fatal(err)
	}
	if stored, _ := s.DNSDeployment("d1"); stored.Name != "renamed" || !slices.Equal(stored.CertMonitorIDs, []string{"mon_old", "mon_new"}) {
		t.Fatalf("a save rewrote the link: %+v", stored)
	}
	// A new record starts unlinked whatever it carries.
	fresh := model.DNSDeployment{ID: "d2", Name: "other", NodeID: "n1", Engine: model.DNSEngineExternal, CertMonitorIDs: []string{"mon_old"}}
	if err := s.UpsertDNSDeployment(fresh); err != nil {
		t.Fatal(err)
	}
	if stored, _ := s.DNSDeployment("d2"); stored.CertMonitorIDs != nil {
		t.Fatalf("a new record linked checks by saving: %+v", stored.CertMonitorIDs)
	}

	// Linking again is idempotent, and a deleted check drops out of the link.
	if err := s.DeleteMonitor("mon_old"); err != nil {
		t.Fatal(err)
	}
	read, _ = s.DNSDeployment("d1")
	got, err = s.LinkDNSCertMonitors("d1", read.UpdatedAt, nil, []string{"mon_new"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.CertMonitorIDs, []string{"mon_new"}) {
		t.Fatalf("relink: %v", got.CertMonitorIDs)
	}
}

// Nothing is written when the deployment is gone, is not an external
// engine, was saved since the caller read it, or a check to link was deleted
// in between.
func TestLinkDNSCertMonitorsWritesNothingOnRefusal(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertDNSDeployment(model.DNSDeployment{ID: "core", Name: "core", NodeID: "n1", Engine: model.DNSEngineCoreDNS}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertDNSDeployment(model.DNSDeployment{ID: "ext", Name: "ext", NodeID: "n1", Engine: model.DNSEngineExternal}); err != nil {
		t.Fatal(err)
	}
	create := []model.Monitor{tlsCheck("mon_x", "dns.example.com:853")}
	ext, _ := s.DNSDeployment("ext")
	core, _ := s.DNSDeployment("core")
	for _, tc := range []struct {
		dep    string
		readAt time.Time
		link   []string
		want   error
	}{
		{"gone", ext.UpdatedAt, nil, ErrDNSDeploymentNotFound},
		{"core", core.UpdatedAt, nil, ErrDNSDeploymentNotExternal},
		{"ext", ext.UpdatedAt, []string{"mon_missing"}, ErrDNSCertMonitorGone},
		{"ext", ext.UpdatedAt.Add(-time.Second), nil, ErrDNSDeploymentChanged},
	} {
		if _, err := s.LinkDNSCertMonitors(tc.dep, tc.readAt, create, tc.link); !errors.Is(err, tc.want) {
			t.Fatalf("%s: got %v, want %v", tc.dep, err, tc.want)
		}
		if _, ok := s.Monitor("mon_x"); ok {
			t.Fatalf("%s: a refused link created its check", tc.dep)
		}
	}
	if stored, _ := s.DNSDeployment("ext"); len(stored.CertMonitorIDs) != 0 {
		t.Fatalf("a refused link wrote the deployment: %+v", stored.CertMonitorIDs)
	}
}
