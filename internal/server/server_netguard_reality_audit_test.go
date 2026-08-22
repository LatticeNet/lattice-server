package server

import (
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func reality(listeners ...string) model.GuardNodeReality {
	out := model.GuardNodeReality{NodeID: "node-a", CollectedAt: time.Unix(1_700_000_000, 0).UTC()}
	for _, address := range listeners {
		out.Listeners = append(out.Listeners, model.GuardListener{Protocol: "tcp", Address: address, Port: 22})
	}
	return out
}

// An unattended poll is not a security event. Auditing every accepted reality
// report put roughly 250k rows a day into a log that is held in memory for the
// life of the process; the reported firewall changing is the thing worth a row.
func TestGuardRealityAuditSkipsUnchangedReports(t *testing.T) {
	s := &Server{}
	at := time.Unix(1_700_000_000, 0).UTC()

	if !s.shouldAuditGuardReality("node-a", reality(":22"), at) {
		t.Fatal("the first report from a node must be audited")
	}
	for i := 1; i <= 20; i++ {
		later := reality(":22")
		// Each poll carries a fresh collected_at, which is exactly the field
		// that must not make an unchanged report look like a new event.
		later.CollectedAt = at.Add(time.Duration(i) * time.Minute)
		if s.shouldAuditGuardReality("node-a", later, at.Add(time.Duration(i)*time.Minute)) {
			t.Fatalf("poll %d reported the same reality and must not be audited", i)
		}
	}
}

func TestGuardRealityAuditRecordsChangeAndPeriodicProof(t *testing.T) {
	s := &Server{}
	at := time.Unix(1_700_000_000, 0).UTC()
	s.shouldAuditGuardReality("node-a", reality(":22"), at)

	if !s.shouldAuditGuardReality("node-a", reality(":22", ":8088"), at.Add(time.Minute)) {
		t.Fatal("a changed listener set is the security event and must be audited")
	}
	if s.shouldAuditGuardReality("node-a", reality(":22", ":8088"), at.Add(2*time.Minute)) {
		t.Fatal("the same changed reality must not be audited twice in a row")
	}
	// The interval runs from the last audited report, which was the change at
	// at+1m, not from the node's first ever report.
	if !s.shouldAuditGuardReality("node-a", reality(":22", ":8088"), at.Add(time.Minute+guardRealityAuditInterval)) {
		t.Fatal("the trail must still show the node reporting once per interval")
	}
}

func TestGuardRealityAuditIsPerNodeAndClearedOnDelete(t *testing.T) {
	s := &Server{}
	at := time.Unix(1_700_000_000, 0).UTC()
	s.shouldAuditGuardReality("node-a", reality(":22"), at)

	if !s.shouldAuditGuardReality("node-b", reality(":22"), at) {
		t.Fatal("another node's first report must be audited on its own terms")
	}
	if s.shouldAuditGuardReality("node-a", reality(":22"), at.Add(time.Minute)) {
		t.Fatal("node-b's report must not reset node-a's gate")
	}

	s.removeGuardRealityAudit("node-a")
	if !s.shouldAuditGuardReality("node-a", reality(":22"), at.Add(2*time.Minute)) {
		t.Fatal("a re-enrolled node must record its reality again, not inherit a stale fingerprint")
	}
	if s.shouldAuditGuardReality("node-b", reality(":22"), at.Add(2*time.Minute)) {
		t.Fatal("deleting node-a must not clear node-b's gate")
	}
}
