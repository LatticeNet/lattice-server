package server

import (
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-server/internal/store"
)

func capServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &Server{store: st, now: func() time.Time { return time.Now().UTC() }}
}

// The default that the whole design turns on: reading a node needs no
// paperwork, changing one does. Getting this backwards in either direction is
// the difference between an unusable console and a fleet-wide SSH run against
// machines nobody meant to include.
func TestChangingANodeIsOptInWhileReadingItIsNot(t *testing.T) {
	s := capServer(t)
	if d := s.resolveNodeCapability("node-a", sshGuardPlugin); d.Allowed {
		t.Error("a mutating capability defaulted to allowed")
	}
	if d := s.resolveNodeCapability("node-a", "metrics"); !d.Allowed {
		t.Error("a read-only capability defaulted to denied")
	}
	// An undeclared capability is not gated, or every flow not yet onboarded
	// would break the moment this shipped.
	if d := s.resolveNodeCapability("node-a", "something-not-declared"); !d.Allowed {
		t.Error("an undeclared capability was gated")
	}
}

func TestEnrolmentAllowsAndExclusionRefusesWithItsReason(t *testing.T) {
	s := capServer(t)
	if err := s.store.SetNodeCapability(store.NodeCapability{
		NodeID: "node-a", Capability: sshGuardPlugin, State: store.CapabilityEnrolled,
	}); err != nil {
		t.Fatal(err)
	}
	if d := s.resolveNodeCapability("node-a", sshGuardPlugin); !d.Allowed {
		t.Fatalf("an enrolled node was refused: %s", d.Reason)
	}

	// The reason has to survive into the refusal. "Not this one" without a why
	// is the state this replaced.
	if err := s.store.SetNodeCapability(store.NodeCapability{
		NodeID: "node-b", Capability: sshGuardPlugin, State: store.CapabilityExcluded,
		Reason: "no exposed port until forwarding is configured",
	}); err != nil {
		t.Fatal(err)
	}
	d := s.resolveNodeCapability("node-b", sshGuardPlugin)
	if d.Allowed {
		t.Fatal("an excluded node was allowed")
	}
	if !strings.Contains(d.Reason, "forwarding is configured") {
		t.Errorf("the exclusion reason was lost: %q", d.Reason)
	}
}

// Not-enrolled and excluded are both refusals but call for opposite actions, so
// they must not read the same.
func TestAMissingEnrolmentAndAnExclusionDoNotSayTheSameThing(t *testing.T) {
	s := capServer(t)
	if err := s.store.SetNodeCapability(store.NodeCapability{
		NodeID: "node-b", Capability: sshGuardPlugin, State: store.CapabilityExcluded,
		Reason: "personal machine",
	}); err != nil {
		t.Fatal(err)
	}
	missing := s.resolveNodeCapability("node-a", sshGuardPlugin).Reason
	excluded := s.resolveNodeCapability("node-b", sshGuardPlugin).Reason
	if missing == excluded {
		t.Fatal("a node nobody has decided about reads the same as one deliberately excluded")
	}
	if !strings.Contains(missing, "not enrolled") || !strings.Contains(excluded, "excluded") {
		t.Errorf("refusals are not distinguishable: missing=%q excluded=%q", missing, excluded)
	}
}

// Clearing returns the node to the default rather than asserting anything.
func TestClearingARecordReturnsTheNodeToTheDefault(t *testing.T) {
	s := capServer(t)
	for _, state := range []string{store.CapabilityEnrolled, ""} {
		if err := s.store.SetNodeCapability(store.NodeCapability{
			NodeID: "node-a", Capability: sshGuardPlugin, State: state,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := s.store.NodeCapability("node-a", sshGuardPlugin); ok {
		t.Fatal("clearing left a record behind")
	}
	if d := s.resolveNodeCapability("node-a", sshGuardPlugin); d.Allowed {
		t.Error("a cleared node stayed allowed instead of returning to opt-in")
	}
}

// Only sshguard is live in this phase. If a future edit flips one of the others
// on without wiring its existing per-node record, that capability would start
// refusing every node that has no new-style enrolment - which for something
// like nft means refusing the whole fleet.
func TestOnlySSHGuardIsEnforcedInThisPhase(t *testing.T) {
	for _, known := range KnownCapabilities() {
		if known.Enforced != capabilityEnforced(known.ID) {
			t.Errorf("%s reports Enforced=%v to the console but resolves as %v",
				known.ID, known.Enforced, capabilityEnforced(known.ID))
		}
		if known.ID == sshGuardPlugin && !known.Enforced {
			t.Error("sshguard is not enforced; it is the capability this was built for")
		}
		if known.ID != sshGuardPlugin && known.Enforced {
			t.Errorf("%s became enforced without its existing per-node record being wired in", known.ID)
		}
	}
}
