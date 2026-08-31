package server

import (
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
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

// A capability may only be enforced once it can answer for a node that has no
// new-style enrolment. Without a Derive, flipping Enforced refuses the entire
// fleet on the first request, because nothing has an explicit record yet - and
// for something like nft that is every firewall in the estate.
//
// sshguard is the deliberate exception: it never had a per-node record of any
// kind, which is why its scope was decided by whoever was selecting rows, and
// there is nothing to derive from.
func TestACapabilityIsOnlyEnforcedOnceItCanAnswerForAnUnenrolledNode(t *testing.T) {
	enforced := map[string]bool{}
	for _, known := range KnownCapabilities() {
		if known.Enforced != capabilityEnforced(known.ID) {
			t.Errorf("%s reports Enforced=%v to the console but resolves as %v",
				known.ID, known.Enforced, capabilityEnforced(known.ID))
		}
		if !known.Enforced {
			continue
		}
		enforced[known.ID] = true
		if known.ID == sshGuardPlugin {
			continue
		}
		if capabilitySpecs[known.ID].Derive == nil {
			t.Errorf("%s is enforced with no Derive: it will refuse every node that has no explicit enrolment", known.ID)
		}
	}
	// The two the operator asked for by name.
	for _, id := range []string{sshGuardPlugin, capabilitySingBox} {
		if !enforced[id] {
			t.Errorf("%s is not enforced", id)
		}
	}
}

// Turning a capability on must not refuse a fleet that has been correctly
// configured for years under the old shape. sing-box is the case: the operator
// already said which nodes run it, via the discover switch, and that answer has
// to carry over or enabling the gate breaks every working node at once.
func TestSingBoxScopeComesFromTheNodesOwnConfigurationWhenNobodyHasEnrolledIt(t *testing.T) {
	s := capServer(t)
	mk := func(id string, discover bool) {
		if err := s.store.UpsertNode(model.Node{
			ID: id, Name: id,
			AgentLaunch: &model.AgentLaunchConfig{SingBoxDiscover: discover},
		}); err != nil {
			t.Fatal(err)
		}
	}
	mk("node-runs-it", true)
	mk("node-does-not", false)
	if err := s.store.UpsertNode(model.Node{ID: "node-unconfigured", Name: "node-unconfigured"}); err != nil {
		t.Fatal(err)
	}

	if d := s.resolveNodeCapability("node-runs-it", capabilitySingBox); !d.Allowed {
		t.Errorf("a node configured for sing-box was refused: %s", d.Reason)
	}
	d := s.resolveNodeCapability("node-does-not", capabilitySingBox)
	if d.Allowed {
		t.Error("sing-box management was allowed on a node that does not run sing-box")
	}
	if !strings.Contains(d.Reason, "not configured") {
		t.Errorf("refusal should point at the node's own configuration, got %q", d.Reason)
	}
	// A node with no agent launch config at all says nothing either way, so the
	// capability default decides - and sing-box management mutates, so it is
	// opt-in.
	if s.resolveNodeCapability("node-unconfigured", capabilitySingBox).Allowed {
		t.Error("a node with no configuration defaulted to allowed for a mutating capability")
	}
}

// An operator decision always beats an inferred one, in both directions.
// Otherwise "I know this box runs sing-box, let it through" would be impossible
// to express, and so would "it does, but leave it alone".
func TestAnExplicitDecisionOverridesWhatTheNodesConfigurationImplies(t *testing.T) {
	s := capServer(t)
	if err := s.store.UpsertNode(model.Node{
		ID: "node-a", Name: "node-a",
		AgentLaunch: &model.AgentLaunchConfig{SingBoxDiscover: false},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetNodeCapability(store.NodeCapability{
		NodeID: "node-a", Capability: capabilitySingBox, State: store.CapabilityEnrolled,
	}); err != nil {
		t.Fatal(err)
	}
	if !s.resolveNodeCapability("node-a", capabilitySingBox).Allowed {
		t.Error("an explicit enrolment lost to the derived answer")
	}

	if err := s.store.UpsertNode(model.Node{
		ID: "node-b", Name: "node-b",
		AgentLaunch: &model.AgentLaunchConfig{SingBoxDiscover: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetNodeCapability(store.NodeCapability{
		NodeID: "node-b", Capability: capabilitySingBox, State: store.CapabilityExcluded,
		Reason: "customer box, hands off",
	}); err != nil {
		t.Fatal(err)
	}
	d := s.resolveNodeCapability("node-b", capabilitySingBox)
	if d.Allowed {
		t.Error("an explicit exclusion lost to the derived answer")
	}
	if !strings.Contains(d.Reason, "hands off") {
		t.Errorf("the exclusion reason was lost: %q", d.Reason)
	}
}

// Handlers are where a check gets forgotten. queueTask is the one path every
// directly-queued task takes, so the guarantee lives there and a new caller
// that never heard of capabilities still cannot dispatch out of scope.
func TestQueueTaskRefusesAnOutOfScopeTargetEvenWithNoHandlerCheck(t *testing.T) {
	s := capServer(t)
	if err := s.store.UpsertNode(model.Node{
		ID: "node-a", Name: "node-a",
		AgentLaunch: &model.AgentLaunchConfig{SingBoxDiscover: false},
	}); err != nil {
		t.Fatal(err)
	}
	task := model.Task{
		ID: "task_x", Targets: []string{"node-a"}, Interpreter: "sh", Script: "true",
		Status: model.TaskQueued, CreatedAt: time.Now().UTC(),
	}
	if err := s.queueTaskFor(capabilitySingBox, task); err == nil {
		t.Fatal("queueTask accepted a task for a node out of scope for its capability")
	}
	// The same task with no capability named keeps working, so a path that has
	// not been migrated does not silently lose its ability to queue.
	if err := s.queueTask(task); err != nil {
		t.Fatalf("an unscoped task was refused: %v", err)
	}
}

// A task inherits its capability from its approval, so approval-backed work is
// gated without any caller cooperation at all.
func TestQueueTaskTakesItsCapabilityFromTheApproval(t *testing.T) {
	s := capServer(t)
	if err := s.store.UpsertNode(model.Node{ID: "node-a", Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	approval := model.Approval{
		ID: "approval_x", NodeID: "node-a", Plugin: sshGuardPlugin,
		Action: "arm", Status: model.ApprovalPending, CreatedAt: time.Now().UTC(),
	}
	if err := s.store.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	task := model.Task{
		ID: "task_y", ApprovalID: approval.ID, Targets: []string{"node-a"},
		Interpreter: "sh", Script: "true", Status: model.TaskQueued, CreatedAt: time.Now().UTC(),
	}
	if err := s.queueTask(task); err == nil {
		t.Fatal("an approval-backed task was queued for a node not enrolled in the approval's capability")
	}
	if err := s.store.SetNodeCapability(store.NodeCapability{
		NodeID: "node-a", Capability: sshGuardPlugin, State: store.CapabilityEnrolled,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.queueTask(task); err != nil {
		t.Fatalf("an enrolled node was refused: %v", err)
	}
}
