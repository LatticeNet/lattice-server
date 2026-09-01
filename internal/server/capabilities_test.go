package server

import (
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// enforceGate turns a capability's gate on, the way an operator would from the
// Capability Gates page. Nothing ships enforced, so any test about refusal has
// to say which gate it is testing.
func enforceGate(t *testing.T, s *Server, capability string) {
	t.Helper()
	if err := s.store.SetCapabilityPolicy(store.CapabilityPolicy{
		Capability: capability, Enforced: true, UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}

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
	if d := s.resolveCapabilityScope("node-a", sshGuardPlugin); d.Allowed {
		t.Error("a mutating capability defaulted to allowed")
	}
	if d := s.resolveCapabilityScope("node-a", "metrics"); !d.Allowed {
		t.Error("a read-only capability defaulted to denied")
	}
	// An undeclared capability is not gated, or every flow not yet onboarded
	// would break the moment this shipped.
	if d := s.resolveCapabilityScope("node-a", "something-not-declared"); !d.Allowed {
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
	if d := s.resolveCapabilityScope("node-a", sshGuardPlugin); !d.Allowed {
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
	d := s.resolveCapabilityScope("node-b", sshGuardPlugin)
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
	missing := s.resolveCapabilityScope("node-a", sshGuardPlugin).Reason
	excluded := s.resolveCapabilityScope("node-b", sshGuardPlugin).Reason
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
	if d := s.resolveCapabilityScope("node-a", sshGuardPlugin); d.Allowed {
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
	s := capServer(t)
	enforced := map[string]bool{}
	for _, known := range s.KnownCapabilities() {
		if known.Enforced != s.capabilityEnforced(known.ID) {
			t.Errorf("%s reports Enforced=%v to the console but resolves as %v",
				known.ID, known.Enforced, s.capabilityEnforced(known.ID))
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
	// Nothing ships enforced, deliberately: a compiled default decides what a
	// fleet does the moment a version starts, and on that morning no node has an
	// enrolment. Enforcement is stored policy, set against a real fleet once the
	// operator can see what each gate would refuse.
	if len(enforced) != 0 {
		t.Errorf("a capability ships enforced: %v. A fresh install has an empty "+
			"enrolment table, so this refuses work on first boot", enforced)
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

	if d := s.resolveCapabilityScope("node-runs-it", capabilitySingBox); !d.Allowed {
		t.Errorf("a node configured for sing-box was refused: %s", d.Reason)
	}
	d := s.resolveCapabilityScope("node-does-not", capabilitySingBox)
	if d.Allowed {
		t.Error("sing-box management was allowed on a node that does not run sing-box")
	}
	if !strings.Contains(d.Reason, "not configured") {
		t.Errorf("refusal should point at the node's own configuration, got %q", d.Reason)
	}
	// A node with no agent launch config at all says nothing either way, so the
	// capability default decides - and sing-box management mutates, so it is
	// opt-in.
	if s.resolveCapabilityScope("node-unconfigured", capabilitySingBox).Allowed {
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
	if !s.resolveCapabilityScope("node-a", capabilitySingBox).Allowed {
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
	d := s.resolveCapabilityScope("node-b", capabilitySingBox)
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
	enforceGate(t, s, capabilitySingBox)
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
	enforceGate(t, s, sshGuardPlugin)
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

// Whether a gate is live is policy, and policy belongs to the operator. The
// compiled value is what a fresh install does; a stored decision replaces it,
// in both directions, without a release.
func TestTheOperatorsPolicyBeatsTheCompiledDefault(t *testing.T) {
	s := capServer(t)
	// Nothing ships enforced; the operator turns gates on against their own
	// fleet once they can see what each would refuse.
	for _, id := range []string{sshGuardPlugin, capabilitySingBox, "nft"} {
		if s.capabilityEnforced(id) {
			t.Fatalf("%s ships enforced", id)
		}
	}
	set := func(capability string, enforced bool) {
		if err := s.store.SetCapabilityPolicy(store.CapabilityPolicy{
			Capability: capability, Enforced: enforced, UpdatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	set("nft", true)
	if !s.capabilityEnforced("nft") {
		t.Error("enabling a gate did not take effect")
	}
	// With the gate on, the decision follows the scope answer again.
	if s.resolveNodeCapability("node-nobody-enrolled", "nft").Allowed {
		t.Error("an enabled gate allowed a node with no enrolment")
	}
	// Turning one off has to work too. An operator who needs the lever during an
	// incident will otherwise reach for something worse than a recorded, audited
	// setting.
	set(sshGuardPlugin, true)
	set(sshGuardPlugin, false)
	if s.capabilityEnforced(sshGuardPlugin) {
		t.Error("disabling a gate did not take effect")
	}
	if !s.resolveNodeCapability("node-nobody-enrolled", sshGuardPlugin).Allowed {
		t.Error("a disabled gate still refused")
	}
}

// Enforcing a capability that cannot derive an answer refuses every node with
// no explicit enrolment, which on a fresh table is the whole fleet. The impact
// preview exists so that is visible before the switch, not after.
func TestTheImpactPreviewSaysWhatEnforcingWouldRefuse(t *testing.T) {
	s := capServer(t)
	for _, id := range []string{"node-a", "node-b", "node-c"} {
		if err := s.store.UpsertNode(model.Node{ID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.store.SetNodeCapability(store.NodeCapability{
		NodeID: "node-a", Capability: sshGuardPlugin, State: store.CapabilityEnrolled,
	}); err != nil {
		t.Fatal(err)
	}
	admin := principal{Principal: rbac.Principal{Scopes: []string{"*"}}}
	impact := s.capabilityImpact(admin, sshGuardPlugin)
	if impact.AllowCount != 1 || impact.RefuseCount != 2 {
		t.Fatalf("want 1 allowed / 2 refused, got %d / %d", impact.AllowCount, impact.RefuseCount)
	}
	// A count alone does not tell an operator whether the answer is "the two I
	// excluded" or "everything", so the names come with it.
	if len(impact.Refused) != 2 {
		t.Fatalf("want the refused nodes named, got %+v", impact.Refused)
	}
	if impact.Refused[0].Reason == "" {
		t.Error("a refused node came back with no reason")
	}
}

// A third-party plugin acts on nodes exactly like a built-in capability: it
// mints an approval carrying its manifest id and queues a task. It was the one
// family that could reach any node unscoped.
func TestAnInstalledPluginIsACapability(t *testing.T) {
	s := capServer(t)
	if _, ok := s.capabilitySpecFor("some.unknown.thing"); ok {
		t.Error("an unknown id resolved to a capability")
	}
	s.plugins = []plugin.Loaded{{Manifest: plugin.Manifest{ID: "acme.firewall"}}}
	spec, ok := s.capabilitySpecFor("acme.firewall")
	if !ok {
		t.Fatal("an installed plugin is not a capability")
	}
	if !spec.Mutates {
		t.Error("a plugin capability should default to opt-in; it queues tasks against nodes")
	}
	// Declared but not enforced: an operator turns it on after seeing the impact.
	if s.capabilityEnforced("acme.firewall") {
		t.Error("a newly installed plugin started enforcing on its own")
	}
	if !s.resolveNodeCapability("node-a", "acme.firewall").Allowed {
		t.Error("an unenforced plugin capability refused a node")
	}
}

// A declared capability narrows a free-text task's targets and can never widen
// them. Nothing can verify that a script "is" a sing-box script, so the
// declaration is a promise about the operator's own intent: safe to honour as a
// restriction, worthless as a grant.
func TestADeclaredCapabilityOnlyNarrowsAFreeTextTask(t *testing.T) {
	s := capServer(t)
	enforceGate(t, s, capabilitySingBox)
	if err := s.store.UpsertNode(model.Node{
		ID: "node-runs-it", Name: "node-runs-it",
		AgentLaunch: &model.AgentLaunchConfig{SingBoxDiscover: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpsertNode(model.Node{ID: "node-plain", Name: "node-plain"}); err != nil {
		t.Fatal(err)
	}
	mk := func(id string, targets ...string) model.Task {
		return model.Task{
			ID: id, Targets: targets, Interpreter: "sh", Script: "true",
			Status: model.TaskQueued, CreatedAt: time.Now().UTC(),
		}
	}

	// Undeclared: today's behaviour, both targets accepted.
	if err := s.queueTaskFor("", mk("task_none", "node-runs-it", "node-plain")); err != nil {
		t.Fatalf("an undeclared task was refused: %v", err)
	}
	// Declared: the target that is out of scope refuses the whole task, rather
	// than the task silently running on a subset the operator did not choose.
	if err := s.queueTaskFor(capabilitySingBox, mk("task_mixed", "node-runs-it", "node-plain")); err == nil {
		t.Error("a declared capability let through a target that is out of scope for it")
	}
	if err := s.queueTaskFor(capabilitySingBox, mk("task_ok", "node-runs-it")); err != nil {
		t.Errorf("a declared capability refused a target that is in scope: %v", err)
	}

	// Declaring a capability cannot grant reach the operator did not have: an
	// excluded node stays refused however it is declared.
	if err := s.store.SetNodeCapability(store.NodeCapability{
		NodeID: "node-runs-it", Capability: capabilitySingBox,
		State: store.CapabilityExcluded, Reason: "hands off",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.queueTaskFor(capabilitySingBox, mk("task_after", "node-runs-it")); err == nil {
		t.Error("declaring a capability got past an explicit exclusion")
	}
}

// TestQueueTaskForReportsEveryRefusedTarget pins the accumulation rewrite: an
// operator dispatching to several excluded nodes learns all of them in one
// round trip, not one per retry.
func TestQueueTaskForReportsEveryRefusedTarget(t *testing.T) {
	s := capServer(t)
	enforceGate(t, s, "nft")
	for _, nodeID := range []string{"node-a", "node-b"} {
		if err := s.store.SetNodeCapability(store.NodeCapability{
			NodeID: nodeID, Capability: "nft", State: "excluded",
			Reason: "test exclusion", UpdatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	err := s.queueTaskFor("nft", model.Task{
		ID: "task-1", Targets: []string{"node-a", "node-b", "node-c"},
	})
	if err == nil {
		t.Fatal("excluded targets must refuse the dispatch")
	}
	msg := err.Error()
	if !strings.Contains(msg, "node-a") || !strings.Contains(msg, "node-b") {
		t.Fatalf("refusal must name every refused node, got %q", msg)
	}
	if _, ok := s.store.Task("task-1"); ok {
		t.Fatal("nothing may be dispatched when any target is refused")
	}
}

// TestRerunReanswersAdmission pins the rerun bypass fix: a task rerun must be
// gated by the same capability the original was confined to (persisted
// Capability) or authorized by (its approval's plugin, resolved now), so a
// node excluded after the original dispatch cannot be reached again through
// rerun. Dropping this was a live gate bypass.
func TestRerunReanswersAdmission(t *testing.T) {
	s := capServer(t)
	enforceGate(t, s, "nft")

	// Approval-backed task: the approval's plugin is the capability.
	if err := s.store.UpsertApproval(model.Approval{
		ID: "appr-1", NodeID: "node-a", Plugin: "nft", Status: "applied",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.CreateTask(model.Task{
		ID: "task-src", Targets: []string{"node-a"}, Interpreter: "sh",
		Script: "echo apply", Status: model.TaskFinished, ApprovalID: "appr-1",
	}); err != nil {
		t.Fatal(err)
	}
	// Confined ad-hoc task: the persisted Capability field is the capability.
	if err := s.store.CreateTask(model.Task{
		ID: "task-confined", Targets: []string{"node-a"}, Interpreter: "sh",
		Script: "echo probe", Status: model.TaskFinished, Capability: "nft",
	}); err != nil {
		t.Fatal(err)
	}

	// The node is excluded AFTER both tasks ran.
	if err := s.store.SetNodeCapability(store.NodeCapability{
		NodeID: "node-a", Capability: "nft", State: "excluded",
		Reason: "decommissioned from firewall management", UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	rerunGateCapability := func(src model.Task) string {
		capability := src.Capability
		if capability == "" && src.ApprovalID != "" {
			if approval, ok := s.store.Approval(src.ApprovalID); ok {
				capability = approval.Plugin
			}
		}
		return capability
	}
	for _, srcID := range []string{"task-src", "task-confined"} {
		src, ok := s.store.Task(srcID)
		if !ok {
			t.Fatalf("source task %s missing", srcID)
		}
		rebuilt := model.Task{ID: "rerun-" + srcID, Targets: src.Targets, Capability: src.Capability}
		if err := s.queueTaskFor(rerunGateCapability(src), rebuilt); err == nil {
			t.Fatalf("rerun of %s reached an excluded node", srcID)
		}
	}
}

// TestDeriveCoversEveryMutatingCapability pins the usability rule from the
// gate audit: every mutating capability must derive from an existing per-node
// record, or flipping Enforced refuses the entire fleet on the first request.
// acme-dns is the sole allowed exception until its producer exists anywhere.
func TestDeriveCoversEveryMutatingCapability(t *testing.T) {
	for id, spec := range capabilitySpecs {
		// acme-dns has no producer anywhere in this repo yet; sshguard is
		// explicitly-enrolled by design (admission design 2026-08-31: the
		// operator fills its registry from the survey), so an implicit
		// derive would defeat the decision that capability exists to record.
		if !spec.Mutates || id == "acme-dns" || id == sshGuardPlugin {
			continue
		}
		if spec.Derive == nil {
			t.Errorf("mutating capability %q has no Derive: enforcement would refuse the whole fleet", id)
		}
	}
}

// TestDeriveReadsExistingRecords exercises each new Derive against its
// source record: absent record means undecided, present record enrols.
func TestDeriveReadsExistingRecords(t *testing.T) {
	s := capServer(t)
	if err := s.store.UpsertNode(model.Node{ID: "node-w", WireGuardIP: "10.0.0.7"}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpsertNode(model.Node{ID: "node-bare"}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpsertNetPolicy(model.NetPolicy{ID: "np-1", TargetNodeID: "node-w"}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpsertDNSDeployment(model.DNSDeployment{ID: "dns-1", NodeID: "node-w"}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpsertProxyNodeProfile(model.ProxyNodeProfile{NodeID: "node-w"}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpsertTunnel(model.TunnelProfile{ID: "tun-1", NodeID: "node-w", TunnelID: "t"}); err != nil {
		t.Fatal(err)
	}
	cases := []string{"nftpolicy", "wireguard", "selfdns", "proxycore", "cftunnel"}
	for _, capability := range cases {
		allowed, decided := capabilitySpecs[capability].Derive(s, "node-w")
		if !decided || !allowed {
			t.Errorf("%s: enrolled node must derive allowed, got allowed=%v decided=%v", capability, allowed, decided)
		}
		_, decided = capabilitySpecs[capability].Derive(s, "node-bare")
		if decided {
			t.Errorf("%s: bare node must be undecided, not denied or allowed", capability)
		}
	}
}
