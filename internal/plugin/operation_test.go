package plugin

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type recordingTaskHost struct {
	enqueued []HostTaskRequest
	err      error
}

func (h *recordingTaskHost) Enqueue(_ context.Context, req HostTaskRequest) (string, error) {
	if h.err != nil {
		return "", h.err
	}
	h.enqueued = append(h.enqueued, req)
	return "task-1", nil
}

func operationBroker(t *testing.T) (*Broker, *recordingTaskHost) {
	t.Helper()
	host := &recordingTaskHost{}
	capabilities := []string{"task:run"}
	broker, err := NewBroker(Loaded{
		Manifest: Manifest{
			ID: "latticenet.wireguard", Name: "WG", Type: TypeSystem, Capabilities: capabilities,
		},
		Capabilities: capabilities,
	}, HostServices{Task: host})
	if err != nil {
		t.Fatal(err)
	}
	return broker, host
}

func grant() *OperationGrant {
	return &OperationGrant{
		ApprovalID: "approval-1", PluginID: "latticenet.wireguard",
		PlanSHA256: strings.Repeat("a", 64), Targets: []string{"node-a"}, Remaining: 2,
	}
}

// The capability is eligibility, not authorization. task:run says a plugin MAY run work;
// only an approved operation says which work, on which nodes. Without a grant — which is
// to say, reached any way other than through the approval executor — there is nothing to
// enqueue against.
func TestTaskEnqueueRequiresAnApprovedOperation(t *testing.T) {
	broker, host := operationBroker(t)

	_, err := broker.TaskEnqueue(context.Background(), HostTaskRequest{
		NodeID: "node-a", Interpreter: "sh", Script: "echo hi",
	})
	if err == nil {
		t.Fatal("a plugin enqueued agent work with no approved operation behind it")
	}
	if !strings.Contains(err.Error(), "approved operation") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(host.enqueued) != 0 {
		t.Fatal("the task reached the host despite having no approval")
	}
}

// A grant authorizes the reviewed blast radius and not one node more.
func TestTaskEnqueueCannotReachAnUnapprovedNode(t *testing.T) {
	broker, host := operationBroker(t)
	ctx, err := BindOperation(context.Background(), grant())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := broker.TaskEnqueue(ctx, HostTaskRequest{
		NodeID: "node-b", Interpreter: "sh", Script: "echo hi",
	}); err == nil {
		t.Fatal("a plugin reached a node the operator never approved")
	}
	if len(host.enqueued) != 0 {
		t.Fatal("the unapproved task reached the host")
	}

	if _, err := broker.TaskEnqueue(ctx, HostTaskRequest{
		NodeID: "node-a", Interpreter: "sh", Script: "echo hi",
	}); err != nil {
		t.Fatalf("an approved target must be reachable: %v", err)
	}
	if len(host.enqueued) != 1 || host.enqueued[0].NodeID != "node-a" {
		t.Fatalf("unexpected enqueue: %+v", host.enqueued)
	}
	// The broker stamps the verified plugin id and the approval it is acting under; the
	// plugin does not get to claim either.
	if host.enqueued[0].PluginID != "latticenet.wireguard" || host.enqueued[0].ApprovalID != "approval-1" {
		t.Fatalf("broker did not stamp the verified identity: %+v", host.enqueued[0])
	}
}

// An approval authorizes a plan, not an open-ended session.
func TestOperationGrantIsExhaustible(t *testing.T) {
	broker, _ := operationBroker(t)
	ctx, err := BindOperation(context.Background(), grant()) // Remaining: 2
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if _, err := broker.TaskEnqueue(ctx, HostTaskRequest{
			NodeID: "node-a", Interpreter: "sh", Script: "echo hi",
		}); err != nil {
			t.Fatalf("enqueue %d should be within the grant: %v", i, err)
		}
	}
	if _, err := broker.TaskEnqueue(ctx, HostTaskRequest{
		NodeID: "node-a", Interpreter: "sh", Script: "echo hi",
	}); err == nil {
		t.Fatal("a plugin kept enqueueing past its grant")
	}
}

// A grant is bound to the plugin it was issued to. The broker stamps the verified id, so
// a grant that does not match it can only mean something has gone wrong — refuse rather
// than reason about it.
func TestOperationGrantIsNotTransferableBetweenPlugins(t *testing.T) {
	broker, _ := operationBroker(t) // latticenet.wireguard
	foreign := grant()
	foreign.PluginID = "latticenet.vpn-core"
	ctx, err := BindOperation(context.Background(), foreign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.TaskEnqueue(ctx, HostTaskRequest{
		NodeID: "node-a", Interpreter: "sh", Script: "echo hi",
	}); err == nil {
		t.Fatal("a plugin executed under another plugin's grant")
	}
}

func TestTaskEnqueueRequiresTheCapability(t *testing.T) {
	host := &recordingTaskHost{}
	broker, err := NewBroker(Loaded{
		Manifest: Manifest{
			ID: "latticenet.wireguard", Name: "WG", Type: TypeSystem,
			Capabilities: []string{"kv:read"},
		},
		Capabilities: []string{"kv:read"},
	}, HostServices{Task: host})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := BindOperation(context.Background(), grant())
	if err != nil {
		t.Fatal(err)
	}
	// Even holding a valid grant, a plugin that never declared task:run cannot enqueue.
	if _, err := broker.TaskEnqueue(ctx, HostTaskRequest{
		NodeID: "node-a", Interpreter: "sh", Script: "echo hi",
	}); err == nil {
		t.Fatal("a plugin without task:run enqueued agent work")
	}
}

// The envelope is the approval's plan text, so its hash is what the operator approves.
// Any field moving must move the hash, or an approval could be honoured for a plugin,
// version, artifact, request, or target set the reviewer never saw.
func TestEveryBoundFieldChangesThePlanHash(t *testing.T) {
	base := OperationEnvelope{
		PluginID: "latticenet.wireguard", PluginVersion: "0.1.0", ArtifactDigest: strings.Repeat("a", 64),
		Service: "latticenet.wireguard/networks", Method: "apply", RequestSHA256: strings.Repeat("b", 64),
		Plan: PluginOperationPlan{Summary: "rotate keys", Targets: []string{"node-a"}},
	}
	canonical, err := CanonicalOperationEnvelope(base)
	if err != nil {
		t.Fatal(err)
	}
	baseHash := SHA256Hex([]byte(canonical))

	mutations := map[string]func(*OperationEnvelope){
		"plugin id":       func(e *OperationEnvelope) { e.PluginID = "latticenet.vpn-core" },
		"plugin version":  func(e *OperationEnvelope) { e.PluginVersion = "0.2.0" },
		"artifact digest": func(e *OperationEnvelope) { e.ArtifactDigest = strings.Repeat("c", 64) },
		"service":         func(e *OperationEnvelope) { e.Service = "latticenet.wireguard/other" },
		"method":          func(e *OperationEnvelope) { e.Method = "destroy" },
		"request hash":    func(e *OperationEnvelope) { e.RequestSHA256 = strings.Repeat("d", 64) },
		"targets":         func(e *OperationEnvelope) { e.Plan.Targets = []string{"node-a", "node-b"} },
		"summary":         func(e *OperationEnvelope) { e.Plan.Summary = "something else entirely" },
		"plan data":       func(e *OperationEnvelope) { e.Plan.Data = json.RawMessage(`{"x":1}`) },
	}
	for name, mutate := range mutations {
		mutated := base
		mutate(&mutated)
		canonical, err := CanonicalOperationEnvelope(mutated)
		if err != nil {
			t.Fatal(err)
		}
		if SHA256Hex([]byte(canonical)) == baseHash {
			t.Fatalf("changing the %s did not change the plan hash: an approval could be "+
				"honoured for something the operator never approved", name)
		}
	}
}

func TestOperationPlanIsBounded(t *testing.T) {
	if err := ValidateOperationPlan(PluginOperationPlan{Targets: []string{"node-a"}}); err == nil {
		t.Fatal("a plan with no summary is not reviewable")
	}
	if err := ValidateOperationPlan(PluginOperationPlan{Summary: "x"}); err == nil {
		t.Fatal("a plan must name the nodes it would touch")
	}
	if err := ValidateOperationPlan(PluginOperationPlan{
		Summary: "x", Targets: []string{"node-a", "node-a"},
	}); err == nil {
		t.Fatal("a repeated target must be rejected")
	}
	many := make([]string, maxOperationTargets+1)
	for i := range many {
		many[i] = string(rune('a'+i%26)) + strings.Repeat("x", i)
	}
	if err := ValidateOperationPlan(PluginOperationPlan{Summary: "x", Targets: many}); err == nil {
		t.Fatal("target count must be bounded")
	}
	if err := ValidateOperationPlan(PluginOperationPlan{
		Summary: "x", Targets: []string{"node-a"},
	}); err != nil {
		t.Fatalf("a minimal well-formed plan must validate: %v", err)
	}
}

func TestParseOperationEnvelopeRejectsForeignPlans(t *testing.T) {
	// The nft/dns/agent-update approvals are plain strings; they must not be mistaken
	// for plugin operations, or the generic executor would try to run them.
	for _, plan := range []string{"", "nft add rule ...", `{"kind":"something.else"}`} {
		if _, err := ParseOperationEnvelope(plan); err == nil {
			t.Fatalf("plan %q was accepted as a plugin operation", plan)
		}
	}
}
