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

// The stored plan is what the operator's plan-hash approval covers, so its serialization
// must be deterministic: the same plan must always render to the same bytes, or the same
// plan could hash two ways and an approval could be for a rendering the operator did not
// see.
func TestCanonicalOperationPlanIsDeterministic(t *testing.T) {
	plan := PluginOperationPlan{
		Summary: "rotate keys", Targets: []string{"node-a", "node-b"},
		Preview: "…", Steps: []string{"a", "b"}, Rollback: "restore",
		Data: json.RawMessage(`{"k":1}`),
	}
	first, err := CanonicalOperationPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalOperationPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("canonical plan is not stable: %q vs %q", first, second)
	}
	back, err := ParseOperationPlan(first)
	if err != nil {
		t.Fatal(err)
	}
	if back.Summary != plan.Summary || len(back.Targets) != 2 || string(back.Data) != `{"k":1}` {
		t.Fatalf("plan did not round-trip: %+v", back)
	}
}
