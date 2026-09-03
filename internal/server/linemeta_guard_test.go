package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// renderLineMetadataJSON resolves downstream_node by walking every node's lines
// fleet-wide, so rendering node A's sidecar needs node B to be in the read
// model. maybeQueueLineMetaSyncOnDiscovery fires on an inventory post, so the
// first post after a restart renders while the rest of the fleet has not posted
// yet and the cross-node downstream resolves to nothing.
//
// Observed in production: a restart filed seven fresh approvals, one per hub,
// for nodes whose metadata was already applied. On one node twelve of thirteen
// entries were byte-identical and the thirteenth had lost
// chain.downstream_node. Approving it would have written that loss to the box.
// This is the first cold-read-model defect that writes rather than misreports.
func TestLineMetaSyncRefusesAPlanThatLosesTheDownstreamNode(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	now := time.Date(2026, 9, 3, 11, 2, 0, 0, time.UTC)
	srv.now = func() time.Time { return now }
	seedLinemetaNodes(t, srv)

	out, err := srv.vpnCoreLinesSyncMetadata(lineUserTestPrincipal(), json.RawMessage(`{"node_id":"node-a"}`))
	if err != nil {
		t.Fatalf("first sync: %v", err)
	}
	var resp struct {
		Approval model.Approval `json:"approval"`
		Queued   bool           `json:"queued"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Queued || !strings.Contains(resp.Approval.Plan, `"downstream_node"`) {
		t.Fatalf("fixture: the first plan must name a downstream node: queued=%v plan=%s", resp.Queued, resp.Approval.Plan)
	}
	applied := resp.Approval
	applied.Status = model.ApprovalApplied
	applied.UpdatedAt = now
	if err := st.UpsertApproval(applied); err != nil {
		t.Fatal(err)
	}

	// The control plane restarts. node-a posts its inventory first, which is
	// what triggers the sync; node-b has not posted yet, so the hub's downstream
	// resolves to no owner and the plan comes out without downstream_node.
	now = now.Add(3 * time.Hour)
	srv.linemetaSyncFP = nil
	srv.singboxInvMu.Lock()
	invA := srv.singboxInv["node-a"]
	invA.At = now
	srv.singboxInv = map[string]model.SingBoxInventory{"node-a": invA}
	srv.singboxInvMu.Unlock()
	srv.invalidateLineReadModel()

	degraded, err := srv.renderLineMetadataJSON("node-a")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(degraded), `"downstream_node"`) {
		t.Fatalf("fixture: the cold render should have lost downstream_node: %s", degraded)
	}

	_, err = srv.vpnCoreLinesSyncMetadata(lineUserTestPrincipal(), json.RawMessage(`{"node_id":"node-a"}`))
	if err == nil {
		t.Fatal("a plan that drops chain.downstream_node was queued for review")
	}
	if !strings.Contains(err.Error(), "downstream_node") {
		t.Fatalf("the refusal must name the field that would go: %v", err)
	}
	// Nothing was filed, so there is no degraded plan for an operator to approve
	// and the applied one stays the newest thing describing the box.
	for _, ap := range st.Approvals() {
		if ap.Plugin == singBoxLineMetaPlugin && ap.Status == model.ApprovalPending {
			t.Fatalf("a pending approval was left behind: %s", ap.Plan)
		}
	}

	// The rest of the fleet posts and the sync goes through unchanged, so the
	// guard delays a good plan by exactly one discovery cycle and blocks nothing.
	srv.singboxInvMu.Lock()
	srv.singboxInv["node-b"] = model.SingBoxInventory{
		NodeID: "node-b", At: now, Status: "ok",
		Nodes: []model.SingBoxNode{
			{Name: "exit-b-in", Protocol: "vless", Network: "tcp", Address: "198.51.100.9", Port: "8443"},
		},
	}
	srv.singboxInvMu.Unlock()
	srv.invalidateLineReadModel()
	warm, err := srv.renderLineMetadataJSON("node-a")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(warm), `"downstream_node"`) {
		t.Fatalf("the warm render still lost downstream_node: %s", warm)
	}
	if lost := lineMetaPlanRegression([]byte(applied.Plan), warm); lost != "" {
		t.Fatalf("the warm plan reads as a regression on %s", lost)
	}
}

// The comparison itself, stated directly. It is one-way: adding or changing a
// value is fine and only present-to-absent is refused.
func TestLineMetaPlanRegression(t *testing.T) {
	ds := "1eec4b5a-9c2f-4a1b-8d3e-5f6a7b8c9d0e"
	plan := func(doc lineMetadataDocV2) []byte {
		out, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	full := lineMetadataDocV2{NodeUUID: "node-uuid-a", Inbounds: []lineMetadataInboundV2{
		{Tag: "hub.json", LineUUID: "u1", LineHashID: "line_1",
			Chain: &lineMetadataChainV2{DownstreamLineUUID: &ds, DownstreamNode: "Node B"}},
		{Tag: "direct.json", LineUUID: "u2", LineHashID: "line_2"},
	}}
	mutate := func(f func(*lineMetadataDocV2)) []byte {
		d := lineMetadataDocV2{NodeUUID: full.NodeUUID}
		for _, ib := range full.Inbounds {
			if ib.Chain != nil {
				c := *ib.Chain
				ib.Chain = &c
			}
			d.Inbounds = append(d.Inbounds, ib)
		}
		f(&d)
		return plan(d)
	}
	for _, tc := range []struct {
		name  string
		fresh []byte
		want  string
	}{
		{"identical", plan(full), ""},
		{"downstream_node dropped", mutate(func(d *lineMetadataDocV2) { d.Inbounds[0].Chain.DownstreamNode = "" }), "chain.downstream_node on hub.json"},
		{"downstream_line_uuid dropped", mutate(func(d *lineMetadataDocV2) { d.Inbounds[0].Chain.DownstreamLineUUID = nil }), "chain.downstream_line_uuid on hub.json"},
		{"whole chain block dropped", mutate(func(d *lineMetadataDocV2) { d.Inbounds[0].Chain = nil }), "the chain block on hub.json"},
		{"line_uuid dropped", mutate(func(d *lineMetadataDocV2) { d.Inbounds[1].LineUUID = "" }), "line_uuid on direct.json"},
		{"line_hash_id dropped", mutate(func(d *lineMetadataDocV2) { d.Inbounds[1].LineHashID = "" }), "line_hash_id on direct.json"},
		{"node_uuid dropped", mutate(func(d *lineMetadataDocV2) { d.NodeUUID = "" }), "node_uuid"},
		{"every entry gone", plan(lineMetadataDocV2{NodeUUID: "node-uuid-a"}), "all 2 inbound entries"},

		// Not regressions. A plan may add, may change, and may remove a line,
		// because removing one is a thing an operator does on purpose.
		{"a downstream node gained", mutate(func(d *lineMetadataDocV2) {
			d.Inbounds[1].Chain = &lineMetadataChainV2{DownstreamNode: "Node C"}
		}), ""},
		{"a downstream node renamed", mutate(func(d *lineMetadataDocV2) { d.Inbounds[0].Chain.DownstreamNode = "Node C" }), ""},
		// A value CHANGING is not a loss, and refusing it would be worse than
		// the loss this guards. A line re-identified while keeping its file name
		// (a port change reallocates the hash and the uuid) would otherwise be
		// refused on every future sync, locking the node out permanently.
		{"line_uuid reallocated", mutate(func(d *lineMetadataDocV2) { d.Inbounds[0].LineUUID = "u9" }), ""},
		{"line_hash_id recomputed", mutate(func(d *lineMetadataDocV2) { d.Inbounds[0].LineHashID = "line_9" }), ""},
		{"node_uuid changed", mutate(func(d *lineMetadataDocV2) { d.NodeUUID = "node-uuid-z" }), ""},
		{"a downstream uuid repointed", mutate(func(d *lineMetadataDocV2) {
			other := "2aac4b5a-9c2f-4a1b-8d3e-5f6a7b8c9d0e"
			d.Inbounds[0].Chain.DownstreamLineUUID = &other
		}), ""},
		{"one line removed", mutate(func(d *lineMetadataDocV2) { d.Inbounds = d.Inbounds[:1] }), ""},
		{"a line added", mutate(func(d *lineMetadataDocV2) {
			d.Inbounds = append(d.Inbounds, lineMetadataInboundV2{Tag: "new.json", LineUUID: "u3"})
		}), ""},
		{"an unparseable applied plan compares to nothing", []byte(`{`), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := lineMetaPlanRegression(plan(full), tc.fresh); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	if got := lineMetaPlanRegression([]byte(`{`), plan(full)); got != "" {
		t.Fatalf("an unparseable applied plan must not block a sync: %q", got)
	}
	// A node that never had an applied plan has nothing to lose, and an empty
	// applied inbound list is not a floor to hold against.
	if got := lineMetaPlanRegression(plan(lineMetadataDocV2{}), plan(lineMetadataDocV2{})); got != "" {
		t.Fatalf("empty against empty: %q", got)
	}
}
