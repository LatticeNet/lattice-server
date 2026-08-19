package netguard

import (
	"encoding/json"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/network"
)

// The lockout check, driven by a snapshot a real fleet node actually reported.
//
// The other tests in this package build their reality by hand, which proves the
// logic but not that the shape the agent sends matches the shape the lint
// expects. This one uses the verbatim JSON that node_ob46mh4ltshdpkhc reported
// to production on 2026-08-19, captured while a second sshd was briefly bound
// to 2222 so the interesting branch had real data behind it. Process names
// arrive as "sshd(645)", with the pid, which is exactly the detail a hand-built
// fixture is most likely to get wrong.
//
// Trimmed to the listeners: the full snapshot carries 21 of them and the rest
// are irrelevant to a management-path decision.
const productionSnapshotJSON = `{
  "node_id": "node_ob46mh4ltshdpkhc",
  "collected_at": "2026-08-19T08:49:05.630450121Z",
  "listeners": [
    {"protocol":"tcp","port":22,"address":"0.0.0.0","process":"sshd(645)"},
    {"protocol":"tcp","port":22,"address":"::","process":"sshd(645)"},
    {"protocol":"tcp","port":2222,"address":"0.0.0.0","process":"sshd(2158851)"},
    {"protocol":"tcp","port":2222,"address":"::","process":"sshd(2158851)"},
    {"protocol":"tcp","port":53,"address":"::","process":"dnsproxy(610)"},
    {"protocol":"tcp","port":2053,"address":"::","process":"dnsproxy(610)"},
    {"protocol":"tcp","port":3433,"address":"0.0.0.0","process":"realm(620)"},
    {"protocol":"tcp","port":7000,"address":"::","process":"frps(612)"},
    {"protocol":"tcp","port":7443,"address":"::","process":"frps(612)"},
    {"protocol":"tcp","port":7500,"address":"::","process":"frps(612)"}
  ]
}`

func productionReality(t *testing.T) *model.GuardNodeReality {
	t.Helper()
	var reality model.GuardNodeReality
	if err := json.Unmarshal([]byte(productionSnapshotJSON), &reality); err != nil {
		t.Fatalf("the captured production snapshot no longer decodes into the model: %v", err)
	}
	if len(reality.Listeners) == 0 {
		t.Fatal("the captured snapshot decoded with no listeners, so the field names have drifted")
	}
	return &reality
}

func TestProductionSnapshotLearnsTheNonStandardShellPort(t *testing.T) {
	reality := productionReality(t)

	// The assertion that proves the fix. Before it, managementPorts always
	// answered tcp/22 regardless of what the node reported, so a plan that
	// kept only 2222 looked like a lockout and blocked. With real listener
	// data the check knows 2222 is a shell path and lets it through.
	only2222 := Lint(network.NFTPlan{PublicTCP: []int{2222, 443}}, LintOptions{
		PublicURLConfigured: true,
		Reality:             reality,
	})
	if Blocking(only2222) {
		t.Fatalf("a plan keeping the node's non-standard shell port must not block: %+v", only2222)
	}
	for _, f := range only2222 {
		if f.Code == FindingManagementPortAssumed {
			t.Fatalf("the check had real listener data and must not report the port as assumed: %+v", f)
		}
	}

	// The genuine lockout: neither reported shell port survives. This is the
	// case the node-side watchdog cannot catch, because its selfcheck is an
	// outbound connection that a default-drop INPUT chain does not affect.
	neither := Lint(network.NFTPlan{PublicTCP: []int{443}}, LintOptions{
		PublicURLConfigured: true,
		Reality:             reality,
	})
	if !Blocking(neither) {
		t.Fatalf("a plan that drops every reported shell path must block: %+v", neither)
	}

	// Deliberately not asserted: that dropping 2222 while keeping 22 blocks. It
	// does not, and should not. One surviving shell path is not a lockout, and
	// requiring every reported port to stay open would make the check refuse
	// legitimate plans that close a port the operator meant to close.
}

func TestProductionSnapshotDoesNotTreatServicePortsAsShellPaths(t *testing.T) {
	reality := productionReality(t)

	// dnsproxy, realm and frps are listening too. None of them is a way back
	// into the box, so none may satisfy the management-path requirement: a plan
	// that keeps only those still cuts every shell path.
	findings := Lint(network.NFTPlan{PublicTCP: []int{53, 3433, 7000, 7443, 7500}}, LintOptions{
		PublicURLConfigured: true,
		Reality:             reality,
	})
	if !Blocking(findings) {
		t.Fatalf("non-shell service ports must not count as a management path: %+v", findings)
	}
}

func TestAFleetNodeThatHasNotReportedIsMarkedAssumed(t *testing.T) {
	// 33 of the 35 nodes are in exactly this state until the agent rollout
	// reaches them, so this is the common case, not the edge case. The check
	// still falls back to tcp/22, and must say that it guessed.
	findings := Lint(network.NFTPlan{PublicTCP: []int{22}}, LintOptions{
		PublicURLConfigured: true,
		Reality:             nil,
	})
	if Blocking(findings) {
		t.Fatalf("the tcp/22 fallback must not block a plan that keeps 22 open: %+v", findings)
	}
	var assumed bool
	for _, f := range findings {
		if f.Code == FindingManagementPortAssumed {
			assumed = true
		}
	}
	if !assumed {
		t.Fatalf("a node with no snapshot must report that its management port was assumed: %+v", findings)
	}
}
