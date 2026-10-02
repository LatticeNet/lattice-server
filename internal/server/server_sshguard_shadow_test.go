package server

import (
	"slices"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/sshguard"
)

// SSH Guard's override finding asks whether the node's lattice_guard chain,
// which is policy drop and sits in front of the knock table, accepts the
// ports a profile gates. It used to collect every port an accept mentioned
// and skip every drop, the same blindness the NetGuard lockout lint had, so a
// drop on the gate port ahead of its allow passed: the knock would report
// success and the connection would never open.
func TestSSHGuardPlanIsBlockedByADropAheadOfTheGatePortAllow(t *testing.T) {
	allow := func(id string, port int) model.GuardRule {
		return model.GuardRule{ID: id, Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: model.NetProtoTCP,
			Ports: []model.GuardPortRange{{From: port, To: port}}, Remote: model.NetEndpoint{Kind: model.NetRefZone, ZoneID: model.GuardZonePublic}}
	}
	deny := model.GuardRule{ID: "deny-gate", Action: model.NetRuleDeny, Direction: model.NetDirIngress, Protocol: model.NetProtoTCP,
		Ports: []model.GuardPortRange{{From: 58394, To: 58394}}, Remote: model.NetEndpoint{Kind: model.NetRefAny}}
	for _, tc := range []struct {
		name      string
		overrides []model.GuardRule
		want      bool
	}{
		{"the gate port's allow sits behind a drop", []model.GuardRule{deny, allow("ssh", 22), allow("gate", 58394)}, true},
		{"the gate port is allowed ahead of the drop", []model.GuardRule{allow("ssh", 22), allow("gate", 58394), deny}, false},
		{"allow-only guard that opens both ports", []model.GuardRule{allow("ssh", 22), allow("gate", 58394)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, handler, st := newInventoryServer(t)
			seedAgentUpdateNode(t, st)
			enrolSSHGuard(t, st, "node-a")
			if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{
				NodeID: "node-a", Managed: true, Overrides: tc.overrides,
				AppliedTableSHA: "3f0c2a1d", LastAppliedAt: time.Now().UTC(),
			}); err != nil {
				t.Fatalf("seed managed binding: %v", err)
			}
			cookies, csrf := loginSession(t, handler)
			token := createPAT(t, handler, cookies, csrf, []string{"network:plan", "sshguard:admin"}, []string{"node-a"})
			_, codes := sshGuardPlanFindings(t, handler, token)
			if got := slices.Contains(codes, sshguard.FindingOverriddenByGuard); got != tc.want {
				t.Fatalf("override finding = %v, want %v (codes %v)", got, tc.want, codes)
			}
		})
	}
}
