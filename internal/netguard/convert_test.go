package netguard

import (
	"reflect"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestPortRanges(t *testing.T) {
	cases := []struct {
		name string
		in   []int
		want []model.GuardPortRange
	}{
		{"empty", nil, nil},
		{"single", []int{443}, []model.GuardPortRange{{From: 443, To: 443}}},
		{"unsorted with duplicates", []int{443, 80, 443},
			[]model.GuardPortRange{{From: 80, To: 80}, {From: 443, To: 443}}},
		{"adjacent run collapses", []int{9010, 9009, 9011, 9012, 9013},
			[]model.GuardPortRange{{From: 9009, To: 9013}}},
		{"run plus gap", []int{22, 9009, 9010, 9011, 9013},
			[]model.GuardPortRange{{From: 22, To: 22}, {From: 9009, To: 9011}, {From: 9013, To: 9013}}},
		{"out of range dropped", []int{0, -1, 70000, 80},
			[]model.GuardPortRange{{From: 80, To: 80}}},
		{"all invalid", []int{0, 70000}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PortRanges(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("PortRanges(%v) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

// The dmit-eb-wee incident fixture: 15 mirrored TCP+UDP baseline ports on
// eth0 / 10.66.0.0/24. The converted view must compress the croc run
// 9009-9013 into one range, reference the builtin zones, and stay
// observe-only (Managed=false, wireguard never a trusted zone).
func TestLegacyBaselineConvertsRealBaseline(t *testing.T) {
	ports := []int{115, 3433, 7443, 7500, 7780, 9009, 9010, 9011, 9012, 9013, 17891, 17893, 42622, 48358, 57289}
	view := LegacyBaseline(model.NFTInputs{
		ID:            "dmit-eb-wee",
		NodeID:        "dmit-eb-wee",
		InterfaceName: "eth0",
		WireGuardCIDR: "10.66.0.0/24",
		PublicTCP:     ports,
		PublicUDP:     ports,
	})

	if view.Group.ID != "sg-legacy-dmit-eb-wee" {
		t.Fatalf("group id = %q", view.Group.ID)
	}
	if len(view.Group.Rules) != 2 {
		t.Fatalf("want 2 rules (tcp+udp), got %d: %+v", len(view.Group.Rules), view.Group.Rules)
	}
	wantRanges := []model.GuardPortRange{
		{From: 115, To: 115}, {From: 3433, To: 3433}, {From: 7443, To: 7443},
		{From: 7500, To: 7500}, {From: 7780, To: 7780}, {From: 9009, To: 9013},
		{From: 17891, To: 17891}, {From: 17893, To: 17893}, {From: 42622, To: 42622},
		{From: 48358, To: 48358}, {From: 57289, To: 57289},
	}
	for i, proto := range []string{model.NetProtoTCP, model.NetProtoUDP} {
		rule := view.Group.Rules[i]
		if rule.Protocol != proto || rule.Action != model.NetRuleAllow || rule.Direction != model.NetDirIngress {
			t.Fatalf("rule %d shape wrong: %+v", i, rule)
		}
		if rule.Remote.Kind != model.NetRefZone || rule.Remote.ZoneID != model.GuardZonePublic {
			t.Fatalf("rule %d remote wrong: %+v", i, rule.Remote)
		}
		if !reflect.DeepEqual(rule.Ports, wantRanges) {
			t.Fatalf("rule %d ranges = %+v, want %+v", i, rule.Ports, wantRanges)
		}
	}

	if view.Binding.Managed {
		t.Fatal("legacy binding must be observe-only (Managed=false)")
	}
	if len(view.Binding.ZoneIDs) != 0 {
		t.Fatalf("legacy binding must not trust any zone, got %v", view.Binding.ZoneIDs)
	}
	if !reflect.DeepEqual(view.Binding.GroupIDs, []string{"sg-legacy-dmit-eb-wee"}) {
		t.Fatalf("binding groups = %v", view.Binding.GroupIDs)
	}

	zoneByID := map[string]model.GuardZone{}
	for _, z := range view.Zones {
		zoneByID[z.ID] = z
	}
	if got := zoneByID[model.GuardZonePublic].Interfaces; !reflect.DeepEqual(got, []string{"eth0"}) {
		t.Fatalf("public zone interfaces = %v", got)
	}
	if got := zoneByID[model.GuardZoneWireGuard].CIDRs; !reflect.DeepEqual(got, []string{"10.66.0.0/24"}) {
		t.Fatalf("wireguard zone cidrs = %v", got)
	}
	if _, ok := zoneByID[model.GuardZoneLoopback]; !ok {
		t.Fatal("loopback zone missing")
	}
}

func TestLegacyBaselineWireGuardPortsAndDefaults(t *testing.T) {
	view := LegacyBaseline(model.NFTInputs{
		ID:           "node-a",
		NodeID:       "node-a",
		WireGuardTCP: []int{9100, 22},
		WireGuardUDP: []int{51820},
	})
	if len(view.Group.Rules) != 2 {
		t.Fatalf("want 2 wg rules, got %d", len(view.Group.Rules))
	}
	for _, rule := range view.Group.Rules {
		if rule.Remote.Kind != model.NetRefZone || rule.Remote.ZoneID != model.GuardZoneWireGuard {
			t.Fatalf("wg rule remote wrong: %+v", rule.Remote)
		}
	}
	if got := view.Group.Rules[0].Ports; !reflect.DeepEqual(got, []model.GuardPortRange{{From: 22, To: 22}, {From: 9100, To: 9100}}) {
		t.Fatalf("wg tcp ranges = %+v", got)
	}
	zoneByID := map[string]model.GuardZone{}
	for _, z := range view.Zones {
		zoneByID[z.ID] = z
	}
	if got := zoneByID[model.GuardZonePublic].Interfaces; !reflect.DeepEqual(got, []string{"eth0"}) {
		t.Fatalf("default public interface = %v", got)
	}
	if got := zoneByID[model.GuardZoneWireGuard].CIDRs; !reflect.DeepEqual(got, []string{"10.66.0.0/24"}) {
		t.Fatalf("default wg cidr = %v", got)
	}
}

func TestLegacyBaselineEmptyInputsYieldsNoRules(t *testing.T) {
	view := LegacyBaseline(model.NFTInputs{ID: "node-b", NodeID: "node-b"})
	if len(view.Group.Rules) != 0 {
		t.Fatalf("empty baseline must convert to zero rules, got %+v", view.Group.Rules)
	}
	if view.Binding.Managed {
		t.Fatal("empty baseline must stay observe-only")
	}
}
