package netguard

import (
	"reflect"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestSuggestMissingAllowAndStaleAllow(t *testing.T) {
	view := LegacyBaseline(model.NFTInputs{
		NodeID:        "node-a",
		InterfaceName: "eth0",
		PublicTCP:     []int{443},
		PublicUDP:     []int{115},
	})
	view.Binding.Managed = true

	got, err := Suggest(SuggestInput{
		Binding: view.Binding,
		Groups:  []model.SecurityGroup{view.Group},
		Zones:   ZoneMap(view.Zones),
		Reality: model.GuardNodeReality{
			NodeID: "node-a",
			Listeners: []model.GuardListener{
				{Protocol: model.NetProtoTCP, Port: 22, Address: "0.0.0.0", Process: "sshd"},
				{Protocol: model.NetProtoTCP, Port: 443, Address: "0.0.0.0", Process: "nginx"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantIDs := []string{
		"node-a:allow_without_listener:public:udp:115",
		"node-a:listener_missing_allow:public:tcp:22",
	}
	if ids := suggestionIDs(got); !reflect.DeepEqual(ids, wantIDs) {
		t.Fatalf("suggestion ids = %v, want %v\nsuggestions: %+v", ids, wantIDs, got)
	}
	assertSuggestion(t, got[0], SuggestionAllowWithoutListener, model.GuardZonePublic, model.NetProtoUDP, 115)
	assertSuggestion(t, got[1], SuggestionListenerMissingAllow, model.GuardZonePublic, model.NetProtoTCP, 22)
	if got[1].Process != "sshd" {
		t.Fatalf("missing-allow process = %q, want sshd", got[1].Process)
	}
}

func TestSuggestOverlayOnlyListenerAndUntrustedZone(t *testing.T) {
	zones := ZoneMap([]model.GuardZone{
		{ID: model.GuardZonePublic, Name: "public", Builtin: true, Interfaces: []string{"eth0"}},
		{ID: model.GuardZoneTailscale, Name: "tailscale", Builtin: true, Interfaces: []string{"tailscale0"}},
		{ID: model.GuardZoneLoopback, Name: "loopback", Builtin: true, Interfaces: []string{"lo"}},
	})

	got, err := Suggest(SuggestInput{
		Binding: model.NodeGuardBinding{NodeID: "node-a", Managed: true},
		Groups: []model.SecurityGroup{{ID: "sg", Rules: []model.GuardRule{{
			ID:        "public-tailscale",
			Action:    model.NetRuleAllow,
			Direction: model.NetDirIngress,
			Protocol:  model.NetProtoTCP,
			Ports:     []model.GuardPortRange{{From: 42622, To: 42622}},
			Remote:    model.NetEndpoint{Kind: model.NetRefZone, ZoneID: model.GuardZonePublic},
		}}}},
		Zones: zones,
		Reality: model.GuardNodeReality{
			NodeID: "node-a",
			Interfaces: []model.GuardInterface{
				{Name: "eth0", Addresses: []string{"192.0.2.10/24"}, Up: true},
				{Name: "tailscale0", Addresses: []string{"100.64.0.2/32"}, Up: true},
			},
			Listeners: []model.GuardListener{{
				Protocol: model.NetProtoTCP,
				Port:     42622,
				Address:  "100.64.0.2",
				Process:  "tailscaled",
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantIDs := []string{
		"node-a:overlay_listener_public_allow:tailscale:tcp:42622",
		"node-a:overlay_zone_untrusted:tailscale",
	}
	if ids := suggestionIDs(got); !reflect.DeepEqual(ids, wantIDs) {
		t.Fatalf("suggestion ids = %v, want %v\nsuggestions: %+v", ids, wantIDs, got)
	}
	assertSuggestion(t, got[0], SuggestionOverlayListenerPublicAllow, model.GuardZoneTailscale, model.NetProtoTCP, 42622)
	if got[0].Interface != "tailscale0" || got[0].Process != "tailscaled" {
		t.Fatalf("overlay listener detail mismatch: %+v", got[0])
	}
	assertSuggestion(t, got[1], SuggestionOverlayZoneUntrusted, model.GuardZoneTailscale, "", 0)
	if got[1].Interface != "tailscale0" {
		t.Fatalf("untrusted zone interface = %q, want tailscale0", got[1].Interface)
	}
}

func TestSuggestManagedTableDrift(t *testing.T) {
	got, err := Suggest(SuggestInput{
		Binding: model.NodeGuardBinding{
			NodeID:          "node-a",
			Managed:         true,
			AppliedTableSHA: "old",
		},
		Reality: model.GuardNodeReality{
			NodeID:     "node-a",
			ManagedSHA: "new",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantIDs := []string{"node-a:managed_table_drift"}
	if ids := suggestionIDs(got); !reflect.DeepEqual(ids, wantIDs) {
		t.Fatalf("suggestion ids = %v, want %v\nsuggestions: %+v", ids, wantIDs, got)
	}
	assertSuggestion(t, got[0], SuggestionManagedTableDrift, "", "", 0)
}

func TestSuggestBindingOverridesAreIntent(t *testing.T) {
	got, err := Suggest(SuggestInput{
		Binding: model.NodeGuardBinding{
			NodeID:  "node-a",
			Managed: true,
			Overrides: []model.GuardRule{
				{
					ID:        "operator-https",
					Action:    model.NetRuleAllow,
					Direction: model.NetDirIngress,
					Protocol:  model.NetProtoTCP,
					Ports:     []model.GuardPortRange{{From: 8443, To: 8443}},
					Remote:    model.NetEndpoint{Kind: model.NetRefZone, ZoneID: model.GuardZonePublic},
				},
				{
					ID:        "stale-mdns",
					Action:    model.NetRuleAllow,
					Direction: model.NetDirIngress,
					Protocol:  model.NetProtoUDP,
					Ports:     []model.GuardPortRange{{From: 5353, To: 5353}},
					Remote:    model.NetEndpoint{Kind: model.NetRefZone, ZoneID: model.GuardZonePublic},
				},
			},
		},
		Zones: ZoneMap([]model.GuardZone{{ID: model.GuardZonePublic, Interfaces: []string{"eth0"}}}),
		Reality: model.GuardNodeReality{
			NodeID:    "node-a",
			Listeners: []model.GuardListener{{Protocol: model.NetProtoTCP, Port: 8443, Address: "0.0.0.0", Process: "console"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantIDs := []string{"node-a:allow_without_listener:public:udp:5353"}
	if ids := suggestionIDs(got); !reflect.DeepEqual(ids, wantIDs) {
		t.Fatalf("suggestion ids = %v, want %v\nsuggestions: %+v", ids, wantIDs, got)
	}
	assertSuggestion(t, got[0], SuggestionAllowWithoutListener, model.GuardZonePublic, model.NetProtoUDP, 5353)
}

func TestSuggestCIDROverlayZone(t *testing.T) {
	zones := ZoneMap([]model.GuardZone{
		{ID: model.GuardZonePublic, Name: "public", Builtin: true, Interfaces: []string{"eth0"}},
		{ID: model.GuardZoneWireGuard, Name: "wireguard", Builtin: true, CIDRs: []string{"100.64.0.0/10"}},
	})

	got, err := Suggest(SuggestInput{
		Binding: model.NodeGuardBinding{NodeID: "node-a", Managed: true},
		Groups: []model.SecurityGroup{{ID: "sg", Rules: []model.GuardRule{{
			ID:        "public-wg",
			Action:    model.NetRuleAllow,
			Direction: model.NetDirIngress,
			Protocol:  model.NetProtoUDP,
			Ports:     []model.GuardPortRange{{From: 51820, To: 51820}},
			Remote:    model.NetEndpoint{Kind: model.NetRefZone, ZoneID: model.GuardZonePublic},
		}}}},
		Zones: zones,
		Reality: model.GuardNodeReality{
			NodeID: "node-a",
			Interfaces: []model.GuardInterface{
				{Name: "eth0", Addresses: []string{"192.0.2.10/24"}, Up: true},
				{Name: "wg0", Addresses: []string{"100.64.0.2/32"}, Up: true},
			},
			Listeners: []model.GuardListener{{
				Protocol: model.NetProtoUDP,
				Port:     51820,
				Address:  "100.64.0.2",
				Process:  "wireguard-go",
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantIDs := []string{
		"node-a:overlay_listener_public_allow:wireguard:udp:51820",
		"node-a:overlay_zone_untrusted:wireguard",
	}
	if ids := suggestionIDs(got); !reflect.DeepEqual(ids, wantIDs) {
		t.Fatalf("suggestion ids = %v, want %v\nsuggestions: %+v", ids, wantIDs, got)
	}
	assertSuggestion(t, got[0], SuggestionOverlayListenerPublicAllow, model.GuardZoneWireGuard, model.NetProtoUDP, 51820)
	if got[0].Interface != "wg0" || got[0].Process != "wireguard-go" {
		t.Fatalf("cidr overlay listener detail mismatch: %+v", got[0])
	}
	assertSuggestion(t, got[1], SuggestionOverlayZoneUntrusted, model.GuardZoneWireGuard, "", 0)
	if got[1].Interface != "wg0" {
		t.Fatalf("cidr untrusted zone interface = %q, want wg0", got[1].Interface)
	}
}

func TestSuggestCleanIntentNoSuggestions(t *testing.T) {
	zones := ZoneMap([]model.GuardZone{
		{ID: model.GuardZonePublic, Name: "public", Builtin: true, Interfaces: []string{"eth0"}},
		{ID: model.GuardZoneTailscale, Name: "tailscale", Builtin: true, Interfaces: []string{"tailscale0"}},
	})
	got, err := Suggest(SuggestInput{
		Binding: model.NodeGuardBinding{
			NodeID:          "node-a",
			Managed:         true,
			ZoneIDs:         []string{model.GuardZoneTailscale},
			AppliedTableSHA: "same",
		},
		Groups: []model.SecurityGroup{{ID: "sg", Rules: []model.GuardRule{{
			ID:        "ssh",
			Action:    model.NetRuleAllow,
			Direction: model.NetDirIngress,
			Protocol:  model.NetProtoTCP,
			Ports:     []model.GuardPortRange{{From: 22, To: 22}},
			Remote:    model.NetEndpoint{Kind: model.NetRefZone, ZoneID: model.GuardZonePublic},
		}}}},
		Zones: zones,
		Reality: model.GuardNodeReality{
			NodeID: "node-a",
			Interfaces: []model.GuardInterface{
				{Name: "eth0", Addresses: []string{"192.0.2.10/24"}, Up: true},
				{Name: "tailscale0", Addresses: []string{"100.64.0.2/32"}, Up: true},
			},
			Listeners:  []model.GuardListener{{Protocol: model.NetProtoTCP, Port: 22, Address: "0.0.0.0", Process: "sshd"}},
			ManagedSHA: "same",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("clean intent produced suggestions: %+v", got)
	}
}

func suggestionIDs(suggestions []Suggestion) []string {
	ids := make([]string, 0, len(suggestions))
	for _, suggestion := range suggestions {
		ids = append(ids, suggestion.ID)
	}
	return ids
}

func assertSuggestion(t *testing.T, got Suggestion, code, zoneID, proto string, port int) {
	t.Helper()
	if got.Code != code {
		t.Fatalf("code = %q, want %q in %+v", got.Code, code, got)
	}
	if got.Severity != SeverityWarn {
		t.Fatalf("severity = %q, want %q in %+v", got.Severity, SeverityWarn, got)
	}
	if got.ZoneID != zoneID {
		t.Fatalf("zone id = %q, want %q in %+v", got.ZoneID, zoneID, got)
	}
	if got.Protocol != proto {
		t.Fatalf("protocol = %q, want %q in %+v", got.Protocol, proto, got)
	}
	if got.Port != port {
		t.Fatalf("port = %d, want %d in %+v", got.Port, port, got)
	}
	if got.Title == "" || got.Detail == "" {
		t.Fatalf("suggestion must carry title and detail: %+v", got)
	}
}
