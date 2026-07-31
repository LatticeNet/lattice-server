package netguard

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
)

const (
	SuggestionListenerMissingAllow       = "listener_missing_allow"
	SuggestionAllowWithoutListener       = "allow_without_listener"
	SuggestionOverlayListenerPublicAllow = "overlay_listener_public_allow"
	SuggestionOverlayZoneUntrusted       = "overlay_zone_untrusted"
	SuggestionManagedTableDrift          = "managed_table_drift"
)

const wildcardZone = "*"

// SuggestInput is the read-only state needed to compare operator intent with a
// low-trust node reality report. It intentionally contains no store, HTTP, or
// task-executor dependency so G3 can wire persistence and routes later without
// changing the core diff logic.
type SuggestInput struct {
	Binding model.NodeGuardBinding
	Groups  []model.SecurityGroup
	Zones   map[string]model.GuardZone
	Reality model.GuardNodeReality
}

// Suggestion is an operator-review prompt derived from reality. Suggestions
// are display/diff input only; accepting one is a later, audited mutation path.
type Suggestion struct {
	ID        string `json:"id"`
	Code      string `json:"code"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	ZoneID    string `json:"zone_id,omitempty"`
	Interface string `json:"interface,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Port      int    `json:"port,omitempty"`
	Address   string `json:"address,omitempty"`
	Process   string `json:"process,omitempty"`
}

// Suggest compares the node's current guard intent with the latest reality
// snapshot and emits deterministic, de-duplicated suggestions.
func Suggest(in SuggestInput) ([]Suggestion, error) {
	intent, err := indexIntent(in.Binding, in.Groups)
	if err != nil {
		return nil, err
	}
	reality := indexReality(in.Reality)

	var suggestions []Suggestion
	add := func(s Suggestion) {
		if s.Severity == "" {
			s.Severity = SeverityWarn
		}
		suggestions = append(suggestions, s)
	}

	if drifted(in.Binding.AppliedTableSHA, in.Reality.ManagedSHA) {
		add(Suggestion{
			ID:       suggestionID(in.Binding.NodeID, SuggestionManagedTableDrift),
			Code:     SuggestionManagedTableDrift,
			Title:    "Managed table drift detected",
			Detail:   "The live lattice_guard table hash differs from the last applied plan hash; review and re-apply the guard plan.",
			Severity: SeverityWarn,
		})
	}

	for _, overlay := range activeUntrustedOverlays(in.Zones, in.Binding.ZoneIDs, reality) {
		add(Suggestion{
			ID:        suggestionID(in.Binding.NodeID, SuggestionOverlayZoneUntrusted, overlay.zoneID),
			Code:      SuggestionOverlayZoneUntrusted,
			Title:     "Trust detected overlay zone",
			Detail:    fmt.Sprintf("%s is up but the %s zone is not trusted on this node; add the zone before relying on that overlay path.", overlay.iface, overlay.zoneID),
			ZoneID:    overlay.zoneID,
			Interface: overlay.iface,
		})
	}

	for _, listener := range normalizedListeners(in.Reality.Listeners) {
		zoneID, iface := listenerZone(listener, in.Zones, reality)
		if zoneID == model.GuardZoneLoopback {
			continue
		}
		key := serviceKey{proto: listener.Protocol, port: listener.Port}
		if intent.allows(zoneID, key) {
			continue
		}
		if isOverlayZone(zoneID) && intent.allows(model.GuardZonePublic, key) {
			add(Suggestion{
				ID:        suggestionID(in.Binding.NodeID, SuggestionOverlayListenerPublicAllow, zoneID, listener.Protocol, strconv.Itoa(listener.Port)),
				Code:      SuggestionOverlayListenerPublicAllow,
				Title:     "Move public allow to overlay zone",
				Detail:    fmt.Sprintf("%s/%d is bound to %s on %s; review whether the public allow should become a %s-zone rule.", listener.Protocol, listener.Port, listener.Address, iface, zoneID),
				ZoneID:    zoneID,
				Interface: iface,
				Protocol:  listener.Protocol,
				Port:      listener.Port,
				Address:   listener.Address,
				Process:   listener.Process,
			})
			continue
		}
		if zoneID == "" || zoneID == wildcardZone {
			zoneID = model.GuardZonePublic
		}
		add(Suggestion{
			ID:       suggestionID(in.Binding.NodeID, SuggestionListenerMissingAllow, zoneID, listener.Protocol, strconv.Itoa(listener.Port)),
			Code:     SuggestionListenerMissingAllow,
			Title:    "Listener has no matching allow",
			Detail:   fmt.Sprintf("%s/%d is listening on %s but no matching ingress allow was found; review whether to add it.", listener.Protocol, listener.Port, displayAddress(listener.Address)),
			ZoneID:   zoneID,
			Protocol: listener.Protocol,
			Port:     listener.Port,
			Address:  listener.Address,
			Process:  listener.Process,
		})
	}

	for _, allow := range intent.explicitAllows {
		if allow.zoneID == wildcardZone || allow.zoneID == model.GuardZoneLoopback {
			continue
		}
		if reality.hasListener(allow.serviceKey) {
			continue
		}
		add(Suggestion{
			ID:       suggestionID(in.Binding.NodeID, SuggestionAllowWithoutListener, allow.zoneID, allow.proto, strconv.Itoa(allow.port)),
			Code:     SuggestionAllowWithoutListener,
			Title:    "Allowed port has no listener",
			Detail:   fmt.Sprintf("%s/%d is allowed in the %s zone but no matching listener was reported; review whether the rule is stale.", allow.proto, allow.port, allow.zoneID),
			ZoneID:   allow.zoneID,
			Protocol: allow.proto,
			Port:     allow.port,
		})
	}

	return dedupeAndSortSuggestions(suggestions), nil
}

type serviceKey struct {
	proto string
	port  int
}

type zoneServiceKey struct {
	zoneID string
	serviceKey
}

type intentIndex struct {
	explicit       map[zoneServiceKey]struct{}
	allPorts       map[string]map[string]struct{}
	allProtocols   map[string]struct{}
	explicitAllows []zoneServiceKey
}

func indexIntent(binding model.NodeGuardBinding, groups []model.SecurityGroup) (intentIndex, error) {
	out := intentIndex{
		explicit:     map[zoneServiceKey]struct{}{},
		allPorts:     map[string]map[string]struct{}{},
		allProtocols: map[string]struct{}{},
	}
	if err := addIntentRules(&out, binding.Overrides); err != nil {
		return intentIndex{}, err
	}
	for _, group := range groups {
		if err := addIntentRules(&out, group.Rules); err != nil {
			return intentIndex{}, err
		}
	}
	out.explicitAllows = sortedZoneServiceKeys(out.explicitAllows)
	return out, nil
}

func addIntentRules(out *intentIndex, rules []model.GuardRule) error {
	for _, rule := range rules {
		if rule.Disabled || rule.Action != model.NetRuleAllow || rule.Direction != model.NetDirIngress {
			continue
		}
		zones, staleCandidate := intentZones(rule.Remote)
		if len(zones) == 0 {
			continue
		}
		ports, err := ExpandPortRanges(rule.Ports)
		if err != nil {
			return fmt.Errorf("rule %q: %w", rule.ID, err)
		}
		switch rule.Protocol {
		case model.NetProtoTCP, model.NetProtoUDP:
		case model.NetProtoAny:
			if len(ports) > 0 {
				return fmt.Errorf("rule %q: protocol any cannot carry ports", rule.ID)
			}
		default:
			return fmt.Errorf("rule %q: invalid protocol %q", rule.ID, rule.Protocol)
		}
		for _, zoneID := range zones {
			if rule.Protocol == model.NetProtoAny {
				out.allProtocols[zoneID] = struct{}{}
				continue
			}
			if len(ports) == 0 {
				if out.allPorts[zoneID] == nil {
					out.allPorts[zoneID] = map[string]struct{}{}
				}
				out.allPorts[zoneID][rule.Protocol] = struct{}{}
				continue
			}
			for _, port := range ports {
				key := zoneServiceKey{zoneID: zoneID, serviceKey: serviceKey{proto: rule.Protocol, port: port}}
				out.explicit[key] = struct{}{}
				if staleCandidate {
					out.explicitAllows = append(out.explicitAllows, key)
				}
			}
		}
	}
	return nil
}

func intentZones(remote model.NetEndpoint) ([]string, bool) {
	switch remote.Kind {
	case model.NetRefZone:
		if remote.ZoneID == "" {
			return nil, false
		}
		return []string{remote.ZoneID}, true
	case model.NetRefAny, "":
		return []string{wildcardZone}, true
	case model.NetRefCIDR, model.NetRefNode, model.NetRefGroup:
		return []string{wildcardZone}, false
	default:
		return nil, false
	}
}

func (i intentIndex) allows(zoneID string, key serviceKey) bool {
	for _, candidate := range []string{zoneID, wildcardZone} {
		if _, ok := i.allProtocols[candidate]; ok {
			return true
		}
		if protos := i.allPorts[candidate]; protos != nil {
			if _, ok := protos[key.proto]; ok {
				return true
			}
		}
		if _, ok := i.explicit[zoneServiceKey{zoneID: candidate, serviceKey: key}]; ok {
			return true
		}
	}
	return false
}

type realityIndex struct {
	interfaces []interfaceFacts
	listeners  map[serviceKey]struct{}
}

type interfaceFacts struct {
	name     string
	up       bool
	prefixes []netip.Prefix
}

func indexReality(reality model.GuardNodeReality) realityIndex {
	out := realityIndex{listeners: map[serviceKey]struct{}{}}
	for _, iface := range reality.Interfaces {
		facts := interfaceFacts{name: strings.TrimSpace(iface.Name), up: iface.Up}
		if facts.name == "" {
			continue
		}
		for _, raw := range iface.Addresses {
			if prefix, ok := parsePrefix(raw); ok {
				facts.prefixes = append(facts.prefixes, prefix)
			}
		}
		sort.Slice(facts.prefixes, func(i, j int) bool {
			if facts.prefixes[i].Bits() != facts.prefixes[j].Bits() {
				return facts.prefixes[i].Bits() > facts.prefixes[j].Bits()
			}
			return facts.prefixes[i].String() < facts.prefixes[j].String()
		})
		out.interfaces = append(out.interfaces, facts)
	}
	sort.Slice(out.interfaces, func(i, j int) bool { return out.interfaces[i].name < out.interfaces[j].name })
	for _, listener := range normalizedListeners(reality.Listeners) {
		out.listeners[serviceKey{proto: listener.Protocol, port: listener.Port}] = struct{}{}
	}
	return out
}

func (r realityIndex) hasListener(key serviceKey) bool {
	_, ok := r.listeners[key]
	return ok
}

func (r realityIndex) interfaceUp(name string) bool {
	for _, iface := range r.interfaces {
		if iface.name == name && iface.up {
			return true
		}
	}
	return false
}

func (r realityIndex) interfaceForAddress(addr netip.Addr) string {
	for _, iface := range r.interfaces {
		for _, prefix := range iface.prefixes {
			if prefix.Addr() == addr {
				return iface.name
			}
		}
	}
	bestName := ""
	bestBits := -1
	for _, iface := range r.interfaces {
		for _, prefix := range iface.prefixes {
			if prefix.Contains(addr) && prefix.Bits() > bestBits {
				bestName = iface.name
				bestBits = prefix.Bits()
			}
		}
	}
	return bestName
}

func normalizedListeners(listeners []model.GuardListener) []model.GuardListener {
	out := make([]model.GuardListener, 0, len(listeners))
	for _, listener := range listeners {
		listener.Protocol = strings.ToLower(strings.TrimSpace(listener.Protocol))
		listener.Address = strings.TrimSpace(listener.Address)
		listener.Process = strings.TrimSpace(listener.Process)
		if listener.Port < 1 || listener.Port > 65535 {
			continue
		}
		switch listener.Protocol {
		case model.NetProtoTCP, model.NetProtoUDP:
			out = append(out, listener)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return listenerSortKey(out[i]) < listenerSortKey(out[j])
	})
	return out
}

func listenerSortKey(listener model.GuardListener) string {
	return listener.Protocol + ":" + fmt.Sprintf("%05d", listener.Port) + ":" + listener.Address + ":" + listener.Process
}

func listenerZone(listener model.GuardListener, zones map[string]model.GuardZone, reality realityIndex) (string, string) {
	addr, ok := parseAddr(listener.Address)
	if !ok || addr.IsUnspecified() {
		return model.GuardZonePublic, ""
	}
	if addr.IsLoopback() {
		return model.GuardZoneLoopback, "lo"
	}
	iface := reality.interfaceForAddress(addr)
	if zoneID := zoneForInterface(zones, iface); zoneID != "" {
		return zoneID, iface
	}
	if zoneID := zoneForAddress(zones, addr); zoneID != "" {
		return zoneID, iface
	}
	return model.GuardZonePublic, iface
}

func zoneForInterface(zones map[string]model.GuardZone, iface string) string {
	if iface == "" {
		return ""
	}
	for _, preferred := range []string{model.GuardZoneLoopback, model.GuardZonePublic, model.GuardZoneWireGuard, model.GuardZoneTailscale} {
		if zoneHasInterface(zones[preferred], iface) {
			return preferred
		}
	}
	ids := make([]string, 0, len(zones))
	for id := range zones {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if zoneHasInterface(zones[id], iface) {
			return id
		}
	}
	return ""
}

func zoneHasInterface(zone model.GuardZone, iface string) bool {
	for _, candidate := range zone.Interfaces {
		if candidate == iface {
			return true
		}
	}
	return false
}

func zoneForAddress(zones map[string]model.GuardZone, addr netip.Addr) string {
	bestID := ""
	bestBits := -1
	for _, id := range zoneIDsByPriority(zones) {
		for _, raw := range zones[id].CIDRs {
			prefix, ok := parsePrefix(raw)
			if !ok || !prefix.Contains(addr) {
				continue
			}
			if bits := prefix.Bits(); bits > bestBits {
				bestID = id
				bestBits = bits
			}
		}
	}
	return bestID
}

type overlayInterface struct {
	zoneID string
	iface  string
}

func activeUntrustedOverlays(zones map[string]model.GuardZone, trustedZones []string, reality realityIndex) []overlayInterface {
	trusted := map[string]struct{}{}
	for _, zoneID := range trustedZones {
		trusted[zoneID] = struct{}{}
	}
	var out []overlayInterface
	for _, zoneID := range []string{model.GuardZoneWireGuard, model.GuardZoneTailscale} {
		if _, ok := trusted[zoneID]; ok {
			continue
		}
		zone, ok := zones[zoneID]
		if !ok {
			continue
		}
		found := false
		for _, iface := range sortedStrings(zone.Interfaces) {
			if reality.interfaceUp(iface) {
				out = append(out, overlayInterface{zoneID: zoneID, iface: iface})
				found = true
				break
			}
		}
		if found {
			continue
		}
		if iface := reality.interfaceInCIDRs(zone.CIDRs); iface != "" {
			out = append(out, overlayInterface{zoneID: zoneID, iface: iface})
		}
	}
	return out
}

func isOverlayZone(zoneID string) bool {
	return zoneID == model.GuardZoneWireGuard || zoneID == model.GuardZoneTailscale
}

func drifted(applied, managed string) bool {
	applied = strings.TrimSpace(applied)
	managed = strings.TrimSpace(managed)
	return applied != "" && managed != "" && applied != managed
}

func parseAddr(raw string) (netip.Addr, bool) {
	value := strings.Trim(strings.TrimSpace(raw), "[]")
	if value == "" || value == "*" {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(value)
	return addr, err == nil
}

func parsePrefix(raw string) (netip.Prefix, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return netip.Prefix{}, false
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked(), true
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, false
	}
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(addr, bits), true
}

func dedupeAndSortSuggestions(in []Suggestion) []Suggestion {
	byID := make(map[string]Suggestion, len(in))
	for _, suggestion := range in {
		if suggestion.ID == "" {
			continue
		}
		byID[suggestion.ID] = suggestion
	}
	out := make([]Suggestion, 0, len(byID))
	for _, suggestion := range byID {
		out = append(out, suggestion)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func suggestionID(nodeID, code string, parts ...string) string {
	values := []string{strings.TrimSpace(nodeID), code}
	values = append(values, parts...)
	return strings.Join(values, ":")
}

func displayAddress(addr string) string {
	if strings.TrimSpace(addr) == "" {
		return "an unspecified address"
	}
	return addr
}

func sortedZoneServiceKeys(keys []zoneServiceKey) []zoneServiceKey {
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].zoneID != keys[j].zoneID {
			return keys[i].zoneID < keys[j].zoneID
		}
		if keys[i].proto != keys[j].proto {
			return keys[i].proto < keys[j].proto
		}
		return keys[i].port < keys[j].port
	})
	return keys
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func (r realityIndex) interfaceInCIDRs(cidrs []string) string {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, raw := range cidrs {
		if prefix, ok := parsePrefix(raw); ok {
			prefixes = append(prefixes, prefix)
		}
	}
	if len(prefixes) == 0 {
		return ""
	}
	for _, iface := range r.interfaces {
		if !iface.up {
			continue
		}
		for _, ifacePrefix := range iface.prefixes {
			for _, zonePrefix := range prefixes {
				if zonePrefix.Contains(ifacePrefix.Addr()) {
					return iface.name
				}
			}
		}
	}
	return ""
}

func zoneIDsByPriority(zones map[string]model.GuardZone) []string {
	seen := map[string]struct{}{}
	ids := make([]string, 0, len(zones))
	for _, id := range []string{model.GuardZoneLoopback, model.GuardZonePublic, model.GuardZoneWireGuard, model.GuardZoneTailscale} {
		if _, ok := zones[id]; ok {
			ids = append(ids, id)
			seen[id] = struct{}{}
		}
	}
	custom := make([]string, 0, len(zones))
	for id := range zones {
		if _, ok := seen[id]; ok {
			continue
		}
		custom = append(custom, id)
	}
	sort.Strings(custom)
	return append(ids, custom...)
}
