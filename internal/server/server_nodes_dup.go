package server

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Duplicate-node detection. The hard part (operator's note): a single public IP
// is NOT a reliable key, because NAT hosts and many small containers legitimately
// share one public IPv4. So we cluster on signals that survive NAT and identify
// the SAME machine re-enrolled, never on public IP alone:
//
//   - wireguard_key: identical WireGuard public key — near-certain same node.
//   - public_internal_ip: identical public IP AND identical internal/LAN IP.
//     Distinct NAT containers share the public IP but get different internal
//     IPs, so a match on BOTH means the same host (only one machine can hold a
//     given LAN address behind a given NAT). High confidence.
//   - host_fingerprint: identical hostname + CPU model/cores + total memory +
//     virtualization. Catches a machine re-enrolled under a new node id; medium
//     confidence because default/identical images can collide.
//
// It is detection, not a block: enrollment still succeeds and the operator
// decides (a deliberate replace vs an accidental double-enroll).

type duplicateGroup struct {
	Reason     string   `json:"reason"`     // wireguard_key | public_internal_ip | host_fingerprint
	Confidence string   `json:"confidence"` // high | medium
	Signal     string   `json:"signal"`     // human-readable shared value (sensitive parts shortened)
	NodeIDs    []string `json:"node_ids"`
}

func detectDuplicateNodes(nodes []model.Node) []duplicateGroup {
	byWG := map[string][]string{}
	byIPPair := map[string][]string{}
	byFP := map[string][]string{}
	fpSignal := map[string]string{}

	for _, n := range nodes {
		if n.Disabled {
			continue // a disabled node is intentionally retired; don't flag it
		}
		if k := strings.TrimSpace(n.WireGuardPublicKey); k != "" {
			byWG[k] = append(byWG[k], n.ID)
		}
		if pair := ipPairKey(n); pair != "" {
			byIPPair[pair] = append(byIPPair[pair], n.ID)
		}
		if fp, sig := hostFingerprint(n); fp != "" {
			byFP[fp] = append(byFP[fp], n.ID)
			fpSignal[fp] = sig
		}
	}

	var groups []duplicateGroup
	emit := func(reason, confidence string, m map[string][]string, signalFor func(key string) string) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			ids := m[k]
			if len(ids) < 2 {
				continue
			}
			sort.Strings(ids)
			groups = append(groups, duplicateGroup{
				Reason:     reason,
				Confidence: confidence,
				Signal:     signalFor(k),
				NodeIDs:    ids,
			})
		}
	}

	emit("wireguard_key", "high", byWG, shortSignal)
	emit("public_internal_ip", "high", byIPPair, func(k string) string { return k })
	emit("host_fingerprint", "medium", byFP, func(k string) string { return fpSignal[k] })
	return groups
}

// ipPairKey returns "public|internal" only when both are present and the internal
// address is a real (non-loopback/non-unspecified) address. Empty otherwise, so
// a node with only a public IP never contributes a key (NAT-safe).
func ipPairKey(n model.Node) string {
	pub := strings.TrimSpace(n.PublicIP)
	in := strings.TrimSpace(n.InternalIP)
	if pub == "" || in == "" {
		return ""
	}
	if addr, err := netip.ParseAddr(in); err != nil || addr.IsLoopback() || addr.IsUnspecified() {
		return ""
	}
	return pub + "|" + in
}

// hostFingerprint returns a stable hash of distinguishing host facts plus a
// human-readable signal. It requires enough facts (hostname + CPU model + memory)
// to avoid clustering bare/just-enrolled nodes that have no facts yet.
func hostFingerprint(n model.Node) (string, string) {
	hf := n.HostFacts
	host := strings.ToLower(strings.TrimSpace(hf.Hostname))
	if host == "" || strings.TrimSpace(hf.CPUModel) == "" || hf.MemoryTotal == 0 {
		return "", ""
	}
	parts := []string{
		host,
		strings.TrimSpace(hf.CPUModel),
		strconv.Itoa(hf.CPUCores),
		strconv.FormatUint(hf.MemoryTotal, 10),
		strings.TrimSpace(hf.Virtualization),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:]), host
}

// shortSignal trims a sensitive value (e.g. a key) for display.
func shortSignal(v string) string {
	if len(v) <= 12 {
		return v
	}
	return v[:12] + "…"
}

func (s *Server) handleNodeDuplicates(w http.ResponseWriter, _ *http.Request, p principal) {
	if !s.requireScope(w, p, "node:read") {
		return
	}
	groups := detectDuplicateNodes(s.store.Nodes())
	if groups == nil {
		groups = []duplicateGroup{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups})
}
