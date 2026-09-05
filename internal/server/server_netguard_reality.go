package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

const (
	guardRealityFutureSlack       = 5 * time.Minute
	guardRealityStaleAfter        = 30 * time.Hour
	guardRealityDefaultLimit      = 100
	guardRealityMaxLimit          = 500
	guardRealityMaxListeners      = 4096
	guardRealityMaxInterfaces     = 256
	guardRealityMaxIfaceAddresses = 64
	guardRealityMaxForeignTables  = 512
	guardRealityMaxStringBytes    = 256
	guardRealityMaxIfaceNameBytes = 64
	// sshd accepts any number of Port and ListenAddress lines; a report
	// carrying more than this says something is wrong on the node, and the
	// SSH Guard columns could not print it anyway.
	guardRealityMaxSSHDPorts           = 64
	guardRealityMaxSSHDListenAddresses = 64
	// The agent's refusal note quotes the failed rule and, for a command
	// failure, the bounded stderr; 512 bytes holds that with room to spare.
	guardRealityMaxSSHDNoteBytes = 512
)

type guardRealityResponse struct {
	OK                 bool      `json:"ok"`
	NodeID             string    `json:"node_id"`
	CollectedAt        time.Time `json:"collected_at"`
	ReceivedAt         time.Time `json:"received_at"`
	CollectedAtClamped bool      `json:"collected_at_clamped"`
}

// guardRealitySummary is one row of the fleet posture table.
//
// Every field an operator needs to triage a fleet is here on purpose. Drift
// used to be computable only through the per-node review method, so a
// fleet-wide "which of my nodes drifted" question cost one request per node
// and no surface asked it. Answering it here makes the posture view a single
// call and removes the incentive to render a green fleet nobody checked.
type guardRealitySummary struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name,omitempty"`
	// SnapshotStatus is unknown (never reported), fresh, or stale.
	SnapshotStatus string `json:"snapshot_status"`
	// DriftState is unknown, in_sync, or drift, computed exactly as the
	// per-node review computes it. "unknown" covers both "never reported" and
	// "never applied": calling either of those in_sync would be the most
	// dangerous label in the product.
	DriftState        string     `json:"drift_state"`
	Managed           bool       `json:"managed"`
	HasBinding        bool       `json:"has_binding"`
	CollectedAt       *time.Time `json:"collected_at,omitempty"`
	ReceivedAt        *time.Time `json:"received_at,omitempty"`
	StaleAfter        *time.Time `json:"stale_after,omitempty"`
	ManagedSHA        *string    `json:"managed_sha,omitempty"`
	AppliedTableSHA   string     `json:"applied_table_sha,omitempty"`
	LastAppliedAt     *time.Time `json:"last_applied_at,omitempty"`
	LastError         string     `json:"last_error,omitempty"`
	ListenerCount     *int       `json:"listener_count,omitempty"`
	InterfaceCount    *int       `json:"interface_count,omitempty"`
	ForeignTableCount *int       `json:"foreign_table_count,omitempty"`
}

type guardRealityListResponse struct {
	Nodes      []guardRealitySummary `json:"nodes"`
	NextCursor string                `json:"next_cursor,omitempty"`
}

type guardRealityDetailResponse struct {
	Node guardRealityDetail `json:"node"`
}

type guardRealityDetail struct {
	NodeID         string                  `json:"node_id"`
	SnapshotStatus string                  `json:"snapshot_status"`
	Reality        *model.GuardNodeReality `json:"reality"`
	ReceivedAt     *time.Time              `json:"received_at"`
	StaleAfter     *time.Time              `json:"stale_after"`
	// KnockGate is true when the report lists the inet lattice_knock table:
	// SSH Guard's gate is on the node right now, whoever put it there. It is
	// the same fact the SSH Guard posture row prints, repeated here because
	// the exposure view is built from this record and a gated sshd port that
	// it rendered as open to the internet was the most visible lie in the
	// product.
	KnockGate bool `json:"knock_gate"`
	// KnockGatedPorts are the tcp ports the gate covers: the ports the arm
	// plan that reached the node gated, or, when no plan of ours put the
	// table there, the ports sshd reports, which is what the gate is built
	// for. Empty with KnockGate set means the table is there and its scope
	// is not known.
	KnockGatedPorts []int `json:"knock_gated_ports,omitempty"`
}

func (s *Server) handleAgentGuardReality(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		agentAuthRequest
		Reality model.GuardNodeReality `json:"reality"`
	}
	if !decodeAgentJSON(w, r, &req) {
		return
	}
	req.NodeID = strings.TrimSpace(req.NodeID)
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, apiError(model.APIErrorBadRequest, "node_id is required"))
		return
	}
	node, ok := s.authenticateAgentRequest(r, req.NodeID)
	if !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	if realityNodeID := strings.TrimSpace(req.Reality.NodeID); realityNodeID != "" && realityNodeID != node.ID {
		writeError(w, http.StatusBadRequest, apiError(model.APIErrorBadRequest, "reality node_id does not match authenticated node"))
		return
	}
	req.Reality.NodeID = node.ID
	receivedAt := s.now().UTC()
	reality, clamped, err := normalizeGuardReality(req.Reality, receivedAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, apiError(model.APIErrorBadRequest, err.Error()))
		return
	}
	stored, _, err := s.store.UpsertGuardRealitySnapshot(node.LatticeIdentityUUID, store.GuardRealitySnapshot{
		Reality:    reality,
		ReceivedAt: receivedAt,
	})
	if errors.Is(err, store.ErrGuardRealityDurabilityDegraded) {
		if s.logger != nil {
			s.logger.Printf("guard reality committed with degraded durability: node_id=%s: %v", node.ID, err)
		}
		err = nil
	}
	if errors.Is(err, store.ErrGuardRealityNodeChanged) {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	if errors.Is(err, store.ErrGuardRealityStale) {
		writeError(w, http.StatusConflict, apiError("guard_reality_stale", "guard reality snapshot is stale"))
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if s.shouldAuditGuardReality(node.ID, stored.Reality, s.now()) {
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			Action:   "netguard.reality.report",
			Decision: "allow",
			NodeID:   node.ID,
			Metadata: map[string]string{
				"listener_count":      strconv.Itoa(len(stored.Reality.Listeners)),
				"interface_count":     strconv.Itoa(len(stored.Reality.Interfaces)),
				"foreign_table_count": strconv.Itoa(len(stored.Reality.ForeignTables)),
			},
		})
	}
	writeJSON(w, http.StatusOK, guardRealityResponse{
		OK:                 true,
		NodeID:             node.ID,
		CollectedAt:        stored.Reality.CollectedAt,
		ReceivedAt:         stored.ReceivedAt,
		CollectedAtClamped: clamped,
	})
}

func (s *Server) handleNetGuardReality(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireScope(w, p, "netguard:read") {
		return
	}
	q := r.URL.Query()
	nodeID := strings.TrimSpace(q.Get("node_id"))
	if nodeID != "" {
		if q.Get("cursor") != "" || q.Get("limit") != "" {
			writeError(w, http.StatusBadRequest, apiError(model.APIErrorBadRequest, "node_id cannot be combined with pagination"))
			return
		}
		if _, ok := s.store.Node(nodeID); !ok || !rbac.Allows(p.Principal, "netguard:read", nodeID) {
			writeError(w, http.StatusNotFound, apiError(model.APIErrorNotFound, "not found"))
			return
		}
		writeJSON(w, http.StatusOK, guardRealityDetailResponse{
			Node: s.guardRealityDetailForNode(nodeID, s.now().UTC()),
		})
		return
	}
	limit, err := parseGuardRealityLimit(q.Get("limit"))
	if err != nil {
		writeError(w, http.StatusBadRequest, apiError(model.APIErrorBadRequest, err.Error()))
		return
	}
	afterNodeID := ""
	if cursor := strings.TrimSpace(q.Get("cursor")); cursor != "" {
		afterNodeID, err = decodeGuardRealityCursor(cursor)
		if err != nil {
			writeError(w, http.StatusBadRequest, apiError(model.APIErrorBadRequest, "invalid cursor"))
			return
		}
	}
	nodes := s.visibleGuardRealityNodes(p)
	start := sort.Search(len(nodes), func(i int) bool {
		return nodes[i].ID > afterNodeID
	})
	if afterNodeID == "" {
		start = 0
	}
	end := start + limit
	if end > len(nodes) {
		end = len(nodes)
	}
	now := s.now().UTC()
	out := make([]guardRealitySummary, 0, end-start)
	for _, node := range nodes[start:end] {
		out = append(out, s.guardRealitySummaryForNode(node.ID, node.Name, now))
	}
	resp := guardRealityListResponse{Nodes: out}
	if end < len(nodes) && len(out) > 0 {
		resp.NextCursor = encodeGuardRealityCursor(out[len(out)-1].NodeID)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) visibleGuardRealityNodes(p principal) []model.Node {
	nodes := s.store.Nodes()
	out := nodes[:0]
	for _, node := range nodes {
		if rbac.Allows(p.Principal, "netguard:read", node.ID) {
			out = append(out, node)
		}
	}
	return out
}

func (s *Server) guardRealitySummaryForNode(nodeID, nodeName string, now time.Time) guardRealitySummary {
	out := guardRealitySummary{
		NodeID:         nodeID,
		NodeName:       nodeName,
		SnapshotStatus: "unknown",
		DriftState:     netGuardDriftUnknown,
	}
	binding, hasBinding := s.store.NodeGuardBinding(nodeID)
	if hasBinding {
		out.HasBinding = true
		out.Managed = binding.Managed
		out.AppliedTableSHA = binding.AppliedTableSHA
		out.LastError = binding.LastError
		if !binding.LastAppliedAt.IsZero() {
			lastAppliedAt := binding.LastAppliedAt.UTC()
			out.LastAppliedAt = &lastAppliedAt
		}
	}
	snapshot, ok := s.store.GuardRealitySnapshot(nodeID)
	if !ok {
		return out
	}
	status, staleAfter := guardRealityFreshness(snapshot, now)
	managedSHA := snapshot.Reality.ManagedSHA
	listenerCount := len(snapshot.Reality.Listeners)
	interfaceCount := len(snapshot.Reality.Interfaces)
	foreignTableCount := len(snapshot.Reality.ForeignTables)
	collectedAt := snapshot.Reality.CollectedAt.UTC()
	receivedAt := snapshot.ReceivedAt.UTC()
	out.SnapshotStatus = status
	out.CollectedAt = &collectedAt
	out.ReceivedAt = &receivedAt
	out.StaleAfter = &staleAfter
	out.ManagedSHA = &managedSHA
	out.ListenerCount = &listenerCount
	out.InterfaceCount = &interfaceCount
	out.ForeignTableCount = &foreignTableCount
	if hasBinding {
		out.DriftState = netGuardDriftState(binding, &snapshot.Reality)
	}
	return out
}

// guardRealityForLint hands the plan path the node's last reported reality, or
// nil when the node has never reported one. nil is the honest input: the lint
// then says out loud that it is assuming the management port rather than
// silently checking the wrong one.
func (s *Server) guardRealityForLint(nodeID string) *model.GuardNodeReality {
	snapshot, ok := s.store.GuardRealitySnapshot(nodeID)
	if !ok {
		return nil
	}
	reality := snapshot.Reality
	return &reality
}

func (s *Server) guardRealityDetailForNode(nodeID string, now time.Time) guardRealityDetail {
	snapshot, ok := s.store.GuardRealitySnapshot(nodeID)
	if !ok {
		return guardRealityDetail{
			NodeID:         nodeID,
			SnapshotStatus: "unknown",
			Reality:        nil,
			ReceivedAt:     nil,
			StaleAfter:     nil,
		}
	}
	status, staleAfter := guardRealityFreshness(snapshot, now)
	reality := snapshot.Reality
	receivedAt := snapshot.ReceivedAt.UTC()
	detail := guardRealityDetail{
		NodeID:         nodeID,
		SnapshotStatus: status,
		Reality:        &reality,
		ReceivedAt:     &receivedAt,
		StaleAfter:     &staleAfter,
		KnockGate:      sshGuardKnockGate(&reality),
	}
	if detail.KnockGate {
		detail.KnockGatedPorts = s.sshGuardGatedPorts(nodeID, &reality)
	}
	return detail
}

// sshGuardGatedPorts reports which tcp ports the node's knock table covers.
//
// The table's rules are not in the report, only its name, so the scope comes
// from the arm plan that governs the node's knock (the one that carried a
// firewall and reached the node, exactly as the SSH Guard status picks it).
// A table this system never installed is read the way SSH Guard builds one:
// it gates what sshd listens on. No sshd facts means no claim.
func (s *Server) sshGuardGatedPorts(nodeID string, reality *model.GuardNodeReality) []int {
	ks := s.sshGuardKnockStateFor(nodeID)
	switch ks.Knowledge {
	case knockInstalled, knockInstalledSuperseded, knockNoKnock:
		if len(ks.GatedPorts) > 0 {
			return append([]int(nil), ks.GatedPorts...)
		}
	}
	if reality == nil || reality.SSHD == nil || len(reality.SSHD.Ports) == 0 {
		return nil
	}
	return append([]int(nil), reality.SSHD.Ports...)
}

func guardRealityFreshness(snapshot store.GuardRealitySnapshot, now time.Time) (string, time.Time) {
	staleAfter := snapshot.Reality.CollectedAt.UTC().Add(guardRealityStaleAfter)
	if !now.UTC().Before(staleAfter) {
		return "stale", staleAfter
	}
	return "fresh", staleAfter
}

func parseGuardRealityLimit(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return guardRealityDefaultLimit, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 || limit > guardRealityMaxLimit {
		return 0, fmt.Errorf("limit must be 1-%d", guardRealityMaxLimit)
	}
	return limit, nil
}

func encodeGuardRealityCursor(nodeID string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(nodeID))
}

func decodeGuardRealityCursor(raw string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(decoded) == 0 {
		return "", errors.New("invalid cursor")
	}
	nodeID := string(decoded)
	if !utf8.ValidString(nodeID) || strings.TrimSpace(nodeID) == "" {
		return "", errors.New("invalid cursor")
	}
	return nodeID, nil
}

func normalizeGuardReality(reality model.GuardNodeReality, receivedAt time.Time) (model.GuardNodeReality, bool, error) {
	reality.NodeID = strings.TrimSpace(reality.NodeID)
	if reality.NodeID == "" {
		return model.GuardNodeReality{}, false, errors.New("node_id is required")
	}
	if reality.CollectedAt.IsZero() {
		return model.GuardNodeReality{}, false, errors.New("collected_at is required")
	}
	collectedAtClamped := false
	reality.CollectedAt = reality.CollectedAt.UTC()
	if reality.CollectedAt.After(receivedAt.UTC().Add(guardRealityFutureSlack)) {
		reality.CollectedAt = receivedAt.UTC()
		collectedAtClamped = true
	}
	if len(reality.Listeners) > guardRealityMaxListeners {
		return model.GuardNodeReality{}, false, fmt.Errorf("listeners must contain at most %d entries", guardRealityMaxListeners)
	}
	if len(reality.Interfaces) > guardRealityMaxInterfaces {
		return model.GuardNodeReality{}, false, fmt.Errorf("interfaces must contain at most %d entries", guardRealityMaxInterfaces)
	}
	if len(reality.ForeignTables) > guardRealityMaxForeignTables {
		return model.GuardNodeReality{}, false, fmt.Errorf("foreign_tables must contain at most %d entries", guardRealityMaxForeignTables)
	}
	if err := normalizeGuardRealityListeners(reality.Listeners); err != nil {
		return model.GuardNodeReality{}, false, err
	}
	if err := normalizeGuardRealityInterfaces(reality.Interfaces); err != nil {
		return model.GuardNodeReality{}, false, err
	}
	if err := normalizeGuardRealityForeignTables(reality.ForeignTables); err != nil {
		return model.GuardNodeReality{}, false, err
	}
	managedSHA, err := normalizePrintableString(reality.ManagedSHA, "managed_sha", guardRealityMaxStringBytes, false)
	if err != nil {
		return model.GuardNodeReality{}, false, err
	}
	if managedSHA != "" && !isLowerHex64(managedSHA) {
		return model.GuardNodeReality{}, false, errors.New("managed_sha must be empty or 64 lowercase hex characters")
	}
	nftVersion, err := normalizePrintableString(reality.NFTVersion, "nft_version", guardRealityMaxStringBytes, false)
	if err != nil {
		return model.GuardNodeReality{}, false, err
	}
	reality.ManagedSHA = managedSHA
	reality.NFTVersion = nftVersion
	// sshd facts are optional on the wire: an agent that predates them sends
	// neither key and must keep reporting exactly as before, and a current
	// agent that refused sends only the note.
	sshdNote, err := normalizePrintableString(reality.SSHDNote, "sshd_note", guardRealityMaxSSHDNoteBytes, false)
	if err != nil {
		return model.GuardNodeReality{}, false, err
	}
	reality.SSHDNote = sshdNote
	if reality.SSHD != nil {
		sshd, err := normalizeGuardRealitySSHD(*reality.SSHD, receivedAt)
		if err != nil {
			return model.GuardNodeReality{}, false, err
		}
		reality.SSHD = &sshd
	}
	return reality, collectedAtClamped, nil
}

// normalizeGuardRealitySSHD bounds the sshd facts the way the listeners are
// bounded. observed_at is clamped like collected_at, so an agent clock in the
// future cannot make a fact look fresher than the report that carried it.
func normalizeGuardRealitySSHD(sshd model.GuardSSHDFacts, receivedAt time.Time) (model.GuardSSHDFacts, error) {
	if sshd.ObservedAt.IsZero() {
		return model.GuardSSHDFacts{}, errors.New("sshd.observed_at is required")
	}
	sshd.ObservedAt = sshd.ObservedAt.UTC()
	if sshd.ObservedAt.After(receivedAt.UTC().Add(guardRealityFutureSlack)) {
		sshd.ObservedAt = receivedAt.UTC()
	}
	if len(sshd.Ports) == 0 {
		return model.GuardSSHDFacts{}, errors.New("sshd.ports must contain at least one port")
	}
	if len(sshd.Ports) > guardRealityMaxSSHDPorts {
		return model.GuardSSHDFacts{}, fmt.Errorf("sshd.ports must contain at most %d entries", guardRealityMaxSSHDPorts)
	}
	for _, port := range sshd.Ports {
		if port < 1 || port > 65535 {
			return model.GuardSSHDFacts{}, errors.New("sshd.ports must be 1-65535")
		}
	}
	permitRootLogin, err := normalizePrintableString(sshd.PermitRootLogin, "sshd.permit_root_login", guardRealityMaxStringBytes, true)
	if err != nil {
		return model.GuardSSHDFacts{}, err
	}
	sshd.PermitRootLogin = permitRootLogin
	if sshd.MaxAuthTries < 0 {
		return model.GuardSSHDFacts{}, errors.New("sshd.max_auth_tries must not be negative")
	}
	if len(sshd.ListenAddresses) > guardRealityMaxSSHDListenAddresses {
		return model.GuardSSHDFacts{}, fmt.Errorf("sshd.listen_addresses must contain at most %d entries", guardRealityMaxSSHDListenAddresses)
	}
	for i := range sshd.ListenAddresses {
		address, err := normalizePrintableString(sshd.ListenAddresses[i], "sshd.listen_addresses", guardRealityMaxStringBytes, true)
		if err != nil {
			return model.GuardSSHDFacts{}, err
		}
		sshd.ListenAddresses[i] = address
	}
	return sshd, nil
}

func normalizeGuardRealityListeners(listeners []model.GuardListener) error {
	for i := range listeners {
		protocol, err := normalizePrintableString(listeners[i].Protocol, "listeners.protocol", guardRealityMaxStringBytes, true)
		if err != nil {
			return err
		}
		if protocol != "tcp" && protocol != "udp" {
			return errors.New("listeners.protocol must be tcp or udp")
		}
		if listeners[i].Port < 1 || listeners[i].Port > 65535 {
			return errors.New("listeners.port must be 1-65535")
		}
		address, err := normalizeGuardRealityAddress(listeners[i].Address, "listeners.address", false)
		if err != nil {
			return err
		}
		process, err := normalizePrintableString(listeners[i].Process, "listeners.process", guardRealityMaxStringBytes, false)
		if err != nil {
			return err
		}
		listeners[i].Protocol = protocol
		listeners[i].Address = address
		listeners[i].Process = process
	}
	return nil
}

func normalizeGuardRealityInterfaces(interfaces []model.GuardInterface) error {
	for i := range interfaces {
		name, err := normalizePrintableString(interfaces[i].Name, "interfaces.name", guardRealityMaxIfaceNameBytes, true)
		if err != nil {
			return err
		}
		if len(interfaces[i].Addresses) > guardRealityMaxIfaceAddresses {
			return fmt.Errorf("interfaces.addresses must contain at most %d entries", guardRealityMaxIfaceAddresses)
		}
		for j := range interfaces[i].Addresses {
			address, err := normalizeGuardRealityAddress(interfaces[i].Addresses[j], "interfaces.addresses", true)
			if err != nil {
				return err
			}
			interfaces[i].Addresses[j] = address
		}
		interfaces[i].Name = name
	}
	return nil
}

func normalizeGuardRealityForeignTables(tables []string) error {
	for i := range tables {
		table, err := normalizePrintableString(tables[i], "foreign_tables", guardRealityMaxStringBytes, true)
		if err != nil {
			return err
		}
		tables[i] = table
	}
	return nil
}

func normalizeGuardRealityAddress(value, field string, required bool) (string, error) {
	value, err := normalizePrintableString(value, field, guardRealityMaxStringBytes, required)
	if err != nil || value == "" {
		return value, err
	}
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return "", fmt.Errorf("%s must be an IP address or prefix", field)
		}
		return prefix.String(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", fmt.Errorf("%s must be an IP address or prefix", field)
	}
	return addr.String(), nil
}

func normalizePrintableString(value, field string, maxBytes int, required bool) (string, error) {
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("%s must be valid UTF-8", field)
	}
	value = strings.TrimSpace(value)
	if required && value == "" {
		return "", fmt.Errorf("%s is required", field)
	}
	if len(value) > maxBytes {
		return "", fmt.Errorf("%s must be at most %d bytes", field, maxBytes)
	}
	for _, r := range value {
		if !unicode.IsPrint(r) {
			return "", fmt.Errorf("%s must contain printable characters only", field)
		}
	}
	return value, nil
}

func isLowerHex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, b := range []byte(value) {
		if b >= '0' && b <= '9' {
			continue
		}
		if b >= 'a' && b <= 'f' {
			continue
		}
		return false
	}
	return true
}

// A node re-reports its firewall reality on every poll, and auditing each
// accepted report turned the audit log into a telemetry stream: on the
// production control plane 29,958 of the last 30,000 audit events were this
// one action, roughly 250k rows a day from 33 nodes. Every one of them is held
// in memory for the life of the process, which is how a 3.8 GB host ended up
// unable to boot the server it had been running for weeks.
//
// Audit the security event rather than the poll: the reported reality changed,
// or enough time passed that the trail should still show this node reporting.
// This mirrors shouldAuditSingBoxDiscovery, which already solved exactly this
// for the sing-box discovery report.
const guardRealityAuditInterval = 6 * time.Hour

type guardRealityAuditState struct {
	fingerprint string
	auditedAt   time.Time
}

func (s *Server) shouldAuditGuardReality(nodeID string, reality model.GuardNodeReality, now time.Time) bool {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	fingerprint := guardRealityFingerprint(reality)
	s.guardRealityAuditMu.Lock()
	defer s.guardRealityAuditMu.Unlock()
	if s.guardRealityAudit == nil {
		s.guardRealityAudit = map[string]guardRealityAuditState{}
	}
	prev, ok := s.guardRealityAudit[nodeID]
	if !ok || prev.fingerprint != fingerprint || now.Sub(prev.auditedAt) >= guardRealityAuditInterval {
		s.guardRealityAudit[nodeID] = guardRealityAuditState{fingerprint: fingerprint, auditedAt: now}
		return true
	}
	return false
}

// guardRealityFingerprint identifies the reported state, not the report. The
// snapshot is canonicalized by the store before it comes back here, so the only
// fields that differ between two reports of an unchanged firewall are the two
// cleared below.
func guardRealityFingerprint(reality model.GuardNodeReality) string {
	reality.NodeID = ""
	reality.CollectedAt = time.Time{}
	// The sshd observation time moves with every poll exactly like
	// collected_at; leaving it in would audit every report again.
	if reality.SSHD != nil {
		sshd := *reality.SSHD
		sshd.ObservedAt = time.Time{}
		reality.SSHD = &sshd
	}
	data, _ := json.Marshal(reality)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// removeGuardRealityAudit drops a node's audit gate state (called on delete),
// so a re-enrolled node with the same id starts by recording its reality again
// instead of inheriting a stale fingerprint.
func (s *Server) removeGuardRealityAudit(nodeID string) {
	s.guardRealityAuditMu.Lock()
	delete(s.guardRealityAudit, nodeID)
	s.guardRealityAuditMu.Unlock()
}
