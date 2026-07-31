package server

import (
	"encoding/base64"
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
)

type guardRealityResponse struct {
	OK                 bool      `json:"ok"`
	NodeID             string    `json:"node_id"`
	CollectedAt        time.Time `json:"collected_at"`
	ReceivedAt         time.Time `json:"received_at"`
	CollectedAtClamped bool      `json:"collected_at_clamped"`
}

type guardRealitySummary struct {
	NodeID            string     `json:"node_id"`
	SnapshotStatus    string     `json:"snapshot_status"`
	CollectedAt       *time.Time `json:"collected_at,omitempty"`
	ReceivedAt        *time.Time `json:"received_at,omitempty"`
	StaleAfter        *time.Time `json:"stale_after,omitempty"`
	ManagedSHA        *string    `json:"managed_sha,omitempty"`
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
	s.recordRequestAudit(r, model.AuditEvent{
		ID:       id.New("audit"),
		Action:   "netguard.reality.report",
		Decision: "allow",
		NodeID:   node.ID,
		Metadata: map[string]string{
			"listener_count":      strconv.Itoa(len(reality.Listeners)),
			"interface_count":     strconv.Itoa(len(reality.Interfaces)),
			"foreign_table_count": strconv.Itoa(len(reality.ForeignTables)),
		},
	})
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
		out = append(out, s.guardRealitySummaryForNode(node.ID, now))
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

func (s *Server) guardRealitySummaryForNode(nodeID string, now time.Time) guardRealitySummary {
	snapshot, ok := s.store.GuardRealitySnapshot(nodeID)
	if !ok {
		return guardRealitySummary{NodeID: nodeID, SnapshotStatus: "unknown"}
	}
	status, staleAfter := guardRealityFreshness(snapshot, now)
	managedSHA := snapshot.Reality.ManagedSHA
	listenerCount := len(snapshot.Reality.Listeners)
	interfaceCount := len(snapshot.Reality.Interfaces)
	foreignTableCount := len(snapshot.Reality.ForeignTables)
	collectedAt := snapshot.Reality.CollectedAt.UTC()
	receivedAt := snapshot.ReceivedAt.UTC()
	return guardRealitySummary{
		NodeID:            nodeID,
		SnapshotStatus:    status,
		CollectedAt:       &collectedAt,
		ReceivedAt:        &receivedAt,
		StaleAfter:        &staleAfter,
		ManagedSHA:        &managedSHA,
		ListenerCount:     &listenerCount,
		InterfaceCount:    &interfaceCount,
		ForeignTableCount: &foreignTableCount,
	}
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
	return guardRealityDetail{
		NodeID:         nodeID,
		SnapshotStatus: status,
		Reality:        &reality,
		ReceivedAt:     &receivedAt,
		StaleAfter:     &staleAfter,
	}
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
	return reality, collectedAtClamped, nil
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
