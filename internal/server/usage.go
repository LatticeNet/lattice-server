package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
)

// Usage is the vpn-core 3-D usage read-model (design-12 S3). It presents traffic
// from two operator-facing dimensions — by user and by node — plus the per-(node,
// user) breakdown. It is DERIVED on demand from the existing accounting substrate:
// ProxyUser.UsedBytes (monotonic per-user total) and the latest ProxyUsageSnapshot
// per node (raw per-(node,user) counters), mapped onto VpnUser identities.
//
// The target shape carries line_hash_id so the future per-line collector (S3b:
// `sb stats` over the sing-box clash/v2ray stats API, with an up/down split) can
// populate it without a model change. Until then per-line attribution is unknown
// (line_hash_id empty) and bytes are a single total, not an up/down split.
type UsageByUser struct {
	UserID     string `json:"user_id"`
	Email      string `json:"email,omitempty"`
	UsedBytes  int64  `json:"used_bytes"`
	QuotaBytes int64  `json:"quota_bytes,omitempty"`
	Status     string `json:"status,omitempty"`
	LastSeen   string `json:"last_seen,omitempty"`
}

type UsageByNode struct {
	NodeID    string `json:"node_id"`
	NodeName  string `json:"node_name,omitempty"`
	UsedBytes int64  `json:"used_bytes"`
	UserCount int    `json:"user_count"`
	At        string `json:"at,omitempty"`
}

type UsageRow struct {
	NodeID     string `json:"node_id"`
	NodeName   string `json:"node_name,omitempty"`
	UserID     string `json:"user_id"`
	Email      string `json:"email,omitempty"`
	LineHashID string `json:"line_hash_id,omitempty"` // empty until S3b sb-stats collector
	Bytes      int64  `json:"bytes"`
}

type UsageCollector struct {
	NodeID    string `json:"node_id"`
	NodeName  string `json:"node_name,omitempty"`
	Source    string `json:"source,omitempty"`
	Status    string `json:"status,omitempty"`
	Error     string `json:"error,omitempty"`
	CheckedAt string `json:"checked_at,omitempty"`
}

// buildUsage assembles the usage read-model. proxyUserID → VpnUser identity is
// resolved through the migration link so usage is reported against the new
// identity (email) where one exists, falling back to the legacy ProxyUser name.
func (s *Server) buildUsage() (byUser []UsageByUser, byNode []UsageByNode, rows []UsageRow, collectors []UsageCollector) {
	// proxyUserID -> (email, vpnUserID) via the migration link.
	type ident struct{ id, email string }
	identByProxyUser := map[string]ident{}
	for _, vu := range s.listVpnUsers() {
		if vu.MigratedFromProxyUser != "" {
			identByProxyUser[vu.MigratedFromProxyUser] = ident{id: vu.ID, email: vu.Email}
		}
	}
	resolve := func(proxyUserID, fallbackName string) (string, string) {
		if it, ok := identByProxyUser[proxyUserID]; ok {
			return it.id, it.email
		}
		return proxyUserID, fallbackName
	}

	// by-user totals from the monotonic ProxyUser.UsedBytes.
	for _, pu := range s.store.ProxyUsers() {
		uid, email := resolve(pu.ID, pu.Name)
		row := UsageByUser{
			UserID: uid, Email: email, UsedBytes: pu.UsedBytes,
			QuotaBytes: pu.TrafficLimitBytes, Status: pu.Status,
		}
		if !pu.LastSeenAt.IsZero() {
			row.LastSeen = pu.LastSeenAt.UTC().Format("2006-01-02T15:04:05Z07:00")
		}
		byUser = append(byUser, row)
	}
	sort.Slice(byUser, func(i, j int) bool { return byUser[i].UsedBytes > byUser[j].UsedBytes })

	// by-node + per-(node,user) rows from the latest snapshot per node.
	for _, snap := range s.store.ProxyUsageSnapshots() {
		nodeName := s.nodeDisplayName(snap.NodeID)
		nodeTotal := int64(0)
		userCount := 0
		for proxyUserID, bytes := range snap.UserBytes {
			uid, email := resolve(proxyUserID, proxyUserID)
			rows = append(rows, UsageRow{NodeID: snap.NodeID, NodeName: nodeName, UserID: uid, Email: email, Bytes: bytes})
			nodeTotal += bytes
			userCount++
		}
		bn := UsageByNode{NodeID: snap.NodeID, NodeName: nodeName, UsedBytes: nodeTotal, UserCount: userCount}
		if !snap.At.IsZero() {
			bn.At = snap.At.UTC().Format("2006-01-02T15:04:05Z07:00")
		}
		byNode = append(byNode, bn)

		if snap.CollectorSource != "" || snap.CollectorStatus != "" {
			c := UsageCollector{NodeID: snap.NodeID, NodeName: nodeName, Source: snap.CollectorSource, Status: snap.CollectorStatus, Error: snap.CollectorError}
			if !snap.CollectorCheckedAt.IsZero() {
				c.CheckedAt = snap.CollectorCheckedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
			}
			collectors = append(collectors, c)
		}
	}
	sort.Slice(byNode, func(i, j int) bool { return byNode[i].UsedBytes > byNode[j].UsedBytes })
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].NodeID != rows[j].NodeID {
			return rows[i].NodeID < rows[j].NodeID
		}
		return rows[i].Bytes > rows[j].Bytes
	})
	sort.Slice(collectors, func(i, j int) bool { return collectors[i].NodeID < collectors[j].NodeID })
	return byUser, byNode, rows, collectors
}

// vpnCoreUsageRPC serves latticenet.vpn-core/usage (design-12 S3), proxy:read.
//
//	query -> {by_user, by_node, rows, collectors, per_line: false}
func (s *Server) vpnCoreUsageRPC(_ context.Context, method string, _ []byte) ([]byte, error) {
	switch method {
	case "query":
		byUser, byNode, rows, collectors := s.buildUsage()
		if byUser == nil {
			byUser = []UsageByUser{}
		}
		if byNode == nil {
			byNode = []UsageByNode{}
		}
		if rows == nil {
			rows = []UsageRow{}
		}
		if collectors == nil {
			collectors = []UsageCollector{}
		}
		return json.Marshal(struct {
			ByUser     []UsageByUser    `json:"by_user"`
			ByNode     []UsageByNode    `json:"by_node"`
			Rows       []UsageRow       `json:"rows"`
			Collectors []UsageCollector `json:"collectors"`
			PerLine    bool             `json:"per_line"` // false until the sb-stats collector lands (S3b)
		}{ByUser: byUser, ByNode: byNode, Rows: rows, Collectors: collectors, PerLine: false})
	default:
		return nil, fmt.Errorf("vpn-core/usage: unknown method %q", method)
	}
}
