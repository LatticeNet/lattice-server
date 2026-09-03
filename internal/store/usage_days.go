package store

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Daily usage rollups. Two record families, each keyed "<id>/<yyyymmdd>":
//
//	usage_day_node  <node_id>/<day>  that node's lines for the day
//	usage_day_user  <user_id>/<day>  one identity's counted traffic for the day
//
// Monotonic deltas are added into the current UTC day at ingestion, so a row
// is a sum of deltas rather than a copy of a counter, and a core restart on
// the node cannot zero a day. Retention is UsageDayRetentionDays, pruned when
// the ingestion path sees the UTC day roll over.
//
// JSON keys are deliberately short. The documented bound is 33 nodes with 200
// lines each kept for 400 days; a node-day record in which every line was
// active and carried one named user marshals to roughly 30 KiB with these
// keys, which keeps the whole fleet under 512 MiB on disk in that worst case.
// TestUsageDaySizeBound holds the number.
const (
	UsageDayRetentionDays = 400
	usageDayLayout        = "20060102"
)

// UsageDayBytes is one uplink/downlink pair.
type UsageDayBytes struct {
	Uplink   int64 `json:"u"`
	Downlink int64 `json:"d"`
}

func (b *UsageDayBytes) add(o UsageDayBytes) {
	b.Uplink += o.Uplink
	b.Downlink += o.Downlink
}

// UsageDayLine is one inbound's traffic for one day. Users carries the named
// user counters that landed on this line, keyed by VpnUser id, plus the users
// an inbound counter was attributed to when the line carried no named users.
type UsageDayLine struct {
	LineHashID string                   `json:"h,omitempty"`
	Uplink     int64                    `json:"u"`
	Downlink   int64                    `json:"d"`
	Users      map[string]UsageDayBytes `json:"us,omitempty"`
}

// UsageDayNode is one node's day, lines keyed by the core's inbound tag. An
// inbound the server could not join to a line still has its row here with an
// empty LineHashID: the bytes are real egress and are never dropped.
type UsageDayNode struct {
	NodeID string                  `json:"n"`
	Day    string                  `json:"day"`
	Lines  map[string]UsageDayLine `json:"l,omitempty"`
}

// UsageDayUserLine is one identity's counted traffic on one line for the day.
type UsageDayUserLine struct {
	Uplink     int64     `json:"u"`
	Downlink   int64     `json:"d"`
	LastSeenAt time.Time `json:"at,omitempty"`
}

// UsageDayUser is one identity's counted traffic for the day, split by the
// line it was counted on. Only attributions that count toward the quota land
// here (named, credential, binding); estimates are derived at read time.
type UsageDayUser struct {
	UserID     string                      `json:"uid"`
	Day        string                      `json:"day"`
	Uplink     int64                       `json:"u"`
	Downlink   int64                       `json:"d"`
	ByLine     map[string]UsageDayUserLine `json:"bl,omitempty"`
	LastSeenAt time.Time                   `json:"at,omitempty"`
}

// UsageDay formats a time as the UTC day key.
func UsageDay(t time.Time) string { return t.UTC().Format(usageDayLayout) }

// ParseUsageDay is the inverse of UsageDay.
func ParseUsageDay(day string) (time.Time, error) {
	return time.ParseInLocation(usageDayLayout, day, time.UTC)
}

// UsageDayKey is the record key for one id on one day.
func UsageDayKey(id, day string) string { return id + "/" + day }

func splitUsageDayKey(key string) (id, day string, ok bool) {
	i := strings.LastIndexByte(key, '/')
	if i <= 0 || i == len(key)-1 {
		return "", "", false
	}
	return key[:i], key[i+1:], true
}

func validUsageDay(day string) bool {
	if len(day) != len(usageDayLayout) {
		return false
	}
	_, err := ParseUsageDay(day)
	return err == nil
}

func validUsageDayID(id string) error {
	if id == "" || strings.ContainsAny(id, "/\x00") {
		return fmt.Errorf("invalid usage day id %q", id)
	}
	return nil
}

// ProxyUsageUpdate is one ingestion's write set, committed together so a
// crash between the snapshot and its day rows cannot leave a delta counted
// twice on the next report.
type ProxyUsageUpdate struct {
	Users    []model.ProxyUser
	Profile  *model.ProxyNodeProfile
	Snapshot *model.ProxyUsageSnapshot
	// DayNode and DayUsers are deltas: they are added into the stored rows.
	DayNode  *UsageDayNode
	DayUsers []UsageDayUser
}

func (u ProxyUsageUpdate) empty() bool {
	return len(u.Users) == 0 && u.Profile == nil && u.Snapshot == nil && u.DayNode == nil && len(u.DayUsers) == 0
}

func (u ProxyUsageUpdate) validateDays() error {
	if u.DayNode != nil {
		if err := validUsageDayID(u.DayNode.NodeID); err != nil {
			return err
		}
		if !validUsageDay(u.DayNode.Day) {
			return fmt.Errorf("invalid usage day %q", u.DayNode.Day)
		}
	}
	for _, row := range u.DayUsers {
		if err := validUsageDayID(row.UserID); err != nil {
			return err
		}
		if !validUsageDay(row.Day) {
			return fmt.Errorf("invalid usage day %q", row.Day)
		}
	}
	return nil
}

func addUsageDayNode(dst *UsageDayNode, delta UsageDayNode) {
	if dst.NodeID == "" {
		dst.NodeID, dst.Day = delta.NodeID, delta.Day
	}
	if dst.Lines == nil {
		dst.Lines = map[string]UsageDayLine{}
	}
	for tag, line := range delta.Lines {
		cur := dst.Lines[tag]
		if line.LineHashID != "" {
			cur.LineHashID = line.LineHashID
		}
		cur.Uplink += line.Uplink
		cur.Downlink += line.Downlink
		if len(line.Users) > 0 && cur.Users == nil {
			cur.Users = map[string]UsageDayBytes{}
		}
		for userID, bytes := range line.Users {
			u := cur.Users[userID]
			u.add(bytes)
			cur.Users[userID] = u
		}
		dst.Lines[tag] = cur
	}
}

func addUsageDayUser(dst *UsageDayUser, delta UsageDayUser) {
	if dst.UserID == "" {
		dst.UserID, dst.Day = delta.UserID, delta.Day
	}
	dst.Uplink += delta.Uplink
	dst.Downlink += delta.Downlink
	if delta.LastSeenAt.After(dst.LastSeenAt) {
		dst.LastSeenAt = delta.LastSeenAt
	}
	if len(delta.ByLine) > 0 && dst.ByLine == nil {
		dst.ByLine = map[string]UsageDayUserLine{}
	}
	for hash, line := range delta.ByLine {
		cur := dst.ByLine[hash]
		cur.Uplink += line.Uplink
		cur.Downlink += line.Downlink
		if line.LastSeenAt.After(cur.LastSeenAt) {
			cur.LastSeenAt = line.LastSeenAt
		}
		dst.ByLine[hash] = cur
	}
}

// ApplyProxyUsage commits one ingestion. It supersedes ApplyProxyUsageUpdate,
// which remains for callers that carry no day rows.
func (s *Store) ApplyProxyUsage(update ProxyUsageUpdate) error {
	if update.empty() {
		return nil
	}
	if err := update.validateDays(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for _, user := range update.Users {
		user = normalizeProxyUserForStore(user, now)
		s.state.ProxyUsers[user.ID] = user
	}
	if update.Profile != nil {
		normalized := normalizeProxyNodeProfileForStore(*update.Profile, now)
		s.state.ProxyProfiles[normalized.NodeID] = normalized
		update.Profile = &normalized
	}
	if update.Snapshot != nil {
		normalized := normalizeProxyUsageSnapshotForStore(*update.Snapshot, now)
		s.state.ProxyUsage[normalized.NodeID] = normalized
		update.Snapshot = &normalized
	}
	if s.runtimeBoltHot != nil {
		normalizedUsers := make([]model.ProxyUser, 0, len(update.Users))
		for _, user := range update.Users {
			normalizedUsers = append(normalizedUsers, normalizeProxyUserForStore(user, now))
		}
		update.Users = normalizedUsers
		return s.runtimeBoltHot.ApplyProxyUsage(update)
	}
	if update.DayNode != nil {
		key := UsageDayKey(update.DayNode.NodeID, update.DayNode.Day)
		row := s.state.UsageDayNodes[key]
		addUsageDayNode(&row, *update.DayNode)
		s.state.UsageDayNodes[key] = row
	}
	for _, delta := range update.DayUsers {
		key := UsageDayKey(delta.UserID, delta.Day)
		row := s.state.UsageDayUsers[key]
		addUsageDayUser(&row, delta)
		s.state.UsageDayUsers[key] = row
	}
	return s.Save()
}

// UsageDayNodeRows returns a node's rows for the inclusive day range, oldest
// first. Rows are copies: callers may mutate them freely.
func (s *Store) UsageDayNodeRows(nodeID, from, to string) ([]UsageDayNode, error) {
	if !validUsageDay(from) || !validUsageDay(to) {
		return nil, errors.New("usage day range must be yyyymmdd")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runtimeBoltHot != nil {
		return s.runtimeBoltHot.UsageDayNodeRows(nodeID, from, to)
	}
	out := []UsageDayNode{}
	for key, row := range s.state.UsageDayNodes {
		id, day, ok := splitUsageDayKey(key)
		if !ok || id != nodeID || day < from || day > to {
			continue
		}
		out = append(out, cloneUsageDayNode(row))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Day < out[j].Day })
	return out, nil
}

// UsageDayUserRows returns one identity's rows for the inclusive day range,
// oldest first.
func (s *Store) UsageDayUserRows(userID, from, to string) ([]UsageDayUser, error) {
	if !validUsageDay(from) || !validUsageDay(to) {
		return nil, errors.New("usage day range must be yyyymmdd")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runtimeBoltHot != nil {
		return s.runtimeBoltHot.UsageDayUserRows(userID, from, to)
	}
	out := []UsageDayUser{}
	for key, row := range s.state.UsageDayUsers {
		id, day, ok := splitUsageDayKey(key)
		if !ok || id != userID || day < from || day > to {
			continue
		}
		out = append(out, cloneUsageDayUser(row))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Day < out[j].Day })
	return out, nil
}

// PruneUsageDays deletes every row older than the given day and reports how
// many went. Called at the day roll, not on every ingestion.
func (s *Store) PruneUsageDays(before string) (int, error) {
	if !validUsageDay(before) {
		return 0, errors.New("usage day cutoff must be yyyymmdd")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runtimeBoltHot != nil {
		return s.runtimeBoltHot.PruneUsageDays(before)
	}
	pruned := 0
	for key := range s.state.UsageDayNodes {
		if _, day, ok := splitUsageDayKey(key); ok && day < before {
			delete(s.state.UsageDayNodes, key)
			pruned++
		}
	}
	for key := range s.state.UsageDayUsers {
		if _, day, ok := splitUsageDayKey(key); ok && day < before {
			delete(s.state.UsageDayUsers, key)
			pruned++
		}
	}
	if pruned == 0 {
		return 0, nil
	}
	return pruned, s.Save()
}

func cloneUsageDayNode(row UsageDayNode) UsageDayNode {
	out := row
	out.Lines = make(map[string]UsageDayLine, len(row.Lines))
	for tag, line := range row.Lines {
		cl := line
		if line.Users != nil {
			cl.Users = make(map[string]UsageDayBytes, len(line.Users))
			for id, b := range line.Users {
				cl.Users[id] = b
			}
		}
		out.Lines[tag] = cl
	}
	return out
}

func cloneUsageDayUser(row UsageDayUser) UsageDayUser {
	out := row
	if row.ByLine != nil {
		out.ByLine = make(map[string]UsageDayUserLine, len(row.ByLine))
		for hash, line := range row.ByLine {
			out.ByLine[hash] = line
		}
	}
	return out
}
