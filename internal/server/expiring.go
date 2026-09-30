package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// GET /api/expiring is one list of what runs out across the areas that keep a
// date: machine renewals (inventory), VPN users (vpn-core), subscription shares
// (publishing) and watched TLS certificates (monitoring). Each kind is read
// under the scope its own list endpoint requires. A kind the session cannot
// read at all is named in hidden_kinds so the console can say so; nothing is
// counted, because a count would tell a confined session how large the rest of
// the fleet is. A node-confined session gets its own nodes' machines and
// monitors, and the other nodes are outside its domain rather than hidden
// from it.
const (
	expiringKindMachine = "machine_renewal"
	expiringKindVPNUser = "vpn_user"
	expiringKindShare   = "share"
	expiringKindTLS     = "tls_certificate"

	expiringStateOverdue  = "overdue"
	expiringStateDue      = "due"
	expiringStateUpcoming = "upcoming"
	expiringStateAuto     = "auto"

	expiringDefaultWithin = 60
	expiringMaxWithin     = 365
	// expiringDueDays is how close a date is before it reads as due.
	expiringDueDays = 7
)

type expiringReminder struct {
	Enabled        bool `json:"enabled"`
	NextOffsetDays *int `json:"next_offset_days,omitempty"`
}

type expiringItem struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Title string `json:"title"`
	// Subtitle is data only, never English words, so the console can
	// localise the row around it.
	Subtitle  string            `json:"subtitle,omitempty"`
	DueAt     time.Time         `json:"due_at"`
	Days      int               `json:"days"`
	State     string            `json:"state"`
	CostCents int64             `json:"cost_cents"`
	Currency  string            `json:"currency"`
	Reminder  *expiringReminder `json:"reminder,omitempty"`
	// UsedBytes and QuotaBytes are VPN user rows with a quota only: the
	// figure the quota alerts measure, so the console writes the phrase.
	UsedBytes  *int64 `json:"used_bytes,omitempty"`
	QuotaBytes *int64 `json:"quota_bytes,omitempty"`
	Href       string `json:"href"`
}

type expiringTotal struct {
	Currency  string `json:"currency"`
	CostCents int64  `json:"cost_cents"`
	Count     int    `json:"count"`
}

type expiringResponse struct {
	GeneratedAt time.Time       `json:"generated_at"`
	WithinDays  int             `json:"within_days"`
	Items       []expiringItem  `json:"items"`
	Totals      []expiringTotal `json:"totals"`
	HiddenKinds []string        `json:"hidden_kinds"`
}

func (s *Server) handleExpiring(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	within, err := parseExpiringWithin(r.URL.Query().Get("within"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, s.expiringFor(p, s.now(), within))
}

// parseExpiringWithin reads the look-ahead in whole days, 1..365, default 60.
// A trailing "d" is accepted so ?within=60d reads the same as ?within=60.
func parseExpiringWithin(raw string) (int, error) {
	raw = strings.TrimSuffix(strings.TrimSpace(raw), "d")
	if raw == "" {
		return expiringDefaultWithin, nil
	}
	days, err := strconv.Atoi(raw)
	if err != nil || days < 1 || days > expiringMaxWithin {
		return 0, errors.New("within must be a whole number of days from 1 to 365")
	}
	return days, nil
}

func (s *Server) expiringFor(p principal, now time.Time, within int) expiringResponse {
	out := expiringResponse{GeneratedAt: now.UTC(), WithinDays: within, Items: []expiringItem{}, Totals: []expiringTotal{}, HiddenKinds: []string{}}
	// Which kinds the session can read at all. VPN users and shares are
	// fleet-wide objects: their list endpoints refuse a node-restricted
	// session, and so does this. Machines and certificates follow their list
	// endpoints too: the scope admits the kind, and each row is then checked
	// the way that list checks it, so a node-confined session sees its own
	// nodes' rows.
	unrestricted := !principalHasNodeRestriction(p)
	readable := map[string]bool{
		expiringKindMachine: rbac.Allows(p.Principal, "inventory:read", ""),
		expiringKindVPNUser: unrestricted && rbac.Allows(p.Principal, "proxy:read", ""),
		expiringKindShare:   unrestricted && rbac.Allows(p.Principal, "proxy:admin", ""),
		expiringKindTLS:     rbac.Allows(p.Principal, "monitor:read", ""),
	}
	for _, kind := range []string{expiringKindMachine, expiringKindVPNUser, expiringKindShare, expiringKindTLS} {
		if !readable[kind] {
			out.HiddenKinds = append(out.HiddenKinds, kind)
		}
	}
	// add keeps a row inside the window; anything past due always is.
	add := func(item expiringItem) {
		if item.Days <= within {
			out.Items = append(out.Items, item)
		}
	}

	if readable[expiringKindMachine] {
		nodes := map[string]model.Node{}
		for _, node := range s.store.Nodes() {
			nodes[node.ID] = node
		}
		for _, profile := range s.store.MachineProfiles() {
			if profile.NextRenewal.IsZero() || !rbac.Allows(p.Principal, "inventory:read", profile.NodeID) {
				continue
			}
			add(machineExpiringItem(profile, nodes[profile.NodeID], now))
		}
	}

	if readable[expiringKindVPNUser] {
		for _, user := range s.listVpnUsers() {
			if !user.Enabled || user.ExpiresAt.IsZero() {
				continue
			}
			days := daysUntilRenewal(now, user.ExpiresAt)
			item := expiringItem{
				Kind:  expiringKindVPNUser,
				ID:    user.ID,
				Title: firstNonEmpty(user.Email, user.Name, user.ID),
				DueAt: user.ExpiresAt.UTC(),
				Days:  days,
				State: expiringState(days),
				Href:  "/plugins/" + vpnCorePluginID + "/users",
			}
			if user.Name != item.Title {
				item.Subtitle = strings.TrimSpace(user.Name)
			}
			if user.QuotaBytes > 0 {
				acct := firstNonEmpty(strings.TrimSpace(user.MigratedFromProxyUser), user.ID)
				record, _ := s.store.ProxyUser(acct)
				used, _ := s.quotaUsedBytes(user, record.UsedBytes, now, usageCounter{})
				quota := user.QuotaBytes
				item.UsedBytes, item.QuotaBytes = &used, &quota
			}
			add(item)
		}
	}

	if readable[expiringKindShare] {
		recordNames := s.subStoreRecordNames()
		for _, share := range s.store.SubscriptionShares() {
			if !share.Enabled || share.ExpiresAt == nil || share.ExpiresAt.IsZero() {
				continue
			}
			days := daysUntilRenewal(now, *share.ExpiresAt)
			add(expiringItem{
				Kind:     expiringKindShare,
				ID:       share.ID,
				Title:    firstNonEmpty(share.Slug, share.ID),
				Subtitle: s.shareRecordName(share.Source, recordNames),
				DueAt:    share.ExpiresAt.UTC(),
				Days:     days,
				State:    expiringState(days),
				Href:     "/platform/publishing?origin=share&share=" + url.QueryEscape(share.ID),
			})
		}
	}

	for _, mon := range s.store.Monitors() {
		if !readable[expiringKindTLS] || mon.Type != model.MonitorTypeTLS || !mon.Enabled || !monitorVisibleToPrincipal(p, "monitor:read", mon) {
			continue
		}
		notAfter, ok := s.latestCertNotAfter(mon.ID)
		if !ok {
			continue
		}
		days := daysUntilRenewal(now, notAfter)
		add(expiringItem{
			Kind:     expiringKindTLS,
			ID:       mon.ID,
			Title:    firstNonEmpty(mon.Name, mon.Target),
			Subtitle: mon.Target,
			DueAt:    notAfter.UTC(),
			Days:     days,
			State:    expiringState(days),
			Href:     "/monitoring/" + url.PathEscape(mon.ID),
		})
	}

	sort.SliceStable(out.Items, func(i, j int) bool {
		if !out.Items[i].DueAt.Equal(out.Items[j].DueAt) {
			return out.Items[i].DueAt.Before(out.Items[j].DueAt)
		}
		return out.Items[i].Title < out.Items[j].Title
	})
	totals := map[string]*expiringTotal{}
	for _, item := range out.Items {
		if item.CostCents <= 0 || item.Currency == "" {
			continue
		}
		total := totals[item.Currency]
		if total == nil {
			total = &expiringTotal{Currency: item.Currency}
			totals[item.Currency] = total
		}
		total.CostCents += item.CostCents
		total.Count++
	}
	for _, total := range totals {
		out.Totals = append(out.Totals, *total)
	}
	sort.Slice(out.Totals, func(i, j int) bool { return out.Totals[i].Currency < out.Totals[j].Currency })
	return out
}

// machineExpiringItem reads a machine's renewal as of now. An auto_roll date
// that has passed reads as the date it rolls to, so it is never overdue.
func machineExpiringItem(profile model.MachineProfile, node model.Node, now time.Time) expiringItem {
	due := effectiveRenewal(profile, now)
	days := daysUntilRenewal(now, due)
	state := expiringState(days)
	if profile.AutoRoll {
		state = expiringStateAuto
	}
	item := expiringItem{
		Kind:     expiringKindMachine,
		ID:       profile.ID,
		Title:    firstNonEmpty(profile.Label, node.Name, profile.NodeID),
		Subtitle: joinNonEmpty(" · ", profile.Vendor, profile.Region),
		DueAt:    due,
		Days:     days,
		State:    state,
		Reminder: &expiringReminder{Enabled: profile.RemindersEnabled},
		Href:     "/inventory?machine=" + url.QueryEscape(profile.ID),
	}
	if profile.PriceCents > 0 && profile.Currency != "" {
		item.CostCents, item.Currency = profile.PriceCents, profile.Currency
	}
	if !due.Equal(dateOnlyUTC(profile.NextRenewal)) {
		profile.NextRenewal, profile.LastRemindedKey = due, ""
	}
	if offset, ok := nextReminderOffset(profile, now); ok {
		item.Reminder.NextOffsetDays = &offset
	}
	return item
}

func expiringState(days int) string {
	switch {
	case days < 0:
		return expiringStateOverdue
	case days <= expiringDueDays:
		return expiringStateDue
	default:
		return expiringStateUpcoming
	}
}

// nextReminderOffset is the offset of the next reminder the scheduler will
// send for this profile, found by asking nextReminderFire day by day, so it
// cannot disagree with what actually fires.
func nextReminderOffset(profile model.MachineProfile, now time.Time) (int, bool) {
	if !profile.RemindersEnabled || profile.NextRenewal.IsZero() {
		return 0, false
	}
	today := dateOnlyUTC(now)
	days := daysUntilRenewal(now, profile.NextRenewal)
	for k := 0; days-k >= -overdueReminderDays; k++ {
		at := now
		if k > 0 {
			at = today.AddDate(0, 0, k)
		}
		if fire, ok := nextReminderFire(profile, at); ok {
			return fire.OffsetDays, true
		}
	}
	return 0, false
}

// subStoreRecordNames maps Sub-Store record ids to the names the operator
// gave them, read from the plugin's document the same way the plugin does.
func (s *Server) subStoreRecordNames() map[string]string {
	out := map[string]string{}
	entry, ok := s.store.KVEntry(usageSubStoreKVBucket, usageSubStoreRecordsKey)
	if !ok || len(entry.Value) == 0 || len(entry.Value) > usageMaxSubStoreRecordsLen {
		return out
	}
	var doc struct {
		Records []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			DisplayName string `json:"display_name"`
		} `json:"records"`
	}
	if err := json.Unmarshal([]byte(entry.Value), &doc); err != nil {
		return out
	}
	for _, rec := range doc.Records {
		if name := firstNonEmpty(rec.DisplayName, rec.Name); rec.ID != "" && name != "" {
			out[rec.ID] = strings.TrimSpace(name)
		}
	}
	return out
}

// shareRecordName names what a share publishes: the Sub-Store record's name,
// or the proxy user's, falling back to the id when the record is gone.
func (s *Server) shareRecordName(source model.ShareSource, recordNames map[string]string) string {
	if source.Kind == model.ShareSourceCoreProxyUser {
		if user, ok := s.store.ProxyUser(source.ProxyUserID); ok && strings.TrimSpace(user.Name) != "" {
			return strings.TrimSpace(user.Name)
		}
		return source.ProxyUserID
	}
	return firstNonEmpty(recordNames[source.SubscriptionID], source.SubscriptionID)
}

// latestCertNotAfter is the certificate expiry from the newest result that
// completed a handshake.
func (s *Server) latestCertNotAfter(monitorID string) (time.Time, bool) {
	results := s.store.MonitorResults(monitorID)
	for i := len(results) - 1; i >= 0; i-- {
		if !results[i].CertNotAfter.IsZero() {
			return results[i].CertNotAfter, true
		}
	}
	return time.Time{}, false
}

func joinNonEmpty(sep string, values ...string) string {
	kept := make([]string, 0, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			kept = append(kept, v)
		}
	}
	return strings.Join(kept, sep)
}
