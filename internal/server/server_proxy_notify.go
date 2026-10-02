package server

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

const (
	proxyUserAlertQuota  = "quota"
	proxyUserAlertExpiry = "expiry"
)

// proxyAlertOnlyNote ends the text of a quota or expiry alert about an
// identity no managed render carries (vpnUserInManagedRender): it may be on
// adopted lines only, on lines of another protocol, or on none, and in every
// case nothing Lattice renders follows the alert. A digest, which always
// covers two or more users, ends with proxyDigestAlertOnlyNote or
// proxyDigestMixedAlertOnlyNote instead.
const (
	proxyAlertOnlyNote            = "No managed line carries this user, so Lattice will not remove it and this message is an alert only."
	proxyDigestAlertOnlyNote      = "No managed line carries these users, so Lattice will not remove them and this message is an alert only."
	proxyDigestMixedAlertOnlyNote = "No managed line carries the users marked alert only, so Lattice will not remove them and for them this message is an alert only."
)

type proxyUserNotificationFire struct {
	UserID            string
	UserName          string
	Kind              string
	Key               string
	ThresholdPercent  int
	ExpiryOffsetDays  int
	UsedBytes         int64
	TrafficLimitBytes int64
	ExpiresAt         time.Time
	Status            string
	// AlertOnly marks an alert about an identity outside the managed render:
	// nothing Lattice renders removes it, so the text says so.
	AlertOnly bool
}

func (s *Server) evaluateProxyUserNotifications(now time.Time, onlyID string) ([]proxyUserNotificationFire, error) {
	users := s.store.ProxyUsers()
	identities := s.vpnUsersByAccounting()
	fired := []proxyUserNotificationFire{}
	found := onlyID == ""
	changed := false
	stored := make(map[string]bool, len(users))
	for _, user := range users {
		stored[user.ID] = true
	}
	// An identity whose lines have reported no traffic has no stored
	// projection yet. It is evaluated from the identity all the same, and its
	// projection is written only when an alert fires, to hold the cursor.
	accts := make([]string, 0, len(identities))
	for acct := range identities {
		if !stored[acct] {
			accts = append(accts, acct)
		}
	}
	sort.Strings(accts)
	for _, acct := range accts {
		projection := vpnUserUsageProjection(identities[acct])
		projection.ID = acct
		users = append(users, projection)
	}
	for _, user := range users {
		if onlyID != "" && user.ID != onlyID {
			continue
		}
		found = true
		originalStatus := user.Status
		var identity *VpnUser
		if vu, ok := identities[user.ID]; ok {
			identity = &vu
		}
		originalExpiryKey := user.LastExpiryNotifiedKey
		updated, alerts := s.quotaEvaluate(user, identity, now, usageCounter{})
		if len(alerts) == 0 {
			// A status change, or a cursor seeded silently for a long-past
			// expiry, is kept on a stored record. An identity without one
			// needs nothing written: it did not alert.
			if stored[user.ID] && (updated.Status != originalStatus || updated.LastExpiryNotifiedKey != originalExpiryKey) {
				if err := s.store.UpsertProxyUser(updated); err != nil {
					s.emitProxyUserNotifications(fired, now)
					return nil, err
				}
				changed = true
			}
			continue
		}
		if err := s.store.UpsertProxyUser(updated); err != nil {
			// Whatever was already recorded is still delivered.
			s.emitProxyUserNotifications(fired, now)
			return nil, err
		}
		changed = true
		fired = append(fired, alerts...)
	}
	if changed {
		s.invalidateLineReadModel()
	}
	if !found {
		return nil, fmt.Errorf("proxy user not found")
	}
	s.emitProxyUserNotifications(fired, now)
	return fired, nil
}

func nextProxyUserNotifications(user model.ProxyUser, now time.Time) (model.ProxyUser, []proxyUserNotificationFire) {
	return nextProxyUserNotificationsForPeriod(user, now, "")
}

// nextProxyUserNotificationsForPeriod is the period-aware form: period is the
// yyyymmdd the current quota period started, or empty for a lifetime quota.
// The period is part of the notification key, so the 80 and 100 percent
// alerts fire again in every period.
func nextProxyUserNotificationsForPeriod(user model.ProxyUser, now time.Time, period string) (model.ProxyUser, []proxyUserNotificationFire) {
	if !user.Enabled {
		return user, nil
	}
	alerts := []proxyUserNotificationFire{}
	if alert, ok := nextProxyQuotaNotification(user, period); ok {
		user.LastQuotaNotifiedKey = alert.Key
		alerts = append(alerts, alert)
	}
	if alert, ok := nextProxyExpiryNotification(user, now); ok {
		user.LastExpiryNotifiedKey = alert.Key
		alerts = append(alerts, alert)
	} else if proxyExpiryLongPast(user.ExpiresAt, now) {
		// Too old to announce: record it as announced, so the state says so
		// and no later evaluation reconsiders it.
		user.LastExpiryNotifiedKey = proxyExpiryNotificationKey(user.ExpiresAt, -1)
	}
	return user, alerts
}

// proxyExpiredAlertDays is how many UTC days after an expiry the expired
// alert may still fire, the same window a manual machine renewal is reminded
// in. An older expiry is recorded silently, so evaluating identities that
// expired long ago cannot flood the channels.
const proxyExpiredAlertDays = overdueReminderDays

func proxyExpiryLongPast(expiresAt, now time.Time) bool {
	return !expiresAt.IsZero() && daysUntilRenewal(now, expiresAt) < -proxyExpiredAlertDays
}

func nextProxyQuotaNotification(user model.ProxyUser, period string) (proxyUserNotificationFire, bool) {
	threshold, ok := proxyQuotaThreshold(user.UsedBytes, user.TrafficLimitBytes)
	if !ok {
		return proxyUserNotificationFire{}, false
	}
	key := proxyQuotaNotificationKey(user.TrafficLimitBytes, period, threshold)
	if proxyQuotaNotificationAlreadySent(user.LastQuotaNotifiedKey, user.TrafficLimitBytes, period, threshold) {
		return proxyUserNotificationFire{}, false
	}
	return proxyUserNotificationFire{
		UserID:            user.ID,
		UserName:          user.Name,
		Kind:              proxyUserAlertQuota,
		Key:               key,
		ThresholdPercent:  threshold,
		UsedBytes:         user.UsedBytes,
		TrafficLimitBytes: user.TrafficLimitBytes,
		Status:            user.Status,
	}, true
}

func nextProxyExpiryNotification(user model.ProxyUser, now time.Time) (proxyUserNotificationFire, bool) {
	if proxyExpiryLongPast(user.ExpiresAt, now) {
		return proxyUserNotificationFire{}, false
	}
	offset, ok := proxyExpiryOffset(user.ExpiresAt, now)
	if !ok {
		return proxyUserNotificationFire{}, false
	}
	key := proxyExpiryNotificationKey(user.ExpiresAt, offset)
	if proxyExpiryNotificationAlreadySent(user.LastExpiryNotifiedKey, user.ExpiresAt, offset) {
		return proxyUserNotificationFire{}, false
	}
	return proxyUserNotificationFire{
		UserID:           user.ID,
		UserName:         user.Name,
		Kind:             proxyUserAlertExpiry,
		Key:              key,
		ExpiryOffsetDays: offset,
		ExpiresAt:        user.ExpiresAt,
		Status:           user.Status,
	}, true
}

func proxyQuotaThreshold(used, limit int64) (int, bool) {
	if used <= 0 || limit <= 0 {
		return 0, false
	}
	if proxyQuotaExhausted(used, limit) {
		return 100, true
	}
	if float64(used)/float64(limit) >= 0.8 {
		return 80, true
	}
	return 0, false
}

func proxyQuotaNotificationKey(limit int64, period string, threshold int) string {
	return proxyQuotaNotificationPrefix(limit, period) + strconv.Itoa(threshold)
}

// proxyQuotaNotificationPrefix is "quota:<limit>:" for a lifetime quota and
// "quota:<limit>:<period>:" for a period one, so a cursor written under the
// old shape keeps suppressing the lifetime alert it was written for.
func proxyQuotaNotificationPrefix(limit int64, period string) string {
	if period == "" {
		return fmt.Sprintf("quota:%d:", limit)
	}
	return fmt.Sprintf("quota:%d:%s:", limit, period)
}

func proxyQuotaNotificationAlreadySent(last string, limit int64, period string, threshold int) bool {
	prefix := proxyQuotaNotificationPrefix(limit, period)
	if !strings.HasPrefix(last, prefix) {
		return false
	}
	prior, err := strconv.Atoi(strings.TrimPrefix(last, prefix))
	if err != nil {
		return false
	}
	return prior >= threshold
}

func proxyExpiryOffset(expiresAt, now time.Time) (int, bool) {
	if expiresAt.IsZero() {
		return 0, false
	}
	if !expiresAt.After(now) {
		return -1, true
	}
	days := daysUntilRenewal(now, expiresAt)
	switch {
	case days <= 1:
		return 1, true
	case days <= 7:
		return 7, true
	default:
		return 0, false
	}
}

func proxyExpiryNotificationKey(expiresAt time.Time, offset int) string {
	label := strconv.Itoa(offset)
	if offset < 0 {
		label = "expired"
	}
	return "expiry:" + dateOnlyUTC(expiresAt).Format("2006-01-02") + ":" + label
}

func proxyExpiryNotificationAlreadySent(last string, expiresAt time.Time, offset int) bool {
	prefix := "expiry:" + dateOnlyUTC(expiresAt).Format("2006-01-02") + ":"
	if !strings.HasPrefix(last, prefix) {
		return false
	}
	return proxyExpiryOffsetRank(strings.TrimPrefix(last, prefix)) >= proxyExpiryOffsetRank(strconv.Itoa(offset))
}

func proxyExpiryOffsetRank(label string) int {
	switch label {
	case "expired", "-1":
		return 3
	case "1":
		return 2
	case "7":
		return 1
	default:
		return 0
	}
}

// emitProxyUserNotifications audits every alert of one run and sends one
// message per kind: a single alert keeps its own message, several of a kind
// become one digest whose title keeps the kind's prefix, so rules routing
// proxy.expiry or proxy.quota still match it.
func (s *Server) emitProxyUserNotifications(alerts []proxyUserNotificationFire, now time.Time) {
	byKind := map[string][]proxyUserNotificationFire{}
	for _, alert := range alerts {
		s.recordAudit(model.AuditEvent{
			ID:       id.New("audit"),
			Action:   "proxy.user.notify",
			Scope:    "proxy:read",
			Decision: "observe",
			Metadata: map[string]string{
				"user_id": alert.UserID,
				"kind":    alert.Kind,
				"key":     alert.Key,
			},
		})
		byKind[alert.Kind] = append(byKind[alert.Kind], alert)
	}
	for _, kind := range []string{proxyUserAlertExpiry, proxyUserAlertQuota} {
		switch group := byKind[kind]; len(group) {
		case 0:
		case 1:
			s.emitProxyUserNotification(group[0])
		default:
			title, body := proxyUserDigestMessage(kind, group, now)
			s.emitNotify(title, body)
		}
	}
}

// proxyUserDigestMessage is one line per user: expiries soonest first, quota
// alerts fullest first.
func proxyUserDigestMessage(kind string, alerts []proxyUserNotificationFire, now time.Time) (string, string) {
	sorted := append([]proxyUserNotificationFire(nil), alerts...)
	name := func(a proxyUserNotificationFire) string { return firstNonEmpty(a.UserName, a.UserID) }
	lines := make([]string, 0, len(sorted))
	if kind == proxyUserAlertExpiry {
		sort.SliceStable(sorted, func(i, j int) bool {
			if !sorted[i].ExpiresAt.Equal(sorted[j].ExpiresAt) {
				return sorted[i].ExpiresAt.Before(sorted[j].ExpiresAt)
			}
			return name(sorted[i]) < name(sorted[j])
		})
		for _, a := range sorted {
			when := "expired"
			if a.ExpiryOffsetDays >= 0 {
				when = fmt.Sprintf("within %dd", a.ExpiryOffsetDays)
			}
			lines = append(lines, strings.Join([]string{renewalShortDate(a.ExpiresAt, now), name(a), when}, "  "))
		}
		return fmt.Sprintf("Lattice proxy expiry digest: %d users", len(sorted)), proxyDigestBody(sorted, lines)
	}
	share := func(a proxyUserNotificationFire) float64 {
		return float64(a.UsedBytes) / float64(a.TrafficLimitBytes)
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		if share(sorted[i]) != share(sorted[j]) {
			return share(sorted[i]) > share(sorted[j])
		}
		return name(sorted[i]) < name(sorted[j])
	})
	for _, a := range sorted {
		lines = append(lines, fmt.Sprintf("%s  %s of %s (%.1f%%)", name(a), formatProxyBytes(a.UsedBytes), formatProxyBytes(a.TrafficLimitBytes), share(a)*100))
	}
	return fmt.Sprintf("Lattice proxy quota digest: %d users", len(sorted)), proxyDigestBody(sorted, lines)
}

// proxyDigestBody joins a digest's lines, one per alert in the same order,
// and says which of them are an alert only: the whole message when every user
// is outside the managed render, otherwise the lines marked "alert only".
func proxyDigestBody(alerts []proxyUserNotificationFire, lines []string) string {
	alertOnly := 0
	for _, a := range alerts {
		if a.AlertOnly {
			alertOnly++
		}
	}
	switch alertOnly {
	case 0:
		return strings.Join(lines, "\n")
	case len(alerts):
		return strings.Join(lines, "\n") + "\n" + proxyDigestAlertOnlyNote
	}
	marked := make([]string, len(lines))
	for i, line := range lines {
		marked[i] = line
		if alerts[i].AlertOnly {
			marked[i] += "  alert only"
		}
	}
	return strings.Join(marked, "\n") + "\n" + proxyDigestMixedAlertOnlyNote
}

// withAlertOnlyNote ends a single alert's text with proxyAlertOnlyNote when
// the alert is about an identity outside the managed render.
func withAlertOnlyNote(alert proxyUserNotificationFire, body string) string {
	if !alert.AlertOnly {
		return body
	}
	return body + " " + proxyAlertOnlyNote
}

func (s *Server) emitProxyUserNotification(alert proxyUserNotificationFire) {
	name := firstNonEmpty(alert.UserName, alert.UserID)
	switch alert.Kind {
	case proxyUserAlertQuota:
		pct := float64(alert.UsedBytes) / float64(alert.TrafficLimitBytes) * 100
		title := fmt.Sprintf("Lattice proxy quota %d%%: %s", alert.ThresholdPercent, name)
		body := fmt.Sprintf("%s used %s of %s (%.1f%%). Status: %s.",
			name, formatProxyBytes(alert.UsedBytes), formatProxyBytes(alert.TrafficLimitBytes), pct, firstNonEmpty(alert.Status, model.ProxyUserStatusActive))
		s.emitNotify(title, withAlertOnlyNote(alert, body))
	case proxyUserAlertExpiry:
		when := dateOnlyUTC(alert.ExpiresAt).Format("2006-01-02")
		due := "expired"
		if alert.ExpiryOffsetDays >= 0 {
			due = fmt.Sprintf("due in %dd", alert.ExpiryOffsetDays)
		}
		title := fmt.Sprintf("Lattice proxy expiry %s: %s", due, name)
		body := fmt.Sprintf("%s subscription expires on %s. Status: %s.",
			name, when, firstNonEmpty(alert.Status, model.ProxyUserStatusActive))
		s.emitNotify(title, withAlertOnlyNote(alert, body))
	}
}

func formatProxyBytes(v int64) string {
	return formatProxyBytesIn(v, v)
}

// formatProxyBytesIn formats v in the unit formatProxyBytes picks for ref, so
// two figures meant to be compared read in one unit: "1100 B of its 1000 B
// quota", not "1.1 KiB of its 1000 B quota".
func formatProxyBytesIn(v, ref int64) string {
	const unit = 1024
	if ref < unit {
		return fmt.Sprintf("%d B", v)
	}
	value, scale := float64(v), float64(ref)
	for _, suffix := range []string{"KiB", "MiB", "GiB", "TiB", "PiB"} {
		value /= unit
		scale /= unit
		if scale < unit {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1f EiB", value/unit)
}
