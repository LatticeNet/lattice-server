package server

import (
	"fmt"
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
}

func (s *Server) evaluateProxyUserNotifications(now time.Time, onlyID string) ([]proxyUserNotificationFire, error) {
	users := s.store.ProxyUsers()
	identities := s.vpnUsersByAccounting()
	fired := []proxyUserNotificationFire{}
	found := onlyID == ""
	changed := false
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
		updated, alerts := s.quotaEvaluate(user, identity, now, usageCounter{})
		if len(alerts) == 0 {
			if updated.Status != originalStatus {
				if err := s.store.UpsertProxyUser(updated); err != nil {
					return nil, err
				}
				changed = true
			}
			continue
		}
		if err := s.store.UpsertProxyUser(updated); err != nil {
			return nil, err
		}
		changed = true
		s.emitProxyUserNotifications(alerts)
		fired = append(fired, alerts...)
	}
	if changed {
		s.invalidateLineReadModel()
	}
	if !found {
		return nil, fmt.Errorf("proxy user not found")
	}
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
	}
	return user, alerts
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
	if used >= limit {
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

func (s *Server) emitProxyUserNotifications(alerts []proxyUserNotificationFire) {
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
		s.emitProxyUserNotification(alert)
	}
}

func (s *Server) emitProxyUserNotification(alert proxyUserNotificationFire) {
	name := firstNonEmpty(alert.UserName, alert.UserID)
	switch alert.Kind {
	case proxyUserAlertQuota:
		pct := float64(alert.UsedBytes) / float64(alert.TrafficLimitBytes) * 100
		title := fmt.Sprintf("Lattice proxy quota %d%%: %s", alert.ThresholdPercent, name)
		body := fmt.Sprintf("%s used %s of %s (%.1f%%). Status: %s.",
			name, formatProxyBytes(alert.UsedBytes), formatProxyBytes(alert.TrafficLimitBytes), pct, firstNonEmpty(alert.Status, model.ProxyUserStatusActive))
		s.emitNotify(title, body)
	case proxyUserAlertExpiry:
		when := dateOnlyUTC(alert.ExpiresAt).Format("2006-01-02")
		due := "expired"
		if alert.ExpiryOffsetDays >= 0 {
			due = fmt.Sprintf("due in %dd", alert.ExpiryOffsetDays)
		}
		title := fmt.Sprintf("Lattice proxy expiry %s: %s", due, name)
		body := fmt.Sprintf("%s subscription expires on %s. Status: %s.",
			name, when, firstNonEmpty(alert.Status, model.ProxyUserStatusActive))
		s.emitNotify(title, body)
	}
}

func formatProxyBytes(v int64) string {
	const unit = 1024
	if v < unit {
		return fmt.Sprintf("%d B", v)
	}
	value := float64(v)
	for _, suffix := range []string{"KiB", "MiB", "GiB", "TiB", "PiB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1f EiB", value/unit)
}
