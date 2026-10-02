package server

import (
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// One policy projection for every vpn-core identity (adopted-suspend P3).
//
// decideVpnUserPolicy is the only place that decides whether an identity may
// use its lines at a given moment, and if not, why and on whose word. The
// managed render, quota and expiry alerts, plan refusals, the identity views
// and subscription eligibility all read it, directly or through the row it
// writes (vpnUserPolicy.applyTo), so none of them can call an identity over
// its quota while another calls it active. The predicates it shares with
// derivedProxyUserStatusAt, proxyUserExpiredAt and proxyQuotaExhausted, are
// the same functions, so a legacy row with no identity behind it follows the
// same rule too.
//
// It decides; it does not act. Taking a suspended identity off an adopted line
// is the reconciler's job (adopted-suspend P4), which does not exist yet, and
// which will read Reason, By and Evidence from here rather than deciding
// again.

const (
	// vpnSuspendReasonDisabled: the identity's enabled flag is off.
	vpnSuspendReasonDisabled = "disabled"
	// vpnSuspendReasonOperator: an operator suspended the identity while
	// leaving it enabled. It is recorded on the identity (VpnSuspension) by
	// the console's suspend action, which adopted-suspend P8 adds; nothing
	// in this release writes it.
	vpnSuspendReasonOperator = "operator"
	// vpnSuspendReasonExpiry: the identity is past its expiry.
	vpnSuspendReasonExpiry = "expiry"
	// vpnSuspendReasonQuota: the identity has used its whole quota.
	vpnSuspendReasonQuota = "quota"

	// vpnPolicyActor is who suspends an identity for expiry or quota: the
	// policy itself, decided from the identity's own figures.
	vpnPolicyActor = "policy"

	// vpnQuotaEvidenceProof: the bytes a proof rule counted reach the quota
	// on their own (store.UsageDayUser.Proof).
	vpnQuotaEvidenceProof = "proof"
	// vpnQuotaEvidenceInferred: the quota is reached only with bytes an
	// inference rule counted, or the proven part is not known.
	vpnQuotaEvidenceInferred = "inferred"
)

// VpnSuspension records an operator's act that took an identity out of
// service, so the policy can say who did it and since when. It is kept on the
// identity's public record. Reason is disabled (the enabled flag was turned
// off; vpnUserWrite records it) or operator (see vpnSuspendReasonOperator).
// Expiry and quota are not recorded here: the policy derives them from the
// identity's own figures every time it is asked.
type VpnSuspension = store.VpnUserSuspension

// vpnUserQuotaUsage is the usage an identity's quota is measured with.
type vpnUserQuotaUsage struct {
	// Used is the figure compared with the quota: the current period's day
	// rows for a monthly quota, the accounting record's running total for a
	// lifetime one (quotaUsedBytes says why).
	Used int64
	// Proof is the part of Used a proof rule counted, valid when ProofKnown.
	// For a lifetime quota it is summed from the retained day rows, so it is
	// a floor: bytes older than retention, or counted before day rows carried
	// the split, are not proof here.
	Proof      int64
	ProofKnown bool
	// PeriodKey is the yyyymmdd the monthly period started, the key quota
	// alerts carry; empty for a lifetime quota.
	PeriodKey              string
	PeriodStart, PeriodEnd time.Time
}

// vpnUserPolicy is what decideVpnUserPolicy says about one identity at one
// moment.
type vpnUserPolicy struct {
	// Status is the model status rows and alerts carry: active, disabled,
	// expired or over_quota. An operator suspension reads as disabled here,
	// because a row has no other way to say "not now".
	Status string
	// Reason is empty while Status is active, and otherwise why the identity
	// is suspended: disabled, operator, expiry or quota, in that precedence.
	Reason string
	// By is who suspended it: the operator's actor id for disabled or
	// operator when Lattice recorded one (empty for an identity disabled
	// before suspensions were recorded), and vpnPolicyActor for expiry and
	// quota.
	By string
	// Since is when the suspension began, where Lattice knows: the recorded
	// time for disabled or operator, the expiry itself for expiry. A quota
	// crossing's moment is not recorded, so it is zero there.
	Since time.Time

	Enabled    bool
	ExpiresAt  time.Time
	LimitBytes int64
	Usage      vpnUserQuotaUsage
	// Evidence is set when Reason is quota: proof when the proven bytes
	// alone reach the quota, inferred otherwise. Anything that acts on a
	// node without a human may act on proof only.
	Evidence string
}

// Active reports whether the identity may use its lines now.
func (p vpnUserPolicy) Active() bool { return p.Status == model.ProxyUserStatusActive }

// proxyUserExpiredAt is the one expiry rule: an expiry at or before now has
// passed.
func proxyUserExpiredAt(expiresAt, now time.Time) bool {
	return !expiresAt.IsZero() && !expiresAt.After(now)
}

// proxyQuotaExhausted is the one quota rule: a positive quota is used up when
// the usage reaches it.
func proxyQuotaExhausted(used, limit int64) bool {
	return limit > 0 && used >= limit
}

// decideVpnUserPolicy is the policy decision itself, pure over the identity,
// the usage its quota is measured with, and the clock.
func decideVpnUserPolicy(u VpnUser, usage vpnUserQuotaUsage, now time.Time) vpnUserPolicy {
	p := vpnUserPolicy{
		Status: model.ProxyUserStatusActive, Enabled: u.Enabled, ExpiresAt: u.ExpiresAt,
		LimitBytes: u.QuotaBytes, Usage: usage,
	}
	recorded := func(reason string) (string, time.Time) {
		if u.Suspension != nil && u.Suspension.Reason == reason {
			return u.Suspension.By, u.Suspension.Since
		}
		return "", time.Time{}
	}
	switch {
	case !u.Enabled:
		p.Status, p.Reason = model.ProxyUserStatusDisabled, vpnSuspendReasonDisabled
		p.By, p.Since = recorded(vpnSuspendReasonDisabled)
	case u.Suspension != nil && u.Suspension.Reason == vpnSuspendReasonOperator:
		p.Status, p.Reason = model.ProxyUserStatusDisabled, vpnSuspendReasonOperator
		p.By, p.Since = recorded(vpnSuspendReasonOperator)
	case proxyUserExpiredAt(u.ExpiresAt, now):
		p.Status, p.Reason, p.By, p.Since = model.ProxyUserStatusExpired, vpnSuspendReasonExpiry, vpnPolicyActor, u.ExpiresAt
	case proxyQuotaExhausted(usage.Used, u.QuotaBytes):
		p.Status, p.Reason, p.By = model.ProxyUserStatusOverQuota, vpnSuspendReasonQuota, vpnPolicyActor
		p.Evidence = vpnQuotaEvidenceInferred
		if usage.ProofKnown && proxyQuotaExhausted(usage.Proof, u.QuotaBytes) {
			p.Evidence = vpnQuotaEvidenceProof
		}
	}
	return p
}

// applyTo writes the policy onto a ProxyUser row: whether it may serve, its
// expiry, its quota, the usage the quota is measured with, and the status
// those give. The managed render, the drift check and the alerts read rows,
// and derivedProxyUserStatusAt over the result gives back Status, so a row
// and the policy it came from cannot disagree. An operator suspension turns
// the row off, which is the only way a row can carry it.
func (p vpnUserPolicy) applyTo(row model.ProxyUser) model.ProxyUser {
	row.Enabled = p.Enabled && p.Reason != vpnSuspendReasonOperator
	row.ExpiresAt = p.ExpiresAt
	row.TrafficLimitBytes = p.LimitBytes
	if p.LimitBytes > 0 {
		row.UsedBytes = p.Usage.Used
	}
	row.Status = p.Status
	return row
}

// vpnUserQuotaMeasure is the usage an identity's quota is measured with, from
// its day rows. rows must cover the current period for a monthly quota (older
// rows are ignored). For a lifetime quota, accountTotal is the figure, and
// rows, when they cover retention, give its proven part. pending is a report
// being ingested that the rows do not hold yet; its proof split is not known,
// so a measure with pending traffic leaves the proof unknown.
func vpnUserQuotaMeasure(u VpnUser, accountTotal int64, rows []store.UsageDayUser, rowsCoverRetention bool, now time.Time, pending usageCounter) vpnUserQuotaUsage {
	if start, end, ok := vpnUserQuotaPeriod(u, now); ok {
		from, to := store.UsageDay(start), store.UsageDay(now)
		usage := vpnUserQuotaUsage{PeriodKey: from, PeriodStart: start, PeriodEnd: end, ProofKnown: pending.zero()}
		for _, row := range rows {
			if row.Day < from || row.Day > to {
				continue
			}
			usage.Used += row.Uplink + row.Downlink
			usage.Proof += row.Proof
		}
		usage.Used += pending.total()
		return usage
	}
	usage := vpnUserQuotaUsage{Used: accountTotal}
	if rowsCoverRetention {
		for _, row := range rows {
			usage.Proof += row.Proof
		}
		usage.ProofKnown = true
	}
	return usage
}

// vpnUserAccountTotal is the running total on the identity's accounting
// record: the legacy record for a migrated identity, the canonical projection
// otherwise.
func (s *Server) vpnUserAccountTotal(u VpnUser) int64 {
	acct, _ := s.store.ProxyUser(firstNonEmpty(strings.TrimSpace(u.MigratedFromProxyUser), u.ID))
	return acct.UsedBytes
}

// vpnUserPolicyAt is the identity's policy at now with nothing pending. It
// reads the current period's rows for a monthly quota. For a lifetime quota
// the figure is the accounting total, and the retained rows are read for its
// proven part only once the quota is reached, the one case the split
// decides anything, so an identity under its quota costs one record read.
func (s *Server) vpnUserPolicyAt(u VpnUser, now time.Time) vpnUserPolicy {
	if u.QuotaBytes <= 0 {
		return decideVpnUserPolicy(u, vpnUserQuotaUsage{}, now)
	}
	total := s.vpnUserAccountTotal(u)
	var rows []store.UsageDayUser
	coverRetention := false
	if start, _, ok := vpnUserQuotaPeriod(u, now); ok {
		rows = s.usageDayUserRows(u.ID, start, now)
	} else if proxyQuotaExhausted(total, u.QuotaBytes) {
		rows = s.usageDayUserRows(u.ID, now.AddDate(0, 0, -store.UsageDayRetentionDays), now)
		coverRetention = true
	}
	return decideVpnUserPolicy(u, vpnUserQuotaMeasure(u, total, rows, coverRetention, now, usageCounter{}), now)
}

// usageDayUserRows reads an identity's day rows over [from, to] (inclusive
// days), logging and returning none on a read error, as periodUsage does.
func (s *Server) usageDayUserRows(userID string, from, to time.Time) []store.UsageDayUser {
	rows, err := s.store.UsageDayUserRows(userID, store.UsageDay(from), store.UsageDay(to))
	if err != nil {
		s.logger.Printf("usage: read day rows for %s: %v", userID, err)
		return nil
	}
	return rows
}

// vpnUserPolicyView is the policy as the identity views carry it, so the
// console shows the server's decision and its numbers instead of deciding
// again from used_period_bytes.
type vpnUserPolicyView struct {
	Status string `json:"status"`
	// Reason, By and Since are set while the identity is suspended.
	Reason string `json:"reason,omitempty"`
	By     string `json:"suspended_by,omitempty"`
	Since  string `json:"suspended_since,omitempty"`
	// Quota is present when the identity has one.
	Quota *vpnUserQuotaView `json:"quota,omitempty"`
}

type vpnUserQuotaView struct {
	LimitBytes int64 `json:"limit_bytes"`
	// UsedBytes is the figure the quota is compared with (vpnUserQuotaUsage).
	UsedBytes int64 `json:"used_bytes"`
	// ProofBytes is its proven part, present when known.
	ProofBytes *int64 `json:"proof_bytes,omitempty"`
	// Evidence is set once the quota is reached: proof or inferred.
	Evidence    string `json:"evidence,omitempty"`
	Period      string `json:"period"` // monthly | lifetime
	PeriodStart string `json:"period_start,omitempty"`
	PeriodEnd   string `json:"period_end,omitempty"`
}

func (p vpnUserPolicy) view() vpnUserPolicyView {
	out := vpnUserPolicyView{Status: p.Status, Reason: p.Reason, By: p.By}
	if !p.Since.IsZero() {
		out.Since = p.Since.UTC().Format(usageWireTimeFmt)
	}
	if p.LimitBytes > 0 {
		quota := &vpnUserQuotaView{LimitBytes: p.LimitBytes, UsedBytes: p.Usage.Used, Evidence: p.Evidence, Period: "lifetime"}
		if p.Usage.ProofKnown {
			proof := p.Usage.Proof
			quota.ProofBytes = &proof
		}
		if p.Usage.PeriodKey != "" {
			quota.Period = vpnQuotaPeriodMonthly
			quota.PeriodStart = p.Usage.PeriodStart.UTC().Format(usageWireTimeFmt)
			quota.PeriodEnd = p.Usage.PeriodEnd.UTC().Format(usageWireTimeFmt)
		}
		out.Quota = quota
	}
	return out
}
