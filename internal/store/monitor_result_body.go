package store

import (
	"math"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
)

// What an agent result may carry beyond success and latency (design 29 M2a):
// the packets of a multi-packet run and the reason a run measured nothing.

// monitorRTTMaxMs bounds one echo's round trip: past any timeout a save
// allows.
const monitorRTTMaxMs = 120_000

// monitorReasonPattern is the shape of a reason code. The set is open, so
// an agent newer than this server can name a reason it does not know yet;
// the console shows an unknown code as it is.
var monitorReasonPattern = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)

// normalizeMonitorResultBody checks and normalizes the packet and reason
// fields of an agent's result for a monitor of kind. False refuses the
// result as invalid.
//
// A result with a reason is neither up nor down: success, latency and
// packets are cleared. A multi-packet result must be consistent (lost
// within sent, one RTT per echo that came back, at most
// model.MonitorPacketsMax); its success and latency are derived from the
// packets, so the rollups never count a run the packets contradict. Other
// kinds carry no packets.
func normalizeMonitorResultBody(kind string, r model.MonitorResult) (model.MonitorResult, bool) {
	if r.Reason != "" {
		if !monitorReasonPattern.MatchString(r.Reason) {
			return r, false
		}
		r.Success, r.LatencyMs = false, 0
		r.Sent, r.Lost, r.RTTsMs = 0, 0, nil
		return r, true
	}
	if math.IsNaN(r.LatencyMs) || math.IsInf(r.LatencyMs, 0) || r.LatencyMs < 0 || r.LatencyMs > monitorRTTMaxMs {
		return r, false
	}
	if !model.MonitorKindSendsPackets(kind) {
		r.Sent, r.Lost, r.RTTsMs = 0, 0, nil
		return r, true
	}
	if r.Sent == 0 && r.Lost == 0 && len(r.RTTsMs) == 0 {
		// A run that reports no packets counts as one probe.
		return r, true
	}
	if r.Sent < 1 || r.Sent > model.MonitorPacketsMax || r.Lost < 0 || r.Lost > r.Sent || len(r.RTTsMs) != r.Sent-r.Lost {
		return r, false
	}
	for _, rtt := range r.RTTsMs {
		if math.IsNaN(rtt) || math.IsInf(rtt, 0) || rtt < 0 || rtt > monitorRTTMaxMs {
			return r, false
		}
	}
	r.RTTsMs = slices.Clone(r.RTTsMs)
	r.Success = r.Lost < r.Sent
	r.LatencyMs = 0
	if r.Success {
		r.LatencyMs = medianMs(r.RTTsMs)
	}
	return r, true
}

// medianMs is the median of values, the mean of the two middle ones when
// there is an even number. values is not modified.
func medianMs(values []float64) float64 {
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

// monitorErrorURL finds URLs in error text: Go's HTTP client quotes the URL
// it requested in every error it returns.
var monitorErrorURL = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.\-]*://[^\s"'<>]+`)

// SanitizeMonitorError removes the user info, the query and the fragment of
// every URL in an error text, so a token in a check's URL, or one a
// redirect carried, never lands in the stored history.
func SanitizeMonitorError(text string) string {
	if !strings.Contains(text, "://") {
		return text
	}
	return monitorErrorURL.ReplaceAllStringFunc(text, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return stripURLSecretsByHand(raw)
		}
		u.User = nil
		u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = "", false, "", ""
		return u.String()
	})
}

// stripURLSecretsByHand is SanitizeMonitorError for a URL that does not
// parse: cut at the first '?' or '#', and drop everything up to the last '@'
// of the authority.
func stripURLSecretsByHand(raw string) string {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return raw
	}
	authority, path, hasPath := strings.Cut(rest, "/")
	if i := strings.LastIndexByte(authority, '@'); i >= 0 {
		authority = authority[i+1:]
	}
	if hasPath {
		return scheme + "://" + authority + "/" + path
	}
	return scheme + "://" + authority
}
