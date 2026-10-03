package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Headers a subscription client reads besides the body. Clash-family clients
// set their refresh period from Profile-Update-Interval (hours) and name the
// profile after the Content-Disposition filename; most clients show quota and
// expiry from Subscription-Userinfo. Without the first two, every client fell
// back to its own default period and named the profile after the URL.

const (
	// defaultLinkUpdateIntervalHours is what a link advertises unless the
	// operator set its own: the operator default for this phase.
	defaultLinkUpdateIntervalHours = 2
	maxLinkUpdateIntervalHours     = 168
	// shareExtraUpdateInterval stores a share's own interval.
	//
	// yagni: the pinned SDK's SubscriptionShare has no field for it, and cutting
	// an SDK tag is not this slice's to do, so the value rides in the share's
	// Extra map, which round-trips fields a newer schema writes. Upgrade path:
	// add UpdateIntervalHours `json:"update_interval_hours,omitempty"` to the
	// SDK model and read the field; stored values decode into it unchanged.
	shareExtraUpdateInterval = "update_interval_hours"
)

// shareUpdateIntervalHours is the interval a share advertises.
func shareUpdateIntervalHours(share model.SubscriptionShare) int {
	raw, ok := share.Extra[shareExtraUpdateInterval]
	if !ok {
		return defaultLinkUpdateIntervalHours
	}
	var hours int
	if err := json.Unmarshal(raw, &hours); err != nil || hours < 1 || hours > maxLinkUpdateIntervalHours {
		return defaultLinkUpdateIntervalHours
	}
	return hours
}

// withShareUpdateIntervalHours returns the share with its own interval set,
// or cleared back to the default for 0. The Extra map is copied, never
// edited in place: it is shared with the store's copy of the record.
func withShareUpdateIntervalHours(share model.SubscriptionShare, hours int) (model.SubscriptionShare, error) {
	if hours < 0 || hours > maxLinkUpdateIntervalHours {
		return share, errors.New("update_interval_hours must be between 1 and 168, or 0 for the default")
	}
	extra := make(map[string]json.RawMessage, len(share.Extra)+1)
	for k, v := range share.Extra {
		extra[k] = v
	}
	if hours == 0 {
		delete(extra, shareExtraUpdateInterval)
	} else {
		extra[shareExtraUpdateInterval] = json.RawMessage(strconv.Itoa(hours))
	}
	if len(extra) == 0 {
		extra = nil
	}
	share.Extra = extra
	return share, nil
}

// setLinkClientHeaders writes the headers that describe a link to its client.
// The title is the share's slug: an operator-chosen label that is already
// public in the URL, limited by shareSlugRe to characters that need no
// escaping.
func setLinkClientHeaders(header http.Header, title string, updateIntervalHours int) {
	header.Set("Profile-Update-Interval", strconv.Itoa(updateIntervalHours))
	if shareSlugRe.MatchString(title) {
		header.Set("Content-Disposition", `attachment; filename="`+title+`"; filename*=UTF-8''`+title)
	}
}

// subscriptionUserinfoFields are the keys clients read from
// Subscription-Userinfo, in the order they are written.
var subscriptionUserinfoFields = []string{"upload", "download", "total", "expire"}

// canonicalSubscriptionUserinfo keeps the quota header honest. Only the four
// keys clients read survive, each with a non-negative integer value, written
// in one order with one separator. Anything else a source put there (another
// key, a fraction, text, a line break) is dropped rather than repaired, and a
// value with none of the four keys is no header at all.
func canonicalSubscriptionUserinfo(value string) string {
	if len(value) > maxSubscriptionUserinfoBytes {
		return ""
	}
	found := map[string]string{}
	for _, part := range strings.Split(value, ";") {
		key, number, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		key, number = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(number)
		if number == "" || len(number) > 20 || strings.Trim(number, "0123456789") != "" {
			continue
		}
		if _, err := strconv.ParseUint(number, 10, 64); err != nil {
			continue
		}
		found[key] = strings.TrimLeft(number, "0")
		if found[key] == "" {
			found[key] = "0"
		}
	}
	parts := make([]string, 0, len(subscriptionUserinfoFields))
	for _, key := range subscriptionUserinfoFields {
		if number, ok := found[key]; ok {
			parts = append(parts, key+"="+number)
		}
	}
	return strings.Join(parts, "; ")
}
