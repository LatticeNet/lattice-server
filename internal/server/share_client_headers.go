package server

import (
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"slices"
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

// Response headers a plugin record asks for (design 28, "Share serving and
// tokens"). A render reply may carry headers, and so may the convert reply of
// a fleet-bound record's response chain. Core forwards only the four the SDK
// allow-lists, matching names without regard to case, and only values that
// pass model.ValidateSubscriptionResponseHeader: no control character, so no
// CR or LF can end the header early; an interval of 1 to 168 hours; a web
// page URL that is https, carries no userinfo, fits in 2 KiB and names no
// local host and no private, loopback, link-local or other non-public address
// literal. Every other value is held to recordHeaderValueBytes here. A header
// that fails is dropped, never the response, and every other name is dropped
// too: a record never sets the status or Subscription-Userinfo.
//
// A share that names an identity also screens every value for that
// identity's credentials with the catalogue's row check (lineCatalogueSecrets:
// any whole credential part four bytes or longer, raw or encoded). None of the
// four headers has a reason to carry one, and the response chain of a
// fleet-bound record runs over a document that holds them.

// recordHeaderValueBytes bounds a record header's value, the web page URL
// excepted (model.MaxSubscriptionResponseHeaderBytes).
const recordHeaderValueBytes = 256

// shareRecordHeaders returns the headers core forwards from what a record
// asked for, keyed by lower-case name, or nil. A later map replaces an
// earlier one's value for the same name; within one map, names are read in
// sorted order, so two spellings of one name resolve the same way every time.
func shareRecordHeaders(identity lineCatalogueSecrets, asked ...map[string]string) map[string]string {
	var out map[string]string
	for _, headers := range asked {
		for _, name := range slices.Sorted(maps.Keys(headers)) {
			value, lower := headers[name], strings.ToLower(name)
			if model.ValidateSubscriptionResponseHeader(lower, value) != nil ||
				(lower != model.ResponseHeaderProfileWebPageURL && len(value) > recordHeaderValueBytes) ||
				identity.in([]byte(value)) {
				continue
			}
			if out == nil {
				out = map[string]string{}
			}
			out[lower] = value
		}
	}
	return out
}

// setShareRecordHeaders writes the record headers shareRecordHeaders
// admitted. They replace the link's defaults from setLinkClientHeaders,
// except that an update interval the operator set on the share itself wins
// over the record's.
func setShareRecordHeaders(header http.Header, share model.SubscriptionShare, record map[string]string) {
	_, ownInterval := share.Extra[shareExtraUpdateInterval]
	for name, value := range record {
		if name == model.ResponseHeaderProfileUpdateInterval && ownInterval {
			continue
		}
		header.Set(name, value)
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
