package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// The fleet-feed guard (identity-sub P10, server half).
//
// A Sub-Store record whose source is vpn-core with no identity reads the
// whole fleet export: every legacy user's links and every adopted line's
// owner share_url, which is every line owner's credential. That feed is the
// operator's own; handed to a user, it gives them everyone's credentials,
// which is the opposite of "a user can only ever fetch their own". So a share
// that would publish such a record, directly or through a combination or a
// file that takes its nodes from one, is refused unless the request says
// publishes_fleet_credentials: true, and the share records that it does so
// the console can keep warning about it.
//
// The core reads the plugin's records the way subStoreGraphRecords does
// (plugin:latticenet.sub-store / subscriptions-v1), so the guard needs no
// plugin release. A record list that exists but cannot be read (over
// usageMaxSubStoreRecordsLen, or not JSON) is an unknown answer, and an
// unknown answer needs the flag as a fleet feed does.
//
// Limits, stated so nobody mistakes the guard for an enforcement point:
//
//   - The refusal runs at creation only. A record edited in the plugin after
//     its share was made (a provider turned into the identity-less vpn-core
//     source, a fleet record added to a combination) is not refused. The
//     share views re-run the walk on every read and answer fleet_feed_now
//     ("fleet" or "unknown") for an unflagged share, so the console can warn
//     about it; the share keeps serving.
//   - The serve path does not re-check. It would parse the plugin's record
//     list (up to 4 MiB) on every client poll, the hot path a105 budgeted.
//   - A remote record whose URL points at another store's fleet subscription
//     (the external Sub-Store's lattice-vpn-core) cannot be told from any
//     other provider URL and is not caught.

const (
	// shareExtraFleetCredentials marks a share created with the explicit
	// flag. It rides in the share's Extra map until the SDK has a field, as
	// update_interval_hours does.
	shareExtraFleetCredentials = "publishes_fleet_credentials"
	// apiErrorFleetFeedFlagRequired refuses a share of a fleet feed created
	// without the flag.
	apiErrorFleetFeedFlagRequired = "fleet_feed_flag_required"

	subStoreSourceVPNCore = "vpn-core"

	// fleetFeedNowFleet and fleetFeedNowUnknown are the share view's
	// fleet_feed_now answers for an unflagged Sub-Store share.
	fleetFeedNowFleet   = "fleet"
	fleetFeedNowUnknown = "unknown"
	// subStoreFleetWalkDepth bounds the walk through combinations and files;
	// the plugin itself refuses deeper nesting.
	subStoreFleetWalkDepth = 8
)

// subStoreFleetRecord is the part of a Sub-Store record the guard reads.
type subStoreFleetRecord struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Name        string   `json:"name"`
	Source      string   `json:"source"`
	VPNIdentity string   `json:"vpn_identity"`
	Tags        []string `json:"tags"`
	Members     []string `json:"members"`
	MemberTags  []string `json:"member_tags"`
	NodeSource  string   `json:"node_source"`
}

// subStoreFleetIndex is the plugin's record list as the guard reads it.
type subStoreFleetIndex struct {
	records []subStoreFleetRecord
	byID    map[string]subStoreFleetRecord
	// unreadable says a list exists and could not be read: over the size
	// limit or not JSON. No list at all is a store with no records.
	unreadable bool
}

// fleetFeedVerdict is the guard's answer for one record.
type fleetFeedVerdict struct {
	// Fleet: the record publishes the identity-less vpn-core export,
	// through Via (the record's name, or a member's).
	Fleet bool
	Via   string
	// Unknown: the record list could not be read, so nothing was checked.
	Unknown bool
}

// now is the verdict as a share view's fleet_feed_now.
func (v fleetFeedVerdict) now() string {
	switch {
	case v.Fleet:
		return fleetFeedNowFleet
	case v.Unknown:
		return fleetFeedNowUnknown
	}
	return ""
}

func (s *Server) subStoreFleetIndex() subStoreFleetIndex {
	entry, ok := s.store.KVEntry(usageSubStoreKVBucket, usageSubStoreRecordsKey)
	if !ok || len(entry.Value) == 0 {
		return subStoreFleetIndex{}
	}
	if len(entry.Value) > usageMaxSubStoreRecordsLen {
		return subStoreFleetIndex{unreadable: true}
	}
	var doc struct {
		Records []subStoreFleetRecord `json:"records"`
	}
	if err := json.Unmarshal([]byte(entry.Value), &doc); err != nil {
		return subStoreFleetIndex{unreadable: true}
	}
	index := subStoreFleetIndex{records: doc.Records, byID: make(map[string]subStoreFleetRecord, len(doc.Records))}
	for _, rec := range doc.Records {
		index.byID[rec.ID] = rec
	}
	return index
}

// subStoreFleetFeed answers whether the Sub-Store record subscriptionID
// publishes the identity-less vpn-core export.
func (s *Server) subStoreFleetFeed(subscriptionID string) fleetFeedVerdict {
	return s.subStoreFleetIndex().verdict(subscriptionID)
}

// verdict walks from subscriptionID through combinations (by member and by
// tag) and file node sources to an identity-less vpn-core record.
func (index subStoreFleetIndex) verdict(subscriptionID string) fleetFeedVerdict {
	if index.unreadable {
		return fleetFeedVerdict{Unknown: true}
	}
	seen := map[string]bool{}
	var walk func(id string, depth int) (bool, string)
	walk = func(id string, depth int) (bool, string) {
		rec, ok := index.byID[strings.TrimSpace(id)]
		if !ok || seen[rec.ID] || depth > subStoreFleetWalkDepth {
			return false, ""
		}
		seen[rec.ID] = true
		if rec.Source == subStoreSourceVPNCore && strings.TrimSpace(rec.VPNIdentity) == "" {
			return true, firstNonEmpty(rec.Name, rec.ID)
		}
		var next []string
		if rec.Kind == "collection" {
			next = append(next, rec.Members...)
			for _, other := range index.records {
				if other.Kind == "collection" || other.Kind == "file" {
					continue
				}
				for _, tag := range other.Tags {
					for _, want := range rec.MemberTags {
						if tag == want {
							next = append(next, other.ID)
						}
					}
				}
			}
		}
		if rec.NodeSource != "" {
			next = append(next, rec.NodeSource)
		}
		for _, child := range next {
			if fleet, via := walk(child, depth+1); fleet {
				return true, via
			}
		}
		return false, ""
	}
	fleet, via := walk(subscriptionID, 0)
	return fleetFeedVerdict{Fleet: fleet, Via: via}
}

// writeFleetFeedRefusal answers 400 fleet_feed_flag_required with the
// verdict beside the error ("fleet_feed": "fleet" or "unknown", and "via",
// the record that reads the export), so the console can word the two cases
// without parsing the sentence.
func writeFleetFeedRefusal(w http.ResponseWriter, verdict fleetFeedVerdict, message string) {
	requestID := w.Header().Get(requestIDHeader)
	if requestID == "" {
		requestID = id.New("req")
		w.Header().Set(requestIDHeader, requestID)
	}
	writeJSON(w, http.StatusBadRequest, map[string]any{
		"error":      model.APIError{Code: apiErrorFleetFeedFlagRequired, Message: message, RequestID: requestID},
		"fleet_feed": verdict.now(),
		"via":        verdict.Via,
	})
}

// isSubStoreShare reports a share whose source is a Sub-Store record.
func isSubStoreShare(share model.SubscriptionShare) bool {
	return share.Source.Kind == model.ShareSourcePlugin && share.Source.PluginID == subStorePluginID
}

// shareFleetCredentials reports whether a share was created with the flag.
func shareFleetCredentials(share model.SubscriptionShare) bool {
	raw, ok := share.Extra[shareExtraFleetCredentials]
	if !ok {
		return false
	}
	var flagged bool
	return json.Unmarshal(raw, &flagged) == nil && flagged
}

// withShareFleetCredentials returns the share carrying the flag. The Extra
// map is copied, never edited in place.
func withShareFleetCredentials(share model.SubscriptionShare) model.SubscriptionShare {
	extra := make(map[string]json.RawMessage, len(share.Extra)+1)
	for k, v := range share.Extra {
		extra[k] = v
	}
	extra[shareExtraFleetCredentials] = json.RawMessage("true")
	share.Extra = extra
	return share
}
