package server

import (
	"encoding/json"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
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
// plugin release. A remote record whose URL points at another store's fleet
// subscription (the external Sub-Store's lattice-vpn-core) cannot be told
// from any other provider URL and is not caught here.

const (
	// shareExtraFleetCredentials marks a share created with the explicit
	// flag. It rides in the share's Extra map until the SDK has a field, as
	// update_interval_hours does.
	shareExtraFleetCredentials = "publishes_fleet_credentials"
	// apiErrorFleetFeedFlagRequired refuses a share of a fleet feed created
	// without the flag.
	apiErrorFleetFeedFlagRequired = "fleet_feed_flag_required"

	subStoreSourceVPNCore = "vpn-core"
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

// subStoreFleetFeed reports whether the Sub-Store record subscriptionID
// publishes the identity-less vpn-core export, and through which record.
func (s *Server) subStoreFleetFeed(subscriptionID string) (bool, string) {
	entry, ok := s.store.KVEntry(usageSubStoreKVBucket, usageSubStoreRecordsKey)
	if !ok || len(entry.Value) == 0 || len(entry.Value) > usageMaxSubStoreRecordsLen {
		return false, ""
	}
	var doc struct {
		Records []subStoreFleetRecord `json:"records"`
	}
	if err := json.Unmarshal([]byte(entry.Value), &doc); err != nil {
		return false, ""
	}
	byID := make(map[string]subStoreFleetRecord, len(doc.Records))
	for _, rec := range doc.Records {
		byID[rec.ID] = rec
	}
	seen := map[string]bool{}
	var walk func(id string, depth int) (bool, string)
	walk = func(id string, depth int) (bool, string) {
		rec, ok := byID[strings.TrimSpace(id)]
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
			for _, other := range doc.Records {
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
	return walk(subscriptionID, 0)
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
