package server

import (
	"encoding/json"
	"fmt"
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
// The core reads the plugin's records the way the plugin stores them since
// the split store (0.17.0-alpha.2): the index, subscriptions-index-v2, for
// the record list, names, sources, tags, members and node sources, and for a
// vpn-core record its own document, record-v2-<id>, for the identity it
// narrows to, which the index does not carry (subStoreIndexV2 below). The
// guard needs no plugin release. An index that exists but cannot be read
// (over usageMaxSubStoreRecordsLen, or not JSON), and a vpn-core record whose
// document is missing or does not decode, are unknown answers, and an
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
	ID          string
	Kind        string
	Name        string
	Source      string
	VPNIdentity string
	Tags        []string
	Members     []string
	MemberTags  []string
	NodeSource  string
	// identityUnknown marks a vpn-core record whose own document could not
	// be read, so whether it narrows to an identity is not known.
	identityUnknown bool
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
	read := s.subStoreIndexV2()
	if read.unreadable {
		return subStoreFleetIndex{unreadable: true}
	}
	index := subStoreFleetIndex{byID: make(map[string]subStoreFleetRecord, len(read.entries))}
	for _, entry := range read.entries {
		if entry.Revision == "" {
			// A staged-only entry carries no live fact: nothing reads it yet.
			continue
		}
		rec := subStoreFleetRecord{ID: entry.ID, Kind: entry.Kind, Name: firstNonEmpty(entry.DisplayName, entry.Name), Source: entry.Source,
			Tags: entry.Tags, Members: entry.Members, MemberTags: entry.MemberTags, NodeSource: entry.NodeSource}
		if entry.Source == subStoreSourceVPNCore {
			doc, ok := s.subStoreRecordDocument(entry.ID)
			rec.VPNIdentity, rec.identityUnknown = doc.VPNIdentity, !ok
		}
		index.records = append(index.records, rec)
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
	unknown := false
	var walk func(id string, depth int) (bool, string)
	walk = func(id string, depth int) (bool, string) {
		rec, ok := index.byID[strings.TrimSpace(id)]
		if !ok || seen[rec.ID] || depth > subStoreFleetWalkDepth {
			return false, ""
		}
		seen[rec.ID] = true
		if rec.Source == subStoreSourceVPNCore && rec.identityUnknown {
			unknown = true
			return false, ""
		}
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
	if !fleet && unknown {
		return fleetFeedVerdict{Unknown: true}
	}
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

// The plugin's split store as core reads it (S2 plan section 2.6): the index
// for the record list and every live fact it carries, and a record's own
// document for what the index leaves out, the legacy identity and roots. The
// three readers (the fleet-feed guard, usage attribution and the expiring
// names) read nothing from subscriptions-v1, which the plugin deletes after
// a124 and 0.18 are both live.
const (
	// subStoreIndexKey is the plugin's index document.
	subStoreIndexKey = "subscriptions-index-v2"
	// subStoreRecordKeyPrefix starts a record's own document key.
	subStoreRecordKeyPrefix = "record-v2-"
	// subStoreSourceVPNCoreGraph is the legacy graph source.
	subStoreSourceVPNCoreGraph = "vpn-core-graph"
)

// subStoreIndexEntry is the part of an index entry core reads. Revision is
// empty for an entry with no live revision (a staged new record), which
// carries no live fact.
type subStoreIndexEntry struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Tags        []string `json:"tags"`
	Source      string   `json:"source"`
	Members     []string `json:"members"`
	MemberTags  []string `json:"member_tags"`
	NodeSource  string   `json:"node_source"`
	Revision    string   `json:"revision"`
	Flags       struct {
		OwnerCredentials bool `json:"owner_credentials"`
		FleetBound       bool `json:"fleet_bound"`
	} `json:"flags"`
}

// subStoreIndexRead is the index as one read found it. unreadable says an
// index exists and could not be read; no index at all is a store with no
// records.
type subStoreIndexRead struct {
	entries    []subStoreIndexEntry
	unreadable bool
}

// subStoreIndexV2 reads the plugin's index: the live records, in manual
// order. Archived entries are not read.
func (s *Server) subStoreIndexV2() subStoreIndexRead {
	entry, ok := s.store.KVEntry(usageSubStoreKVBucket, subStoreIndexKey)
	if !ok || len(entry.Value) == 0 {
		return subStoreIndexRead{}
	}
	if len(entry.Value) > usageMaxSubStoreRecordsLen {
		return subStoreIndexRead{unreadable: true}
	}
	var doc struct {
		Records []subStoreIndexEntry `json:"records"`
	}
	if err := json.Unmarshal([]byte(entry.Value), &doc); err != nil {
		return subStoreIndexRead{unreadable: true}
	}
	out := subStoreIndexRead{entries: make([]subStoreIndexEntry, 0, len(doc.Records))}
	for _, rec := range doc.Records {
		if strings.TrimSpace(rec.ID) != "" {
			out.entries = append(out.entries, rec)
		}
	}
	return out
}

// subStoreRecordDocument is the part of a record's own document core reads.
type subStoreRecordDocument struct {
	ID          string   `json:"id"`
	Source      string   `json:"source"`
	VPNIdentity string   `json:"vpn_identity"`
	EntryRoots  []string `json:"entry_roots"`
}

// subStoreRecordKey is a record's document key as the plugin writes it
// (storeKeyComponent in the plugin's store_v2.go): the bytes the server
// refuses in a key (a slash, a backslash, a control byte, DEL) and the escape
// byte itself are written as %XX; every other byte is itself.
func subStoreRecordKey(id string) string {
	var b strings.Builder
	b.WriteString(subStoreRecordKeyPrefix)
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c == '%' || c == '/' || c == '\\' || c < 0x20 || c == 0x7f {
			fmt.Fprintf(&b, "%%%02X", c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// subStoreRecordDocument reads one record's own document. ok is false when
// it is missing, over the bound, does not decode or names another record,
// which every reader treats as unknown.
func (s *Server) subStoreRecordDocument(id string) (subStoreRecordDocument, bool) {
	entry, ok := s.store.KVEntry(usageSubStoreKVBucket, subStoreRecordKey(id))
	if !ok || len(entry.Value) == 0 || len(entry.Value) > usageMaxSubStoreRecordsLen {
		return subStoreRecordDocument{}, false
	}
	var doc subStoreRecordDocument
	if err := json.Unmarshal([]byte(entry.Value), &doc); err != nil || doc.ID != id {
		return subStoreRecordDocument{}, false
	}
	return doc, true
}
