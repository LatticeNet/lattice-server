package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The fleet closure a Sub-Store plan covers (S2 plan section 2.6).
//
// The unit a plan covers is the fleet closure of the changed records, not the
// records alone: every collection that reads one of them now, or would read
// it at its staged revision. Core reads it from the plugin's depends_on v2
// with include_staged, one call per promoted record, and reads the plugin's
// whole graph once more only when a collection is involved, because the
// closure runs upward to readers and never across to a collection's other
// members, which the migration rules need. Files cannot be fleet-bound in S2,
// so a closure that holds one is refused before anything is previewed.

// Plan modes: what the apply does.
const (
	// subStorePlanModePromote promotes one or more staged revisions.
	subStorePlanModePromote = "promote"
	// subStorePlanModeAssign gives identity-less shares an identity (and may
	// clear or archive others) on a record that does not move: no staged
	// document, no apply_revision.
	subStorePlanModeAssign = "assign"
	// subStorePlanModeClear only clears identities and archives shares. It
	// computes no closure, previews nothing and makes no plugin call.
	subStorePlanModeClear = "clear"
	// subStorePlanModeDelete archives a fleet-bound record through the
	// plugin and archives the record's own shares.
	subStorePlanModeDelete = "delete"
)

// Roles of a record in a plan.
const (
	subStorePlanRolePromote    = "promote"
	subStorePlanRoleDelete     = "delete"
	subStorePlanRoleSelf       = "self"
	subStorePlanRoleDependent  = "dependent"
	subStorePlanRoleStagedOnly = "staged_only"
)

// Plan actions on the wire.
const (
	subStorePlanActionPromote = "promote"
	subStorePlanActionDelete  = "delete"
)

// Codes core's plans service answers with (section 2.6). The gateway passes
// a core service's error through, so each reaches the UI as written.
const (
	apiErrorPlanRequired                     = "plan_required"
	apiErrorMigrationRequiresPlan            = "migration_requires_plan"
	apiErrorSharesWithoutIdentity            = "shares_without_identity"
	apiErrorMigrationIncomplete              = "migration_incomplete"
	apiErrorFleetDeleteHasExplicitDependents = "fleet_delete_has_explicit_dependents"
	apiErrorFleetFileUnavailable             = "fleet_file_unavailable"
	apiErrorRevisionUnknown                  = "revision_unknown"
)

// Sources the plans service tells apart.
const (
	subStoreRecordKindCollection = "collection"
	subStoreRecordKindFile       = "file"
)

func subStoreLegacySource(source string) bool {
	return source == subStoreSourceVPNCore || source == subStoreSourceVPNCoreGraph
}

// subStorePlanSpec is a propose request read for its shape.
type subStorePlanSpec struct {
	mode    string
	primary string
	// from and to are the primary record's revisions.
	from, to string
	// promoted is every record the apply promotes, the primary first, each
	// with its own revisions (promote mode); the primary alone for delete.
	promoted []subStorePlanRecordRequest
	// changes are the share changes the request names, by share id.
	changes map[string]subStorePlanShareChange
}

func subStorePlanBadRequest(message string) error {
	return rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, message)
}

// subStorePlanSpecOf validates a propose request's shape: the action, the
// revisions each shape needs, and the share changes.
func subStorePlanSpecOf(req subStorePlansProposeRequest) (subStorePlanSpec, error) {
	spec := subStorePlanSpec{primary: req.SubscriptionID, from: req.FromRevision, changes: map[string]subStorePlanShareChange{}}
	if !subStoreSvcValidID(req.SubscriptionID) {
		return spec, subStorePlanBadRequest("subscription_id is required")
	}
	validRevision := func(revision string) bool { return revision == "" || subStoreSvcValidID(revision) }
	if !validRevision(req.FromRevision) {
		return spec, subStorePlanBadRequest("from_revision is not a revision")
	}
	for shareID, identityID := range req.ShareIdentities {
		if !subStoreSvcValidID(shareID) || (identityID != "" && !subStoreSvcValidID(identityID)) {
			return spec, subStorePlanBadRequest("share_identities maps share ids to an identity id or \"\"")
		}
		spec.changes[shareID] = subStorePlanShareChange{ShareID: shareID, IdentityID: identityID}
	}
	for _, shareID := range req.ArchiveShares {
		if !subStoreSvcValidID(shareID) {
			return spec, subStorePlanBadRequest("archive_shares names an invalid share id")
		}
		if _, dup := spec.changes[shareID]; dup {
			return spec, subStorePlanBadRequest("share " + shareID + " is named twice in share_identities and archive_shares")
		}
		spec.changes[shareID] = subStorePlanShareChange{ShareID: shareID, Archive: true}
	}
	switch req.Action {
	case subStorePlanActionDelete:
		spec.mode = subStorePlanModeDelete
		switch {
		case req.ToRevision != nil:
			return spec, subStorePlanBadRequest("a delete plan takes no to_revision")
		case req.FromRevision == "":
			return spec, subStorePlanBadRequest("a delete plan needs from_revision, the record's live revision")
		case len(req.Records) > 0 || len(spec.changes) > 0:
			return spec, subStorePlanBadRequest("a delete plan takes no records, share_identities or archive_shares: it archives the record's own shares")
		}
		spec.promoted = []subStorePlanRecordRequest{{SubscriptionID: req.SubscriptionID, FromRevision: req.FromRevision}}
		return spec, nil
	case "", subStorePlanActionPromote:
	default:
		return spec, subStorePlanBadRequest("action is promote or delete")
	}
	if req.ToRevision == nil {
		return spec, subStorePlanBadRequest("subscription_id, from_revision and to_revision are required")
	}
	spec.to = *req.ToRevision
	if !validRevision(spec.to) {
		return spec, subStorePlanBadRequest("to_revision is not a revision")
	}
	if spec.from == spec.to {
		if len(req.Records) > 0 {
			return spec, subStorePlanBadRequest("from_revision and to_revision are the same revision: a plan that promotes nothing takes no records")
		}
		if len(spec.changes) == 0 {
			return spec, subStorePlanBadRequest("from_revision and to_revision are the same revision and the plan changes no share")
		}
		spec.mode = subStorePlanModeClear
		for _, change := range spec.changes {
			if !change.Archive && change.IdentityID != "" {
				spec.mode = subStorePlanModeAssign
			}
		}
		if spec.mode == subStorePlanModeAssign && spec.from == "" {
			return spec, subStorePlanBadRequest("an assignment needs the record's live revision as from_revision and to_revision")
		}
		return spec, nil
	}
	if spec.to == "" {
		return spec, subStorePlanBadRequest("to_revision names the staged revision to publish")
	}
	spec.mode = subStorePlanModePromote
	spec.promoted = []subStorePlanRecordRequest{{SubscriptionID: req.SubscriptionID, FromRevision: req.FromRevision, ToRevision: spec.to}}
	for _, record := range req.Records {
		if !subStoreSvcValidID(record.SubscriptionID) || !validRevision(record.FromRevision) || !subStoreSvcValidID(record.ToRevision) || record.FromRevision == record.ToRevision {
			return spec, subStorePlanBadRequest("each of records names a subscription_id, its live from_revision and a different staged to_revision")
		}
		if record.SubscriptionID == req.SubscriptionID {
			if record != spec.promoted[0] {
				return spec, subStorePlanBadRequest("records names the plan's own record with other revisions")
			}
			continue
		}
		if slices.ContainsFunc(spec.promoted, func(r subStorePlanRecordRequest) bool { return r.SubscriptionID == record.SubscriptionID }) {
			return spec, subStorePlanBadRequest("records names " + record.SubscriptionID + " twice")
		}
		spec.promoted = append(spec.promoted, record)
	}
	return spec, nil
}

// promotedIDs is the ids of the records the apply moves.
func (spec subStorePlanSpec) promotedIDs() []string {
	out := make([]string, 0, len(spec.promoted))
	for _, record := range spec.promoted {
		out = append(out, record.SubscriptionID)
	}
	return out
}

// promotedByID indexes the promoted records.
func (spec subStorePlanSpec) promotedByID() map[string]subStorePlanRecordRequest {
	out := make(map[string]subStorePlanRecordRequest, len(spec.promoted))
	for _, record := range spec.promoted {
		out[record.SubscriptionID] = record
	}
	return out
}

// subStorePlanGraph is the closure a plan is computed over.
type subStorePlanGraph struct {
	// closure is the merged depends_on answer of every root.
	closure fleetDependsGraph
	// siblings is the plugin's whole graph over live and staged state, read
	// only when the closure holds a collection; zero otherwise.
	siblings     fleetDependsGraph
	haveSiblings bool
	// ids is the closure record set: every root and every record that reads
	// one, transitively.
	ids map[string]bool
}

// subStorePlanDependsError maps a depends_on failure to a reply that carries
// none of the plugin's text.
func (s *Server) subStorePlanDependsError(err error) error {
	if errors.Is(err, errFleetDependsV1) {
		return rpcAPIError(http.StatusConflict, model.APIErrorBadGateway, err.Error())
	}
	s.logger.Printf("sub-store plans: depends_on failed (%s)", subscriptionDiagnosticSummary(err))
	return rpcAPIError(http.StatusBadGateway, model.APIErrorBadGateway, "the sub-store plugin's depends_on did not answer; nothing was proposed")
}

// subStorePlanGraphFor asks depends_on for the closure of every root, over
// live and staged state, and, when siblings is set and the closure holds a
// collection, for the whole graph as well.
func (s *Server) subStorePlanGraphFor(ctx context.Context, roots []string, siblings bool) (subStorePlanGraph, error) {
	var g subStorePlanGraph
	for i, root := range roots {
		answer, err := s.fleetDependsQuery(ctx, subStorePluginID, fleetDependsRequest{SubscriptionID: root, IncludeStaged: true})
		if err != nil {
			return subStorePlanGraph{}, err
		}
		if _, ok := answer.records[root]; !ok {
			return subStorePlanGraph{}, fmt.Errorf("depends_on did not name the record it was asked for")
		}
		if i == 0 {
			g.closure = answer
		} else {
			g.closure = g.closure.merge(answer)
		}
	}
	g.ids = g.closure.readers(roots...)
	if !siblings {
		return g, nil
	}
	for id := range g.ids {
		if g.closure.records[id].Kind == subStoreRecordKindCollection {
			whole, err := s.fleetDependsQuery(ctx, subStorePluginID, fleetDependsRequest{IncludeStaged: true})
			if err != nil {
				return subStorePlanGraph{}, err
			}
			g.siblings, g.haveSiblings = whole, true
			break
		}
	}
	return g, nil
}

// facts are a record's depends_on facts, from the closure answer or else the
// whole graph.
func (g subStorePlanGraph) facts(id string) (fleetDependsFacts, bool) {
	if facts, ok := g.closure.records[id]; ok {
		return facts, true
	}
	facts, ok := g.siblings.records[id]
	return facts, ok
}

// sortedIDs is the closure record set, sorted.
func (g subStorePlanGraph) sortedIDs() []string {
	out := make([]string, 0, len(g.ids))
	for id := range g.ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// files is every file in the closure.
func (g subStorePlanGraph) files() []string {
	var out []string
	for _, id := range g.sortedIDs() {
		if facts, _ := g.facts(id); facts.Kind == subStoreRecordKindFile {
			out = append(out, id)
		}
	}
	return out
}

// gathered is every record a collection gathers, by either graph, with the
// edge kind; an explicit member wins over a tag match.
func (g subStorePlanGraph) gathered(collection string) map[string]string {
	out := map[string]string{}
	for _, part := range []fleetDependsGraph{g.closure, g.siblings} {
		for _, edge := range part.gathers(collection) {
			if edge.Via == fleetDependsViaNodeSource {
				continue
			}
			if edge.Via == fleetDependsViaMember || out[edge.To] == "" {
				out[edge.To] = edge.Via
			}
		}
	}
	return out
}

// subStorePlanFileRefusal refuses a closure that holds a file: a fleet-bound
// file cannot exist in S2, so apply_revision would refuse the promotion.
func subStorePlanFileRefusal(g subStorePlanGraph) error {
	files := g.files()
	if len(files) == 0 {
		return nil
	}
	return rpcAPIError(http.StatusConflict, apiErrorFleetFileUnavailable, fmt.Sprintf(
		"fleet_file_unavailable: files %s read a record this change makes fleet-bound, and files over fleet sources arrive with S3; "+
			"point them at another node source first", strings.Join(files, ", ")))
}

// subStorePlanMissingMigrations is every legacy record a plan must promote
// beside the ones it does: a collection the promotion makes fleet-bound, or a
// promoted collection, that gathers a record that stays legacy live would be
// mixed and refuse on every fetch, and a promoted collection that names
// explicitly a member with no live revision would fail its next fetch. The
// edges are the union of live and staged state, which may refuse where the
// promotion removes the edge; that refusal costs one more record in the plan.
func subStorePlanMissingMigrations(g subStorePlanGraph, promoted map[string]subStorePlanRecordRequest) []string {
	missing := map[string]bool{}
	collections := map[string]bool{}
	for id := range g.ids {
		if facts, _ := g.facts(id); facts.Kind == subStoreRecordKindCollection {
			collections[id] = true
		}
	}
	for id := range promoted {
		if facts, _ := g.facts(id); facts.Kind == subStoreRecordKindCollection {
			collections[id] = true
		}
	}
	for collection := range collections {
		cf, _ := g.facts(collection)
		members := g.gathered(collection)
		_, changed := promoted[collection]
		becomesFleet := changed || cf.FleetBound || cf.Source == subStoreSourceFleet
		for member := range members {
			if _, ok := promoted[member]; ok {
				if mf, _ := g.facts(member); mf.StagedSource == subStoreSourceFleet || mf.Kind == subStoreRecordKindCollection {
					becomesFleet = true
				}
			}
		}
		if !becomesFleet {
			continue
		}
		for member, via := range members {
			if _, ok := promoted[member]; ok {
				continue
			}
			mf, known := g.facts(member)
			switch {
			case known && mf.Revision != "" && subStoreLegacySource(mf.Source):
				missing[member] = true
			case changed && via == fleetDependsViaMember && known && mf.Revision == "":
				missing[member] = true
			}
		}
	}
	out := make([]string, 0, len(missing))
	for id := range missing {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// subStorePlanMigrationRefusal is migration_incomplete for the missing
// records, or nil.
func subStorePlanMigrationRefusal(missing []string) error {
	if len(missing) == 0 {
		return nil
	}
	return rpcAPIError(http.StatusConflict, apiErrorMigrationIncomplete, fmt.Sprintf(
		"migration_incomplete: %s must be promoted in the same plan, because a collection would otherwise gather a fleet record and a legacy one, "+
			"or name a member that is not live; stage their migrations and pass them in records", strings.Join(missing, ", ")))
}

// subStorePlanExplicitDependents is every collection that names the record
// explicitly as a member, live or staged: a delete would leave each with a
// member that no longer resolves, which fails its next fetch.
func subStorePlanExplicitDependents(g subStorePlanGraph, record string) []string {
	var out []string
	for _, part := range []fleetDependsGraph{g.closure, g.siblings} {
		for _, edge := range part.edges {
			if edge.To == record && edge.Via == fleetDependsViaMember && !slices.Contains(out, edge.From) {
				out = append(out, edge.From)
			}
		}
	}
	sort.Strings(out)
	return out
}

// subStorePlanApplyOrder orders the promoted records so every member comes
// before a collection that gathers it, because apply_revision resolves a
// collection's gathered members by their live state. Ties keep id order.
func subStorePlanApplyOrder(ids []string, g subStorePlanGraph) []string {
	set := map[string]bool{}
	for _, id := range ids {
		set[id] = true
	}
	before := map[string]map[string]bool{} // before[c] = members of c in the set
	for _, id := range ids {
		for member := range g.gathered(id) {
			if set[member] && member != id {
				if before[id] == nil {
					before[id] = map[string]bool{}
				}
				before[id][member] = true
			}
		}
	}
	remaining := slices.Sorted(slices.Values(ids))
	var out []string
	for len(remaining) > 0 {
		progressed := false
		for i, id := range remaining {
			ready := true
			for member := range before[id] {
				if !slices.Contains(out, member) {
					ready = false
					break
				}
			}
			if ready {
				out = append(out, id)
				remaining = slices.Delete(remaining, i, i+1)
				progressed = true
				break
			}
		}
		if !progressed {
			// A cycle cannot be ordered; keep id order for the rest.
			out = append(out, remaining...)
			break
		}
	}
	return out
}

// subStorePlanSharesOf is the live shares of the records, by record.
func (s *Server) subStorePlanSharesOf(ids []string) map[string][]model.SubscriptionShare {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	out := map[string][]model.SubscriptionShare{}
	for _, share := range s.store.SubscriptionSharesUnordered() {
		if isSubStoreShare(share) && share.ArchivedAt == nil && want[share.Source.SubscriptionID] {
			out[share.Source.SubscriptionID] = append(out[share.Source.SubscriptionID], share)
		}
	}
	for id := range out {
		sort.Slice(out[id], func(i, j int) bool { return out[id][i].ID < out[id][j].ID })
	}
	return out
}

// subStorePlanChangeRefusal checks the share changes against the live shares
// of the records the plan previews: each names a live share of one of them,
// a move is between empty and one identity, the identity exists, and an
// identity lands only on a record that is fleet-bound after the plan.
func (s *Server) subStorePlanChangeRefusal(changes map[string]subStorePlanShareChange, shares map[string][]model.SubscriptionShare, fleetAfter func(string) bool) error {
	byID := map[string]model.SubscriptionShare{}
	for _, list := range shares {
		for _, share := range list {
			byID[share.ID] = share
		}
	}
	ids := make([]string, 0, len(changes))
	for id := range changes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, shareID := range ids {
		change := changes[shareID]
		share, ok := byID[shareID]
		if !ok {
			return subStorePlanBadRequest("share " + shareID + " is not a live share of a record this plan covers")
		}
		if change.Archive {
			continue
		}
		switch current := share.Source.IdentityID; {
		case change.IdentityID == current:
			return subStorePlanBadRequest("share " + shareID + " already names that identity")
		case change.IdentityID != "" && current != "":
			return rpcAPIError(http.StatusConflict, apiErrorIdentityChangeRefused, fmt.Sprintf(
				"identity_change_refused: share %s serves identity %s; a link already handed out never starts serving another identity. "+
					"Clear it, or archive it and create a share for the other identity", shareID, current))
		case change.IdentityID != "":
			if _, known := s.getVpnUser(change.IdentityID); !known {
				return subStorePlanBadRequest("share_identities names no identity " + change.IdentityID)
			}
			if !fleetAfter(share.Source.SubscriptionID) {
				return rpcAPIError(http.StatusBadRequest, apiErrorIdentityRequiresFleetRecord, fmt.Sprintf(
					"identity_requires_fleet_record: record %s is not fleet-bound after this plan, so share %s would answer the decoy", share.Source.SubscriptionID, shareID))
			}
		}
	}
	return nil
}
