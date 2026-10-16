package server

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Building a Sub-Store plan's text (S2 plan section 2.6): one section per
// record the plan covers, each with its own live shares, the identities they
// serve before and after, and what each identity receives from each side.
// The first section is the record the request names; it is written at the
// top level of the plan as it always was, and every other record follows in
// records, the promoted ones in apply order, then the dependent collections,
// then the staged-only records, each by id.

// subStorePlanSections is a plan's sections, the request's record first.
func (plan subStorePlan) sections() []subStorePlanRecord {
	primary := subStorePlanRecord{
		SubscriptionID: plan.SubscriptionID, Kind: plan.RecordKind, Role: plan.Role, FromRevision: plan.FromRevision, ToRevision: plan.ToRevision,
		MemberRevisions: plan.MemberRevisions, BeforeEmpty: plan.BeforeEmpty, Totals: plan.PrimaryTotals,
		Shares: plan.Shares, UnboundShares: plan.UnboundShares, Coverage: plan.Coverage, Identities: plan.Identities,
	}
	if primary.Role == "" {
		primary.Role = subStorePlanRolePromote
	}
	return append([]subStorePlanRecord{primary}, plan.Records...)
}

// mode is the plan's mode; a plan written before modes existed promotes.
func (plan subStorePlan) mode() string {
	if plan.Mode == "" {
		return subStorePlanModePromote
	}
	return plan.Mode
}

// applyOrder is the records apply_revision runs for, in order.
func (plan subStorePlan) applyOrder() []string {
	switch plan.mode() {
	case subStorePlanModeAssign, subStorePlanModeClear:
		return nil
	}
	if len(plan.ApplyOrder) > 0 {
		return plan.ApplyOrder
	}
	return []string{plan.SubscriptionID}
}

// shareMaps is, per section that is not staged-only, every live share the
// plan was computed for with the identity it served before the plan: the map
// the stale check compares the live shares against.
func (plan subStorePlan) shareMaps() map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, section := range plan.sections() {
		if section.Role == subStorePlanRoleStagedOnly {
			continue
		}
		m := map[string]string{}
		for _, share := range section.Shares {
			if share.Assigned {
				m[share.ShareID] = ""
			} else {
				m[share.ShareID] = share.IdentityID
			}
		}
		for _, share := range section.UnboundShares {
			m[share.ShareID] = share.ClearedIdentityID
		}
		out[section.SubscriptionID] = m
	}
	return out
}

// sides are the two renders a section's diff is computed from and the live
// revision each must read, by the section's role. An assignment previews only
// the record's live revision: the record does not move, and a share that
// gains an identity goes from no lines to that identity's lines.
func (section subStorePlanRecord) sides() (from, to subStorePlanSide, expected string) {
	expected = section.FromRevision
	switch section.Role {
	case subStorePlanRolePromote:
		from = subStorePlanSide{Revision: section.FromRevision, Skip: section.BeforeEmpty || section.FromRevision == ""}
		to = subStorePlanSide{Revision: section.ToRevision, MemberRevisions: section.MemberRevisions}
	case subStorePlanRoleDelete:
		from = subStorePlanSide{Revision: section.FromRevision}
		to = subStorePlanSide{Skip: true}
	case subStorePlanRoleSelf:
		from = subStorePlanSide{Skip: true}
		to = subStorePlanSide{Revision: section.FromRevision}
	default:
		from = subStorePlanSide{Revision: section.FromRevision, Skip: section.BeforeEmpty}
		to = subStorePlanSide{Revision: section.FromRevision, MemberRevisions: section.MemberRevisions}
	}
	return from, to, expected
}

// identityIDs is every identity a section's shares serve before or after the
// plan; for an assignment, only the identities given and cleared.
func (section subStorePlanRecord) identityIDs() []string {
	seen := map[string]bool{}
	add := func(id string) {
		if id != "" {
			seen[id] = true
		}
	}
	for _, share := range section.Shares {
		if section.Role != subStorePlanRoleSelf || share.Assigned {
			add(share.IdentityID)
		}
	}
	for _, share := range section.UnboundShares {
		add(share.ClearedIdentityID)
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// subStorePlanPreviewSection previews one section's two sides once each and
// binds every identity it names into each, through the bind code's
// subStorePlanIdentities with the section's own expected live revision and
// member revisions. A staged-only section is not previewed.
func (s *Server) subStorePlanPreviewSection(ctx context.Context, section subStorePlanRecord) (map[string]subStorePlanIdentity, error) {
	out := map[string]subStorePlanIdentity{}
	if section.Role == subStorePlanRoleStagedOnly {
		return out, nil
	}
	from, to, expected := section.sides()
	diffs, err := s.subStorePlanIdentities(ctx, section.SubscriptionID, expected, from, to, section.identityIDs())
	if err != nil {
		return nil, err
	}
	for _, diff := range diffs {
		out[diff.IdentityID] = diff
	}
	return out, nil
}

// subStorePlanSectionRows lists a record's live shares under the identity
// each serves after the plan, with its change: given an identity, cleared of
// one, or archived.
func subStorePlanSectionRows(section *subStorePlanRecord, shares []model.SubscriptionShare, changes map[string]subStorePlanShareChange) {
	section.Shares, section.UnboundShares = []subStorePlanShare{}, []subStorePlanUnboundShare{}
	for _, share := range shares {
		change, changed := changes[share.ID]
		before, after := share.Source.IdentityID, share.Source.IdentityID
		archive := changed && change.Archive
		if changed && !change.Archive {
			after = change.IdentityID
		}
		if after != "" {
			section.Shares = append(section.Shares, subStorePlanShare{
				ShareID: share.ID, Slug: share.Slug, DisplayName: share.DisplayName, IdentityID: after,
				Enabled: share.Enabled, ExpiresAt: share.ExpiresAt, Assigned: before == "", Archive: archive,
			})
			continue
		}
		section.UnboundShares = append(section.UnboundShares, subStorePlanUnboundShare{
			ShareID: share.ID, Slug: share.Slug, DisplayName: share.DisplayName, Enabled: share.Enabled, ExpiresAt: share.ExpiresAt,
			FleetCredentials: shareFleetCredentials(share), ClearedIdentityID: before, Archive: archive,
		})
	}
}

// subStorePlanFillSection writes a section's counts and identities from its
// diffs. An assignment's section lists only the identities it gives.
func subStorePlanFillSection(section *subStorePlanRecord, diffs map[string]subStorePlanIdentity) {
	section.Identities = []subStorePlanIdentity{}
	section.Totals = subStorePlanTotals{}
	listed := map[string]bool{}
	for _, share := range section.Shares {
		if section.Role != subStorePlanRoleSelf || share.Assigned {
			listed[share.IdentityID] = true
		}
	}
	for i := range section.Shares {
		share := &section.Shares[i]
		if section.Role == subStorePlanRoleSelf && !share.Assigned {
			continue
		}
		diff := diffs[share.IdentityID]
		share.Added, share.Removed, share.Changed, share.Excluded = len(diff.Added), len(diff.Removed), len(diff.Changed), len(diff.Excluded)
	}
	ids := make([]string, 0, len(listed))
	for id := range listed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		diff, ok := diffs[id]
		if !ok {
			continue
		}
		section.Identities = append(section.Identities, diff)
		section.Totals.Added += len(diff.Added)
		section.Totals.Removed += len(diff.Removed)
		section.Totals.Changed += len(diff.Changed)
		section.Totals.Excluded += len(diff.Excluded)
	}
	section.Totals.Shares, section.Totals.UnboundShares, section.Totals.Identities = len(section.Shares), len(section.UnboundShares), len(section.Identities)
	section.Coverage = ""
	if len(section.UnboundShares) > 0 {
		section.Coverage = subStorePlanUnboundCoverage
	}
}

// subStorePlanLinesAfter and subStorePlanLinesBefore count the lines an
// identity receives after and before the plan.
func subStorePlanLinesAfter(diff subStorePlanIdentity) int {
	return len(diff.Added) + len(diff.Changed) + diff.Unchanged
}

func subStorePlanLinesBefore(diff subStorePlanIdentity) int {
	return len(diff.Removed) + len(diff.Changed) + diff.Unchanged
}

// subStoreBuildPlan writes the plan of a propose: a section per record of
// the closure, previewed once per side, and the assignments, clearings and
// archivals under their own headings, so the approval's hash covers them.
func (s *Server) subStoreBuildPlan(ctx context.Context, spec subStorePlanSpec, g subStorePlanGraph, shares map[string][]model.SubscriptionShare) (subStorePlan, error) {
	sections := s.subStorePlanSections(spec, g)
	plan := subStorePlan{Kind: subStorePlanKind, PluginID: subStorePluginID, SubscriptionID: spec.primary, FromRevision: spec.from, ToRevision: spec.to,
		Mode: spec.mode}
	if spec.mode == subStorePlanModeDelete {
		plan.Action = subStorePlanActionDelete
		plan.ToRevision = ""
	}
	switch spec.mode {
	case subStorePlanModePromote:
		plan.ApplyOrder = subStorePlanApplyOrder(spec.promotedIDs(), g)
	case subStorePlanModeDelete:
		plan.ApplyOrder = []string{spec.primary}
	}
	changes := spec.changes
	if spec.mode == subStorePlanModeDelete {
		// A delete archives the record's own live shares, and only those.
		changes = map[string]subStorePlanShareChange{}
		for _, share := range shares[spec.primary] {
			changes[share.ID] = subStorePlanShareChange{ShareID: share.ID, Archive: true}
		}
	}
	allDiffs := map[string]map[string]subStorePlanIdentity{}
	for i := range sections {
		section := &sections[i]
		if section.Role == subStorePlanRoleStagedOnly {
			section.Shares, section.UnboundShares, section.Identities = []subStorePlanShare{}, []subStorePlanUnboundShare{}, []subStorePlanIdentity{}
			continue
		}
		subStorePlanSectionRows(section, shares[section.SubscriptionID], changes)
		diffs, err := s.subStorePlanPreviewSection(ctx, *section)
		if err != nil {
			return subStorePlan{}, subStorePlanProposeError(err)
		}
		allDiffs[section.SubscriptionID] = diffs
		subStorePlanFillSection(section, diffs)
	}
	subStorePlanListChanges(&plan, sections, allDiffs)
	for _, section := range sections {
		plan.Closure = append(plan.Closure, section.SubscriptionID)
		plan.Totals.Shares += section.Totals.Shares
		plan.Totals.UnboundShares += section.Totals.UnboundShares
		plan.Totals.Identities += section.Totals.Identities
		plan.Totals.Added += section.Totals.Added
		plan.Totals.Removed += section.Totals.Removed
		plan.Totals.Changed += section.Totals.Changed
		plan.Totals.Excluded += section.Totals.Excluded
	}
	sort.Strings(plan.Closure)
	primary := sections[0]
	plan.RecordKind, plan.Role, plan.MemberRevisions, plan.BeforeEmpty = primary.Kind, primary.Role, primary.MemberRevisions, primary.BeforeEmpty
	plan.PrimaryTotals, plan.Shares, plan.UnboundShares, plan.Coverage, plan.Identities = primary.Totals, primary.Shares, primary.UnboundShares, primary.Coverage, primary.Identities
	plan.Records = sections[1:]
	return plan, nil
}

// subStorePlanListChanges lists the share changes under their headings, each
// with the lines the identity it gives or clears receives.
func subStorePlanListChanges(plan *subStorePlan, sections []subStorePlanRecord, diffs map[string]map[string]subStorePlanIdentity) {
	for _, section := range sections {
		for _, share := range section.Shares {
			if share.Archive {
				plan.Archivals = append(plan.Archivals, subStorePlanArchival{ShareID: share.ShareID, SubscriptionID: section.SubscriptionID,
					Slug: share.Slug, DisplayName: share.DisplayName, IdentityID: share.IdentityID})
			}
			if share.Assigned {
				plan.Assignments = append(plan.Assignments, subStorePlanAssignment{ShareID: share.ShareID, SubscriptionID: section.SubscriptionID,
					Slug: share.Slug, DisplayName: share.DisplayName, IdentityID: share.IdentityID,
					Lines: subStorePlanLinesAfter(diffs[section.SubscriptionID][share.IdentityID])})
			}
		}
		for _, share := range section.UnboundShares {
			if share.Archive {
				plan.Archivals = append(plan.Archivals, subStorePlanArchival{ShareID: share.ShareID, SubscriptionID: section.SubscriptionID,
					Slug: share.Slug, DisplayName: share.DisplayName, IdentityID: share.ClearedIdentityID})
			}
			if share.ClearedIdentityID != "" && !share.Archive {
				diff := diffs[section.SubscriptionID][share.ClearedIdentityID]
				lines := subStorePlanLinesBefore(diff)
				if section.Role == subStorePlanRoleSelf {
					// The record does not move: what the identity receives
					// from the live revision is what the share stops serving.
					lines = subStorePlanLinesAfter(diff)
				}
				plan.Clearings = append(plan.Clearings, subStorePlanAssignment{ShareID: share.ShareID, SubscriptionID: section.SubscriptionID,
					Slug: share.Slug, DisplayName: share.DisplayName, IdentityID: share.ClearedIdentityID, Lines: lines})
			}
		}
	}
}

// subStorePlanSections is the section of every record the plan covers, with
// its role and the sides it previews, the request's record first.
func (s *Server) subStorePlanSections(spec subStorePlanSpec, g subStorePlanGraph) []subStorePlanRecord {
	promoted := spec.promotedByID()
	memberRevisions := func(self string) map[string]string {
		if spec.mode == subStorePlanModeDelete {
			if self == spec.primary {
				return nil
			}
			return map[string]string{spec.primary: ""}
		}
		out := map[string]string{}
		for id, record := range promoted {
			if id != self {
				out[id] = record.ToRevision
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	mixed := func(facts fleetDependsFacts) bool { return facts.FleetBound && facts.OwnerCredentials }
	var head, promotedTail, dependents, stagedOnly []subStorePlanRecord
	add := func(section subStorePlanRecord) {
		switch {
		case section.SubscriptionID == spec.primary:
			head = append(head, section)
		case section.Role == subStorePlanRolePromote:
			promotedTail = append(promotedTail, section)
		case section.Role == subStorePlanRoleStagedOnly:
			stagedOnly = append(stagedOnly, section)
		default:
			dependents = append(dependents, section)
		}
	}
	switch spec.mode {
	case subStorePlanModeAssign:
		facts, _ := g.facts(spec.primary)
		add(subStorePlanRecord{SubscriptionID: spec.primary, Kind: facts.Kind, Role: subStorePlanRoleSelf, FromRevision: spec.from})
		return head
	case subStorePlanModeDelete:
		facts, _ := g.facts(spec.primary)
		add(subStorePlanRecord{SubscriptionID: spec.primary, Kind: facts.Kind, Role: subStorePlanRoleDelete, FromRevision: spec.from})
	default:
		for _, id := range subStorePlanApplyOrder(spec.promotedIDs(), g) {
			record := promoted[id]
			facts, _ := g.facts(id)
			add(subStorePlanRecord{SubscriptionID: id, Kind: facts.Kind, Role: subStorePlanRolePromote, FromRevision: record.FromRevision,
				ToRevision: record.ToRevision, MemberRevisions: memberRevisions(id), BeforeEmpty: record.FromRevision == "" || mixed(facts)})
		}
	}
	for _, id := range g.sortedIDs() {
		if _, ok := promoted[id]; ok || id == spec.primary {
			continue
		}
		facts, _ := g.facts(id)
		if facts.Revision == "" {
			add(subStorePlanRecord{SubscriptionID: id, Kind: facts.Kind, Role: subStorePlanRoleStagedOnly})
			continue
		}
		add(subStorePlanRecord{SubscriptionID: id, Kind: facts.Kind, Role: subStorePlanRoleDependent, FromRevision: facts.Revision,
			MemberRevisions: memberRevisions(id), BeforeEmpty: mixed(facts)})
	}
	out := append(head, promotedTail...)
	out = append(out, dependents...)
	return append(out, stagedOnly...)
}

// subStorePlanIdentitiesEqual reports whether a decision's previews of a
// section give the identities the plan shows for it.
func subStorePlanIdentitiesEqual(want []subStorePlanIdentity, got map[string]subStorePlanIdentity, section subStorePlanRecord) bool {
	rebuilt := section
	rebuilt.Shares = append([]subStorePlanShare(nil), section.Shares...)
	subStorePlanFillSection(&rebuilt, got)
	a, errA := json.Marshal(want)
	b, errB := json.Marshal(rebuilt.Identities)
	return errA == nil && errB == nil && string(a) == string(b)
}
