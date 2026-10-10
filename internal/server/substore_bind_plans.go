package server

import (
	"context"
	"slices"
	"strings"
)

// subStorePlanProviderKey is the plan key provider nodes fold under. It is
// not a line UUID, so it can never collide with a catalogue line.
const subStorePlanProviderKey = "provider-content"

// subStoreBindQuery asks for the validate-and-bind result of one record
// revision for several identities: one render, then one bind per identity.
type subStoreBindQuery struct {
	PluginID       string
	SubscriptionID string
	// Revision is the record revision to render. Never empty: a plan names
	// the live revision and the staged one explicitly.
	Revision string
	// MemberRevisions names, for a collection, the revision each named
	// member resolves at, so the collection's preview follows a member's
	// staged revision ("" names a deleted member). Nil for a record whose
	// own revision is all that changes.
	MemberRevisions map[string]string
	// IdentityIDs are the identities to bind, each once.
	IdentityIDs []string
}

// subStoreBindPreviewer runs validate-and-bind without serving anything:
// fetch or reuse the record's snapshot, render the named revision to a plan
// once, validate every node against one catalogue build, bind each identity,
// and report per identity the entries included and excluded,
// credential-free, with the record's live revision. bind.preview answers
// the UI from the same step. A revision that renders a document binds no
// line for anyone: each identity's result is empty but for LiveRevision.
type subStoreBindPreviewer interface {
	PreviewBind(ctx context.Context, q subStoreBindQuery) (map[string]subStoreBindResult, error)
}

// substoreBindPlansPreviewer runs the plans service's previews through the
// bind step (substore_bind_service.go).
type substoreBindPlansPreviewer struct{ s *Server }

func (p substoreBindPlansPreviewer) PreviewBind(ctx context.Context, q subStoreBindQuery) (map[string]subStoreBindResult, error) {
	out := make(map[string]subStoreBindResult, len(q.IdentityIDs))
	if len(q.IdentityIDs) == 0 {
		return out, nil
	}
	identities := make([]VpnUser, 0, len(q.IdentityIDs))
	for _, identityID := range q.IdentityIDs {
		u, ok := p.s.getVpnUser(identityID)
		if !ok {
			return nil, &subStorePlanPreviewError{revision: q.Revision, identityID: identityID}
		}
		identities = append(identities, u)
	}
	prepared, err := p.s.substoreBindPrepare(ctx, q.PluginID, q.SubscriptionID, q.Revision, q.MemberRevisions)
	if err != nil {
		return nil, err
	}
	for _, u := range identities {
		if prepared.plan == nil {
			out[u.ID] = subStoreBindResult{LiveRevision: prepared.liveRevision}
			continue
		}
		out[u.ID] = substoreBindResultFromPreview(p.s.substoreBindPreviewFor(prepared, u))
	}
	return out, nil
}

// substoreBindResultFromPreview turns a bind preview into the plans
// service's per-identity result.
func substoreBindResultFromPreview(reply substoreBindPreviewReply) subStoreBindResult {
	out := subStoreBindResult{LiveRevision: reply.LiveRevision}
	for _, e := range reply.Entries {
		line := subStoreBindLine{LineUUID: e.LineUUID, Name: e.Label, Digest: e.Digest}
		if e.Provider {
			// Provider nodes bind no line, but they are served on every
			// share, so a revision that swaps provider content must show in
			// the plan: they fold under one key whose digest covers them all.
			line.LineUUID, line.Name = subStorePlanProviderKey, e.Name
		}
		if reply.Refused != "" {
			// A refused plan serves nothing: every line it would bind is excluded.
			line.Reason, line.Digest = reply.Refused, ""
			out.Excluded = append(out.Excluded, line)
			continue
		}
		out.Included = append(out.Included, line)
	}
	for _, x := range reply.Excluded {
		out.Excluded = append(out.Excluded, subStoreBindLine{LineUUID: x.LineUUID, Name: x.Name, Reason: x.Reason})
	}
	return out
}

// subStorePlanSide is one side of a plan's diff for one record: the
// revision the record renders at and the member revisions a collection
// resolves staged members from. Skip takes the side as empty without
// rendering it: the from side of a restored record that has no live
// revision, the before set of a collection that serves nothing, the to side
// of a delete.
type subStorePlanSide struct {
	Revision        string
	MemberRevisions map[string]string
	Skip            bool
}

// subStorePlanIdentities previews one record's two sides once each, binds
// every identity into each, checks that every preview read expectedLive as
// the record's live revision, and diffs them, sorted by identity. With no
// identity, or with both sides skipped, it previews nothing. A caller that
// covers several records (a dependent collection previewed over a member's
// staged revision) passes each record's own expected live revision.
func (s *Server) subStorePlanIdentities(ctx context.Context, subscriptionID, expectedLive string, from, to subStorePlanSide, identityIDs []string) ([]subStorePlanIdentity, error) {
	out := []subStorePlanIdentity{}
	if len(identityIDs) == 0 {
		return out, nil
	}
	previewer := s.subStoreSvc.previewer
	if previewer == nil && (!from.Skip || !to.Skip) {
		return nil, errSubStorePlanNoPreviewer
	}
	sorted := slices.Compact(slices.Sorted(slices.Values(identityIDs)))
	preview := func(side subStorePlanSide) (map[string]subStoreBindResult, error) {
		if side.Skip {
			return map[string]subStoreBindResult{}, nil
		}
		results, err := previewer.PreviewBind(ctx, subStoreBindQuery{PluginID: subStorePluginID, SubscriptionID: subscriptionID,
			Revision: side.Revision, MemberRevisions: side.MemberRevisions, IdentityIDs: sorted})
		if err != nil {
			s.logger.Printf("sub-store plans: bind preview failed for record %s revision %s (%s)",
				subscriptionID, side.Revision, subscriptionDiagnosticSummary(err))
			return nil, &subStorePlanPreviewError{revision: side.Revision, identityID: strings.Join(sorted, ",")}
		}
		for _, identityID := range sorted {
			result, ok := results[identityID]
			if !ok {
				return nil, &subStorePlanPreviewError{revision: side.Revision, identityID: identityID}
			}
			if result.LiveRevision != expectedLive {
				return nil, errSubStorePlanNotLive
			}
		}
		return results, nil
	}
	before, err := preview(from)
	if err != nil {
		return nil, err
	}
	after, err := preview(to)
	if err != nil {
		return nil, err
	}
	for _, identityID := range sorted {
		out = append(out, subStorePlanDiff(identityID, before[identityID], after[identityID]))
	}
	return out, nil
}
