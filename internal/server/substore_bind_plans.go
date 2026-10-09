package server

import (
	"context"
	"errors"
)

// subStorePlanProviderKey is the plan key provider nodes fold under. It is
// not a line UUID, so it can never collide with a catalogue line.
const subStorePlanProviderKey = "provider-content"

// substoreBindPlansPreviewer runs the plans service's previews through the
// bind step (substore_bind_service.go).
type substoreBindPlansPreviewer struct{ s *Server }

func (p substoreBindPlansPreviewer) PreviewBind(ctx context.Context, q subStoreBindQuery) (subStoreBindResult, error) {
	reply, err := p.s.substoreBindPreview(ctx, q.PluginID, q.SubscriptionID, q.Revision, q.IdentityID)
	var notBound substoreBindNotFleetBound
	if errors.As(err, &notBound) {
		// A revision that renders a document binds no line for the identity.
		return subStoreBindResult{LiveRevision: notBound.liveRevision}, nil
	}
	if err != nil {
		return subStoreBindResult{}, err
	}
	return substoreBindResultFromPreview(reply), nil
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
