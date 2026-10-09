package server

import "context"

// substoreBindPlansPreviewer runs the plans service's previews through the
// bind step (substore_bind_service.go).
type substoreBindPlansPreviewer struct{ s *Server }

func (p substoreBindPlansPreviewer) PreviewBind(ctx context.Context, q subStoreBindQuery) (subStoreBindResult, error) {
	reply, err := p.s.substoreBindPreview(ctx, q.PluginID, q.SubscriptionID, q.Revision, q.IdentityID)
	if err != nil {
		return subStoreBindResult{}, err
	}
	var out subStoreBindResult
	for _, e := range reply.Entries {
		if e.Provider {
			continue
		}
		line := subStoreBindLine{LineUUID: e.LineUUID, Name: e.Label, Digest: e.Digest}
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
	return out, nil
}
