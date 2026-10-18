package server

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Design 31, S5: what a plan with a source list says, and the script lines
// it adds. The Safety lines are derived from the list, so a plan that lists a
// mirror or the release can never claim the node needs no third-party
// egress.

// agentUpdateLastSuccess is the node's last applied agent update that carried
// a source list.
type agentUpdateLastSuccess struct {
	ApprovalID string
	Version    string
	Sources    []model.AgentUpdateSource
}

// lastAppliedAgentUpdateSources finds the node's most recently applied
// agent update whose payload carries sources.
func (s *Server) lastAppliedAgentUpdateSources(nodeID string) *agentUpdateLastSuccess {
	var best *agentUpdateLastSuccess
	var bestAt model.Approval
	for _, a := range s.store.Approvals() {
		if a.Plugin != agentUpdatePlugin || a.NodeID != nodeID || a.Status != model.ApprovalApplied {
			continue
		}
		payload, err := agentUpdatePayloadFromApproval(a)
		if err != nil || len(payload.Sources) == 0 {
			continue
		}
		if best == nil || a.UpdatedAt.After(bestAt.UpdatedAt) {
			best = &agentUpdateLastSuccess{ApprovalID: a.ID, Version: payload.TargetVersion, Sources: payload.Sources}
			bestAt = a
		}
	}
	return best
}

// writeAgentUpdateSourceLines writes the Safety lines of a plan with
// sources: each source in order with what it is sent and whether it is
// followed through a redirect, the hosts the node contacts, the manifest,
// and how the list differs from the last successful update.
func writeAgentUpdateSourceLines(b *strings.Builder, payload agentUpdatePayload, last *agentUpdateLastSuccess) {
	compressed := payload.CompressedSHA256 != ""
	controlPlane := false
	var hosts []string
	fmt.Fprintf(b, "- sources, tried in this order, each over HTTPS only and each continuing what the sources before it kept of the same file:\n")
	for i, src := range payload.Sources {
		switch src.Kind {
		case model.AgentSourceKindMirror:
			fmt.Fprintf(b, "  %d. mirror %s (%s): %s; sent no credential and never followed through a redirect\n", i+1, src.Mirror, src.Reason, src.URL)
		case model.AgentSourceKindControlPlane:
			controlPlane = true
			fmt.Fprintf(b, "  %d. this control plane (%s): %s; the only source sent the task lease, and never followed through a redirect\n", i+1, src.Reason, src.URL)
		case model.AgentSourceKindUpstream:
			fmt.Fprintf(b, "  %d. upstream (%s): %s; followed through redirects to HTTPS only, and sent no credential\n", i+1, src.Reason, src.URL)
		}
		if src.Kind == model.AgentSourceKindControlPlane {
			continue
		}
		if u, err := url.Parse(src.URL); err == nil && !slices.Contains(hosts, u.Hostname()) {
			hosts = append(hosts, u.Hostname())
		}
	}
	if len(hosts) == 0 {
		fmt.Fprintf(b, "- the binary comes from this control plane, so the node needs no third-party egress\n")
	} else {
		fmt.Fprintf(b, "- the node contacts %s for the binary, so it needs egress to them\n", strings.Join(hosts, ", "))
	}
	if controlPlane {
		fmt.Fprintf(b, "- the control plane re-verifies the stored bytes against this digest before serving them\n")
	} else {
		fmt.Fprintf(b, "- import this version under Agent updates to serve it from the control plane as well\n")
	}
	if compressed {
		fmt.Fprintf(b, "- the control plane sends the binary gzip-compressed, %d bytes for %d; the node holds the compressed file to compressed_sha256 before decompressing it, stops decompressing past binary_size bytes and refuses any other size, then holds the result to sha256 before running it; the compressed download is kept between attempts as %s<compressed_sha256>, the other sources' as %s<sha256>\n",
			payload.CompressedSize, payload.BinarySize, agentUpdatePartialPrefix, agentUpdatePartialPrefix)
		if len(payload.Sources) > 1 {
			fmt.Fprintf(b, "- a node without a working gzip or head -c skips the compressed download and walks the other sources\n")
		} else {
			fmt.Fprintf(b, "- a node without a working gzip or head -c has no source it can use, and the task fails with that reason\n")
		}
	}
	if m := payload.ChunkManifest; m != nil {
		fmt.Fprintf(b, "- chunk manifest sha256 %s: %d chunks of %d bytes for the %d byte binary; after each fetch the node holds every chunk that fetch finished to it and cuts the download back to the first chunk that fails, and when another source takes over it first cuts back the unchecked part of a chunk the last source left; so a source that sends wrong bytes loses only its own, at most one chunk in flight, never what came before, is marked in the summary line and is never given the second pass\n",
			m.digest(), m.count(), m.ChunkSize, m.Size)
		fmt.Fprintf(b, "- a node where dd or cut does not work cannot hold a download to the manifest, so it skips the mirrors\n")
	}
	switch {
	case last == nil:
		fmt.Fprintf(b, "- no earlier successful update of this node recorded a source list\n")
	case slices.Equal(agentUpdateSourceLabels(last.Sources), agentUpdateSourceLabels(payload.Sources)):
		fmt.Fprintf(b, "- the source order is the one of the last successful update (%s, %s)\n", last.ApprovalID, last.Version)
	default:
		before, now := agentUpdateSourceLabels(last.Sources), agentUpdateSourceLabels(payload.Sources)
		var added, removed []string
		for _, label := range now {
			if !slices.Contains(before, label) {
				added = append(added, label)
			}
		}
		for _, label := range before {
			if !slices.Contains(now, label) {
				removed = append(removed, label)
			}
		}
		fmt.Fprintf(b, "- the source order changed since the last successful update (%s, %s): it was %s", last.ApprovalID, last.Version, strings.Join(before, " "))
		if len(added) > 0 {
			fmt.Fprintf(b, "; added %s", strings.Join(added, " "))
		}
		if len(removed) > 0 {
			fmt.Fprintf(b, "; removed %s", strings.Join(removed, " "))
		}
		fmt.Fprintf(b, "\n")
	}
}

// agentUpdateMirrorURLLines declares each mirror's URL, by its place in the
// list, and nothing for a plan without mirrors.
func agentUpdateMirrorURLLines(payload agentUpdatePayload) string {
	var b strings.Builder
	for i, src := range payload.Sources {
		if src.Kind == model.AgentSourceKindMirror {
			fmt.Fprintf(&b, "MIRROR_URL_%d=%s\n", i+1, shellQuote(src.URL))
		}
	}
	return b.String()
}
