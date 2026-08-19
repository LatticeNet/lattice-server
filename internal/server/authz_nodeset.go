package server

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// This file holds the authorization primitives for the one defect class that
// has now shipped twice: a handler authorizes the caller on the identifier it
// was given, then dereferences a second identifier on the way to building its
// answer, and that second dereference is never checked.
//
// handleWireGuardPlan authorized the target node, then compiled a mesh from
// every node in the store and returned each peer's public key, mesh IP and
// endpoint. handleNetPolicyPlan authorized the target node, then resolved a
// rule's remote node id through an unscoped lookup and embedded that node's
// WireGuard IP and public addresses into the ruleset it returned, which made it
// a lookup oracle: name any guessable node id, receive its addresses.
//
// Both were hand-rolled fixes in the handler. Hand-rolled is why there were
// two. The primitives here move the check off the handler author's memory:
//
//   - requireReadableNodes is the one place the refuse-with-a-count policy is
//     written, so no handler invents its own wording or leaks an identity.
//   - scopedNodeResolver carries the principal through the compilers. Every
//     compiler that turns records into a config already takes a NodeResolver,
//     so a resolver that knows who is asking converts "the handler must
//     remember to check" into "a plan cannot be compiled without naming a
//     scope". authz_resolver_test.go fails the build if a call site slips back
//     to an unscoped lookup.

// unreadableNodesError is the refusal a caller sees when an artefact would be
// assembled from nodes their session cannot read.
//
// Refusal, not filtering, and deliberately so. These call sites produce a
// config: a mesh, a ruleset, a firewall plan. A config that silently drops the
// members the caller could not read is not a shorter answer, it is a wrong
// artefact, and an asymmetric mesh or a policy missing half its rules is worse
// than an error. Where the result is a list rather than an artefact, filtering
// stays correct and these primitives are not the right tool.
//
// The error reports how many nodes were unreadable and never which. The whole
// point of the netpolicy defect was that naming a node disclosed it; an error
// that names what it is protecting reintroduces the oracle it closed.
func unreadableNodesError(count int, scope, what string) error {
	return fmt.Errorf(
		"%s would use %d node(s) this session cannot read; %s is required on every node involved: %w",
		what, count, scope, errUnreadableNodes)
}

// errUnreadableNodes is the sentinel every refusal wraps, so a helper that
// returns the refusal up a call chain still lands on 403 rather than being
// flattened into a generic 400 by an intermediate caller.
var errUnreadableNodes = errors.New("forbidden")

// requireReadableNodes reports whether p may read every node in ids under
// scope, and writes the count-only refusal if not. Empty and duplicate ids are
// ignored so callers can pass a raw set straight out of a record.
func (s *Server) requireReadableNodes(w http.ResponseWriter, p principal, scope, what string, ids []string) bool {
	denied := deniedNodeCount(p.Principal, scope, ids)
	if denied == 0 {
		return true
	}
	s.recordAudit(model.AuditEvent{
		ID:            id.New("audit"),
		ActorID:       p.ActorID,
		TokenID:       p.TokenID,
		Action:        "authorize.nodeset",
		Scope:         scope,
		Decision:      "deny",
		Reason:        fmt.Sprintf("%d node(s) outside the session server allowlist", denied),
		CorrelationID: p.CorrelationID,
	})
	writeError(w, http.StatusForbidden, unreadableNodesError(denied, scope, what))
	return false
}

// deniedNodeCount counts the distinct non-empty ids in ids that p cannot read
// under scope.
func deniedNodeCount(p rbac.Principal, scope string, ids []string) int {
	seen := make(map[string]struct{}, len(ids))
	denied := 0
	for _, nodeID := range ids {
		nodeID = strings.TrimSpace(nodeID)
		if nodeID == "" {
			continue
		}
		if _, dup := seen[nodeID]; dup {
			continue
		}
		seen[nodeID] = struct{}{}
		if !rbac.Allows(p, scope, nodeID) {
			denied++
		}
	}
	return denied
}

// scopedNodeResolver is a node lookup that carries the principal asking for it.
// It satisfies netpolicy.NodeResolver and netguard.NodeResolver, so it drops
// into every compiler in the tree without those packages learning about RBAC.
//
// A denied lookup returns not-found rather than an error, for two reasons. The
// compilers already handle not-found, so no compiler changes. And a caller must
// not be able to tell "this node is outside your allowlist" from "this node
// does not exist", because that difference is itself the oracle. The handler
// calls Refused before it inspects the compiler's error, so a denial always
// surfaces as the count-only refusal and never as the compiler's own message,
// which would name the node.
type scopedNodeResolver struct {
	lookup func(string) (model.Node, bool)
	p      rbac.Principal
	scope  string
	// what names the artefact under construction, for the refusal message.
	what string
	// exempt holds ids the handler already authorized under a stronger scope,
	// normally the plan's target node. Without it a target the caller may admin
	// but whose read scope is spelled differently would be counted as denied.
	exempt map[string]struct{}
	denied map[string]struct{}
	// system marks a resolver built by systemNodeResolver: no principal, no
	// check, output that never reaches a caller.
	system bool
}

// nodeResolverFor builds the resolver a plan, compile, render or export path
// must use instead of reaching into the store directly. exempt lists ids the
// caller has already authorized, normally the target node.
func (s *Server) nodeResolverFor(p principal, scope, what string, exempt ...string) *scopedNodeResolver {
	return s.nodeResolverOver(s.store.Node, p, scope, what, exempt...)
}

// nodeResolverOver is nodeResolverFor over a lookup other than the live store,
// for compile paths that work from a consistent snapshot. The snapshot is the
// reason this exists: a snapshot map holds every node in the fleet, so reading
// straight out of it is the unscoped lookup wearing a different coat.
func (s *Server) nodeResolverOver(lookup func(string) (model.Node, bool), p principal, scope, what string, exempt ...string) *scopedNodeResolver {
	exemptSet := make(map[string]struct{}, len(exempt))
	for _, nodeID := range exempt {
		if nodeID = strings.TrimSpace(nodeID); nodeID != "" {
			exemptSet[nodeID] = struct{}{}
		}
	}
	return &scopedNodeResolver{
		lookup: lookup,
		p:      p.Principal,
		scope:  scope,
		what:   what,
		exempt: exemptSet,
		denied: map[string]struct{}{},
	}
}

// systemNodeResolver is the deliberate escape hatch: a resolver with no
// principal, for server-side recomputation whose output never reaches a
// caller. It exists so those call sites are declared rather than accidental.
// The reason argument is not read at runtime; it is there so writing one of
// these forces the author to state why, and so `grep systemNodeResolver` lists
// every unscoped lookup in the tree.
//
// Do not use it for anything a caller can see. If the bytes reach a response
// body, an error message, or a stored artefact the caller can fetch, it needs
// nodeResolverFor and a scope.
func (s *Server) systemNodeResolver(reason string) *scopedNodeResolver {
	return s.systemNodeResolverOver(s.store.Node, reason)
}

// systemNodeResolverOver is systemNodeResolver over a snapshot lookup.
func (s *Server) systemNodeResolverOver(lookup func(string) (model.Node, bool), reason string) *scopedNodeResolver {
	_ = reason
	return &scopedNodeResolver{
		lookup: lookup,
		system: true,
		denied: map[string]struct{}{},
	}
}

// Resolve implements netpolicy.NodeResolver and netguard.NodeResolver.
func (r *scopedNodeResolver) Resolve(nodeID string) (model.Node, bool) {
	trimmed := strings.TrimSpace(nodeID)
	if trimmed == "" {
		return model.Node{}, false
	}
	if r.system {
		return r.lookup(trimmed)
	}
	if _, ok := r.exempt[trimmed]; !ok && !rbac.Allows(r.p, r.scope, trimmed) {
		r.denied[trimmed] = struct{}{}
		return model.Node{}, false
	}
	return r.lookup(trimmed)
}

// Denied reports how many distinct nodes this resolver refused.
func (r *scopedNodeResolver) Denied() int { return len(r.denied) }

// DeniedIDs is for audit records and tests only. It must never reach a
// response body: the identities are exactly what the refusal protects.
func (r *scopedNodeResolver) DeniedIDs() []string {
	out := make([]string, 0, len(r.denied))
	for nodeID := range r.denied {
		out = append(out, nodeID)
	}
	sort.Strings(out)
	return out
}

// Refused returns the count-only refusal if this resolver denied anything, and
// nil otherwise. Check it before the compiler's own error: a denial makes the
// compiler fail with a message that names the node, and that message must not
// be what the caller sees.
func (r *scopedNodeResolver) Refused() error {
	if len(r.denied) == 0 {
		return nil
	}
	return unreadableNodesError(len(r.denied), r.scope, r.what)
}

// writeRefusal writes the count-only refusal and reports whether it did. Use it
// immediately after a compile, before touching the compile error.
func (s *Server) writeRefusal(w http.ResponseWriter, p principal, r *scopedNodeResolver) bool {
	err := r.Refused()
	if err == nil {
		return false
	}
	s.recordAudit(model.AuditEvent{
		ID:            id.New("audit"),
		ActorID:       p.ActorID,
		TokenID:       p.TokenID,
		Action:        "authorize.nodeset",
		Scope:         r.scope,
		Decision:      "deny",
		Reason:        fmt.Sprintf("%d node(s) outside the session server allowlist", r.Denied()),
		CorrelationID: p.CorrelationID,
	})
	writeError(w, http.StatusForbidden, err)
	return true
}
