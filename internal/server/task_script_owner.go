package server

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// Task script reveal and the surfaces that own what a script carries.
//
// POST /api/tasks/reveal-script returns a task's whole script to a principal
// holding task:read on every target that also passes the secret-reveal gate.
// Some scripts are rendered by core with a credential that another surface
// owns, and that surface keeps it from a principal holding task:read alone:
//
//   - a witness configure script carries a stored notification channel's Bark
//     device key, which the notify API returns to nobody, and whose plan only
//     an unconfined notify:admin may author, decide or read;
//   - line-user, managed-line and proxycore apply scripts, and the sing-box
//     user sync that /api/proxy/managed/users queues, carry VPN user
//     credentials, which the identity surface reveals only to proxy:admin
//     with an unrestricted allowlist (handleRevealVPNUserCredentials through
//     requireGlobalProxyScope); proxycore and line-user configs also carry
//     REALITY private keys;
//   - an SSH Guard apply script writes knockd.conf, which carries the node's
//     knock sequence, revealed through its own door only to sshguard:read
//     plus network:plan on that node (sshGuardKnockScopes).
//
// Without this gate task:read plus a step-up was enough to read any of them.
// The reveal now also requires the owning surface's own reveal scope. Line
// chain scripts stay refused outright, by the check in handleRevealTaskScript.
//
// The other core apply scripts carry nothing secret, so they are not listed:
// selfdns plans exclude the DNS token by contract, WireGuard renders a
// placeholder the agent fills with a node-local key, cftunnel references a
// node-local credentials file, and the nft, netguard, netpolicy, linemeta and
// agentupdate scripts are firewall rules, metadata and download facts.
// Plugin-enqueued tasks carry what the plugin wrote; none of the official
// plugins enqueues a task today.

// apiErrorRevealScriptOwnerScopeRequired: the caller passed task:read and
// the reveal gate, but the script carries a credential whose owning surface
// requires a scope the caller does not hold. The message names the scope.
const apiErrorRevealScriptOwnerScopeRequired = "reveal_script_owner_scope_required"

// sbUserCredentialRe matches the on-box `sb --json user add|del` call. Its
// JSON payload is the user's credential: the fork's cmd_json_user refuses a
// payload without one, so any script that makes the call carries one. Keyed
// on the script rather than on an origin because the sing-box user sync is a
// direct task with no approval to resolve.
var sbUserCredentialRe = regexp.MustCompile(`--json\s+user\s+(add|del)\b`)

// taskScriptOwner is one surface whose reveal authority a script reveal must
// also hold.
type taskScriptOwner struct {
	// kind names the script for the audit row; what says what it is and
	// what it holds, for the refusal. Neither quotes the secret.
	kind string
	what string
	// scope is the authority in scope syntax, for the audit row; need says
	// it in words, for the refusal.
	scope  string
	need   string
	allows func(p principal) bool
}

func (o taskScriptOwner) refusal() string {
	return fmt.Sprintf("%s; revealing it also requires %s", o.what, o.need)
}

// unrestrictedScopeAllows is the check requireGlobalProxyScope makes, as a
// predicate: the scope on any node, and no server allowlist restriction.
func unrestrictedScopeAllows(p principal, scope string) bool {
	return !principalHasNodeRestriction(p) && rbac.Allows(p.Principal, scope, "")
}

func vpnCredentialScriptOwner(kind, carries string) taskScriptOwner {
	return taskScriptOwner{
		kind: kind, what: "this " + kind + " script carries " + carries,
		scope: "proxy:admin", need: "proxy:admin with an unrestricted server allowlist",
		allows: func(p principal) bool { return unrestrictedScopeAllows(p, "proxy:admin") },
	}
}

// unknownOriginScriptOwner applies when a task names an origin that no longer
// resolves: an approval that is gone, or a rerun whose source task was
// deleted. A rerun copies its source's script and not its approval link, so
// without this, rerunning a witness apply and deleting the original would
// leave a copy of the key that task:read alone could reveal. Only a full
// administrator, who may read every surface, can reveal it.
func unknownOriginScriptOwner(why string) taskScriptOwner {
	return taskScriptOwner{
		kind: "unresolved origin", what: "the origin of this task's script cannot be resolved because " + why,
		scope: "*", need: "a full administrator (scope *, unrestricted server allowlist)",
		allows: func(p principal) bool {
			return !principalHasNodeRestriction(p) && rbac.HoldsExplicitScope(p.Scopes, "*")
		},
	}
}

// approvalScriptOwner is the owner of an apply script core rendered for this
// approval, if its script carries another surface's credential. Every plugin
// that core renders an apply script for is classified in
// TestEveryCoreApplyScriptIsClassifiedForReveal, so a new renderer cannot
// fall through here unnoticed.
func approvalScriptOwner(approval model.Approval) (taskScriptOwner, bool) {
	switch approval.Plugin {
	case witnessPlugin:
		return taskScriptOwner{
			kind: "witness apply", what: "this witness apply script carries a notification channel's Bark device key",
			scope: "notify:admin", need: "notify:admin with an unrestricted server allowlist",
			allows: func(p principal) bool { return unrestrictedScopeAllows(p, "notify:admin") },
		}, true
	case singBoxLineUserPlugin:
		return vpnCredentialScriptOwner("line-user apply", "a VPN user's credential"), true
	case singBoxManagedLinePlugin:
		return vpnCredentialScriptOwner("managed-line apply", "a VPN user's credential and the line's REALITY key"), true
	case proxyCorePlugin:
		return vpnCredentialScriptOwner("proxy config apply", "VPN user credentials and REALITY private keys"), true
	case sshGuardPlugin:
		// The knock sequence is the node's, so the scopes are checked on that
		// node, as sshGuardKnockScopes checks them. An approval with no node
		// fails closed: rbac.Allows reads an empty node as "any node", which
		// would skip a confined principal's allowlist.
		nodeID := strings.TrimSpace(approval.NodeID)
		return taskScriptOwner{
			kind: "SSH Guard apply", what: "this SSH Guard apply script carries the node's knock sequence",
			scope: "sshguard:read,network:plan", need: "sshguard:read and network:plan on node " + nodeID,
			allows: func(p principal) bool {
				return nodeID != "" && rbac.Allows(p.Principal, "sshguard:read", nodeID) && rbac.Allows(p.Principal, "network:plan", nodeID)
			},
		}, true
	default:
		return taskScriptOwner{}, false
	}
}

// taskScriptOwners lists every owner whose authority a reveal of this task's
// script must hold, beside task:read and the reveal gate. A rerun is resolved
// to the approval of the task it was copied from.
func (s *Server) taskScriptOwners(task model.Task) []taskScriptOwner {
	var owners []taskScriptOwner
	approvalID := strings.TrimSpace(task.ApprovalID)
	if rerunOf := strings.TrimSpace(task.RerunOfTaskID); approvalID == "" && rerunOf != "" {
		if source, ok := s.store.Task(rerunOf); ok {
			approvalID = strings.TrimSpace(source.ApprovalID)
		} else {
			owners = append(owners, unknownOriginScriptOwner("the task it reruns no longer exists"))
		}
	}
	if approvalID != "" {
		if approval, ok := s.store.Approval(approvalID); !ok {
			owners = append(owners, unknownOriginScriptOwner("the approval that produced it no longer exists"))
		} else if owner, ok := approvalScriptOwner(approval); ok {
			owners = append(owners, owner)
		}
	}
	if sbUserCredentialRe.MatchString(task.Script) {
		owners = append(owners, vpnCredentialScriptOwner("sing-box user sync", "a VPN user's credential"))
	}
	return owners
}

// requireTaskScriptOwners refuses a script reveal the owning surfaces would
// not allow, auditing the refusal under the reveal's own action.
func (s *Server) requireTaskScriptOwners(w http.ResponseWriter, p principal, task model.Task) bool {
	for _, owner := range s.taskScriptOwners(task) {
		if owner.allows(p) {
			continue
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID: id.New("audit"), Action: "task.script.reveal", Scope: owner.scope, Decision: "deny",
			Reason:   "script owner scope missing: " + owner.scope,
			Metadata: map[string]string{"task_id": task.ID, "script_kind": owner.kind},
		})
		writeError(w, http.StatusForbidden, apiError(apiErrorRevealScriptOwnerScopeRequired, owner.refusal()))
		return false
	}
	return true
}
