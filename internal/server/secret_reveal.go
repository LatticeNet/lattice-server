package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// One reveal gate for every secret.
//
// Lattice holds material that authenticates as somebody: an identity's
// credentials, a subscription link and the token in it, an adopted line's
// share URL (its owner's credential), a knock sequence, a provider panel's
// console link, a task script that carries a credential. The operator's rule
// (2026-10-02) is that such material is revealed only to an interactive
// session after a fresh second-factor step-up, and to an API token only
// through a separate, audited grant. decideSecretReveal is that rule, and
// every endpoint that returns secret material asks it before the value leaves
// the server; everything else redacts by default.
//
// Step-up is the one already in the product (requireStepUpGrant's grants,
// issued by the TOTP and passkey step-up endpoints). The token grant is the
// secrets:reveal scope, which nothing else implies (rbac.SecretRevealScope),
// which no user account carries, and which only a full administrator can put
// on a token, from a session, after step-up (handleTokens). Every reveal is
// audited; a token's names the token and the object.
//
// Scope still comes first and stays each endpoint's own: the gate decides
// whether this principal may see a secret at all, not which objects it may
// see.

const (
	// apiErrorStepUpRequired: a session asked for a secret without a fresh
	// step-up grant. The console answers it with the step-up prompt.
	apiErrorStepUpRequired = "step_up_required"
	// apiErrorRevealScopeRequired: an API token without secrets:reveal asked
	// for a secret.
	apiErrorRevealScopeRequired = "secret_reveal_scope_required"

	// revealViaStepUp and revealViaToken name how a reveal was allowed, in
	// the audit event's metadata ("via").
	revealViaStepUp = "step_up"
	revealViaToken  = "token"
)

// secretRevealDecision is the gate's answer for one principal.
type secretRevealDecision struct {
	Allowed bool
	// Via is revealViaStepUp or revealViaToken when Allowed.
	Via string
	// Code, Message and Reason describe a refusal: the API error code and
	// message the caller sees, and the reason the deny audit records.
	Code    string
	Message string
	Reason  string
}

const (
	revealTokenRefusal = "this API token cannot reveal secrets: that needs a token carrying the secrets:reveal scope, " +
		"which no other scope implies and which a full administrator grants from an interactive session after step-up"
	revealSessionRefusal = "revealing a secret requires an interactive session with a fresh second-factor step-up"
)

// decideSecretReveal is the one decision. grantID is the step-up grant the
// request carried, if any; a token's is ignored.
func (s *Server) decideSecretReveal(p principal, grantID string) secretRevealDecision {
	if p.viaBearer {
		if p.TokenID != "" && rbac.HoldsExplicitScope(p.Scopes, rbac.SecretRevealScope) {
			return secretRevealDecision{Allowed: true, Via: revealViaToken}
		}
		return secretRevealDecision{Code: apiErrorRevealScopeRequired, Message: revealTokenRefusal, Reason: "token lacks secrets:reveal"}
	}
	if p.ActorID == "" || p.sessionID == "" {
		return secretRevealDecision{Code: apiErrorStepUpRequired, Message: revealSessionRefusal, Reason: "no interactive session"}
	}
	grantID = strings.TrimSpace(grantID)
	if grantID == "" {
		return secretRevealDecision{Code: apiErrorStepUpRequired, Message: "second-factor step-up required", Reason: "missing second-factor step-up"}
	}
	if !s.stepUpGrantHeld(p, grantID) {
		return secretRevealDecision{Code: apiErrorStepUpRequired, Message: "second-factor step-up required", Reason: "missing or expired second-factor step-up"}
	}
	return secretRevealDecision{Allowed: true, Via: revealViaStepUp}
}

// refuseSecretReveal audits a refused reveal under the endpoint's action.
func (s *Server) refuseSecretReveal(p principal, d secretRevealDecision, ev model.AuditEvent) {
	if ev.ID == "" {
		ev.ID = id.New("audit")
	}
	ev.Decision = "deny"
	ev.Reason = d.Reason
	s.recordPrincipalAudit(p, ev)
}

// requireSecretReveal is the gate for an HTTP handler: true when the
// principal may see the secret, otherwise it audits the refusal under action
// and answers 403 with a code the console can act on.
func (s *Server) requireSecretReveal(w http.ResponseWriter, p principal, grantID string, ev model.AuditEvent) (secretRevealDecision, bool) {
	return s.requireSecretRevealHint(w, p, grantID, ev, "")
}

// requireSecretRevealHint is requireSecretReveal with a sentence added to a
// token's refusal: where the endpoint's non-secret half lives, so an agent
// that cannot have the secret learns what it can read instead.
func (s *Server) requireSecretRevealHint(w http.ResponseWriter, p principal, grantID string, ev model.AuditEvent, tokenHint string) (secretRevealDecision, bool) {
	d := s.decideSecretReveal(p, grantID)
	if d.Allowed {
		return d, true
	}
	s.refuseSecretReveal(p, d, ev)
	message := d.Message
	if tokenHint != "" && d.Code == apiErrorRevealScopeRequired {
		message += "; " + tokenHint
	}
	writeError(w, http.StatusForbidden, apiError(d.Code, message))
	return d, false
}

// secretRevealRPCError is the refusal as a plugin RPC error: the gateway
// writes its status and body through, so the console sees the same 403 and
// code as on the REST door.
func secretRevealRPCError(d secretRevealDecision) error {
	return rpcAPIError(http.StatusForbidden, d.Code, d.Message)
}

// rpcAPIError is an error a core RPC provider returns when the caller should
// see a real status and message rather than the gateway's generic 502.
func rpcAPIError(status int, code, message string) error {
	body, _ := json.Marshal(model.APIErrorResponse{Error: model.APIError{Code: code, Message: message}})
	return &pluginOperationError{StatusCode: status, Body: body}
}

// apiErrorRevealGrantRefused: a caller asked to mint a token carrying
// secrets:reveal without the authority to grant it.
const apiErrorRevealGrantRefused = "secret_reveal_grant_refused"

// requireSecretRevealGrantAuthority is the only door to secrets:reveal. A
// token gets it only when a full administrator (a session holding "*" by
// name, with an unrestricted allowlist) asks from an interactive session with
// a fresh step-up. A token cannot pass it, whatever it holds, so a reveal
// token cannot mint another one; and since no user account may hold the
// scope (server_users.go), ordinary delegation never reaches it either.
func (s *Server) requireSecretRevealGrantAuthority(w http.ResponseWriter, p principal, grantID string) bool {
	refuse := func(code, message, reason string) bool {
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "token.create", Scope: "token:admin",
			Decision: "deny", Reason: reason, Metadata: map[string]string{"grants_secret_reveal": "true"}})
		writeError(w, http.StatusForbidden, apiError(code, message))
		return false
	}
	if p.viaBearer || p.ActorID == "" || p.sessionID == "" {
		return refuse(apiErrorRevealGrantRefused, "secrets:reveal is granted only from an interactive session after second-factor step-up, never by another token", "reveal grant from a non-session principal")
	}
	if !rbac.HoldsExplicitScope(p.Scopes, "*") || principalHasNodeRestriction(p) {
		return refuse(apiErrorRevealGrantRefused, "only a full administrator (scope *, unrestricted server allowlist) may grant secrets:reveal", "reveal grant by a principal that is not a full administrator")
	}
	if !s.stepUpGrantHeld(p, strings.TrimSpace(grantID)) {
		return refuse(apiErrorStepUpRequired, "second-factor step-up required", "reveal grant without a fresh second-factor step-up")
	}
	return true
}

// recordSecretReveal audits one allowed reveal. ev names the action, the
// scope it was checked under and the object (its ids in Metadata, never the
// secret); this adds how it was allowed and, for a token, which token.
func (s *Server) recordSecretReveal(p principal, d secretRevealDecision, ev model.AuditEvent) {
	if ev.ID == "" {
		ev.ID = id.New("audit")
	}
	if ev.Decision == "" {
		ev.Decision = "allow"
	}
	meta := make(map[string]string, len(ev.Metadata)+2)
	for k, v := range ev.Metadata {
		meta[k] = v
	}
	meta["via"] = d.Via
	if d.Via == revealViaToken {
		meta["token_id"] = p.TokenID
	}
	ev.Metadata = meta
	s.recordPrincipalAudit(p, ev)
}
