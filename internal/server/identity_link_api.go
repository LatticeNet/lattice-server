package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// The operator surface of identity links: one REST door and the matching
// users-admin RPC methods, both over the same operations below.
//
//	GET    /api/vpn/users/{id}/link          status (never the token)
//	POST   /api/vpn/users/{id}/link          issue
//	PATCH  /api/vpn/users/{id}/link          enabled, slug, expiry, refresh period
//	DELETE /api/vpn/users/{id}/link          revoke
//	POST   /api/vpn/users/{id}/link/rotate   new token, the old one answers the decoy at once
//	POST   /api/vpn/users/{id}/link/reveal   the token, through the reveal gate
//
// RPC on latticenet.vpn-core/users-admin: link_get, link_issue, link_set,
// link_revoke, link_rotate, link_reveal, each taking {"user_id", ...} with the
// REST body's fields. Every operation re-checks vpncore:admin with an
// unrestricted allowlist in core, the way subStoreSharesRPC re-checks
// proxy:admin, so a manifest mistake cannot widen who manages or reads links.

const (
	auditActionIdentityLinkIssue  = "vpn.user.link.issue"
	auditActionIdentityLinkRotate = "vpn.user.link.rotate"
	auditActionIdentityLinkRevoke = "vpn.user.link.revoke"
	auditActionIdentityLinkUpdate = "vpn.user.link.update"
	auditActionIdentityLinkReveal = "vpn.user.link.reveal"

	apiErrorLinkNotIssued     = "link_not_issued"
	apiErrorLinkAlreadyIssued = "link_already_issued"
	apiErrorLinkSlugTaken     = "link_slug_taken"
)

// identityLinkOpError is an operation's refusal, rendered as an HTTP error
// on the REST door and as the same status and body on the RPC door.
type identityLinkOpError struct {
	status  int
	code    string
	message string
}

func (e *identityLinkOpError) Error() string { return e.message }

func linkOpError(status int, code, message string) error {
	return &identityLinkOpError{status: status, code: code, message: message}
}

// identityLinkFormatsView says which client documents the link can serve.
type identityLinkFormatsView struct {
	// Native are written in core: the URI list, base64 by default and plain
	// with format=plain.
	Native []string `json:"native"`
	// Converted are written by the Sub-Store convert method; empty when no
	// converter is available, and then every one of them is served as the
	// base64 URI list with X-Lattice-Subscription-Fallback.
	Converted        []string `json:"converted"`
	ConvertAvailable bool     `json:"convert_available"`
	Fallback         string   `json:"fallback,omitempty"`
}

// identityLinkStatusView is what GET .../link answers: the link's route
// facts and what it serves now, never the token.
type identityLinkStatusView struct {
	IdentityID string              `json:"identity_id"`
	Issued     bool                `json:"issued"`
	Link       *vpnUserLinkSummary `json:"link,omitempty"`
	// Answer is what a fetch gets now: nodes, placeholder or decoy, and
	// AnswerReason why (active, no_lines, transient_empty, disabled,
	// operator, expiry, quota, link_disabled, link_expired, not_issued).
	Answer       string `json:"answer"`
	AnswerReason string `json:"answer_reason"`
	// Placeholder is the entry name a placeholder answer serves.
	Placeholder string `json:"placeholder,omitempty"`
	// SubscriptionUserinfo is the quota header a fetch gets now.
	SubscriptionUserinfo string                  `json:"subscription_userinfo,omitempty"`
	Included             []identityLinkLine      `json:"included"`
	Excluded             []identityLinkLine      `json:"excluded"`
	Formats              identityLinkFormatsView `json:"formats"`
	// LastFetch is the last fetch since this server started; nil when none.
	LastFetch *identityLinkFetchSeen `json:"last_fetch,omitempty"`
}

func (s *Server) identityLinkStatus(u VpnUser) identityLinkStatusView {
	now := s.now()
	answer := s.decideIdentityLinkAnswer(u, now)
	view := identityLinkStatusView{IdentityID: u.ID, Issued: u.Link != nil, Link: vpnUserLinkSummaryOf(u.Link),
		Answer: answer.Kind, AnswerReason: answer.Reason, Included: answer.Content.Included, Excluded: answer.Content.Excluded,
		LastFetch: s.identityLinkLastFetch(u.ID)}
	if view.Included == nil {
		view.Included = []identityLinkLine{}
	}
	if view.Excluded == nil {
		view.Excluded = []identityLinkLine{}
	}
	if answer.Kind == identityAnswerPlaceholder {
		view.Placeholder = answer.Message
	}
	if answer.Kind != identityAnswerDecoy {
		view.SubscriptionUserinfo = identityLinkUserinfo(answer.Policy, answer.Kind != identityAnswerNodes)
	}
	switch {
	case u.Link == nil:
		view.Answer, view.AnswerReason, view.SubscriptionUserinfo, view.Placeholder = identityAnswerDecoy, identityReasonNotIssued, "", ""
	case u.Link.Disabled:
		view.Answer, view.AnswerReason, view.SubscriptionUserinfo, view.Placeholder = identityAnswerDecoy, identityReasonLinkDisabled, "", ""
	case u.Link.ExpiresAt != nil && !now.Before(*u.Link.ExpiresAt):
		view.Answer, view.AnswerReason, view.SubscriptionUserinfo, view.Placeholder = identityAnswerDecoy, identityReasonLinkExpired, "", ""
	}
	view.Formats = identityLinkFormatsView{Native: []string{"URI", "V2Ray"}, Converted: []string{}, ConvertAvailable: s.identityLinkConvertAvailable()}
	if view.Formats.ConvertAvailable {
		for _, target := range []string{"ClashMeta", "Clash", "Stash", "sing-box", "Surge", "SurgeMac", "Loon", "QX", "Shadowrocket", "Egern", "Surfboard", "JSON"} {
			view.Formats.Converted = append(view.Formats.Converted, target)
		}
	} else {
		view.Formats.Fallback = "base64_uri"
	}
	return view
}

// identityLinkTokenUnique mints a link token no share, identity link or
// legacy proxy user holds. The token is the same 256-bit primitive shares
// use, so it matches proxySubTokenRe on the public path.
func (s *Server) identityLinkTokenUnique() (string, error) {
	for i := 0; i < 8; i++ {
		token, err := auth.NewRandomToken(32)
		if err != nil {
			return "", err
		}
		if !s.store.LinkTokenInUse(token) {
			return token, nil
		}
	}
	return "", errors.New("could not generate a unique link token")
}

// identityLinkDefaultSlug is u- and ten random base32 characters, never
// derived from the identity (the slug reaches access logs and screenshots).
func (s *Server) identityLinkDefaultSlug() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	for i := 0; i < 8; i++ {
		var b [10]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		out := make([]byte, len(b))
		for j := range b {
			out[j] = alphabet[int(b[j])&31]
		}
		slug := identityLinkSlugPrefix + string(out)
		if !s.store.LinkSlugInUse(slug, "") {
			return slug, nil
		}
	}
	return "", errors.New("could not generate a unique link slug")
}

type identityLinkWriteRequest struct {
	UserID              string     `json:"user_id,omitempty"`
	Slug                *string    `json:"slug,omitempty"`
	Enabled             *bool      `json:"enabled,omitempty"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
	ClearExpiry         bool       `json:"clear_expiry,omitempty"`
	UpdateIntervalHours *int       `json:"update_interval_hours,omitempty"`
	StepUpGrant         string     `json:"step_up_grant,omitempty"`
}

func (s *Server) identityLinkUser(userID string) (VpnUser, error) {
	u, ok := s.getVpnUser(strings.TrimSpace(userID))
	if !ok {
		return VpnUser{}, linkOpError(http.StatusNotFound, model.APIErrorNotFound, "vpn user not found")
	}
	return u, nil
}

// checkIdentityLinkFields validates a write's fields before the store lock
// is taken: the slug's shape and that no other link holds it, and the
// expiry and refresh period. Staging repeats the slug uniqueness check under
// the lock, so a concurrent write cannot slip a duplicate past this one.
func (s *Server) checkIdentityLinkFields(req identityLinkWriteRequest, userID string) error {
	if req.Slug != nil {
		slug := strings.TrimSpace(*req.Slug)
		if !shareSlugRe.MatchString(slug) {
			return linkOpError(http.StatusBadRequest, model.APIErrorBadRequest, "slug must be lowercase letters, digits and hyphens, starting with a letter or digit")
		}
		if s.store.LinkSlugInUse(slug, userID) {
			return linkOpError(http.StatusConflict, apiErrorLinkSlugTaken, "a share or another identity's link already uses this slug")
		}
	}
	if req.ClearExpiry && req.ExpiresAt != nil {
		return linkOpError(http.StatusBadRequest, model.APIErrorBadRequest, "expires_at and clear_expiry cannot both be set")
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.UTC().After(s.now()) {
		return linkOpError(http.StatusBadRequest, model.APIErrorBadRequest, "expires_at must be in the future")
	}
	if req.UpdateIntervalHours != nil && (*req.UpdateIntervalHours < 0 || *req.UpdateIntervalHours > maxLinkUpdateIntervalHours) {
		return linkOpError(http.StatusBadRequest, model.APIErrorBadRequest, "update_interval_hours must be between 1 and 168, or 0 for the default")
	}
	return nil
}

// applyIdentityLinkFields writes checked fields onto a link. It runs inside
// the store lock and reads nothing else.
func applyIdentityLinkFields(link *VpnUserLink, req identityLinkWriteRequest) {
	if req.Slug != nil {
		link.Slug = strings.TrimSpace(*req.Slug)
	}
	if req.Enabled != nil {
		link.Disabled = !*req.Enabled
	}
	if req.ClearExpiry {
		link.ExpiresAt = nil
	}
	if req.ExpiresAt != nil {
		when := req.ExpiresAt.UTC()
		link.ExpiresAt = &when
	}
	if req.UpdateIntervalHours != nil {
		link.UpdateIntervalHours = *req.UpdateIntervalHours
	}
}

// writeIdentityLink runs one link write under the store lock and maps the
// store's answers to operation errors.
func (s *Server) writeIdentityLink(userID string, fn func(link *VpnUserLink, token string) (*VpnUserLink, string, error)) error {
	err := s.withSubscriptionGraphWriteErr(vpnCorePluginID, func() error { return s.store.UpdateVpnUserLink(userID, fn) })
	var opErr *identityLinkOpError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrVpnUserNotFound):
		return linkOpError(http.StatusNotFound, model.APIErrorNotFound, "vpn user not found")
	case errors.As(err, &opErr):
		return err
	case strings.Contains(err.Error(), "link slug"):
		// Staging found a slug another link took after the check above.
		return linkOpError(http.StatusConflict, apiErrorLinkSlugTaken, "a share or another identity's link already uses this slug")
	default:
		return err
	}
}

func (s *Server) issueIdentityLink(p principal, userID string, req identityLinkWriteRequest) (identityLinkStatusView, error) {
	u, err := s.identityLinkUser(userID)
	if err != nil {
		return identityLinkStatusView{}, err
	}
	token, err := s.identityLinkTokenUnique()
	if err != nil {
		return identityLinkStatusView{}, err
	}
	if err := s.checkIdentityLinkFields(req, u.ID); err != nil {
		return identityLinkStatusView{}, err
	}
	slug := ""
	if req.Slug == nil {
		if slug, err = s.identityLinkDefaultSlug(); err != nil {
			return identityLinkStatusView{}, err
		}
	}
	err = s.writeIdentityLink(u.ID, func(link *VpnUserLink, _ string) (*VpnUserLink, string, error) {
		if link != nil {
			return nil, "", linkOpError(http.StatusConflict, apiErrorLinkAlreadyIssued, "this identity already has a link; rotate it for a new token")
		}
		next := &VpnUserLink{Slug: slug, IssuedAt: s.now().UTC()}
		applyIdentityLinkFields(next, req)
		return next, token, nil
	})
	if err != nil {
		return identityLinkStatusView{}, err
	}
	s.dropIdentityLinkServingState(u.ID)
	stored, _ := s.getVpnUser(u.ID)
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: auditActionIdentityLinkIssue, Scope: "vpncore:admin", Decision: "allow",
		Metadata: map[string]string{"identity_id": u.ID, "slug": stored.Link.Slug, "token_sha256": proxySubTokenAuditHash(token)}})
	return s.identityLinkStatus(stored), nil
}

func (s *Server) rotateIdentityLink(p principal, userID string) (identityLinkStatusView, error) {
	u, err := s.identityLinkUser(userID)
	if err != nil {
		return identityLinkStatusView{}, err
	}
	token, err := s.identityLinkTokenUnique()
	if err != nil {
		return identityLinkStatusView{}, err
	}
	oldToken := ""
	err = s.writeIdentityLink(u.ID, func(link *VpnUserLink, current string) (*VpnUserLink, string, error) {
		if link == nil {
			return nil, "", linkOpError(http.StatusNotFound, apiErrorLinkNotIssued, "this identity has no link; issue one first")
		}
		now := s.now().UTC()
		link.RotatedAt = &now
		oldToken = current
		return link, token, nil
	})
	if err != nil {
		return identityLinkStatusView{}, err
	}
	s.dropIdentityLinkServingState(u.ID)
	stored, _ := s.getVpnUser(u.ID)
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: auditActionIdentityLinkRotate, Scope: "vpncore:admin", Decision: "allow",
		Metadata: map[string]string{"identity_id": u.ID, "slug": stored.Link.Slug,
			"old_token_sha256": proxySubTokenAuditHash(oldToken), "new_token_sha256": proxySubTokenAuditHash(token)}})
	return s.identityLinkStatus(stored), nil
}

// revokeIdentityLink removes the link and replaces the stored token with a
// fresh one nothing serves, so the revoked token answers the decoy at once
// and a later issue mints yet another.
func (s *Server) revokeIdentityLink(p principal, userID string) (identityLinkStatusView, error) {
	u, err := s.identityLinkUser(userID)
	if err != nil {
		return identityLinkStatusView{}, err
	}
	unserved, err := s.identityLinkTokenUnique()
	if err != nil {
		return identityLinkStatusView{}, err
	}
	oldToken, slug := "", ""
	err = s.writeIdentityLink(u.ID, func(link *VpnUserLink, current string) (*VpnUserLink, string, error) {
		if link == nil {
			return nil, "", linkOpError(http.StatusNotFound, apiErrorLinkNotIssued, "this identity has no link")
		}
		oldToken, slug = current, link.Slug
		return nil, unserved, nil
	})
	if err != nil {
		return identityLinkStatusView{}, err
	}
	s.dropIdentityLinkServingState(u.ID)
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: auditActionIdentityLinkRevoke, Scope: "vpncore:admin", Decision: "allow",
		Metadata: map[string]string{"identity_id": u.ID, "slug": slug, "token_sha256": proxySubTokenAuditHash(oldToken)}})
	stored, _ := s.getVpnUser(u.ID)
	return s.identityLinkStatus(stored), nil
}

func (s *Server) updateIdentityLink(p principal, userID string, req identityLinkWriteRequest) (identityLinkStatusView, error) {
	u, err := s.identityLinkUser(userID)
	if err != nil {
		return identityLinkStatusView{}, err
	}
	if err := s.checkIdentityLinkFields(req, u.ID); err != nil {
		return identityLinkStatusView{}, err
	}
	err = s.writeIdentityLink(u.ID, func(link *VpnUserLink, token string) (*VpnUserLink, string, error) {
		if link == nil {
			return nil, "", linkOpError(http.StatusNotFound, apiErrorLinkNotIssued, "this identity has no link; issue one first")
		}
		applyIdentityLinkFields(link, req)
		return link, token, nil
	})
	if err != nil {
		return identityLinkStatusView{}, err
	}
	stored, _ := s.getVpnUser(u.ID)
	expires := "never"
	if stored.Link.ExpiresAt != nil {
		expires = stored.Link.ExpiresAt.UTC().Format(time.RFC3339)
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: auditActionIdentityLinkUpdate, Scope: "vpncore:admin", Decision: "allow",
		Metadata: map[string]string{"identity_id": u.ID, "slug": stored.Link.Slug, "enabled": boolString(!stored.Link.Disabled), "expires_to": expires}})
	return s.identityLinkStatus(stored), nil
}

// revealIdentityLink hands the token to a principal the reveal gate admits.
func (s *Server) revealIdentityLink(p principal, userID, grant string) (linkRevealView, error) {
	u, err := s.identityLinkUser(userID)
	if err != nil {
		return linkRevealView{}, err
	}
	if u.Link == nil {
		return linkRevealView{}, linkOpError(http.StatusNotFound, apiErrorLinkNotIssued, "this identity has no link; issue one first")
	}
	ev := model.AuditEvent{Action: auditActionIdentityLinkReveal, Scope: "vpncore:admin",
		Metadata: map[string]string{"identity_id": u.ID, "slug": u.Link.Slug, "token_sha256": proxySubTokenAuditHash(u.SubID)}}
	reveal := s.decideSecretReveal(p, grant)
	if !reveal.Allowed {
		s.refuseSecretReveal(p, reveal, ev)
		return linkRevealView{}, linkOpError(http.StatusForbidden, reveal.Code, reveal.Message)
	}
	s.recordSecretReveal(p, reveal, ev)
	return s.linkRevealViewOf(identityLinkKind, u.ID, u.Link.Slug, u.SubID), nil
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// requireIdentityLinkAdmin is the core-side check both doors make.
func requireIdentityLinkAdmin(p principal) error {
	if ok, reason := pluginGatewayScopeAllowed(p, "vpncore:admin"); !ok {
		return linkOpError(http.StatusForbidden, model.APIErrorForbidden, reason)
	}
	return nil
}

// handleVpnUserLink serves /api/vpn/users/{id}/link[/rotate|/reveal].
func (s *Server) handleVpnUserLink(w http.ResponseWriter, r *http.Request, p principal) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/vpn/users/")
	userID, tail, ok := strings.Cut(rest, "/")
	if !ok || userID == "" {
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	action := ""
	switch tail {
	case "link":
	case "link/rotate":
		action = "rotate"
	case "link/reveal":
		action = "reveal"
	default:
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	if !s.requireGlobalProxyScope(w, p, "vpncore:admin") {
		return
	}
	var req identityLinkWriteRequest
	readBody := func() bool {
		if r.ContentLength == 0 && r.Body == http.NoBody {
			return true
		}
		return decodeLimitedJSON(w, r, &req, 16<<10)
	}
	var out any
	var err error
	switch {
	case action == "" && r.Method == http.MethodGet:
		u, uerr := s.identityLinkUser(userID)
		if uerr != nil {
			err = uerr
			break
		}
		out = s.identityLinkStatus(u)
	case action == "" && r.Method == http.MethodPost:
		if !readBody() {
			return
		}
		out, err = s.issueIdentityLink(p, userID, req)
	case action == "" && r.Method == http.MethodPatch:
		if !readBody() {
			return
		}
		out, err = s.updateIdentityLink(p, userID, req)
	case action == "" && r.Method == http.MethodDelete:
		out, err = s.revokeIdentityLink(p, userID)
	case action == "rotate" && r.Method == http.MethodPost:
		out, err = s.rotateIdentityLink(p, userID)
	case action == "reveal" && r.Method == http.MethodPost:
		if !readBody() {
			return
		}
		out, err = s.revealIdentityLink(p, userID, req.StepUpGrant)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if err != nil {
		var opErr *identityLinkOpError
		if errors.As(err, &opErr) {
			writeError(w, opErr.status, apiError(opErr.code, opErr.message))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// vpnUserLinkRPC is the users-admin side of the same operations.
func (s *Server) vpnUserLinkRPC(ctx context.Context, method string, request []byte) ([]byte, error) {
	p, err := pluginOperatorPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireIdentityLinkAdmin(p); err != nil {
		return nil, identityLinkRPCError(err)
	}
	var req identityLinkWriteRequest
	if len(bytes.TrimSpace(request)) > 0 {
		if err := json.Unmarshal(request, &req); err != nil {
			return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "vpn-core/users-admin "+method+": invalid request")
		}
	}
	var out any
	switch method {
	case "link_get":
		u, uerr := s.identityLinkUser(req.UserID)
		if uerr != nil {
			return nil, identityLinkRPCError(uerr)
		}
		out = s.identityLinkStatus(u)
	case "link_issue":
		out, err = s.issueIdentityLink(p, req.UserID, req)
	case "link_set":
		out, err = s.updateIdentityLink(p, req.UserID, req)
	case "link_revoke":
		out, err = s.revokeIdentityLink(p, req.UserID)
	case "link_rotate":
		out, err = s.rotateIdentityLink(p, req.UserID)
	case "link_reveal":
		out, err = s.revealIdentityLink(p, req.UserID, req.StepUpGrant)
	default:
		return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "vpn-core/users-admin: unknown method "+method)
	}
	if err != nil {
		return nil, identityLinkRPCError(err)
	}
	return json.Marshal(out)
}

func identityLinkRPCError(err error) error {
	var opErr *identityLinkOpError
	if errors.As(err, &opErr) {
		return rpcAPIError(opErr.status, opErr.code, opErr.message)
	}
	return err
}
