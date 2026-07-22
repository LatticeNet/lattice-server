package server

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// userView is the secret-free projection of an operator user. model.User
// serializes PasswordHash/TOTPSecret/RecoveryCodeHashes by default, so user
// endpoints MUST return this view and never a raw model.User.
type userView struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	Scopes      []string  `json:"scopes"`
	TOTPEnabled bool      `json:"totp_enabled"`
	HasPassword bool      `json:"has_password"`
	CreatedAt   time.Time `json:"created_at"`
}

func toUserView(u model.User) userView {
	return userView{
		ID:          u.ID,
		Username:    u.Username,
		Scopes:      u.Scopes,
		TOTPEnabled: u.TOTPEnabled,
		HasPassword: u.PasswordHash != "",
		CreatedAt:   u.CreatedAt,
	}
}

func hasWildcardScope(scopes []string) bool {
	for _, s := range scopes {
		if s == "*" {
			return true
		}
	}
	return false
}

// normalizeScopes trims, drops empties, and de-duplicates a requested scope set.
func normalizeScopes(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	seen := map[string]struct{}{}
	for _, sc := range scopes {
		sc = strings.TrimSpace(sc)
		if sc == "" {
			continue
		}
		if _, dup := seen[sc]; dup {
			continue
		}
		seen[sc] = struct{}{}
		out = append(out, sc)
	}
	return out
}

// validateGrantScopes enforces two rules on a scope assignment: every scope is a
// real catalog scope (no typos / made-up strings), and every scope is within the
// acting admin's own grant (no privilege escalation, mirroring token creation).
// Returns (status, err) with status 0 on success.
func (s *Server) validateGrantScopes(p principal, scopes []string) (int, error) {
	for _, sc := range scopes {
		if !rbac.ValidScope(sc) {
			return http.StatusBadRequest, fmt.Errorf("unknown scope %q", sc)
		}
		if !rbac.CanDelegateScope(p.Principal, sc) {
			return http.StatusForbidden, fmt.Errorf("cannot grant scope %q beyond your own access", sc)
		}
	}
	return 0, nil
}

// handleUsers lists operator users (GET) or creates one (POST). Gated by
// user:admin. Username is the login id and — for SSO — must equal the operator's
// verified IdP email (Lattice matches OIDC email to username). Password is
// optional: omit it for an SSO-only account (no password login).
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		users := s.store.Users()
		out := make([]userView, 0, len(users))
		for _, u := range users {
			out = append(out, toUserView(u))
		}
		sort.Slice(out, func(i, j int) bool {
			if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
				return out[i].CreatedAt.Before(out[j].CreatedAt)
			}
			return out[i].Username < out[j].Username
		})
		writeJSON(w, http.StatusOK, map[string]any{"users": out})
	case http.MethodPost:
		var req struct {
			Username string   `json:"username"`
			Scopes   []string `json:"scopes"`
			Password string   `json:"password"`
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		username := strings.TrimSpace(req.Username)
		if username == "" {
			writeError(w, http.StatusBadRequest, errors.New("username is required"))
			return
		}
		if _, exists := s.store.UserByUsername(username); exists {
			writeError(w, http.StatusConflict, errors.New("a user with that username already exists"))
			return
		}
		scopes := normalizeScopes(req.Scopes)
		if status, err := s.validateGrantScopes(p, scopes); err != nil {
			s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "user.create", Scope: "user:admin", Decision: "deny", Reason: err.Error(), Metadata: map[string]string{"username": username}})
			writeError(w, status, err)
			return
		}
		u := model.User{
			ID:        id.New("user"),
			Username:  username,
			Scopes:    scopes,
			CreatedAt: s.now(),
		}
		if req.Password != "" {
			hash, err := auth.HashSecret(req.Password)
			if err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			u.PasswordHash = hash
		}
		if err := s.store.UpsertUser(u); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "user.create", Scope: "user:admin", Decision: "allow", Metadata: map[string]string{"target": u.ID, "username": username, "scopes": strings.Join(u.Scopes, ","), "sso_only": fmt.Sprintf("%t", u.PasswordHash == "")}})
		writeJSON(w, http.StatusOK, toUserView(u))
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

// handleUserUpdate changes a user's scopes and/or resets their password. Empty
// password leaves the existing one untouched. A scope or password change bumps
// SecurityEpoch, which revokes that user's live cookie sessions on their next
// request. Enforces the self-de-admin and last-admin guards.
func (s *Server) handleUserUpdate(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		ID       string   `json:"id"`
		Scopes   []string `json:"scopes"`
		Password string   `json:"password"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	target, ok := s.store.User(req.ID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("user not found"))
		return
	}
	newScopes := normalizeScopes(req.Scopes)
	if status, err := s.validateGrantScopes(p, newScopes); err != nil {
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "user.update", Scope: "user:admin", Decision: "deny", Reason: err.Error(), Metadata: map[string]string{"target": target.ID}})
		writeError(w, status, err)
		return
	}
	losingAdmin := hasWildcardScope(target.Scopes) && !hasWildcardScope(newScopes)
	if losingAdmin && target.ID == p.ActorID {
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "user.update", Scope: "user:admin", Decision: "deny", Reason: "cannot remove own admin access", Metadata: map[string]string{"target": target.ID}})
		writeError(w, http.StatusForbidden, errors.New("cannot remove your own admin (*) access"))
		return
	}
	if losingAdmin && s.store.CountWildcardAdmins(target.ID) == 0 {
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "user.update", Scope: "user:admin", Decision: "deny", Reason: "would remove last admin", Metadata: map[string]string{"target": target.ID}})
		writeError(w, http.StatusConflict, errors.New("refusing to remove the last administrator (*)"))
		return
	}
	target.Scopes = newScopes
	if req.Password != "" {
		hash, err := auth.HashSecret(req.Password)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		target.PasswordHash = hash
	}
	target.SecurityEpoch++ // revoke the target's existing cookie sessions
	if err := s.store.UpsertUser(target); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "user.update", Scope: "user:admin", Decision: "allow", Metadata: map[string]string{"target": target.ID, "scopes": strings.Join(target.Scopes, ","), "password_reset": fmt.Sprintf("%t", req.Password != "")}})
	writeJSON(w, http.StatusOK, toUserView(target))
}

// handleDeleteUser removes a user and cascades: revoke their API tokens (bearer
// tokens ignore SecurityEpoch and would otherwise outlive the account), drop
// their OIDC subject links, and kill their cookie sessions. Refuses to delete
// the caller's own account or the last administrator.
func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	target, ok := s.store.User(req.ID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("user not found"))
		return
	}
	if target.ID == p.ActorID {
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "user.delete", Scope: "user:admin", Decision: "deny", Reason: "cannot delete own account", Metadata: map[string]string{"target": target.ID}})
		writeError(w, http.StatusForbidden, errors.New("cannot delete your own account"))
		return
	}
	if hasWildcardScope(target.Scopes) && s.store.CountWildcardAdmins(target.ID) == 0 {
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "user.delete", Scope: "user:admin", Decision: "deny", Reason: "would remove last admin", Metadata: map[string]string{"target": target.ID}})
		writeError(w, http.StatusConflict, errors.New("refusing to delete the last administrator (*)"))
		return
	}
	tokensRevoked := s.store.RevokeTokensByActor(target.ID)
	oidcRemoved := s.store.DeleteOIDCIdentitiesByUser(target.ID)
	sessionsKilled := s.store.DeleteSessionsByActor(target.ID)
	s.store.DeleteUser(target.ID)
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "user.delete", Scope: "user:admin", Decision: "allow", Metadata: map[string]string{
		"target":          target.ID,
		"username":        target.Username,
		"tokens_revoked":  fmt.Sprintf("%d", tokensRevoked),
		"oidc_removed":    fmt.Sprintf("%d", oidcRemoved),
		"sessions_killed": fmt.Sprintf("%d", sessionsKilled),
	}})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
