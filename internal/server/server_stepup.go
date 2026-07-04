package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/id"
)

const stepUpGrantTTL = time.Minute

type stepUpGrant struct {
	ID        string
	ActorID   string
	SessionID string
	ExpiresAt time.Time
}

func (s *Server) handleSecurityStepUp(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if p.viaBearer || p.ActorID == "" || p.sessionID == "" {
		writeError(w, http.StatusForbidden, errors.New("2fa step-up requires an interactive session"))
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	user, ok := s.store.User(p.ActorID)
	if !ok || !user.TOTPEnabled || user.TOTPSecret == "" {
		writeError(w, http.StatusForbidden, errors.New("2fa must be enabled before sensitive actions"))
		return
	}
	step, ok := auth.ValidateTOTPStep(user.TOTPSecret, req.Code, s.now())
	if !ok {
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "security.step_up", Decision: "deny", Reason: "invalid second factor"})
		writeError(w, http.StatusUnauthorized, errors.New("invalid second factor"))
		return
	}
	advanced, err := s.store.AdvanceTOTPStep(user.ID, step)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !advanced {
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "security.step_up", Decision: "deny", Reason: "replayed second factor"})
		writeError(w, http.StatusUnauthorized, errors.New("invalid second factor"))
		return
	}
	token, err := auth.NewRandomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	expiresAt := s.now().UTC().Add(stepUpGrantTTL)
	s.stepUpMu.Lock()
	if s.stepUpGrants == nil {
		s.stepUpGrants = map[string]stepUpGrant{}
	}
	now := s.now().UTC()
	for k, grant := range s.stepUpGrants {
		if !grant.ExpiresAt.After(now) {
			delete(s.stepUpGrants, k)
		}
	}
	s.stepUpGrants[token] = stepUpGrant{
		ID:        token,
		ActorID:   p.ActorID,
		SessionID: p.sessionID,
		ExpiresAt: expiresAt,
	}
	s.stepUpMu.Unlock()
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "security.step_up", Decision: "allow"})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "grant": token, "expires_at": expiresAt})
}

func (s *Server) requireStepUpGrant(w http.ResponseWriter, p principal, grantID, action string) bool {
	if p.viaBearer || p.ActorID == "" || p.sessionID == "" {
		writeError(w, http.StatusForbidden, errors.New("2fa step-up requires an interactive session"))
		return false
	}
	if grantID == "" {
		writeError(w, http.StatusForbidden, errors.New("2fa step-up required"))
		return false
	}
	now := s.now().UTC()
	s.stepUpMu.Lock()
	defer s.stepUpMu.Unlock()
	for k, grant := range s.stepUpGrants {
		if !grant.ExpiresAt.After(now) {
			delete(s.stepUpGrants, k)
		}
	}
	grant, ok := s.stepUpGrants[grantID]
	if !ok || grant.ActorID != p.ActorID || grant.SessionID != p.sessionID || !grant.ExpiresAt.After(now) {
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: action, Decision: "deny", Reason: "missing or expired 2fa step-up"})
		writeError(w, http.StatusForbidden, errors.New("2fa step-up required"))
		return false
	}
	return true
}
