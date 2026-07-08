package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Passkey (WebAuthn) registration, login, and management.
//
// Library choice: github.com/go-webauthn/webauthn. Hand-rolling CBOR/COSE
// decoding, attestation parsing, and assertion signature verification is a
// well-known security anti-pattern; this repo already carries vetted third-party
// auth dependencies (go-oidc), so a maintained WebAuthn library is the
// consistent, safer choice. We keep the dependency surface minimal: attestation
// conveyance is "none" and no MDS/TPM/Apple attestation verification paths are
// configured — we only need proof-of-possession of a resident, user-verified
// credential, not authenticator provenance.
//
// RP identity: the Relying Party ID and origin are derived from the server's
// configured external base URL (Options.PublicURL, the same value that anchors
// the OIDC redirect). RPID = the URL host (no scheme/port); RPOrigin =
// scheme://host[:port]. When PublicURL is unset, passkey endpoints fail closed
// with a clear error (503), mirroring the OIDC handlers — no new config surface
// is introduced.

const webAuthnChallengeTTL = 5 * time.Minute

// webAuthnRP returns the passkey relying party derived from the server's
// configured external URL, built once and cached. It fails closed when no
// external URL is configured, mirroring the OIDC handlers.
func (s *Server) webAuthnRP() (*webauthn.WebAuthn, error) {
	if s.publicURL == "" {
		return nil, errors.New("passkeys are not configured (server public URL unset)")
	}
	s.webauthnOnce.Do(func() {
		s.webauthnRP, s.webauthnErr = newWebAuthnFromOrigin(s.publicURL)
	})
	return s.webauthnRP, s.webauthnErr
}

// newWebAuthnFromOrigin builds a relying party whose RPID is the origin host and
// whose sole permitted origin is that exact scheme+host+port. Resident
// (discoverable) keys and user verification are both required so that Apple
// Passwords / iCloud Keychain stores the passkey and usernameless login works.
func newWebAuthnFromOrigin(origin string) (*webauthn.WebAuthn, error) {
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid webauthn origin %q", origin)
	}
	requireResidentKey := true
	return webauthn.New(&webauthn.Config{
		RPID:                  u.Hostname(),
		RPDisplayName:         "Lattice",
		RPOrigins:             []string{u.Scheme + "://" + u.Host},
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: &requireResidentKey,
			UserVerification:   protocol.VerificationRequired,
		},
	})
}

// webAuthnUser adapts a Lattice user (plus its stored passkeys) to the
// go-webauthn User interface. The user handle is the opaque Lattice user id,
// which lets a discoverable login resolve the account in O(1) from the
// authenticator's userHandle.
type webAuthnUser struct {
	id    string
	name  string
	creds []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte                         { return []byte(u.id) }
func (u *webAuthnUser) WebAuthnName() string                       { return u.name }
func (u *webAuthnUser) WebAuthnDisplayName() string                { return u.name }
func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (s *Server) webAuthnUser(user model.User) *webAuthnUser {
	stored := s.store.WebAuthnCredentialsByUser(user.ID)
	creds := make([]webauthn.Credential, 0, len(stored))
	for _, c := range stored {
		creds = append(creds, storedCredentialToLibrary(c))
	}
	name := user.Username
	if name == "" {
		name = user.ID
	}
	return &webAuthnUser{id: user.ID, name: name, creds: creds}
}

func storedCredentialToLibrary(c auth.WebAuthnCredential) webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
	for _, t := range c.Transports {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}
	return webauthn.Credential{
		ID:              c.CredentialID,
		PublicKey:       c.PublicKey,
		AttestationType: "none",
		Transport:       transports,
		Flags: webauthn.CredentialFlags{
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:    c.AAGUID,
			SignCount: c.SignCount,
		},
	}
}

func libraryCredentialToStored(userID, name string, lc *webauthn.Credential, now time.Time) auth.WebAuthnCredential {
	transports := make([]string, 0, len(lc.Transport))
	for _, t := range lc.Transport {
		if t == "" {
			continue
		}
		transports = append(transports, string(t))
	}
	return auth.WebAuthnCredential{
		ID:             id.New("wacred"),
		UserID:         userID,
		Name:           name,
		CredentialID:   lc.ID,
		PublicKey:      lc.PublicKey,
		AAGUID:         lc.Authenticator.AAGUID,
		SignCount:      lc.Authenticator.SignCount,
		Transports:     transports,
		BackupEligible: lc.Flags.BackupEligible,
		BackupState:    lc.Flags.BackupState,
		CreatedAt:      now,
		LastUsedAt:     now,
	}
}

// webAuthnCredentialView is the secret-free projection returned to the dashboard.
type webAuthnCredentialView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	BackedUp   bool       `json:"backed_up"`
	Transports []string   `json:"transports,omitempty"`
	AAGUID     string     `json:"aaguid,omitempty"`
}

func webAuthnCredentialToView(c auth.WebAuthnCredential) webAuthnCredentialView {
	v := webAuthnCredentialView{
		ID:         c.ID,
		Name:       c.Name,
		CreatedAt:  c.CreatedAt,
		BackedUp:   c.BackupState,
		Transports: c.Transports,
	}
	if !c.LastUsedAt.IsZero() {
		t := c.LastUsedAt
		v.LastUsedAt = &t
	}
	if len(c.AAGUID) > 0 && !allZero(c.AAGUID) {
		v.AAGUID = fmt.Sprintf("%x", c.AAGUID)
	}
	return v
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// defaultPasskeyName builds a friendly default label from the platform hinted by
// the User-Agent and the creation time, so a user with several passkeys can tell
// them apart before renaming.
func defaultPasskeyName(r *http.Request, now time.Time) string {
	ua := r.UserAgent()
	platform := ""
	switch {
	case strings.Contains(ua, "iPhone"):
		platform = "iPhone "
	case strings.Contains(ua, "iPad"):
		platform = "iPad "
	case strings.Contains(ua, "Macintosh") || strings.Contains(ua, "Mac OS"):
		platform = "Mac "
	case strings.Contains(ua, "Android"):
		platform = "Android "
	case strings.Contains(ua, "Windows"):
		platform = "Windows "
	case strings.Contains(ua, "Linux"):
		platform = "Linux "
	}
	return fmt.Sprintf("%sPasskey · %s", platform, now.Format("2006-01-02"))
}

// requireInteractiveUser resolves the interactive-session user for a passkey
// management call, rejecting bearer tokens (PATs are not interactive sessions).
func (s *Server) requireInteractiveUser(w http.ResponseWriter, p principal) (model.User, bool) {
	if p.viaBearer || p.ActorID == "" || p.sessionID == "" {
		writeError(w, http.StatusForbidden, errors.New("passkey management requires an interactive session"))
		return model.User{}, false
	}
	user, ok := s.store.User(p.ActorID)
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("unknown user"))
		return model.User{}, false
	}
	return user, true
}

// handleWebAuthnRegisterBegin starts a passkey registration for the current
// operator. Registering a login-capable credential is security-sensitive, so a
// user who has TOTP enrolled must present a fresh step-up grant (the same verb
// used to reveal secrets or perform destructive actions).
func (s *Server) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	user, ok := s.requireInteractiveUser(w, p)
	if !ok {
		return
	}
	var req struct {
		StepUpGrant string `json:"step_up_grant"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if user.TOTPEnabled && !s.requireStepUpGrant(w, p, strings.TrimSpace(req.StepUpGrant), "webauthn.register") {
		return
	}
	if s.store.CountWebAuthnCredentialsByUser(user.ID) >= store.MaxWebAuthnCredentialsPerUser {
		writeError(w, http.StatusConflict, store.ErrWebAuthnCredentialLimit)
		return
	}
	rp, err := s.webAuthnRP()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	// Exclude already-registered credentials so the same authenticator is not
	// enrolled twice on this account.
	waUser := s.webAuthnUser(user)
	exclusions := make([]protocol.CredentialDescriptor, 0, len(waUser.creds))
	for _, c := range waUser.creds {
		exclusions = append(exclusions, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: c.ID,
		})
	}
	creation, session, err := rp.BeginRegistration(waUser, webauthn.WithExclusions(exclusions))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	challengeID, ok := s.storeWebAuthnChallenge(w, user.ID, s.clientIP(r), auth.WebAuthnPurposeRegister, session)
	if !ok {
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "webauthn.register", Decision: "observe"})
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge_id": challengeID,
		"publicKey":    creation.Response,
	})
}

// handleWebAuthnRegisterFinish verifies the attestation response and persists the
// new passkey. The step-up gate is re-checked here (the point of persistence),
// not only at begin.
func (s *Server) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	user, ok := s.requireInteractiveUser(w, p)
	if !ok {
		return
	}
	var req struct {
		ChallengeID string          `json:"challenge_id"`
		Name        string          `json:"name"`
		Credential  json.RawMessage `json:"credential"`
		StepUpGrant string          `json:"step_up_grant"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if user.TOTPEnabled && !s.requireStepUpGrant(w, p, strings.TrimSpace(req.StepUpGrant), "webauthn.register") {
		return
	}
	challenge, session, ok := s.loadWebAuthnChallenge(w, req.ChallengeID, s.clientIP(r), auth.WebAuthnPurposeRegister)
	if !ok {
		return
	}
	// The challenge is bound to the user who began the ceremony.
	if challenge.UserID != user.ID {
		writeError(w, http.StatusUnauthorized, errors.New("invalid or expired challenge"))
		return
	}
	rp, err := s.webAuthnRP()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(req.Credential))
	if err != nil {
		writeError(w, http.StatusBadRequest, apiError(model.APIErrorBadRequest, "invalid attestation response"))
		return
	}
	credential, err := rp.CreateCredential(s.webAuthnUser(user), *session, parsed)
	if err != nil {
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "webauthn.register", Decision: "deny", Reason: "attestation verification failed"})
		writeError(w, http.StatusBadRequest, apiError(model.APIErrorBadRequest, "passkey registration failed verification"))
		return
	}
	// Single-use: burn the challenge as soon as it verifies.
	_ = s.store.ConsumeWebAuthnChallenge(challenge.ID)
	// Reject a credential id already known to the server (same authenticator
	// re-registered, or a cross-account collision).
	if _, exists := s.store.WebAuthnCredentialByCredentialID(credential.ID); exists {
		writeError(w, http.StatusConflict, apiError(model.APIErrorBadRequest, "this passkey is already registered"))
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = defaultPasskeyName(r, s.now())
	}
	name = clampPasskeyName(name)
	record := libraryCredentialToStored(user.ID, name, credential, s.now().UTC())
	if err := s.store.UpsertWebAuthnCredential(record); err != nil {
		if errors.Is(err, store.ErrWebAuthnCredentialLimit) {
			writeError(w, http.StatusConflict, store.ErrWebAuthnCredentialLimit)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "webauthn.register", Decision: "allow"})
	writeJSON(w, http.StatusOK, map[string]any{"credential": webAuthnCredentialToView(record)})
}

// handleWebAuthnCredentials lists the current operator's passkeys (GET).
func (s *Server) handleWebAuthnCredentials(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	user, ok := s.requireInteractiveUser(w, p)
	if !ok {
		return
	}
	stored := s.store.WebAuthnCredentialsByUser(user.ID)
	views := make([]webAuthnCredentialView, 0, len(stored))
	for _, c := range stored {
		views = append(views, webAuthnCredentialToView(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"credentials": views})
}

// handleWebAuthnRename updates a passkey's operator-editable label. Renaming is
// not security-sensitive (it grants no new access), so no step-up is required.
func (s *Server) handleWebAuthnRename(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	user, ok := s.requireInteractiveUser(w, p)
	if !ok {
		return
	}
	var req struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	name := clampPasskeyName(strings.TrimSpace(req.Name))
	if name == "" {
		writeError(w, http.StatusBadRequest, apiError(model.APIErrorBadRequest, "name is required"))
		return
	}
	updated, ok, err := s.store.RenameWebAuthnCredential(strings.TrimSpace(req.ID), user.ID, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("passkey not found"))
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "webauthn.rename", Decision: "allow"})
	writeJSON(w, http.StatusOK, map[string]any{"credential": webAuthnCredentialToView(updated)})
}

// handleWebAuthnDelete removes a passkey. Deleting a login-capable credential is
// security-sensitive, so a TOTP-enrolled user must present a fresh step-up grant.
// Deleting the operator's last passkey is blocked only when the account has no
// other way in (no password) — in this deployment every account keeps a
// password, so removing all passkeys is permitted.
func (s *Server) handleWebAuthnDelete(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	user, ok := s.requireInteractiveUser(w, p)
	if !ok {
		return
	}
	var req struct {
		ID          string `json:"id"`
		StepUpGrant string `json:"step_up_grant"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if user.TOTPEnabled && !s.requireStepUpGrant(w, p, strings.TrimSpace(req.StepUpGrant), "webauthn.delete") {
		return
	}
	cred, found := s.store.WebAuthnCredential(strings.TrimSpace(req.ID))
	if !found || cred.UserID != user.ID {
		writeError(w, http.StatusNotFound, errors.New("passkey not found"))
		return
	}
	// Guard: refuse to strip the account's last login method. A password always
	// exists in this deployment, so this only triggers for a (hypothetical)
	// passwordless account.
	if user.PasswordHash == "" && s.store.CountWebAuthnCredentialsByUser(user.ID) <= 1 {
		writeError(w, http.StatusConflict, apiError(model.APIErrorBadRequest, "cannot remove the last sign-in method for this account"))
		return
	}
	deleted, err := s.store.DeleteWebAuthnCredential(strings.TrimSpace(req.ID), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, errors.New("passkey not found"))
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "webauthn.delete", Decision: "allow"})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleWebAuthnLoginBegin starts a usernameless (discoverable) passkey login.
// It is pre-auth, so it shares the login rate limiter with password login.
func (s *Server) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.loginLimiter.Allow(s.clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, errors.New("too many login attempts; slow down"))
		return
	}
	rp, err := s.webAuthnRP()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	assertion, session, err := rp.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	challengeID, ok := s.storeWebAuthnChallenge(w, "", s.clientIP(r), auth.WebAuthnPurposeLogin, session)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge_id": challengeID,
		"publicKey":    assertion.Response,
	})
}

// handleWebAuthnLoginFinish verifies a discoverable assertion, resolves the user
// from the authenticator's user handle, and issues the SAME session the
// password+TOTP path issues — a user-verified passkey satisfies both possession
// and inherence, so no separate second factor is required.
func (s *Server) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.loginLimiter.Allow(s.clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, errors.New("too many login attempts; slow down"))
		return
	}
	var req struct {
		ChallengeID string          `json:"challenge_id"`
		Credential  json.RawMessage `json:"credential"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	challenge, session, ok := s.loadWebAuthnChallenge(w, req.ChallengeID, s.clientIP(r), auth.WebAuthnPurposeLogin)
	if !ok {
		return
	}
	rp, err := s.webAuthnRP()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(req.Credential))
	if err != nil {
		writeError(w, http.StatusBadRequest, apiError(model.APIErrorBadRequest, "invalid assertion response"))
		return
	}
	var resolved model.User
	var resolvedOK bool
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		u, found := s.store.User(string(userHandle))
		if !found {
			return nil, errors.New("unknown user handle")
		}
		resolved, resolvedOK = u, true
		return s.webAuthnUser(u), nil
	}
	credential, err := rp.ValidateDiscoverableLogin(handler, *session, parsed)
	// Burn the challenge regardless of outcome (single-use; no replay of a failed
	// or successful assertion).
	_ = s.store.ConsumeWebAuthnChallenge(challenge.ID)
	if err != nil || !resolvedOK {
		s.recordRequestAudit(r, model.AuditEvent{ID: id.New("audit"), Action: "login.webauthn", Decision: "deny", Reason: "assertion verification failed"})
		writeError(w, http.StatusUnauthorized, errors.New("passkey login failed"))
		return
	}
	// Locate the stored record to update sign-count / backup-state / last-used.
	stored, found := s.store.WebAuthnCredentialByCredentialID(credential.ID)
	if !found || stored.UserID != resolved.ID {
		s.recordRequestAudit(r, model.AuditEvent{ID: id.New("audit"), ActorID: resolved.ID, Action: "login.webauthn", Decision: "deny", Reason: "credential not registered to user"})
		writeError(w, http.StatusUnauthorized, errors.New("passkey login failed"))
		return
	}
	newCount := credential.Authenticator.SignCount
	// Sign-count policy: synced passkeys (e.g. Apple's) always report 0, so a
	// zero or non-incrementing counter is NOT an error. Only a regression from a
	// previously non-zero counter is a clone signal, and we log it rather than
	// hard-fail (per WebAuthn guidance, the RP decides; we choose to warn and
	// continue so a legitimate operator is never locked out).
	if stored.SignCount != 0 && newCount != 0 && newCount <= stored.SignCount {
		s.logger.Printf("WARNING: passkey sign-count regression for user %s credential %s (stored=%d presented=%d); possible cloned authenticator", resolved.ID, stored.ID, stored.SignCount, newCount)
	}
	if err := s.store.TouchWebAuthnCredential(stored.ID, newCount, credential.Flags.BackupState, s.now()); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordRequestAudit(r, model.AuditEvent{ID: id.New("audit"), ActorID: resolved.ID, Action: "login.webauthn", Decision: "allow"})
	// Passkey with user verification = possession + inherence; issue the standard
	// session with 2FA already satisfied (the password→TOTP two-step is bypassed).
	s.issueSession(w, r, resolved)
}

// handleWebAuthnStepUpBegin starts an authenticated, user-bound passkey
// assertion for issuing the same short-lived step-up grant as TOTP.
func (s *Server) handleWebAuthnStepUpBegin(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	user, ok := s.requireInteractiveUser(w, p)
	if !ok {
		return
	}
	if s.store.CountWebAuthnCredentialsByUser(user.ID) == 0 {
		writeError(w, http.StatusForbidden, errors.New("no passkey is registered for this account"))
		return
	}
	rp, err := s.webAuthnRP()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	assertion, session, err := rp.BeginLogin(s.webAuthnUser(user), webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	challengeID, ok := s.storeWebAuthnChallenge(w, user.ID, s.clientIP(r), auth.WebAuthnPurposeStepUp, session)
	if !ok {
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "security.step_up.webauthn", Decision: "observe"})
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge_id": challengeID,
		"publicKey":    assertion.Response,
	})
}

func (s *Server) handleWebAuthnStepUpFinish(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	user, ok := s.requireInteractiveUser(w, p)
	if !ok {
		return
	}
	var req struct {
		ChallengeID string          `json:"challenge_id"`
		Credential  json.RawMessage `json:"credential"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	challenge, session, ok := s.loadWebAuthnChallenge(w, req.ChallengeID, s.clientIP(r), auth.WebAuthnPurposeStepUp)
	if !ok {
		return
	}
	if challenge.UserID != user.ID {
		writeError(w, http.StatusUnauthorized, errors.New("invalid or expired challenge"))
		return
	}
	rp, err := s.webAuthnRP()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(req.Credential))
	if err != nil {
		writeError(w, http.StatusBadRequest, apiError(model.APIErrorBadRequest, "invalid assertion response"))
		return
	}
	credential, err := rp.ValidateLogin(s.webAuthnUser(user), *session, parsed)
	_ = s.store.ConsumeWebAuthnChallenge(challenge.ID)
	if err != nil {
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "security.step_up.webauthn", Decision: "deny", Reason: "assertion verification failed"})
		writeError(w, http.StatusUnauthorized, errors.New("passkey verification failed"))
		return
	}
	stored, found := s.store.WebAuthnCredentialByCredentialID(credential.ID)
	if !found || stored.UserID != user.ID {
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "security.step_up.webauthn", Decision: "deny", Reason: "credential not registered to user"})
		writeError(w, http.StatusUnauthorized, errors.New("passkey verification failed"))
		return
	}
	if stored.SignCount != 0 && credential.Authenticator.SignCount != 0 && credential.Authenticator.SignCount <= stored.SignCount {
		s.logger.Printf("WARNING: passkey sign-count regression for step-up user %s credential %s (stored=%d presented=%d); possible cloned authenticator", user.ID, stored.ID, stored.SignCount, credential.Authenticator.SignCount)
	}
	if err := s.store.TouchWebAuthnCredential(stored.ID, credential.Authenticator.SignCount, credential.Flags.BackupState, s.now()); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	grant, expiresAt, err := s.issueStepUpGrant(p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "security.step_up", Decision: "allow", Reason: "webauthn"})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "grant": grant, "expires_at": expiresAt})
}

// storeWebAuthnChallenge serialises the ceremony session data and persists a
// short-lived, single-use, IP-bound challenge, returning the store record id the
// client echoes back at finish. Returns ("", false) (after writing the error)
// when persistence fails.
func (s *Server) storeWebAuthnChallenge(w http.ResponseWriter, userID, clientIP, purpose string, session *webauthn.SessionData) (string, bool) {
	data, err := json.Marshal(session)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return "", false
	}
	challenge, err := auth.NewWebAuthnChallenge(userID, clientIP, purpose, data, webAuthnChallengeTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return "", false
	}
	// The challenge id we hand the client is the store record id, decoupled from
	// the raw WebAuthn challenge bytes carried inside session data.
	if err := s.store.PutWebAuthnChallenge(challenge); err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return "", false
	}
	return challenge.ID, true
}

// loadWebAuthnChallenge fetches and validates a pending challenge: it must exist,
// be active, match the requesting client IP, and be for the expected ceremony.
// On success it returns the decoded session data.
func (s *Server) loadWebAuthnChallenge(w http.ResponseWriter, challengeID, clientIP, purpose string) (auth.WebAuthnChallenge, *webauthn.SessionData, bool) {
	challenge, ok := s.store.WebAuthnChallenge(strings.TrimSpace(challengeID))
	if !ok || challenge.Purpose != purpose || challenge.ClientIP != clientIP {
		writeError(w, http.StatusUnauthorized, errors.New("invalid or expired challenge"))
		return auth.WebAuthnChallenge{}, nil, false
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(challenge.SessionData, &session); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return auth.WebAuthnChallenge{}, nil, false
	}
	return challenge, &session, true
}

const maxPasskeyNameLen = 64

func clampPasskeyName(name string) string {
	name = strings.TrimSpace(name)
	if len(name) > maxPasskeyNameLen {
		name = strings.TrimSpace(name[:maxPasskeyNameLen])
	}
	return name
}
