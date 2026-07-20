package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// design-15 D3: per-line user management for adopted (233boy-script) sing-box
// nodes. The vpn-core users-admin plan methods compile a reviewed approval; the
// approval executor renders the `sb user add|del` invocation; nothing touches a
// node before an operator approves the exact credential hash.
//
// The approval carries NO secret material: Plan is the redacted, human-reviewed
// payload and Action binds the credential SHA-256. The apply script re-derives
// the credential from the write-only store at execution time and refuses to run
// when the bytes no longer match what was approved (same discipline as
// proxyCoreApplyScript's current-config SHA binding).
const (
	// singBoxLineUserPlugin is the approval.Plugin value routing line-user
	// approvals through lineUserApplyScript / handleLineUserTaskResult.
	singBoxLineUserPlugin = "singbox-lineuser"
	// lineUserActionPrefix prefixes the credential SHA-256 in approval.Action.
	lineUserActionPrefix = "apply-line-user:"

	lineUserOpAdd    = "add"
	lineUserOpRemove = "remove"
)

// lineUserProtocols is the set of line protocols the on-box `sb user` CLI can
// mutate (mirrors json_line_user_obj in the 233boy fork: single-user
// shadowsocks and unmanaged inbounds are rejected on-box, so they are rejected
// here first with a clearer error).
var lineUserProtocols = map[string]bool{
	"vless": true, "vmess": true, "trojan": true,
	"hysteria2": true, "tuic": true, "anytls": true, "socks": true,
}

// userLineName derives the sing-box users[].name for a (user, line) pair —
// the single join key for auth, route auth_user rules, and per-user stats
// (design-15 §5). PII-free, deterministic, unique per pair.
func userLineName(userID, lineUUID string) string {
	sum := sha256.Sum256([]byte(userID + "|" + lineUUID))
	return "u_" + hex.EncodeToString(sum[:])[:16]
}

// lineUserPlan is the redacted, operator-reviewed approval payload. It never
// carries uuid/password material — only the hash binding it.
type lineUserPlan struct {
	Op               string `json:"op"` // add | remove
	NodeID           string `json:"node_id"`
	Line             string `json:"line"` // on-box conf name (sb CLI line handle)
	LineHashID       string `json:"line_hash_id"`
	LineUUID         string `json:"line_uuid"`
	UserID           string `json:"user_id"`
	UserName         string `json:"user_name"` // derived userLineName
	Protocol         string `json:"protocol"`
	CredentialSHA256 string `json:"credential_sha256"`
	Summary          string `json:"summary"`
}

// lineUserCredentialPayload is the exact JSON object passed to
// `sb user add|del <line> <payload>`. Field order is fixed so CredentialSHA256
// is stable; omitempty keeps protocol-irrelevant fields out.
type lineUserCredentialPayload struct {
	Name     string `json:"name"`
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
	Username string `json:"username,omitempty"`
	Flow     string `json:"flow,omitempty"`
}

// lineUserCredential builds the on-box payload for one (user, protocol) pair
// from the write-only credential store.
func lineUserCredential(u VpnUser, protocol, userName string) (lineUserCredentialPayload, error) {
	var cred *VpnCredential
	for i := range u.Credentials {
		if u.Credentials[i].Protocol == protocol {
			cred = &u.Credentials[i]
			break
		}
	}
	if cred == nil {
		return lineUserCredentialPayload{}, fmt.Errorf("user %q has no %s credential", u.ID, protocol)
	}
	payload := lineUserCredentialPayload{Name: userName}
	switch protocol {
	case "vless", "vmess":
		if cred.UUID == "" {
			return lineUserCredentialPayload{}, fmt.Errorf("user %q %s credential has no uuid", u.ID, protocol)
		}
		payload.UUID = cred.UUID
		if protocol == "vless" {
			payload.Flow = cred.Flow
		}
	case "tuic":
		if cred.UUID == "" || cred.Password == "" {
			return lineUserCredentialPayload{}, fmt.Errorf("user %q tuic credential needs uuid and password", u.ID)
		}
		payload.UUID, payload.Password = cred.UUID, cred.Password
	case "trojan", "hysteria2", "anytls":
		if cred.Password == "" {
			return lineUserCredentialPayload{}, fmt.Errorf("user %q %s credential has no password", u.ID, protocol)
		}
		payload.Password = cred.Password
	case "socks":
		if cred.Password == "" {
			return lineUserCredentialPayload{}, fmt.Errorf("user %q socks credential has no password", u.ID)
		}
		payload.Username, payload.Password = userName, cred.Password
	default:
		return lineUserCredentialPayload{}, fmt.Errorf("protocol %q does not support per-line user mutation", protocol)
	}
	return payload, nil
}

// lineUserCredentialSHA binds the exact payload bytes an approval reviewed.
func lineUserCredentialSHA(payload lineUserCredentialPayload) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// resolveAdoptedLine finds a discovered (adopted-track) line by hash. Managed
// lines take the whole-config render path (design-15 D6 deferred), so they are
// rejected here with an explicit error rather than silently mis-routed.
func (s *Server) resolveAdoptedLine(lineHashID string) (Line, error) {
	for _, g := range s.buildLineGroups() {
		for _, ln := range g.Lines {
			if ln.LineHashID != lineHashID {
				continue
			}
			if ln.Managed {
				return Line{}, fmt.Errorf("line %q is Lattice-managed; managed-track user writes are a later slice", lineHashID)
			}
			if ln.LineUUID == "" {
				return Line{}, fmt.Errorf("line %q has no line_uuid yet; wait for allocation and retry", lineHashID)
			}
			protocol := strings.ToLower(strings.TrimSpace(ln.Type))
			if !lineUserProtocols[protocol] {
				return Line{}, fmt.Errorf("line %q protocol %q does not support per-line user mutation", lineHashID, ln.Type)
			}
			if strings.TrimSpace(ln.Tag) == "" {
				return Line{}, fmt.Errorf("line %q has no on-box tag", lineHashID)
			}
			ln.Type = protocol
			return ln, nil
		}
	}
	return Line{}, fmt.Errorf("line %q is not a known line on any node", lineHashID)
}

// vpnUserLinePlan compiles the reviewed approval for one `plan_add` /
// `plan_remove` call. Nothing is applied here: the operator reviews the plan,
// and the approval executor renders the sb invocation against the then-current
// credential bytes.
func (s *Server) vpnUserLinePlan(ctxPrincipal principal, request []byte, op string) ([]byte, error) {
	var req struct {
		UserID     string `json:"user_id"`
		LineHashID string `json:"line_hash_id"`
	}
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("vpn-core/users-admin plan_%s: invalid request: %w", op, err)
	}
	u, ok := s.getVpnUser(strings.TrimSpace(req.UserID))
	if !ok {
		return nil, fmt.Errorf("vpn-core/users-admin plan_%s: user %q not found", op, req.UserID)
	}
	if op == lineUserOpAdd && !u.Enabled {
		return nil, fmt.Errorf("user %q is disabled", u.ID)
	}
	ln, err := s.resolveAdoptedLine(strings.TrimSpace(req.LineHashID))
	if err != nil {
		return nil, err
	}
	name := userLineName(u.ID, ln.LineUUID)
	if op == lineUserOpAdd {
		bound := false
		for _, b := range u.Bindings {
			if b.LineHashID == ln.LineHashID && b.Enabled {
				bound = true
				break
			}
		}
		if !bound {
			return nil, fmt.Errorf("user %q is not bound to line %q; bind first, then plan the add", u.ID, ln.LineHashID)
		}
	}
	payload, err := lineUserCredential(u, ln.Type, name)
	if err != nil {
		return nil, err
	}
	sha, err := lineUserCredentialSHA(payload)
	if err != nil {
		return nil, err
	}
	plan := lineUserPlan{
		Op: op, NodeID: ln.NodeID, Line: ln.Tag, LineHashID: ln.LineHashID, LineUUID: ln.LineUUID,
		UserID: u.ID, UserName: name, Protocol: ln.Type, CredentialSHA256: sha,
		Summary: fmt.Sprintf("sb user %s %s on node %s (user %s as %s, credential sha %s…)",
			op, ln.Tag, ln.NodeID, u.Email, name, sha[:12]),
	}
	planJSON, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	approval := model.Approval{
		ID:        id.New("approval"),
		NodeID:    ln.NodeID,
		Plugin:    singBoxLineUserPlugin,
		Action:    lineUserActionPrefix + sha,
		Plan:      string(planJSON),
		Status:    model.ApprovalPending,
		ActorID:   ctxPrincipal.ActorID,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := s.store.UpsertApproval(approval); err != nil {
		return nil, err
	}
	s.recordPrincipalAudit(ctxPrincipal, model.AuditEvent{
		ID: id.New("audit"), NodeID: ln.NodeID, Action: "vpnuser.line.plan", Scope: "proxy:admin",
		Metadata: map[string]string{
			"approval_id": approval.ID, "op": op, "user_id": u.ID,
			"line_hash_id": ln.LineHashID, "credential_sha256": sha,
		},
	})
	return json.Marshal(struct {
		Approval model.Approval `json:"approval"`
	}{Approval: approval})
}

// lineUserApplyScript renders the on-box `sb user add|del` invocation for an
// approved plan, re-deriving the credential from the write-only store and
// failing closed when the bytes no longer match the approved hash. The script
// never embeds a credential that was not exactly the reviewed one.
func (s *Server) lineUserApplyScript(approval model.Approval) string {
	fail := func(err error) string {
		return "set -e\n" +
			"echo " + shellQuote("lattice lineuser: "+err.Error()) + " >&2\n" +
			"exit 1\n"
	}
	if !strings.HasPrefix(approval.Action, lineUserActionPrefix) {
		return fail(fmt.Errorf("invalid approval action %q", approval.Action))
	}
	approvedSHA := strings.TrimPrefix(approval.Action, lineUserActionPrefix)
	var plan lineUserPlan
	if err := json.Unmarshal([]byte(approval.Plan), &plan); err != nil {
		return fail(fmt.Errorf("invalid approval plan: %v", err))
	}
	if plan.CredentialSHA256 != approvedSHA {
		return fail(errors.New("plan credential hash does not match approval action; re-plan"))
	}
	u, ok := s.getVpnUser(plan.UserID)
	if !ok {
		return fail(fmt.Errorf("user %q no longer exists; re-plan", plan.UserID))
	}
	payload, err := lineUserCredential(u, plan.Protocol, plan.UserName)
	if err != nil {
		return fail(fmt.Errorf("re-derive credential: %v; re-plan", err))
	}
	sha, err := lineUserCredentialSHA(payload)
	if err != nil || sha != approvedSHA {
		return fail(errors.New("credential changed since approval; re-plan"))
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fail(fmt.Errorf("encode payload: %v", err))
	}
	return "set -e\n" +
		"SB_BIN=\"${LATTICE_SINGBOX_BIN:-sb}\"\n" +
		"command -v \"$SB_BIN\" >/dev/null 2>&1 || { echo " + shellQuote("lattice lineuser: sb binary not found") + " >&2; exit 1; }\n" +
		"\"$SB_BIN\" --json user " + plan.Op + " " + shellQuote(plan.Line) + " " + shellQuote(string(payloadJSON)) + "\n"
}

// handleLineUserTaskResult reconciles a line-user approval once the agent
// reports back. A failed task leaves the approval in place for re-approval; a
// successful remove also drops the (now untrue) server-side binding so the
// read model stops claiming the user should be on the line.
func (s *Server) handleLineUserTaskResult(r *http.Request, approval model.Approval, task model.Task, result model.TaskResult) error {
	metadata := map[string]string{
		"approval_id": approval.ID, "task_id": task.ID, "plugin_id": approval.Plugin,
	}
	if result.Error != "" || result.ExitCode != 0 {
		reason := result.Error
		if reason == "" {
			reason = fmt.Sprintf("line-user task exited %d", result.ExitCode)
		}
		s.recordRequestAudit(r, model.AuditEvent{
			ID: id.New("audit"), NodeID: approval.NodeID, Action: "vpnuser.line.failed",
			Decision: "deny", Reason: reason, Metadata: metadata,
		})
		return nil
	}
	approval.Status = model.ApprovalApplied
	approval.Reason = ""
	approval.UpdatedAt = time.Now().UTC()
	if err := s.store.UpsertApproval(approval); err != nil {
		return fmt.Errorf("mark line-user approval applied: %w", err)
	}
	s.recordRequestAudit(r, model.AuditEvent{
		ID: id.New("audit"), NodeID: approval.NodeID, Action: "vpnuser.line.applied",
		Decision: "allow", Metadata: metadata,
	})
	var plan lineUserPlan
	if err := json.Unmarshal([]byte(approval.Plan), &plan); err == nil && plan.Op == lineUserOpRemove {
		if u, ok := s.getVpnUser(plan.UserID); ok {
			kept := u.Bindings[:0]
			for _, b := range u.Bindings {
				if b.LineHashID != plan.LineHashID {
					kept = append(kept, b)
				}
			}
			if len(kept) != len(u.Bindings) {
				u.Bindings = kept
				u.UpdatedAt = s.now()
				if err := s.putVpnUser(u); err != nil {
					return fmt.Errorf("drop applied remove binding: %w", err)
				}
			}
		}
	}
	// An applied line-user change alters what nodes should serve: re-arm the
	// Sub-Store auto-sync just like the direct mutations do (design-15 §7).
	s.triggerVPNCoreMutation()
	return nil
}

// ── credential rotation (one-time reveal, write-only invariant preserved) ────

// newLineUserPassword generates a fresh URL-safe password for password-based
// protocols (trojan/hysteria2/tuic/anytls/socks/shadowsocks).
func newLineUserPassword() (string, error) {
	var b [18]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	out := make([]byte, 24)
	for i := range out {
		out[i] = alphabet[int(b[i%len(b)])&63]
	}
	return string(out), nil
}

// vpnUserRotateCredential regenerates ONE protocol credential for a user. The
// new secret is returned exactly once in the response (`revealed_credential`);
// the store keeps its write-only discipline and read RPCs keep returning
// has_secret only. A rotation only changes server state — pushing it onto
// lines is an explicit plan_add/plan_remove afterwards (drift is surfaced).
func (s *Server) vpnUserRotateCredential(ctxPrincipal principal, request []byte) ([]byte, error) {
	var req struct {
		UserID   string `json:"user_id"`
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("vpn-core/users-admin rotate: invalid request: %w", err)
	}
	protocol := strings.ToLower(strings.TrimSpace(req.Protocol))
	if !vpnCredProtocols[protocol] {
		return nil, fmt.Errorf("unsupported credential protocol %q", req.Protocol)
	}
	u, ok := s.getVpnUser(strings.TrimSpace(req.UserID))
	if !ok {
		return nil, fmt.Errorf("vpn-core/users-admin rotate: user %q not found", req.UserID)
	}
	idx := -1
	for i := range u.Credentials {
		if u.Credentials[i].Protocol == protocol {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("user %q has no %s credential to rotate", u.ID, protocol)
	}
	cred := u.Credentials[idx]
	revealed := ""
	if vpnCredUUIDProtos[protocol] {
		fresh, err := newProxyUUID()
		if err != nil {
			return nil, err
		}
		cred.UUID = fresh
		revealed = fresh
		if protocol == "tuic" {
			pw, err := newLineUserPassword()
			if err != nil {
				return nil, err
			}
			cred.Password = pw
		}
	} else {
		pw, err := newLineUserPassword()
		if err != nil {
			return nil, err
		}
		cred.Password = pw
		revealed = pw
	}
	u.Credentials[idx] = cred
	u.UpdatedAt = s.now()
	if err := s.putVpnUser(u); err != nil {
		return nil, err
	}
	s.recordPrincipalAudit(ctxPrincipal, model.AuditEvent{
		ID: id.New("audit"), Action: "vpnuser.credential.rotate", Scope: "proxy:admin",
		Metadata: map[string]string{"user_id": u.ID, "protocol": protocol},
	})
	return json.Marshal(struct {
		User     vpnUserView `json:"user"`
		Protocol string      `json:"protocol"`
		// RevealedCredential is the new secret, returned once and never again.
		RevealedCredential string `json:"revealed_credential"`
	}{User: toVpnUserView(u), Protocol: protocol, RevealedCredential: revealed})
}
