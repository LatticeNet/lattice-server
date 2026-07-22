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
	"github.com/LatticeNet/lattice-server/internal/proxycore"
	"github.com/LatticeNet/lattice-server/internal/rbac"
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
	lineUserOpUpdate = "update"
	lineUserOpRemove = "remove"

	lineUserTrackAdopted = "adopted"
	lineUserTrackManaged = "managed"
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
	Op               string `json:"op"` // add | update | remove
	Track            string `json:"track"`
	NodeID           string `json:"node_id"`
	Line             string `json:"line"` // on-box conf name (sb CLI line handle)
	LineHashID       string `json:"line_hash_id"`
	LineUUID         string `json:"line_uuid"`
	UserID           string `json:"user_id"`
	UserName         string `json:"user_name"` // derived userLineName
	Protocol         string `json:"protocol"`
	CredentialSHA256 string `json:"credential_sha256"`
	ConfigSHA256     string `json:"config_sha256,omitempty"`
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
	credential, ok := vpnCredentialForProtocol(u.Credentials, protocol)
	if !ok {
		return lineUserCredentialPayload{}, fmt.Errorf("user %q has no %s credential", u.ID, protocol)
	}
	cred := &credential
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

func lineUserRequestSHA(userID, lineHashID string) string {
	raw, _ := json.Marshal(struct {
		UserID     string `json:"user_id"`
		LineHashID string `json:"line_hash_id"`
	}{UserID: strings.TrimSpace(userID), LineHashID: strings.TrimSpace(lineHashID)})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func vpnUserHasEnabledBinding(user VpnUser, lineHashID string) bool {
	for _, binding := range user.Bindings {
		if binding.LineHashID == lineHashID && binding.Enabled {
			return true
		}
	}
	return false
}

func vpnUserWithPlannedBinding(user VpnUser, lineHashID, op string) VpnUser {
	bindings := append([]LineBinding(nil), user.Bindings...)
	switch op {
	case lineUserOpAdd, lineUserOpUpdate:
		found := false
		for i := range bindings {
			if bindings[i].LineHashID == lineHashID {
				bindings[i].Enabled, found = true, true
			}
		}
		if !found {
			bindings = append(bindings, LineBinding{LineHashID: lineHashID, Enabled: true})
		}
	case lineUserOpRemove:
		kept := bindings[:0]
		for _, binding := range bindings {
			if binding.LineHashID != lineHashID {
				kept = append(kept, binding)
			}
		}
		bindings = kept
	}
	user.Bindings = bindings
	return user
}

// resolveAdoptedLine finds a discovered (adopted-track) line by hash. Managed
// lines take the whole-config render path (design-15 D6 deferred), so they are
// rejected here with an explicit error rather than silently mis-routed.
func (s *Server) resolveLineUserTarget(lineHashID string) (Line, error) {
	groups, _ := s.lineReadModel()
	for _, g := range groups {
		for _, ln := range g.Lines {
			if ln.LineHashID != lineHashID {
				continue
			}
			if ln.LineUUID == "" {
				return Line{}, fmt.Errorf("line %q has no line_uuid yet; wait for allocation and retry", lineHashID)
			}
			protocol := strings.ToLower(strings.TrimSpace(ln.Type))
			if ln.Managed && (ln.Core != model.ProxyCoreSingbox || protocol != model.ProxyProtocolVLESS) {
				return Line{}, fmt.Errorf("managed line %q requires the supported sing-box VLESS renderer", lineHashID)
			}
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
	if op != lineUserOpAdd && op != lineUserOpUpdate && op != lineUserOpRemove {
		return nil, fmt.Errorf("vpn-core/users-admin: invalid line-user op %q", op)
	}
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
	if (op == lineUserOpAdd || op == lineUserOpUpdate) && !u.Enabled {
		return nil, fmt.Errorf("user %q is disabled", u.ID)
	}
	ln, err := s.resolveLineUserTarget(strings.TrimSpace(req.LineHashID))
	if err != nil {
		return nil, err
	}
	bound := vpnUserHasEnabledBinding(u, ln.LineHashID)
	if op == lineUserOpAdd && bound {
		return nil, fmt.Errorf("user %q is already bound to line %q; plan_update instead", u.ID, ln.LineHashID)
	}
	if (op == lineUserOpUpdate || op == lineUserOpRemove) && !bound {
		return nil, fmt.Errorf("user %q is not bound to line %q", u.ID, ln.LineHashID)
	}
	name := userLineName(u.ID, ln.LineUUID)
	payload, err := lineUserCredential(u, ln.Type, name)
	if err != nil {
		return nil, err
	}
	sha, err := lineUserCredentialSHA(payload)
	if err != nil {
		return nil, err
	}
	track := lineUserTrackAdopted
	configSHA := ""
	if ln.Managed {
		track = lineUserTrackManaged
		planned := vpnUserWithPlannedBinding(u, ln.LineHashID, op)
		_, _, artifact, err := s.renderProxyCoreArtifactWithVpnUser(ln.NodeID, &planned)
		if err != nil {
			return nil, fmt.Errorf("render managed line-user plan: %w", err)
		}
		configSHA = artifact.ConfigSHA256
	}
	summary := fmt.Sprintf("sb user %s %s on node %s (user %s as %s, credential sha %s…)",
		op, ln.Tag, ln.NodeID, u.Email, name, sha[:12])
	if track == lineUserTrackManaged {
		summary = fmt.Sprintf("render full sing-box config for %s on node %s (%s user %s as %s, config sha %s…)",
			ln.Tag, ln.NodeID, op, u.Email, name, configSHA[:12])
	}
	plan := lineUserPlan{
		Op: op, Track: track, NodeID: ln.NodeID, Line: ln.Tag, LineHashID: ln.LineHashID, LineUUID: ln.LineUUID,
		UserID: u.ID, UserName: name, Protocol: ln.Type, CredentialSHA256: sha,
		ConfigSHA256: configSHA,
		Summary:      summary,
	}
	planJSON, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	approval := model.Approval{
		ID:            id.New("approval"),
		NodeID:        ln.NodeID,
		Plugin:        singBoxLineUserPlugin,
		Action:        lineUserActionPrefix + sha,
		Plan:          string(planJSON),
		Status:        model.ApprovalPending,
		ActorID:       ctxPrincipal.ActorID,
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
		PluginVersion: "design-15", Service: vpnCoreUsersAdminService, Method: "apply_" + op,
		RequestSHA256: lineUserRequestSHA(u.ID, ln.LineHashID), Targets: []string{ln.NodeID},
	}
	if configSHA != "" {
		approval.ArtifactDigest = configSHA
	} else {
		approval.ArtifactDigest = sha
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
func (s *Server) validateLineUserApproval(approval model.Approval) (lineUserPlan, VpnUser, Line, lineUserCredentialPayload, *proxycore.Artifact, error) {
	var zeroPlan lineUserPlan
	var zeroUser VpnUser
	var zeroLine Line
	var zeroPayload lineUserCredentialPayload
	if approval.Plugin != singBoxLineUserPlugin || approval.PluginVersion != "design-15" || approval.Service != vpnCoreUsersAdminService {
		return zeroPlan, zeroUser, zeroLine, zeroPayload, nil, errors.New("typed approval plugin/service binding is invalid")
	}
	if !strings.HasPrefix(approval.Method, "apply_") || len(approval.Targets) != 1 || approval.Targets[0] != approval.NodeID {
		return zeroPlan, zeroUser, zeroLine, zeroPayload, nil, errors.New("typed approval method/target binding is invalid")
	}
	if !strings.HasPrefix(approval.Action, lineUserActionPrefix) {
		return zeroPlan, zeroUser, zeroLine, zeroPayload, nil, fmt.Errorf("invalid approval action %q", approval.Action)
	}
	var plan lineUserPlan
	if err := json.Unmarshal([]byte(approval.Plan), &plan); err != nil {
		return zeroPlan, zeroUser, zeroLine, zeroPayload, nil, fmt.Errorf("invalid approval plan: %w", err)
	}
	if approval.Method != "apply_"+plan.Op || approval.RequestSHA256 != lineUserRequestSHA(plan.UserID, plan.LineHashID) {
		return zeroPlan, zeroUser, zeroLine, zeroPayload, nil, errors.New("typed approval method/request binding changed; re-plan")
	}
	if plan.NodeID != approval.NodeID {
		return zeroPlan, zeroUser, zeroLine, zeroPayload, nil, errors.New("approval node changed; re-plan")
	}
	user, ok := s.getVpnUser(plan.UserID)
	if !ok {
		return zeroPlan, zeroUser, zeroLine, zeroPayload, nil, fmt.Errorf("user %q no longer exists; re-plan", plan.UserID)
	}
	line, err := s.resolveLineUserTarget(plan.LineHashID)
	if err != nil {
		return zeroPlan, zeroUser, zeroLine, zeroPayload, nil, fmt.Errorf("resolve current line: %w; re-plan", err)
	}
	track := lineUserTrackAdopted
	if line.Managed {
		track = lineUserTrackManaged
	}
	if plan.Track != track || plan.NodeID != line.NodeID || plan.Line != line.Tag || plan.LineUUID != line.LineUUID || plan.Protocol != line.Type || plan.UserName != userLineName(user.ID, line.LineUUID) {
		return zeroPlan, zeroUser, zeroLine, zeroPayload, nil, errors.New("line identity, track, tag, UUID, or protocol changed; re-plan")
	}
	bound := vpnUserHasEnabledBinding(user, line.LineHashID)
	if (plan.Op == lineUserOpAdd && bound) || ((plan.Op == lineUserOpUpdate || plan.Op == lineUserOpRemove) && !bound) {
		return zeroPlan, zeroUser, zeroLine, zeroPayload, nil, errors.New("line binding changed since planning; re-plan")
	}
	payload, err := lineUserCredential(user, plan.Protocol, plan.UserName)
	if err != nil {
		return zeroPlan, zeroUser, zeroLine, zeroPayload, nil, fmt.Errorf("re-derive credential: %w; re-plan", err)
	}
	sha, err := lineUserCredentialSHA(payload)
	if err != nil || sha != plan.CredentialSHA256 || sha != strings.TrimPrefix(approval.Action, lineUserActionPrefix) {
		return zeroPlan, zeroUser, zeroLine, zeroPayload, nil, errors.New("credential changed since approval; re-plan")
	}
	if track == lineUserTrackManaged {
		planned := vpnUserWithPlannedBinding(user, line.LineHashID, plan.Op)
		_, _, artifact, err := s.renderProxyCoreArtifactWithVpnUser(line.NodeID, &planned)
		if err != nil {
			return zeroPlan, zeroUser, zeroLine, zeroPayload, nil, fmt.Errorf("render current managed config: %w", err)
		}
		if plan.ConfigSHA256 != artifact.ConfigSHA256 || approval.ArtifactDigest != artifact.ConfigSHA256 {
			return zeroPlan, zeroUser, zeroLine, zeroPayload, nil, errors.New("managed config changed since approval; re-plan")
		}
		return plan, user, line, payload, &artifact, nil
	}
	if plan.ConfigSHA256 != "" || approval.ArtifactDigest != sha {
		return zeroPlan, zeroUser, zeroLine, zeroPayload, nil, errors.New("adopted artifact binding changed; re-plan")
	}
	return plan, user, line, payload, nil, nil
}

func (s *Server) lineUserApplyScript(approval model.Approval) string {
	fail := func(err error) string {
		return "set -e\n" +
			"echo " + shellQuote("lattice lineuser: "+err.Error()) + " >&2\n" +
			"exit 1\n"
	}
	plan, _, _, payload, artifact, err := s.validateLineUserApproval(approval)
	if err != nil {
		return fail(err)
	}
	if artifact != nil {
		return proxyCoreApplyScript(*artifact)
	}
	var argv string
	switch plan.Op {
	case lineUserOpAdd, lineUserOpUpdate:
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			return fail(fmt.Errorf("encode payload: %v", err))
		}
		argv = " --json user add " + shellQuote(plan.Line) + " " + shellQuote(string(payloadJSON))
	case lineUserOpRemove:
		// The adopted script contract deletes by the stable users[].name join
		// key. Sending the credential object here is both the wrong argv shape
		// and needlessly exposes write-only credential material to the task.
		argv = " user del " + shellQuote(plan.Line) + " " + shellQuote(plan.UserName)
	default:
		return fail(fmt.Errorf("invalid line-user op %q", plan.Op))
	}
	return "set -e\n" +
		"SB_BIN=\"${LATTICE_SINGBOX_BIN:-sb}\"\n" +
		"command -v \"$SB_BIN\" >/dev/null 2>&1 || { echo " + shellQuote("lattice lineuser: sb binary not found") + " >&2; exit 1; }\n" +
		"\"$SB_BIN\"" + argv + "\n"
}

// handleLineUserTaskResult reconciles a line-user approval once the agent
// reports back. A failed task leaves the approval in place for re-approval. A
// successful add creates the enabled binding; a successful remove drops it.
// Reconciliation is persisted before the approval is marked applied so the
// control plane cannot report success while exposing stale subscription state.
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
	plan, u, _, _, artifact, err := s.validateLineUserApproval(approval)
	if err != nil {
		reason := "successful task belongs to stale line-user plan; runtime rediscovery required"
		if rejectErr := s.rejectApprovalWithReason(approval, reason); rejectErr != nil {
			return fmt.Errorf("reject stale successful line-user task: %v; validation: %w", rejectErr, err)
		}
		probeID, probeErr := s.queueLineUserRediscovery(approval.NodeID)
		staleMetadata := map[string]string{"approval_id": approval.ID, "task_id": task.ID, "validation_error": err.Error()}
		if probeErr == nil {
			staleMetadata["rediscovery_task_id"] = probeID
		}
		s.recordRequestAudit(r, model.AuditEvent{
			ID: id.New("audit"), NodeID: approval.NodeID, Action: "vpnuser.line.stale_result",
			Decision: "deny", Reason: reason, Metadata: staleMetadata,
		})
		return nil
	}
	changed := false
	if artifact != nil && u.MigratedFromProxyUser != "" {
		legacyID := u.MigratedFromProxyUser
		if err := s.store.DeleteProxyUser(legacyID); err != nil {
			return fmt.Errorf("detach managed user from legacy render substrate %q: %w", legacyID, err)
		}
		u.MigratedFromProxyUser = ""
		changed = true
	}
	switch plan.Op {
	case lineUserOpAdd, lineUserOpUpdate:
		found := false
		for i := range u.Bindings {
			if u.Bindings[i].LineHashID == plan.LineHashID {
				if !u.Bindings[i].Enabled {
					u.Bindings[i].Enabled = true
					changed = true
				}
				found = true
				break
			}
		}
		if !found {
			u.Bindings = append(u.Bindings, LineBinding{LineHashID: plan.LineHashID, Enabled: true})
			changed = true
		}
	case lineUserOpRemove:
		kept := u.Bindings[:0]
		for _, b := range u.Bindings {
			if b.LineHashID != plan.LineHashID {
				kept = append(kept, b)
			}
		}
		changed = len(kept) != len(u.Bindings)
		u.Bindings = kept
	default:
		return fmt.Errorf("reconcile line-user approval: invalid op %q", plan.Op)
	}
	if changed {
		u.UpdatedAt = s.now()
		if err := s.putVpnUser(u); err != nil {
			return fmt.Errorf("persist applied line-user binding: %w", err)
		}
	}
	if artifact != nil {
		profile, ok := s.store.ProxyNodeProfile(plan.NodeID)
		if !ok {
			return fmt.Errorf("managed line-user profile %q disappeared", plan.NodeID)
		}
		profile.AppliedSHA256 = artifact.ConfigSHA256
		profile.LastApplyAt = result.FinishedAt
		if profile.LastApplyAt.IsZero() {
			profile.LastApplyAt = s.now()
		}
		profile.LastError = ""
		if err := s.store.UpsertProxyNodeProfile(profile); err != nil {
			return fmt.Errorf("persist managed line-user applied config: %w", err)
		}
	}
	approval.Status = model.ApprovalApplied
	approval.Reason = ""
	approval.UpdatedAt = time.Now().UTC()
	if err := s.store.UpsertApproval(approval); err != nil {
		return fmt.Errorf("mark line-user approval applied: %w", err)
	}
	probeTaskID, probeErr := s.queueLineUserRediscovery(plan.NodeID)
	if probeErr != nil {
		approval.Reason = "runtime applied; bounded rediscovery queue failed"
		_ = s.store.UpsertApproval(approval)
		metadata["rediscovery"] = "queue_failed"
	} else {
		metadata["rediscovery_task_id"] = probeTaskID
	}
	s.invalidateLineReadModel()
	if artifact != nil {
		s.refreshProxyDriftFor(plan.NodeID, s.now())
		metadata["drift_refresh"] = "completed"
	}
	s.recordRequestAudit(r, model.AuditEvent{
		ID: id.New("audit"), NodeID: approval.NodeID, Action: "vpnuser.line.applied",
		Decision: "allow", Metadata: metadata,
	})
	// An applied line-user change alters what nodes should serve: re-arm the
	// Sub-Store auto-sync just like the direct mutations do (design-15 §7).
	s.triggerVPNCoreMutation()
	return nil
}

func (s *Server) queueLineUserRediscovery(nodeID string) (string, error) {
	for _, task := range s.store.Tasks() {
		if isSingBoxProbeTask(task) && containsString(task.Targets, nodeID) &&
			(task.Status == model.TaskQueued || task.Status == model.TaskLeased) {
			return task.ID, nil
		}
	}
	task, err := s.queueSingBoxProbeTask(principal{Principal: rbac.Principal{ActorID: "system"}}, nodeID)
	if err != nil {
		return "", err
	}
	return task.ID, nil
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

// ── usage name reversal (design-15 §8) ───────────────────────────────────────

// userLineNameTarget identifies the accounting row a u_<hash> counter maps to.
type userLineNameTarget struct {
	LineHashID  string
	VpnUserID   string
	ProxyUserID string
}

// userLineNameIndex recomputes the design-15 §5 on-box names for every
// (identity, line) pair and maps them back to (line_hash_id, proxy user id) —
// the server's half of the per-user stats join. Native VpnUsers are indexed as
// known identities even though the legacy ProxyUsageSnapshot has no safe key
// for them yet; foldUserLineUsage handles that case as an explicit degradation.
func (s *Server) userLineNameIndex() map[string]userLineNameTarget {
	index := map[string]userLineNameTarget{}
	for _, u := range s.listVpnUsers() {
		accountingID := strings.TrimSpace(u.MigratedFromProxyUser)
		if accountingID == "" {
			accountingID = u.ID
		}
		for _, b := range u.Bindings {
			if !b.Enabled {
				continue
			}
			lineUUID := ""
			if e, ok := s.store.KVEntry(lineUUIDKVBucket, b.LineHashID); ok {
				lineUUID = strings.TrimSpace(e.Value)
			}
			if lineUUID == "" {
				continue
			}
			index[userLineName(u.ID, lineUUID)] = userLineNameTarget{LineHashID: b.LineHashID, VpnUserID: u.ID, ProxyUserID: accountingID}
		}
	}
	return index
}

// foldUserLineUsage rewrites a singbox-stats snapshot's on-box u_<hash> keys
// into the server's accounting shape: the per-user total joins the proxy user
// id (so the normal monotonic-diff path advances it) and the line-scoped
// granularity lands in line_user_bytes. Unmatched names stay untouched and
// degrade to "ignored" — never zero-filled traffic (design-15 §8).
func foldUserLineUsage(snapshot *model.ProxyUsageSnapshot, index map[string]userLineNameTarget) {
	if len(index) == 0 || len(snapshot.UserBytes) == 0 {
		return
	}
	for name, value := range snapshot.UserBytes {
		target, ok := index[name]
		if !ok {
			continue
		}
		delete(snapshot.UserBytes, name)
		snapshot.UserBytes[target.ProxyUserID] += value
		if snapshot.LineUserBytes == nil {
			snapshot.LineUserBytes = map[string]map[string]int64{}
		}
		bucket := snapshot.LineUserBytes[target.LineHashID]
		if bucket == nil {
			bucket = map[string]int64{}
			snapshot.LineUserBytes[target.LineHashID] = bucket
		}
		bucket[target.ProxyUserID] += value
	}
}
