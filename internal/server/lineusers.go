package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
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
	// Omitted is renderOmissions for a managed plan's render: the users the
	// config already leaves out by policy, each as "label (status)".
	Omitted []string `json:"omitted,omitempty"`
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
		// The quota is server-side policy, not on-box state: plan_add and
		// plan_update accept it so one operator action allocates the line and
		// sets the allowance, and it is written before the approval is queued
		// because nothing on the node depends on it.
		QuotaBytes    *int64  `json:"quota_bytes"`
		QuotaPeriod   *string `json:"quota_period"`
		QuotaResetDay *int    `json:"quota_reset_day"`
	}
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("vpn-core/users-admin plan_%s: invalid request: %w", op, err)
	}
	u, ok := s.getVpnUser(strings.TrimSpace(req.UserID))
	if !ok {
		if op == lineUserOpRemove {
			return s.deletedUserLineRemovePlan(ctxPrincipal, strings.TrimSpace(req.UserID), strings.TrimSpace(req.LineHashID))
		}
		return nil, fmt.Errorf("vpn-core/users-admin plan_%s: user %q not found", op, req.UserID)
	}
	if (op == lineUserOpAdd || op == lineUserOpUpdate) && !u.Enabled {
		return nil, fmt.Errorf("user %q is disabled", u.ID)
	}
	quotaChanged := false
	if op != lineUserOpRemove && (req.QuotaBytes != nil || req.QuotaPeriod != nil || req.QuotaResetDay != nil) {
		if req.QuotaBytes != nil {
			if *req.QuotaBytes < 0 {
				return nil, errors.New("quota_bytes cannot be negative")
			}
			u.QuotaBytes = *req.QuotaBytes
		}
		if err := applyQuotaPeriod(&u, req.QuotaPeriod, req.QuotaResetDay); err != nil {
			return nil, err
		}
		quotaChanged = true
	}
	// Only plan_add is held to the policy. plan_update re-sends the current
	// credential for a user already bound to the line, so it adds nobody,
	// and it is how a leaked credential of an expired or over-quota user is
	// rotated on an adopted line, where Lattice does not remove the user.
	if op == lineUserOpAdd {
		if err := s.requireVpnUserWithinPolicy(u, s.now()); err != nil {
			return nil, err
		}
	}
	if quotaChanged {
		u.UpdatedAt = s.now()
		if err := s.putVpnUser(u); err != nil {
			return nil, err
		}
	}
	ln, err := s.resolveLineUserTarget(strings.TrimSpace(req.LineHashID))
	if err != nil {
		return nil, err
	}
	bound := vpnUserHasEnabledBinding(u, ln.LineHashID)
	if op == lineUserOpAdd && bound {
		return nil, fmt.Errorf("user %q is already bound to line %q; plan_update instead", u.ID, ln.LineHashID)
	}
	// A remove on an adopted line does not need a binding. unbind drops only
	// the server's record, so a user that plan_add put on the node keeps its
	// credential there after an unbind, and plan_remove is the only way
	// Lattice can take it off. sb user del names only this user's derived
	// name, so the plan cannot touch anyone else. A managed line's render
	// already leaves an unbound user out, so a remove there would change
	// nothing and still needs the binding.
	if (op == lineUserOpUpdate || (op == lineUserOpRemove && ln.Managed)) && !bound {
		return nil, fmt.Errorf("user %q is not bound to line %q", u.ID, ln.LineHashID)
	}
	// Without a binding, the approvals have to show Lattice put the user on
	// this line, or the removal would run sb user del for a name that was
	// never there.
	if op == lineUserOpRemove && !bound {
		if err := s.requireLineUserOnLine(u.ID, ln.LineHashID); err != nil {
			return nil, err
		}
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
	var omitted []string
	if ln.Managed {
		track = lineUserTrackManaged
		now := s.now()
		planned := vpnUserWithPlannedBinding(u, ln.LineHashID, op)
		users := s.proxyUsersForManagedRender(&planned, now)
		_, profile, artifact, err := s.renderProxyCoreArtifactForUsers(ln.NodeID, users, now)
		if err != nil {
			return nil, fmt.Errorf("render managed line-user plan: %w", err)
		}
		configSHA = artifact.ConfigSHA256
		omitted = s.renderOmissions(profile, users, now)
	}
	summary := fmt.Sprintf("sb user %s %s on node %s (user %s as %s, credential sha %s…)",
		op, ln.Tag, ln.NodeID, u.Email, name, sha[:12])
	if op == lineUserOpRemove && !bound {
		summary += "; Lattice holds no binding for this user on the line"
	}
	if track == lineUserTrackManaged {
		summary = fmt.Sprintf("render full sing-box config for %s on node %s (%s user %s as %s, config sha %s…)",
			ln.Tag, ln.NodeID, op, u.Email, name, configSHA[:12])
		if len(omitted) > 0 {
			summary += "; already left out by policy: " + omittedSummary(omitted)
		}
	}
	plan := lineUserPlan{
		Op: op, Track: track, NodeID: ln.NodeID, Line: ln.Tag, LineHashID: ln.LineHashID, LineUUID: ln.LineUUID,
		UserID: u.ID, UserName: name, Protocol: ln.Type, CredentialSHA256: sha,
		ConfigSHA256: configSHA,
		Summary:      summary,
		Omitted:      omitted,
	}
	return s.fileLineUserPlan(ctxPrincipal, plan, map[string]string{"quota_changed": strconv.FormatBool(quotaChanged)})
}

// deletedUserLineRemovePlan files plan_remove for a user that no longer
// exists. Deleting a user does not take its credential off an adopted line,
// where Lattice added it with sb user add, and plan_remove used to need the
// user record, so nothing in Lattice could take it off. sb user del needs
// only the line's tag and the on-box name, and the name is derived from the
// user id and the line UUID alone (userLineName), so the plan removes that
// one credential and nothing else.
//
// The id comes from the operator with no record left to check it against,
// so it is held to two things before it is filed or echoed. It must have the
// shape Lattice mints (vpnUserIDRe), and the approvals, which are never
// pruned, must show an applied plan that put this user on this line with no
// applied removal since (requireLineUserOnLine). A typo, or an id that never
// reached the line, is refused here rather than filed as a task that fails.
// The node reports a user count but no names, so this is the closest
// Lattice can come to confirming the node holds the name. A managed line
// needs no such plan: its render already leaves a deleted user out, and the
// line's next config apply removes it.
func (s *Server) deletedUserLineRemovePlan(ctxPrincipal principal, userID, lineHashID string) ([]byte, error) {
	if !vpnUserIDRe.MatchString(userID) {
		return nil, errors.New("vpn-core/users-admin plan_remove: user_id is neither an existing user nor a VpnUser id Lattice mints (vpnuser_ and 16 base32 characters, or vu_ and a proxy user id)")
	}
	ln, err := s.resolveLineUserTarget(lineHashID)
	if err != nil {
		return nil, err
	}
	if ln.Managed {
		return nil, fmt.Errorf("user %q no longer exists, and managed line %q already leaves it out of its render; apply the line's config to remove it", userID, ln.LineHashID)
	}
	if err := s.requireLineUserOnLine(userID, ln.LineHashID); err != nil {
		return nil, err
	}
	name := userLineName(userID, ln.LineUUID)
	sha, err := lineUserCredentialSHA(lineUserCredentialPayload{Name: name})
	if err != nil {
		return nil, err
	}
	plan := lineUserPlan{
		Op: lineUserOpRemove, Track: lineUserTrackAdopted, NodeID: ln.NodeID, Line: ln.Tag,
		LineHashID: ln.LineHashID, LineUUID: ln.LineUUID,
		UserID: userID, UserName: name, Protocol: ln.Type, CredentialSHA256: sha,
		Summary: fmt.Sprintf("sb user remove %s on node %s (deleted user %s as %s, credential sha %s…)",
			ln.Tag, ln.NodeID, userID, name, sha[:12]),
	}
	return s.fileLineUserPlan(ctxPrincipal, plan, map[string]string{"user_deleted": "true"})
}

// vpnUserIDRe matches the VpnUser ids Lattice mints: id.New("vpnuser"),
// which is "vpnuser_" and 16 lowercase base32 characters (23 digits on its
// clock fallback), and the ProxyUser migration's "vu_" and a proxy user id
// (proxyIDRe, at most 128 characters). Nothing else creates a VpnUser id, and
// the character set keeps an id safe to echo in a summary or an audit row.
var vpnUserIDRe = regexp.MustCompile(`^(?:vpnuser_(?:[a-z2-7]{16}|[0-9]{23})|vu_[A-Za-z0-9][A-Za-z0-9_.:-]{0,127})$`)

// requireLineUserOnLine refuses a removal Lattice has no grounds for: it
// needs an applied line-user plan that put userID on lineHashID (an add or
// an update) with no applied removal after it. Approvals are never pruned,
// so this history is complete. A removal of a user Lattice still binds to
// the line does not ask for it; the binding is the record.
func (s *Server) requireLineUserOnLine(userID, lineHashID string) error {
	requestSHA := lineUserRequestSHA(userID, lineHashID)
	lastOp := ""
	var lastAt time.Time
	for _, a := range s.store.Approvals() {
		if a.Plugin != singBoxLineUserPlugin || a.Status != model.ApprovalApplied || a.RequestSHA256 != requestSHA {
			continue
		}
		var plan lineUserPlan
		if err := json.Unmarshal([]byte(a.Plan), &plan); err != nil || plan.UserID != userID || plan.LineHashID != lineHashID {
			continue
		}
		if lastOp == "" || a.UpdatedAt.After(lastAt) {
			lastOp, lastAt = plan.Op, a.UpdatedAt
		}
	}
	switch lastOp {
	case lineUserOpAdd, lineUserOpUpdate:
		return nil
	case lineUserOpRemove:
		return fmt.Errorf("an applied plan already removed user %q from line %q, and none has added it since; nothing is left to remove", userID, lineHashID)
	default:
		return fmt.Errorf("no applied plan ever put user %q on line %q, so Lattice has nothing to remove there; check the user id and the line", userID, lineHashID)
	}
}

// openLineUserRemove finds a removal of userID from lineHashID that can still
// act, and says why: pending, so an operator can still approve or reject it,
// or approved with a live task (queued or leased) for it. The "not bound"
// refusal used to stop a second removal once the first applied; a removal no
// longer needs a binding, so a second one filed while the first can still
// act is refused here. An applied removal is covered by requireLineUserOnLine.
//
// An approved removal with no live task is not open. It can never be decided
// again (reject acts only on pending, approve is a no-op past pending, and
// dismiss refuses line-user plans), so counting it would block every later
// removal of the user from the line for good, a bound user's included. That
// covers a cancelled task, and a task that finished with a result nobody
// recorded. A task that stays queued because its node never reports is live
// until an operator cancels it.
func (s *Server) openLineUserRemove(userID, lineHashID string) (string, bool) {
	requestSHA := lineUserRequestSHA(userID, lineHashID)
	var live map[string]model.Task
	for _, a := range s.store.Approvals() {
		if a.Plugin != singBoxLineUserPlugin || a.Method != "apply_"+lineUserOpRemove || a.RequestSHA256 != requestSHA {
			continue
		}
		switch a.Status {
		case model.ApprovalPending:
			return fmt.Sprintf("pending as approval %s; approve or reject it before filing another", a.ID), true
		case model.ApprovalApproved:
			if live == nil {
				live = map[string]model.Task{}
				for _, task := range s.store.Tasks() {
					if task.ApprovalID != "" && (task.Status == model.TaskQueued || task.Status == model.TaskLeased) {
						live[task.ApprovalID] = task
					}
				}
			}
			if task, ok := live[a.ID]; ok {
				return fmt.Sprintf("approved as approval %s, and its task %s is %s; wait for its result, or cancel the task while it is queued, before filing another", a.ID, task.ID, task.Status), true
			}
		}
	}
	return "", false
}

// fileLineUserPlan stores plan as a pending line-user approval, records the
// plan audit event with extra metadata, and answers the approval.
func (s *Server) fileLineUserPlan(ctxPrincipal principal, plan lineUserPlan, extra map[string]string) ([]byte, error) {
	// No lock covers the check and the store write below, and plan filing has
	// none to reuse, so two concurrent removals of the same user from the same
	// line can both pass it. The cost is bounded: both name the same derived
	// on-box user, so the second can remove nothing the first did not, and at
	// worst its task fails and returns it to pending for an operator to reject.
	if plan.Op == lineUserOpRemove {
		if open, ok := s.openLineUserRemove(plan.UserID, plan.LineHashID); ok {
			return nil, fmt.Errorf("a removal of user %q from line %q is already %s",
				plan.UserID, plan.LineHashID, open)
		}
	}
	planJSON, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	approval := model.Approval{
		ID:            id.New("approval"),
		NodeID:        plan.NodeID,
		Plugin:        singBoxLineUserPlugin,
		Action:        lineUserActionPrefix + plan.CredentialSHA256,
		Plan:          string(planJSON),
		Status:        model.ApprovalPending,
		ActorID:       ctxPrincipal.ActorID,
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
		PluginVersion: "design-15", Service: vpnCoreUsersAdminService, Method: "apply_" + plan.Op,
		RequestSHA256: lineUserRequestSHA(plan.UserID, plan.LineHashID), Targets: []string{plan.NodeID},
	}
	if plan.ConfigSHA256 != "" {
		approval.ArtifactDigest = plan.ConfigSHA256
	} else {
		approval.ArtifactDigest = plan.CredentialSHA256
	}
	// The plugin-RPC dispatch layer carries no request context; policy
	// evaluation here is synchronous and not request-bound.
	if _, err := s.submitApproval(context.Background(), approval); err != nil {
		return nil, err
	}
	metadata := map[string]string{
		"approval_id": approval.ID, "op": plan.Op, "user_id": plan.UserID,
		"line_hash_id": plan.LineHashID, "credential_sha256": plan.CredentialSHA256,
	}
	for k, v := range extra {
		metadata[k] = v
	}
	s.recordPrincipalAudit(ctxPrincipal, model.AuditEvent{
		ID: id.New("audit"), NodeID: plan.NodeID, Action: "vpnuser.line.plan", Scope: "proxy:admin",
		Metadata: metadata,
	})
	return json.Marshal(struct {
		Approval model.Approval `json:"approval"`
	}{Approval: approval})
}

// omittedSummary names the first five omitted users for a one-line summary
// and counts the rest; the plan's Omitted field carries every one.
func omittedSummary(omitted []string) string {
	const shown = 5
	if len(omitted) <= shown {
		return strings.Join(omitted, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(omitted[:shown], ", "), len(omitted)-shown)
}

// requireVpnUserWithinPolicy refuses a plan_add, or a managed-line rollout,
// for an identity that is expired or over its quota at now, the way
// plan_add refuses a disabled one. Such a plan would grant what the policy
// denies: on a managed line the render leaves the identity out while the
// task result marks the binding enabled, and on an adopted line sb would add
// a user its own alerts call expired or over quota. The quota is read with
// the request's changes applied, so raising it in the same call is enough.
func (s *Server) requireVpnUserWithinPolicy(u VpnUser, now time.Time) error {
	if reason, remedy := s.vpnUserPolicyRefusal(u, now); reason != "" {
		return fmt.Errorf("%s; %s before planning a line", reason, remedy)
	}
	return nil
}

// vpnUserPolicyRefusal says why the policy denies u a line at now, and what
// the operator can do about it. Both are empty when the policy allows it.
// The usage and the quota are written in the quota's unit, so they compare.
func (s *Server) vpnUserPolicyRefusal(u VpnUser, now time.Time) (reason, remedy string) {
	policy := s.vpnUserPolicyRow(u, now)
	switch policy.Status {
	case model.ProxyUserStatusExpired:
		return fmt.Sprintf("user %q expired on %s", u.ID, dateOnlyUTC(u.ExpiresAt).Format("2006-01-02")), "renew it"
	case model.ProxyUserStatusOverQuota:
		remedy = "raise the quota"
		if u.QuotaPeriod == vpnQuotaPeriodMonthly {
			remedy = "raise the quota or wait for the next period"
		}
		return fmt.Sprintf("user %q has used %s of its %s quota", u.ID,
			formatProxyBytesIn(policy.UsedBytes, policy.TrafficLimitBytes),
			formatProxyBytes(policy.TrafficLimitBytes)), remedy
	}
	return "", ""
}

// lineUserGrantRefusal re-checks the gates vpnUserLinePlan applied when the
// plan was made, against the user as it is now: a disabled user may not be
// added or updated, and an expired or over-quota user may not be added. An
// approval can wait for days, and the adopted track has no config hash to
// catch such a change, so without this sb would add a user its own alerts
// deny. On the managed track the render would leave the user out and the
// hash would fail too; this says why. The plan itself stays valid: once the
// user is enabled, renewed or given room, the same approval can be approved.
func (s *Server) lineUserGrantRefusal(op string, u VpnUser) error {
	if op != lineUserOpAdd && op != lineUserOpUpdate {
		return nil
	}
	if !u.Enabled {
		return fmt.Errorf("user %q is disabled, so this plan would grant a disabled user; enable it before approving", u.ID)
	}
	if op != lineUserOpAdd {
		return nil
	}
	if reason, remedy := s.vpnUserPolicyRefusal(u, s.now()); reason != "" {
		return fmt.Errorf("%s, so this plan would add a user its policy denies; %s before approving", reason, remedy)
	}
	return nil
}

// validateLineUserApproval checks that an approval still describes the
// current user, line and credential, failing closed when the credential bytes
// no longer match the approved hash, so a script never embeds a credential
// that was not exactly the reviewed one. checkGrant also re-runs the plan-time
// gates (lineUserGrantRefusal); it is set when the approval is approved and
// when its script is rendered, the two points before anything reaches the
// node.
func (s *Server) validateLineUserApproval(approval model.Approval, checkGrant bool) (lineUserPlan, VpnUser, Line, lineUserCredentialPayload, *proxycore.Artifact, error) {
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
		if plan.Op == lineUserOpRemove {
			return s.validateDeletedUserLineRemove(approval, plan)
		}
		return zeroPlan, zeroUser, zeroLine, zeroPayload, nil, fmt.Errorf("user %q no longer exists; re-plan", plan.UserID)
	}
	if checkGrant {
		if err := s.lineUserGrantRefusal(plan.Op, user); err != nil {
			return zeroPlan, zeroUser, zeroLine, zeroPayload, nil, err
		}
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
	// An adopted remove needs no binding, for the reason vpnUserLinePlan
	// gives; one filed while the user was bound still completes after an
	// unbind.
	bound := vpnUserHasEnabledBinding(user, line.LineHashID)
	removeNeedsBinding := track == lineUserTrackManaged
	if (plan.Op == lineUserOpAdd && bound) || (plan.Op == lineUserOpUpdate && !bound) ||
		(plan.Op == lineUserOpRemove && removeNeedsBinding && !bound) {
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

// validateDeletedUserLineRemove checks an adopted plan_remove whose user no
// longer exists, whether it was filed before the deletion or after it
// (deletedUserLineRemovePlan). Its script needs only the line's tag and the
// on-box name, so this checks those against the line as it is now and
// against the plan's own bindings, and skips the credential and binding
// checks, which need the user record. A managed remove for a deleted user
// stays refused: the render already leaves the user out.
func (s *Server) validateDeletedUserLineRemove(approval model.Approval, plan lineUserPlan) (lineUserPlan, VpnUser, Line, lineUserCredentialPayload, *proxycore.Artifact, error) {
	fail := func(err error) (lineUserPlan, VpnUser, Line, lineUserCredentialPayload, *proxycore.Artifact, error) {
		return lineUserPlan{}, VpnUser{}, Line{}, lineUserCredentialPayload{}, nil, err
	}
	line, err := s.resolveLineUserTarget(plan.LineHashID)
	if err != nil {
		return fail(fmt.Errorf("resolve current line: %w; re-plan", err))
	}
	if line.Managed || plan.Track != lineUserTrackAdopted {
		return fail(fmt.Errorf("user %q no longer exists; re-plan", plan.UserID))
	}
	if plan.NodeID != line.NodeID || plan.Line != line.Tag || plan.LineUUID != line.LineUUID ||
		plan.Protocol != line.Type || plan.UserName != userLineName(plan.UserID, line.LineUUID) {
		return fail(errors.New("line identity, track, tag, UUID, or protocol changed; re-plan"))
	}
	if plan.ConfigSHA256 != "" || plan.CredentialSHA256 == "" || approval.ArtifactDigest != plan.CredentialSHA256 ||
		strings.TrimPrefix(approval.Action, lineUserActionPrefix) != plan.CredentialSHA256 {
		return fail(errors.New("adopted artifact binding changed; re-plan"))
	}
	return plan, VpnUser{}, line, lineUserCredentialPayload{Name: plan.UserName}, nil, nil
}

// lineUserApplyScript renders the on-box `sb user add|del` invocation for an
// approved plan, re-deriving the credential from the write-only store.
func (s *Server) lineUserApplyScript(approval model.Approval) string {
	fail := func(err error) string {
		return "set -e\n" +
			"echo " + shellQuote("lattice lineuser: "+err.Error()) + " >&2\n" +
			"exit 1\n"
	}
	plan, _, _, payload, artifact, err := s.validateLineUserApproval(approval, true)
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
// reports back. A failed task returns the approval to pending with the failure
// reason (re-approval retries the same plan). A successful add creates the
// enabled binding; a successful remove drops it.
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
		// Execution failure is not a decision: return the approval to pending
		// with the reason so the operator can fix the cause and re-approve.
		// Leaving it approved stranded the plan — the approve endpoint is a
		// deliberate no-op on non-pending approvals.
		approval.Status = model.ApprovalPending
		approval.Reason = "execution failed: " + reason
		approval.UpdatedAt = time.Now().UTC()
		if err := s.store.UpsertApproval(approval); err != nil {
			return fmt.Errorf("return failed line-user approval to pending: %w", err)
		}
		s.recordRequestAudit(r, model.AuditEvent{
			ID: id.New("audit"), NodeID: approval.NodeID, Action: "vpnuser.line.failed",
			Decision: "deny", Reason: reason, Metadata: metadata,
		})
		return nil
	}
	// checkGrant is off here. The task has already run sb on the node, so
	// the result records what the node now holds; refusing to record it
	// because the user crossed its policy during the run would leave a user
	// on the node with no binding behind it. The policy's alerts cover that
	// user from here on.
	plan, u, _, _, artifact, err := s.validateLineUserApproval(approval, false)
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
