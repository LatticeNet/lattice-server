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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/proxycore"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
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
	// lineUserOpSuspend and lineUserOpResume are the suspension reconciler's
	// ops (adopted-suspend P4): take the identity's credential off an adopted
	// line and put the same credential back, keeping the binding. No plan
	// carries them yet; vpnUserLinePlan refuses them. reconcileLineUserBinding
	// already knows what each does to the binding, so the reconciler adds the
	// plans and scripts, not a second owner of the applied credential.
	lineUserOpSuspend = "suspend"
	lineUserOpResume  = "resume"

	lineUserTrackAdopted = "adopted"
	lineUserTrackManaged = "managed"

	// singBoxUserDelByNameCapability says a node's sb script removes a user
	// by a payload that carries its name alone: lr00rl/sing-box
	// v1.24.3-alpha.8 and later list user-del-by-name in `sb --json caps`.
	// The server learns no script capability any other way, so it is one of
	// the agent capabilities a heartbeat reports (agentCapabilities): an
	// agent that ran `sb --json caps` on its node reports each script cap
	// with an "sb:" prefix. Like the others it is live and fails closed: a
	// node that has not reported it since this server started is treated
	// as running alpha.7.
	singBoxUserDelByNameCapability = "sb:user-del-by-name"
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
	// Batch names the operator action that filed this plan with others, the
	// credential cutover (vpn_cutover.go). Empty for a plan filed alone.
	Batch string `json:"batch,omitempty"`
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
	return s.vpnUserLinePlanInBatch(ctxPrincipal, request, op, "")
}

// vpnUserLinePlanInBatch is vpnUserLinePlan for a plan filed as part of a
// batch: the plan, its summary and its audit name the batch.
func (s *Server) vpnUserLinePlanInBatch(ctxPrincipal principal, request []byte, op, batch string) ([]byte, error) {
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
	// plan_update re-sends the credential with sb user add, which would put a
	// suspended identity back on the node (adopted-suspend F10).
	if op == lineUserOpAdd || op == lineUserOpUpdate {
		if err := vpnUserOperatorSuspension(u, s.now()); err != nil {
			return nil, fmt.Errorf("%w; resume it before planning a line", err)
		}
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
	// Lattice can take it off. sb user del matches entries by name or by any
	// credential field, so lineUserRemovalRefusal below refuses a removal
	// that Lattice can see would also take another entry off the line. A
	// managed line's render already leaves an unbound user out, so a remove
	// there would change nothing and still needs the binding.
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
	if op == lineUserOpRemove && !ln.Managed {
		if err := s.lineUserRemovalRefusal(u.ID, ln, payload); err != nil {
			return nil, err
		}
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
	extra := map[string]string{"quota_changed": strconv.FormatBool(quotaChanged)}
	if batch != "" {
		summary = batch + ": " + summary
		extra["batch"] = batch
	}
	plan := lineUserPlan{
		Op: op, Track: track, NodeID: ln.NodeID, Line: ln.Tag, LineHashID: ln.LineHashID, LineUUID: ln.LineUUID,
		UserID: u.ID, UserName: name, Protocol: ln.Type, CredentialSHA256: sha,
		ConfigSHA256: configSHA,
		Summary:      summary,
		Omitted:      omitted,
		Batch:        batch,
	}
	return s.fileLineUserPlan(ctxPrincipal, plan, extra)
}

// deletedUserLineRemovePlan answers plan_remove for a user that no longer
// exists. Deleting a user does not take its credential off an adopted line,
// where Lattice added it with sb user add, and the delete is refused while
// Lattice's record still places the user there (vpnUserDeleteRefusal); a user
// gets here when it was deleted before that refusal existed, or while its
// line did not resolve. Deleting the user deleted the only copy of its
// credential, so the removal can carry the on-box name and nothing else.
//
// Whether the node can act on that depends on its script. lr00rl/sing-box
// alpha.7 (cmd_json_user) refuses a payload that carries no uuid or password
// with invalid_user, and a bare name with invalid_payload, so every task a102
// filed for such a removal failed on the node and went back to pending.
// alpha.8 removes the one entry with that name, refuses a name two entries
// share, and leaves an entry that only shares the credential. A node whose
// agent reports singBoxUserDelByNameCapability gets a plan whose payload is
// {"name": <on-box name>}, hashed like any other; any other node gets the
// refusal, with the reason, rather than a task that always fails.
//
// The id is still held to what a102 checked, so neither answer is filed for
// a user Lattice never put there: it must have the shape Lattice mints
// (vpnUserIDRe), the line must be adopted, and the approvals, which are never
// pruned, must show an applied plan that put this user on this line with no
// applied removal since (requireLineUserOnLine). A typo, or an id that never
// reached the line, gets the narrower refusal. A managed line needs no such
// plan: its render already leaves a deleted user out, and the line's next
// config apply removes it.
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
	if !s.agentHasCapability(ln.NodeID, singBoxUserDelByNameCapability) {
		return nil, deletedUserRemovalUnsupported(userID, ln)
	}
	name := userLineName(userID, ln.LineUUID)
	sha, err := lineUserCredentialSHA(lineUserCredentialPayload{Name: name})
	if err != nil {
		return nil, err
	}
	plan := lineUserPlan{
		Op: lineUserOpRemove, Track: lineUserTrackAdopted, NodeID: ln.NodeID, Line: ln.Tag, LineHashID: ln.LineHashID,
		LineUUID: ln.LineUUID, UserID: userID, UserName: name, Protocol: ln.Type, CredentialSHA256: sha,
		Summary: fmt.Sprintf("sb user remove %s on node %s by name alone (deleted user %s as %s, payload sha %s…); "+
			"Lattice no longer holds the credential, so an entry that shares it under another name stays on the line",
			ln.Tag, ln.NodeID, userID, name, sha[:12]),
	}
	return s.fileLineUserPlan(ctxPrincipal, plan, map[string]string{"by_name": "true"})
}

// deletedUserRemovalUnsupported is the refusal for removing a deleted user
// from an adopted line on a node that has not reported removing a user by
// name, at plan time and when an approval for it is approved or rendered.
func deletedUserRemovalUnsupported(userID string, ln Line) error {
	return fmt.Errorf("user %q no longer exists, so Lattice no longer holds the credential the node script needs to remove it: "+
		"node %s has not reported that its sb script removes a user by name alone (%s, from `sb --json caps` in lr00rl/sing-box v1.24.3-alpha.8 and later), "+
		"and alpha.7 matches entries by credential and refuses a name alone; on-box user %s stays on line %s until the node reports it",
		userID, ln.NodeID, singBoxUserDelByNameCapability, userLineName(userID, ln.LineUUID), ln.Tag)
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
	switch s.lineUserAppliedOps(lineHashID)[userID] {
	case lineUserOpAdd, lineUserOpUpdate:
		return nil
	case lineUserOpRemove:
		return fmt.Errorf("an applied plan already removed user %q from line %q, and none has added it since; nothing is left to remove", userID, lineHashID)
	default:
		return fmt.Errorf("no applied plan ever put user %q on line %q, so Lattice has nothing to remove there; check the user id and the line", userID, lineHashID)
	}
}

// lineUserAppliedOps returns, per user, the op of the last applied line-user
// plan on lineHashID: add or update means an applied plan last put that user
// on the line, remove means one last took it off. The approvals are never
// pruned, so this is the complete record of what Lattice did on the line.
func (s *Server) lineUserAppliedOps(lineHashID string) map[string]string {
	ops := map[string]string{}
	for _, plan := range s.lineUserLastApplied(func(plan lineUserPlan) bool { return plan.LineHashID == lineHashID }) {
		ops[plan.UserID] = plan.Op
	}
	return ops
}

// lineUserLastApplied returns the last applied line-user plan for each
// (user, line) pair whose plan keep accepts, in no particular order.
func (s *Server) lineUserLastApplied(keep func(lineUserPlan) bool) []lineUserPlan {
	type last struct {
		plan lineUserPlan
		at   time.Time
	}
	latest := map[[2]string]last{}
	for _, a := range s.store.Approvals() {
		if a.Plugin != singBoxLineUserPlugin || a.Status != model.ApprovalApplied {
			continue
		}
		var plan lineUserPlan
		if err := json.Unmarshal([]byte(a.Plan), &plan); err != nil || !keep(plan) ||
			a.RequestSHA256 != lineUserRequestSHA(plan.UserID, plan.LineHashID) {
			continue
		}
		key := [2]string{plan.UserID, plan.LineHashID}
		if prev, ok := latest[key]; !ok || a.UpdatedAt.After(prev.at) {
			latest[key] = last{plan: plan, at: a.UpdatedAt}
		}
	}
	plans := make([]lineUserPlan, 0, len(latest))
	for _, l := range latest {
		plans = append(plans, l.plan)
	}
	return plans
}

// vpnUserDeleteRefusal refuses deleting userID while the delete would leave
// its credential on an adopted line. The identity record holds the only copy
// of the credential. A removal filed before the delete sends it, and sb user
// del takes every entry holding it, which revokes it on the line. After the
// delete only a removal by name can be filed (deletedUserLineRemovePlan): it
// takes Lattice's own entry and leaves any entry that shares the credential,
// and only a node whose script removes by name runs it; on an alpha.7 node it
// cannot be filed at all (deletedUserRemovalUnsupported). So the delete waits
// for the removals. Two cases are refused:
//
//   - a line-user task for the user is queued or leased. A leased add
//     already carries the credential and puts it on the node with no
//     identity behind it; a removal renders its script at lease, without a
//     credential once the identity is gone, and fails.
//   - an applied plan put the user on an adopted line with no applied
//     removal since, and the line still resolves, so plan_remove can be
//     filed for it now with the credential, and after the delete only by
//     name, if at all.
//
// A line that no longer resolves is left out: plan_remove cannot be filed
// for it either, so refusing would make the identity undeletable and remove
// nothing. A managed line is left out: its render already drops a deleted
// user, and the line's next config apply removes it. Nothing holds a lock
// across this check and the delete; a plan approved in between is refused at
// render for its missing user, so only a task leased in that window escapes.
func (s *Server) vpnUserDeleteRefusal(userID string) error {
	var live map[string]model.Task
	for _, a := range s.store.Approvals() {
		if a.Plugin != singBoxLineUserPlugin || a.Status != model.ApprovalApproved {
			continue
		}
		var plan lineUserPlan
		if err := json.Unmarshal([]byte(a.Plan), &plan); err != nil || plan.UserID != userID {
			continue
		}
		if live == nil {
			live = map[string]model.Task{}
			for _, task := range s.store.Tasks() {
				if task.ApprovalID != "" && (task.Status == model.TaskQueued || task.Status == model.TaskLeased) {
					live[task.ApprovalID] = task
				}
			}
		}
		if task, ok := live[a.ID]; ok {
			return fmt.Errorf("user %q has approval %s (%s on line %s) whose task %s is %s; wait for its result, or cancel the task while it is queued, before deleting the user",
				userID, a.ID, plan.Op, plan.LineHashID, task.ID, task.Status)
		}
	}
	var held []string
	for _, plan := range s.lineUserLastApplied(func(plan lineUserPlan) bool { return plan.UserID == userID }) {
		if plan.Op != lineUserOpAdd && plan.Op != lineUserOpUpdate {
			continue
		}
		ln, err := s.resolveLineUserTarget(plan.LineHashID)
		if err != nil || ln.Managed {
			continue
		}
		held = append(held, fmt.Sprintf("%s (%s on node %s)", ln.LineHashID, ln.Tag, ln.NodeID))
	}
	if len(held) == 0 {
		return nil
	}
	sort.Strings(held)
	return fmt.Errorf("user %q is still on adopted line %s, where an applied plan put it; the user record holds the only copy of its credential, and deleting the user now "+
		"would leave that credential live on the node: afterwards Lattice can remove the entry only by name, which leaves any entry sharing the credential, and only on a node "+
		"whose sb script reports removing by name (lr00rl/sing-box v1.24.3-alpha.8 and later; alpha.7 refuses a name alone); "+
		"plan_remove the user from every line listed and apply the removals, then delete",
		userID, strings.Join(held, ", "))
}

// lineUserRemovalRefusal refuses removing userID from adopted line ln when
// what Lattice knows says the removal would do harm the plan does not show.
//
// sb user del (cmd_json_user in lr00rl/sing-box v1.24.3-alpha.7) deletes every
// entry on the line that matches the payload's name, or ANY of its uuid,
// username or password. The payload carries the identity's whole credential,
// so an entry under another name that holds the same uuid or password goes
// too. Migrated identities carry their legacy proxy user's uuid, and a line's
// own first entry can hold it. Lattice sees two such cases:
//
//   - another identity that Lattice binds to the line, or put on it, holds the
//     same credential for the line's protocol;
//   - the line's first entry, the one its share link is built from, holds
//     the credential, and either no applied plan put this identity on the
//     line (so that entry is not the one Lattice added) or the line holds
//     more than one entry (an applied add appends, so the first entry is
//     somebody else's).
//
// Entries past the first are not reported by the node, so a hand-added
// duplicate further down the list is invisible here. The task result reads
// the counts the script reports and flags a removal that took more than one
// entry (lineUserOvermatch); that is after the fact, which is why the cases
// above are refused first. Rotating the identity's credential and applying
// plan_update separates it from the other entry, after which the removal
// matches only Lattice's own.
func (s *Server) lineUserRemovalRefusal(userID string, ln Line, payload lineUserCredentialPayload) error {
	remedy := fmt.Sprintf("rotate this identity's %s credential and apply plan_update on the line first, so the removal matches only Lattice's own entry", ln.Type)
	shares := func(uuid, password string) string {
		switch {
		case payload.UUID != "" && strings.EqualFold(strings.TrimSpace(uuid), payload.UUID):
			return "uuid"
		case payload.Password != "" && password == payload.Password:
			return "password"
		}
		return ""
	}
	ops := s.lineUserAppliedOps(ln.LineHashID)
	for _, other := range s.listVpnUsers() {
		if other.ID == userID {
			continue
		}
		if !vpnUserHasEnabledBinding(other, ln.LineHashID) && ops[other.ID] != lineUserOpAdd && ops[other.ID] != lineUserOpUpdate {
			continue
		}
		credential, ok := vpnCredentialForProtocol(other.Credentials, ln.Type)
		if !ok {
			continue
		}
		if field := shares(credential.UUID, credential.Password); field != "" {
			return fmt.Errorf("identity %q is on line %q with the same %s as user %q, and sb user del removes every entry that matches any credential field, so this removal would take that identity off the node too; %s",
				other.ID, ln.LineHashID, field, userID, remedy)
		}
	}
	if node, ok := s.singBoxInventoryNode(ln.NodeID, firstNonEmpty(ln.Name, ln.Tag)); ok && strings.TrimSpace(node.ShareURL) != "" {
		uuid, password := shareURLCredential(node.ShareURL)
		if field := shares(uuid, password); field != "" {
			added := ops[userID] == lineUserOpAdd || ops[userID] == lineUserOpUpdate
			if !added || !ln.UserKnown || ln.UserCount > 1 {
				return fmt.Errorf("the first entry on line %q, the one its share link is built from, holds the same %s as user %q, and %s; sb user del removes every entry that matches any credential field, so this removal would take that entry off the node too; %s",
					ln.LineHashID, field, userID, lineUserOwnerReason(added, ln), remedy)
			}
		}
	}
	return nil
}

func lineUserOwnerReason(added bool, ln Line) string {
	if !added {
		return "no applied plan put this user on the line, so that entry is not the one Lattice added"
	}
	if !ln.UserKnown {
		return "the node reports no user count, so Lattice cannot tell that entry from its own"
	}
	return fmt.Sprintf("the line holds %d entries while Lattice's add appended its own last, so that entry is somebody else's", ln.UserCount)
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
// A disabled identity gets nothing here: every caller refuses it first, with
// its own wording.
func (s *Server) vpnUserPolicyRefusal(u VpnUser, now time.Time) (reason, remedy string) {
	policy := s.vpnUserPolicyAt(u, now)
	switch policy.Reason {
	case vpnSuspendReasonOperator:
		return vpnUserOperatorSuspendedReason(u.ID, policy), "resume it"
	case vpnSuspendReasonExpiry:
		return fmt.Sprintf("user %q expired on %s", u.ID, dateOnlyUTC(u.ExpiresAt).Format("2006-01-02")), "renew it"
	case vpnSuspendReasonQuota:
		remedy = "raise the quota"
		if u.QuotaPeriod == vpnQuotaPeriodMonthly {
			remedy = "raise the quota or wait for the next period"
		}
		return fmt.Sprintf("user %q has used %s of its %s quota", u.ID,
			formatProxyBytesIn(policy.Usage.Used, policy.LimitBytes),
			formatProxyBytes(policy.LimitBytes)), remedy
	}
	return "", ""
}

// vpnUserOperatorSuspendedReason says that an operator suspended the
// identity, and who, when Lattice recorded it.
func vpnUserOperatorSuspendedReason(userID string, policy vpnUserPolicy) string {
	if policy.By != "" {
		return fmt.Sprintf("user %q is suspended by %s", userID, policy.By)
	}
	return fmt.Sprintf("user %q is suspended by an operator", userID)
}

// vpnUserOperatorSuspension returns the refusal for granting an identity an
// operator suspended, or nil. It needs no usage: an operator suspension
// outranks expiry and quota, so the decision over no usage already says it.
func vpnUserOperatorSuspension(u VpnUser, now time.Time) error {
	if policy := decideVpnUserPolicy(u, vpnUserQuotaUsage{}, now); policy.Reason == vpnSuspendReasonOperator {
		return errors.New(vpnUserOperatorSuspendedReason(u.ID, policy))
	}
	return nil
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
	if err := vpnUserOperatorSuspension(u, s.now()); err != nil {
		return fmt.Errorf("%w, so this plan would grant a suspended user; resume it before approving", err)
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
			return s.validateDeletedUserLineRemove(approval, plan, checkGrant)
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
	// The removal is checked again as of now: an identity sharing the
	// credential can be bound, or the line's entries change, while the
	// approval waits.
	if checkGrant && plan.Op == lineUserOpRemove {
		if err := s.lineUserRemovalRefusal(user.ID, line, payload); err != nil {
			return zeroPlan, zeroUser, zeroLine, zeroPayload, nil, err
		}
	}
	return plan, user, line, payload, nil, nil
}

// validateDeletedUserLineRemove checks an adopted plan_remove whose user no
// longer exists: one filed before the deletion, or one filed after it by
// a102 or by deletedUserLineRemovePlan. The payload it answers is the on-box
// name alone, the only thing left to send. When checkGrant is set, at
// approval and at script render, the node must report removing a user by
// name (singBoxUserDelByNameCapability), or the task could only fail
// (deletedUserRemovalUnsupported), and the approval must have hashed that
// name-only payload: one filed before the deletion hashed the credential,
// which no longer exists to send, and running it by name would run
// something other than what was approved. Without checkGrant, when a task
// result is recorded, it checks the line's tag and the on-box name against
// the line as it is now, since that result records what the node already
// did. A managed remove for a deleted user stays refused: the render
// already leaves the user out.
func (s *Server) validateDeletedUserLineRemove(approval model.Approval, plan lineUserPlan, checkGrant bool) (lineUserPlan, VpnUser, Line, lineUserCredentialPayload, *proxycore.Artifact, error) {
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
	payload := lineUserCredentialPayload{Name: plan.UserName}
	if checkGrant {
		if !s.agentHasCapability(line.NodeID, singBoxUserDelByNameCapability) {
			return fail(deletedUserRemovalUnsupported(plan.UserID, line))
		}
		if sha, err := lineUserCredentialSHA(payload); err != nil || sha != plan.CredentialSHA256 {
			return fail(fmt.Errorf("user %q no longer exists, and approval %s hashed its credential, which went with it; node %s removes a user by name alone, "+
				"but that is not the payload this approval reviewed: reject it and plan_remove again, which files the removal by name", plan.UserID, approval.ID, line.NodeID))
		}
	}
	return plan, VpnUser{}, line, payload, nil, nil
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
	// Both ops pass the same JSON payload the approval hashed. The fork routes
	// every `user` subcommand to cmd_json_user, which refuses anything that is
	// not a JSON object carrying the credential the line's protocol needs,
	// except that from alpha.8 a del may carry the user's name alone (a
	// deleted user's removal, validateDeletedUserLineRemove): a bare name
	// fails with invalid_payload and exit 2, which is what every removal a102
	// rendered did. The task view exposes only the script's digest and size,
	// so the credential is no more visible than an add's.
	script, err := adoptedLineUserScript(plan.Op, plan.Line, payload)
	if err != nil {
		return fail(err)
	}
	return script
}

// adoptedLineUserScript is the apply script for one adopted line-user op:
// `sb --json user add|del <line> <payload>`, with the payload as JSON.
func adoptedLineUserScript(op, line string, payload lineUserCredentialPayload) (string, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode payload: %v", err)
	}
	var argv string
	switch op {
	case lineUserOpAdd, lineUserOpUpdate:
		argv = " --json user add " + shellQuote(line) + " " + shellQuote(string(payloadJSON))
	case lineUserOpRemove:
		argv = " --json user del " + shellQuote(line) + " " + shellQuote(string(payloadJSON))
	default:
		return "", fmt.Errorf("invalid line-user op %q", op)
	}
	return "set -e\n" +
		"SB_BIN=\"${LATTICE_SINGBOX_BIN:-sb}\"\n" +
		"command -v \"$SB_BIN\" >/dev/null 2>&1 || { echo " + shellQuote("lattice lineuser: sb binary not found") + " >&2; exit 1; }\n" +
		"\"$SB_BIN\"" + argv + "\n", nil
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
		// The exit code alone does not say what to fix. The script prints
		// why it refused, and the operator reads it here: a removal that
		// would leave a socks line open to anyone, a name two entries share,
		// another user call holding the node's lock.
		if code, message, ok := lineUserScriptError(result.Stdout); ok {
			reason += ": the node script refused with " + code
			if message != "" {
				reason += ": " + message
			}
			metadata["script_error"] = code
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
	var bindingChanged bool
	u, bindingChanged, err = reconcileLineUserBinding(u, plan)
	if err != nil {
		return err
	}
	changed = changed || bindingChanged
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
	// The script prints the line's user count before and after the change.
	// An over-match is past undoing by now (the script removes its backup once
	// the core accepts the file), so it is recorded where the operator reads
	// the result: on the applied approval and in its own audit event.
	overmatch := ""
	if artifact == nil {
		if before, after, ok := lineUserScriptCounts(result.Stdout); ok {
			metadata["user_count_before"] = strconv.Itoa(before)
			metadata["user_count_after"] = strconv.Itoa(after)
			overmatch = lineUserOvermatch(plan, before, after)
		}
	}
	approval.Status = model.ApprovalApplied
	approval.Reason = overmatch
	approval.UpdatedAt = time.Now().UTC()
	if err := s.store.UpsertApproval(approval); err != nil {
		return fmt.Errorf("mark line-user approval applied: %w", err)
	}
	if overmatch != "" {
		metadata["overmatch"] = "true"
		s.recordRequestAudit(r, model.AuditEvent{
			ID: id.New("audit"), NodeID: approval.NodeID, Action: "vpnuser.line.overmatch",
			Decision: "allow", Reason: overmatch, Metadata: map[string]string{
				"approval_id": approval.ID, "task_id": task.ID, "op": plan.Op, "line_hash_id": plan.LineHashID,
				"user_id": plan.UserID, "user_count_before": metadata["user_count_before"], "user_count_after": metadata["user_count_after"],
			},
		})
	}
	probeTaskID, probeErr := s.queueLineUserRediscovery(plan.NodeID)
	if probeErr != nil {
		approval.Reason = strings.TrimPrefix(overmatch+"; runtime applied; bounded rediscovery queue failed", "; ")
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
	// Sub-Store auto-sync just like the direct mutations do (design-15 §7),
	// and drop what core shares cached.
	s.triggerVPNCoreMutation()
	s.invalidateCoreSourceShares()
	return nil
}

// reconcileLineUserBinding records on the identity what an applied line-user
// plan did on the node. It is the one owner of a binding's applied credential
// (r1-critic X-5), for every op:
//
//	add, update  the binding is enabled and carries the plan's credential hash
//	resume       the same: the node holds the identity's credential again
//	suspend      the binding stays, with no applied credential
//	remove       the binding goes, and its applied credential with it
//
// A rotation changes only the stored credential, so the applied hash stops
// matching until a plan_update, or a resume, applies the new one; a rotation
// while suspended is therefore picked up by the resume. The credential hash
// is the plan's, which the result path has just checked against the
// identity's current credential (validateLineUserApproval).
func reconcileLineUserBinding(u VpnUser, plan lineUserPlan) (VpnUser, bool, error) {
	applied := lineUserAppliedCredential(plan.Op, plan.CredentialSHA256)
	bindings := append([]LineBinding(nil), u.Bindings...)
	changed := false
	switch plan.Op {
	case lineUserOpAdd, lineUserOpUpdate, lineUserOpResume, lineUserOpSuspend:
		found := false
		for i := range bindings {
			if bindings[i].LineHashID != plan.LineHashID {
				continue
			}
			found = true
			if plan.Op != lineUserOpSuspend && !bindings[i].Enabled {
				bindings[i].Enabled, changed = true, true
			}
			if bindings[i].AppliedCredentialSHA256 != applied {
				bindings[i].AppliedCredentialSHA256, changed = applied, true
			}
			break
		}
		if !found && plan.Op != lineUserOpSuspend {
			bindings = append(bindings, LineBinding{LineHashID: plan.LineHashID, Enabled: true, AppliedCredentialSHA256: applied})
			changed = true
		}
	case lineUserOpRemove:
		kept := bindings[:0]
		for _, b := range bindings {
			if b.LineHashID != plan.LineHashID {
				kept = append(kept, b)
			}
		}
		changed = len(kept) != len(bindings)
		bindings = kept
	default:
		return u, false, fmt.Errorf("reconcile line-user approval: invalid op %q", plan.Op)
	}
	u.Bindings = bindings
	return u, changed, nil
}

// lineUserAppliedCredential is the applied-credential hash a binding carries
// after op ran on the node: the plan's hash when the op leaves the
// identity's credential on the node, empty when it takes it off.
func lineUserAppliedCredential(op, credentialSHA256 string) string {
	switch op {
	case lineUserOpAdd, lineUserOpUpdate, lineUserOpResume:
		return credentialSHA256
	default:
		return ""
	}
}

const (
	// lineCredentialCurrent: the node holds the identity's current credential.
	lineCredentialCurrent = "current"
	// lineCredentialStale: an applied plan put a credential there, but the
	// identity's credential has been rotated since.
	lineCredentialStale = "stale"
	// lineCredentialNone: no applied plan put the identity's credential on
	// the node (bind, the runtime path, a hand edit), or the last one took it
	// off.
	lineCredentialNone = "none"
	// lineCredentialUnknown: the line is not in the read model, so the
	// current credential's hash cannot be computed.
	lineCredentialUnknown = "unknown"
)

// lineBindingCredentialState says whether the node behind a binding holds
// the identity's current credential: the binding's applied hash against the
// hash of the payload the identity's credential gives on that line now. This
// is the test a per-identity link applies before serving a line
// (identity-sub 4.2 rule 3).
func lineBindingCredentialState(u VpnUser, b LineBinding, ln Line, lineKnown bool) string {
	if b.AppliedCredentialSHA256 == "" {
		return lineCredentialNone
	}
	if !lineKnown || ln.LineUUID == "" {
		return lineCredentialUnknown
	}
	payload, err := lineUserCredential(u, strings.ToLower(strings.TrimSpace(ln.Type)), userLineName(u.ID, ln.LineUUID))
	if err != nil {
		return lineCredentialStale
	}
	sha, err := lineUserCredentialSHA(payload)
	if err != nil || sha != b.AppliedCredentialSHA256 {
		return lineCredentialStale
	}
	return lineCredentialCurrent
}

// lineUserAppliedCredentialBackfill names the one-time migration that fills
// the applied credential of bindings made before the field existed.
const lineUserAppliedCredentialBackfill = "vpnuser-applied-credential-v1"

// backfillLineUserAppliedCredentials fills each binding that has no applied
// credential from approval history, once per store: the credential hash of
// the last applied plan for the (identity, line) pair, when that plan was an
// add or an update. A pair whose last applied plan was a removal, or that no
// plan ever touched (bind, the runtime path, a hand edit), stays empty. A
// credential rotated since that plan leaves a hash that no longer matches,
// which is the truth: the node still holds the old one. Approvals are never
// pruned, so the history is complete.
func (s *Server) backfillLineUserAppliedCredentials() error {
	// Every boot gets here; reading the whole approval history is for the
	// first one only.
	if s.store.MigrationRan(lineUserAppliedCredentialBackfill) {
		return nil
	}
	last := map[[2]string]lineUserPlan{}
	for _, plan := range s.lineUserLastApplied(func(lineUserPlan) bool { return true }) {
		last[[2]string{plan.UserID, plan.LineHashID}] = plan
	}
	changed, ran, err := s.store.MigrateVpnUserPublicRecordsOnce(lineUserAppliedCredentialBackfill, func(record store.VpnUserPublicRecord) (store.VpnUserPublicRecord, bool) {
		touched := false
		for i, binding := range record.Bindings {
			if binding.AppliedCredentialSHA256 != "" {
				continue
			}
			plan, ok := last[[2]string{record.ID, binding.LineHashID}]
			if !ok || lineUserAppliedCredential(plan.Op, plan.CredentialSHA256) == "" {
				continue
			}
			record.Bindings[i].AppliedCredentialSHA256 = plan.CredentialSHA256
			touched = true
		}
		return record, touched
	})
	if err != nil {
		return fmt.Errorf("backfill applied line credentials: %w", err)
	}
	if ran && len(changed) > 0 {
		s.logger.Printf("vpn-core: recorded the applied line credential for the bindings of %d identities from approval history", len(changed))
	}
	return nil
}

// lineUserScriptCounts reads the line cmd_json_user prints when it succeeds,
// {"ok":true,"action":"add|del","line":...,"user_count_before":N,
// "user_count_after":M}, from the end of the task's stdout. ok is false when
// no such line is there, which is how an older script answers.
func lineUserScriptCounts(stdout string) (before, after int, ok bool) {
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var out struct {
			OK     bool `json:"ok"`
			Before *int `json:"user_count_before"`
			After  *int `json:"user_count_after"`
		}
		if json.Unmarshal([]byte(line), &out) != nil || !out.OK || out.Before == nil || out.After == nil {
			continue
		}
		return *out.Before, *out.After, true
	}
	return 0, 0, false
}

// lineUserScriptErrorCode is the shape of the error codes the node script's
// json_err prints (invalid_user, last_user_open_proxy, busy). Anything else
// on that line is not repeated onto the approval.
var lineUserScriptErrorCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// lineUserScriptError reads the line the node script prints when it refuses,
// {"ok":false,"error":"<code>","message":"<why>"}, from the end of the task's
// stdout: the last line that holds a JSON object decides. ok is false when
// that line is not such a refusal, or there is none. The message comes from
// the node, so control characters are dropped and it is cut to a bound
// before it is kept on the approval.
func lineUserScriptError(stdout string) (code, message string, ok bool) {
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var out struct {
			OK      *bool  `json:"ok"`
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if json.Unmarshal([]byte(line), &out) != nil || out.OK == nil || *out.OK || !lineUserScriptErrorCode.MatchString(out.Error) {
			return "", "", false
		}
		return out.Error, truncateMetadataValue(normalizeTaskResultText(out.Message), 240), true
	}
	return "", "", false
}

// lineUserOvermatch says what went wrong when the script's counts show it
// matched more than one entry, or "" when they do not. sb user add replaces
// every entry matching the payload and appends one, and sb user del removes
// every match, so the entries matched are before minus after, plus one for an
// add. Lattice's own entry is at most one of them.
func lineUserOvermatch(plan lineUserPlan, before, after int) string {
	matched := before - after
	if plan.Op != lineUserOpRemove {
		matched++
	}
	if matched <= 1 {
		return ""
	}
	if plan.Op == lineUserOpRemove {
		return fmt.Sprintf("applied, but sb user del removed %d entries from line %s where Lattice expected only its own %s: "+
			"%d other entries on the line held the same credential and are no longer on the node", matched, plan.Line, plan.UserName, matched-1)
	}
	return fmt.Sprintf("applied, but sb user add replaced %d entries on line %s while adding %s: "+
		"entries that held the same credential were removed and only Lattice's %s now stands for them", matched, plan.Line, plan.UserName, plan.UserName)
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

// vpnUserRotateCredential regenerates ONE protocol credential for a user. A
// rotation only changes server state; pushing it onto lines is an explicit
// plan_update afterwards (drift is surfaced).
//
// The new secret is in the answer (`revealed_credential`) only when the
// reveal gate admits the caller (secret_reveal.go): a session that sent a
// fresh "step_up_grant", or a token carrying secrets:reveal. Otherwise the
// rotation still happens and the answer says the credential was withheld;
// the credential reveal hands it out later through the same gate.
func (s *Server) vpnUserRotateCredential(ctxPrincipal principal, request []byte) ([]byte, error) {
	var req struct {
		UserID      string `json:"user_id"`
		Protocol    string `json:"protocol"`
		StepUpGrant string `json:"step_up_grant"`
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
	reveal := s.decideSecretReveal(ctxPrincipal, req.StepUpGrant)
	s.recordPrincipalAudit(ctxPrincipal, model.AuditEvent{
		ID: id.New("audit"), Action: "vpnuser.credential.rotate", Scope: "proxy:admin",
		Metadata: map[string]string{"user_id": u.ID, "protocol": protocol, "revealed": strconv.FormatBool(reveal.Allowed)},
	})
	out := struct {
		User     vpnUserView `json:"user"`
		Protocol string      `json:"protocol"`
		// RevealedCredential is the new secret, present only when the reveal
		// gate admitted the caller.
		RevealedCredential string `json:"revealed_credential,omitempty"`
		// CredentialWithheld says the rotation happened and the secret was
		// not revealed; RevealCode is the gate's reason.
		CredentialWithheld bool   `json:"credential_withheld,omitempty"`
		RevealCode         string `json:"reveal_code,omitempty"`
	}{User: toVpnUserView(u), Protocol: protocol}
	if reveal.Allowed {
		out.RevealedCredential = revealed
		s.recordSecretReveal(ctxPrincipal, reveal, model.AuditEvent{Action: "vpn.user.credentials.reveal", Scope: "proxy:admin",
			Metadata: map[string]string{"user_id": u.ID, "protocol": protocol, "at": "rotate"}})
	} else {
		out.CredentialWithheld, out.RevealCode = true, reveal.Code
	}
	return json.Marshal(out)
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
