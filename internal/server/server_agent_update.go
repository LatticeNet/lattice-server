package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

const (
	agentUpdatePlugin       = "agentupdate"
	agentUpdateAction       = "update-agent"
	agentUpdateActionPrefix = agentUpdateAction + ":"

	defaultAgentInstallPath = "/usr/local/bin/lattice-agent"
	defaultAgentServiceName = "lattice-agent.service"
)

var (
	agentVersionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}$`)
	agentSHA256Re  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	agentServiceRe = regexp.MustCompile(`^[A-Za-z0-9_.@:-]{1,128}$`)
)

type agentUpdatePayload struct {
	NodeID        string `json:"node_id"`
	TargetVersion string `json:"target_version"`
	BinaryURL     string `json:"binary_url"`
	SHA256        string `json:"sha256"`
	InstallPath   string `json:"install_path"`
	ServiceName   string `json:"service_name"`
}

func (s *Server) handleAgentUpdatePolicies(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		policies := s.store.AgentUpdatePolicies()
		visible := make([]model.AgentUpdatePolicy, 0, len(policies))
		for _, policy := range policies {
			if rbac.Allows(p.Principal, "node:read", policy.NodeID) {
				visible = append(visible, policy)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"policies": visible})
	case http.MethodPost:
		var req model.AgentUpdatePolicy
		if !decodeClientJSON(w, r, &req) {
			return
		}
		if !s.requireNodeScope(w, p, "node:admin", strings.TrimSpace(req.NodeID)) {
			return
		}
		policy, err := s.normalizeAgentUpdatePolicy(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.store.UpsertAgentUpdatePolicy(policy); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:     id.New("audit"),
			NodeID: policy.NodeID,
			Action: "agent.update.policy",
			Scope:  "node:admin",
			Metadata: map[string]string{
				"target_version": policy.TargetVersion,
				"auto_plan":      fmt.Sprintf("%t", policy.AutoPlan),
			},
		})
		writeJSON(w, http.StatusOK, policy)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleDeleteAgentUpdatePolicy(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	nodeID := strings.TrimSpace(req.NodeID)
	if !s.requireNodeScope(w, p, "node:admin", nodeID) {
		return
	}
	if err := s.store.DeleteAgentUpdatePolicy(nodeID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), NodeID: nodeID, Action: "agent.update.policy.delete", Scope: "node:admin"})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAgentUpdatePlan(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
		Force  bool   `json:"force"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	nodeID := strings.TrimSpace(req.NodeID)
	if !s.requireNodeScope(w, p, "node:admin", nodeID) {
		return
	}
	if !s.requireNodeScope(w, p, "network:plan", nodeID) {
		return
	}
	approval, err := s.createAgentUpdateApproval(nodeID, p.ActorID, req.Force, "manual", s.now())
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errAgentUpdateNoop) {
			status = http.StatusConflict
		}
		writeError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, toApprovalView(approval))
}

var errAgentUpdateNoop = errors.New("agent already reports the target version")

func (s *Server) normalizeAgentUpdatePolicy(req model.AgentUpdatePolicy) (model.AgentUpdatePolicy, error) {
	out := model.AgentUpdatePolicy{}
	nodeID := strings.TrimSpace(req.NodeID)
	if nodeID == "" {
		return model.AgentUpdatePolicy{}, errors.New("node_id is required")
	}
	if _, ok := s.store.Node(nodeID); !ok {
		return model.AgentUpdatePolicy{}, errors.New("node not found")
	}
	if existing, ok := s.store.AgentUpdatePolicy(nodeID); ok {
		out = existing
	}
	out.NodeID = nodeID
	out.Enabled = req.Enabled
	out.AutoPlan = req.AutoPlan
	out.TargetVersion = strings.TrimSpace(req.TargetVersion)
	if !agentVersionRe.MatchString(out.TargetVersion) {
		return model.AgentUpdatePolicy{}, errors.New("target_version is required and must be an auditable version string")
	}
	binaryURL, err := normalizeAgentUpdateURL(req.BinaryURL)
	if err != nil {
		return model.AgentUpdatePolicy{}, err
	}
	out.BinaryURL = binaryURL
	out.SHA256 = strings.ToLower(strings.TrimSpace(req.SHA256))
	if !agentSHA256Re.MatchString(out.SHA256) {
		return model.AgentUpdatePolicy{}, errors.New("sha256 must be a 64-character lowercase hex digest")
	}
	out.InstallPath = strings.TrimSpace(req.InstallPath)
	if out.InstallPath == "" {
		out.InstallPath = defaultAgentInstallPath
	}
	if err := validateAgentInstallPath(out.InstallPath); err != nil {
		return model.AgentUpdatePolicy{}, err
	}
	out.ServiceName = strings.TrimSpace(req.ServiceName)
	if out.ServiceName == "" {
		out.ServiceName = defaultAgentServiceName
	}
	if !agentServiceRe.MatchString(out.ServiceName) {
		return model.AgentUpdatePolicy{}, errors.New("service_name contains unsupported characters")
	}
	return out, nil
}

func normalizeAgentUpdateURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("binary_url is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return "", errors.New("binary_url must be an HTTPS URL")
	}
	if u.User != nil {
		return "", errors.New("binary_url must not contain userinfo")
	}
	if u.Fragment != "" {
		return "", errors.New("binary_url must not contain a fragment")
	}
	return u.String(), nil
}

func validateAgentInstallPath(value string) error {
	if strings.TrimSpace(value) != value {
		return errors.New("install_path has leading or trailing whitespace")
	}
	if !strings.HasPrefix(value, "/") {
		return errors.New("install_path must be absolute")
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return errors.New("install_path must not contain a .. segment")
		}
	}
	if strings.ContainsFunc(value, proxyUnsafeControl) || strings.ContainsAny(value, "\"'`$;&|<>") {
		return errors.New("install_path contains unsafe characters")
	}
	if !strings.HasSuffix(value, "/lattice-agent") {
		return errors.New("install_path must end with /lattice-agent")
	}
	return nil
}

func (s *Server) evaluateAgentUpdatePolicies(now time.Time) {
	for _, policy := range s.store.AgentUpdatePolicies() {
		if !policy.Enabled || !policy.AutoPlan {
			continue
		}
		if _, err := s.createAgentUpdateApproval(policy.NodeID, "", false, "auto", now); err != nil && !errors.Is(err, errAgentUpdateNoop) {
			s.logger.Printf("agent update policy %s: %v", policy.NodeID, err)
		}
	}
}

func (s *Server) createAgentUpdateApproval(nodeID, actorID string, force bool, mode string, now time.Time) (model.Approval, error) {
	node, ok := s.store.Node(nodeID)
	if !ok {
		return model.Approval{}, errors.New("node not found")
	}
	policy, ok := s.store.AgentUpdatePolicy(nodeID)
	if !ok || !policy.Enabled {
		return model.Approval{}, errors.New("agent update policy is not enabled for this node")
	}
	if !force && strings.TrimSpace(node.AgentVersion) == policy.TargetVersion {
		return model.Approval{}, errAgentUpdateNoop
	}
	payload := agentUpdatePayload{
		NodeID:        policy.NodeID,
		TargetVersion: policy.TargetVersion,
		BinaryURL:     policy.BinaryURL,
		SHA256:        policy.SHA256,
		InstallPath:   policy.InstallPath,
		ServiceName:   policy.ServiceName,
	}
	if s.hasOpenAgentUpdateApproval(payload) {
		return model.Approval{}, errors.New("an equivalent agent update approval is already open")
	}
	plan := renderAgentUpdatePlan(node, payload, mode)
	approval := model.Approval{
		ID:        id.New("approval"),
		NodeID:    nodeID,
		Plugin:    agentUpdatePlugin,
		Action:    agentUpdateApprovalAction(payload),
		Plan:      plan,
		Status:    model.ApprovalPending,
		ActorID:   actorID,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.store.UpsertApproval(approval); err != nil {
		return model.Approval{}, err
	}
	policy.LastPlannedVersion = policy.TargetVersion
	policy.LastPlannedAt = now
	policy.LastError = ""
	if err := s.store.UpsertAgentUpdatePolicy(policy); err != nil {
		return model.Approval{}, err
	}
	s.recordAudit(model.AuditEvent{
		ID:       id.New("audit"),
		ActorID:  actorID,
		NodeID:   nodeID,
		Action:   "agent.update.plan",
		Scope:    "network:plan",
		Decision: "observe",
		Metadata: map[string]string{
			"target_version": policy.TargetVersion,
			"mode":           mode,
			"approval_id":    approval.ID,
		},
	})
	return approval, nil
}

func (s *Server) hasOpenAgentUpdateApproval(payload agentUpdatePayload) bool {
	action := agentUpdateApprovalAction(payload)
	for _, approval := range s.store.Approvals() {
		if approval.Plugin != agentUpdatePlugin || approval.NodeID != payload.NodeID || approval.Action != action {
			continue
		}
		if approval.Status == model.ApprovalPending || approval.Status == model.ApprovalApproved {
			return true
		}
	}
	return false
}

func renderAgentUpdatePlan(node model.Node, payload agentUpdatePayload, mode string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "plugin: agentupdate\n")
	fmt.Fprintf(&b, "mode: %s\n", mode)
	fmt.Fprintf(&b, "node_id: %s\n", payload.NodeID)
	if node.Name != "" {
		fmt.Fprintf(&b, "node_name: %s\n", node.Name)
	}
	fmt.Fprintf(&b, "current_version: %s\n", node.AgentVersion)
	fmt.Fprintf(&b, "target_version: %s\n", payload.TargetVersion)
	fmt.Fprintf(&b, "binary_url: %s\n", payload.BinaryURL)
	fmt.Fprintf(&b, "sha256: %s\n", payload.SHA256)
	fmt.Fprintf(&b, "install_path: %s\n", payload.InstallPath)
	fmt.Fprintf(&b, "service_name: %s\n", payload.ServiceName)
	fmt.Fprintf(&b, "\nSafety:\n")
	fmt.Fprintf(&b, "- download is HTTPS-only and verified against the pinned SHA-256 digest\n")
	fmt.Fprintf(&b, "- binary is installed atomically with a timestamped backup\n")
	fmt.Fprintf(&b, "- service restart is delayed so the current agent can post the task result\n")
	fmt.Fprintf(&b, "- execution still requires node-agent -allow-exec and root updates require -allow-root-exec\n")
	return b.String()
}

func agentUpdateApprovalAction(payload agentUpdatePayload) string {
	data, _ := json.Marshal(payload)
	return agentUpdateActionPrefix + base64.RawURLEncoding.EncodeToString(data)
}

func agentUpdateApprovalDisplayAction(action string) string {
	if action == agentUpdateAction || strings.HasPrefix(action, agentUpdateActionPrefix) {
		return agentUpdateAction
	}
	return action
}

func agentUpdatePayloadFromApproval(approval model.Approval) (agentUpdatePayload, error) {
	if approval.Plugin != agentUpdatePlugin {
		return agentUpdatePayload{}, errors.New("not an agent update approval")
	}
	if !strings.HasPrefix(approval.Action, agentUpdateActionPrefix) {
		return agentUpdatePayload{}, errors.New("agent update approval is missing its bound payload")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(approval.Action, agentUpdateActionPrefix))
	if err != nil {
		return agentUpdatePayload{}, err
	}
	var payload agentUpdatePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return agentUpdatePayload{}, err
	}
	payload.NodeID = strings.TrimSpace(payload.NodeID)
	if payload.NodeID == "" {
		return agentUpdatePayload{}, errors.New("agent update approval is missing node_id")
	}
	if payload.NodeID != approval.NodeID {
		return agentUpdatePayload{}, errors.New("agent update approval node_id mismatch")
	}
	policy := model.AgentUpdatePolicy{
		NodeID:        payload.NodeID,
		Enabled:       true,
		TargetVersion: payload.TargetVersion,
		BinaryURL:     payload.BinaryURL,
		SHA256:        payload.SHA256,
		InstallPath:   payload.InstallPath,
		ServiceName:   payload.ServiceName,
	}
	normalized, err := sNormalizeAgentUpdatePayload(policy)
	if err != nil {
		return agentUpdatePayload{}, err
	}
	return agentUpdatePayload{
		NodeID:        payload.NodeID,
		TargetVersion: normalized.TargetVersion,
		BinaryURL:     normalized.BinaryURL,
		SHA256:        normalized.SHA256,
		InstallPath:   normalized.InstallPath,
		ServiceName:   normalized.ServiceName,
	}, nil
}

func sNormalizeAgentUpdatePayload(policy model.AgentUpdatePolicy) (model.AgentUpdatePolicy, error) {
	policy.TargetVersion = strings.TrimSpace(policy.TargetVersion)
	if !agentVersionRe.MatchString(policy.TargetVersion) {
		return model.AgentUpdatePolicy{}, errors.New("invalid target_version")
	}
	binaryURL, err := normalizeAgentUpdateURL(policy.BinaryURL)
	if err != nil {
		return model.AgentUpdatePolicy{}, err
	}
	policy.BinaryURL = binaryURL
	policy.SHA256 = strings.ToLower(strings.TrimSpace(policy.SHA256))
	if !agentSHA256Re.MatchString(policy.SHA256) {
		return model.AgentUpdatePolicy{}, errors.New("invalid sha256")
	}
	if policy.InstallPath == "" {
		policy.InstallPath = defaultAgentInstallPath
	}
	if err := validateAgentInstallPath(policy.InstallPath); err != nil {
		return model.AgentUpdatePolicy{}, err
	}
	if policy.ServiceName == "" {
		policy.ServiceName = defaultAgentServiceName
	}
	if !agentServiceRe.MatchString(policy.ServiceName) {
		return model.AgentUpdatePolicy{}, errors.New("invalid service_name")
	}
	return policy, nil
}

func (s *Server) requireCurrentAgentUpdateApproval(approval model.Approval) error {
	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		return fmt.Errorf("agent update approval payload is invalid; re-plan before approving")
	}
	policy, ok := s.store.AgentUpdatePolicy(approval.NodeID)
	if !ok {
		return fmt.Errorf("agent update policy %q not found; re-plan before approving", approval.NodeID)
	}
	if !policy.Enabled {
		return fmt.Errorf("agent update policy %q is disabled; re-enable and re-plan before approving", approval.NodeID)
	}
	current := agentUpdatePayload{
		NodeID:        policy.NodeID,
		TargetVersion: policy.TargetVersion,
		BinaryURL:     policy.BinaryURL,
		SHA256:        policy.SHA256,
		InstallPath:   policy.InstallPath,
		ServiceName:   policy.ServiceName,
	}
	if current != payload {
		return fmt.Errorf("agent update policy changed since this approval was planned; re-plan before approving")
	}
	return nil
}

func agentUpdateApplyScript(approval model.Approval) (string, error) {
	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		return "", err
	}
	return "set -e\n" +
		"umask 077\n" +
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n" +
		"URL=" + shellQuote(payload.BinaryURL) + "\n" +
		"EXPECT_SHA=" + shellQuote(payload.SHA256) + "\n" +
		"TARGET=" + shellQuote(payload.InstallPath) + "\n" +
		"SERVICE=" + shellQuote(payload.ServiceName) + "\n" +
		"TARGET_VERSION=" + shellQuote(payload.TargetVersion) + "\n" +
		"WORK=$(mktemp -d \"${TMPDIR:-/tmp}/lattice-agent-update.XXXXXX\")\n" +
		"cleanup() { rm -rf \"$WORK\"; }\n" +
		"trap cleanup EXIT\n" +
		"CANDIDATE=\"$WORK/lattice-agent\"\n" +
		"if command -v curl >/dev/null 2>&1; then\n" +
		"  curl -fsSL --proto '=https' --tlsv1.2 -o \"$CANDIDATE\" \"$URL\"\n" +
		"elif command -v wget >/dev/null 2>&1; then\n" +
		"  wget -qO \"$CANDIDATE\" \"$URL\"\n" +
		"else\n" +
		"  echo 'lattice agent update: curl or wget is required' >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"if command -v sha256sum >/dev/null 2>&1; then\n" +
		"  ACTUAL_SHA=$(sha256sum \"$CANDIDATE\" | awk '{print $1}')\n" +
		"elif command -v shasum >/dev/null 2>&1; then\n" +
		"  ACTUAL_SHA=$(shasum -a 256 \"$CANDIDATE\" | awk '{print $1}')\n" +
		"else\n" +
		"  echo 'lattice agent update: sha256sum or shasum is required' >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"if [ \"$ACTUAL_SHA\" != \"$EXPECT_SHA\" ]; then\n" +
		"  echo \"lattice agent update: sha256 mismatch expected=$EXPECT_SHA actual=$ACTUAL_SHA\" >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"chmod 0755 \"$CANDIDATE\"\n" +
		"\"$CANDIDATE\" -version >/dev/null\n" +
		"mkdir -p \"$(dirname \"$TARGET\")\"\n" +
		"if [ -e \"$TARGET\" ]; then\n" +
		"  cp -p \"$TARGET\" \"$TARGET.bak.$(date +%Y%m%d%H%M%S)\"\n" +
		"fi\n" +
		"install -m 0755 \"$CANDIDATE\" \"$TARGET.new\"\n" +
		"mv \"$TARGET.new\" \"$TARGET\"\n" +
		"if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then\n" +
		"  systemctl daemon-reload\n" +
		"  if command -v systemd-run >/dev/null 2>&1; then\n" +
		"    systemd-run --unit=lattice-agent-delayed-restart --on-active=3s /bin/systemctl restart \"$SERVICE\" >/dev/null\n" +
		"  else\n" +
		"    nohup sh -c \"sleep 3; systemctl restart '$SERVICE'\" >/dev/null 2>&1 &\n" +
		"  fi\n" +
		"  echo \"lattice agent update: installed $TARGET_VERSION and scheduled $SERVICE restart\"\n" +
		"else\n" +
		"  echo \"lattice agent update: installed $TARGET_VERSION; restart $SERVICE manually (systemd unavailable)\"\n" +
		"fi\n", nil
}

func (s *Server) handleAgentUpdateTaskResult(r *http.Request, approval model.Approval, result model.TaskResult) error {
	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		return err
	}
	policy, ok := s.store.AgentUpdatePolicy(payload.NodeID)
	if !ok {
		policy = model.AgentUpdatePolicy{NodeID: payload.NodeID}
	}
	if result.Error == "" && result.ExitCode == 0 {
		policy.LastAppliedVersion = payload.TargetVersion
		policy.LastAppliedAt = result.FinishedAt
		policy.LastError = ""
		approval.Status = model.ApprovalApplied
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   approval.NodeID,
			Action:   "agent.update.applied",
			Decision: "allow",
			Metadata: map[string]string{"target_version": payload.TargetVersion, "approval_id": approval.ID},
		})
	} else {
		policy.LastError = boundedTaskError(result)
		approval.Status = model.ApprovalRejected
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   approval.NodeID,
			Action:   "agent.update.failed",
			Decision: "deny",
			Reason:   policy.LastError,
			Metadata: map[string]string{"target_version": payload.TargetVersion, "approval_id": approval.ID},
		})
	}
	if err := s.store.UpsertAgentUpdatePolicy(policy); err != nil {
		return err
	}
	approval.UpdatedAt = time.Now().UTC()
	return s.store.UpsertApproval(approval)
}

func boundedTaskError(result model.TaskResult) string {
	msg := strings.TrimSpace(result.Error)
	if msg == "" {
		msg = strings.TrimSpace(result.Stderr)
	}
	if msg == "" && result.ExitCode != 0 {
		msg = fmt.Sprintf("exit code %d", result.ExitCode)
	}
	msg = strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' {
			return -1
		}
		return r
	}, msg)
	const max = 512
	if len([]rune(msg)) > max {
		return string([]rune(msg)[:max])
	}
	return msg
}
