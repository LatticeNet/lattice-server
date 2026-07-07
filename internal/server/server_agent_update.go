package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

const (
	agentUpdatePlugin         = "agentupdate"
	agentUpdateAction         = "update-agent"
	agentUpdateActionPrefix   = agentUpdateAction + ":"
	agentUpdateAwaitingPrefix = "awaiting agent version confirmation"

	defaultAgentInstallPath         = "/opt/lattice/node-agent/lattice-agent"
	previousDefaultAgentInstallPath = "/opt/lattice/lattice-agent"
	defaultAgentServiceName         = "lattice-agent.service"
	legacyAgentInstallPath          = "/usr/local/bin/lattice-agent"
	defaultAgentReleaseRepo         = "LatticeNet/lattice-node-agent"
	agentReleaseLatest              = "latest"
	agentReleaseMetadataLimit       = 512 * 1024
	agentReleaseSuccessCacheTTL     = 10 * time.Minute
	agentReleaseErrorCacheTTL       = 60 * time.Second
)

var (
	agentVersionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}$`)
	agentSHA256Re  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	agentServiceRe = regexp.MustCompile(`^[A-Za-z0-9_.@:-]{1,128}$`)
	agentRepoRe    = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
)

type agentUpdatePayload struct {
	NodeID         string `json:"node_id"`
	CurrentVersion string `json:"current_version"`
	TargetVersion  string `json:"target_version"`
	BinaryURL      string `json:"binary_url"`
	SHA256         string `json:"sha256"`
	InstallPath    string `json:"install_path"`
	ServiceName    string `json:"service_name"`
}

type agentReleaseInfoView struct {
	Repo          string            `json:"repo"`
	LatestTag     string            `json:"latest_tag"`
	LatestVersion string            `json:"latest_version"`
	ReleaseURL    string            `json:"release_url"`
	Artifacts     []string          `json:"artifacts"`
	SHA256        map[string]string `json:"sha256"`
	FetchedAt     time.Time         `json:"fetched_at"`
}

type agentReleaseCacheEntry struct {
	body      string
	err       error
	expiresAt time.Time
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
		existing, hadExisting := s.store.AgentUpdatePolicy(policy.NodeID)
		if err := s.store.UpsertAgentUpdatePolicy(policy); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !hadExisting || agentUpdatePolicyApprovalBindingChanged(existing, policy) {
			if err := s.rejectSupersededAgentUpdateApprovals(policy.NodeID, "", s.now()); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
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
	if err := s.rejectSupersededAgentUpdateApprovals(nodeID, "", s.now()); err != nil {
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
			err = apiError(model.APIErrorAgentUpdateNoop, err.Error())
		}
		writeError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, toApprovalView(approval))
}

func (s *Server) handleAgentUpdateReleaseInfo(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	info, err := s.fetchAgentReleaseInfo()
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

var (
	errAgentUpdateNoop          = errors.New("agent already reports the target version")
	errAgentUpdateApprovalStale = errors.New("agent update policy changed since this approval was planned")
)

const (
	agentUpdateApprovalStaleCode   = model.ApprovalStaleAgentUpdatePolicyChanged
	agentUpdateApprovalStaleReason = "agent update policy changed since this approval was planned; re-plan before approving"
)

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
	binaryRaw := strings.TrimSpace(req.BinaryURL)
	shaRaw := strings.TrimSpace(req.SHA256)
	officialRelease := binaryRaw == "" && shaRaw == ""
	if (binaryRaw == "") != (shaRaw == "") {
		return model.AgentUpdatePolicy{}, errors.New("binary_url and sha256 must be provided together, or both left empty for the official release")
	}
	if officialRelease {
		target, err := normalizeOfficialAgentTarget(out.TargetVersion)
		if err != nil {
			return model.AgentUpdatePolicy{}, err
		}
		out.TargetVersion = target
	} else if !agentVersionRe.MatchString(out.TargetVersion) {
		return model.AgentUpdatePolicy{}, errors.New("target_version is required and must be an auditable version string")
	}
	if officialRelease {
		out.BinaryURL = ""
		out.SHA256 = ""
	} else {
		binaryURL, err := normalizeAgentUpdateURL(req.BinaryURL)
		if err != nil {
			return model.AgentUpdatePolicy{}, err
		}
		out.BinaryURL = binaryURL
		out.SHA256 = strings.ToLower(strings.TrimSpace(req.SHA256))
		if !agentSHA256Re.MatchString(out.SHA256) {
			return model.AgentUpdatePolicy{}, errors.New("sha256 must be a 64-character lowercase hex digest")
		}
	}
	out.InstallPath = strings.TrimSpace(req.InstallPath)
	if out.InstallPath == "" {
		out.InstallPath = defaultAgentInstallPath
	}
	out.InstallPath = normalizeDefaultAgentInstallPath(out.InstallPath)
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

func normalizeOfficialAgentTarget(raw string) (string, error) {
	target := strings.TrimSpace(raw)
	if target == "" || strings.EqualFold(target, agentReleaseLatest) {
		return agentReleaseLatest, nil
	}
	if strings.HasPrefix(target, "v") && len(target) > 1 {
		target = strings.TrimPrefix(target, "v")
	}
	if !agentVersionRe.MatchString(target) {
		return "", errors.New("target_version must be latest or an auditable version string")
	}
	return target, nil
}

func agentUpdatePolicyApprovalBindingChanged(before, after model.AgentUpdatePolicy) bool {
	return before.Enabled != after.Enabled ||
		before.TargetVersion != after.TargetVersion ||
		before.BinaryURL != after.BinaryURL ||
		before.SHA256 != after.SHA256 ||
		before.InstallPath != after.InstallPath ||
		before.ServiceName != after.ServiceName
}

func normalizeDefaultAgentInstallPath(value string) string {
	switch strings.TrimSpace(value) {
	case "", previousDefaultAgentInstallPath:
		return defaultAgentInstallPath
	default:
		return value
	}
}

func isAgentVersionDowngrade(current, target string) bool {
	cmp, ok := compareAgentVersions(current, target)
	return ok && cmp > 0
}

func compareAgentVersions(a, b string) (int, bool) {
	left, okLeft := parseAgentVersionParts(a)
	right, okRight := parseAgentVersionParts(b)
	if !okLeft || !okRight {
		return 0, false
	}
	maxLen := len(left)
	if len(right) > maxLen {
		maxLen = len(right)
	}
	for i := 0; i < maxLen; i++ {
		var lv, rv int
		if i < len(left) {
			lv = left[i]
		}
		if i < len(right) {
			rv = right[i]
		}
		if lv > rv {
			return 1, true
		}
		if lv < rv {
			return -1, true
		}
	}
	return 0, true
}

func parseAgentVersionParts(raw string) ([]int, bool) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "v")
	if raw == "" {
		return nil, false
	}
	parts := strings.Split(raw, ".")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, false
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return nil, false
		}
		out = append(out, value)
	}
	return out, true
}

func normalizeAgentReleaseRepo(raw string) (string, error) {
	repo := strings.TrimSpace(raw)
	if repo == "" {
		repo = defaultAgentReleaseRepo
	}
	if !agentRepoRe.MatchString(repo) {
		return "", errors.New("agent release repo must be owner/repo")
	}
	return repo, nil
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
	if u.RawQuery != "" || u.ForceQuery {
		return "", errors.New("binary_url must not contain a query")
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
	payload, err := s.agentUpdatePayloadForPolicy(node, policy)
	if err != nil {
		return model.Approval{}, err
	}
	if !force && isAgentVersionDowngrade(strings.TrimSpace(node.AgentVersion), payload.TargetVersion) {
		return model.Approval{}, fmt.Errorf("refusing to plan agent downgrade from %s to %s", strings.TrimSpace(node.AgentVersion), payload.TargetVersion)
	}
	if !force && strings.TrimSpace(node.AgentVersion) == payload.TargetVersion {
		if err := s.rejectSupersededAgentUpdateApprovals(nodeID, "", now); err != nil {
			return model.Approval{}, err
		}
		if err := s.markAgentUpdatePolicySatisfied(policy, payload.TargetVersion, now); err != nil {
			return model.Approval{}, err
		}
		return model.Approval{}, errAgentUpdateNoop
	}
	currentAction := agentUpdateApprovalAction(payload)
	if err := s.rejectSupersededAgentUpdateApprovals(nodeID, currentAction, now); err != nil {
		return model.Approval{}, err
	}
	if approval, ok := s.openAgentUpdateApproval(payload); ok {
		return approval, nil
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
	if payload.TargetVersion != "" {
		policy.LastPlannedVersion = payload.TargetVersion
	}
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

func (s *Server) markAgentUpdatePolicySatisfied(policy model.AgentUpdatePolicy, targetVersion string, now time.Time) error {
	targetVersion = strings.TrimSpace(targetVersion)
	changed := false
	if strings.TrimSpace(policy.LastError) != "" {
		policy.LastError = ""
		changed = true
	}
	if targetVersion != "" && policy.LastAppliedVersion != targetVersion {
		policy.LastAppliedVersion = targetVersion
		if now.IsZero() {
			now = s.now()
		}
		policy.LastAppliedAt = now.UTC()
		changed = true
	}
	if !changed {
		return nil
	}
	if now.IsZero() {
		now = s.now()
	}
	policy.UpdatedAt = now.UTC()
	return s.store.UpsertAgentUpdatePolicy(policy)
}

func (s *Server) agentUpdatePayloadForPolicy(node model.Node, policy model.AgentUpdatePolicy) (agentUpdatePayload, error) {
	if _, err := managedAgentUpdateOS(node); err != nil {
		return agentUpdatePayload{}, err
	}
	policy.NodeID = strings.TrimSpace(policy.NodeID)
	if policy.NodeID == "" {
		return agentUpdatePayload{}, errors.New("agent update policy is missing node_id")
	}
	if policy.InstallPath == "" {
		policy.InstallPath = defaultAgentInstallPath
	}
	policy.InstallPath = normalizeDefaultAgentInstallPath(policy.InstallPath)
	if err := validateAgentInstallPath(policy.InstallPath); err != nil {
		return agentUpdatePayload{}, err
	}
	if policy.ServiceName == "" {
		policy.ServiceName = defaultAgentServiceName
	}
	if !agentServiceRe.MatchString(policy.ServiceName) {
		return agentUpdatePayload{}, errors.New("invalid service_name")
	}
	binaryRaw := strings.TrimSpace(policy.BinaryURL)
	shaRaw := strings.TrimSpace(policy.SHA256)
	if (binaryRaw == "") != (shaRaw == "") {
		return agentUpdatePayload{}, errors.New("binary_url and sha256 must be provided together, or both left empty for the official release")
	}
	if binaryRaw != "" {
		normalized, err := sNormalizeAgentUpdatePayload(policy)
		if err != nil {
			return agentUpdatePayload{}, err
		}
		return agentUpdatePayload{
			NodeID:         normalized.NodeID,
			CurrentVersion: strings.TrimSpace(node.AgentVersion),
			TargetVersion:  normalized.TargetVersion,
			BinaryURL:      normalized.BinaryURL,
			SHA256:         normalized.SHA256,
			InstallPath:    normalized.InstallPath,
			ServiceName:    normalized.ServiceName,
		}, nil
	}
	return s.resolveOfficialAgentUpdatePayload(node, policy)
}

func (s *Server) resolveOfficialAgentUpdatePayload(node model.Node, policy model.AgentUpdatePolicy) (agentUpdatePayload, error) {
	target, tag, err := s.officialAgentTargetAndTag(policy.TargetVersion)
	if err != nil {
		return agentUpdatePayload{}, err
	}
	artifact, err := agentArtifactForNode(node)
	if err != nil {
		return agentUpdatePayload{}, err
	}
	base := fmt.Sprintf("https://github.com/%s/releases/download/%s", s.agentReleaseRepo, url.PathEscape(tag))
	sums, err := s.fetchAgentReleaseText(base + "/SHA256SUMS")
	if err != nil {
		return agentUpdatePayload{}, err
	}
	sha, ok := shaFromSums(sums, artifact)
	if !ok {
		return agentUpdatePayload{}, fmt.Errorf("official release %s does not publish checksum for %s", tag, artifact)
	}
	return agentUpdatePayload{
		NodeID:         policy.NodeID,
		CurrentVersion: strings.TrimSpace(node.AgentVersion),
		TargetVersion:  target,
		BinaryURL:      base + "/" + url.PathEscape(artifact),
		SHA256:         sha,
		InstallPath:    policy.InstallPath,
		ServiceName:    policy.ServiceName,
	}, nil
}

func (s *Server) officialAgentTargetAndTag(raw string) (targetVersion string, tag string, err error) {
	target := strings.TrimSpace(raw)
	if target == "" || strings.EqualFold(target, agentReleaseLatest) {
		tag, err := s.fetchLatestAgentReleaseTag()
		if err != nil {
			return "", "", err
		}
		return strings.TrimPrefix(tag, "v"), tag, nil
	}
	if strings.HasPrefix(target, "v") {
		tag = target
		target = strings.TrimPrefix(target, "v")
	} else {
		tag = "v" + target
	}
	if !agentVersionRe.MatchString(target) {
		return "", "", errors.New("target_version is required and must be an auditable version string")
	}
	return target, tag, nil
}

func (s *Server) fetchLatestAgentReleaseTag() (string, error) {
	tag, err := s.fetchCachedAgentReleaseValue("latest-tag:"+s.agentReleaseRepo, func() (string, error) {
		return s.fetchLatestAgentReleaseRedirectTag("https://github.com/" + s.agentReleaseRepo + "/releases/latest")
	})
	if err != nil {
		return "", err
	}
	tag = strings.TrimSpace(tag)
	if tag == "" || !strings.HasPrefix(tag, "v") {
		return "", errors.New("latest agent release has no v* tag")
	}
	return tag, nil
}

func (s *Server) fetchLatestAgentReleaseRedirectTag(rawURL string) (string, error) {
	client := &http.Client{Timeout: 12 * time.Second}
	req, err := http.NewRequest(http.MethodHead, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "lattice-server-agent-update")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch latest agent release redirect: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("fetch latest agent release redirect: %s", resp.Status)
	}
	if resp.Request == nil || resp.Request.URL == nil {
		return "", errors.New("latest agent release redirect did not expose final URL")
	}
	parts := strings.Split(strings.Trim(resp.Request.URL.EscapedPath(), "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "tag" {
			tag, err := url.PathUnescape(parts[i+1])
			if err != nil {
				return "", fmt.Errorf("decode latest agent release tag: %w", err)
			}
			return strings.TrimSpace(tag), nil
		}
	}
	return "", fmt.Errorf("latest agent release redirect did not resolve to a release tag: %s", resp.Request.URL.String())
}

func (s *Server) fetchAgentReleaseInfo() (agentReleaseInfoView, error) {
	tag, err := s.fetchLatestAgentReleaseTag()
	if err != nil {
		return agentReleaseInfoView{}, err
	}
	base := fmt.Sprintf("https://github.com/%s/releases/download/%s", s.agentReleaseRepo, url.PathEscape(tag))
	sums, err := s.fetchAgentReleaseText(base + "/SHA256SUMS")
	if err != nil {
		return agentReleaseInfoView{}, err
	}
	sha := map[string]string{}
	for _, line := range strings.Split(sums, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		sum := strings.ToLower(fields[0])
		artifact := fields[1]
		if !agentSHA256Re.MatchString(sum) {
			continue
		}
		sha[artifact] = sum
	}
	artifacts := make([]string, 0, len(sha))
	for artifact := range sha {
		artifacts = append(artifacts, artifact)
	}
	sort.Strings(artifacts)
	return agentReleaseInfoView{
		Repo:          s.agentReleaseRepo,
		LatestTag:     tag,
		LatestVersion: strings.TrimPrefix(tag, "v"),
		ReleaseURL:    "https://github.com/" + s.agentReleaseRepo + "/releases/tag/" + url.PathEscape(tag),
		Artifacts:     artifacts,
		SHA256:        sha,
		FetchedAt:     s.now(),
	}, nil
}

func (s *Server) fetchAgentReleaseText(rawURL string) (string, error) {
	return s.fetchCachedAgentReleaseValue("text:"+rawURL, func() (string, error) {
		return s.fetchAgentReleaseTextUncached(rawURL)
	})
}

func (s *Server) fetchCachedAgentReleaseValue(key string, fetch func() (string, error)) (string, error) {
	now := s.now()
	s.agentReleaseCacheMu.Lock()
	if s.agentReleaseCache != nil {
		if cached, ok := s.agentReleaseCache[key]; ok && now.Before(cached.expiresAt) {
			s.agentReleaseCacheMu.Unlock()
			return cached.body, cached.err
		}
	}
	s.agentReleaseCacheMu.Unlock()

	body, err := fetch()
	ttl := agentReleaseSuccessCacheTTL
	if err != nil {
		ttl = agentReleaseErrorCacheTTL
	}
	s.agentReleaseCacheMu.Lock()
	if s.agentReleaseCache == nil {
		s.agentReleaseCache = map[string]agentReleaseCacheEntry{}
	}
	s.agentReleaseCache[key] = agentReleaseCacheEntry{body: body, err: err, expiresAt: now.Add(ttl)}
	s.agentReleaseCacheMu.Unlock()
	return body, err
}

func (s *Server) fetchAgentReleaseTextUncached(rawURL string) (string, error) {
	client := &http.Client{Timeout: 12 * time.Second}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json, text/plain")
	req.Header.Set("User-Agent", "lattice-server-agent-update")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch agent release metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("fetch agent release metadata: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, agentReleaseMetadataLimit+1))
	if err != nil {
		return "", err
	}
	if len(data) > agentReleaseMetadataLimit {
		return "", fmt.Errorf("fetch agent release metadata: response exceeds %d bytes", agentReleaseMetadataLimit)
	}
	return string(data), nil
}

func shaFromSums(sums string, artifact string) (string, bool) {
	for _, line := range strings.Split(sums, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[1] == artifact && agentSHA256Re.MatchString(strings.ToLower(fields[0])) {
			return strings.ToLower(fields[0]), true
		}
	}
	return "", false
}

func agentArtifactForNode(node model.Node) (string, error) {
	osName, err := managedAgentUpdateOS(node)
	if err != nil {
		return "", err
	}
	arch := strings.ToLower(strings.TrimSpace(node.HostFacts.Arch))
	switch arch {
	case "", "x86_64":
		arch = "amd64"
	case "aarch64":
		arch = "arm64"
	}
	switch arch {
	case "amd64", "arm64":
	default:
		return "", fmt.Errorf("official lattice-agent releases do not support arch %q", arch)
	}
	return "lattice-agent-" + osName + "-" + arch, nil
}

func managedAgentUpdateOS(node model.Node) (string, error) {
	osName := strings.ToLower(strings.TrimSpace(node.HostFacts.OS))
	if osName == "" {
		platform := strings.ToLower(strings.TrimSpace(node.HostFacts.Platform))
		if strings.Contains(platform, "darwin") || strings.Contains(platform, "mac") {
			osName = "darwin"
		} else {
			osName = "linux"
		}
	}
	switch osName {
	case "linux":
		return osName, nil
	case "darwin":
		return "", errors.New("server-controlled agent updates currently require linux/systemd nodes; darwin release artifacts are manual-only")
	default:
		return "", fmt.Errorf("server-controlled agent updates currently require linux/systemd nodes; got os %q", osName)
	}
}

func (s *Server) openAgentUpdateApproval(payload agentUpdatePayload) (model.Approval, bool) {
	action := agentUpdateApprovalAction(payload)
	for _, approval := range s.store.Approvals() {
		if approval.Plugin != agentUpdatePlugin || approval.NodeID != payload.NodeID || approval.Action != action {
			continue
		}
		if approval.Status == model.ApprovalPending || approval.Status == model.ApprovalApproved {
			return approval, true
		}
	}
	return model.Approval{}, false
}

func (s *Server) hasActiveTaskForApproval(approvalID string) bool {
	_, ok := s.activeTaskApprovalIDs()[approvalID]
	return ok
}

func (s *Server) activeTaskApprovalIDs() map[string]struct{} {
	active := map[string]struct{}{}
	for _, task := range s.store.Tasks() {
		if task.ApprovalID == "" {
			continue
		}
		if task.Status == model.TaskQueued || task.Status == model.TaskLeased {
			active[task.ApprovalID] = struct{}{}
		}
	}
	return active
}

func renderAgentUpdatePlan(node model.Node, payload agentUpdatePayload, mode string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "plugin: agentupdate\n")
	fmt.Fprintf(&b, "mode: %s\n", mode)
	fmt.Fprintf(&b, "node_id: %s\n", payload.NodeID)
	if node.Name != "" {
		fmt.Fprintf(&b, "node_name: %s\n", node.Name)
	}
	currentVersion := strings.TrimSpace(payload.CurrentVersion)
	if currentVersion == "" {
		currentVersion = strings.TrimSpace(node.AgentVersion)
	}
	fmt.Fprintf(&b, "current_version: %s\n", currentVersion)
	fmt.Fprintf(&b, "target_version: %s\n", payload.TargetVersion)
	fmt.Fprintf(&b, "binary_url: %s\n", payload.BinaryURL)
	fmt.Fprintf(&b, "sha256: %s\n", payload.SHA256)
	fmt.Fprintf(&b, "install_path: %s\n", payload.InstallPath)
	fmt.Fprintf(&b, "service_name: %s\n", payload.ServiceName)
	fmt.Fprintf(&b, "\nSafety:\n")
	fmt.Fprintf(&b, "- download is HTTPS-only and verified against the pinned SHA-256 digest\n")
	fmt.Fprintf(&b, "- binary is installed atomically with a timestamped backup\n")
	fmt.Fprintf(&b, "- service restart is delayed so the current agent can post the task result\n")
	fmt.Fprintf(&b, "- default/legacy install targets follow the running lattice-agent path and default service may follow the running systemd unit\n")
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
	payload.CurrentVersion = strings.TrimSpace(payload.CurrentVersion)
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
		NodeID:         payload.NodeID,
		CurrentVersion: payload.CurrentVersion,
		TargetVersion:  normalized.TargetVersion,
		BinaryURL:      normalized.BinaryURL,
		SHA256:         normalized.SHA256,
		InstallPath:    normalized.InstallPath,
		ServiceName:    normalized.ServiceName,
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
	policy.InstallPath = normalizeDefaultAgentInstallPath(policy.InstallPath)
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
	node, ok := s.store.Node(approval.NodeID)
	if !ok {
		return fmt.Errorf("agent update node %q not found; re-plan before approving", approval.NodeID)
	}
	current, err := s.agentUpdatePayloadForPolicy(node, policy)
	if err != nil {
		return fmt.Errorf("agent update policy %q is invalid; re-plan before approving: %w", approval.NodeID, err)
	}
	if current != payload {
		return fmt.Errorf("%w; %s; re-plan before approving", errAgentUpdateApprovalStale, agentUpdatePayloadChangeSummary(payload, current))
	}
	return nil
}

func agentUpdatePayloadChangeSummary(planned, current agentUpdatePayload) string {
	changes := []string{}
	if planned.CurrentVersion != current.CurrentVersion {
		changes = append(changes, fmt.Sprintf("current_version planned=%s current=%s", planned.CurrentVersion, current.CurrentVersion))
	}
	if planned.TargetVersion != current.TargetVersion {
		changes = append(changes, fmt.Sprintf("target_version planned=%s current=%s", planned.TargetVersion, current.TargetVersion))
	}
	if planned.BinaryURL != current.BinaryURL {
		changes = append(changes, fmt.Sprintf("binary_url planned=%s current=%s", planned.BinaryURL, current.BinaryURL))
	}
	if planned.SHA256 != current.SHA256 {
		changes = append(changes, fmt.Sprintf("sha256 planned=%s current=%s", shortDigest(planned.SHA256), shortDigest(current.SHA256)))
	}
	if planned.InstallPath != current.InstallPath {
		changes = append(changes, fmt.Sprintf("install_path planned=%s current=%s", planned.InstallPath, current.InstallPath))
	}
	if planned.ServiceName != current.ServiceName {
		changes = append(changes, fmt.Sprintf("service_name planned=%s current=%s", planned.ServiceName, current.ServiceName))
	}
	if len(changes) == 0 {
		return "resolved update payload changed"
	}
	return "changed fields: " + strings.Join(changes, "; ")
}

func shortDigest(value string) string {
	if len(value) <= 16 {
		return value
	}
	return value[:16] + "..."
}

func (s *Server) rejectSupersededAgentUpdateApprovals(nodeID, currentAction string, now time.Time) error {
	activeApprovals := s.activeTaskApprovalIDs()
	for _, approval := range s.store.Approvals() {
		if approval.Plugin != agentUpdatePlugin || approval.NodeID != nodeID {
			continue
		}
		if currentAction != "" && approval.Action == currentAction {
			continue
		}
		if !agentUpdateApprovalCanAutoReject(approval, activeApprovals) {
			continue
		}
		approval.Status = model.ApprovalRejected
		approval.Reason = s.agentUpdateApprovalStaleReason(approval)
		approval.UpdatedAt = now
		if err := s.store.UpsertApproval(approval); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) rejectAgentUpdateApproval(approval model.Approval, now time.Time) error {
	return s.rejectAgentUpdateApprovalWithReason(approval, s.agentUpdateApprovalStaleReason(approval), now)
}

func (s *Server) rejectAgentUpdateApprovalWithReason(approval model.Approval, reason string, now time.Time) error {
	if !agentUpdateApprovalCanAutoReject(approval, s.activeTaskApprovalIDs()) {
		return nil
	}
	approval.Status = model.ApprovalRejected
	approval.Reason = strings.TrimSpace(reason)
	if approval.Reason == "" {
		approval.Reason = agentUpdateApprovalStaleReason
	}
	approval.UpdatedAt = now
	return s.store.UpsertApproval(approval)
}

func (s *Server) rejectLocallyStaleAgentUpdateApprovals(now time.Time) error {
	activeApprovals := s.activeTaskApprovalIDs()
	for _, approval := range s.store.Approvals() {
		if !agentUpdateApprovalCanAutoReject(approval, activeApprovals) {
			continue
		}
		if stale, reason := s.agentUpdateApprovalLocalStaleness(approval); stale {
			if err := s.rejectAgentUpdateApprovalWithReason(approval, reason, now); err != nil {
				return err
			}
		}
	}
	return nil
}

func agentUpdateApprovalCanAutoReject(approval model.Approval, activeApprovals map[string]struct{}) bool {
	if approval.Plugin != agentUpdatePlugin {
		return false
	}
	if approval.Status == model.ApprovalPending {
		return true
	}
	_, active := activeApprovals[approval.ID]
	return approval.Status == model.ApprovalApproved && !active
}

func (s *Server) agentUpdateApprovalStaleReason(approval model.Approval) string {
	_, reason := s.agentUpdateApprovalLocalStaleness(approval)
	return reason
}

func (s *Server) dismissibleAgentUpdateApprovalReason(approval model.Approval) (string, bool) {
	reason := strings.TrimSpace(approval.Reason)
	if strings.HasPrefix(reason, errAgentUpdateApprovalStale.Error()) {
		return reason, true
	}
	stale, reason := s.agentUpdateApprovalLocalStaleness(approval)
	if stale {
		return reason, true
	}
	return "", false
}

func agentUpdateApprovalStaleReasonWithDetails(details string) string {
	details = strings.TrimSpace(details)
	if details == "" {
		return agentUpdateApprovalStaleReason
	}
	return fmt.Sprintf("%s; %s; re-plan before approving", errAgentUpdateApprovalStale.Error(), details)
}

func (s *Server) agentUpdateApprovalLocalStaleness(approval model.Approval) (bool, string) {
	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		return true, agentUpdateApprovalStaleReasonWithDetails("approval payload is invalid")
	}
	policy, ok := s.store.AgentUpdatePolicy(approval.NodeID)
	if !ok || !policy.Enabled {
		if !ok {
			return true, agentUpdateApprovalStaleReasonWithDetails(fmt.Sprintf("policy %q not found", approval.NodeID))
		}
		return true, agentUpdateApprovalStaleReasonWithDetails(fmt.Sprintf("policy %q is disabled", approval.NodeID))
	}
	node, ok := s.store.Node(approval.NodeID)
	if !ok {
		return true, agentUpdateApprovalStaleReasonWithDetails(fmt.Sprintf("node %q not found", approval.NodeID))
	}
	binaryURL := strings.TrimSpace(policy.BinaryURL)
	sha256 := strings.TrimSpace(policy.SHA256)
	if binaryURL != "" || sha256 != "" {
		if binaryURL == "" || sha256 == "" {
			return true, agentUpdateApprovalStaleReasonWithDetails("binary_url and sha256 are no longer provided together")
		}
		current, err := s.agentUpdatePayloadForPolicy(node, policy)
		if err != nil {
			return true, agentUpdateApprovalStaleReasonWithDetails("current policy is invalid: " + err.Error())
		}
		if current != payload {
			return true, agentUpdateApprovalStaleReasonWithDetails(agentUpdatePayloadChangeSummary(payload, current))
		}
		return false, ""
	}
	current := payload
	changed := false
	if policy.InstallPath == "" {
		policy.InstallPath = defaultAgentInstallPath
	}
	policy.InstallPath = normalizeDefaultAgentInstallPath(policy.InstallPath)
	if err := validateAgentInstallPath(policy.InstallPath); err != nil {
		return true, agentUpdateApprovalStaleReasonWithDetails("install_path is invalid: " + err.Error())
	}
	if policy.InstallPath != payload.InstallPath {
		current.InstallPath = policy.InstallPath
		changed = true
	}
	if policy.ServiceName == "" {
		policy.ServiceName = defaultAgentServiceName
	}
	if !agentServiceRe.MatchString(policy.ServiceName) {
		return true, agentUpdateApprovalStaleReasonWithDetails("service_name is invalid")
	}
	if policy.ServiceName != payload.ServiceName {
		current.ServiceName = policy.ServiceName
		changed = true
	}
	target, err := normalizeOfficialAgentTarget(policy.TargetVersion)
	if err != nil {
		return true, agentUpdateApprovalStaleReasonWithDetails("target_version is invalid: " + err.Error())
	}
	if target == agentReleaseLatest {
		resolved := strings.TrimSpace(policy.LastPlannedVersion)
		if strings.HasPrefix(resolved, "v") {
			resolved = strings.TrimPrefix(resolved, "v")
		}
		if resolved != "" && resolved != payload.TargetVersion {
			current.TargetVersion = resolved
			changed = true
		}
	} else if target != payload.TargetVersion {
		current.TargetVersion = target
		changed = true
	}
	if changed {
		return true, agentUpdateApprovalStaleReasonWithDetails(agentUpdatePayloadChangeSummary(payload, current))
	}
	return false, ""
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
		"DEFAULT_TARGET=" + shellQuote(defaultAgentInstallPath) + "\n" +
		"OLD_DEFAULT_TARGET=" + shellQuote(previousDefaultAgentInstallPath) + "\n" +
		"LEGACY_TARGET=" + shellQuote(legacyAgentInstallPath) + "\n" +
		"DEFAULT_SERVICE=" + shellQuote(defaultAgentServiceName) + "\n" +
		"RUNNING_AGENT=\"\"\n" +
		"if [ -r \"/proc/$PPID/exe\" ]; then\n" +
		"  RUNNING_AGENT=$(readlink -f \"/proc/$PPID/exe\" 2>/dev/null || readlink \"/proc/$PPID/exe\" 2>/dev/null || true)\n" +
		"fi\n" +
		"case \"$RUNNING_AGENT\" in\n" +
		"  */lattice-agent)\n" +
		"    if [ \"$TARGET\" = \"$DEFAULT_TARGET\" ] || [ \"$TARGET\" = \"$OLD_DEFAULT_TARGET\" ] || [ \"$TARGET\" = \"$LEGACY_TARGET\" ]; then TARGET=\"$RUNNING_AGENT\"; fi\n" +
		"    ;;\n" +
		"esac\n" +
		"RUNNING_SERVICE=\"\"\n" +
		"if [ -r \"/proc/$PPID/cgroup\" ]; then\n" +
		"  RUNNING_SERVICE=$(sed -n 's#.*system\\.slice/\\([^/]*\\.service\\).*#\\1#p' \"/proc/$PPID/cgroup\" | head -n 1)\n" +
		"fi\n" +
		"if [ -z \"$RUNNING_SERVICE\" ] && [ -r /proc/self/cgroup ]; then\n" +
		"  RUNNING_SERVICE=$(sed -n 's#.*system\\.slice/\\([^/]*\\.service\\).*#\\1#p' /proc/self/cgroup | head -n 1)\n" +
		"fi\n" +
		"if [ -n \"$RUNNING_SERVICE\" ] && [ \"$SERVICE\" = \"$DEFAULT_SERVICE\" ]; then SERVICE=\"$RUNNING_SERVICE\"; fi\n" +
		"echo \"lattice agent update: effective target=$TARGET service=$SERVICE\"\n" +
		"if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then\n" +
		"  echo 'lattice agent update: systemd is required for managed agent updates; refusing to install without a restart manager' >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"if ! command -v systemd-run >/dev/null 2>&1; then\n" +
		"  echo 'lattice agent update: systemd-run is required to schedule a verified delayed restart' >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"systemctl daemon-reload\n" +
		"if ! systemctl status \"$SERVICE\" >/dev/null 2>&1 && ! systemctl --no-legend list-unit-files \"$SERVICE\" 2>/dev/null | awk '{print $1}' | grep -Fxq \"$SERVICE\"; then\n" +
		"  echo \"lattice agent update: service $SERVICE not found before installing $TARGET\" >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"WORK=$(mktemp -d \"${TMPDIR:-/tmp}/lattice-agent-update.XXXXXX\")\n" +
		"cleanup() { rm -rf \"$WORK\"; }\n" +
		"trap cleanup EXIT\n" +
		"CANDIDATE=\"$WORK/lattice-agent\"\n" +
		"if command -v curl >/dev/null 2>&1; then\n" +
		"  curl -fsSL --proto '=https' --tlsv1.2 -o \"$CANDIDATE\" \"$URL\"\n" +
		"elif command -v wget >/dev/null 2>&1; then\n" +
		"  wget --https-only -qO \"$CANDIDATE\" \"$URL\"\n" +
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
		"CANDIDATE_VERSION=$(\"$CANDIDATE\" -version)\n" +
		"if [ \"$CANDIDATE_VERSION\" != \"$TARGET_VERSION\" ]; then\n" +
		"  echo \"lattice agent update: version mismatch expected=$TARGET_VERSION actual=$CANDIDATE_VERSION\" >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"mkdir -p \"$(dirname \"$TARGET\")\"\n" +
		"if [ -e \"$TARGET\" ]; then\n" +
		"  cp -p \"$TARGET\" \"$TARGET.bak.$(date +%Y%m%d%H%M%S)\"\n" +
		"fi\n" +
		"install -m 0755 \"$CANDIDATE\" \"$TARGET.new\"\n" +
		"mv \"$TARGET.new\" \"$TARGET\"\n" +
		"systemctl daemon-reload\n" +
		"RESTART_UNIT=\"lattice-agent-delayed-restart-$(date +%Y%m%d%H%M%S)-$$\"\n" +
		"systemd-run --unit=\"$RESTART_UNIT\" --on-active=3s /bin/systemctl restart \"$SERVICE\" >/dev/null\n" +
		"echo \"lattice agent update: installed $TARGET_VERSION and scheduled $SERVICE restart via $RESTART_UNIT\"\n", nil
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
		reason := agentUpdateAwaitingConfirmationReason(payload.TargetVersion)
		policy.LastError = reason
		approval.Status = model.ApprovalApproved
		approval.Reason = reason
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   approval.NodeID,
			Action:   "agent.update.awaiting_confirmation",
			Decision: "allow",
			Metadata: map[string]string{"target_version": payload.TargetVersion, "approval_id": approval.ID},
		})
	} else {
		policy.LastError = taskFailureSummary(result)
		approval.Status = model.ApprovalRejected
		approval.Reason = policy.LastError
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

func agentUpdateAwaitingConfirmationReason(targetVersion string) string {
	targetVersion = strings.TrimSpace(targetVersion)
	if targetVersion == "" {
		return agentUpdateAwaitingPrefix
	}
	return agentUpdateAwaitingPrefix + ": " + targetVersion
}

func isAgentUpdateAwaitingConfirmation(approval model.Approval) bool {
	return approval.Plugin == agentUpdatePlugin &&
		approval.Status == model.ApprovalApproved &&
		strings.HasPrefix(strings.TrimSpace(approval.Reason), agentUpdateAwaitingPrefix)
}

func (s *Server) reconcileAgentUpdateHeartbeat(r *http.Request, nodeID, version string, seenAt time.Time) error {
	nodeID = strings.TrimSpace(nodeID)
	version = strings.TrimSpace(version)
	if nodeID == "" || version == "" {
		return nil
	}
	if seenAt.IsZero() {
		seenAt = s.now().UTC()
	}
	for _, approval := range s.store.Approvals() {
		if approval.NodeID != nodeID || !isAgentUpdateAwaitingConfirmation(approval) {
			continue
		}
		payload, err := agentUpdatePayloadFromApproval(approval)
		if err != nil || payload.TargetVersion != version {
			continue
		}
		policy, ok := s.store.AgentUpdatePolicy(nodeID)
		if !ok {
			policy = model.AgentUpdatePolicy{NodeID: nodeID}
		}
		policy.LastAppliedVersion = payload.TargetVersion
		policy.LastAppliedAt = seenAt.UTC()
		policy.LastError = ""
		approval.Status = model.ApprovalApplied
		approval.Reason = ""
		approval.UpdatedAt = seenAt.UTC()
		if err := s.store.UpsertAgentUpdatePolicy(policy); err != nil {
			return err
		}
		if err := s.store.UpsertApproval(approval); err != nil {
			return err
		}
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   nodeID,
			Action:   "agent.update.applied",
			Decision: "allow",
			Metadata: map[string]string{"target_version": payload.TargetVersion, "approval_id": approval.ID},
		})
	}
	return nil
}
