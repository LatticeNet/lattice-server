package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/ddns"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/network"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/selfdns"
)

var dnsLabelRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

const (
	selfDNSApplyAction       = "apply-config"
	selfDNSApplyActionPrefix = selfDNSApplyAction + ":"
)

type dnsDeploymentView struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	NodeID           string          `json:"node_id"`
	NodeName         string          `json:"node_name,omitempty"`
	Engine           string          `json:"engine"`
	ListenPort       int             `json:"listen_port"`
	EnableUDP        bool            `json:"enable_udp"`
	EnableTCP        bool            `json:"enable_tcp"`
	Exposure         string          `json:"exposure"`
	Zones            []model.DNSZone `json:"zones"`
	Hostname         string          `json:"hostname,omitempty"`
	PublishIPv4      bool            `json:"publish_ipv4"`
	PublishIPv6      bool            `json:"publish_ipv6"`
	RecordTTL        int             `json:"record_ttl,omitempty"`
	DDNSProfileID    string          `json:"ddns_profile_id,omitempty"`
	HasCredential    bool            `json:"has_credential"`
	Status           string          `json:"status"`
	EngineVersion    string          `json:"engine_version,omitempty"`
	LastIPv4         string          `json:"last_ipv4,omitempty"`
	LastIPv6         string          `json:"last_ipv6,omitempty"`
	LastAppliedAt    time.Time       `json:"last_applied_at,omitempty"`
	LastError        string          `json:"last_error,omitempty"`
	LastPublishedAt  time.Time       `json:"last_published_at,omitempty"`
	LastPublishError string          `json:"last_publish_error,omitempty"`
	Disabled         bool            `json:"disabled,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

func (s *Server) handleDNSDeployments(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		deployments := s.store.DNSDeployments()
		views := make([]dnsDeploymentView, 0, len(deployments))
		for _, dep := range deployments {
			if rbac.Allows(p.Principal, "dns:admin", dep.NodeID) {
				views = append(views, s.toDNSDeploymentView(dep))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"deployments": views})
	case http.MethodPost:
		var req model.DNSDeployment
		if !decodeClientJSON(w, r, &req) {
			return
		}
		req.ID = strings.TrimSpace(req.ID)
		req.NodeID = strings.TrimSpace(req.NodeID)
		existing, hadExisting := model.DNSDeployment{}, false
		if req.ID != "" {
			existing, hadExisting = s.store.DNSDeployment(req.ID)
			if !hadExisting {
				writeError(w, http.StatusNotFound, errors.New("dns deployment not found"))
				return
			}
			if !s.requireNodeScope(w, p, "dns:admin", existing.NodeID) {
				return
			}
		}
		if !s.requireNodeScope(w, p, "dns:admin", req.NodeID) {
			return
		}
		if _, ok := s.store.Node(req.NodeID); !ok {
			writeError(w, http.StatusNotFound, errors.New("node not found"))
			return
		}
		dep, err := s.normalizeDNSDeployment(req, existing, hadExisting)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.store.UpsertDNSDeployment(dep); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if stored, ok := s.store.DNSDeployment(dep.ID); ok {
			dep = stored
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:     id.New("audit"),
			NodeID: dep.NodeID,
			Action: "dns.deployment.upsert",
			Scope:  "dns:admin",
			Metadata: map[string]string{
				"dns_id":   dep.ID,
				"engine":   dep.Engine,
				"exposure": dep.Exposure,
			},
		})
		writeJSON(w, http.StatusOK, s.toDNSDeploymentView(dep))
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleDeleteDNSDeployment(w http.ResponseWriter, r *http.Request, p principal) {
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
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	nodeID := ""
	if dep, ok := s.store.DNSDeployment(req.ID); ok {
		nodeID = dep.NodeID
		if !s.requireNodeScope(w, p, "dns:admin", dep.NodeID) {
			return
		}
	}
	if err := s.store.DeleteDNSDeployment(req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:       id.New("audit"),
		NodeID:   nodeID,
		Action:   "dns.deployment.delete",
		Scope:    "dns:admin",
		Metadata: map[string]string{"dns_id": req.ID},
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDNSPlan(w http.ResponseWriter, r *http.Request, p principal) {
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
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	dep, ok := s.store.DNSDeployment(req.ID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("dns deployment not found"))
		return
	}
	node, ok := s.store.Node(dep.NodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	if !s.requireNodeScope(w, p, "dns:admin", dep.NodeID) {
		return
	}
	// DNS plans include the composed lattice_guard ruleset, so callers must also
	// be allowed to view network plans for the same node.
	if !s.requireNodeScope(w, p, "network:plan", dep.NodeID) {
		return
	}

	cfg, err := selfdns.GenerateConfig(dep, selfdns.RenderOptions{MeshBindIP: node.WireGuardIP})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	planInput := network.NFTPlan{}
	inputSource := "default"
	if stored, ok := s.store.NFTInputs(dep.NodeID); ok {
		planInput = nftPlanFromStoredInputs(stored)
		inputSource = "stored"
	}
	ingressRules, err := s.composeNFTIngressPolicy(dep.NodeID, &planInput, p)
	if err != nil {
		if errors.Is(err, errNFTIngressPolicyReadRequired) {
			writeError(w, http.StatusForbidden, err)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	composed, firewallSummary, err := selfdns.ComposeFirewallPlan(dep, planInput)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	firewallSummary = append([]string{"nft inputs source: " + inputSource}, firewallSummary...)
	if ingressRules > 0 {
		firewallSummary = append(firewallSummary, "ingress netpolicy rules composed: "+strconv.Itoa(ingressRules))
	}
	nftRuleset, err := network.GenerateNFTPlan(composed)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	planText, err := selfdns.RenderApprovalPlanWithOptions(dep, node.Name, cfg, nftRuleset, firewallSummary, selfdns.ApprovalPlanOptions{CoreDNSBinary: s.coreDNSBinary})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	approval := model.Approval{
		ID:        id.New("approval"),
		NodeID:    dep.NodeID,
		Plugin:    "selfdns",
		Action:    selfDNSApprovalAction(dep.ID),
		Plan:      planText,
		Status:    model.ApprovalPending,
		ActorID:   p.ActorID,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.UpsertApproval(approval); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	metadata := map[string]string{
		"approval_id": approval.ID,
		"dns_id":      dep.ID,
		"engine":      dep.Engine,
		"exposure":    dep.Exposure,
		"nft_source":  inputSource,
	}
	if ingressRules > 0 {
		metadata["ingress_rules"] = strconv.Itoa(ingressRules)
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), NodeID: dep.NodeID, Action: "dns.plan", Scope: "dns:admin", Metadata: metadata})
	writeJSON(w, http.StatusOK, approval)
}

func (s *Server) handleDNSPublish(w http.ResponseWriter, r *http.Request, p principal) {
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
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	dep, ok := s.store.DNSDeployment(req.ID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("dns deployment not found"))
		return
	}
	if !s.requireNodeScope(w, p, "dns:admin", dep.NodeID) {
		return
	}
	if dep.Disabled {
		writeError(w, http.StatusBadRequest, errors.New("dns deployment is disabled"))
		return
	}
	node, ok := s.store.Node(dep.NodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	if err := s.publishDNSDeploymentForPrincipal(r.Context(), p, dep, node.PublicIP, node.PublicIPv6); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	updated, _ := s.store.DNSDeployment(dep.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"ipv4":       updated.LastIPv4,
		"ipv6":       updated.LastIPv6,
		"deployment": s.toDNSDeploymentView(updated),
	})
}

func selfDNSApprovalAction(deploymentID string) string {
	return selfDNSApplyActionPrefix + base64.RawURLEncoding.EncodeToString([]byte(deploymentID))
}

func selfDNSApprovalDisplayAction(action string) string {
	if action == selfDNSApplyAction || strings.HasPrefix(action, selfDNSApplyActionPrefix) {
		return selfDNSApplyAction
	}
	return action
}

func selfDNSApprovalDeploymentID(action string) (string, error) {
	if action == selfDNSApplyAction {
		return "", errors.New("legacy selfdns approval does not carry deployment id; re-plan before applying")
	}
	if !strings.HasPrefix(action, selfDNSApplyActionPrefix) {
		return "", fmt.Errorf("unexpected selfdns action %q", action)
	}
	encoded := strings.TrimPrefix(action, selfDNSApplyActionPrefix)
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(data))
	if id == "" {
		return "", errors.New("empty selfdns deployment id")
	}
	return id, nil
}

func (s *Server) requireSelfDNSDeploymentForApproval(approval model.Approval) error {
	deploymentID, err := selfDNSApprovalDeploymentID(approval.Action)
	if err != nil {
		return err
	}
	dep, ok := s.store.DNSDeployment(deploymentID)
	if !ok {
		return fmt.Errorf("dns deployment %q not found; re-plan before applying", deploymentID)
	}
	if dep.NodeID != approval.NodeID {
		return fmt.Errorf("dns deployment %q no longer belongs to node %s; re-plan before applying", deploymentID, approval.NodeID)
	}
	return nil
}

func (s *Server) markSelfDNSApplying(approval model.Approval) error {
	deploymentID, err := selfDNSApprovalDeploymentID(approval.Action)
	if err != nil {
		return err
	}
	dep, ok := s.store.DNSDeployment(deploymentID)
	if !ok {
		return fmt.Errorf("dns deployment %q not found for approval %s", deploymentID, approval.ID)
	}
	dep.Status = model.DNSStatusApplying
	dep.LastError = ""
	return s.store.UpsertDNSDeployment(dep)
}

func (s *Server) handleSelfDNSTaskResult(r *http.Request, approval model.Approval, task model.Task, result model.TaskResult) error {
	deploymentID, err := selfDNSApprovalDeploymentID(approval.Action)
	if err != nil {
		return err
	}
	dep, ok := s.store.DNSDeployment(deploymentID)
	if !ok {
		return fmt.Errorf("dns deployment %q not found for approval %s", deploymentID, approval.ID)
	}
	if result.FinishedAt.IsZero() {
		result.FinishedAt = time.Now().UTC()
	}
	metadata := map[string]string{
		"approval_id": approval.ID,
		"task_id":     task.ID,
		"dns_id":      dep.ID,
		"plan_sha":    approvalPlanSHA(approval),
	}
	if result.Error == "" && result.ExitCode == 0 {
		dep.Status = model.DNSStatusRunning
		dep.LastAppliedAt = result.FinishedAt
		dep.LastError = ""
		approval.Status = model.ApprovalApplied
		approval.UpdatedAt = time.Now().UTC()
		if err := s.store.UpsertDNSDeployment(dep); err != nil {
			return fmt.Errorf("mark dns deployment running: %w", err)
		}
		if err := s.store.UpsertApproval(approval); err != nil {
			return fmt.Errorf("mark selfdns approval applied: %w", err)
		}
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   approval.NodeID,
			Action:   "dns.apply.applied",
			Decision: "allow",
			Metadata: metadata,
		})
		return nil
	}
	reason := taskFailureSummary(result)
	dep.Status = model.DNSStatusFailed
	dep.LastError = reason
	if err := s.store.UpsertDNSDeployment(dep); err != nil {
		return fmt.Errorf("mark dns deployment failed: %w", err)
	}
	s.recordRequestAudit(r, model.AuditEvent{
		ID:       id.New("audit"),
		NodeID:   approval.NodeID,
		Action:   "dns.apply.failed",
		Decision: "deny",
		Reason:   reason,
		Metadata: metadata,
	})
	return nil
}

func (s *Server) publishDNSDeployment(dep model.DNSDeployment, v4, v6 string) error {
	return s.publishDNSDeploymentWithAudit(context.Background(), dep, v4, v6, s.recordAudit)
}

func (s *Server) publishDNSDeploymentForPrincipal(ctx context.Context, p principal, dep model.DNSDeployment, v4, v6 string) error {
	return s.publishDNSDeploymentWithAudit(ctx, dep, v4, v6, func(ev model.AuditEvent) {
		s.recordPrincipalAudit(p, ev)
	})
}

func (s *Server) publishDNSDeploymentWithAudit(parent context.Context, dep model.DNSDeployment, v4, v6 string, record func(model.AuditEvent)) error {
	recordPublishAudit := func(ok bool) {
		record(model.AuditEvent{
			ID:     id.New("audit"),
			NodeID: dep.NodeID,
			Action: "dns.publish",
			Scope:  "dns:admin",
			Metadata: map[string]string{
				"dns_id":   dep.ID,
				"hostname": dep.Hostname,
				"ok":       fmt.Sprintf("%t", ok),
			},
		})
	}
	profile, err := s.dnsPublishProfile(dep)
	if err != nil {
		s.markDNSPublishResult(dep, "", "", err)
		recordPublishAudit(false)
		return err
	}
	publishV4, publishV6, err := publishableDNSIPs(profile, v4, v6)
	if err != nil {
		s.markDNSPublishResult(dep, "", "", err)
		recordPublishAudit(false)
		return err
	}
	prov, err := s.ddnsProvider(profile)
	if err != nil {
		s.markDNSPublishResult(dep, publishV4, publishV6, err)
		recordPublishAudit(false)
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	applyErr := ddns.Apply(ctx, prov, profile, publishV4, publishV6)
	if err := s.markDNSPublishResult(dep, publishV4, publishV6, applyErr); err != nil {
		s.logger.Printf("dns publish: persist deployment %s: %v", dep.ID, err)
	}
	recordPublishAudit(applyErr == nil)
	return applyErr
}

func (s *Server) dnsPublishProfile(dep model.DNSDeployment) (model.DDNSProfile, error) {
	if strings.TrimSpace(dep.Hostname) == "" {
		return model.DDNSProfile{}, errors.New("dns deployment has no hostname to publish")
	}
	if dep.Disabled {
		return model.DDNSProfile{}, errors.New("dns deployment is disabled")
	}
	profile := model.DDNSProfile{
		ID:         "dns:" + dep.ID,
		Name:       "dns:" + dep.Name,
		NodeID:     dep.NodeID,
		Provider:   model.DDNSProviderCloudflare,
		Domains:    []string{dep.Hostname},
		EnableIPv4: dep.PublishIPv4,
		EnableIPv6: dep.PublishIPv6,
		TTL:        dep.RecordTTL,
	}
	if !profile.EnableIPv4 && !profile.EnableIPv6 {
		profile.EnableIPv4 = true
	}
	if profile.TTL == 0 {
		profile.TTL = 60
	}
	if dep.DDNSProfileID != "" {
		reusable, ok := s.store.DDNSProfile(dep.DDNSProfileID)
		if !ok {
			return model.DDNSProfile{}, errors.New("ddns_profile_id does not exist")
		}
		if reusable.NodeID != "" && reusable.NodeID != dep.NodeID {
			return model.DDNSProfile{}, errors.New("ddns_profile_id must belong to the same node")
		}
		if reusable.Provider != model.DDNSProviderCloudflare {
			return model.DDNSProfile{}, errors.New("ddns_profile_id must reference a cloudflare profile")
		}
		if reusable.CFAPIToken == "" {
			return model.DDNSProfile{}, errors.New("ddns_profile_id has no cloudflare credential")
		}
		profile.CFAPIToken = reusable.CFAPIToken
		profile.MaxRetries = reusable.MaxRetries
	} else {
		profile.CFAPIToken = dep.CFAPIToken
	}
	if profile.CFAPIToken == "" {
		return model.DDNSProfile{}, errors.New("hostname publishing requires cf_api_token or ddns_profile_id")
	}
	return profile, nil
}

func publishableDNSIPs(profile model.DDNSProfile, v4, v6 string) (string, string, error) {
	outV4, outV6 := "", ""
	if profile.EnableIPv4 {
		if strings.TrimSpace(v4) == "" {
			return "", "", errors.New("publish_ipv4 is enabled but the node has no public IPv4")
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(v4))
		if err != nil || !ip.Is4() || ip.IsUnspecified() {
			return "", "", errors.New("node public IPv4 is invalid")
		}
		outV4 = ip.String()
	}
	if profile.EnableIPv6 {
		if strings.TrimSpace(v6) == "" {
			return "", "", errors.New("publish_ipv6 is enabled but the node has no public IPv6")
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(v6))
		if err != nil || !ip.Is6() || ip.IsUnspecified() {
			return "", "", errors.New("node public IPv6 is invalid")
		}
		outV6 = ip.String()
	}
	if outV4 == "" && outV6 == "" {
		return "", "", errors.New("no enabled public IP family is available for publishing")
	}
	return outV4, outV6, nil
}

func (s *Server) markDNSPublishResult(dep model.DNSDeployment, v4, v6 string, err error) error {
	if v4 != "" {
		dep.LastIPv4 = v4
	}
	if v6 != "" {
		dep.LastIPv6 = v6
	}
	dep.LastPublishedAt = s.now()
	if err != nil {
		dep.LastPublishError = err.Error()
	} else {
		dep.LastPublishError = ""
	}
	return s.store.UpsertDNSDeployment(dep)
}

func (s *Server) normalizeDNSDeployment(req, existing model.DNSDeployment, hadExisting bool) (model.DNSDeployment, error) {
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		req.ID = id.New("dns")
	}
	req.Name = strings.TrimSpace(req.Name)
	req.NodeID = strings.TrimSpace(req.NodeID)
	if req.Name == "" || req.NodeID == "" {
		return model.DNSDeployment{}, errors.New("name and node_id are required")
	}
	req.Engine = strings.TrimSpace(strings.ToLower(req.Engine))
	if req.Engine == "" {
		req.Engine = model.DNSEngineCoreDNS
	}
	if req.Engine != model.DNSEngineCoreDNS {
		return model.DNSDeployment{}, fmt.Errorf("unsupported dns engine %q", req.Engine)
	}
	if req.ListenPort == 0 {
		req.ListenPort = 53
	}
	if req.ListenPort < 1 || req.ListenPort > 65535 {
		return model.DNSDeployment{}, errors.New("listen_port must be between 1 and 65535")
	}
	if !req.EnableUDP && !req.EnableTCP {
		req.EnableUDP = true
		req.EnableTCP = true
	}
	req.Exposure = strings.TrimSpace(strings.ToLower(req.Exposure))
	if req.Exposure == "" {
		req.Exposure = model.DNSExposureMesh
	}
	if req.Exposure != model.DNSExposureMesh && req.Exposure != model.DNSExposurePublic {
		return model.DNSDeployment{}, fmt.Errorf("unsupported dns exposure %q", req.Exposure)
	}
	zones, err := normalizeDNSZones(req.Zones)
	if err != nil {
		return model.DNSDeployment{}, err
	}
	req.Zones = zones

	if req.Hostname != "" {
		host, err := normalizeDNSName(req.Hostname, false, false)
		if err != nil {
			return model.DNSDeployment{}, fmt.Errorf("invalid hostname: %w", err)
		}
		if !strings.Contains(host, ".") {
			return model.DNSDeployment{}, errors.New("hostname must be a fully qualified domain")
		}
		req.Hostname = host
		if !req.PublishIPv4 && !req.PublishIPv6 {
			req.PublishIPv4 = true
		}
	}
	if req.RecordTTL == 0 {
		req.RecordTTL = 60
	}
	if req.RecordTTL < 1 || req.RecordTTL > 86400 {
		return model.DNSDeployment{}, errors.New("record_ttl must be between 1 and 86400")
	}
	req.DDNSProfileID = strings.TrimSpace(req.DDNSProfileID)
	if req.DDNSProfileID != "" {
		profile, ok := s.store.DDNSProfile(req.DDNSProfileID)
		if !ok {
			return model.DNSDeployment{}, errors.New("ddns_profile_id does not exist")
		}
		if profile.NodeID != "" && profile.NodeID != req.NodeID {
			return model.DNSDeployment{}, errors.New("ddns_profile_id must belong to the same node")
		}
		if profile.Provider != model.DDNSProviderCloudflare {
			return model.DNSDeployment{}, errors.New("ddns_profile_id must reference a cloudflare profile")
		}
		if profile.CFAPIToken == "" {
			return model.DNSDeployment{}, errors.New("ddns_profile_id has no cloudflare credential")
		}
		req.CFAPIToken = ""
	} else if req.CFAPIToken == "" && hadExisting {
		req.CFAPIToken = existing.CFAPIToken
	}
	if req.Hostname != "" && req.DDNSProfileID == "" && req.CFAPIToken == "" {
		return model.DNSDeployment{}, errors.New("hostname publishing requires cf_api_token or ddns_profile_id")
	}
	if hadExisting {
		req.CreatedAt = existing.CreatedAt
		req.Status = existing.Status
		req.EngineVersion = existing.EngineVersion
		req.LastIPv4 = existing.LastIPv4
		req.LastIPv6 = existing.LastIPv6
		req.LastAppliedAt = existing.LastAppliedAt
		req.LastError = existing.LastError
		req.LastPublishedAt = existing.LastPublishedAt
		req.LastPublishError = existing.LastPublishError
	}
	if req.Disabled {
		req.Status = model.DNSStatusDisabled
	} else if req.Status == "" || req.Status == model.DNSStatusDisabled {
		req.Status = model.DNSStatusPending
	}
	return req, nil
}

func normalizeDNSZones(input []model.DNSZone) ([]model.DNSZone, error) {
	if len(input) == 0 {
		return nil, errors.New("at least one dns zone is required")
	}
	out := make([]model.DNSZone, 0, len(input))
	for i, z := range input {
		suffix, err := normalizeDNSName(z.Suffix, true, true)
		if err != nil {
			return nil, fmt.Errorf("zone %d suffix: %w", i+1, err)
		}
		z.Suffix = suffix
		z.Mode = strings.TrimSpace(strings.ToLower(z.Mode))
		if z.Mode == "" {
			z.Mode = model.DNSZoneForward
		}
		switch z.Mode {
		case model.DNSZoneForward:
			if len(z.Upstreams) == 0 {
				return nil, fmt.Errorf("zone %d forward mode requires at least one upstream", i+1)
			}
			z.Upstreams = normalizeDNSUpstreams(z.Upstreams)
			if len(z.Upstreams) == 0 {
				return nil, fmt.Errorf("zone %d forward mode requires at least one upstream", i+1)
			}
			for _, upstream := range z.Upstreams {
				if err := validateDNSUpstream(upstream); err != nil {
					return nil, fmt.Errorf("zone %d upstream %q: %w", i+1, upstream, err)
				}
			}
			z.Records = nil
		case model.DNSZoneStatic:
			if len(z.Records) == 0 {
				return nil, fmt.Errorf("zone %d static mode requires at least one record", i+1)
			}
			records, err := normalizeDNSRecords(z.Records)
			if err != nil {
				return nil, fmt.Errorf("zone %d: %w", i+1, err)
			}
			z.Records = records
			z.Upstreams = nil
		case model.DNSZoneBlock:
			z.Upstreams = nil
			z.Records = nil
		default:
			return nil, fmt.Errorf("zone %d unsupported mode %q", i+1, z.Mode)
		}
		out = append(out, z)
	}
	return out, nil
}

func normalizeDNSRecords(input []model.DNSRecord) ([]model.DNSRecord, error) {
	out := make([]model.DNSRecord, 0, len(input))
	for i, rec := range input {
		name, err := normalizeDNSName(rec.Name, true, false)
		if err != nil {
			return nil, fmt.Errorf("record %d name: %w", i+1, err)
		}
		rec.Name = name
		rec.Type = strings.ToUpper(strings.TrimSpace(rec.Type))
		rec.Value = strings.TrimSpace(rec.Value)
		if rec.TTL == 0 {
			rec.TTL = 300
		}
		if rec.TTL < 1 || rec.TTL > 86400 {
			return nil, fmt.Errorf("record %d ttl must be between 1 and 86400", i+1)
		}
		switch rec.Type {
		case "A":
			addr, err := netip.ParseAddr(rec.Value)
			if err != nil || !addr.Is4() {
				return nil, fmt.Errorf("record %d A value must be an IPv4 address", i+1)
			}
		case "AAAA":
			addr, err := netip.ParseAddr(rec.Value)
			if err != nil || !addr.Is6() {
				return nil, fmt.Errorf("record %d AAAA value must be an IPv6 address", i+1)
			}
		case "CNAME":
			value, err := normalizeDNSName(rec.Value, true, false)
			if err != nil {
				return nil, fmt.Errorf("record %d CNAME value: %w", i+1, err)
			}
			rec.Value = value
		default:
			return nil, fmt.Errorf("record %d unsupported type %q", i+1, rec.Type)
		}
		out = append(out, rec)
	}
	return out, nil
}

func normalizeDNSUpstreams(input []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range input {
		v := strings.TrimSpace(raw)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func validateDNSUpstream(value string) error {
	if value == "" {
		return errors.New("empty upstream")
	}
	if strings.ContainsAny(value, "\r\n{};") {
		return errors.New("contains unsafe characters")
	}
	addr := strings.TrimPrefix(value, "tls://")
	if strings.HasPrefix(value, "tls://") && addr == value {
		return errors.New("invalid tls upstream")
	}
	if parsed, err := netip.ParseAddr(addr); err == nil {
		if parsed.IsUnspecified() {
			return errors.New("upstream cannot be unspecified")
		}
		return nil
	}
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		if ap.Addr().IsUnspecified() || ap.Port() == 0 {
			return errors.New("upstream address or port is invalid")
		}
		return nil
	}
	return errors.New("must be an IP, IP:port, or tls://IP[:port]")
}

func normalizeDNSName(value string, trailingDot bool, allowRoot bool) (string, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	if strings.ContainsAny(v, "\r\n\t {};/\\") {
		return "", errors.New("contains unsafe characters")
	}
	if allowRoot && v == "." {
		return ".", nil
	}
	v = strings.TrimSuffix(v, ".")
	if v == "" {
		return "", errors.New("empty name")
	}
	if len(v) > 253 {
		return "", errors.New("name is too long")
	}
	labels := strings.Split(v, ".")
	for _, label := range labels {
		if !dnsLabelRe.MatchString(label) {
			return "", fmt.Errorf("invalid label %q", label)
		}
	}
	if trailingDot {
		return v + ".", nil
	}
	return v, nil
}

func (s *Server) toDNSDeploymentView(dep model.DNSDeployment) dnsDeploymentView {
	nodeName := ""
	if n, ok := s.store.Node(dep.NodeID); ok {
		nodeName = n.Name
	}
	return dnsDeploymentView{
		ID: dep.ID, Name: dep.Name, NodeID: dep.NodeID, NodeName: nodeName, Engine: dep.Engine,
		ListenPort: dep.ListenPort, EnableUDP: dep.EnableUDP, EnableTCP: dep.EnableTCP, Exposure: dep.Exposure,
		Zones: dep.Zones, Hostname: dep.Hostname, PublishIPv4: dep.PublishIPv4, PublishIPv6: dep.PublishIPv6,
		RecordTTL: dep.RecordTTL, DDNSProfileID: dep.DDNSProfileID, HasCredential: dep.CFAPIToken != "" || dep.DDNSProfileID != "",
		Status: dep.Status, EngineVersion: dep.EngineVersion, LastIPv4: dep.LastIPv4, LastIPv6: dep.LastIPv6,
		LastAppliedAt: dep.LastAppliedAt, LastError: dep.LastError,
		LastPublishedAt: dep.LastPublishedAt, LastPublishError: dep.LastPublishError, Disabled: dep.Disabled,
		CreatedAt: dep.CreatedAt, UpdatedAt: dep.UpdatedAt,
	}
}
