package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/proxycore"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

var (
	proxyIDRe       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	proxyALPNRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9./+-]{0,31}$`)
	proxyShortIDRe  = regexp.MustCompile(`^[0-9a-fA-F]{2,16}$`)
	proxyKeyRe      = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	proxySubTokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)
	proxyUUIDRe     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	proxySHA256Re   = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

const (
	proxyCorePlugin            = "proxycore"
	proxyCoreApplyAction       = "apply-config"
	proxyCoreApplyActionPrefix = proxyCoreApplyAction + ":"
)

type proxyInboundView struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	Core                 string    `json:"core"`
	Protocol             string    `json:"protocol"`
	Listen               string    `json:"listen,omitempty"`
	Port                 int       `json:"port"`
	Transport            string    `json:"transport,omitempty"`
	Path                 string    `json:"path,omitempty"`
	Host                 string    `json:"host,omitempty"`
	Security             string    `json:"security,omitempty"`
	SNI                  string    `json:"sni,omitempty"`
	ALPN                 []string  `json:"alpn,omitempty"`
	Fingerprint          string    `json:"fingerprint,omitempty"`
	CertPath             string    `json:"cert_path,omitempty"`
	KeyPath              string    `json:"key_path,omitempty"`
	HasRealityPrivateKey bool      `json:"has_reality_private_key"`
	RealityPublicKey     string    `json:"reality_public_key,omitempty"`
	RealityShortIDs      []string  `json:"reality_short_ids,omitempty"`
	RealityDest          string    `json:"reality_dest,omitempty"`
	SSMethod             string    `json:"ss_method,omitempty"`
	Enabled              bool      `json:"enabled"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type proxyUserView struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Enabled           bool      `json:"enabled"`
	HasUUID           bool      `json:"has_uuid"`
	HasPassword       bool      `json:"has_password"`
	HasSubToken       bool      `json:"has_sub_token"`
	InboundIDs        []string  `json:"inbound_ids,omitempty"`
	TrafficLimitBytes int64     `json:"traffic_limit_bytes,omitempty"`
	ExpiresAt         time.Time `json:"expires_at,omitempty"`
	UsedBytes         int64     `json:"used_bytes"`
	LastSeenAt        time.Time `json:"last_seen_at,omitempty"`
	Status            string    `json:"status"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type proxyNodeProfileView struct {
	ID            string    `json:"id"`
	NodeID        string    `json:"node_id"`
	NodeName      string    `json:"node_name,omitempty"`
	Core          string    `json:"core"`
	InboundIDs    []string  `json:"inbound_ids"`
	Hostname      string    `json:"hostname,omitempty"`
	ListenIP      string    `json:"listen_ip,omitempty"`
	ConfigPath    string    `json:"config_path,omitempty"`
	StatsAPI      string    `json:"stats_api,omitempty"`
	AppliedSHA256 string    `json:"applied_sha256,omitempty"`
	LastApplyAt   time.Time `json:"last_apply_at,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (s *Server) handleProxySubscription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	token, ok := subscriptionTokenFromPath(r.URL.Path)
	tokenHash := proxySubTokenAuditHash(token)
	if !ok {
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			Action:   "proxy.subscription.fetch",
			Decision: "deny",
			Reason:   "invalid subscription token path",
			Metadata: map[string]string{"token_sha256": tokenHash},
		})
		writeError(w, http.StatusNotFound, errors.New("subscription not found"))
		return
	}
	format, err := normalizeProxySubscriptionFormat(r.URL.Query().Get("format"))
	if err != nil {
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			Action:   "proxy.subscription.fetch",
			Decision: "deny",
			Reason:   "invalid subscription format",
			Metadata: map[string]string{"token_sha256": tokenHash},
		})
		writeError(w, http.StatusBadRequest, err)
		return
	}
	user, found, duplicate := s.proxyUserBySubToken(token)
	if duplicate {
		s.logger.Printf("proxy subscription: duplicate sub_token hash %s; refusing public subscription", tokenHash)
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			Action:   "proxy.subscription.fetch",
			Decision: "deny",
			Reason:   "duplicate subscription token",
			Metadata: map[string]string{"token_sha256": tokenHash},
		})
		writeError(w, http.StatusNotFound, errors.New("subscription not found"))
		return
	}
	if !found {
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			Action:   "proxy.subscription.fetch",
			Decision: "deny",
			Reason:   "subscription token not found",
			Metadata: map[string]string{"token_sha256": tokenHash},
		})
		writeError(w, http.StatusNotFound, errors.New("subscription not found"))
		return
	}

	links, warnings, err := proxycore.VLESSRealityLinks(user, s.proxySubscriptionProfiles(), s.store.ProxyInbounds(), proxycore.SubscriptionOptions{Now: s.now()})
	if err != nil {
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			ActorID:  user.ID,
			Action:   "proxy.subscription.fetch",
			Decision: "deny",
			Reason:   "subscription render failed",
			Metadata: map[string]string{"token_sha256": tokenHash, "user_id": user.ID},
		})
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	body := proxycore.Base64Subscription(links)
	if format == proxycore.SubscriptionFormatPlain {
		body = proxycore.PlainSubscription(links)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Subscription-Userinfo", proxycore.SubscriptionUserinfo(user))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
	s.recordRequestAudit(r, model.AuditEvent{
		ID:       id.New("audit"),
		ActorID:  user.ID,
		Action:   "proxy.subscription.fetch",
		Decision: "allow",
		Metadata: map[string]string{
			"token_sha256":  tokenHash,
			"user_id":       user.ID,
			"format":        format,
			"link_count":    strconv.Itoa(len(links)),
			"warning_count": strconv.Itoa(len(warnings)),
		},
	})
}

func subscriptionTokenFromPath(value string) (string, bool) {
	if !strings.HasPrefix(value, "/sub/") {
		return "", false
	}
	token := strings.TrimPrefix(value, "/sub/")
	if token == "" || strings.Contains(token, "/") || !proxySubTokenRe.MatchString(token) {
		return token, false
	}
	return token, true
}

func normalizeProxySubscriptionFormat(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", proxycore.SubscriptionFormatBase64:
		return proxycore.SubscriptionFormatBase64, nil
	case proxycore.SubscriptionFormatPlain:
		return proxycore.SubscriptionFormatPlain, nil
	default:
		return "", errors.New("unsupported subscription format")
	}
}

func (s *Server) proxyUserBySubToken(token string) (model.ProxyUser, bool, bool) {
	want := sha256.Sum256([]byte(token))
	var found model.ProxyUser
	matches := 0
	for _, user := range s.store.ProxyUsers() {
		got := sha256.Sum256([]byte(user.SubToken))
		if user.SubToken != "" && subtle.ConstantTimeCompare(want[:], got[:]) == 1 {
			matches++
			if matches == 1 {
				found = user
			}
		}
	}
	return found, matches == 1, matches > 1
}

func (s *Server) proxySubscriptionProfiles() []proxycore.SubscriptionProfile {
	profiles := s.store.ProxyNodeProfiles()
	out := make([]proxycore.SubscriptionProfile, 0, len(profiles))
	for _, profile := range profiles {
		name := ""
		if node, ok := s.store.Node(profile.NodeID); ok {
			name = node.Name
		}
		out = append(out, proxycore.SubscriptionProfile{Profile: profile, NodeName: name})
	}
	return out
}

func proxySubTokenAuditHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Server) proxySubscriptionURL(_ *http.Request, token string) string {
	base := strings.TrimRight(s.publicURL, "/")
	if base == "" {
		return "/sub/" + url.PathEscape(token)
	}
	return base + "/sub/" + url.PathEscape(token)
}

func (s *Server) handleProxyInbounds(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireGlobalProxyScope(w, p, "proxy:read") {
			return
		}
		inbounds := s.store.ProxyInbounds()
		views := make([]proxyInboundView, 0, len(inbounds))
		for _, in := range inbounds {
			views = append(views, toProxyInboundView(in))
		}
		writeJSON(w, http.StatusOK, map[string]any{"inbounds": views})
	case http.MethodPost:
		if !s.requireGlobalProxyScope(w, p, "proxy:admin") {
			return
		}
		var req model.ProxyInbound
		if !decodeClientJSON(w, r, &req) {
			return
		}
		existing, hadExisting := model.ProxyInbound{}, false
		if strings.TrimSpace(req.ID) != "" {
			existing, hadExisting = s.store.ProxyInbound(strings.TrimSpace(req.ID))
		}
		inbound, err := s.normalizeProxyInbound(req, existing, hadExisting)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.store.UpsertProxyInbound(inbound); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if stored, ok := s.store.ProxyInbound(inbound.ID); ok {
			inbound = stored
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:     id.New("audit"),
			Action: "proxy.inbound.upsert",
			Scope:  "proxy:admin",
			Metadata: map[string]string{
				"inbound_id": inbound.ID,
				"core":       inbound.Core,
				"protocol":   inbound.Protocol,
				"security":   inbound.Security,
			},
		})
		writeJSON(w, http.StatusOK, toProxyInboundView(inbound))
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleDeleteProxyInbound(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireGlobalProxyScope(w, p, "proxy:admin") {
		return
	}
	var req struct {
		ID    string `json:"id"`
		Force bool   `json:"force,omitempty"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	if !req.Force {
		for _, profile := range s.store.ProxyNodeProfiles() {
			if proxyStringSliceContains(profile.InboundIDs, req.ID) {
				writeError(w, http.StatusConflict, fmt.Errorf("proxy inbound %s is referenced by profile %s", req.ID, profile.NodeID))
				return
			}
		}
	}
	if err := s.store.DeleteProxyInbound(req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:       id.New("audit"),
		Action:   "proxy.inbound.delete",
		Scope:    "proxy:admin",
		Metadata: map[string]string{"inbound_id": req.ID},
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleProxyUsers(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireGlobalProxyScope(w, p, "proxy:read") {
			return
		}
		users := s.store.ProxyUsers()
		views := make([]proxyUserView, 0, len(users))
		for _, user := range users {
			views = append(views, toProxyUserView(user))
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": views})
	case http.MethodPost:
		if !s.requireGlobalProxyScope(w, p, "proxy:admin") {
			return
		}
		var req model.ProxyUser
		if !decodeClientJSON(w, r, &req) {
			return
		}
		existing, hadExisting := model.ProxyUser{}, false
		if strings.TrimSpace(req.ID) != "" {
			existing, hadExisting = s.store.ProxyUser(strings.TrimSpace(req.ID))
		}
		user, err := s.normalizeProxyUser(req, existing, hadExisting)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.store.UpsertProxyUser(user); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if stored, ok := s.store.ProxyUser(user.ID); ok {
			user = stored
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:       id.New("audit"),
			Action:   "proxy.user.upsert",
			Scope:    "proxy:admin",
			Metadata: map[string]string{"user_id": user.ID},
		})
		writeJSON(w, http.StatusOK, toProxyUserView(user))
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleDeleteProxyUser(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireGlobalProxyScope(w, p, "proxy:admin") {
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
	if err := s.store.DeleteProxyUser(req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:       id.New("audit"),
		Action:   "proxy.user.delete",
		Scope:    "proxy:admin",
		Metadata: map[string]string{"user_id": req.ID},
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleRotateProxyUserSubToken(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireGlobalProxyScope(w, p, "proxy:admin") {
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
	user, ok := s.store.ProxyUser(req.ID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("proxy user not found"))
		return
	}
	oldHash := proxySubTokenAuditHash(user.SubToken)
	token, err := s.newUniqueProxySubToken(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	user.SubToken = token
	user.UpdatedAt = s.now()
	if err := s.store.UpsertProxyUser(user); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if stored, ok := s.store.ProxyUser(user.ID); ok {
		user = stored
	}
	newHash := proxySubTokenAuditHash(token)
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:       id.New("audit"),
		Action:   "proxy.user.rotate_sub_token",
		Scope:    "proxy:admin",
		Decision: "allow",
		Metadata: map[string]string{
			"user_id":          user.ID,
			"old_token_sha256": oldHash,
			"new_token_sha256": newHash,
		},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"user":             toProxyUserView(user),
		"subscription_url": s.proxySubscriptionURL(r, token),
		"token_sha256":     newHash,
	})
}

func (s *Server) handleProxyProfiles(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireScope(w, p, "proxy:read") {
			return
		}
		profiles := s.store.ProxyNodeProfiles()
		views := make([]proxyNodeProfileView, 0, len(profiles))
		for _, profile := range profiles {
			if rbac.Allows(p.Principal, "proxy:read", profile.NodeID) {
				views = append(views, s.toProxyNodeProfileView(profile))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"profiles": views})
	case http.MethodPost:
		var req model.ProxyNodeProfile
		if !decodeClientJSON(w, r, &req) {
			return
		}
		req.NodeID = strings.TrimSpace(req.NodeID)
		existing, hadExisting := model.ProxyNodeProfile{}, false
		if req.NodeID != "" {
			existing, hadExisting = s.store.ProxyNodeProfile(req.NodeID)
		}
		if hadExisting && !s.requireNodeScope(w, p, "proxy:admin", existing.NodeID) {
			return
		}
		if !s.requireNodeScope(w, p, "proxy:admin", req.NodeID) {
			return
		}
		if _, ok := s.store.Node(req.NodeID); !ok {
			writeError(w, http.StatusNotFound, errors.New("node not found"))
			return
		}
		profile, err := s.normalizeProxyNodeProfile(req, existing, hadExisting)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.store.UpsertProxyNodeProfile(profile); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if stored, ok := s.store.ProxyNodeProfile(profile.NodeID); ok {
			profile = stored
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   profile.NodeID,
			Action:   "proxy.profile.upsert",
			Scope:    "proxy:admin",
			Metadata: map[string]string{"profile_id": profile.ID},
		})
		writeJSON(w, http.StatusOK, s.toProxyNodeProfileView(profile))
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleDeleteProxyProfile(w http.ResponseWriter, r *http.Request, p principal) {
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
	req.NodeID = strings.TrimSpace(req.NodeID)
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	if !s.requireNodeScope(w, p, "proxy:admin", req.NodeID) {
		return
	}
	if err := s.store.DeleteProxyNodeProfile(req.NodeID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:       id.New("audit"),
		NodeID:   req.NodeID,
		Action:   "proxy.profile.delete",
		Scope:    "proxy:admin",
		Metadata: map[string]string{"node_id": req.NodeID},
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleProxyNodePlan(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	nodeID, ok := proxyNodeIDFromPlanPath(r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("proxy plan route not found"))
		return
	}
	if !s.requireNodeScope(w, p, "network:plan", nodeID) {
		return
	}
	if !s.requireGlobalProxyScope(w, p, "proxy:read") {
		return
	}
	var req struct{}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	node, profile, artifact, err := s.renderProxyCoreArtifact(nodeID)
	if err != nil {
		writeError(w, statusForProxyPlanError(err), err)
		return
	}
	redactedConfig, err := redactProxyConfigJSON(artifact.ConfigJSON)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	plan := renderProxyCoreApprovalPlan(node, profile, artifact, redactedConfig)
	approval := model.Approval{
		ID:        id.New("approval"),
		NodeID:    nodeID,
		Plugin:    proxyCorePlugin,
		Action:    proxyCoreApprovalAction(artifact.ConfigSHA256),
		Plan:      plan,
		Status:    model.ApprovalPending,
		ActorID:   p.ActorID,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.UpsertApproval(approval); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:     id.New("audit"),
		NodeID: nodeID,
		Action: "proxy.plan",
		Scope:  "network:plan",
		Metadata: map[string]string{
			"approval_id":   approval.ID,
			"profile_id":    profile.ID,
			"config_sha256": artifact.ConfigSHA256,
			"inbounds":      strconv.Itoa(len(profile.InboundIDs)),
			"warnings":      strconv.Itoa(len(artifact.Warnings)),
		},
	})
	writeJSON(w, http.StatusOK, toApprovalView(approval))
}

func toProxyInboundView(in model.ProxyInbound) proxyInboundView {
	return proxyInboundView{
		ID:                   in.ID,
		Name:                 in.Name,
		Core:                 in.Core,
		Protocol:             in.Protocol,
		Listen:               in.Listen,
		Port:                 in.Port,
		Transport:            in.Transport,
		Path:                 in.Path,
		Host:                 in.Host,
		Security:             in.Security,
		SNI:                  in.SNI,
		ALPN:                 append([]string(nil), in.ALPN...),
		Fingerprint:          in.Fingerprint,
		CertPath:             in.CertPath,
		KeyPath:              in.KeyPath,
		HasRealityPrivateKey: in.RealityPrivateKey != "",
		RealityPublicKey:     in.RealityPublicKey,
		RealityShortIDs:      append([]string(nil), in.RealityShortIDs...),
		RealityDest:          in.RealityDest,
		SSMethod:             in.SSMethod,
		Enabled:              in.Enabled,
		CreatedAt:            in.CreatedAt,
		UpdatedAt:            in.UpdatedAt,
	}
}

func proxyNodeIDFromPlanPath(path string) (string, bool) {
	const prefix = "/api/proxy/nodes/"
	const suffix = "/plan"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return "", false
	}
	nodeID := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	if nodeID == "" || strings.Contains(nodeID, "/") {
		return "", false
	}
	return nodeID, true
}

func (s *Server) renderProxyCoreArtifact(nodeID string) (model.Node, model.ProxyNodeProfile, proxycore.SingBoxArtifact, error) {
	node, ok := s.store.Node(nodeID)
	if !ok {
		return model.Node{}, model.ProxyNodeProfile{}, proxycore.SingBoxArtifact{}, errProxyPlanNodeNotFound
	}
	profile, ok := s.store.ProxyNodeProfile(nodeID)
	if !ok {
		return model.Node{}, model.ProxyNodeProfile{}, proxycore.SingBoxArtifact{}, errProxyPlanProfileNotFound
	}
	artifact, err := proxycore.RenderSingBoxConfigJSON(profile, s.store.ProxyInbounds(), s.store.ProxyUsers(), proxycore.RenderOptions{})
	if err != nil {
		return model.Node{}, model.ProxyNodeProfile{}, proxycore.SingBoxArtifact{}, err
	}
	return node, profile, artifact, nil
}

var (
	errProxyPlanNodeNotFound    = errors.New("node not found")
	errProxyPlanProfileNotFound = errors.New("proxy node profile not found")
)

func statusForProxyPlanError(err error) int {
	switch {
	case errors.Is(err, errProxyPlanNodeNotFound), errors.Is(err, errProxyPlanProfileNotFound):
		return http.StatusNotFound
	default:
		return http.StatusBadRequest
	}
}

func proxyCoreApprovalAction(configSHA256 string) string {
	return proxyCoreApplyActionPrefix + strings.ToLower(strings.TrimSpace(configSHA256))
}

func proxyCoreApprovalDisplayAction(action string) string {
	if strings.HasPrefix(action, proxyCoreApplyActionPrefix) {
		return proxyCoreApplyAction
	}
	return action
}

func proxyCoreApprovalConfigSHA(approval model.Approval) (string, error) {
	if approval.Plugin != proxyCorePlugin {
		return "", nil
	}
	if !strings.HasPrefix(approval.Action, proxyCoreApplyActionPrefix) {
		return "", fmt.Errorf("unexpected proxycore approval action %q", approval.Action)
	}
	sha := strings.TrimSpace(strings.TrimPrefix(approval.Action, proxyCoreApplyActionPrefix))
	if !proxySHA256Re.MatchString(sha) {
		return "", fmt.Errorf("invalid proxycore config sha %q", sha)
	}
	return strings.ToLower(sha), nil
}

func (s *Server) requireCurrentProxyCoreApproval(approval model.Approval) error {
	_, err := s.currentProxyCoreArtifactForApproval(approval)
	return err
}

func (s *Server) currentProxyCoreArtifactForApproval(approval model.Approval) (proxycore.SingBoxArtifact, error) {
	want, err := proxyCoreApprovalConfigSHA(approval)
	if err != nil {
		return proxycore.SingBoxArtifact{}, err
	}
	_, _, artifact, err := s.renderProxyCoreArtifact(approval.NodeID)
	if err != nil {
		return proxycore.SingBoxArtifact{}, fmt.Errorf("proxycore plan is no longer renderable: %w", err)
	}
	if !strings.EqualFold(want, artifact.ConfigSHA256) {
		return proxycore.SingBoxArtifact{}, errors.New("proxycore config changed since this plan was created; re-plan before approving")
	}
	return artifact, nil
}

func (s *Server) proxyCoreApplyScript(approval model.Approval) (string, error) {
	artifact, err := s.currentProxyCoreArtifactForApproval(approval)
	if err != nil {
		return "", err
	}
	return proxyCoreApplyScript(artifact), nil
}

func proxyCoreApplyScript(artifact proxycore.SingBoxArtifact) string {
	target := artifact.ConfigPath
	candidate := target + ".lattice-new"
	backup := target + ".lattice-prev"
	dir := path.Dir(target)
	return "set -e\n" +
		"umask 077\n" +
		"if ! command -v sing-box >/dev/null 2>&1; then\n" +
		"  echo 'lattice proxycore: sing-box binary not found on node' >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"TARGET=" + shellQuote(target) + "\n" +
		"CANDIDATE=" + shellQuote(candidate) + "\n" +
		"BACKUP=" + shellQuote(backup) + "\n" +
		"DIR=" + shellQuote(dir) + "\n" +
		"RESTORE_TARGET=none\n" +
		"mkdir -p \"$DIR\"\n" +
		"cleanup_candidate() {\n" +
		"  rm -f \"$CANDIDATE\"\n" +
		"}\n" +
		"restore_target() {\n" +
		"  case \"$RESTORE_TARGET\" in\n" +
		"    backup)\n" +
		"      if [ -f \"$BACKUP\" ]; then mv -f \"$BACKUP\" \"$TARGET\"; fi\n" +
		"      ;;\n" +
		"    remove)\n" +
		"      rm -f \"$TARGET\"\n" +
		"      ;;\n" +
		"  esac\n" +
		"  rm -f \"$BACKUP\"\n" +
		"}\n" +
		"restart_after_restore() {\n" +
		"  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then\n" +
		"    systemctl restart sing-box 2>/dev/null || true\n" +
		"  elif command -v service >/dev/null 2>&1; then\n" +
		"    service sing-box restart 2>/dev/null || true\n" +
		"  fi\n" +
		"}\n" +
		"trap 'cleanup_candidate; restore_target; restart_after_restore' ERR\n" +
		heredocWrite(shellQuote(candidate), "LATTICE_PROXYCORE_SINGBOX_EOF", artifact.ConfigJSON) +
		"chmod 0600 \"$CANDIDATE\"\n" +
		"sing-box check -c \"$CANDIDATE\"\n" +
		"if [ -e \"$TARGET\" ]; then\n" +
		"  cp -p \"$TARGET\" \"$BACKUP\"\n" +
		"  RESTORE_TARGET=backup\n" +
		"else\n" +
		"  RESTORE_TARGET=remove\n" +
		"fi\n" +
		"mv -f \"$CANDIDATE\" \"$TARGET\"\n" +
		"if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then\n" +
		"  systemctl reload sing-box 2>/dev/null || systemctl restart sing-box\n" +
		"elif command -v service >/dev/null 2>&1; then\n" +
		"  service sing-box reload 2>/dev/null || service sing-box restart\n" +
		"else\n" +
		"  echo 'lattice proxycore: no supported service manager found for sing-box reload/restart' >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"trap - ERR\n" +
		"rm -f \"$BACKUP\"\n" +
		"echo 'lattice proxycore: sing-box config applied and verified'\n"
}

func (s *Server) handleProxyCoreTaskResult(r *http.Request, approval model.Approval, task model.Task, result model.TaskResult) error {
	profile, ok := s.store.ProxyNodeProfile(approval.NodeID)
	if !ok {
		return fmt.Errorf("proxy profile %q not found for approval %s", approval.NodeID, approval.ID)
	}
	configSHA, err := proxyCoreApprovalConfigSHA(approval)
	if err != nil {
		return err
	}
	metadata := map[string]string{
		"approval_id": approval.ID,
		"task_id":     task.ID,
		"config_sha":  configSHA,
	}
	if result.Error == "" && result.ExitCode == 0 {
		if result.FinishedAt.IsZero() {
			result.FinishedAt = time.Now().UTC()
		}
		profile.AppliedSHA256 = configSHA
		profile.LastApplyAt = result.FinishedAt
		profile.LastError = ""
		approval.Status = model.ApprovalApplied
		approval.UpdatedAt = time.Now().UTC()
		if err := s.store.UpsertApproval(approval); err != nil {
			return fmt.Errorf("mark proxycore approval applied: %w", err)
		}
		if err := s.store.UpsertProxyNodeProfile(profile); err != nil {
			return fmt.Errorf("mark proxycore profile applied: %w", err)
		}
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   approval.NodeID,
			Action:   "proxy.apply.applied",
			Decision: "allow",
			Metadata: metadata,
		})
		return nil
	}
	reason := taskFailureSummary(result)
	profile.LastError = reason
	if err := s.store.UpsertProxyNodeProfile(profile); err != nil {
		return fmt.Errorf("mark proxycore apply failed: %w", err)
	}
	s.recordRequestAudit(r, model.AuditEvent{
		ID:       id.New("audit"),
		NodeID:   approval.NodeID,
		Action:   "proxy.apply.failed",
		Decision: "deny",
		Reason:   reason,
		Metadata: metadata,
	})
	return nil
}

func renderProxyCoreApprovalPlan(node model.Node, profile model.ProxyNodeProfile, artifact proxycore.SingBoxArtifact, redactedConfig string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Lattice proxycore review plan\n\n")
	fmt.Fprintf(&b, "node_id: %s\n", profile.NodeID)
	if node.Name != "" {
		fmt.Fprintf(&b, "node_name: %s\n", node.Name)
	}
	fmt.Fprintf(&b, "profile_id: %s\n", profile.ID)
	fmt.Fprintf(&b, "core: %s\n", profile.Core)
	fmt.Fprintf(&b, "config_path: %s\n", artifact.ConfigPath)
	fmt.Fprintf(&b, "artifact_sha256: %s\n", artifact.ConfigSHA256)
	fmt.Fprintf(&b, "inbound_count: %d\n", len(profile.InboundIDs))
	if profile.Hostname != "" {
		fmt.Fprintf(&b, "hostname: %s\n", profile.Hostname)
	}
	if profile.ListenIP != "" {
		fmt.Fprintf(&b, "listen_ip: %s\n", profile.ListenIP)
	}
	if len(artifact.Warnings) > 0 {
		b.WriteString("\nwarnings:\n")
		for _, warning := range artifact.Warnings {
			fmt.Fprintf(&b, "- %s\n", warning)
		}
	}
	b.WriteString("\nsecret_handling: redacted_config hides UUID/password/token/private_key fields; artifact_sha256 binds the real rendered config.\n")
	b.WriteString("\n## redacted sing-box config\n")
	b.WriteString(redactedConfig)
	if !strings.HasSuffix(redactedConfig, "\n") {
		b.WriteByte('\n')
	}
	return b.String()
}

func redactProxyConfigJSON(configJSON string) (string, error) {
	var value any
	if err := json.Unmarshal([]byte(configJSON), &value); err != nil {
		return "", fmt.Errorf("decode rendered proxy config for redaction: %w", err)
	}
	redactProxyConfigValue(value)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		return "", fmt.Errorf("encode redacted proxy config: %w", err)
	}
	return buf.String(), nil
}

func redactProxyConfigValue(value any) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			switch strings.ToLower(key) {
			case "private_key", "uuid", "password":
				if s, ok := child.(string); ok && s != "" {
					v[key] = "<redacted>"
					continue
				}
			}
			redactProxyConfigValue(child)
		}
	case []any:
		for _, child := range v {
			redactProxyConfigValue(child)
		}
	}
}

func toProxyUserView(user model.ProxyUser) proxyUserView {
	return proxyUserView{
		ID:                user.ID,
		Name:              user.Name,
		Enabled:           user.Enabled,
		HasUUID:           user.UUID != "",
		HasPassword:       user.Password != "",
		HasSubToken:       user.SubToken != "",
		InboundIDs:        append([]string(nil), user.InboundIDs...),
		TrafficLimitBytes: user.TrafficLimitBytes,
		ExpiresAt:         user.ExpiresAt,
		UsedBytes:         user.UsedBytes,
		LastSeenAt:        user.LastSeenAt,
		Status:            user.Status,
		CreatedAt:         user.CreatedAt,
		UpdatedAt:         user.UpdatedAt,
	}
}

func (s *Server) toProxyNodeProfileView(profile model.ProxyNodeProfile) proxyNodeProfileView {
	nodeName := ""
	if node, ok := s.store.Node(profile.NodeID); ok {
		nodeName = node.Name
	}
	return proxyNodeProfileView{
		ID:            profile.ID,
		NodeID:        profile.NodeID,
		NodeName:      nodeName,
		Core:          profile.Core,
		InboundIDs:    append([]string(nil), profile.InboundIDs...),
		Hostname:      profile.Hostname,
		ListenIP:      profile.ListenIP,
		ConfigPath:    profile.ConfigPath,
		StatsAPI:      profile.StatsAPI,
		AppliedSHA256: profile.AppliedSHA256,
		LastApplyAt:   profile.LastApplyAt,
		LastError:     profile.LastError,
		CreatedAt:     profile.CreatedAt,
		UpdatedAt:     profile.UpdatedAt,
	}
}

func (s *Server) normalizeProxyInbound(req, existing model.ProxyInbound, hadExisting bool) (model.ProxyInbound, error) {
	out := existing
	if !hadExisting {
		out = model.ProxyInbound{ID: id.New("pin"), Enabled: true}
	}
	if strings.TrimSpace(req.ID) != "" {
		out.ID = strings.TrimSpace(req.ID)
	}
	if !proxyIDRe.MatchString(out.ID) {
		return model.ProxyInbound{}, fmt.Errorf("invalid proxy inbound id %q", out.ID)
	}
	out.Name = strings.TrimSpace(req.Name)
	if err := validateProxyLabel(out.Name, "name"); err != nil {
		return model.ProxyInbound{}, err
	}
	out.Core = strings.TrimSpace(req.Core)
	if out.Core == "" {
		out.Core = model.ProxyCoreSingbox
	}
	if out.Core != model.ProxyCoreSingbox {
		return model.ProxyInbound{}, fmt.Errorf("unsupported proxy core %q", out.Core)
	}
	out.Protocol = strings.TrimSpace(req.Protocol)
	if out.Protocol == "" {
		out.Protocol = model.ProxyProtocolVLESS
	}
	if out.Protocol != model.ProxyProtocolVLESS {
		return model.ProxyInbound{}, fmt.Errorf("unsupported proxy protocol %q", out.Protocol)
	}
	out.Transport = strings.TrimSpace(req.Transport)
	if out.Transport == "" {
		out.Transport = model.ProxyTransportTCP
	}
	if out.Transport != model.ProxyTransportTCP {
		return model.ProxyInbound{}, fmt.Errorf("unsupported proxy transport %q", out.Transport)
	}
	out.Path = strings.TrimSpace(req.Path)
	out.Host = strings.TrimSpace(req.Host)
	if out.Path != "" || out.Host != "" {
		return model.ProxyInbound{}, errors.New("path/host are not supported for the TCP REALITY MVP")
	}
	out.Security = strings.TrimSpace(req.Security)
	if out.Security == "" {
		out.Security = model.ProxySecurityReality
	}
	if out.Security != model.ProxySecurityReality {
		return model.ProxyInbound{}, fmt.Errorf("unsupported proxy security %q", out.Security)
	}
	out.Listen = strings.TrimSpace(req.Listen)
	if out.Listen != "" {
		if _, err := netip.ParseAddr(out.Listen); err != nil {
			return model.ProxyInbound{}, fmt.Errorf("listen must be an IP address: %w", err)
		}
	}
	out.Port = req.Port
	if out.Port < 1 || out.Port > 65535 {
		return model.ProxyInbound{}, errors.New("port must be between 1 and 65535")
	}
	out.SNI = strings.TrimSpace(req.SNI)
	if out.SNI != "" {
		sni, err := normalizeDNSName(out.SNI, false, false)
		if err != nil {
			return model.ProxyInbound{}, fmt.Errorf("invalid sni: %w", err)
		}
		out.SNI = sni
	}
	alpn, err := normalizeProxyALPN(req.ALPN)
	if err != nil {
		return model.ProxyInbound{}, err
	}
	out.ALPN = alpn
	out.Fingerprint = strings.TrimSpace(req.Fingerprint)
	if out.Fingerprint != "" {
		return model.ProxyInbound{}, errors.New("fingerprint is subscription metadata and is not supported until the subscription slice")
	}
	out.CertPath = strings.TrimSpace(req.CertPath)
	out.KeyPath = strings.TrimSpace(req.KeyPath)
	if out.CertPath != "" || out.KeyPath != "" {
		return model.ProxyInbound{}, errors.New("certificate paths cannot be combined with REALITY in the MVP")
	}
	if strings.TrimSpace(req.RealityPrivateKey) != "" {
		out.RealityPrivateKey = strings.TrimSpace(req.RealityPrivateKey)
	}
	if out.RealityPrivateKey == "" {
		return model.ProxyInbound{}, errors.New("reality_private_key is required until key generation lands")
	}
	if !proxyKeyRe.MatchString(out.RealityPrivateKey) {
		return model.ProxyInbound{}, errors.New("invalid reality_private_key")
	}
	out.RealityPublicKey = strings.TrimSpace(req.RealityPublicKey)
	if out.RealityPublicKey != "" && !proxyKeyRe.MatchString(out.RealityPublicKey) {
		return model.ProxyInbound{}, errors.New("invalid reality_public_key")
	}
	shortIDs, err := normalizeProxyShortIDs(req.RealityShortIDs)
	if err != nil {
		return model.ProxyInbound{}, err
	}
	out.RealityShortIDs = shortIDs
	out.RealityDest = strings.TrimSpace(req.RealityDest)
	if err := validateProxyHostPort(out.RealityDest, "reality_dest"); err != nil {
		return model.ProxyInbound{}, err
	}
	out.SSMethod = strings.TrimSpace(req.SSMethod)
	if out.SSMethod != "" {
		return model.ProxyInbound{}, errors.New("ss_method is only valid for future shadowsocks support")
	}
	out.Enabled = req.Enabled
	if !hadExisting && !req.Enabled {
		// Default new inbounds to enabled when the caller omits the flag. A caller
		// can disable it in a follow-up update before assigning it to a profile.
		out.Enabled = true
	}
	return out, nil
}

func (s *Server) requireGlobalProxyScope(w http.ResponseWriter, p principal, scope string) bool {
	if !s.requireScope(w, p, scope) {
		return false
	}
	if !principalHasNodeRestriction(p) {
		return true
	}
	s.recordAudit(model.AuditEvent{
		ID:            id.New("audit"),
		ActorID:       p.ActorID,
		TokenID:       p.TokenID,
		Action:        "authorize.scope",
		Scope:         scope,
		Decision:      "deny",
		Reason:        "global proxy objects require an unrestricted server allowlist",
		CorrelationID: p.CorrelationID,
	})
	writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
	return false
}

func (s *Server) normalizeProxyUser(req, existing model.ProxyUser, hadExisting bool) (model.ProxyUser, error) {
	out := existing
	if !hadExisting {
		out = model.ProxyUser{ID: id.New("puser"), Enabled: true}
	}
	if strings.TrimSpace(req.ID) != "" {
		out.ID = strings.TrimSpace(req.ID)
	}
	if !proxyIDRe.MatchString(out.ID) {
		return model.ProxyUser{}, fmt.Errorf("invalid proxy user id %q", out.ID)
	}
	out.Name = strings.TrimSpace(req.Name)
	if err := validateProxyLabel(out.Name, "name"); err != nil {
		return model.ProxyUser{}, err
	}
	out.Enabled = req.Enabled
	if !hadExisting && !req.Enabled {
		out.Enabled = true
	}
	inboundIDs, err := s.normalizeProxyInboundIDs(req.InboundIDs)
	if err != nil {
		return model.ProxyUser{}, err
	}
	out.InboundIDs = inboundIDs
	if strings.TrimSpace(req.UUID) != "" {
		if !proxyUUIDRe.MatchString(req.UUID) {
			return model.ProxyUser{}, errors.New("invalid uuid")
		}
		out.UUID = strings.ToLower(strings.TrimSpace(req.UUID))
	} else if out.UUID == "" {
		uuid, err := newProxyUUID()
		if err != nil {
			return model.ProxyUser{}, err
		}
		out.UUID = uuid
	}
	if req.Password != "" {
		if strings.ContainsFunc(req.Password, proxyUnsafeControl) {
			return model.ProxyUser{}, errors.New("password contains control characters")
		}
		if len(req.Password) > 256 {
			return model.ProxyUser{}, errors.New("password is too long")
		}
		out.Password = req.Password
	}
	if strings.TrimSpace(req.SubToken) != "" {
		token := strings.TrimSpace(req.SubToken)
		if !proxySubTokenRe.MatchString(token) {
			return model.ProxyUser{}, errors.New("invalid sub_token")
		}
		out.SubToken = token
	} else if out.SubToken == "" {
		token, err := s.newUniqueProxySubToken(out.ID)
		if err != nil {
			return model.ProxyUser{}, err
		}
		out.SubToken = token
	}
	if out.SubToken != "" && s.proxySubTokenInUse(out.SubToken, out.ID) {
		return model.ProxyUser{}, errors.New("sub_token already exists")
	}
	if req.TrafficLimitBytes < 0 {
		return model.ProxyUser{}, errors.New("traffic_limit_bytes cannot be negative")
	}
	out.TrafficLimitBytes = req.TrafficLimitBytes
	out.ExpiresAt = req.ExpiresAt
	if hadExisting {
		out.UsedBytes = existing.UsedBytes
		out.LastSeenAt = existing.LastSeenAt
	}
	out.Status = derivedProxyUserStatus(out)
	return out, nil
}

func (s *Server) newUniqueProxySubToken(excludeID string) (string, error) {
	for i := 0; i < 8; i++ {
		token, err := auth.NewRandomToken(32)
		if err != nil {
			return "", err
		}
		if !s.proxySubTokenInUse(token, excludeID) {
			return token, nil
		}
	}
	return "", errors.New("could not generate unique sub_token")
}

func (s *Server) proxySubTokenInUse(token, excludeID string) bool {
	want := sha256.Sum256([]byte(token))
	for _, user := range s.store.ProxyUsers() {
		if user.ID == excludeID || user.SubToken == "" {
			continue
		}
		got := sha256.Sum256([]byte(user.SubToken))
		if subtle.ConstantTimeCompare(want[:], got[:]) == 1 {
			return true
		}
	}
	return false
}

func (s *Server) normalizeProxyNodeProfile(req, existing model.ProxyNodeProfile, hadExisting bool) (model.ProxyNodeProfile, error) {
	out := existing
	if !hadExisting {
		out = model.ProxyNodeProfile{ID: req.NodeID, NodeID: req.NodeID}
	}
	out.NodeID = strings.TrimSpace(req.NodeID)
	if out.NodeID == "" {
		return model.ProxyNodeProfile{}, errors.New("node_id is required")
	}
	out.ID = strings.TrimSpace(req.ID)
	if out.ID == "" {
		out.ID = out.NodeID
	}
	if !proxyIDRe.MatchString(out.ID) {
		return model.ProxyNodeProfile{}, fmt.Errorf("invalid proxy profile id %q", out.ID)
	}
	out.Core = strings.TrimSpace(req.Core)
	if out.Core == "" {
		out.Core = model.ProxyCoreSingbox
	}
	if out.Core != model.ProxyCoreSingbox {
		return model.ProxyNodeProfile{}, fmt.Errorf("unsupported proxy core %q", out.Core)
	}
	inboundIDs, err := s.normalizeProxyInboundIDs(req.InboundIDs)
	if err != nil {
		return model.ProxyNodeProfile{}, err
	}
	if len(inboundIDs) == 0 {
		return model.ProxyNodeProfile{}, errors.New("at least one inbound_id is required")
	}
	for _, inboundID := range inboundIDs {
		inbound, ok := s.store.ProxyInbound(inboundID)
		if !ok {
			return model.ProxyNodeProfile{}, fmt.Errorf("proxy inbound %s not found", inboundID)
		}
		if !inbound.Enabled {
			return model.ProxyNodeProfile{}, fmt.Errorf("proxy inbound %s is disabled", inboundID)
		}
	}
	out.InboundIDs = inboundIDs
	out.Hostname = strings.TrimSpace(req.Hostname)
	if out.Hostname != "" {
		host, err := normalizeDNSName(out.Hostname, false, false)
		if err != nil {
			return model.ProxyNodeProfile{}, fmt.Errorf("invalid hostname: %w", err)
		}
		out.Hostname = host
	}
	out.ListenIP = strings.TrimSpace(req.ListenIP)
	if out.ListenIP != "" {
		if _, err := netip.ParseAddr(out.ListenIP); err != nil {
			return model.ProxyNodeProfile{}, fmt.Errorf("listen_ip must be an IP address: %w", err)
		}
	}
	out.ConfigPath = strings.TrimSpace(req.ConfigPath)
	if out.ConfigPath != "" {
		if err := validateProxyConfigPath(out.ConfigPath); err != nil {
			return model.ProxyNodeProfile{}, err
		}
	}
	out.StatsAPI = strings.TrimSpace(req.StatsAPI)
	if out.StatsAPI != "" {
		if err := validateProxyHostPort(out.StatsAPI, "stats_api"); err != nil {
			return model.ProxyNodeProfile{}, err
		}
	}
	if hadExisting && proxyProfileIntentChanged(existing, out) {
		out.AppliedSHA256 = existing.AppliedSHA256
		out.LastApplyAt = existing.LastApplyAt
		out.LastError = "profile changed since last apply; create a new plan before applying"
	}
	return out, nil
}

func (s *Server) normalizeProxyInboundIDs(values []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		v := strings.TrimSpace(value)
		if v == "" {
			continue
		}
		if !proxyIDRe.MatchString(v) {
			return nil, fmt.Errorf("invalid inbound id %q", v)
		}
		if _, ok := s.store.ProxyInbound(v); !ok {
			return nil, fmt.Errorf("proxy inbound %s not found", v)
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out, nil
}

func validateProxyLabel(value, field string) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(value) > 128 {
		return fmt.Errorf("%s is too long", field)
	}
	if strings.ContainsFunc(value, proxyUnsafeControl) {
		return fmt.Errorf("%s contains control characters", field)
	}
	return nil
}

func normalizeProxyALPN(values []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		v := strings.TrimSpace(value)
		if v == "" {
			continue
		}
		if !proxyALPNRe.MatchString(v) {
			return nil, fmt.Errorf("invalid alpn value %q", v)
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out, nil
}

func normalizeProxyShortIDs(values []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		v := strings.ToLower(strings.TrimSpace(value))
		if v == "" {
			continue
		}
		if !proxyShortIDRe.MatchString(v) || len(v)%2 != 0 {
			return nil, fmt.Errorf("invalid reality short id %q", value)
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("at least one reality_short_id is required")
	}
	return out, nil
}

func validateProxyHostPort(value, field string) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if strings.ContainsFunc(value, proxyUnsafeControl) {
		return fmt.Errorf("%s contains control characters", field)
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("%s must be host:port: %w", field, err)
	}
	if host == "" || strings.ContainsAny(host, "/\\\"'`$;&|<>(){}[]") {
		return fmt.Errorf("%s host contains unsafe characters", field)
	}
	if addr, err := netip.ParseAddr(host); err == nil && addr.IsUnspecified() {
		return fmt.Errorf("%s host cannot be unspecified", field)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%s has invalid port", field)
	}
	return nil
}

func validateProxyConfigPath(value string) error {
	if strings.TrimSpace(value) != value {
		return errors.New("config_path has leading or trailing whitespace")
	}
	if !strings.HasPrefix(value, "/") {
		return errors.New("config_path must be absolute")
	}
	if strings.ContainsFunc(value, proxyUnsafeControl) {
		return errors.New("config_path contains control characters")
	}
	if strings.ContainsAny(value, "\"'`$;&|<>") {
		return errors.New("config_path contains unsafe shell characters")
	}
	return nil
}

func derivedProxyUserStatus(user model.ProxyUser) string {
	if !user.Enabled {
		return model.ProxyUserStatusDisabled
	}
	now := time.Now().UTC()
	if !user.ExpiresAt.IsZero() && !user.ExpiresAt.After(now) {
		return model.ProxyUserStatusExpired
	}
	if user.TrafficLimitBytes > 0 && user.UsedBytes >= user.TrafficLimitBytes {
		return model.ProxyUserStatusOverQuota
	}
	return model.ProxyUserStatusActive
}

func proxyProfileIntentChanged(a, b model.ProxyNodeProfile) bool {
	return a.Core != b.Core ||
		strings.Join(a.InboundIDs, "\x00") != strings.Join(b.InboundIDs, "\x00") ||
		a.Hostname != b.Hostname ||
		a.ListenIP != b.ListenIP ||
		a.ConfigPath != b.ConfigPath ||
		a.StatsAPI != b.StatsAPI
}

func newProxyUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	), nil
}

func proxyUnsafeControl(r rune) bool {
	return unicode.IsControl(r) || r == '\u007f'
}

func proxyStringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
