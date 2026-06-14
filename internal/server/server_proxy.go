package server

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

var (
	proxyIDRe       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	proxyALPNRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9./+-]{0,31}$`)
	proxyShortIDRe  = regexp.MustCompile(`^[0-9a-fA-F]{2,16}$`)
	proxyKeyRe      = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	proxySubTokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)
	proxyUUIDRe     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
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
		token, err := auth.NewRandomToken(32)
		if err != nil {
			return model.ProxyUser{}, err
		}
		out.SubToken = token
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
