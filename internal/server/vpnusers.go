package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// VpnUser is the vpn-core identity model (design-12 S2): one human/account identity
// that carries a credential SET (per protocol) and is bound to many Lines. It is
// OWNED by the vpn-core plugin — persisted in the plugin's durable KV bucket
// (plugin:latticenet.vpn-core), not the SDK-typed store — so it is genuinely
// plugin-owned data with no SDK release coupling. It is additive: the legacy
// model.ProxyUser stays as the subscription-render + usage-accounting substrate
// this slice; VpnUsers are derived from ProxyUsers by an idempotent migration.
//
// Credential secrets (uuid/password) are NEVER returned through the read RPC; the
// gateway-facing views are redacted (see vpnUserView).
type VpnUser struct {
	ID          string          `json:"id"`
	Email       string          `json:"email"`
	Name        string          `json:"name,omitempty"`
	Enabled     bool            `json:"enabled"`
	Credentials []VpnCredential `json:"credentials"`
	Bindings    []LineBinding   `json:"bindings"`
	SubID       string          `json:"sub_id,omitempty"`
	QuotaBytes  int64           `json:"quota_bytes,omitempty"`
	ExpiresAt   time.Time       `json:"expires_at,omitempty"`
	Group       string          `json:"group,omitempty"`
	Comment     string          `json:"comment,omitempty"`

	// MigratedFromProxyUser records the legacy ProxyUser this identity was derived
	// from, so the migration is idempotent and the subscription substrate is traceable.
	MigratedFromProxyUser string `json:"migrated_from_proxy_user,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// VpnCredential is one per-protocol credential. Only the fields relevant to the
// protocol are populated. uuid/password are secret material.
type VpnCredential struct {
	Protocol string `json:"protocol"`           // vless|vmess|trojan|shadowsocks|hysteria2|tuic|anytls
	UUID     string `json:"uuid,omitempty"`     // vless/vmess/tuic
	Password string `json:"password,omitempty"` // trojan/shadowsocks/hysteria2/anytls
	Flow     string `json:"flow,omitempty"`     // vless xtls flow
	Method   string `json:"method,omitempty"`   // shadowsocks cipher
	Security string `json:"security,omitempty"` // vmess security
}

// LineBinding attaches a user to a specific Line (by its stable line_hash_id).
type LineBinding struct {
	LineHashID   string `json:"line_hash_id"`
	Enabled      bool   `json:"enabled"`
	FlowOverride string `json:"flow_override,omitempty"`
}

const (
	vpnCoreKVBucket  = "plugin:" + vpnCorePluginID
	vpnUserKeyPrefix = "vpnuser/"
)

var (
	vpnEmailRe        = regexp.MustCompile(`^[^\s@]{1,64}@[^\s@]{1,255}$`)
	vpnCredProtocols  = map[string]bool{"vless": true, "vmess": true, "trojan": true, "shadowsocks": true, "hysteria2": true, "tuic": true, "anytls": true}
	vpnCredUUIDProtos = map[string]bool{"vless": true, "vmess": true, "tuic": true}
)

// ── Redacted gateway views (no secrets leave the server) ──────────────────────

type vpnCredentialView struct {
	Protocol  string `json:"protocol"`
	Flow      string `json:"flow,omitempty"`
	Method    string `json:"method,omitempty"`
	Security  string `json:"security,omitempty"`
	HasSecret bool   `json:"has_secret"`
}

type vpnUserView struct {
	ID          string              `json:"id"`
	Email       string              `json:"email"`
	Name        string              `json:"name,omitempty"`
	Enabled     bool                `json:"enabled"`
	Credentials []vpnCredentialView `json:"credentials"`
	Bindings    []LineBinding       `json:"bindings"`
	QuotaBytes  int64               `json:"quota_bytes,omitempty"`
	ExpiresAt   time.Time           `json:"expires_at,omitempty"`
	Group       string              `json:"group,omitempty"`
	Comment     string              `json:"comment,omitempty"`
	Migrated    bool                `json:"migrated"`
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
}

func toVpnUserView(u VpnUser) vpnUserView {
	creds := make([]vpnCredentialView, 0, len(u.Credentials))
	for _, c := range u.Credentials {
		creds = append(creds, vpnCredentialView{
			Protocol: c.Protocol, Flow: c.Flow, Method: c.Method, Security: c.Security,
			HasSecret: c.UUID != "" || c.Password != "",
		})
	}
	binds := u.Bindings
	if binds == nil {
		binds = []LineBinding{}
	}
	return vpnUserView{
		ID: u.ID, Email: u.Email, Name: u.Name, Enabled: u.Enabled,
		Credentials: creds, Bindings: binds, QuotaBytes: u.QuotaBytes, ExpiresAt: u.ExpiresAt,
		Group: u.Group, Comment: u.Comment, Migrated: u.MigratedFromProxyUser != "",
		CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
	}
}

// ── KV persistence (vpn-core owns this bucket) ────────────────────────────────

func vpnUserKey(id string) string { return vpnUserKeyPrefix + id }

func (s *Server) putVpnUser(u VpnUser) error {
	b, err := json.Marshal(u)
	if err != nil {
		return err
	}
	return s.store.PutKV(model.KVEntry{Bucket: vpnCoreKVBucket, Key: vpnUserKey(u.ID), Value: string(b)})
}

func (s *Server) getVpnUser(id string) (VpnUser, bool) {
	e, ok := s.store.KVEntry(vpnCoreKVBucket, vpnUserKey(id))
	if !ok {
		return VpnUser{}, false
	}
	var u VpnUser
	if err := json.Unmarshal([]byte(e.Value), &u); err != nil {
		return VpnUser{}, false
	}
	return u, true
}

func (s *Server) listVpnUsers() []VpnUser {
	out := []VpnUser{}
	for _, e := range s.store.KV(vpnCoreKVBucket) {
		if !strings.HasPrefix(e.Key, vpnUserKeyPrefix) {
			continue
		}
		var u VpnUser
		if err := json.Unmarshal([]byte(e.Value), &u); err == nil {
			out = append(out, u)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Email != out[j].Email {
			return out[i].Email < out[j].Email
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (s *Server) deleteVpnUser(id string) error {
	return s.store.DeleteKV(vpnCoreKVBucket, vpnUserKey(id))
}

// ── Migration (idempotent; runs at startup) ───────────────────────────────────

// migrateProxyUsersToVpnUsers derives a VpnUser for each legacy ProxyUser that has
// not already been migrated. It is additive and idempotent: existing VpnUsers are
// left untouched, and the ProxyUser remains the subscription-render substrate.
func (s *Server) migrateProxyUsersToVpnUsers() {
	for _, pu := range s.store.ProxyUsers() {
		vid := "vu_" + pu.ID
		if _, ok := s.getVpnUser(vid); ok {
			continue // already migrated
		}
		creds := []VpnCredential{}
		if strings.TrimSpace(pu.UUID) != "" {
			creds = append(creds, VpnCredential{Protocol: "vless", UUID: pu.UUID})
		}
		if strings.TrimSpace(pu.Password) != "" {
			creds = append(creds, VpnCredential{Protocol: "trojan", Password: pu.Password})
		}
		created := pu.CreatedAt
		if created.IsZero() {
			created = s.now()
		}
		u := VpnUser{
			ID:                    vid,
			Email:                 strings.TrimSpace(pu.Name),
			Name:                  pu.Name,
			Enabled:               pu.Enabled,
			Credentials:           creds,
			Bindings:              []LineBinding{},
			SubID:                 pu.SubToken,
			QuotaBytes:            pu.TrafficLimitBytes,
			ExpiresAt:             pu.ExpiresAt,
			MigratedFromProxyUser: pu.ID,
			CreatedAt:             created,
			UpdatedAt:             s.now(),
		}
		if err := s.putVpnUser(u); err != nil {
			s.logger.Printf("vpn-core: migrate proxy user %s failed: %v", pu.ID, err)
		}
	}
}

// ── RPC: reads (proxy:read) ───────────────────────────────────────────────────

func (s *Server) vpnCoreUsersRPC(_ context.Context, method string, request []byte) ([]byte, error) {
	switch method {
	case "list":
		users := s.listVpnUsers()
		views := make([]vpnUserView, 0, len(users))
		for _, u := range users {
			views = append(views, toVpnUserView(u))
		}
		return json.Marshal(struct {
			Users []vpnUserView `json:"users"`
			Count int           `json:"count"`
		}{Users: views, Count: len(views)})
	case "get":
		id, err := decodeIDRequest(request)
		if err != nil {
			return nil, err
		}
		u, ok := s.getVpnUser(id)
		if !ok {
			return nil, fmt.Errorf("vpn-core/users get: user %q not found", id)
		}
		return json.Marshal(struct {
			User vpnUserView `json:"user"`
		}{User: toVpnUserView(u)})
	default:
		return nil, fmt.Errorf("vpn-core/users: unknown method %q", method)
	}
}

// ── RPC: writes (proxy:admin) ─────────────────────────────────────────────────

func (s *Server) vpnCoreUsersAdminRPC(ctx context.Context, method string, request []byte) ([]byte, error) {
	out, err := s.vpnCoreUsersAdminDispatch(ctx, method, request)
	// design-15 §7: every committed mutation re-arms the Sub-Store auto-sync;
	// plan methods only queue approvals and do not change subscription content.
	if err == nil {
		switch method {
		case "create", "update", "delete", "bind", "unbind", "rotate":
			s.triggerVPNCoreMutation()
			s.invalidateLineReadModel()
		}
	}
	return out, err
}

func (s *Server) vpnCoreUsersAdminDispatch(ctx context.Context, method string, request []byte) ([]byte, error) {
	switch method {
	case "create":
		return s.vpnUserCreate(request)
	case "update":
		return s.vpnUserUpdate(request)
	case "delete":
		id, err := decodeIDRequest(request)
		if err != nil {
			return nil, err
		}
		if _, ok := s.getVpnUser(id); !ok {
			return nil, fmt.Errorf("vpn-core/users-admin delete: user %q not found", id)
		}
		if err := s.deleteVpnUser(id); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"ok": true, "id": id})
	case "bind":
		return s.vpnUserBind(request)
	case "unbind":
		return s.vpnUserUnbind(request)
	case "plan_add", "plan_remove":
		p, err := pluginOperatorPrincipal(ctx)
		if err != nil {
			return nil, err
		}
		op := lineUserOpAdd
		if method == "plan_remove" {
			op = lineUserOpRemove
		}
		return s.vpnUserLinePlan(p, request, op)
	case "rotate":
		p, err := pluginOperatorPrincipal(ctx)
		if err != nil {
			return nil, err
		}
		return s.vpnUserRotateCredential(p, request)
	default:
		return nil, fmt.Errorf("vpn-core/users-admin: unknown method %q", method)
	}
}

type vpnUserWriteReq struct {
	ID          string          `json:"id,omitempty"`
	Email       string          `json:"email"`
	Name        string          `json:"name"`
	Enabled     *bool           `json:"enabled"`
	Credentials []VpnCredential `json:"credentials"`
	QuotaBytes  int64           `json:"quota_bytes"`
	ExpiresAt   *time.Time      `json:"expires_at"`
	Group       string          `json:"group"`
	Comment     string          `json:"comment"`
}

func (s *Server) vpnUserCreate(request []byte) ([]byte, error) {
	var req vpnUserWriteReq
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("vpn-core/users-admin create: invalid request: %w", err)
	}
	email := strings.TrimSpace(req.Email)
	if !vpnEmailRe.MatchString(email) {
		return nil, errors.New("a valid email identity is required")
	}
	if s.vpnUserEmailInUse(email, "") {
		return nil, fmt.Errorf("email %q already exists", email)
	}
	creds, err := s.normalizeCredentials(req.Credentials)
	if err != nil {
		return nil, err
	}
	subID, err := s.newUniqueProxySubToken(id.New("vpnuser"))
	if err != nil {
		return nil, err
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	u := VpnUser{
		ID:          id.New("vpnuser"),
		Email:       email,
		Name:        strings.TrimSpace(req.Name),
		Enabled:     enabled,
		Credentials: creds,
		Bindings:    []LineBinding{},
		SubID:       subID,
		QuotaBytes:  req.QuotaBytes,
		Group:       strings.TrimSpace(req.Group),
		Comment:     strings.TrimSpace(req.Comment),
		CreatedAt:   s.now(),
		UpdatedAt:   s.now(),
	}
	if req.ExpiresAt != nil {
		u.ExpiresAt = *req.ExpiresAt
	}
	if err := s.putVpnUser(u); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		User vpnUserView `json:"user"`
	}{User: toVpnUserView(u)})
}

func (s *Server) vpnUserUpdate(request []byte) ([]byte, error) {
	var req vpnUserWriteReq
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("vpn-core/users-admin update: invalid request: %w", err)
	}
	u, ok := s.getVpnUser(strings.TrimSpace(req.ID))
	if !ok {
		return nil, fmt.Errorf("vpn-core/users-admin update: user %q not found", req.ID)
	}
	if e := strings.TrimSpace(req.Email); e != "" {
		if !vpnEmailRe.MatchString(e) {
			return nil, errors.New("invalid email")
		}
		if s.vpnUserEmailInUse(e, u.ID) {
			return nil, fmt.Errorf("email %q already exists", e)
		}
		u.Email = e
	}
	u.Name = strings.TrimSpace(req.Name)
	if req.Enabled != nil {
		u.Enabled = *req.Enabled
	}
	if req.Credentials != nil {
		creds, err := s.normalizeCredentials(req.Credentials)
		if err != nil {
			return nil, err
		}
		u.Credentials = creds
	}
	u.QuotaBytes = req.QuotaBytes
	if req.ExpiresAt != nil {
		u.ExpiresAt = *req.ExpiresAt
	}
	u.Group = strings.TrimSpace(req.Group)
	u.Comment = strings.TrimSpace(req.Comment)
	u.UpdatedAt = s.now()
	if err := s.putVpnUser(u); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		User vpnUserView `json:"user"`
	}{User: toVpnUserView(u)})
}

type vpnBindReq struct {
	UserID       string `json:"user_id"`
	LineHashID   string `json:"line_hash_id"`
	FlowOverride string `json:"flow_override"`
}

func (s *Server) vpnUserBind(request []byte) ([]byte, error) {
	var req vpnBindReq
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("vpn-core/users-admin bind: invalid request: %w", err)
	}
	u, ok := s.getVpnUser(strings.TrimSpace(req.UserID))
	if !ok {
		return nil, fmt.Errorf("vpn-core/users-admin bind: user %q not found", req.UserID)
	}
	lineHash := strings.TrimSpace(req.LineHashID)
	if lineHash == "" {
		return nil, errors.New("line_hash_id is required")
	}
	if !s.lineExists(lineHash) {
		return nil, fmt.Errorf("line %q is not a known line on any node", lineHash)
	}
	found := false
	for i := range u.Bindings {
		if u.Bindings[i].LineHashID == lineHash {
			u.Bindings[i].Enabled = true
			u.Bindings[i].FlowOverride = strings.TrimSpace(req.FlowOverride)
			found = true
			break
		}
	}
	if !found {
		u.Bindings = append(u.Bindings, LineBinding{LineHashID: lineHash, Enabled: true, FlowOverride: strings.TrimSpace(req.FlowOverride)})
	}
	u.UpdatedAt = s.now()
	if err := s.putVpnUser(u); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		User vpnUserView `json:"user"`
	}{User: toVpnUserView(u)})
}

func (s *Server) vpnUserUnbind(request []byte) ([]byte, error) {
	var req vpnBindReq
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("vpn-core/users-admin unbind: invalid request: %w", err)
	}
	u, ok := s.getVpnUser(strings.TrimSpace(req.UserID))
	if !ok {
		return nil, fmt.Errorf("vpn-core/users-admin unbind: user %q not found", req.UserID)
	}
	lineHash := strings.TrimSpace(req.LineHashID)
	kept := u.Bindings[:0]
	for _, b := range u.Bindings {
		if b.LineHashID != lineHash {
			kept = append(kept, b)
		}
	}
	u.Bindings = kept
	u.UpdatedAt = s.now()
	if err := s.putVpnUser(u); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		User vpnUserView `json:"user"`
	}{User: toVpnUserView(u)})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func decodeIDRequest(request []byte) (string, error) {
	var req struct {
		ID string `json:"id"`
	}
	if len(strings.TrimSpace(string(request))) > 0 {
		if err := json.Unmarshal(request, &req); err != nil {
			return "", fmt.Errorf("invalid request: %w", err)
		}
	}
	if strings.TrimSpace(req.ID) == "" {
		return "", errors.New("id is required")
	}
	return strings.TrimSpace(req.ID), nil
}

func (s *Server) vpnUserEmailInUse(email, exceptID string) bool {
	for _, u := range s.listVpnUsers() {
		if u.ID != exceptID && strings.EqualFold(u.Email, email) {
			return true
		}
	}
	return false
}

// lineExists reports whether a line_hash_id is currently present on any node.
func (s *Server) lineExists(lineHash string) bool {
	_, ok := s.lineFromReadModel(lineHash)
	return ok
}

// normalizeCredentials validates protocols and secret material, auto-generating a
// uuid for uuid-bearing protocols when absent (mirrors the ProxyUser create path).
func (s *Server) normalizeCredentials(in []VpnCredential) ([]VpnCredential, error) {
	out := make([]VpnCredential, 0, len(in))
	seen := map[string]bool{}
	for _, c := range in {
		proto := strings.ToLower(strings.TrimSpace(c.Protocol))
		if !vpnCredProtocols[proto] {
			return nil, fmt.Errorf("unsupported credential protocol %q", c.Protocol)
		}
		if seen[proto] {
			return nil, fmt.Errorf("duplicate credential for protocol %q", proto)
		}
		seen[proto] = true
		nc := VpnCredential{Protocol: proto, Flow: strings.TrimSpace(c.Flow), Method: strings.TrimSpace(c.Method), Security: strings.TrimSpace(c.Security)}
		if vpnCredUUIDProtos[proto] {
			uuid := strings.ToLower(strings.TrimSpace(c.UUID))
			if uuid == "" {
				gen, err := newProxyUUID()
				if err != nil {
					return nil, err
				}
				uuid = gen
			} else if !proxyUUIDRe.MatchString(uuid) {
				return nil, fmt.Errorf("invalid uuid for protocol %q", proto)
			}
			nc.UUID = uuid
		} else {
			pw := c.Password
			if strings.ContainsFunc(pw, proxyUnsafeControl) {
				return nil, errors.New("password contains control characters")
			}
			if len(pw) > 256 {
				return nil, errors.New("password is too long")
			}
			nc.Password = pw
		}
		out = append(out, nc)
	}
	return out, nil
}
