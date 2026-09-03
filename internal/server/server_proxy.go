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
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/proxycore"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

var (
	proxyIDRe          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	proxyALPNRe        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9./+-]{0,31}$`)
	proxyShortIDRe     = regexp.MustCompile(`^[0-9a-fA-F]{2,16}$`)
	proxyKeyRe         = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	proxySubTokenRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)
	proxyFingerprintRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	proxyUUIDRe        = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	proxySHA256Re      = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
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
	ID       string `json:"id"`
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name,omitempty"`
	// Origin is managed for a Lattice-rendered profile and discovered for one
	// registered from a usage report of an sb-managed node.
	Origin        string    `json:"origin"`
	Core          string    `json:"core"`
	InboundIDs    []string  `json:"inbound_ids"`
	Hostname      string    `json:"hostname,omitempty"`
	ListenIP      string    `json:"listen_ip,omitempty"`
	ConfigPath    string    `json:"config_path,omitempty"`
	StatsAPI      string    `json:"stats_api,omitempty"`
	AppliedSHA256 string    `json:"applied_sha256,omitempty"`
	LastApplyAt   time.Time `json:"last_apply_at,omitempty"`
	LastError     string    `json:"last_error,omitempty"`

	UsageCollectorSource      string    `json:"usage_collector_source,omitempty"`
	UsageCollectorStatus      string    `json:"usage_collector_status,omitempty"`
	UsageCollectorCheckedAt   time.Time `json:"usage_collector_checked_at,omitempty"`
	UsageCollectorLastOKAt    time.Time `json:"usage_collector_last_ok_at,omitempty"`
	UsageCollectorLastError   string    `json:"usage_collector_last_error,omitempty"`
	UsageCollectorLastErrorAt time.Time `json:"usage_collector_last_error_at,omitempty"`

	// ConfigStale and friends report whether the applied config still matches the
	// current policy render. They are an operator signal toward a reviewed apply;
	// node mutation always stays behind plan->approve->apply.
	ConfigStale         bool      `json:"config_stale,omitempty"`
	PendingConfigSHA256 string    `json:"pending_config_sha256,omitempty"`
	IneligibleUsers     int       `json:"ineligible_users,omitempty"`
	DriftReason         string    `json:"drift_reason,omitempty"`
	DriftCheckedAt      time.Time `json:"drift_checked_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type proxyUsageSnapshotView struct {
	NodeID        string                      `json:"node_id"`
	NodeName      string                      `json:"node_name,omitempty"`
	At            time.Time                   `json:"at"`
	CoreUptimeSec uint64                      `json:"core_uptime_sec"`
	UserBytes     map[string]int64            `json:"user_bytes"`
	LineUserBytes map[string]map[string]int64 `json:"line_user_bytes,omitempty"`
	// The direction-split counter families as stored: user_traffic carries
	// only the u_<hash> names the server could place, never a raw credential.
	InboundTraffic     map[string]model.ProxyTrafficCounter `json:"inbound_traffic,omitempty"`
	UserTraffic        map[string]model.ProxyTrafficCounter `json:"user_traffic,omitempty"`
	OutboundTraffic    map[string]model.ProxyTrafficCounter `json:"outbound_traffic,omitempty"`
	IgnoredCounters    int                                  `json:"ignored_counters,omitempty"`
	CollectorSource    string                               `json:"collector_source,omitempty"`
	CollectorStatus    string                               `json:"collector_status,omitempty"`
	CollectorError     string                               `json:"collector_error,omitempty"`
	CollectorCheckedAt time.Time                            `json:"collector_checked_at,omitempty"`
}

type proxyUsageUserView struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Enabled           bool      `json:"enabled"`
	UsedBytes         int64     `json:"used_bytes"`
	TrafficLimitBytes int64     `json:"traffic_limit_bytes,omitempty"`
	LastSeenAt        time.Time `json:"last_seen_at,omitempty"`
	Status            string    `json:"status"`
}

type proxyUsageApplyResult struct {
	BytesDelta   int64 `json:"bytes_delta"`
	UsersUpdated int   `json:"users_updated"`
	UsersIgnored int   `json:"users_ignored"`
	// UnknownLines counts inbound tags this report carried that no line on
	// the node matches; their bytes are kept as unknown_line rows.
	UnknownLines int `json:"unknown_lines,omitempty"`
	// ProfileRegistered says this report created the node's discovered
	// profile (see registerDiscoveredProxyProfile).
	ProfileRegistered bool   `json:"profile_registered,omitempty"`
	AlertsFired       int    `json:"alerts_fired"`
	CollectorSource   string `json:"collector_source,omitempty"`
	CollectorStatus   string `json:"collector_status,omitempty"`
	// InboundDeferred says at least one inbound counter was held rather than
	// recorded, because the read model has no line for it right now and the
	// stored day rows say it had one before. Nothing was consumed for those
	// tags: their stored baseline is unchanged and the next report covers the
	// gap. InboundHeldTags names them, sorted.
	InboundDeferred bool     `json:"inbound_deferred,omitempty"`
	InboundHeldTags []string `json:"inbound_held_tags,omitempty"`
}

// usageColdTopologyDeferMax bounds how long a node's usage may be held back
// while its topology is missing. Deferring is safe because the counters are
// cumulative, but a node whose discovery never comes back would otherwise stop
// accounting silently and forever. Past this age the report is recorded the way
// it is today, as unknown_line bytes at node level: worse than attributing it,
// better than dropping it, and the behaviour this replaces rather than a new
// failure mode.
const usageColdTopologyDeferMax = 15 * time.Minute

func proxySubscriptionBody(format string, endpoints []proxycore.VLESSRealityEndpoint) ([]byte, string, error) {
	links := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		links = append(links, endpoint.Link())
	}
	sort.Strings(links)
	switch format {
	case proxycore.SubscriptionFormatPlain:
		return proxycore.PlainSubscription(links), "text/plain; charset=utf-8", nil
	case proxycore.SubscriptionFormatBase64:
		return proxycore.Base64Subscription(links), "text/plain; charset=utf-8", nil
	case proxycore.SubscriptionFormatSingBox:
		body, err := proxycore.SingBoxClientSubscription(endpoints)
		return body, "application/json; charset=utf-8", err
	case proxycore.SubscriptionFormatClash, proxycore.SubscriptionFormatClashMeta:
		return proxycore.ClashMetaSubscription(endpoints), "text/yaml; charset=utf-8", nil
	default:
		return nil, "", errors.New("unsupported subscription format")
	}
}

func normalizeProxySubscriptionFormat(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", proxycore.SubscriptionFormatBase64:
		return proxycore.SubscriptionFormatBase64, nil
	case proxycore.SubscriptionFormatPlain:
		return proxycore.SubscriptionFormatPlain, nil
	case proxycore.SubscriptionFormatSingBox:
		return proxycore.SubscriptionFormatSingBox, nil
	case proxycore.SubscriptionFormatClash:
		return proxycore.SubscriptionFormatClash, nil
	case proxycore.SubscriptionFormatClashMeta, "clash.meta", "clashmeta":
		return proxycore.SubscriptionFormatClashMeta, nil
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
		if proxyProfileOrigin(profile) == proxyProfileOriginDiscovered {
			continue // nothing to render: the lines are sb-managed, not Lattice inbounds
		}
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

// proxySubscriptionURL returns the public URL a proxy user is actually reachable
// at, which is the URL of a SHARE pointing at them - not anything derived from
// their own token.
//
// This distinction is the whole point of shares and it has a consequence worth
// stating: rotating a user's sub token no longer changes public access, because
// the share holds the credential the public URL carries. A user with no share is
// not published at all, and this returns empty rather than a plausible-looking
// address that would 404.
func (s *Server) proxySubscriptionURL(_ *http.Request, userID string) string {
	for _, share := range s.store.SubscriptionShares() {
		if share.Source.Kind != model.ShareSourceCoreProxyUser || share.Source.ProxyUserID != userID {
			continue
		}
		path := "/sub/" + url.PathEscape(share.Slug) + "/" + url.PathEscape(share.Token)
		base := strings.TrimRight(s.publicURL, "/")
		if base == "" {
			return path
		}
		return base + path
	}
	return ""
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
		s.invalidateLineReadModel()
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
	s.invalidateLineReadModel()
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
		s.invalidateLineReadModel()
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
	s.invalidateLineReadModel()
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
		"user": toProxyUserView(user),
		// Empty unless a share publishes this user. Rotating the user token does
		// not rotate that share: the share owns the public credential, and saying
		// so through an empty field is better than implying otherwise.
		"subscription_url":      s.proxySubscriptionURL(r, user.ID),
		"rotates_public_access": false,
		"token_sha256":          newHash,
	})
}

func (s *Server) handleProxyUsage(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireGlobalProxyScope(w, p, "proxy:read") {
		return
	}
	snapshots := s.store.ProxyUsageSnapshots()
	snapshotViews := make([]proxyUsageSnapshotView, 0, len(snapshots))
	for _, snapshot := range snapshots {
		snapshotViews = append(snapshotViews, s.toProxyUsageSnapshotView(snapshot))
	}
	users := s.store.ProxyUsers()
	userViews := make([]proxyUsageUserView, 0, len(users))
	for _, user := range users {
		userViews = append(userViews, toProxyUsageUserView(user))
	}
	window, err := parseUsagePeriod(r.URL.Query().Get("period"), s.now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	report, window := s.buildUsageLines(s.usageAttributionContext(), window)
	writeJSON(w, http.StatusOK, map[string]any{
		"snapshots":                       snapshotViews,
		"users":                           userViews,
		"lines":                           report.Rows,
		"double_counted_via_chains_bytes": report.DoubleCountedViaChainsBytes,
		"period":                          window.Label,
		"from":                            window.fromDay(),
		"to":                              window.toDay(),
	})
}

func (s *Server) handleAgentProxyUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		agentAuthRequest
		Snapshot model.ProxyUsageSnapshot `json:"snapshot"`
	}
	if !decodeAgentJSON(w, r, &req) {
		return
	}
	if _, ok := s.authenticateAgentRequest(r, req.NodeID); !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	req.Snapshot.NodeID = req.NodeID
	result, err := s.applyProxyUsageSnapshot(req.Snapshot)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	auditMeta := map[string]string{
		"bytes_delta":   strconv.FormatInt(result.BytesDelta, 10),
		"users_updated": strconv.Itoa(result.UsersUpdated),
		"users_ignored": strconv.Itoa(result.UsersIgnored),
	}
	if result.UnknownLines > 0 {
		auditMeta["unknown_lines"] = strconv.Itoa(result.UnknownLines)
	}
	// A held report is the state that replaces a burst of unknown_line rows,
	// and unknown_lines is the channel the original incident was found on. Held
	// reports keep UnknownLines at zero by design, so without this a node can
	// sit in a hold for the whole bound and signal nothing here: the fix would
	// be invisible to the surface that detected the problem it fixes.
	if result.InboundDeferred {
		auditMeta["inbound_deferred"] = "true"
	}
	if result.ProfileRegistered {
		auditMeta["profile_registered"] = "true"
	}
	if result.CollectorSource != "" {
		auditMeta["collector_source"] = result.CollectorSource
	}
	if result.CollectorStatus != "" {
		auditMeta["collector_status"] = result.CollectorStatus
	}
	if s.shouldAuditProxyUsage(req.NodeID, auditMeta, s.now()) {
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			Action:   "proxy.usage.report",
			Decision: "allow",
			NodeID:   req.NodeID,
			Metadata: auditMeta,
		})
	}
	writeJSON(w, http.StatusOK, result)
}

// proxyUsageAuditState remembers what the last audited report from a node
// said, so an unchanged heartbeat is not written again.
type proxyUsageAuditState struct {
	fingerprint string
	auditedAt   time.Time
}

// proxyUsageAuditInterval is the longest a node can report unchanged without
// an audit line. Long enough that a quiet fleet costs almost nothing, short
// enough that "this node was reporting" stays answerable.
const proxyUsageAuditInterval = 6 * time.Hour

// shouldAuditProxyUsage decides whether this usage report is worth an audit
// event. Every node posts every ten seconds, so auditing all of them wrote
// about 285,000 events a day across 33 nodes: 95 percent of the audit log was
// heartbeats, every query hit its scan cap inside a day, and an incident from
// the previous week became unreachable. A report is audited when something it
// says has changed, and otherwise at most once per interval. The same shape
// as shouldAuditSingBoxDiscovery, for the same reason.
func (s *Server) shouldAuditProxyUsage(nodeID string, meta map[string]string, now time.Time) bool {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	fingerprint := proxyUsageAuditFingerprint(meta)
	s.proxyUsageAuditMu.Lock()
	defer s.proxyUsageAuditMu.Unlock()
	if s.proxyUsageAudit == nil {
		s.proxyUsageAudit = map[string]proxyUsageAuditState{}
	}
	prev, ok := s.proxyUsageAudit[nodeID]
	if !ok || prev.fingerprint != fingerprint || now.Sub(prev.auditedAt) >= proxyUsageAuditInterval {
		s.proxyUsageAudit[nodeID] = proxyUsageAuditState{fingerprint: fingerprint, auditedAt: now}
		return true
	}
	return false
}

// proxyUsageAuditFingerprint covers what an operator would want an event for:
// a profile being registered, the collector's source or state changing, or
// counters being dropped. Byte counts are deliberately excluded, since those
// change on every report by design and are already recorded as usage.
//
// inbound_deferred belongs here rather than only in the metadata. Adding it to
// auditMeta alone was necessary and not sufficient: the gate below writes an
// event only when this fingerprint changes or six hours pass, so a hold on a
// node with nothing else changing could run its whole 15-minute course without
// producing a single stored event carrying the key, which is the silence the
// key exists to break.
//
// It is safe to include for the reason byte counts are not. It is a boolean
// that is stable across an episode, so it yields exactly two events per hold,
// one when it starts and one when it ends, rather than one per report.
func proxyUsageAuditFingerprint(meta map[string]string) string {
	keys := []string{"profile_registered", "collector_source", "collector_status", "ignored_counters", "error", "inbound_deferred"}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+meta[k])
	}
	return strings.Join(parts, "|")
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
		s.invalidateLineReadModel()
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
	s.invalidateLineReadModel()
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
	approval, err = s.submitApproval(r.Context(), approval)
	if err != nil {
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

func (s *Server) renderProxyCoreArtifact(nodeID string) (model.Node, model.ProxyNodeProfile, proxycore.Artifact, error) {
	return s.renderProxyCoreArtifactWithVpnUser(nodeID, nil)
}

func (s *Server) renderProxyCoreArtifactWithVpnUser(nodeID string, override *VpnUser) (model.Node, model.ProxyNodeProfile, proxycore.Artifact, error) {
	node, ok := s.store.Node(nodeID)
	if !ok {
		return model.Node{}, model.ProxyNodeProfile{}, proxycore.Artifact{}, errProxyPlanNodeNotFound
	}
	profile, ok := s.store.ProxyNodeProfile(nodeID)
	if !ok {
		return model.Node{}, model.ProxyNodeProfile{}, proxycore.Artifact{}, errProxyPlanProfileNotFound
	}
	var (
		artifact proxycore.Artifact
		err      error
	)
	users := s.proxyUsersForManagedRender(override)
	switch profile.Core {
	case model.ProxyCoreSingbox:
		artifact, err = proxycore.RenderSingBoxConfigJSON(profile, s.store.ProxyInbounds(), users, proxycore.RenderOptions{})
	case model.ProxyCoreXray:
		artifact, err = proxycore.RenderXrayConfigJSON(profile, s.store.ProxyInbounds(), users, proxycore.RenderOptions{})
	default:
		err = fmt.Errorf("unsupported proxy core %q", profile.Core)
	}
	if err != nil {
		return model.Node{}, model.ProxyNodeProfile{}, proxycore.Artifact{}, err
	}
	return node, profile, artifact, nil
}

func (s *Server) proxyUsersForManagedRender(override *VpnUser) []model.ProxyUser {
	vpnUsers := s.listVpnUsers()
	if override != nil {
		replaced := false
		for i := range vpnUsers {
			if vpnUsers[i].ID == override.ID {
				vpnUsers[i], replaced = *override, true
				break
			}
		}
		if !replaced {
			vpnUsers = append(vpnUsers, *override)
		}
	}
	lineByHash := map[string]Line{}
	groups, _ := s.lineReadModel()
	for _, group := range groups {
		for _, line := range group.Lines {
			lineByHash[line.LineHashID] = line
		}
	}
	replacedProxyUser := map[string]bool{}
	for _, user := range vpnUsers {
		if user.MigratedFromProxyUser == "" {
			replacedProxyUser[user.ID] = true // canonical usage projection, never a render source
			continue
		}
		if override != nil && override.ID == user.ID {
			replacedProxyUser[user.MigratedFromProxyUser] = true
			continue
		}
		for _, binding := range user.Bindings {
			if binding.Enabled && lineByHash[binding.LineHashID].Managed {
				replacedProxyUser[user.MigratedFromProxyUser] = true
				break
			}
		}
	}
	out := make([]model.ProxyUser, 0, len(s.store.ProxyUsers())+len(vpnUsers))
	for _, user := range s.store.ProxyUsers() {
		if !replacedProxyUser[user.ID] {
			out = append(out, user)
		}
	}
	for _, user := range vpnUsers {
		credential, ok := vpnCredentialForProtocol(user.Credentials, model.ProxyProtocolVLESS)
		if !ok || credential.UUID == "" {
			continue
		}
		for _, binding := range user.Bindings {
			line := lineByHash[binding.LineHashID]
			if !binding.Enabled || !line.Managed || line.Type != model.ProxyProtocolVLESS {
				continue
			}
			name := userLineName(user.ID, line.LineUUID)
			out = append(out, model.ProxyUser{
				ID: name, Name: name, Enabled: user.Enabled,
				UUID: credential.UUID, InboundIDs: []string{line.Tag}, TrafficLimitBytes: user.QuotaBytes,
				ExpiresAt: user.ExpiresAt, Status: model.ProxyUserStatusActive, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt,
			})
		}
	}
	return out
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

func (s *Server) currentProxyCoreArtifactForApproval(approval model.Approval) (proxycore.Artifact, error) {
	want, err := proxyCoreApprovalConfigSHA(approval)
	if err != nil {
		return proxycore.Artifact{}, err
	}
	_, _, artifact, err := s.renderProxyCoreArtifact(approval.NodeID)
	if err != nil {
		return proxycore.Artifact{}, fmt.Errorf("proxycore plan is no longer renderable: %w", err)
	}
	if !strings.EqualFold(want, artifact.ConfigSHA256) {
		return proxycore.Artifact{}, errors.New("proxycore config changed since this plan was created; re-plan before approving")
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

func proxyCoreApplyScript(artifact proxycore.Artifact) string {
	target := artifact.ConfigPath
	candidate := target + ".lattice-new"
	backup := target + ".lattice-prev"
	dir := path.Dir(target)
	binary, service, checkCmd, marker, err := proxyCoreApplyFacts(artifact.Core)
	if err != nil {
		return "set -e\n" +
			"echo " + shellQuote("lattice proxycore: "+err.Error()) + " >&2\n" +
			"exit 1\n"
	}
	return "set -e\n" +
		"umask 077\n" +
		proxyCoreEnsureRuntime(artifact.Core, binary, target) +
		"TARGET=" + shellQuote(target) + "\n" +
		"CANDIDATE=" + shellQuote(candidate) + "\n" +
		"BACKUP=" + shellQuote(backup) + "\n" +
		"DIR=" + shellQuote(dir) + "\n" +
		"RESTORE_TARGET=none\n" +
		"mkdir -p \"$DIR\"\n" +
		// Archive the existing config data (config.json + conf/ if present) before
		// applying, so every change leaves a timestamped per-node backup. Best
		// effort: a backup failure must never block or fail the apply.
		"LATTICE_ARCHIVE=/opt/lattice/.archive_backup\n" +
		"if command -v tar >/dev/null 2>&1 && { [ -f \"$TARGET\" ] || [ -d \"$DIR/conf\" ]; }; then\n" +
		"  mkdir -p \"$LATTICE_ARCHIVE\" 2>/dev/null || true\n" +
		"  LATTICE_BK_ITEMS=\"\"\n" +
		"  [ -f \"$TARGET\" ] && LATTICE_BK_ITEMS=\"$LATTICE_BK_ITEMS $(basename \"$TARGET\")\"\n" +
		"  [ -d \"$DIR/conf\" ] && LATTICE_BK_ITEMS=\"$LATTICE_BK_ITEMS conf\"\n" +
		"  tar -C \"$DIR\" -czf \"$LATTICE_ARCHIVE/" + service + "-$(date -u +%Y%m%d-%H%M%S).tar.gz\" $LATTICE_BK_ITEMS 2>/dev/null || true\n" +
		"fi\n" +
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
		"    systemctl restart " + service + " 2>/dev/null || true\n" +
		"  elif command -v service >/dev/null 2>&1; then\n" +
		"    service " + service + " restart 2>/dev/null || true\n" +
		"  fi\n" +
		"}\n" +
		"trap 'cleanup_candidate; restore_target; restart_after_restore' ERR\n" +
		heredocWrite(shellQuote(candidate), marker, artifact.ConfigJSON) +
		"chmod 0600 \"$CANDIDATE\"\n" +
		checkCmd + "\n" +
		"if [ -e \"$TARGET\" ]; then\n" +
		"  cp -p \"$TARGET\" \"$BACKUP\"\n" +
		"  RESTORE_TARGET=backup\n" +
		"else\n" +
		"  RESTORE_TARGET=remove\n" +
		"fi\n" +
		"mv -f \"$CANDIDATE\" \"$TARGET\"\n" +
		"if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then\n" +
		"  systemctl reload " + service + " 2>/dev/null || systemctl restart " + service + "\n" +
		"elif command -v service >/dev/null 2>&1; then\n" +
		"  service " + service + " reload 2>/dev/null || service " + service + " restart\n" +
		"else\n" +
		"  echo " + shellQuote("lattice proxycore: no supported service manager found for "+service+" reload/restart") + " >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"trap - ERR\n" +
		"rm -f \"$BACKUP\"\n" +
		"echo " + shellQuote("lattice proxycore: "+service+" config applied and verified") + "\n"
}

func proxyCoreApplyFacts(core string) (binary, service, checkCmd, marker string, err error) {
	switch core {
	case model.ProxyCoreSingbox:
		return "sing-box", "sing-box", "sing-box check -c \"$CANDIDATE\"", "LATTICE_PROXYCORE_SINGBOX_EOF", nil
	case model.ProxyCoreXray:
		return "xray", "xray", "xray test -c \"$CANDIDATE\"", "LATTICE_PROXYCORE_XRAY_EOF", nil
	default:
		return "", "", "", "", fmt.Errorf("unsupported proxy core %q", core)
	}
}

// defaultSingBoxVersion is the fallback sing-box release used only if the node
// cannot resolve the latest release tag at provision time. The provision block
// normally installs whatever the SagerNet "latest" redirect resolves to.
const defaultSingBoxVersion = "1.11.0"

// proxyCoreEnsureRuntime returns a shell prelude that guarantees the proxy core
// binary and a service unit exist before config is applied.
//
// For sing-box (the prioritized core) it AUTO-PROVISIONS — download the binary
// and create a systemd unit — but only when they are missing, so an already
// provisioned node (whether by Lattice or by hand) is left completely untouched
// and a re-apply has no install side effects (design-09 §E.3, Phase B). The
// install is gated by the operator approving the plan, whose preview is this
// very script. For any other core it keeps the original fail-closed behavior:
// the binary must already be present.
func proxyCoreEnsureRuntime(core, binary, configPath string) string {
	if core != model.ProxyCoreSingbox {
		return "if ! command -v " + binary + " >/dev/null 2>&1; then\n" +
			"  echo " + shellQuote("lattice proxycore: "+binary+" binary not found on node") + " >&2\n" +
			"  exit 1\n" +
			"fi\n"
	}
	unitPath := "/etc/systemd/system/sing-box.service"
	return "SB_BIN=/usr/local/bin/sing-box\n" +
		"if ! command -v sing-box >/dev/null 2>&1 && [ ! -x \"$SB_BIN\" ]; then\n" +
		"  echo " + shellQuote("lattice proxycore: sing-box not found, installing ...") + " >&2\n" +
		"  case \"$(uname -m)\" in\n" +
		"    x86_64|amd64) SB_ARCH=amd64 ;;\n" +
		"    aarch64|arm64) SB_ARCH=arm64 ;;\n" +
		"    armv7l|armv7) SB_ARCH=armv7 ;;\n" +
		"    *) echo " + shellQuote("lattice proxycore: unsupported arch") + " \"$(uname -m)\" >&2; exit 1 ;;\n" +
		"  esac\n" +
		"  SB_VER=\"$(curl -fsSL --proto '=https' --tlsv1.2 -o /dev/null -w '%{url_effective}' https://github.com/SagerNet/sing-box/releases/latest 2>/dev/null | sed -E 's#.*/tag/v?##')\"\n" +
		"  [ -n \"$SB_VER\" ] || SB_VER=" + shellQuote(defaultSingBoxVersion) + "\n" +
		"  SB_NAME=\"sing-box-${SB_VER}-linux-${SB_ARCH}\"\n" +
		"  SB_URL=\"https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/${SB_NAME}.tar.gz\"\n" +
		"  SB_TMP=\"$(mktemp -d)\"\n" +
		"  if command -v curl >/dev/null 2>&1; then curl -fsSL --proto '=https' --tlsv1.2 \"$SB_URL\" -o \"$SB_TMP/sb.tgz\";\n" +
		"  elif command -v wget >/dev/null 2>&1; then wget --https-only -qO \"$SB_TMP/sb.tgz\" \"$SB_URL\";\n" +
		"  else echo " + shellQuote("lattice proxycore: need curl or wget to install sing-box") + " >&2; exit 1; fi\n" +
		"  tar -xzf \"$SB_TMP/sb.tgz\" -C \"$SB_TMP\"\n" +
		"  install -m 0755 \"$SB_TMP/${SB_NAME}/sing-box\" \"$SB_BIN\"\n" +
		"  rm -rf \"$SB_TMP\"\n" +
		"fi\n" +
		"command -v sing-box >/dev/null 2>&1 || export PATH=\"/usr/local/bin:$PATH\"\n" +
		"if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then\n" +
		"  if [ ! -f " + shellQuote(unitPath) + " ] && ! systemctl cat sing-box >/dev/null 2>&1; then\n" +
		"    SB_RUN=\"$(command -v sing-box || echo /usr/local/bin/sing-box)\"\n" +
		"    SB_CFG=" + shellQuote(configPath) + "\n" +
		"    cat > " + shellQuote(unitPath) + " <<LATTICE_SB_UNIT_EOF\n" +
		"[Unit]\n" +
		"Description=sing-box (managed by Lattice)\n" +
		"After=network.target nss-lookup.target\n" +
		"[Service]\n" +
		"Type=simple\n" +
		"ExecStart=$SB_RUN run -c $SB_CFG\n" +
		"Restart=on-failure\n" +
		"RestartSec=5s\n" +
		"LimitNOFILE=1048576\n" +
		"[Install]\n" +
		"WantedBy=multi-user.target\n" +
		"LATTICE_SB_UNIT_EOF\n" +
		"    systemctl daemon-reload\n" +
		"    systemctl enable sing-box >/dev/null 2>&1 || true\n" +
		"  fi\n" +
		"fi\n"
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
		approval.Reason = ""
		approval.UpdatedAt = time.Now().UTC()
		if err := s.store.UpsertApproval(approval); err != nil {
			return fmt.Errorf("mark proxycore approval applied: %w", err)
		}
		if err := s.store.UpsertProxyNodeProfile(profile); err != nil {
			return fmt.Errorf("mark proxycore profile applied: %w", err)
		}
		s.invalidateLineReadModel()
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   approval.NodeID,
			Action:   "proxy.apply.applied",
			Decision: "allow",
			Metadata: metadata,
		})
		// Recompute drift now so the dashboard "config out of date" banner clears
		// immediately after the enforcing apply, rather than at the next tick.
		s.refreshProxyDriftFor(approval.NodeID, time.Now().UTC())
		return nil
	}
	reason := taskFailureSummary(result)
	profile.LastError = reason
	if err := s.store.UpsertProxyNodeProfile(profile); err != nil {
		return fmt.Errorf("mark proxycore apply failed: %w", err)
	}
	s.invalidateLineReadModel()
	if err := s.rejectApprovalWithReason(approval, reason); err != nil {
		return fmt.Errorf("mark proxycore approval rejected: %w", err)
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

func renderProxyCoreApprovalPlan(node model.Node, profile model.ProxyNodeProfile, artifact proxycore.Artifact, redactedConfig string) string {
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
	fmt.Fprintf(&b, "\n## redacted %s config\n", artifact.Core)
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
			case "private_key", "privatekey", "uuid", "password", "id":
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
	view := proxyNodeProfileView{
		ID:            profile.ID,
		NodeID:        profile.NodeID,
		NodeName:      nodeName,
		Origin:        proxyProfileOrigin(profile),
		Core:          profile.Core,
		InboundIDs:    append([]string(nil), profile.InboundIDs...),
		Hostname:      profile.Hostname,
		ListenIP:      profile.ListenIP,
		ConfigPath:    profile.ConfigPath,
		StatsAPI:      profile.StatsAPI,
		AppliedSHA256: profile.AppliedSHA256,
		LastApplyAt:   profile.LastApplyAt,
		LastError:     profile.LastError,

		UsageCollectorSource:      profile.UsageCollectorSource,
		UsageCollectorStatus:      profile.UsageCollectorStatus,
		UsageCollectorCheckedAt:   profile.UsageCollectorCheckedAt,
		UsageCollectorLastOKAt:    profile.UsageCollectorLastOKAt,
		UsageCollectorLastError:   profile.UsageCollectorLastError,
		UsageCollectorLastErrorAt: profile.UsageCollectorLastErrorAt,

		CreatedAt: profile.CreatedAt,
		UpdatedAt: profile.UpdatedAt,
	}
	if drift, ok := s.proxyDriftFor(profile.NodeID); ok {
		view.ConfigStale = drift.Stale
		view.PendingConfigSHA256 = drift.PendingSHA256
		view.IneligibleUsers = drift.IneligibleUsers
		view.DriftReason = drift.Reason
		view.DriftCheckedAt = drift.CheckedAt
	}
	return view
}

func (s *Server) toProxyUsageSnapshotView(snapshot model.ProxyUsageSnapshot) proxyUsageSnapshotView {
	nodeName := ""
	if node, ok := s.store.Node(snapshot.NodeID); ok {
		nodeName = node.Name
	}
	view := proxyUsageSnapshotView{
		NodeID:             snapshot.NodeID,
		NodeName:           nodeName,
		At:                 snapshot.At,
		CoreUptimeSec:      snapshot.CoreUptimeSec,
		UserBytes:          cloneProxyUserBytes(snapshot.UserBytes),
		InboundTraffic:     cloneTrafficCounters(snapshot.InboundTraffic),
		UserTraffic:        cloneTrafficCounters(snapshot.UserTraffic),
		OutboundTraffic:    cloneTrafficCounters(snapshot.OutboundTraffic),
		IgnoredCounters:    snapshot.IgnoredCounters,
		CollectorSource:    snapshot.CollectorSource,
		CollectorStatus:    snapshot.CollectorStatus,
		CollectorError:     snapshot.CollectorError,
		CollectorCheckedAt: snapshot.CollectorCheckedAt,
	}
	if len(snapshot.LineUserBytes) > 0 {
		view.LineUserBytes = make(map[string]map[string]int64, len(snapshot.LineUserBytes))
		for line, byUser := range snapshot.LineUserBytes {
			view.LineUserBytes[line] = cloneProxyUserBytes(byUser)
		}
	}
	return view
}

func cloneTrafficCounters(in map[string]model.ProxyTrafficCounter) map[string]model.ProxyTrafficCounter {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]model.ProxyTrafficCounter, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func toProxyUsageUserView(user model.ProxyUser) proxyUsageUserView {
	return proxyUsageUserView{
		ID:                user.ID,
		Name:              user.Name,
		Enabled:           user.Enabled,
		UsedBytes:         user.UsedBytes,
		TrafficLimitBytes: user.TrafficLimitBytes,
		LastSeenAt:        user.LastSeenAt,
		Status:            user.Status,
	}
}

func cloneProxyUserBytes(in map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(in))
	for userID, value := range in {
		out[userID] = value
	}
	return out
}

// validProxyUsageCollectorStatus reports whether a status is one of the three
// the agent wire contract defines. Every other value is an arbitrary string and
// carries no meaning, whether it arrives as health or as discovery evidence.
func validProxyUsageCollectorStatus(status string) bool {
	switch status {
	case model.ProxyUsageCollectorStatusOK, model.ProxyUsageCollectorStatusError, proxyUsageCollectorStatusStatsOff:
		return true
	}
	return false
}

func applyProxyUsageCollectorHealth(profile model.ProxyNodeProfile, snapshot model.ProxyUsageSnapshot, now time.Time) (model.ProxyNodeProfile, bool, error) {
	source := strings.TrimSpace(snapshot.CollectorSource)
	status := strings.TrimSpace(snapshot.CollectorStatus)
	errText := sanitizeProxyUsageCollectorError(snapshot.CollectorError)
	hasReport := source != "" || status != "" || errText != "" || !snapshot.CollectorCheckedAt.IsZero()
	if !hasReport {
		return profile, false, nil
	}
	if source != "" && !proxyIDRe.MatchString(source) {
		return model.ProxyNodeProfile{}, false, fmt.Errorf("invalid collector_source %q", source)
	}
	if status == "" {
		if errText != "" {
			status = model.ProxyUsageCollectorStatusError
		} else {
			status = model.ProxyUsageCollectorStatusOK
		}
	}
	if !validProxyUsageCollectorStatus(status) {
		return model.ProxyNodeProfile{}, false, fmt.Errorf("invalid collector_status %q", status)
	}
	checkedAt := snapshot.CollectorCheckedAt
	if checkedAt.IsZero() {
		checkedAt = snapshot.At
	}
	if checkedAt.IsZero() {
		checkedAt = now
	}
	checkedAt = checkedAt.UTC()
	profile.UsageCollectorSource = source
	profile.UsageCollectorStatus = status
	profile.UsageCollectorCheckedAt = checkedAt
	switch status {
	case model.ProxyUsageCollectorStatusOK:
		profile.UsageCollectorLastOKAt = checkedAt
	case model.ProxyUsageCollectorStatusError:
		if len(snapshot.UserBytes) > 0 {
			return model.ProxyNodeProfile{}, false, errors.New("collector error reports must not include user_bytes")
		}
		if errText == "" {
			errText = "collector reported an error"
		}
		profile.UsageCollectorLastError = errText
		profile.UsageCollectorLastErrorAt = checkedAt
	case proxyUsageCollectorStatusStatsOff:
		// The node runs a sing-box config without experimental.v2ray_api. A
		// configuration state, kept apart from a collector fault, and it can
		// carry no counters because there are none.
		if len(snapshot.UserBytes) > 0 || len(snapshot.InboundTraffic) > 0 || len(snapshot.UserTraffic) > 0 {
			return model.ProxyNodeProfile{}, false, errors.New("stats_off reports must not include counters")
		}
		if errText == "" {
			errText = "sing-box config has no experimental.v2ray_api"
		}
		profile.UsageCollectorLastError = errText
		profile.UsageCollectorLastErrorAt = checkedAt
	}
	return profile, true, nil
}

func sanitizeProxyUsageCollectorError(value string) string {
	value = strings.Map(func(r rune) rune {
		if proxyUnsafeControl(r) && r != '\t' {
			return -1
		}
		return r
	}, value)
	return truncateMetadataValue(value, 512)
}

// usageHoldKey addresses one node's hold window for one inbound tag. Holding is
// tracked per tag rather than per node because the two reasons a tag stops
// resolving expire differently: a line the mirror dropped comes back on its own,
// while a line that was genuinely deleted never does. A shared window would let
// the second exhaust the budget of the first.
func usageHoldKey(nodeID, tag string) string { return nodeID + "\x00" + tag }

// usageAttributedTagsForNode returns the inbound tags this node has previously
// had attributed to a line, read from the stored day rows.
//
// This is the discriminator that separates a line the read model has lost from
// a tag that never named one. Ingestion records the line it resolved into
// UsageDayLine.LineHashID, so a tag carrying one is a line the server has
// attributed before and can attribute again once discovery catches up. A tag
// that has never carried one is a ghost: no amount of waiting resolves it, and
// holding it would stall its bytes for the whole bound and then record them
// anyway.
//
// The test is usageDayLineEverAttributed, shared with the read path's own fallback
// rather than restated here. The two ask it for different reasons and are not
// interchangeable, but they must agree about what counts as evidence, and two
// predicates that must agree should be one predicate.
//
// Two days rather than one, so a report arriving just after midnight still sees
// yesterday's evidence.
func (s *Server) usageAttributedTagsForNode(nodeID string, now time.Time) map[string]bool {
	from := store.UsageDay(now.AddDate(0, 0, -1))
	rows, err := s.store.UsageDayNodeRows(nodeID, from, store.UsageDay(now))
	if err != nil {
		s.logger.Printf("usage: read day rows for %s: %v", nodeID, err)
		return nil
	}
	out := map[string]bool{}
	for _, row := range rows {
		for tag, line := range row.Lines {
			if usageDayLineEverAttributed(line) {
				out[tag] = true
			}
		}
	}
	return out
}

// holdUnresolvableInboundTags carries the previous report's value for every
// inbound counter that cannot be attributed right now but has been attributed
// before, and reports how many it held.
//
// A counter that lands with no line to attribute it to becomes an unknown_line
// row carrying no identity. No UsageDayUser row is written for it, the
// cumulative delta is consumed anyway, and quota reads exactly the rows that
// were never written, so that traffic is missing from quota permanently while
// the per-line view re-derives the full number as soon as discovery returns.
// Because the counters are cumulative, holding one costs nothing: the next
// report that lands with the line back produces one delta covering the gap.
//
// Held per tag, not per node. An earlier version held only when the node had no
// lines at all, on the reasoning that a single missing tag is a genuine unknown
// tag. That is true of a tag with no history and false of one with history, and
// the difference is decidable from the stored day rows rather than guessable
// from the shape of the report. A node whose mirror drops one line of thirteen
// still loses that line's traffic permanently, which is the same defect wearing
// a smaller hat, and it was reproduced rather than argued.
//
// Never on a first report, because nothing is consumed without a baseline and
// holding would leave the next report diffing against nothing. Never after a
// core restart, because the current value IS the delta and holding would store
// a pre-restart baseline the next report diffs to nothing.
func (s *Server) holdUnresolvableInboundTags(ctx *usageAttributionContext, snapshot *model.ProxyUsageSnapshot, previous model.ProxyUsageSnapshot, hadPrevious, reset bool, now time.Time) []string {
	if !hadPrevious || reset || len(snapshot.InboundTraffic) == 0 {
		s.clearUsageHolds(snapshot.NodeID, snapshot.InboundTraffic)
		return nil
	}
	lines := ctx.byNodeTag[snapshot.NodeID]
	// Two independent reasons to believe a tag names a real line the read model
	// has merely lost, and either is enough.
	//
	// The node having no lines at all is the whole-node signature: a mirror that
	// went cold cannot speak for any tag, so nothing this node reports can be
	// called a ghost on its evidence. That is the case an eviction produces.
	//
	// Otherwise the tag has to prove itself, and the stored day rows are where
	// it does: ingestion records the line it resolved into UsageDayLine, so a
	// tag carrying one has been attributed before and will be again once the
	// line is back. A tag on a node whose other lines resolve, with no such
	// history, is a ghost. Waiting cannot resolve it and holding would stall its
	// bytes for the whole bound before recording them anyway.
	nodeIsBlind := len(lines) == 0
	var attributedBefore map[string]bool
	var held []string
	for tag := range snapshot.InboundTraffic {
		if lines[tag] != nil {
			delete(s.usageInboundHeldSince, usageHoldKey(snapshot.NodeID, tag))
			continue
		}
		if !nodeIsBlind {
			if attributedBefore == nil {
				attributedBefore = s.usageAttributedTagsForNode(snapshot.NodeID, now)
			}
			if !attributedBefore[tag] {
				continue
			}
		}
		key := usageHoldKey(snapshot.NodeID, tag)
		since, ok := s.usageInboundHeldSince[key]
		if ok && now.Sub(since) > usageColdTopologyDeferMax {
			continue // held long enough; record it the way it would be today
		}
		if !ok {
			if s.usageInboundHeldSince == nil {
				s.usageInboundHeldSince = map[string]time.Time{}
			}
			s.usageInboundHeldSince[key] = now
		}
		held = append(held, tag)
	}
	if len(held) == 0 {
		return nil
	}
	sort.Strings(held)
	// Carry the previous value forward so the counter diffs to zero. A tag with
	// no previous value is dropped instead, which is the same thing: nothing to
	// diff against means nothing is consumed.
	for _, tag := range held {
		if prior, ok := previous.InboundTraffic[tag]; ok {
			snapshot.InboundTraffic[tag] = prior
			continue
		}
		delete(snapshot.InboundTraffic, tag)
	}
	return held
}

// clearUsageHolds forgets the hold windows for tags this report carries, so a
// node that recovers starts from a fresh budget rather than an exhausted one.
func (s *Server) clearUsageHolds(nodeID string, tags map[string]model.ProxyTrafficCounter) {
	for tag := range tags {
		delete(s.usageInboundHeldSince, usageHoldKey(nodeID, tag))
	}
}

func (s *Server) applyProxyUsageSnapshot(snapshot model.ProxyUsageSnapshot) (proxyUsageApplyResult, error) {
	s.proxyUsageMu.Lock()
	defer s.proxyUsageMu.Unlock()

	snapshot.NodeID = strings.TrimSpace(snapshot.NodeID)
	if snapshot.NodeID == "" {
		return proxyUsageApplyResult{}, errors.New("node_id is required")
	}
	result := proxyUsageApplyResult{}
	profile, ok := s.store.ProxyNodeProfile(snapshot.NodeID)
	if !ok {
		registered, err := s.registerDiscoveredProxyProfile(snapshot)
		if err != nil {
			return proxyUsageApplyResult{}, err
		}
		profile = registered
		result.ProfileRegistered = true
	}
	if snapshot.At.IsZero() {
		snapshot.At = s.now()
	}
	collectorUpdated := false
	if updatedProfile, updated, err := applyProxyUsageCollectorHealth(profile, snapshot, s.now()); err != nil {
		return proxyUsageApplyResult{}, err
	} else if updated {
		profile = updatedProfile
		collectorUpdated = true
		result.CollectorSource = profile.UsageCollectorSource
		result.CollectorStatus = profile.UsageCollectorStatus
		if profile.UsageCollectorStatus == model.ProxyUsageCollectorStatusError || profile.UsageCollectorStatus == proxyUsageCollectorStatusStatsOff {
			if err := s.store.ApplyProxyUsageUpdate(nil, &profile, nil); err != nil {
				return proxyUsageApplyResult{}, err
			}
			return result, nil
		}
	}
	if len(snapshot.UserBytes) > 4096 || len(snapshot.UserTraffic) > 4096 || len(snapshot.InboundTraffic) > 4096 || len(snapshot.OutboundTraffic) > 4096 {
		return proxyUsageApplyResult{}, errors.New("usage snapshot has too many entries")
	}
	if err := validateProxyTrafficCounters(snapshot.InboundTraffic, "inbound_traffic"); err != nil {
		return proxyUsageApplyResult{}, err
	}
	if err := validateProxyTrafficCounters(snapshot.OutboundTraffic, "outbound_traffic"); err != nil {
		return proxyUsageApplyResult{}, err
	}
	if err := validateProxyTrafficCounters(snapshot.UserTraffic, "user_traffic"); err != nil {
		return proxyUsageApplyResult{}, err
	}
	// A collector that reports the direction split may leave user_bytes out;
	// the per-user sum is what the monotonic path has always diffed.
	if len(snapshot.UserBytes) == 0 && len(snapshot.UserTraffic) > 0 {
		snapshot.UserBytes = make(map[string]int64, len(snapshot.UserTraffic))
		for name, c := range snapshot.UserTraffic {
			snapshot.UserBytes[name] = c.Uplink + c.Downlink
		}
	}
	// design-15 §8: reverse on-box u_<hash> stat names into (line, proxy user)
	// accounting rows before eligibility checks and monotonic diffing. The
	// attribution context carries the same index, computed once.
	//
	// The index is fleet-wide, so it is narrowed to the reporting node first: a
	// name only proves anything about a line that node serves. A valid name for
	// another node's line is dropped and counted as ignored, never folded and
	// never used to widen eligibility, which is what kept one node from
	// attributing bytes to any (line, user) pair in the fleet.
	attribution := s.usageAttributionContext()
	nameIndex := attribution.nodeNameIndex(snapshot.NodeID)
	folded := map[string]bool{}
	foreignNames := 0
	for name := range snapshot.UserBytes {
		if target, ok := nameIndex[name]; ok {
			folded[target.ProxyUserID] = true
			continue
		}
		if _, ok := attribution.nameIndex[name]; ok {
			delete(snapshot.UserBytes, name)
			foreignNames++
		}
	}
	foldUserLineUsage(&snapshot, nameIndex)
	// Direction-split user counters are kept by name, but only the names the
	// index can place: on an sb-managed node an unnamed user's key is the
	// credential itself, and that must never be stored or echoed.
	snapshot.UserTraffic = keepIndexedUserTraffic(snapshot.UserTraffic, nameIndex)
	eligible := s.proxyUsageEligibleUsers(profile)
	ensureEligible := func(acct string) {
		if _, ok := eligible[acct]; ok {
			return
		}
		if stored, ok := s.store.ProxyUser(acct); ok {
			eligible[acct] = stored
		} else if vu, ok := attribution.users[attribution.vpnByAcct[acct]]; ok {
			eligible[acct] = vpnUserUsageProjection(vu)
		}
	}
	// A folded u_<hash> counter is the node's own statement that it serves
	// that identity, so the identity is eligible here even while discovery
	// is stale and the binding's line is missing from the read model.
	for acct := range folded {
		ensureEligible(acct)
	}
	lineUserBytes, lineUserTotals, lineUsersIgnored, err := s.sanitizeProxyUsageLineUserBytes(snapshot.NodeID, snapshot.LineUserBytes, eligible)
	if err != nil {
		return proxyUsageApplyResult{}, err
	}
	snapshot.LineUserBytes = lineUserBytes
	if len(snapshot.UserBytes) == 0 && len(lineUserTotals) > 0 {
		snapshot.UserBytes = lineUserTotals
	}
	sanitized := map[string]int64{}
	ignored := lineUsersIgnored + foreignNames
	for userID, value := range snapshot.UserBytes {
		userID = strings.TrimSpace(userID)
		if !proxyIDRe.MatchString(userID) {
			return proxyUsageApplyResult{}, fmt.Errorf("invalid proxy user id %q", userID)
		}
		if value < 0 {
			return proxyUsageApplyResult{}, fmt.Errorf("proxy usage for %s cannot be negative", userID)
		}
		if _, ok := eligible[userID]; !ok {
			ignored++
			continue
		}
		sanitized[userID] = value
	}
	snapshot.UserBytes = sanitized

	previous, hadPrevious := s.store.ProxyUsageSnapshot(snapshot.NodeID)
	result.UsersIgnored = ignored
	now := s.now()
	reset := hadPrevious && snapshot.CoreUptimeSec < previous.CoreUptimeSec
	// Inbound counters can only be attributed against the line read model, and
	// that model is fed by an in-memory discovery mirror evicted after
	// nodeOfflineThreshold. A node whose agent misses a couple of inventory
	// posts therefore reports real counters into an empty topology, and every
	// one of them lands as an unknown_line row carrying no user: no
	// UsageDayUser row is written, the cumulative delta is consumed anyway, and
	// quota, which reads exactly those rows, stays short by that traffic
	// permanently while the per-line view re-derives the full number at read.
	// Two surfaces then disagree forever over a gap that lasted seconds.
	//
	// The counters are cumulative, so declining to record the report costs
	// nothing. Leaving the stored baseline untouched means the next report that
	// lands with a warm read model produces one delta covering the whole gap,
	// attributed correctly. This finishes a decision already made one screen up
	// for named counters, which are held eligible while discovery is stale
	// rather than dropped; the inbound family never got the same treatment, and
	// it is the only usage signal for lines whose users carry no name.
	//
	// The trigger is deliberately the whole node having no lines, not a single
	// tag missing one. A tag with no line while the node's other lines resolve
	// is a genuine unknown tag and must still be recorded as one.
	if held := s.holdUnresolvableInboundTags(attribution, &snapshot, previous, hadPrevious, reset, now); len(held) > 0 {
		result.InboundDeferred = true
		result.InboundHeldTags = held
		s.logger.Printf("usage: node %s reported %d inbound counters this server cannot attribute but has attributed before (%s); holding them so the delta is not consumed",
			snapshot.NodeID, len(held), strings.Join(held, ", "))
	}
	// Per-user deltas from the legacy total path. A counter that decreased
	// without an uptime reset is a new baseline for that user and advances
	// nothing.
	legacyDelta := map[string]int64{}
	lineUserDelta := map[string]map[string]int64{}
	if hadPrevious {
		for userID, current := range snapshot.UserBytes {
			if delta := monotonicDelta(current, previous.UserBytes[userID], reset); delta > 0 {
				legacyDelta[userID] = delta
			}
		}
		for lineHash, byUser := range snapshot.LineUserBytes {
			for userID, current := range byUser {
				if delta := monotonicDelta(current, previous.LineUserBytes[lineHash][userID], reset); delta > 0 {
					if lineUserDelta[lineHash] == nil {
						lineUserDelta[lineHash] = map[string]int64{}
					}
					lineUserDelta[lineHash][userID] = delta
				}
			}
		}
	}
	deltas := s.usageIngest(attribution, snapshot, previous, hadPrevious, reset, now, legacyDelta, lineUserDelta)
	result.UnknownLines = deltas.UnknownLines
	userDelta := map[string]int64{}
	for acct, delta := range legacyDelta {
		userDelta[acct] = delta
	}
	// Inbound bytes the credential and binding rules assigned to identities
	// join the per-user delta. Those identities may have no binding on this
	// node, so they are made eligible from their stored projection.
	for acct, c := range deltas.Attributed {
		userDelta[acct] += c.total()
		ensureEligible(acct)
	}
	usersToSave := []model.ProxyUser{}
	alertsToEmit := []proxyUserNotificationFire{}
	if hadPrevious {
		accts := make([]string, 0, len(userDelta))
		for acct := range userDelta {
			accts = append(accts, acct)
		}
		sort.Strings(accts)
		for _, acct := range accts {
			delta := userDelta[acct]
			user, ok := eligible[acct]
			if delta <= 0 || !ok {
				continue
			}
			user.UsedBytes += delta
			user.LastSeenAt = snapshot.At
			pending := usageCounter{Downlink: delta}
			vpnID := attribution.vpnByAcct[acct]
			if row, ok := deltas.DayUsers[vpnID]; ok {
				pending = usageCounter{Uplink: row.Uplink, Downlink: row.Downlink}
			}
			var vpnUser *VpnUser
			if vu, ok := attribution.users[vpnID]; ok {
				vpnUser = &vu
			}
			user, alerts := s.quotaEvaluate(user, vpnUser, now, pending)
			usersToSave = append(usersToSave, user)
			alertsToEmit = append(alertsToEmit, alerts...)
			result.BytesDelta += delta
			result.UsersUpdated++
			result.AlertsFired += len(alerts)
		}
	} else {
		for userID := range snapshot.UserBytes {
			user := eligible[userID]
			user.LastSeenAt = snapshot.At
			user, alerts := s.quotaEvaluate(user, s.vpnUserForAccounting(userID), now, usageCounter{})
			usersToSave = append(usersToSave, user)
			alertsToEmit = append(alertsToEmit, alerts...)
			result.UsersUpdated++
			result.AlertsFired += len(alerts)
		}
	}
	var profileToSave *model.ProxyNodeProfile
	if collectorUpdated {
		profileToSave = &profile
	}
	update := store.ProxyUsageUpdate{Users: usersToSave, Profile: profileToSave, Snapshot: &snapshot, DayNode: deltas.DayNode}
	for _, row := range deltas.DayUsers {
		update.DayUsers = append(update.DayUsers, *row)
	}
	sort.Slice(update.DayUsers, func(i, j int) bool { return update.DayUsers[i].UserID < update.DayUsers[j].UserID })
	if err := s.store.ApplyProxyUsage(update); err != nil {
		return proxyUsageApplyResult{}, err
	}
	s.maybePruneUsageDays(now)
	s.emitProxyUserNotifications(alertsToEmit)
	return result, nil
}

// registerDiscoveredProxyProfile gives a node that reports usage without a
// proxy profile one of origin "discovered": core sing-box, no managed
// inbounds. Every sb-managed node in the fleet is in this position, and the
// alternative was an agent posting every ten seconds into a 400. The node
// must be known, and either its sing-box inventory must be on record or the
// snapshot itself must prove a collector; an empty report from a node with
// no inventory still gets the old error, so nothing is registered on noise.
func (s *Server) registerDiscoveredProxyProfile(snapshot model.ProxyUsageSnapshot) (model.ProxyNodeProfile, error) {
	if _, ok := s.store.Node(snapshot.NodeID); !ok {
		return model.ProxyNodeProfile{}, fmt.Errorf("proxy node profile %s not found", snapshot.NodeID)
	}
	_, discovered := s.singBoxInventory(snapshot.NodeID)
	// Evidence has to be evidence. A collector_source or a collector_status the
	// contract does not define is one arbitrary string, and registering on it
	// let any authenticated node mint a profile and an audit row out of noise.
	// Either the status is one the agent actually reports, or the snapshot
	// carries a counter map.
	proves := validProxyUsageCollectorStatus(strings.TrimSpace(snapshot.CollectorStatus)) ||
		len(snapshot.UserBytes) > 0 || len(snapshot.LineUserBytes) > 0 ||
		len(snapshot.InboundTraffic) > 0 || len(snapshot.UserTraffic) > 0 || len(snapshot.OutboundTraffic) > 0
	if !discovered && !proves {
		return model.ProxyNodeProfile{}, fmt.Errorf("proxy node profile %s not found and the report carries no collector evidence", snapshot.NodeID)
	}
	now := s.now()
	profile := model.ProxyNodeProfile{ID: snapshot.NodeID, NodeID: snapshot.NodeID, Core: model.ProxyCoreSingbox, InboundIDs: []string{}, CreatedAt: now, UpdatedAt: now}
	if err := s.store.UpsertProxyNodeProfile(profile); err != nil {
		return model.ProxyNodeProfile{}, err
	}
	s.invalidateLineReadModel()
	reason := "usage report from a node with discovered sing-box lines"
	if !discovered {
		reason = "usage report carrying collector evidence"
	}
	s.recordAudit(model.AuditEvent{
		ID: id.New("audit"), NodeID: snapshot.NodeID, Action: "proxy.profile.discovered", Scope: "proxy:admin", Decision: "allow", ActorID: "system",
		Metadata: map[string]string{"profile_id": profile.ID, "core": profile.Core, "reason": reason},
	})
	if stored, ok := s.store.ProxyNodeProfile(snapshot.NodeID); ok {
		profile = stored
	}
	return profile, nil
}

const (
	proxyProfileOriginManaged    = "managed"
	proxyProfileOriginDiscovered = "discovered"
)

// proxyProfileOrigin is derived, not stored: a profile with no managed
// inbound and no applied config is by construction one the server never
// rendered, which is exactly the discovered case.
func proxyProfileOrigin(profile model.ProxyNodeProfile) string {
	if len(profile.InboundIDs) == 0 && strings.TrimSpace(profile.AppliedSHA256) == "" {
		return proxyProfileOriginDiscovered
	}
	return proxyProfileOriginManaged
}

// monotonicDelta is the per-counter rule shared by every family: a core
// restart makes the current value the delta; a decrease without one is a new
// baseline that advances nothing.
func monotonicDelta(current, prior int64, reset bool) int64 {
	switch {
	case reset:
		return current
	case current >= prior:
		return current - prior
	default:
		return 0
	}
}

func validateProxyTrafficCounters(counters map[string]model.ProxyTrafficCounter, field string) error {
	for key, c := range counters {
		if strings.TrimSpace(key) == "" || len(key) > 256 || strings.ContainsFunc(key, proxyUnsafeControl) {
			return fmt.Errorf("%s has an invalid counter name", field)
		}
		if c.Uplink < 0 || c.Downlink < 0 {
			return fmt.Errorf("%s counter %q cannot be negative", field, key)
		}
	}
	return nil
}

// keepIndexedUserTraffic drops every user counter whose name the design-15
// index cannot place. Unmatched names degrade to "ignored" on the total path
// already; here they must not even be persisted.
func keepIndexedUserTraffic(counters map[string]model.ProxyTrafficCounter, index map[string]userLineNameTarget) map[string]model.ProxyTrafficCounter {
	if len(counters) == 0 {
		return nil
	}
	out := map[string]model.ProxyTrafficCounter{}
	for name, c := range counters {
		if _, ok := index[name]; ok {
			out[name] = c
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// sanitizeProxyUsageLineUserBytes keeps the (line, user) pairs nodeID is
// entitled to report: the counters live on the box that owns the inbound, so a
// line the read model places on another node is ignored the same way an unknown
// line is, not attributed.
func (s *Server) sanitizeProxyUsageLineUserBytes(nodeID string, input map[string]map[string]int64, eligible map[string]model.ProxyUser) (map[string]map[string]int64, map[string]int64, int, error) {
	if len(input) == 0 {
		return nil, nil, 0, nil
	}
	if len(input) > 4096 {
		return nil, nil, 0, errors.New("line_user_bytes has too many lines")
	}
	knownLines := map[string]bool{}
	groups, _ := s.lineReadModel()
	for _, group := range groups {
		for _, line := range group.Lines {
			if line.LineHashID != "" && line.NodeID == nodeID {
				knownLines[line.LineHashID] = true
			}
		}
	}
	out := map[string]map[string]int64{}
	totals := map[string]int64{}
	ignored := 0
	entries := 0
	for lineID, users := range input {
		lineID = strings.TrimSpace(lineID)
		if lineID == "" {
			return nil, nil, 0, errors.New("line_user_bytes line id cannot be empty")
		}
		if len(lineID) > 256 {
			return nil, nil, 0, errors.New("line_user_bytes line id is too long")
		}
		if !knownLines[lineID] {
			ignored += len(users)
			continue
		}
		dst := out[lineID]
		for userID, value := range users {
			entries++
			if entries > 4096 {
				return nil, nil, 0, errors.New("line_user_bytes has too many entries")
			}
			userID = strings.TrimSpace(userID)
			if !proxyIDRe.MatchString(userID) {
				return nil, nil, 0, fmt.Errorf("invalid proxy user id %q", userID)
			}
			if value < 0 {
				return nil, nil, 0, fmt.Errorf("proxy usage for %s on line %s cannot be negative", userID, lineID)
			}
			if _, ok := eligible[userID]; !ok {
				ignored++
				continue
			}
			if dst == nil {
				dst = map[string]int64{}
				out[lineID] = dst
			}
			dst[userID] += value
			totals[userID] += value
		}
	}
	if len(out) == 0 {
		return nil, nil, ignored, nil
	}
	return out, totals, ignored, nil
}

func (s *Server) proxyUsageEligibleUsers(profile model.ProxyNodeProfile) map[string]model.ProxyUser {
	out := map[string]model.ProxyUser{}
	for _, user := range s.store.ProxyUsers() {
		if proxyUserAppliesToProfile(user, profile) {
			out[user.ID] = user
		}
	}
	lineNode := map[string]string{}
	groups, _ := s.lineReadModel()
	for _, group := range groups {
		for _, line := range group.Lines {
			lineNode[line.LineHashID] = group.NodeID
		}
	}
	for _, user := range s.listVpnUsers() {
		if user.MigratedFromProxyUser != "" {
			continue
		}
		applies := false
		for _, binding := range user.Bindings {
			if binding.Enabled && lineNode[binding.LineHashID] == profile.NodeID {
				applies = true
				break
			}
		}
		if applies {
			projection := vpnUserUsageProjection(user)
			if previous, ok := out[user.ID]; ok {
				projection.UsedBytes = previous.UsedBytes
				projection.LastSeenAt = previous.LastSeenAt
				projection.LastQuotaNotifiedKey = previous.LastQuotaNotifiedKey
				projection.LastExpiryNotifiedKey = previous.LastExpiryNotifiedKey
			}
			out[user.ID] = projection
		}
	}
	return out
}

func vpnUserUsageProjection(user VpnUser) model.ProxyUser {
	status := model.ProxyUserStatusActive
	if !user.Enabled {
		status = model.ProxyUserStatusDisabled
	}
	return model.ProxyUser{
		ID: user.ID, Name: user.Email, Enabled: user.Enabled, InboundIDs: []string{"__vpn_line_scoped__"},
		TrafficLimitBytes: user.QuotaBytes, ExpiresAt: user.ExpiresAt, Status: status,
		CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt,
	}
}

func proxyUserAppliesToProfile(user model.ProxyUser, profile model.ProxyNodeProfile) bool {
	if len(user.InboundIDs) == 0 {
		return true
	}
	for _, inboundID := range profile.InboundIDs {
		if proxyStringSliceContains(user.InboundIDs, inboundID) {
			return true
		}
	}
	return false
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
	if !isSupportedProxyCore(out.Core) {
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
	if out.Fingerprint != "" && !proxyFingerprintRe.MatchString(out.Fingerprint) {
		return model.ProxyInbound{}, errors.New("invalid fingerprint")
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
		// Generate an X25519 REALITY keypair server-side so an operator can create
		// a REALITY inbound without running sing-box/xray by hand (design-09 §E,
		// Phase B). The matching public key is set in the same step.
		priv, pub, err := proxycore.GenerateRealityKeypair()
		if err != nil {
			return model.ProxyInbound{}, fmt.Errorf("generate reality keypair: %w", err)
		}
		out.RealityPrivateKey = priv
		out.RealityPublicKey = pub
	}
	if !proxyKeyRe.MatchString(out.RealityPrivateKey) {
		return model.ProxyInbound{}, errors.New("invalid reality_private_key")
	}
	if strings.TrimSpace(req.RealityPublicKey) != "" {
		out.RealityPublicKey = strings.TrimSpace(req.RealityPublicKey)
	}
	if out.RealityPublicKey == "" {
		// Derive the public key from the (operator-supplied) private key so the
		// subscription/share link always carries a correct pbk.
		pub, err := proxycore.RealityPublicKeyFromPrivate(out.RealityPrivateKey)
		if err != nil {
			return model.ProxyInbound{}, fmt.Errorf("derive reality_public_key: %w", err)
		}
		out.RealityPublicKey = pub
	}
	if !proxyKeyRe.MatchString(out.RealityPublicKey) {
		return model.ProxyInbound{}, errors.New("invalid reality_public_key")
	}
	shortIDsIn := req.RealityShortIDs
	if len(shortIDsIn) == 0 {
		// Auto-generate a short id so a freshly created inbound is immediately
		// renderable (the core requires >=1 non-empty short id).
		sid, err := proxycore.GenerateRealityShortID(4)
		if err != nil {
			return model.ProxyInbound{}, fmt.Errorf("generate reality short id: %w", err)
		}
		shortIDsIn = []string{sid}
	}
	shortIDs, err := normalizeProxyShortIDs(shortIDsIn)
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
	if strings.TrimSpace(req.LastQuotaNotifiedKey) != "" || strings.TrimSpace(req.LastExpiryNotifiedKey) != "" {
		return model.ProxyUser{}, errors.New("proxy notification cursors are server-managed")
	}
	out.Status = derivedProxyUserStatusAt(out, s.now())
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
	if !isSupportedProxyCore(out.Core) {
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
		if inbound.Core != out.Core {
			return model.ProxyNodeProfile{}, fmt.Errorf("proxy inbound %s uses core %s, profile uses %s", inboundID, inbound.Core, out.Core)
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

func isSupportedProxyCore(core string) bool {
	return core == model.ProxyCoreSingbox || core == model.ProxyCoreXray
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
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return errors.New("config_path must not contain a .. path segment")
		}
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
	return derivedProxyUserStatusAt(user, time.Now().UTC())
}

func derivedProxyUserStatusAt(user model.ProxyUser, now time.Time) string {
	if !user.Enabled {
		return model.ProxyUserStatusDisabled
	}
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
