package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/audit"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/cftunnel"
	"github.com/LatticeNet/lattice-server/internal/ddns"
	"github.com/LatticeNet/lattice-server/internal/geoip"
	"github.com/LatticeNet/lattice-server/internal/groups"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/logstore"
	"github.com/LatticeNet/lattice-server/internal/network"
	"github.com/LatticeNet/lattice-server/internal/notify"
	"github.com/LatticeNet/lattice-server/internal/oidc"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/ratelimit"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/selfdns"
	"github.com/LatticeNet/lattice-server/internal/store"
	"github.com/LatticeNet/lattice-server/internal/wireguard"
	"github.com/LatticeNet/lattice-server/internal/worker"
)

type Options struct {
	Store *store.Store
	WebFS fs.FS
	// LogStore is the dedicated bounded log-line database (logs.db). Nil disables
	// the log-ingestion feature: its endpoints return 503 and agents are told to
	// tail nothing. Injected by main (opened beside the state file with the same
	// cipher), mirroring Store.
	LogStore      *logstore.Store
	AdminUsername string
	AdminPassword string
	Build         BuildInfo
	SecureCookies bool
	// TrustProxy enables reading the client address from proxy headers
	// (CF-Connecting-IP, then X-Forwarded-For). Only enable when the server
	// sits behind a trusted reverse proxy / Cloudflare; otherwise clients can
	// spoof the header and evade per-IP rate limiting.
	TrustProxy bool
	// PluginDir is the root directory of installed plugin bundles. Empty disables
	// plugin loading entirely.
	PluginDir string
	// PluginTrust is the operator policy used to verify plugin signatures at load
	// time. The zero value is fail-closed: host-risk plugins require a trusted
	// publisher signature.
	PluginTrust plugin.TrustPolicy
	// PublicURL is the externally-reachable base URL of this server (scheme +
	// host, no trailing slash), used to build the OIDC redirect URL. Required
	// for SSO login; empty disables the OIDC start/callback flow.
	PublicURL string
	// CoreDNSBinary optionally pins the CoreDNS executable that self-host DNS
	// apply scripts may install. Empty preserves the fail-closed precondition
	// that coredns already exists on the node.
	CoreDNSBinary selfdns.CoreDNSBinarySource
	// GeoResolver maps node public IPs to advisory coordinates for the Fleet Map.
	// Nil keeps automatic lookup disabled; manual NodeGeo remains available.
	GeoResolver geoip.Resolver
	// RenewalReminderInterval controls the machine-renewal reminder scheduler.
	// Zero uses the production default. DisableRenewalScheduler is intended for
	// tests that need full control over reminder evaluation.
	RenewalReminderInterval time.Duration
	DisableRenewalScheduler bool
	Logger                  *log.Logger
}

type BuildInfo struct {
	ServerVersion  string `json:"server_version"`
	ServerCommit   string `json:"server_commit"`
	ServerDate     string `json:"server_date"`
	DashboardRef   string `json:"dashboard_ref,omitempty"`
	DashboardBuilt string `json:"dashboard_built,omitempty"`
}

type Server struct {
	store         *store.Store
	logStore      *logstore.Store // bounded log-line db (logs.db); nil disables log ingestion
	webFS         fs.FS
	secureCookies bool
	trustProxy    bool
	logger        *log.Logger
	loginLimiter  *ratelimit.Limiter
	totpLimiter   *ratelimit.Limiter
	agentLimiter  *ratelimit.Limiter
	apiLimiter    *ratelimit.Limiter
	subLimiter    *ratelimit.Limiter
	// logIngestLimiter brakes per-source log ingest (keyed by source id) in
	// lines/sec so a chatty or hostile node cannot flood the store; over budget
	// returns 429 + Retry-After. Disk is independently bounded by the store caps.
	logIngestLimiter *ratelimit.Limiter
	proxyUsageMu     sync.Mutex
	// userLoginFail brakes FAILED password logins PER ACCOUNT (keyed on the
	// resolved user id), mirroring the per-user 2FA limiter in intent: an attacker
	// who already targets a known account cannot widen the password-guess budget by
	// rotating source IPs. Only failures consume budget; once exhausted the account
	// is locked out (even a correct password is rejected) until it refills. It is a
	// leaky token bucket guarded by its own mutex so it never charges successful
	// logins (which would erode a legitimate operator's budget).
	userLoginFailMu sync.Mutex
	userLoginFail   map[string]*loginFailBucket
	// now is an injectable clock (defaults to time.Now). Used for TOTP
	// verification and the per-user login brake so tests can advance time and
	// exercise replay/lockout protection deterministically.
	now func() time.Time
	// ddnsProvider builds a DNS provider from a profile; overridable in tests.
	ddnsProvider func(model.DDNSProfile) (ddns.Provider, error)
	// emitNotify dispatches an event notification; overridable in tests.
	emitNotify func(title, body string)
	// plugins is the verified, registered plugin set established at startup.
	plugins []plugin.Loaded
	// pluginRuntime tracks the in-memory runtime health for active plugins.
	pluginRuntime *plugin.RuntimeManager
	// pluginTrust is the operator policy used by both startup loading and
	// pre-install verification endpoints. It is intentionally not client supplied.
	pluginTrust plugin.TrustPolicy
	// oidc performs SSO flows (discovery cache + auth-code/PKCE + ID-token verify).
	oidc *oidc.Manager
	// publicURL is the external base URL used to build the OIDC redirect URI.
	publicURL string
	// coreDNSBinary is copied into selfdns approval plans when configured. The
	// apply path parses the reviewed plan, not this mutable server field.
	coreDNSBinary selfdns.CoreDNSBinarySource
	// geoResolver is nil only when the operator explicitly disables automatic
	// lookup. The command default uses a no-token HTTPS provider; privacy-focused
	// deployments should set an internal provider or disable lookup.
	geoResolver geoip.Resolver
	// terminalBroker owns short-lived interactive terminal sessions. Sessions are
	// intentionally in-memory only; a server restart forces operators to reopen.
	terminalBroker *terminalBroker
	// terminalHub splices a browser attach WebSocket to the agent-dialed stream
	// WebSocket for the same session (the streaming transport). It owns no
	// session metadata; terminalBroker remains authoritative for lifecycle.
	terminalHub *terminalHub
	// build is immutable process metadata exposed by /api/version and dashboard
	// About. It contains no secrets and is intentionally safe for unauthenticated
	// health/version probes.
	build BuildInfo
	// reminderInterval is the coarse scheduler tick for machine renewal checks.
	reminderInterval time.Duration
	// proxyDrift tracks, per proxy node, whether the applied proxy config still
	// matches what the server would render now. Drift means server-owned
	// eligibility (expiry/quota/disable) or intent changed since the last apply,
	// so the live node config still serves users who should no longer have
	// access. It is recomputed on the scheduler tick and after each apply, held
	// in memory only (re-derived on restart within one tick). It is an operator
	// signal toward a reviewed apply, not authoritative security state.
	proxyDriftMu sync.RWMutex
	proxyDrift   map[string]proxyDriftState
}

const (
	defaultTaskTimeoutSec  = 30
	maxTaskTimeoutSec      = 10 * 60
	defaultTaskOutputLimit = 64 * 1024
	maxTaskOutputLimit     = 256 * 1024
	maxTaskScriptBytes     = 64 * 1024
	requestIDHeader        = "X-Lattice-Request-ID"
	// maxTOTPChallengeAttempts burns a 2FA challenge after this many failed codes.
	maxTOTPChallengeAttempts = 5
)

var allowedTaskInterpreters = map[string]bool{
	"sh":      true,
	"bash":    true,
	"python3": true,
	"node":    true,
}

type principal struct {
	rbac.Principal
	CSRFToken     string
	CorrelationID string
	sessionID     string
	viaBearer     bool
}

type requestIDContextKey struct{}

func New(opts Options) (*Server, error) {
	if opts.Store == nil {
		return nil, errors.New("store is required")
	}
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}
	coreDNSBinary, err := opts.CoreDNSBinary.Normalize()
	if err != nil {
		return nil, err
	}
	s := &Server{
		store:         opts.Store,
		logStore:      opts.LogStore,
		webFS:         opts.WebFS,
		secureCookies: opts.SecureCookies,
		trustProxy:    opts.TrustProxy,
		logger:        opts.Logger,
		// Login is intentionally strict: 5/min sustained, small burst, to slow
		// password guessing without locking out legitimate retries.
		loginLimiter: ratelimit.New(ratelimit.Config{Rate: 5.0 / 60.0, Burst: 5}),
		// Second-factor guesses are throttled PER USER (keyed on user id, not IP)
		// so the guess budget cannot be widened by rotating source addresses.
		totpLimiter: ratelimit.New(ratelimit.Config{Rate: 5.0 / 3600.0, Burst: 5}),
		// Agents poll on an interval; allow generous but bounded throughput.
		agentLimiter: ratelimit.New(ratelimit.Config{Rate: 10, Burst: 40}),
		// General authenticated API surface.
		apiLimiter: ratelimit.New(ratelimit.Config{Rate: 30, Burst: 60}),
		// Public subscription URLs are token-authenticated, unauthenticated HTTP
		// endpoints. Keep a separate low-rate bucket so subscription probing cannot
		// consume the operator/API limiter or widen token-search throughput.
		subLimiter:       ratelimit.New(ratelimit.Config{Rate: 2, Burst: 20}),
		logIngestLimiter: ratelimit.New(ratelimit.Config{Rate: 5000, Burst: 10000}),
		ddnsProvider: func(p model.DDNSProfile) (ddns.Provider, error) {
			return ddns.NewProvider(p, nil)
		},
		oidc:             oidc.NewManager(),
		publicURL:        strings.TrimRight(opts.PublicURL, "/"),
		coreDNSBinary:    coreDNSBinary,
		geoResolver:      opts.GeoResolver,
		terminalBroker:   newTerminalBroker(),
		terminalHub:      newTerminalHub(),
		build:            normalizeBuildInfo(opts.Build),
		pluginTrust:      opts.PluginTrust,
		reminderInterval: opts.RenewalReminderInterval,
		now:              func() time.Time { return time.Now().UTC() },
		userLoginFail:    make(map[string]*loginFailBucket),
		proxyDrift:       make(map[string]proxyDriftState),
	}
	if s.reminderInterval <= 0 {
		s.reminderInterval = time.Hour
	}
	s.emitNotify = s.notifyEvent
	s.pluginRuntime = plugin.NewRuntimeManager(s.pluginHostServices())
	if err := s.ensureAdmin(opts.AdminUsername, opts.AdminPassword); err != nil {
		return nil, err
	}
	s.loadPlugins(opts.PluginDir, opts.PluginTrust)
	if !opts.DisableRenewalScheduler {
		s.startRenewalScheduler()
	}
	return s, nil
}

// loadPlugins verifies and registers plugin bundles at startup. This is the point
// at which the signature/digest/capability trust model becomes load-bearing.
// Verification failures are audited and skipped — one bad or untrusted bundle
// never blocks boot. Execution (host-API binding) is a later milestone.
func (s *Server) loadPlugins(dir string, policy plugin.TrustPolicy) {
	loaded, outcomes, err := plugin.Loader{Dir: dir, Policy: policy}.Load()
	if err != nil {
		s.logger.Printf("plugin loader: %v", err)
		return
	}
	s.plugins = loaded
	for _, pl := range loaded {
		status := model.PluginStatusVerified
		if existing, ok := s.store.PluginInstallation(pl.Manifest.ID); ok {
			status = existing.Status
		}
		if err := s.store.UpsertPluginInstallation(pluginInstallationFromLoaded(pl, status)); err != nil {
			s.logger.Printf("plugin lifecycle: failed to record %s: %v", pl.Manifest.ID, err)
		}
		if status == model.PluginStatusActive {
			rt, err := s.pluginRuntime.Start(context.Background(), pl)
			if err != nil {
				s.logger.Printf("plugin runtime: failed to arm %s: %v", pl.Manifest.ID, err)
				s.recordAudit(model.AuditEvent{ID: id.New("audit"), Action: "plugin.runtime", Decision: "deny", Reason: err.Error(), Metadata: map[string]string{"plugin_id": pl.Manifest.ID, "state": plugin.RuntimeStateFailed}})
			} else {
				s.recordAudit(model.AuditEvent{ID: id.New("audit"), Action: "plugin.runtime", Decision: "allow", Metadata: map[string]string{"plugin_id": pl.Manifest.ID, "state": rt.State, "reason": "startup"}})
			}
		}
	}
	for _, o := range outcomes {
		if o.Loaded {
			s.recordAudit(model.AuditEvent{ID: id.New("audit"), Action: "plugin.loaded", Decision: "allow", Metadata: map[string]string{"plugin_id": o.PluginID, "bundle": filepath.Base(o.BundlePath)}})
		} else {
			s.recordAudit(model.AuditEvent{ID: id.New("audit"), Action: "plugin.rejected", Decision: "deny", Reason: o.Reason, Metadata: map[string]string{"bundle": filepath.Base(o.BundlePath)}})
		}
	}
	if len(outcomes) > 0 {
		s.logger.Printf("plugin loader: %d loaded, %d rejected (dir=%s)", len(loaded), len(outcomes)-len(loaded), dir)
	}
}

func pluginInstallationFromLoaded(pl plugin.Loaded, status string) model.PluginInstallation {
	return model.PluginInstallation{
		ID:             pl.Manifest.ID,
		Name:           pl.Manifest.Name,
		Type:           pl.Manifest.Type,
		Version:        pl.Manifest.Version,
		Entrypoint:     pl.Manifest.Entrypoint,
		Publisher:      pl.Manifest.Publisher,
		Capabilities:   append([]string(nil), pl.Capabilities...),
		ArtifactSHA256: pl.Manifest.DigestSHA256,
		BundlePath:     pl.BundlePath,
		Status:         status,
	}
}

type pluginView struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Version      string   `json:"version,omitempty"`
	Publisher    string   `json:"publisher,omitempty"`
	Capabilities []string `json:"capabilities"`
}

type pluginCapabilityView struct {
	Name string `json:"name"`
	Risk string `json:"risk"`
}

type pluginVerifyResponse struct {
	Trusted      bool                   `json:"trusted"`
	Manifest     plugin.Manifest        `json:"manifest"`
	ArtifactHash string                 `json:"artifact_sha256"`
	Capabilities []pluginCapabilityView `json:"capabilities"`
}

type pluginInstallationView struct {
	ID             string                `json:"id"`
	Name           string                `json:"name"`
	Type           string                `json:"type"`
	Version        string                `json:"version,omitempty"`
	Entrypoint     string                `json:"entrypoint,omitempty"`
	Publisher      string                `json:"publisher,omitempty"`
	Capabilities   []string              `json:"capabilities"`
	ArtifactSHA256 string                `json:"artifact_sha256,omitempty"`
	Available      bool                  `json:"available"`
	Status         string                `json:"status"`
	Runtime        *plugin.RuntimeStatus `json:"runtime,omitempty"`
	VerifiedAt     time.Time             `json:"verified_at,omitempty"`
	InstalledAt    time.Time             `json:"installed_at,omitempty"`
	ActivatedAt    time.Time             `json:"activated_at,omitempty"`
	DisabledAt     time.Time             `json:"disabled_at,omitempty"`
	CreatedAt      time.Time             `json:"created_at"`
	UpdatedAt      time.Time             `json:"updated_at"`
}

// handlePlugins lists the verified, registered plugins (operator visibility into
// the trust-sensitive registry). No signatures/digests are returned.
func (s *Server) handlePlugins(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	views := make([]pluginView, 0, len(s.plugins))
	for _, pl := range s.plugins {
		views = append(views, pluginView{
			ID:           pl.Manifest.ID,
			Name:         pl.Manifest.Name,
			Type:         pl.Manifest.Type,
			Version:      pl.Manifest.Version,
			Publisher:    pl.Manifest.Publisher,
			Capabilities: pl.Capabilities,
		})
	}
	writeJSON(w, http.StatusOK, views)
}

func (s *Server) handlePluginLifecycle(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		installations := s.store.PluginInstallations()
		views := make([]pluginInstallationView, 0, len(installations))
		for _, inst := range installations {
			views = append(views, s.pluginInstallationPublicView(inst))
		}
		writeJSON(w, http.StatusOK, views)
	case http.MethodPost:
		var req struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		req.ID = strings.TrimSpace(req.ID)
		req.Status = strings.TrimSpace(req.Status)
		if req.ID == "" || req.Status == "" {
			writeError(w, http.StatusBadRequest, errors.New("id and status are required"))
			return
		}
		if pluginStatusRequiresLoadedBundle(req.Status) && !s.pluginLoaded(req.ID) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("plugin bundle is not currently verified and loaded: %s", req.ID))
			return
		}
		if err := s.store.SetPluginStatus(req.ID, req.Status); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.Status == model.PluginStatusActive {
			loaded, _ := s.loadedPlugin(req.ID)
			rt, err := s.pluginRuntime.Start(r.Context(), loaded)
			if err != nil {
				_, _ = s.pluginRuntime.Stop(req.ID, "activation failed")
				_ = s.store.SetPluginStatus(req.ID, model.PluginStatusDisabled)
				s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "plugin.runtime", Scope: "plugin:admin", Decision: "deny", Reason: err.Error(), Metadata: map[string]string{"plugin_id": req.ID, "state": plugin.RuntimeStateFailed}})
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "plugin.runtime", Scope: "plugin:admin", Decision: "allow", Metadata: map[string]string{"plugin_id": req.ID, "state": rt.State}})
		}
		if req.Status == model.PluginStatusDisabled {
			rt, err := s.pluginRuntime.Stop(req.ID, "operator disabled plugin")
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "plugin.runtime", Scope: "plugin:admin", Decision: "allow", Metadata: map[string]string{"plugin_id": req.ID, "state": rt.State}})
		}
		inst, _ := s.store.PluginInstallation(req.ID)
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "plugin.status", Scope: "plugin:admin", Metadata: map[string]string{"plugin_id": req.ID, "status": req.Status}})
		writeJSON(w, http.StatusOK, s.pluginInstallationPublicView(inst))
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func pluginStatusRequiresLoadedBundle(status string) bool {
	return status == model.PluginStatusInstalled || status == model.PluginStatusActive
}

func (s *Server) pluginLoaded(id string) bool {
	_, ok := s.loadedPlugin(id)
	return ok
}

func (s *Server) loadedPlugin(id string) (plugin.Loaded, bool) {
	for _, pl := range s.plugins {
		if pl.Manifest.ID == id {
			return pl, true
		}
	}
	return plugin.Loaded{}, false
}

func (s *Server) pluginInstallationPublicView(p model.PluginInstallation) pluginInstallationView {
	var runtimeStatus *plugin.RuntimeStatus
	if s.pluginRuntime != nil {
		if rt, ok := s.pluginRuntime.Status(p.ID); ok {
			runtimeStatus = &rt
		}
	}
	return pluginInstallationView{
		ID:             p.ID,
		Name:           p.Name,
		Type:           p.Type,
		Version:        p.Version,
		Entrypoint:     p.Entrypoint,
		Publisher:      p.Publisher,
		Capabilities:   append([]string(nil), p.Capabilities...),
		ArtifactSHA256: p.ArtifactSHA256,
		Available:      s.pluginLoaded(p.ID),
		Status:         p.Status,
		Runtime:        runtimeStatus,
		VerifiedAt:     p.VerifiedAt,
		InstalledAt:    p.InstalledAt,
		ActivatedAt:    p.ActivatedAt,
		DisabledAt:     p.DisabledAt,
		CreatedAt:      p.CreatedAt,
		UpdatedAt:      p.UpdatedAt,
	}
}

// handlePluginVerify validates a candidate manifest+artifact against the
// operator trust policy without installing, registering, or executing anything.
// It is the safe preflight entrypoint for dashboards and future plugin stores.
func (s *Server) handlePluginVerify(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		Manifest       json.RawMessage `json:"manifest"`
		ArtifactBase64 string          `json:"artifact_base64"`
	}
	if !decodeLimitedJSON(w, r, &req, 4<<20) {
		return
	}
	if len(req.Manifest) == 0 {
		err := errors.New("manifest is required")
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "plugin.verify", Scope: "plugin:verify", Decision: "deny", Reason: err.Error()})
		writeError(w, http.StatusBadRequest, err)
		return
	}
	artifact, err := decodePluginArtifact(req.ArtifactBase64)
	if err != nil {
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "plugin.verify", Scope: "plugin:verify", Decision: "deny", Reason: err.Error()})
		writeError(w, http.StatusBadRequest, err)
		return
	}
	manifest, err := plugin.VerifyInstallManifest(req.Manifest, artifact, s.pluginTrust)
	if err != nil {
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "plugin.verify", Scope: "plugin:verify", Decision: "deny", Reason: err.Error()})
		writeError(w, http.StatusBadRequest, err)
		return
	}
	resp := pluginVerifyResponse{
		Trusted:      true,
		Manifest:     pluginManifestPublicView(manifest),
		ArtifactHash: plugin.DigestSHA256(artifact),
		Capabilities: pluginCapabilitySummary(manifest),
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "plugin.verify", Scope: "plugin:verify", Decision: "allow", Metadata: map[string]string{"plugin_id": manifest.ID, "digest_sha256": resp.ArtifactHash}})
	writeJSON(w, http.StatusOK, resp)
}

func pluginManifestPublicView(m plugin.Manifest) plugin.Manifest {
	m.SignatureEd25519 = ""
	return m
}

func pluginCapabilitySummary(m plugin.Manifest) []pluginCapabilityView {
	caps := append([]string(nil), m.Capabilities...)
	sort.Strings(caps)
	out := make([]pluginCapabilityView, 0, len(caps))
	for _, cap := range caps {
		risk, _ := plugin.CapabilityRisk(cap)
		out = append(out, pluginCapabilityView{Name: cap, Risk: risk})
	}
	return out
}

func decodePluginArtifact(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("artifact_base64 is required")
	}
	if out, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return out, nil
	}
	out, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid artifact_base64: %w", err)
	}
	return out, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/login/totp", s.handleLoginTOTP)
	mux.HandleFunc("/api/auth/oidc", s.handleOIDCList)
	mux.HandleFunc("/api/auth/oidc/start", s.handleOIDCStart)
	mux.HandleFunc("/api/auth/oidc/callback", s.handleOIDCCallback)
	mux.HandleFunc("/api/auth/oidc/providers", s.withAuth("oidc:admin", s.handleOIDCProviders))
	mux.HandleFunc("/api/auth/oidc/providers/delete", s.withAuth("oidc:admin", s.handleDeleteOIDCProvider))
	mux.HandleFunc("/api/logout", s.withAuth("", s.handleLogout))
	mux.HandleFunc("/api/me", s.withAuth("", s.handleMe))
	mux.HandleFunc("/api/auth/password", s.withAuth("", s.handlePasswordChange))
	mux.HandleFunc("/api/2fa/totp/enroll", s.withAuth("", s.handle2FAEnroll))
	mux.HandleFunc("/api/2fa/totp/activate", s.withAuth("", s.handle2FAActivate))
	mux.HandleFunc("/api/2fa/totp/disable", s.withAuth("", s.handle2FADisable))
	mux.HandleFunc("/api/nodes", s.withAuth("node:read", s.handleNodes))
	mux.HandleFunc("/api/nodes/geo", s.withAuth("", s.handleNodesGeo))
	mux.HandleFunc("/api/nodes/geo/resolve", s.withAuth("", s.handleNodesGeoResolve))
	mux.HandleFunc("/api/nodes/agent-updates", s.withAuth("", s.handleAgentUpdatePolicies))
	mux.HandleFunc("/api/nodes/agent-updates/delete", s.withAuth("node:admin", s.handleDeleteAgentUpdatePolicy))
	mux.HandleFunc("/api/nodes/agent-updates/plan", s.withAuth("", s.handleAgentUpdatePlan))
	mux.HandleFunc("/api/nodes/enroll-token", s.withAuth("node:admin", s.handleEnrollNode))
	mux.HandleFunc("/api/nodes/rotate-token", s.withAuth("node:admin", s.handleRotateNodeToken))
	mux.HandleFunc("/api/nodes/disable", s.withAuth("node:admin", s.handleNodeDisable))
	mux.HandleFunc("/api/nodes/debug", s.withAuth("", s.handleNodeDebugPolicy))
	mux.HandleFunc("/api/tasks", s.withAuth("", s.handleTasks))
	mux.HandleFunc("/api/task-results", s.withAuth("task:read", s.handleTaskResults))
	mux.HandleFunc("/api/terminal/sessions", s.withAuth("", s.handleTerminalSessions))
	mux.HandleFunc("/api/terminal/sessions/", s.withAuth("", s.handleTerminalSessionPath))
	mux.HandleFunc("/api/audit", s.withAuth("audit:read", s.handleAudit))
	mux.HandleFunc("/api/audit/verify", s.withAuth("audit:read", s.handleAuditVerify))
	mux.HandleFunc("/api/plugins", s.withAuth("audit:read", s.handlePlugins))
	mux.HandleFunc("/api/plugins/lifecycle", s.withAuth("plugin:admin", s.handlePluginLifecycle))
	mux.HandleFunc("/api/plugins/verify", s.withAuth("plugin:verify", s.handlePluginVerify))
	mux.HandleFunc("/api/kv", s.withAuth("kv:read", s.handleKV))
	mux.HandleFunc("/api/static", s.withAuth("static:read", s.handleStatic))
	mux.HandleFunc("/api/storage/buckets", s.withAuth("", s.handleStorageBuckets))
	mux.HandleFunc("/api/storage/bindings", s.withAuth("", s.handleStorageBindings))
	mux.HandleFunc("/api/storage/bindings/delete", s.withAuth("", s.handleDeleteStorageBinding))
	mux.HandleFunc("/api/storage/tokens", s.withAuth("", s.handleStorageTokens))
	mux.HandleFunc("/api/storage/tokens/revoke", s.withAuth("", s.handleRevokeStorageToken))
	mux.HandleFunc("/api/workers", s.withAuth("worker:deploy", s.handleWorkers))
	mux.HandleFunc("/api/workers/run", s.withAuth("worker:deploy", s.handleWorkerRun))
	mux.HandleFunc("/api/notify/test", s.withAuth("notify:send", s.handleNotifyTest))
	mux.HandleFunc("/api/notify/channels", s.withAuth("notify:send", s.handleNotifyChannels))
	mux.HandleFunc("/api/notify/channels/delete", s.withAuth("notify:send", s.handleDeleteNotifyChannel))
	mux.HandleFunc("/api/notify/rules", s.withAuth("notify:send", s.handleNotifyRules))
	mux.HandleFunc("/api/notify/rules/delete", s.withAuth("notify:send", s.handleDeleteNotifyRule))
	mux.HandleFunc("/api/ddns", s.withAuth("ddns:admin", s.handleDDNS))
	mux.HandleFunc("/api/ddns/delete", s.withAuth("ddns:admin", s.handleDeleteDDNS))
	mux.HandleFunc("/api/ddns/run", s.withAuth("ddns:admin", s.handleRunDDNS))
	mux.HandleFunc("/api/dns/deployments", s.withAuth("dns:admin", s.handleDNSDeployments))
	mux.HandleFunc("/api/dns/deployments/delete", s.withAuth("dns:admin", s.handleDeleteDNSDeployment))
	mux.HandleFunc("/api/dns/plan", s.withAuth("dns:admin", s.handleDNSPlan))
	mux.HandleFunc("/api/dns/publish", s.withAuth("dns:admin", s.handleDNSPublish))
	mux.HandleFunc("/api/geo-routing", s.withAuth("geo:read", s.handleGeoRoutings))
	mux.HandleFunc("/api/geo-routing/delete", s.withAuth("geo:admin", s.handleDeleteGeoRouting))
	mux.HandleFunc("/api/geo-routing/plan", s.withAuth("geo:read", s.handleGeoRoutingPlan))
	mux.HandleFunc("/api/proxy/inbounds", s.withAuth("", s.handleProxyInbounds))
	mux.HandleFunc("/api/proxy/inbounds/delete", s.withAuth("", s.handleDeleteProxyInbound))
	mux.HandleFunc("/api/proxy/users", s.withAuth("", s.handleProxyUsers))
	mux.HandleFunc("/api/proxy/users/rotate-sub-token", s.withAuth("", s.handleRotateProxyUserSubToken))
	mux.HandleFunc("/api/proxy/users/delete", s.withAuth("", s.handleDeleteProxyUser))
	mux.HandleFunc("/api/proxy/usage", s.withAuth("", s.handleProxyUsage))
	mux.HandleFunc("/api/proxy/profiles", s.withAuth("", s.handleProxyProfiles))
	mux.HandleFunc("/api/proxy/profiles/delete", s.withAuth("", s.handleDeleteProxyProfile))
	mux.HandleFunc("/api/proxy/nodes/", s.withAuth("", s.handleProxyNodePlan))
	mux.HandleFunc("/api/machines", s.withAuth("", s.handleMachines))
	mux.HandleFunc("/api/machines/update", s.withAuth("inventory:admin", s.handleMachineUpdate))
	mux.HandleFunc("/api/machines/delete", s.withAuth("inventory:admin", s.handleDeleteMachine))
	mux.HandleFunc("/api/machines/renew", s.withAuth("inventory:admin", s.handleMachineRenew))
	mux.HandleFunc("/api/machines/reminders/run", s.withAuth("inventory:admin", s.handleMachineRemindersRun))
	mux.HandleFunc("/api/monitors", s.withAuth("monitor:read", s.handleMonitors))
	mux.HandleFunc("/api/monitors/delete", s.withAuth("monitor:admin", s.handleDeleteMonitor))
	mux.HandleFunc("/api/monitors/results", s.withAuth("monitor:read", s.handleMonitorResults))
	mux.HandleFunc("/api/logs/sources", s.withAuth("log:read", s.handleLogSources))
	mux.HandleFunc("/api/logs/sources/delete", s.withAuth("log:admin", s.handleDeleteLogSource))
	mux.HandleFunc("/api/logs/query", s.withAuth("log:read", s.handleLogQuery))
	mux.HandleFunc("/api/logs/stats", s.withAuth("log:read", s.handleLogStats))
	mux.HandleFunc("/api/tokens", s.withAuth("token:admin", s.handleTokens))
	mux.HandleFunc("/api/tokens/revoke", s.withAuth("token:admin", s.handleRevokeToken))
	mux.HandleFunc("/api/network/nft/plan", s.withAuth("network:plan", s.handleNFTPlan))
	mux.HandleFunc("/api/network/nft/inputs", s.withAuth("network:plan", s.handleNFTInputs))
	mux.HandleFunc("/api/network/nft/inputs/delete", s.withAuth("network:plan", s.handleDeleteNFTInputs))
	mux.HandleFunc("/api/netpolicy", s.withAuth("", s.handleNetPolicy))
	mux.HandleFunc("/api/netpolicy/plan", s.withAuth("", s.handleNetPolicyPlan))
	mux.HandleFunc("/api/netpolicy/delete", s.withAuth("", s.handleDeleteNetPolicy))
	mux.HandleFunc("/api/netpolicy/graph", s.withAuth("", s.handleNetPolicyGraph))
	mux.HandleFunc("/api/groups", s.withAuth("", s.handleGroups))
	mux.HandleFunc("/api/groups/delete", s.withAuth("group:admin", s.handleDeleteGroup))
	mux.HandleFunc("/api/groups/reorder", s.withAuth("group:admin", s.handleReorderGroups))
	mux.HandleFunc("/api/groups/members", s.withAuth("group:admin", s.handleGroupMembers))
	mux.HandleFunc("/api/groups/preview", s.withAuth("group:read", s.handleGroupPreview))
	mux.HandleFunc("/api/groups/seed", s.withAuth("group:admin", s.handleGroupSeed))
	mux.HandleFunc("/api/group-policies", s.withAuth("", s.handleGroupPolicy))
	mux.HandleFunc("/api/group-policies/delete", s.withAuth("netpolicy:admin", s.handleDeleteGroupPolicy))
	mux.HandleFunc("/api/group-policies/plan", s.withAuth("netpolicy:admin", s.handleGroupPolicyPlan))
	mux.HandleFunc("/api/netpolicy/matrix", s.withAuth("netpolicy:read", s.handleNetPolicyMatrix))
	mux.HandleFunc("/api/network/wireguard/plan", s.withAuth("network:plan", s.handleWireGuardPlan))
	mux.HandleFunc("/api/tunnels", s.withAuth("tunnel:admin", s.handleTunnels))
	mux.HandleFunc("/api/tunnels/delete", s.withAuth("tunnel:admin", s.handleDeleteTunnel))
	mux.HandleFunc("/api/tunnels/plan", s.withAuth("tunnel:admin", s.handleTunnelPlan))
	mux.HandleFunc("/api/network/approvals", s.withAuth("network:plan", s.handleApprovals))
	mux.HandleFunc("/api/network/approvals/approve", s.withAuth("network:apply", s.handleApprove))
	mux.HandleFunc("/sub/", s.withSubscriptionLimit(s.handleProxySubscription))
	mux.HandleFunc("/api/agent/hello", s.withAgentLimit(s.handleAgentHello))
	mux.HandleFunc("/api/agent/metrics", s.withAgentLimit(s.handleAgentMetrics))
	mux.HandleFunc("/api/agent/proxy-usage", s.withAgentLimit(s.handleAgentProxyUsage))
	mux.HandleFunc("/api/agent/tasks", s.withAgentLimit(s.handleAgentTasks))
	mux.HandleFunc("/api/agent/task-result", s.withAgentLimit(s.handleAgentTaskResult))
	mux.HandleFunc("/api/agent/terminal/sessions", s.withAgentLimit(s.handleAgentTerminalSessions))
	mux.HandleFunc("/api/agent/terminal/sessions/", s.withAgentLimit(s.handleAgentTerminalSessionPath))
	mux.HandleFunc("/api/agent/terminal/stream", s.withAgentLimit(s.handleAgentTerminalStream))
	mux.HandleFunc("/api/agent/config", s.withAgentLimit(s.handleAgentConfig))
	mux.HandleFunc("/api/agent/monitors", s.withAgentLimit(s.handleAgentMonitors))
	mux.HandleFunc("/api/agent/monitor-result", s.withAgentLimit(s.handleAgentMonitorResult))
	mux.HandleFunc("/api/agent/log-sources", s.withAgentLimit(s.handleAgentLogSources))
	mux.HandleFunc("/api/agent/logs", s.withAgentLimit(s.handleAgentLogs))
	mux.HandleFunc("/api/agent/debug-events", s.withAgentLimit(s.handleAgentDebugEvents))
	mux.HandleFunc("/api/agent/event", s.withAgentLimit(s.handleAgentEvent))
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/api/version", s.handleVersion)
	mux.Handle("/", s.staticHandler())
	return s.withRequestID(s.withRequestLog(s.securityHeaders(mux)))
}

func (s *Server) ensureAdmin(username, password string) error {
	if s.store.UserCount() > 0 {
		return nil
	}
	username, err := normalizeBootstrapUsername(username)
	if err != nil {
		return err
	}
	if password == "" {
		generated, err := auth.NewRandomToken(24)
		if err != nil {
			return err
		}
		password = generated
		s.logger.Printf("bootstrap admin username: %s", username)
		s.logger.Printf("bootstrap admin password: %s", generated)
	}
	hash, err := auth.HashSecret(password)
	if err != nil {
		return err
	}
	return s.store.UpsertUser(model.User{
		ID:           "user_admin",
		Username:     username,
		PasswordHash: hash,
		Scopes:       []string{"*"},
		CreatedAt:    time.Now().UTC(),
	})
}

func normalizeBootstrapUsername(username string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		username = "admin"
	}
	if len(username) > 128 {
		return "", errors.New("admin username must be at most 128 characters")
	}
	for _, r := range username {
		if r < 0x20 || r == 0x7f {
			return "", errors.New("admin username must not contain control characters")
		}
	}
	return username, nil
}

func normalizeBuildInfo(info BuildInfo) BuildInfo {
	if info.ServerVersion == "" {
		info.ServerVersion = "dev"
	}
	if info.ServerCommit == "" {
		info.ServerCommit = "unknown"
	}
	if info.ServerDate == "" {
		info.ServerDate = "unknown"
	}
	if info.DashboardRef == "" {
		info.DashboardRef = "unknown"
	}
	return info
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	writeJSON(w, http.StatusOK, s.build)
}

func (s *Server) staticHandler() http.Handler {
	var fileServer http.Handler
	if s.webFS != nil {
		fileServer = http.FileServer(http.FS(s.webFS))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		host := requestHost(r.Host)
		if binding, ok := s.storageBindingForRequest(model.StorageKindKV, host, r.URL.Path); ok {
			s.serveKVBinding(w, r, binding)
			return
		}
		if binding, ok := s.storageBindingForRequest(model.StorageKindStatic, host, r.URL.Path); ok {
			s.serveStaticBinding(w, r, binding)
			return
		}
		if s.webFS == nil {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "." || name == "" {
			name = "index.html"
		}
		if _, err := fs.Stat(s.webFS, name); err != nil {
			name = "index.html"
			r.URL.Path = "/"
		}
		w.Header().Set("Cache-Control", staticCacheControl(name))
		fileServer.ServeHTTP(w, r)
	})
}

func staticCacheControl(name string) string {
	switch {
	case name == "index.html" || name == "theme-init.js":
		return "no-cache"
	case strings.HasPrefix(name, "assets/"):
		return "public, max-age=31536000, immutable"
	default:
		return "public, max-age=3600"
	}
}

// withAgentLimit applies per-source rate limiting to the unauthenticated-facing
// agent endpoints so a flood cannot exhaust CPU on token verification.
func (s *Server) withAgentLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.agentLimiter.Allow(s.clientIP(r)) {
			writeError(w, http.StatusTooManyRequests, errors.New("rate limited"))
			return
		}
		next(w, r)
	}
}

// withSubscriptionLimit applies a dedicated limiter to public subscription URLs.
// They intentionally bypass sessions/CSRF, so rate limiting must happen before
// any credential scan.
func (s *Server) withSubscriptionLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.subLimiter.Allow(s.clientIP(r)) {
			writeError(w, http.StatusTooManyRequests, errors.New("rate limited"))
			return
		}
		next(w, r)
	}
}

func (s *Server) withAuth(scope string, next func(http.ResponseWriter, *http.Request, principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.apiLimiter.Allow(s.clientIP(r)) {
			writeError(w, http.StatusTooManyRequests, errors.New("rate limited"))
			return
		}
		p, err := s.principalFromRequest(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err)
			return
		}
		if scope != "" && !rbac.Allows(p.Principal, scope, r.URL.Query().Get("node_id")) {
			s.recordAudit(model.AuditEvent{
				ID:            id.New("audit"),
				ActorID:       p.ActorID,
				TokenID:       p.TokenID,
				Action:        r.Method + " " + r.URL.Path,
				Scope:         scope,
				Decision:      "deny",
				Reason:        "missing scope or server allowlist denied",
				CorrelationID: p.CorrelationID,
			})
			writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
			return
		}
		if !p.viaBearer && unsafeMethod(r.Method) {
			// Constant-time compare so a network attacker cannot recover the CSRF
			// token byte-by-byte via response timing. ConstantTimeCompare returns 0
			// on any length mismatch, so an empty or wrong-length header is rejected.
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Lattice-CSRF")), []byte(p.CSRFToken)) != 1 {
				writeError(w, http.StatusForbidden, errors.New("invalid csrf token"))
				return
			}
		}
		next(w, r, p)
	}
}

func (s *Server) requireNodeScope(w http.ResponseWriter, p principal, scope, nodeID string) bool {
	if rbac.Allows(p.Principal, scope, nodeID) {
		return true
	}
	s.recordAudit(model.AuditEvent{
		ID:            id.New("audit"),
		ActorID:       p.ActorID,
		TokenID:       p.TokenID,
		NodeID:        nodeID,
		Action:        "authorize.node",
		Scope:         scope,
		Decision:      "deny",
		Reason:        "missing scope or server allowlist denied",
		CorrelationID: p.CorrelationID,
	})
	writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
	return false
}

func (s *Server) requireScope(w http.ResponseWriter, p principal, scope string) bool {
	if rbac.Allows(p.Principal, scope, "") {
		return true
	}
	s.recordAudit(model.AuditEvent{
		ID:            id.New("audit"),
		ActorID:       p.ActorID,
		TokenID:       p.TokenID,
		Action:        "authorize.scope",
		Scope:         scope,
		Decision:      "deny",
		Reason:        "missing scope",
		CorrelationID: p.CorrelationID,
	})
	writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
	return false
}

func (s *Server) requireAllNodeScopes(w http.ResponseWriter, p principal, scope string, nodeIDs []string) bool {
	if len(nodeIDs) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("at least one node target is required"))
		return false
	}
	for _, nodeID := range nodeIDs {
		if strings.TrimSpace(nodeID) == "" {
			writeError(w, http.StatusBadRequest, errors.New("node target cannot be empty"))
			return false
		}
		if !s.requireNodeScope(w, p, scope, nodeID) {
			return false
		}
	}
	return true
}

func principalHasNodeRestriction(p principal) bool {
	if len(p.ServerAllowlist) == 0 {
		return false
	}
	for _, nodeID := range p.ServerAllowlist {
		if nodeID == "*" {
			return false
		}
	}
	return true
}

func serverAllowlistSubset(parent, requested []string) bool {
	if len(parent) == 0 {
		return true
	}
	parentSet := map[string]bool{}
	for _, nodeID := range parent {
		if nodeID == "*" {
			return true
		}
		parentSet[nodeID] = true
	}
	if len(requested) == 0 {
		return false
	}
	for _, nodeID := range requested {
		if nodeID == "*" || !parentSet[nodeID] {
			return false
		}
	}
	return true
}

func taskTargetsAllowed(p principal, scope string, nodeIDs []string) bool {
	if len(nodeIDs) == 0 {
		return false
	}
	for _, nodeID := range nodeIDs {
		if !rbac.Allows(p.Principal, scope, nodeID) {
			return false
		}
	}
	return true
}

func (s *Server) principalFromRequest(r *http.Request) (principal, error) {
	if bearer := bearerToken(r); bearer != "" {
		tokenID, secret, ok := auth.SplitToken(bearer)
		if !ok {
			auth.DummyVerify(bearer)
			return principal{}, errors.New("invalid bearer token")
		}
		token, found := s.store.Token(tokenID)
		if !found || !token.RevokedAt.IsZero() {
			auth.DummyVerify(secret)
			return principal{}, errors.New("invalid bearer token")
		}
		if !auth.VerifySecret(token.TokenHash, secret) {
			return principal{}, errors.New("invalid bearer token")
		}
		return principal{
			Principal: rbac.Principal{
				ActorID:         token.ActorID,
				TokenID:         token.ID,
				Scopes:          token.Scopes,
				ServerAllowlist: token.ServerAllowlist,
			},
			CorrelationID: requestIDFromRequest(r),
			viaBearer:     true,
		}, nil
	}
	cookie, err := r.Cookie("lattice_session")
	if err != nil {
		return principal{}, errors.New("missing session")
	}
	session, ok := s.store.Session(cookie.Value)
	if !ok {
		return principal{}, errors.New("session expired")
	}
	user, ok := s.store.User(session.ActorID)
	if !ok {
		return principal{}, errors.New("user not found")
	}
	// Fail closed on a stale session: if the user's security epoch advanced after
	// this session was minted (2FA disable, password change, admin revoke), the
	// session is no longer trustworthy. Treat it as unauthenticated.
	if session.Epoch < user.SecurityEpoch {
		return principal{}, errors.New("session expired")
	}
	return principal{
		Principal: rbac.Principal{
			ActorID: user.ID,
			Scopes:  user.Scopes,
		},
		CSRFToken:     session.CSRFToken,
		CorrelationID: requestIDFromRequest(r),
		sessionID:     session.ID,
	}, nil
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.loginLimiter.Allow(s.clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, errors.New("too many login attempts; slow down"))
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	user, ok := s.store.UserByUsername(req.Username)
	if !ok {
		// Spend comparable CPU so response time does not reveal whether the
		// username exists. The per-user brake below is deliberately NOT consulted
		// here: doing so would leak account existence (a known account could be
		// locked out, an unknown one never could) and defeat the timing
		// equalization.
		auth.DummyVerify(req.Password)
		writeError(w, http.StatusUnauthorized, errors.New("invalid credentials"))
		return
	}
	// Always perform the verification work (timing parity with the unknown-user
	// path) before consulting the per-account brake.
	passwordOK := auth.VerifySecret(user.PasswordHash, req.Password)
	// Per-account failure brake (keyed on the resolved user id), mirroring the
	// per-user 2FA limiter in intent: an attacker who already targets a known
	// account cannot widen the password-guess budget by rotating source IPs. Only
	// FAILED attempts consume budget, so a legitimate operator's repeated correct
	// logins never erode it. Once the per-account budget is exhausted, the account
	// is locked out and even a correct password is rejected with 429 until the
	// window refills — a wrong-guess flood cannot be rescued by slipping in the
	// right password.
	if s.userLoginLocked(user.ID) {
		s.recordRequestAudit(r, model.AuditEvent{ID: id.New("audit"), ActorID: user.ID, Action: "login", Decision: "deny", Reason: "per-user login attempt limit exceeded"})
		writeError(w, http.StatusTooManyRequests, errors.New("too many login attempts; slow down"))
		return
	}
	if !passwordOK {
		s.recordUserLoginFailure(user.ID)
		s.recordRequestAudit(r, model.AuditEvent{ID: id.New("audit"), ActorID: user.ID, Action: "login", Decision: "deny", Reason: "invalid credentials"})
		writeError(w, http.StatusUnauthorized, errors.New("invalid credentials"))
		return
	}
	if user.TOTPEnabled {
		s.issueTOTPChallenge(w, r, user)
		return
	}
	s.issueSession(w, r, user)
}

const (
	// userLoginFailBurst is the per-account failed-password budget before lockout.
	userLoginFailBurst = 5.0
	// userLoginFailRefill is the sustained refill rate (failures forgiven per
	// second) — 5 per minute, matching the per-IP login limiter, so a brief flurry
	// of typos clears quickly while a sustained guessing flood stays locked.
	userLoginFailRefill = 5.0 / 60.0
)

// loginFailBucket is a leaky token bucket counting recent FAILED password
// attempts for one account. failures rises by 1 per failure and leaks back
// toward zero at userLoginFailRefill; the account is locked while failures would
// exceed userLoginFailBurst.
type loginFailBucket struct {
	failures float64
	last     time.Time
}

// userLoginLocked reports whether the account is currently locked out due to too
// many recent failed password attempts. It is non-consuming: a successful login
// never erodes the budget, so a legitimate operator is unaffected.
func (s *Server) userLoginLocked(userID string) bool {
	now := s.now()
	s.userLoginFailMu.Lock()
	defer s.userLoginFailMu.Unlock()
	b := s.userLoginFail[userID]
	if b == nil {
		return false
	}
	leakBucketLocked(b, now)
	if b.failures <= 0 {
		delete(s.userLoginFail, userID)
		return false
	}
	// Locked once the accumulated failures have reached the burst budget. A
	// further failure would push strictly past it.
	return b.failures >= userLoginFailBurst
}

// recordUserLoginFailure charges one failed password attempt against the account.
func (s *Server) recordUserLoginFailure(userID string) {
	now := s.now()
	s.userLoginFailMu.Lock()
	defer s.userLoginFailMu.Unlock()
	b := s.userLoginFail[userID]
	if b == nil {
		b = &loginFailBucket{last: now}
		s.userLoginFail[userID] = b
	}
	leakBucketLocked(b, now)
	b.failures++
	// Cap so a long flood cannot build an unboundedly long lockout tail.
	if b.failures > userLoginFailBurst {
		b.failures = userLoginFailBurst
	}
}

// leakBucketLocked drains a bucket toward zero based on elapsed time. Caller holds
// the mutex.
func leakBucketLocked(b *loginFailBucket, now time.Time) {
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.failures -= elapsed * userLoginFailRefill
		if b.failures < 0 {
			b.failures = 0
		}
		b.last = now
	}
}

const totpIssuer = "Lattice"

// startSession creates a session, persists it, sets the session cookie, and
// audits the login under the given action. Shared by password/2FA login (which
// then returns JSON) and OIDC login (which then redirects).
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, user model.User, action string) (auth.Session, error) {
	session, err := auth.NewSession(user.ID, 12*time.Hour)
	if err != nil {
		return auth.Session{}, err
	}
	// Stamp the session with the user's current security epoch. A later
	// privilege-reducing event (2FA disable, password change, admin revoke) bumps
	// the user's epoch, and principalFromRequest then rejects this now-stale
	// session, invalidating it without enumerating session ids.
	session.Epoch = user.SecurityEpoch
	if err := s.store.PutSession(session); err != nil {
		return auth.Session{}, err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "lattice_session",
		Value:    session.ID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   s.secureCookies,
		Expires:  session.ExpiresAt,
	})
	s.recordRequestAudit(r, model.AuditEvent{ID: id.New("audit"), ActorID: user.ID, Action: action, Decision: "allow"})
	return session, nil
}

// issueSession completes an API login: starts a session and returns the CSRF
// token. Shared by password login and post-2FA login.
func (s *Server) issueSession(w http.ResponseWriter, r *http.Request, user model.User) {
	session, err := s.startSession(w, r, user, "login")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"csrf_token": session.CSRFToken, "actor_id": user.ID})
}

func (s *Server) handlePasswordChange(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if p.viaBearer {
		writeError(w, http.StatusForbidden, errors.New("password changes require an interactive session"))
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, apiError(model.APIErrorBadRequest, "current_password and new_password are required"))
		return
	}
	user, ok := s.store.User(p.ActorID)
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("unknown user"))
		return
	}
	if s.userLoginLocked(user.ID) {
		s.recordRequestAudit(r, model.AuditEvent{ID: id.New("audit"), ActorID: user.ID, Action: "auth.password.change", Decision: "deny", Reason: "per-user password attempt limit exceeded"})
		writeError(w, http.StatusTooManyRequests, errors.New("too many password attempts; slow down"))
		return
	}
	if !auth.VerifySecret(user.PasswordHash, req.CurrentPassword) {
		s.recordUserLoginFailure(user.ID)
		s.recordRequestAudit(r, model.AuditEvent{ID: id.New("audit"), ActorID: user.ID, Action: "auth.password.change", Decision: "deny", Reason: "invalid current password"})
		writeError(w, http.StatusUnauthorized, errors.New("invalid current password"))
		return
	}
	if auth.VerifySecret(user.PasswordHash, req.NewPassword) {
		writeError(w, http.StatusBadRequest, apiError(model.APIErrorBadRequest, "new password must differ from the current password"))
		return
	}
	hash, err := auth.HashSecret(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusBadRequest, apiError(model.APIErrorBadRequest, err.Error()))
		return
	}
	user.PasswordHash = hash
	user.SecurityEpoch++
	if err := s.store.UpsertUser(user); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), ActorID: user.ID, Action: "auth.password.change", Decision: "allow"})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// issueTOTPChallenge gates a 2FA-enabled user: it stores a short-lived, IP-bound,
// single-use challenge and asks the client to complete the second factor instead
// of issuing a session.
func (s *Server) issueTOTPChallenge(w http.ResponseWriter, r *http.Request, user model.User) {
	challenge, err := auth.NewTOTPChallenge(user.ID, s.clientIP(r), 5*time.Minute)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.store.PutTOTPChallenge(challenge); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordRequestAudit(r, model.AuditEvent{ID: id.New("audit"), ActorID: user.ID, Action: "login.totp_required", Decision: "observe"})
	writeJSON(w, http.StatusOK, map[string]any{"totp_required": true, "challenge_id": challenge.ID})
}

// handleLoginTOTP completes a login for a 2FA user by validating a TOTP code or a
// single-use recovery code against the pending challenge, then issuing a session.
func (s *Server) handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.loginLimiter.Allow(s.clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, errors.New("too many login attempts; slow down"))
		return
	}
	var req struct {
		ChallengeID  string `json:"challenge_id"`
		Code         string `json:"code"`
		RecoveryCode string `json:"recovery_code"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	challenge, ok := s.store.TOTPChallenge(req.ChallengeID)
	if !ok || challenge.ClientIP != s.clientIP(r) {
		writeError(w, http.StatusUnauthorized, errors.New("invalid or expired challenge"))
		return
	}
	// If this challenge was issued by the SSO→2FA continuation it carries a
	// browser-binding cookie; require it to match the submitted challenge id so
	// only the browser that completed SSO can finish the second factor. Absent
	// cookie = the password→2FA path, which is unaffected. [C14]
	if c, err := r.Cookie(totpChallengeCookie); err == nil && c.Value != "" {
		if subtle.ConstantTimeCompare([]byte(c.Value), []byte(req.ChallengeID)) != 1 {
			writeError(w, http.StatusUnauthorized, errors.New("invalid or expired challenge"))
			return
		}
	}
	user, ok := s.store.User(challenge.UserID)
	if !ok || !user.TOTPEnabled {
		writeError(w, http.StatusUnauthorized, errors.New("invalid or expired challenge"))
		return
	}
	if challenge.Attempts >= maxTOTPChallengeAttempts {
		_ = s.store.ConsumeTOTPChallenge(challenge.ID)
		writeError(w, http.StatusTooManyRequests, errors.New("too many attempts; restart login"))
		return
	}
	authed, usedRecovery := false, false
	if req.Code != "" {
		if step, ok := auth.ValidateTOTPStep(user.TOTPSecret, req.Code, s.now()); ok {
			// Single-use: the matched step must be strictly newer than the highest
			// step already accepted for this user. AdvanceTOTPStep performs the
			// compare-and-set atomically under the store lock, so a replay of the
			// same code (or a concurrent duplicate submission) is rejected as an
			// invalid second factor. Recovery codes are handled separately below and
			// are unaffected.
			advanced, err := s.store.AdvanceTOTPStep(user.ID, step)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			authed = advanced
		}
	} else if req.RecoveryCode != "" {
		consumed, err := s.store.ConsumeRecoveryCode(user.ID, req.RecoveryCode)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		authed, usedRecovery = consumed, consumed
	}
	if !authed {
		// Throttle failed second factors PER USER (keyed on the user id, not the
		// source IP) so an attacker who already holds the password cannot widen the
		// guess budget by rotating IPs. The failed attempt also counts against the
		// challenge, which is burned at the per-challenge cap.
		_ = s.store.FailTOTPChallenge(challenge.ID, maxTOTPChallengeAttempts)
		if !s.totpLimiter.Allow("totp:" + user.ID) {
			_ = s.store.ConsumeTOTPChallenge(challenge.ID)
			s.emitNotify("🔐 2FA attempt limit", fmt.Sprintf("user %s hit the 2FA attempt limit (last attempt from %s)", user.Username, s.clientIP(r)))
			s.recordRequestAudit(r, model.AuditEvent{ID: id.New("audit"), ActorID: user.ID, Action: "login.totp", Decision: "deny", Reason: "2fa attempt limit exceeded"})
			writeError(w, http.StatusTooManyRequests, errors.New("too many 2fa attempts; restart login"))
			return
		}
		s.recordRequestAudit(r, model.AuditEvent{ID: id.New("audit"), ActorID: user.ID, Action: "login.totp", Decision: "deny", Reason: "invalid second factor"})
		writeError(w, http.StatusUnauthorized, errors.New("invalid second factor"))
		return
	}
	if err := s.store.ConsumeTOTPChallenge(challenge.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if usedRecovery {
		s.recordRequestAudit(r, model.AuditEvent{ID: id.New("audit"), ActorID: user.ID, Action: "login.totp.recovery_used", Decision: "allow"})
	}
	s.clearTOTPChallengeCookie(w)
	s.issueSession(w, r, user)
}

// handle2FAEnroll begins TOTP enrollment for the current operator: it mints a
// secret and recovery codes (shown once) but leaves 2FA inactive until a code is
// verified via activate. Restricted to interactive sessions (not PAT bearers).
func (s *Server) handle2FAEnroll(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if p.viaBearer {
		writeError(w, http.StatusForbidden, errors.New("2fa management requires an interactive session"))
		return
	}
	user, ok := s.store.User(p.ActorID)
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("unknown user"))
		return
	}
	if user.TOTPEnabled {
		writeError(w, http.StatusConflict, errors.New("2fa already enabled; disable it first"))
		return
	}
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	recovery, err := auth.GenerateRecoveryCodes(10)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	hashes := make([]string, 0, len(recovery))
	for _, c := range recovery {
		hashes = append(hashes, auth.HashRecoveryCode(c))
	}
	user.TOTPSecret = secret
	user.RecoveryCodeHashes = hashes
	user.TOTPEnabled = false
	if err := s.store.UpsertUser(user); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "2fa.enroll", Decision: "observe"})
	writeJSON(w, http.StatusOK, map[string]any{
		"secret":         secret,
		"otpauth_uri":    auth.OTPAuthURI(totpIssuer, user.Username, secret),
		"recovery_codes": recovery,
	})
}

// handle2FAActivate verifies the first TOTP code and turns 2FA on.
func (s *Server) handle2FAActivate(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if p.viaBearer {
		writeError(w, http.StatusForbidden, errors.New("2fa management requires an interactive session"))
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	user, ok := s.store.User(p.ActorID)
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("unknown user"))
		return
	}
	if user.TOTPSecret == "" {
		writeError(w, http.StatusBadRequest, errors.New("no pending enrollment; call enroll first"))
		return
	}
	if !auth.ValidateTOTP(user.TOTPSecret, req.Code, time.Now().UTC()) {
		writeError(w, http.StatusUnauthorized, errors.New("invalid code"))
		return
	}
	user.TOTPEnabled = true
	if err := s.store.UpsertUser(user); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "2fa.activate", Decision: "allow"})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handle2FADisable turns 2FA off after verifying a current code or recovery code,
// wiping the secret and recovery hashes.
func (s *Server) handle2FADisable(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if p.viaBearer {
		writeError(w, http.StatusForbidden, errors.New("2fa management requires an interactive session"))
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	user, ok := s.store.User(p.ActorID)
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("unknown user"))
		return
	}
	if !user.TOTPEnabled {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	verified := auth.ValidateTOTP(user.TOTPSecret, req.Code, time.Now().UTC())
	if !verified {
		consumed, err := s.store.ConsumeRecoveryCode(user.ID, req.Code)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		verified = consumed
	}
	if !verified {
		writeError(w, http.StatusUnauthorized, errors.New("invalid code"))
		return
	}
	user.TOTPEnabled = false
	user.TOTPSecret = ""
	user.RecoveryCodeHashes = nil
	user.SecurityEpoch++
	if err := s.store.UpsertUser(user); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "2fa.disable", Decision: "allow"})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, p principal) {
	if p.sessionID != "" {
		if err := s.store.DeleteSession(p.sessionID); err != nil {
			s.logger.Printf("logout: delete session: %v", err)
		}
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "logout", Decision: "allow"})
	http.SetCookie(w, &http.Cookie{
		Name:     "lattice_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   s.secureCookies,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, p principal) {
	totpEnabled := false
	username := ""
	if u, ok := s.store.User(p.ActorID); ok {
		totpEnabled = u.TOTPEnabled
		username = u.Username
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"actor_id":     p.ActorID,
		"username":     username,
		"token_id":     p.TokenID,
		"scopes":       p.Scopes,
		"csrf_token":   p.CSRFToken,
		"totp_enabled": totpEnabled,
	})
}

type nodeView struct {
	ID                 string                 `json:"id"`
	Name               string                 `json:"name"`
	Tags               []string               `json:"tags"`
	Role               string                 `json:"role"`
	WireGuardIP        string                 `json:"wireguard_ip"`
	WireGuardPublicKey string                 `json:"wireguard_public_key,omitempty"`
	WireGuardEndpoint  string                 `json:"wireguard_endpoint,omitempty"`
	WireGuardPort      int                    `json:"wireguard_port,omitempty"`
	PublicIP           string                 `json:"public_ip"`
	PublicIPv6         string                 `json:"public_ipv6,omitempty"`
	AgentVersion       string                 `json:"agent_version"`
	Online             bool                   `json:"online"`
	Disabled           bool                   `json:"disabled,omitempty"`
	LastSeen           time.Time              `json:"last_seen"`
	Metrics            model.Metrics          `json:"metrics"`
	HostFacts          model.HostFacts        `json:"host_facts"`
	Geo                *model.NodeGeo         `json:"geo,omitempty"`
	AgentDebug         model.AgentDebugPolicy `json:"agent_debug"`
	GroupIDs           []string               `json:"group_ids,omitempty"`
	CreatedAt          time.Time              `json:"created_at"`
}

func toNodeView(n model.Node) nodeView {
	return nodeView{
		ID: n.ID, Name: n.Name, Tags: n.Tags, Role: n.Role,
		WireGuardIP: n.WireGuardIP, WireGuardPublicKey: n.WireGuardPublicKey,
		WireGuardEndpoint: n.WireGuardEndpoint, WireGuardPort: n.WireGuardPort,
		PublicIP: n.PublicIP, PublicIPv6: n.PublicIPv6, AgentVersion: n.AgentVersion,
		Online: n.Online, Disabled: n.Disabled, LastSeen: n.LastSeen, Metrics: n.Metrics,
		HostFacts: n.HostFacts, Geo: n.Geo, AgentDebug: n.AgentDebug, GroupIDs: n.GroupIDs, CreatedAt: n.CreatedAt,
	}
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	nodes := s.store.Nodes()
	// Resolve group membership once so each node view carries its group_ids
	// (server-computed; never client-authored). Groups are display-layer here.
	resolvedGroups := groups.ResolveAll(s.store.Groups(), nodes)
	views := make([]nodeView, 0, len(nodes))
	for _, n := range nodes {
		if rbac.Allows(p.Principal, "node:read", n.ID) {
			n.GroupIDs = groups.GroupIDsForNode(n.ID, resolvedGroups)
			views = append(views, toNodeView(n))
		}
	}
	writeJSON(w, http.StatusOK, views)
}

func (s *Server) handleEnrollNode(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		NodeID      string   `json:"node_id"`
		Name        string   `json:"name"`
		Tags        []string `json:"tags"`
		Role        string   `json:"role"`
		WireGuardIP string   `json:"wireguard_ip"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.NodeID == "" {
		req.NodeID = id.New("node")
	}
	// withAuth's allowlist check keys on the ?node_id query param, which this POST
	// does not carry, so a RESTRICTED node:admin token (one with a non-empty
	// ServerAllowlist) would otherwise short-circuit past confinement and mint an
	// enroll token for ANY node id. Bind the enrolled node id to the principal's
	// allowlist explicitly. An unrestricted admin (no allowlist, or "*") is
	// unaffected. The check covers both an empty (server-generated) id and an
	// out-of-allowlist client-supplied id.
	if principalHasNodeRestriction(p) && !rbac.Allows(p.Principal, "node:admin", req.NodeID) {
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:       id.New("audit"),
			Action:   "node.enroll",
			Scope:    "node:admin",
			NodeID:   req.NodeID,
			Decision: "deny",
			Reason:   "node id outside token server allowlist",
		})
		writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "node id outside token allowlist"))
		return
	}
	if req.Name == "" {
		req.Name = req.NodeID
	}
	token, err := auth.NewRandomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	hash, err := auth.HashSecret(token)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	n := model.Node{
		ID:          req.NodeID,
		Name:        req.Name,
		TokenHash:   hash,
		Tags:        req.Tags,
		Role:        req.Role,
		WireGuardIP: req.WireGuardIP,
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.store.UpsertNode(n); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "node.enroll", Scope: "node:admin", NodeID: req.NodeID})
	serverURL := s.agentEnrollServerURL()
	writeJSON(w, http.StatusOK, map[string]string{
		"node_id":    req.NodeID,
		"token":      token,
		"server_url": serverURL,
		"command":    s.agentEnrollCommand(serverURL, req.NodeID, token),
	})
}

func (s *Server) agentEnrollServerURL() string {
	if s.publicURL != "" {
		return s.publicURL
	}
	return "http://127.0.0.1:8088"
}

func (s *Server) agentEnrollCommand(serverURL, nodeID, token string) string {
	return fmt.Sprintf("lattice-agent -server %s -node-id %s -token %s",
		shellQuote(serverURL),
		shellQuote(nodeID),
		shellQuote(token),
	)
}

// handleRotateNodeToken issues a fresh token for an existing node, invalidating
// the old one. The new token is returned exactly once.
func (s *Server) handleRotateNodeToken(w http.ResponseWriter, r *http.Request, p principal) {
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
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	if !s.requireNodeScope(w, p, "node:admin", req.NodeID) {
		return
	}
	token, err := auth.NewRandomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	hash, err := auth.HashSecret(token)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	ok, err := s.store.RotateNodeToken(req.NodeID, hash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), NodeID: req.NodeID, Action: "node.token.rotate", Scope: "node:admin"})
	writeJSON(w, http.StatusOK, map[string]string{"node_id": req.NodeID, "token": token})
}

// handleNodeDisable revokes (or restores) a node's ability to authenticate.
func (s *Server) handleNodeDisable(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		NodeID   string `json:"node_id"`
		Disabled bool   `json:"disabled"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	if !s.requireNodeScope(w, p, "node:admin", req.NodeID) {
		return
	}
	ok, err := s.store.SetNodeDisabled(req.NodeID, req.Disabled)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	action := "node.enable"
	if req.Disabled {
		action = "node.disable"
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), NodeID: req.NodeID, Action: action, Scope: "node:admin"})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true, "disabled": req.Disabled})
}

func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireScope(w, p, "task:read") {
			return
		}
		tasks := s.store.Tasks()
		visible := make([]taskView, 0, len(tasks))
		for _, task := range tasks {
			if taskTargetsAllowed(p, "task:read", task.Targets) {
				visible = append(visible, toTaskView(task))
			}
		}
		writeJSON(w, http.StatusOK, visible)
	case http.MethodPost:
		var req struct {
			Targets     []string `json:"targets"`
			Interpreter string   `json:"interpreter"`
			Script      string   `json:"script"`
			TimeoutSec  int      `json:"timeout_sec"`
			OutputLimit int      `json:"output_limit"`
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		if len(req.Targets) == 0 || strings.TrimSpace(req.Script) == "" {
			writeError(w, http.StatusBadRequest, errors.New("targets and script are required"))
			return
		}
		if !s.requireAllNodeScopes(w, p, "task:run", req.Targets) {
			return
		}
		if req.Interpreter == "" {
			req.Interpreter = "sh"
		}
		if req.TimeoutSec == 0 {
			req.TimeoutSec = defaultTaskTimeoutSec
		}
		if req.OutputLimit == 0 {
			req.OutputLimit = defaultTaskOutputLimit
		}
		if err := validateTaskCreate(req.Interpreter, req.Script, req.TimeoutSec, req.OutputLimit); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		task := model.Task{
			ID:          id.New("task"),
			ActorID:     p.ActorID,
			TokenID:     p.TokenID,
			Targets:     req.Targets,
			Interpreter: req.Interpreter,
			Script:      req.Script,
			TimeoutSec:  req.TimeoutSec,
			OutputLimit: req.OutputLimit,
			Status:      model.TaskQueued,
			CreatedAt:   time.Now().UTC(),
		}
		if err := s.store.CreateTask(task); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "task.create", Scope: "task:run", Metadata: map[string]string{"task_id": task.ID}})
		writeJSON(w, http.StatusOK, toTaskView(task))
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func validateTaskCreate(interpreter, script string, timeoutSec, outputLimit int) error {
	if !allowedTaskInterpreters[interpreter] {
		return fmt.Errorf("interpreter %q is not allowlisted", interpreter)
	}
	if timeoutSec <= 0 || timeoutSec > maxTaskTimeoutSec {
		return fmt.Errorf("timeout_sec must be between 1 and %d", maxTaskTimeoutSec)
	}
	if outputLimit <= 0 || outputLimit > maxTaskOutputLimit {
		return fmt.Errorf("output_limit must be between 1 and %d", maxTaskOutputLimit)
	}
	if len([]byte(script)) > maxTaskScriptBytes {
		return fmt.Errorf("script exceeds %d bytes", maxTaskScriptBytes)
	}
	return nil
}

type taskView struct {
	ID              string    `json:"id"`
	ActorID         string    `json:"actor_id"`
	TokenID         string    `json:"token_id"`
	Targets         []string  `json:"targets"`
	Interpreter     string    `json:"interpreter"`
	ScriptSHA256    string    `json:"script_sha256"`
	ScriptSizeBytes int       `json:"script_size_bytes"`
	TimeoutSec      int       `json:"timeout_sec"`
	OutputLimit     int       `json:"output_limit"`
	Status          string    `json:"status"`
	LeasedBy        string    `json:"leased_by,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	StartedAt       time.Time `json:"started_at,omitempty"`
	FinishedAt      time.Time `json:"finished_at,omitempty"`
}

func toTaskView(t model.Task) taskView {
	return taskView{
		ID:              t.ID,
		ActorID:         t.ActorID,
		TokenID:         t.TokenID,
		Targets:         t.Targets,
		Interpreter:     t.Interpreter,
		ScriptSHA256:    scriptSHA256(t.Script),
		ScriptSizeBytes: len([]byte(t.Script)),
		TimeoutSec:      t.TimeoutSec,
		OutputLimit:     t.OutputLimit,
		Status:          t.Status,
		LeasedBy:        t.LeasedBy,
		CreatedAt:       t.CreatedAt,
		StartedAt:       t.StartedAt,
		FinishedAt:      t.FinishedAt,
	}
}

func scriptSHA256(script string) string {
	sum := sha256.Sum256([]byte(script))
	return hex.EncodeToString(sum[:])
}

func (s *Server) handleTaskResults(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	results := s.store.Results()
	visible := make([]taskResultView, 0, len(results))
	for _, result := range results {
		if rbac.Allows(p.Principal, "task:read", result.NodeID) {
			visible = append(visible, toTaskResultView(result))
		}
	}
	writeJSON(w, http.StatusOK, visible)
}

type taskResultView struct {
	TaskID     string    `json:"task_id"`
	NodeID     string    `json:"node_id"`
	ExitCode   int       `json:"exit_code"`
	Stdout     string    `json:"stdout"`
	Stderr     string    `json:"stderr"`
	Error      string    `json:"error"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

func toTaskResultView(r model.TaskResult) taskResultView {
	return taskResultView{
		TaskID:     r.TaskID,
		NodeID:     r.NodeID,
		ExitCode:   r.ExitCode,
		Stdout:     r.Stdout,
		Stderr:     r.Stderr,
		Error:      r.Error,
		StartedAt:  r.StartedAt,
		FinishedAt: r.FinishedAt,
	}
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	events := s.store.AuditEvents()
	if !auditQueryRequested(r) {
		writeJSON(w, http.StatusOK, events)
		return
	}
	out, err := queryAuditEvents(r, events)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

const (
	defaultAuditLimit = 100
	maxAuditLimit     = 500
)

type auditQueryResponse struct {
	Events []model.AuditEvent `json:"events"`
	Total  int                `json:"total"`
	Limit  int                `json:"limit"`
	Offset int                `json:"offset"`
}

func auditQueryRequested(r *http.Request) bool {
	q := r.URL.Query()
	for _, key := range []string{"action", "decision", "node_id", "actor_id", "token_id", "scope", "correlation_id", "limit", "offset"} {
		if _, ok := q[key]; ok {
			return true
		}
	}
	return false
}

func queryAuditEvents(r *http.Request, events []model.AuditEvent) (auditQueryResponse, error) {
	q := r.URL.Query()
	limit, err := boundedIntQuery(q.Get("limit"), defaultAuditLimit, maxAuditLimit, "limit")
	if err != nil {
		return auditQueryResponse{}, err
	}
	offset, err := boundedIntQuery(q.Get("offset"), 0, 0, "offset")
	if err != nil {
		return auditQueryResponse{}, err
	}
	filtered := make([]model.AuditEvent, 0, len(events))
	for _, ev := range events {
		if !auditEventMatches(ev, q.Get("action"), q.Get("decision"), q.Get("node_id"), q.Get("actor_id"), q.Get("token_id"), q.Get("scope"), q.Get("correlation_id")) {
			continue
		}
		filtered = append(filtered, ev)
	}
	total := len(filtered)
	if offset > total {
		filtered = nil
	} else {
		filtered = filtered[offset:]
	}
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}
	return auditQueryResponse{Events: filtered, Total: total, Limit: limit, Offset: offset}, nil
}

func boundedIntQuery(raw string, fallback, max int, name string) (int, error) {
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", name)
	}
	if value < 0 || (name == "limit" && value == 0) {
		return 0, fmt.Errorf("%s is out of range", name)
	}
	if max > 0 && value > max {
		return 0, fmt.Errorf("%s must be <= %d", name, max)
	}
	return value, nil
}

func auditEventMatches(ev model.AuditEvent, action, decision, nodeID, actorID, tokenID, scope, correlationID string) bool {
	return auditFieldMatches(ev.Action, action) &&
		auditFieldMatches(ev.Decision, decision) &&
		auditFieldMatches(ev.NodeID, nodeID) &&
		auditFieldMatches(ev.ActorID, actorID) &&
		auditFieldMatches(ev.TokenID, tokenID) &&
		auditFieldMatches(ev.Scope, scope) &&
		auditFieldMatches(ev.CorrelationID, correlationID)
}

func auditFieldMatches(value, want string) bool {
	want = strings.TrimSpace(want)
	return want == "" || value == want
}

// handleAuditVerify validates the tamper-evident audit WAL chain and reports the
// result. A broken chain returns ok=false (200) so an operator can SEE the
// tampering rather than receive a generic error.
func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	res, enabled, err := s.store.AuditWALVerify()
	if !enabled {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	out := map[string]any{"enabled": true, "ok": err == nil, "count": res.Count, "head": res.Head}
	if err != nil {
		out["error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleKV(w http.ResponseWriter, r *http.Request, p principal) {
	bucket := r.URL.Query().Get("bucket")
	if bucket == "" {
		bucket = "default"
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.store.KV(bucket))
	case http.MethodPost:
		if !rbac.Allows(p.Principal, "kv:write", "") {
			writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "missing kv:write"))
			return
		}
		var req struct {
			Bucket string `json:"bucket"`
			Key    string `json:"key"`
			Value  string `json:"value"`
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		if req.Bucket == "" {
			req.Bucket = bucket
		}
		if req.Key == "" {
			writeError(w, http.StatusBadRequest, errors.New("key is required"))
			return
		}
		if err := validateStorageName(req.Bucket); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("bucket: %w", err))
			return
		}
		if err := validateStorageName(req.Key); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("key: %w", err))
			return
		}
		entry := model.KVEntry{Bucket: req.Bucket, Key: req.Key, Value: req.Value}
		if err := s.store.PutKV(entry); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "kv.put", Scope: "kv:write", Metadata: map[string]string{"bucket": req.Bucket, "key": req.Key}})
		writeJSON(w, http.StatusOK, entry)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request, p principal) {
	bucket := r.URL.Query().Get("bucket")
	if bucket == "" {
		bucket = "default"
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.store.Static(bucket))
	case http.MethodPost:
		if !rbac.Allows(p.Principal, "static:write", "") {
			writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "missing static:write"))
			return
		}
		var req struct {
			Bucket      string `json:"bucket"`
			Path        string `json:"path"`
			Content     string `json:"content"`
			ContentType string `json:"content_type"`
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		if req.Bucket == "" {
			req.Bucket = bucket
		}
		if err := validateStorageName(req.Bucket); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("bucket: %w", err))
			return
		}
		clean, err := cleanObjectPath(req.Path)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		obj := model.StaticObject{Bucket: req.Bucket, Path: clean, Content: req.Content, ContentType: req.ContentType}
		if err := s.store.PutStatic(obj); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "static.put", Scope: "static:write", Metadata: map[string]string{"bucket": req.Bucket, "path": clean}})
		writeJSON(w, http.StatusOK, obj)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleWorkers(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.store.Workers())
	case http.MethodPost:
		var req struct {
			Name         string   `json:"name"`
			Source       string   `json:"source"`
			Capabilities []string `json:"capabilities"`
			Public       bool     `json:"public"`
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		if req.Name == "" || req.Source == "" {
			writeError(w, http.StatusBadRequest, errors.New("name and source are required"))
			return
		}
		if err := worker.ValidateSource(req.Source); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		wk := model.WorkerScript{ID: id.New("worker"), Name: req.Name, Source: req.Source, Capabilities: req.Capabilities, Public: req.Public}
		if err := s.store.UpsertWorker(wk); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "worker.upsert", Scope: "worker:deploy", Metadata: map[string]string{"worker_id": wk.ID}})
		writeJSON(w, http.StatusOK, wk)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleWorkerRun(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		WorkerID string `json:"worker_id"`
		Path     string `json:"path"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	for _, wk := range s.store.Workers() {
		if wk.ID != req.WorkerID {
			continue
		}
		resp, err := worker.Runtime{KV: s.store}.Run(wk, worker.Request{Path: req.Path})
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	writeError(w, http.StatusNotFound, errors.New("worker not found"))
}

// handleNotifyTest delivers a one-off test notification through a channel whose
// config is supplied inline. Gated by notify:send (admin in practice) because it
// makes an outbound request to a caller-specified destination.
func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		Channel string            `json:"channel"`
		Config  map[string]string `json:"config"`
		Title   string            `json:"title"`
		Body    string            `json:"body"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	ch, err := buildChannel(req.Channel, req.Config)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Title == "" {
		req.Title = "Lattice test"
	}
	if req.Body == "" {
		req.Body = "Notification channel verified."
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	sendErr := ch.Send(ctx, notify.Message{Title: req.Title, Body: req.Body})
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "notify.test", Scope: "notify:send", Metadata: map[string]string{"channel": req.Channel, "ok": fmt.Sprintf("%t", sendErr == nil)}})
	if sendErr != nil {
		writeError(w, http.StatusBadGateway, sendErr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "channel": ch.Kind()})
}

// buildChannel constructs a notify.Channel from a kind and a flat config map.
func buildChannel(kind string, cfg map[string]string) (notify.Channel, error) {
	if cfg == nil {
		cfg = map[string]string{}
	}
	switch kind {
	case "telegram":
		if cfg["token"] == "" || cfg["chat_id"] == "" {
			return nil, errors.New("telegram requires config.token and config.chat_id")
		}
		return notify.Telegram{Token: cfg["token"], ChatID: cfg["chat_id"], BaseURL: cfg["base_url"]}, nil
	case "bark":
		if cfg["base_url"] == "" || cfg["key"] == "" {
			return nil, errors.New("bark requires config.base_url and config.key")
		}
		return notify.Bark{BaseURL: cfg["base_url"], Key: cfg["key"]}, nil
	case "discord":
		if cfg["webhook_url"] == "" {
			return nil, errors.New("discord requires config.webhook_url")
		}
		return notify.Discord{WebhookURL: cfg["webhook_url"]}, nil
	case "webhook":
		if cfg["url"] == "" {
			return nil, errors.New("webhook requires config.url")
		}
		return notify.Webhook{URL: cfg["url"]}, nil
	default:
		return nil, fmt.Errorf("unknown notify channel %q", kind)
	}
}

func (s *Server) handleMonitors(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		monitors := s.store.Monitors()
		visible := make([]model.Monitor, 0, len(monitors))
		for _, mon := range monitors {
			if monitorVisibleToPrincipal(p, "monitor:read", mon) {
				visible = append(visible, mon)
			}
		}
		writeJSON(w, http.StatusOK, toMonitorViews(visible))
	case http.MethodPost:
		if !rbac.Allows(p.Principal, "monitor:admin", "") {
			writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "missing monitor:admin"))
			return
		}
		var req model.Monitor
		if !decodeClientJSON(w, r, &req) {
			return
		}
		if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Target) == "" {
			writeError(w, http.StatusBadRequest, errors.New("name and target are required"))
			return
		}
		if req.Type != model.MonitorTypeTCP && req.Type != model.MonitorTypeHTTP {
			writeError(w, http.StatusBadRequest, errors.New("only tcp and http monitors are supported (icmp pending)"))
			return
		}
		if !req.AssignAll && len(req.NodeIDs) == 0 {
			writeError(w, http.StatusBadRequest, errors.New("set assign_all or provide node_ids"))
			return
		}
		if req.AssignAll && principalHasNodeRestriction(p) {
			writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "restricted token cannot assign monitor to all nodes"))
			return
		}
		if !req.AssignAll && !s.requireAllNodeScopes(w, p, "monitor:admin", req.NodeIDs) {
			return
		}
		if req.IntervalSec <= 0 {
			req.IntervalSec = 30
		}
		if req.TimeoutSec <= 0 {
			req.TimeoutSec = 5
		}
		req.ID = id.New("mon")
		req.Enabled = true
		if err := s.store.UpsertMonitor(req); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "monitor.create", Scope: "monitor:admin", Metadata: map[string]string{"monitor_id": req.ID, "type": req.Type}})
		writeJSON(w, http.StatusOK, req)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleDeleteMonitor(w http.ResponseWriter, r *http.Request, p principal) {
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
	if mon, ok := s.store.Monitor(req.ID); ok && !monitorManageableByPrincipal(p, mon) {
		writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
		return
	}
	if err := s.store.DeleteMonitor(req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "monitor.delete", Scope: "monitor:admin", Metadata: map[string]string{"monitor_id": req.ID}})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMonitorResults(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	monitorID := r.URL.Query().Get("monitor_id")
	if monitorID == "" {
		writeError(w, http.StatusBadRequest, errors.New("monitor_id is required"))
		return
	}
	mon, ok := s.store.Monitor(monitorID)
	if ok && !monitorVisibleToPrincipal(p, "monitor:read", mon) {
		writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
		return
	}
	results := s.store.MonitorResults(monitorID)
	visible := make([]model.MonitorResult, 0, len(results))
	for _, result := range results {
		if rbac.Allows(p.Principal, "monitor:read", result.NodeID) {
			visible = append(visible, result)
		}
	}
	writeJSON(w, http.StatusOK, visible)
}

func monitorVisibleToPrincipal(p principal, scope string, mon model.Monitor) bool {
	if mon.AssignAll {
		return rbac.Allows(p.Principal, scope, "")
	}
	if len(mon.NodeIDs) == 0 {
		return !principalHasNodeRestriction(p) && rbac.Allows(p.Principal, scope, "")
	}
	for _, nodeID := range mon.NodeIDs {
		if rbac.Allows(p.Principal, scope, nodeID) {
			return true
		}
	}
	return false
}

func monitorManageableByPrincipal(p principal, mon model.Monitor) bool {
	if mon.AssignAll {
		return !principalHasNodeRestriction(p) && rbac.Allows(p.Principal, "monitor:admin", "")
	}
	return taskTargetsAllowed(p, "monitor:admin", mon.NodeIDs)
}

// handleAgentMonitors returns the monitors an authenticated agent should run.
func (s *Server) handleAgentMonitors(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	if _, ok := s.authenticateNode(nodeID, bearerToken(r)); !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	writeJSON(w, http.StatusOK, s.store.MonitorsForNode(nodeID))
}

// handleAgentMonitorResult ingests a probe outcome from an authenticated agent.
func (s *Server) handleAgentMonitorResult(w http.ResponseWriter, r *http.Request) {
	var req struct {
		agentAuthRequest
		Result model.MonitorResult `json:"result"`
	}
	if !decodeAgentJSON(w, r, &req) {
		return
	}
	if _, ok := s.authenticateAgentRequest(r, req.NodeID); !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	req.Result.NodeID = req.NodeID
	prior, hadPrior := s.store.LastMonitorResultForNode(req.Result.MonitorID, req.NodeID)
	if err := s.store.AddMonitorResult(req.Result); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.notifyMonitorTransition(req.NodeID, req.Result, prior, hadPrior)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// notifyChannelView is the secret-free projection of a notification channel.
// Config values (tokens, webhook URLs) are never returned; only the set of
// configured keys is exposed so an operator can see what is configured.
type notifyChannelView struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Kind       string    `json:"kind"`
	ConfigKeys []string  `json:"config_keys"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func toNotifyChannelView(c model.NotifyChannel) notifyChannelView {
	keys := make([]string, 0, len(c.Config))
	for k := range c.Config {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return notifyChannelView{ID: c.ID, Name: c.Name, Kind: c.Kind, ConfigKeys: keys, Enabled: c.Enabled, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
}

func (s *Server) handleNotifyChannels(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		channels := s.store.NotifyChannels()
		views := make([]notifyChannelView, 0, len(channels))
		for _, c := range channels {
			views = append(views, toNotifyChannelView(c))
		}
		writeJSON(w, http.StatusOK, views)
	case http.MethodPost:
		var req struct {
			ID      string            `json:"id"`
			Name    string            `json:"name"`
			Kind    string            `json:"kind"`
			Config  map[string]string `json:"config"`
			Enabled *bool             `json:"enabled"`
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		if strings.TrimSpace(req.Name) == "" {
			writeError(w, http.StatusBadRequest, errors.New("name is required"))
			return
		}
		// Validate the channel config eagerly by constructing it.
		if _, err := buildChannel(req.Kind, req.Config); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		channelID := strings.TrimSpace(req.ID)
		if channelID == "" {
			channelID = id.New("notify")
		} else if err := validateNotifyID(channelID); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("id: %w", err))
			return
		}
		channel := model.NotifyChannel{
			ID:      channelID,
			Name:    req.Name,
			Kind:    req.Kind,
			Config:  req.Config,
			Enabled: req.Enabled == nil || *req.Enabled,
		}
		for _, existing := range s.store.NotifyChannels() {
			if existing.ID == channel.ID {
				channel.CreatedAt = existing.CreatedAt
				break
			}
		}
		if err := s.store.UpsertNotifyChannel(channel); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		action := "notify.channel.create"
		if req.ID != "" {
			action = "notify.channel.update"
		}
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: action, Scope: "notify:send", Metadata: map[string]string{"channel_id": channel.ID, "kind": channel.Kind}})
		writeJSON(w, http.StatusOK, toNotifyChannelView(channel))
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleDeleteNotifyChannel(w http.ResponseWriter, r *http.Request, p principal) {
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
	if err := s.store.DeleteNotifyChannel(req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "notify.channel.delete", Scope: "notify:send", Metadata: map[string]string{"channel_id": req.ID}})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleNotifyRules(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"rules": s.store.NotifyRules()})
	case http.MethodPost:
		var req struct {
			ID            string   `json:"id"`
			Name          string   `json:"name"`
			EventTypes    []string `json:"event_types"`
			ChannelIDs    []string `json:"channel_ids"`
			TitleTemplate string   `json:"title_template"`
			BodyTemplate  string   `json:"body_template"`
			Enabled       *bool    `json:"enabled"`
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		rule, err := normalizeNotifyRule(req.ID, req.Name, req.EventTypes, req.ChannelIDs, req.TitleTemplate, req.BodyTemplate, req.Enabled, s.store.NotifyChannels())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if existingRules := s.store.NotifyRules(); rule.ID != "" {
			for _, existing := range existingRules {
				if existing.ID == rule.ID {
					rule.CreatedAt = existing.CreatedAt
					break
				}
			}
		}
		if err := s.store.UpsertNotifyRule(rule); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "notify.rule.upsert", Scope: "notify:send", Metadata: map[string]string{"rule_id": rule.ID}})
		writeJSON(w, http.StatusOK, rule)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleDeleteNotifyRule(w http.ResponseWriter, r *http.Request, p principal) {
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
	if strings.TrimSpace(req.ID) == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	if err := s.store.DeleteNotifyRule(req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "notify.rule.delete", Scope: "notify:send", Metadata: map[string]string{"rule_id": req.ID}})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// notifyEvent fans a message out to every enabled notification channel,
// asynchronously so it never blocks the triggering request.
func (s *Server) notifyEvent(title, body string) {
	channels := s.store.EnabledNotifyChannels()
	deliveries := s.planNotifyDeliveries(classifyNotifyEvent(title), title, body, channels, s.store.EnabledNotifyRules())
	if len(deliveries) == 0 {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for _, delivery := range deliveries {
			if len(delivery.Channels) == 0 {
				continue
			}
			for _, res := range notify.NewDispatcher(delivery.Channels...).Send(ctx, delivery.Message) {
				if res.Err != nil {
					s.logger.Printf("notify: %s delivery failed: %v", res.Kind, res.Err)
				}
			}
		}
	}()
}

type notifyDelivery struct {
	Channels []notify.Channel
	Message  notify.Message
}

func (s *Server) planNotifyDeliveries(eventType, title, body string, channels []model.NotifyChannel, rules []model.NotifyRule) []notifyDelivery {
	if len(channels) == 0 {
		return nil
	}
	if len(rules) == 0 {
		built := s.buildNotifyChannels(channels)
		if len(built) == 0 {
			return nil
		}
		return []notifyDelivery{{Channels: built, Message: notify.Message{Title: title, Body: body}}}
	}
	channelsByID := make(map[string]model.NotifyChannel, len(channels))
	for _, channel := range channels {
		channelsByID[channel.ID] = channel
	}
	deliveries := []notifyDelivery{}
	for _, rule := range rules {
		if !notifyRuleMatches(rule, eventType) {
			continue
		}
		selected := make([]model.NotifyChannel, 0, len(rule.ChannelIDs))
		seen := map[string]bool{}
		for _, channelID := range rule.ChannelIDs {
			if seen[channelID] {
				continue
			}
			seen[channelID] = true
			channel, ok := channelsByID[channelID]
			if !ok {
				s.logger.Printf("notify: rule %s references missing or disabled channel %s", rule.ID, channelID)
				continue
			}
			selected = append(selected, channel)
		}
		built := s.buildNotifyChannels(selected)
		if len(built) == 0 {
			continue
		}
		vars := map[string]string{"event_type": eventType, "title": title, "body": body}
		outTitle := renderNotifyTemplate(rule.TitleTemplate, title, vars)
		outBody := renderNotifyTemplate(rule.BodyTemplate, body, vars)
		deliveries = append(deliveries, notifyDelivery{Channels: built, Message: notify.Message{Title: outTitle, Body: outBody}})
	}
	return deliveries
}

func (s *Server) buildNotifyChannels(channels []model.NotifyChannel) []notify.Channel {
	built := make([]notify.Channel, 0, len(channels))
	for _, c := range channels {
		ch, err := buildChannel(c.Kind, c.Config)
		if err != nil {
			s.logger.Printf("notify: channel %s misconfigured: %v", c.ID, err)
			continue
		}
		built = append(built, ch)
	}
	return built
}

func notifyRuleMatches(rule model.NotifyRule, eventType string) bool {
	if len(rule.EventTypes) == 0 {
		return true
	}
	for _, candidate := range rule.EventTypes {
		if candidate == "*" || candidate == eventType {
			return true
		}
	}
	return false
}

func renderNotifyTemplate(tmpl, fallback string, vars map[string]string) string {
	tmpl = strings.TrimSpace(tmpl)
	if tmpl == "" {
		return fallback
	}
	out := tmpl
	for key, value := range vars {
		out = strings.ReplaceAll(out, "{{"+key+"}}", value)
	}
	return out
}

func classifyNotifyEvent(title string) string {
	switch {
	case strings.Contains(title, "Monitor recovered"):
		return "monitor.recovered"
	case strings.Contains(title, "Monitor down"):
		return "monitor.down"
	case strings.Contains(title, "SSH login"):
		return "ssh.login"
	case strings.HasPrefix(title, "Lattice proxy quota"):
		return "proxy.quota"
	case strings.HasPrefix(title, "Lattice proxy expiry"):
		return "proxy.expiry"
	default:
		return "generic"
	}
}

func normalizeNotifyRule(idValue, name string, eventTypes, channelIDs []string, titleTemplate, bodyTemplate string, enabled *bool, channels []model.NotifyChannel) (model.NotifyRule, error) {
	idValue = strings.TrimSpace(idValue)
	if idValue == "" {
		idValue = id.New("notify_rule")
	} else if err := validateNotifyID(idValue); err != nil {
		return model.NotifyRule{}, fmt.Errorf("id: %w", err)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return model.NotifyRule{}, errors.New("name is required")
	}
	cleanEvents, err := normalizeNotifyEvents(eventTypes)
	if err != nil {
		return model.NotifyRule{}, err
	}
	existingChannels := map[string]bool{}
	for _, channel := range channels {
		existingChannels[channel.ID] = true
	}
	cleanChannels := []string{}
	seenChannels := map[string]bool{}
	for _, channelID := range channelIDs {
		channelID = strings.TrimSpace(channelID)
		if channelID == "" {
			continue
		}
		if !existingChannels[channelID] {
			return model.NotifyRule{}, fmt.Errorf("channel %q does not exist", channelID)
		}
		if !seenChannels[channelID] {
			seenChannels[channelID] = true
			cleanChannels = append(cleanChannels, channelID)
		}
	}
	if len(cleanChannels) == 0 {
		return model.NotifyRule{}, errors.New("at least one channel is required")
	}
	rule := model.NotifyRule{
		ID:            idValue,
		Name:          name,
		EventTypes:    cleanEvents,
		ChannelIDs:    cleanChannels,
		TitleTemplate: strings.TrimSpace(titleTemplate),
		BodyTemplate:  strings.TrimSpace(bodyTemplate),
		Enabled:       enabled == nil || *enabled,
	}
	return rule, nil
}

func normalizeNotifyEvents(eventTypes []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, eventType := range eventTypes {
		eventType = strings.TrimSpace(strings.ToLower(eventType))
		if eventType == "" {
			continue
		}
		if err := validateNotifyEventType(eventType); err != nil {
			return nil, err
		}
		if eventType == "*" {
			return []string{"*"}, nil
		}
		if !seen[eventType] {
			seen[eventType] = true
			out = append(out, eventType)
		}
	}
	if len(out) == 0 {
		return []string{"*"}, nil
	}
	sort.Strings(out)
	return out, nil
}

func validateNotifyEventType(eventType string) error {
	if eventType == "*" {
		return nil
	}
	if len(eventType) > 64 {
		return errors.New("event type is too long")
	}
	for _, r := range eventType {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == ':' || r == '-' {
			continue
		}
		return fmt.Errorf("invalid event type %q", eventType)
	}
	return nil
}

func validateNotifyID(value string) error {
	if value == "" || len(value) > 128 {
		return errors.New("invalid id")
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return errors.New("id contains control characters")
		}
	}
	return nil
}

// notifyMonitorTransition emits an alert when a monitor's success state flips
// (or on the first observed failure), so flapping does not spam every result.
func (s *Server) notifyMonitorTransition(nodeID string, current, prior model.MonitorResult, hadPrior bool) {
	transitioned := (!hadPrior && !current.Success) || (hadPrior && prior.Success != current.Success)
	if !transitioned {
		return
	}
	mon, _ := s.store.Monitor(current.MonitorID)
	name := mon.Name
	if name == "" {
		name = current.MonitorID
	}
	if current.Success {
		s.emitNotify("✅ Monitor recovered", fmt.Sprintf("%s on node %s is back up (%.1fms)", name, nodeID, current.LatencyMs))
	} else {
		detail := current.Error
		if detail == "" {
			detail = "probe failed"
		}
		s.emitNotify("🔴 Monitor down", fmt.Sprintf("%s on node %s failed: %s", name, nodeID, detail))
	}
}

// handleAgentEvent ingests an out-of-band event from an authenticated agent
// (currently SSH login notifications) and turns it into an audit record plus a
// notification.
func (s *Server) handleAgentEvent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		agentAuthRequest
		Kind    string `json:"kind"`
		User    string `json:"user"`
		Address string `json:"address"`
		Method  string `json:"method"`
		Message string `json:"message"`
	}
	if !decodeAgentJSON(w, r, &req) {
		return
	}
	if _, ok := s.authenticateAgentRequest(r, req.NodeID); !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	switch req.Kind {
	case "ssh_login":
		s.recordRequestAudit(r, model.AuditEvent{ID: id.New("audit"), NodeID: req.NodeID, Action: "ssh.login", Decision: "observe", Metadata: map[string]string{"user": req.User, "address": req.Address, "method": req.Method}})
		s.emitNotify("🔐 SSH login", fmt.Sprintf("node %s: %s logged in from %s (%s)", req.NodeID, req.User, req.Address, req.Method))
	default:
		s.recordRequestAudit(r, model.AuditEvent{ID: id.New("audit"), NodeID: req.NodeID, Action: "agent.event", Decision: "observe", Metadata: map[string]string{"kind": req.Kind, "message": req.Message}})
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ddnsView is the secret-free projection of a DDNS profile returned to clients.
// Credentials (Cloudflare token, webhook headers) are never serialized.
type ddnsView struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	NodeID        string    `json:"node_id"`
	Provider      string    `json:"provider"`
	Domains       []string  `json:"domains"`
	EnableIPv4    bool      `json:"enable_ipv4"`
	EnableIPv6    bool      `json:"enable_ipv6"`
	MaxRetries    int       `json:"max_retries"`
	TTL           int       `json:"ttl"`
	HasCredential bool      `json:"has_credential"`
	WebhookURL    string    `json:"webhook_url,omitempty"`
	WebhookMethod string    `json:"webhook_method,omitempty"`
	LastIPv4      string    `json:"last_ipv4,omitempty"`
	LastIPv6      string    `json:"last_ipv6,omitempty"`
	LastRunAt     time.Time `json:"last_run_at,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func toDDNSView(p model.DDNSProfile) ddnsView {
	return ddnsView{
		ID: p.ID, Name: p.Name, NodeID: p.NodeID, Provider: p.Provider, Domains: p.Domains,
		EnableIPv4: p.EnableIPv4, EnableIPv6: p.EnableIPv6, MaxRetries: p.MaxRetries, TTL: p.TTL,
		HasCredential: p.CFAPIToken != "" || p.WebhookHeaders != "",
		WebhookURL:    p.WebhookURL, WebhookMethod: p.WebhookMethod,
		LastIPv4: p.LastIPv4, LastIPv6: p.LastIPv6, LastRunAt: p.LastRunAt, LastError: p.LastError,
		CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
}

func (s *Server) handleDDNS(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		profiles := s.store.DDNSProfiles()
		views := make([]ddnsView, 0, len(profiles))
		for _, pr := range profiles {
			if rbac.Allows(p.Principal, "ddns:admin", pr.NodeID) {
				views = append(views, toDDNSView(pr))
			}
		}
		writeJSON(w, http.StatusOK, views)
	case http.MethodPost:
		var req model.DDNSProfile
		if !decodeClientJSON(w, r, &req) {
			return
		}
		if strings.TrimSpace(req.Name) == "" || req.NodeID == "" || len(req.Domains) == 0 {
			writeError(w, http.StatusBadRequest, errors.New("name, node_id and at least one domain are required"))
			return
		}
		if !s.requireNodeScope(w, p, "ddns:admin", req.NodeID) {
			return
		}
		if !req.EnableIPv4 && !req.EnableIPv6 {
			req.EnableIPv4 = true
		}
		req.ID = id.New("ddns")
		// Validate the provider configuration eagerly by constructing it.
		if _, err := s.ddnsProvider(req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.store.UpsertDDNSProfile(req); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), NodeID: req.NodeID, Action: "ddns.create", Scope: "ddns:admin", Metadata: map[string]string{"ddns_id": req.ID, "provider": req.Provider}})
		writeJSON(w, http.StatusOK, toDDNSView(req))
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleDeleteDDNS(w http.ResponseWriter, r *http.Request, p principal) {
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
	nodeID := ""
	if profile, ok := s.store.DDNSProfile(req.ID); ok {
		nodeID = profile.NodeID
		if !s.requireNodeScope(w, p, "ddns:admin", profile.NodeID) {
			return
		}
	}
	if err := s.store.DeleteDDNSProfile(req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), NodeID: nodeID, Action: "ddns.delete", Scope: "ddns:admin", Metadata: map[string]string{"ddns_id": req.ID}})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleRunDDNS manually triggers a profile using its bound node's current
// public IP, synchronously, so an operator (or a test) gets the outcome inline.
func (s *Server) handleRunDDNS(w http.ResponseWriter, r *http.Request, p principal) {
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
	profile, ok := s.store.DDNSProfile(req.ID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("ddns profile not found"))
		return
	}
	if !s.requireNodeScope(w, p, "ddns:admin", profile.NodeID) {
		return
	}
	node, ok := s.store.Node(profile.NodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	if err := s.runDDNSForPrincipal(p, profile, node.PublicIP, node.PublicIPv6); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	updated, _ := s.store.DDNSProfile(req.ID)
	writeJSON(w, http.StatusOK, toDDNSView(updated))
}

// resolvePublicIPs picks the public IPs to record for an agent request. Values
// the agent reports win; otherwise the observed source address fills the
// matching family, giving zero-config DDNS for dial-out agents.
func (s *Server) resolvePublicIPs(r *http.Request, reportedV4, reportedV6 string) (v4, v6 string) {
	v4, v6 = reportedV4, reportedV6
	if ip := net.ParseIP(s.clientIP(r)); ip != nil {
		if ip.To4() != nil {
			if v4 == "" {
				v4 = ip.String()
			}
		} else if v6 == "" {
			v6 = ip.String()
		}
	}
	return v4, v6
}

// maybeTriggerDDNS runs every profile bound to a node when its public IP changed.
func (s *Server) maybeTriggerDDNS(nodeID, oldV4, oldV6, newV4, newV6 string) {
	changed := (newV4 != "" && newV4 != oldV4) || (newV6 != "" && newV6 != oldV6)
	if !changed {
		return
	}
	for _, profile := range s.store.DDNSProfilesForNode(nodeID) {
		profile := profile
		go func() {
			if err := s.runDDNS(profile, newV4, newV6); err != nil {
				s.logger.Printf("ddns: profile %s update failed: %v", profile.ID, err)
			}
		}()
	}
	for _, dep := range s.store.DNSDeploymentsForNode(nodeID) {
		dep := dep
		if dep.Hostname == "" || dep.Disabled {
			continue
		}
		go func() {
			if err := s.publishDNSDeployment(dep, newV4, newV6); err != nil {
				s.logger.Printf("dns publish: deployment %s update failed: %v", dep.ID, err)
			}
		}()
	}
	// A changed node IP makes any geo-routing that targets or serves this node
	// stale: the rendered zone embeds node IPs. Flag dependents so the operator
	// re-plans and re-applies (the apply path is operator-initiated).
	s.touchGeoRoutingsForNode(nodeID)
}

// runDDNS applies a profile and records the run outcome on the profile.
func (s *Server) runDDNS(profile model.DDNSProfile, v4, v6 string) error {
	return s.runDDNSWithAudit(profile, v4, v6, s.recordAudit)
}

func (s *Server) runDDNSForPrincipal(p principal, profile model.DDNSProfile, v4, v6 string) error {
	return s.runDDNSWithAudit(profile, v4, v6, func(ev model.AuditEvent) {
		s.recordPrincipalAudit(p, ev)
	})
}

func (s *Server) runDDNSWithAudit(profile model.DDNSProfile, v4, v6 string, record func(model.AuditEvent)) error {
	prov, err := s.ddnsProvider(profile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	applyErr := ddns.Apply(ctx, prov, profile, v4, v6)
	profile.LastRunAt = time.Now().UTC()
	if v4 != "" {
		profile.LastIPv4 = v4
	}
	if v6 != "" {
		profile.LastIPv6 = v6
	}
	if applyErr != nil {
		profile.LastError = applyErr.Error()
	} else {
		profile.LastError = ""
	}
	if err := s.store.UpsertDDNSProfile(profile); err != nil {
		s.logger.Printf("ddns: persist profile %s: %v", profile.ID, err)
	}
	record(model.AuditEvent{ID: id.New("audit"), NodeID: profile.NodeID, Action: "ddns.run", Scope: "ddns:admin", Metadata: map[string]string{"ddns_id": profile.ID, "ok": fmt.Sprintf("%t", applyErr == nil)}})
	return applyErr
}

// tokenView is the safe projection of a token returned to clients: it never
// includes the hash or the secret.
type tokenView struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	ActorID         string    `json:"actor_id"`
	Scopes          []string  `json:"scopes"`
	ServerAllowlist []string  `json:"server_allowlist"`
	CreatedAt       time.Time `json:"created_at"`
	RevokedAt       time.Time `json:"revoked_at,omitempty"`
}

func toTokenView(t model.Token) tokenView {
	return tokenView{
		ID:              t.ID,
		Name:            t.Name,
		ActorID:         t.ActorID,
		Scopes:          t.Scopes,
		ServerAllowlist: t.ServerAllowlist,
		CreatedAt:       t.CreatedAt,
		RevokedAt:       t.RevokedAt,
	}
}

func (s *Server) handleTokens(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		tokens := s.store.Tokens()
		views := make([]tokenView, 0, len(tokens))
		for _, t := range tokens {
			views = append(views, toTokenView(t))
		}
		writeJSON(w, http.StatusOK, views)
	case http.MethodPost:
		var req struct {
			Name            string   `json:"name"`
			Scopes          []string `json:"scopes"`
			ServerAllowlist []string `json:"server_allowlist"`
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		if strings.TrimSpace(req.Name) == "" || len(req.Scopes) == 0 {
			writeError(w, http.StatusBadRequest, errors.New("name and at least one scope are required"))
			return
		}
		// Privilege containment: a caller may only mint a token whose scopes are
		// a subset of its own, so token creation cannot be used to escalate.
		for _, scope := range req.Scopes {
			if !rbac.Allows(p.Principal, scope, "") {
				writeError(w, http.StatusForbidden, fmt.Errorf("cannot grant scope %q beyond your own", scope))
				return
			}
		}
		if !serverAllowlistSubset(p.ServerAllowlist, req.ServerAllowlist) {
			writeError(w, http.StatusForbidden, errors.New("cannot grant server allowlist beyond your own"))
			return
		}
		secret, err := auth.NewRandomToken(32)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		hash, err := auth.HashSecret(secret)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		tok := model.Token{
			ID:              id.New("token"),
			Name:            req.Name,
			TokenHash:       hash,
			ActorID:         p.ActorID,
			Scopes:          req.Scopes,
			ServerAllowlist: req.ServerAllowlist,
			CreatedAt:       time.Now().UTC(),
		}
		if err := s.store.UpsertToken(tok); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "token.create", Scope: "token:admin", Metadata: map[string]string{"token_id": tok.ID}})
		// The credential is returned exactly once, in "<id>.<secret>" form.
		writeJSON(w, http.StatusOK, map[string]any{
			"id":    tok.ID,
			"token": auth.FormatToken(tok.ID, secret),
			"view":  toTokenView(tok),
		})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		TokenID string `json:"token_id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	tok, ok := s.store.Token(req.TokenID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("token not found"))
		return
	}
	if tok.RevokedAt.IsZero() {
		tok.RevokedAt = time.Now().UTC()
		if err := s.store.UpsertToken(tok); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "token.revoke", Scope: "token:admin", Metadata: map[string]string{"token_id": tok.ID}})
	writeJSON(w, http.StatusOK, toTokenView(tok))
}

func (s *Server) handleNFTPlan(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
		network.NFTPlan
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	if !s.requireNodeScope(w, p, "network:plan", req.NodeID) {
		return
	}
	planInput := req.NFTPlan
	source := "request"
	if !nftPlanRequestHasInputs(planInput) {
		source = "default"
		if stored, ok := s.store.NFTInputs(req.NodeID); ok {
			planInput = nftPlanFromStoredInputs(stored)
			source = "stored"
		}
	}
	ingressRules, err := s.composeNFTIngressPolicy(req.NodeID, &planInput, p)
	if err != nil {
		if errors.Is(err, errNFTIngressPolicyReadRequired) {
			writeError(w, http.StatusForbidden, err)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	plan, err := network.GenerateNFTPlan(planInput)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	approval := model.Approval{
		ID:        id.New("approval"),
		NodeID:    req.NodeID,
		Plugin:    "nft",
		Action:    "apply-ruleset",
		Plan:      plan,
		Status:    model.ApprovalPending,
		ActorID:   p.ActorID,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.UpsertApproval(approval); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	metadata := map[string]string{"approval_id": approval.ID, "source": source}
	if ingressRules > 0 {
		metadata["ingress_rules"] = strconv.Itoa(ingressRules)
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), NodeID: req.NodeID, Action: "network.nft.plan", Scope: "network:plan", Metadata: metadata})
	writeJSON(w, http.StatusOK, approval)
}

func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	approvals := s.store.Approvals()
	visible := make([]model.Approval, 0, len(approvals))
	for _, approval := range approvals {
		if rbac.Allows(p.Principal, "network:plan", approval.NodeID) {
			visible = append(visible, approval)
		}
	}
	writeJSON(w, http.StatusOK, toApprovalViews(visible))
}

func (s *Server) handleTunnels(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		tunnels := s.store.Tunnels()
		visible := make([]model.TunnelProfile, 0, len(tunnels))
		for _, tun := range tunnels {
			if rbac.Allows(p.Principal, "tunnel:admin", tun.NodeID) {
				visible = append(visible, tun)
			}
		}
		writeJSON(w, http.StatusOK, toTunnelViews(visible))
	case http.MethodPost:
		var req model.TunnelProfile
		if !decodeClientJSON(w, r, &req) {
			return
		}
		if strings.TrimSpace(req.Name) == "" || req.NodeID == "" || req.TunnelID == "" || len(req.Ingress) == 0 {
			writeError(w, http.StatusBadRequest, errors.New("name, node_id, tunnel_id and at least one ingress rule are required"))
			return
		}
		if !s.requireNodeScope(w, p, "tunnel:admin", req.NodeID) {
			return
		}
		req.ID = id.New("tunnel")
		// Validate the ingress by generating the config eagerly.
		if _, err := cftunnel.GenerateConfig(req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.store.UpsertTunnel(req); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), NodeID: req.NodeID, Action: "tunnel.create", Scope: "tunnel:admin", Metadata: map[string]string{"tunnel_id": req.ID}})
		writeJSON(w, http.StatusOK, req)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleDeleteTunnel(w http.ResponseWriter, r *http.Request, p principal) {
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
	nodeID := ""
	if profile, ok := s.store.Tunnel(req.ID); ok {
		nodeID = profile.NodeID
		if !s.requireNodeScope(w, p, "tunnel:admin", profile.NodeID) {
			return
		}
	}
	if err := s.store.DeleteTunnel(req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), NodeID: nodeID, Action: "tunnel.delete", Scope: "tunnel:admin", Metadata: map[string]string{"tunnel_id": req.ID}})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleTunnelPlan renders a tunnel profile to a cloudflared config.yml and
// records it as a pending approval for the bound node.
func (s *Server) handleTunnelPlan(w http.ResponseWriter, r *http.Request, p principal) {
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
	profile, ok := s.store.Tunnel(req.ID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("tunnel profile not found"))
		return
	}
	if !s.requireNodeScope(w, p, "tunnel:admin", profile.NodeID) {
		return
	}
	config, err := cftunnel.GenerateConfig(profile)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	approval := model.Approval{
		ID:        id.New("approval"),
		NodeID:    profile.NodeID,
		Plugin:    "cftunnel",
		Action:    "apply-config",
		Plan:      config,
		Status:    model.ApprovalPending,
		ActorID:   p.ActorID,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.UpsertApproval(approval); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), NodeID: profile.NodeID, Action: "tunnel.plan", Scope: "tunnel:admin", Metadata: map[string]string{"approval_id": approval.ID, "tunnel_id": profile.ID}})
	writeJSON(w, http.StatusOK, approval)
}

// handleWireGuardPlan computes a node's WireGuard mesh config from the current
// cluster state and records it as a pending approval. The node's private key is
// never involved; the plan carries a placeholder substituted at apply time.
func (s *Server) handleWireGuardPlan(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		NodeID     string `json:"node_id"`
		ListenPort int    `json:"listen_port"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	target, ok := s.store.Node(req.NodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	if !s.requireNodeScope(w, p, "network:plan", req.NodeID) {
		return
	}
	iface, peers, err := wireguard.BuildMesh(s.store.Nodes(), target, req.ListenPort)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	config, err := wireguard.GenerateConfig(iface, peers)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	approval := model.Approval{
		ID:        id.New("approval"),
		NodeID:    req.NodeID,
		Plugin:    "wireguard",
		Action:    "apply-config",
		Plan:      config,
		Status:    model.ApprovalPending,
		ActorID:   p.ActorID,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.UpsertApproval(approval); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), NodeID: req.NodeID, Action: "network.wireguard.plan", Scope: "network:plan", Metadata: map[string]string{"approval_id": approval.ID, "peers": fmt.Sprintf("%d", len(peers))}})
	writeJSON(w, http.StatusOK, approval)
}

// applyScriptFor builds the bounded shell that applies an approved plan on the
// agent, branching by plugin. The free function is kept for tests and legacy
// callers; production approval queues call the Server method so plugin scripts
// can use server configuration such as PublicURL.
func applyScriptFor(approval model.Approval) string {
	return applyScriptForWithServer(approval, "")
}

func (s *Server) applyScriptFor(approval model.Approval) string {
	if approval.Plugin == proxyCorePlugin {
		script, err := s.proxyCoreApplyScript(approval)
		if err != nil {
			return "set -e\n" +
				"echo " + shellQuote("lattice proxycore: invalid approval: "+err.Error()) + " >&2\n" +
				"exit 1\n"
		}
		return script
	}
	return applyScriptForWithServer(approval, s.publicURL)
}

func applyScriptForWithServer(approval model.Approval, serverURL string) string {
	switch approval.Plugin {
	case "cftunnel":
		return "set -e\n" +
			"mkdir -p /etc/cloudflared\n" +
			heredocWrite("/etc/cloudflared/config.yml", "LATTICE_CF_EOF", approval.Plan) +
			"cloudflared --config /etc/cloudflared/config.yml ingress validate\n" +
			"systemctl reload cloudflared 2>/dev/null || systemctl restart cloudflared 2>/dev/null || echo 'config written; start cloudflared manually'\n"
	case "wireguard":
		return "set -e\n" +
			"umask 077\n" +
			"mkdir -p /etc/wireguard\n" +
			"KEY_FILE=${LATTICE_WG_KEY:-/etc/wireguard/lattice.key}\n" +
			"if [ ! -f \"$KEY_FILE\" ]; then echo \"missing wireguard private key at $KEY_FILE\" >&2; exit 1; fi\n" +
			"PRIV=$(cat \"$KEY_FILE\")\n" +
			heredocWrite("/etc/wireguard/wg0.conf.new", "LATTICE_WG_EOF", approval.Plan) +
			"sed -i \"s|" + wireguard.PrivateKeyPlaceholder + "|$PRIV|\" /etc/wireguard/wg0.conf.new\n" +
			"mv /etc/wireguard/wg0.conf.new /etc/wireguard/wg0.conf\n" +
			"wg-quick down wg0 2>/dev/null || true\n" +
			"wg-quick up wg0\n"
	case "nftpolicy":
		payload, err := nftPolicyApprovalPayload(approval, serverURL)
		if err != nil {
			return "set -e\n" +
				"echo " + shellQuote("lattice nftpolicy: invalid approval action: "+err.Error()) + " >&2\n" +
				"exit 1\n"
		}
		return nftPolicyApplyScript(approval.Plan, payload.PublicURL, payload.DomainSets)
	case "nft":
		return nftGuardApplyScript(approval.Plan, serverURL)
	case "selfdns":
		script, err := selfdns.ApplyScriptFromPlan(approval.Plan)
		if err != nil {
			return "set -e\n" +
				"echo " + shellQuote("lattice selfdns: invalid approval plan: "+err.Error()) + " >&2\n" +
				"exit 1\n"
		}
		return script
	case proxyCorePlugin:
		return "set -e\n" +
			"echo " + shellQuote("lattice proxycore: server-backed apply context required; re-approve through /api/network/approvals/approve") + " >&2\n" +
			"exit 1\n"
	case agentUpdatePlugin:
		script, err := agentUpdateApplyScript(approval)
		if err != nil {
			return "set -e\n" +
				"echo " + shellQuote("lattice agentupdate: invalid approval payload: "+err.Error()) + " >&2\n" +
				"exit 1\n"
		}
		return script
	default:
		return heredocWrite("/tmp/lattice-nft-plan.nft", "LATTICE_NFT_EOF", approval.Plan) +
			"nft -c -f /tmp/lattice-nft-plan.nft\n"
	}
}

const (
	nftPolicyApplyAction       = "apply-ruleset"
	nftPolicyApplyActionPrefix = nftPolicyApplyAction + ":"
)

type nftPolicyDomainSetBinding struct {
	Host string `json:"host"`
	Set4 string `json:"set4"`
	Set6 string `json:"set6"`
}

type nftPolicyApplyPayload struct {
	PublicURL  string                      `json:"public_url"`
	DomainSets []nftPolicyDomainSetBinding `json:"domain_sets,omitempty"`
}

func nftPolicyApprovalAction(serverURL string, domainSets ...nftPolicyDomainSetBinding) string {
	serverURL = strings.TrimRight(serverURL, "/")
	if serverURL == "" && len(domainSets) == 0 {
		return nftPolicyApplyAction
	}
	if len(domainSets) == 0 {
		return nftPolicyApplyActionPrefix + base64.RawURLEncoding.EncodeToString([]byte(serverURL))
	}
	payload := nftPolicyApplyPayload{PublicURL: serverURL, DomainSets: normalizeNftPolicyDomainSetBindings(domainSets)}
	data, _ := json.Marshal(payload)
	return nftPolicyApplyActionPrefix + base64.RawURLEncoding.EncodeToString(data)
}

func normalizeNftPolicyDomainSetBindings(domainSets []nftPolicyDomainSetBinding) []nftPolicyDomainSetBinding {
	seen := map[string]nftPolicyDomainSetBinding{}
	for _, set := range domainSets {
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(set.Host), "."))
		set4 := strings.TrimSpace(set.Set4)
		set6 := strings.TrimSpace(set.Set6)
		if host == "" || (set4 == "" && set6 == "") {
			continue
		}
		key := host + "\x00" + set4 + "\x00" + set6
		seen[key] = nftPolicyDomainSetBinding{Host: host, Set4: set4, Set6: set6}
	}
	out := make([]nftPolicyDomainSetBinding, 0, len(seen))
	for _, set := range seen {
		out = append(out, set)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host == out[j].Host {
			return out[i].Set4 < out[j].Set4
		}
		return out[i].Host < out[j].Host
	})
	return out
}

func nftPolicyApprovalDisplayAction(action string) string {
	if action == nftPolicyApplyAction || strings.HasPrefix(action, nftPolicyApplyActionPrefix) {
		return nftPolicyApplyAction
	}
	return action
}

func nftPolicyApprovalServerURL(approval model.Approval, fallback string) (string, error) {
	payload, err := nftPolicyApprovalPayload(approval, fallback)
	if err != nil {
		return "", err
	}
	return payload.PublicURL, nil
}

func nftPolicyApprovalPayload(approval model.Approval, fallback string) (nftPolicyApplyPayload, error) {
	fallback = strings.TrimRight(fallback, "/")
	if approval.Plugin != "nftpolicy" {
		return nftPolicyApplyPayload{PublicURL: fallback}, nil
	}
	if approval.Action == nftPolicyApplyAction {
		return nftPolicyApplyPayload{PublicURL: fallback}, nil
	}
	if !strings.HasPrefix(approval.Action, nftPolicyApplyActionPrefix) {
		return nftPolicyApplyPayload{}, fmt.Errorf("unexpected action %q", approval.Action)
	}
	encoded := strings.TrimPrefix(approval.Action, nftPolicyApplyActionPrefix)
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nftPolicyApplyPayload{}, err
	}
	payload := nftPolicyApplyPayload{}
	if len(decoded) > 0 && decoded[0] == '{' {
		if err := json.Unmarshal(decoded, &payload); err != nil {
			return nftPolicyApplyPayload{}, err
		}
		payload.PublicURL = strings.TrimRight(payload.PublicURL, "/")
	} else {
		payload.PublicURL = strings.TrimRight(string(decoded), "/")
	}
	if payload.PublicURL == "" {
		payload.PublicURL = fallback
	}
	if payload.PublicURL == "" {
		return nftPolicyApplyPayload{}, errors.New("empty bound server url")
	}
	domainSets, err := validateNftPolicyDomainSetBindings(payload.DomainSets)
	if err != nil {
		return nftPolicyApplyPayload{}, err
	}
	payload.DomainSets = domainSets
	return payload, nil
}

func validateNftPolicyDomainSetBindings(domainSets []nftPolicyDomainSetBinding) ([]nftPolicyDomainSetBinding, error) {
	out := make([]nftPolicyDomainSetBinding, 0, len(domainSets))
	for _, set := range normalizeNftPolicyDomainSetBindings(domainSets) {
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(set.Host), "."))
		if host == "" || len(host) > 253 || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
			return nil, fmt.Errorf("invalid domain set host %q", set.Host)
		}
		if _, err := normalizeControlPlaneHost(host); err != nil {
			return nil, err
		}
		if set.Set4 == "" && set.Set6 == "" {
			return nil, fmt.Errorf("domain set %q has no nft set", host)
		}
		if set.Set4 != "" && !nftPolicySetNameRe.MatchString(set.Set4) {
			return nil, fmt.Errorf("invalid nft set %q", set.Set4)
		}
		if set.Set6 != "" && !nftPolicySetNameRe.MatchString(set.Set6) {
			return nil, fmt.Errorf("invalid nft set %q", set.Set6)
		}
		out = append(out, nftPolicyDomainSetBinding{Host: host, Set4: set.Set4, Set6: set.Set6})
	}
	return out, nil
}

func nftGuardApplyScript(plan, serverURL string) string {
	serverURL = strings.TrimRight(serverURL, "/")
	selfcheck := "echo 'lattice nft: control-plane selfcheck skipped because public_url is unset' >&2\n"
	done := "echo 'lattice nft: applied; control-plane selfcheck skipped'\n"
	if serverURL != "" {
		selfcheck = "AGENT_BIN=${LATTICE_AGENT_BIN:-lattice-agent}\n" +
			"\"$AGENT_BIN\" --selfcheck-controlplane -server " + shellQuote(serverURL) + "\n"
		done = "echo 'lattice nft: applied and verified'\n"
	}
	return "set -e\n" +
		"umask 077\n" +
		"mkdir -p /etc/lattice\n" +
		"CANDIDATE=/etc/lattice/guard.nft.new\n" +
		"ACTIVE=/etc/lattice/guard.nft\n" +
		"ROLLBACK=/etc/lattice/guard.rollback.nft\n" +
		"WATCHDOG=\n" +
		heredocWrite("$CANDIDATE", "LATTICE_NFT_GUARD_EOF", plan) +
		"nft -c -f \"$CANDIDATE\"\n" +
		"nft list ruleset > \"$ROLLBACK\"\n" +
		"cleanup_watchdog() {\n" +
		"  if [ -n \"$WATCHDOG\" ]; then\n" +
		"    kill \"$WATCHDOG\" 2>/dev/null || true\n" +
		"    wait \"$WATCHDOG\" 2>/dev/null || true\n" +
		"  fi\n" +
		"}\n" +
		"rollback() {\n" +
		"  echo 'lattice nft: rolling back guard ruleset' >&2\n" +
		"  nft -f \"$ROLLBACK\" 2>/dev/null || true\n" +
		"}\n" +
		"trap 'rollback; cleanup_watchdog' ERR\n" +
		"( sleep 60; echo 'lattice nft: watchdog rollback fired' >&2; rollback ) &\n" +
		"WATCHDOG=$!\n" +
		"nft -f \"$CANDIDATE\"\n" +
		selfcheck +
		"trap - ERR\n" +
		"cleanup_watchdog\n" +
		"mv \"$CANDIDATE\" \"$ACTIVE\"\n" +
		done
}

func nftPolicyApplyScript(plan, serverURL string, domainSets []nftPolicyDomainSetBinding) string {
	serverURL = strings.TrimRight(serverURL, "/")
	domainRefresh := nftPolicyDomainRefreshCleanupScript()
	domainSetUpdate := nftPolicyDomainSetUpdateScripts(domainSets)
	if host, ok := controlPlaneDomainSetHost(serverURL); ok {
		domainSetUpdate = nftPolicyDomainSetUpdateScript(nftPolicyDomainSetBinding{Host: host, Set4: "lattice_control4", Set6: "lattice_control6"}) + domainSetUpdate
	}
	if domainSetUpdate != "" {
		domainRefresh = nftPolicyDomainRefreshInstallScript(domainSetUpdate)
	}
	return "set -e\n" +
		"umask 077\n" +
		"mkdir -p /etc/lattice\n" +
		"CANDIDATE=/etc/lattice/policy.nft.new\n" +
		"ACTIVE=/etc/lattice/policy.nft\n" +
		"ROLLBACK=/etc/lattice/policy.rollback.nft\n" +
		"WATCHDOG=\n" +
		heredocWrite("$CANDIDATE", "LATTICE_NFT_POLICY_EOF", plan) +
		"nft -c -f \"$CANDIDATE\"\n" +
		"nft list ruleset > \"$ROLLBACK\"\n" +
		"cleanup_watchdog() {\n" +
		"  if [ -n \"$WATCHDOG\" ]; then\n" +
		"    kill \"$WATCHDOG\" 2>/dev/null || true\n" +
		"    wait \"$WATCHDOG\" 2>/dev/null || true\n" +
		"  fi\n" +
		"}\n" +
		"rollback() {\n" +
		"  echo 'lattice nftpolicy: rolling back ruleset' >&2\n" +
		"  nft -f \"$ROLLBACK\" 2>/dev/null || true\n" +
		"}\n" +
		"trap 'rollback; cleanup_watchdog' ERR\n" +
		"( sleep 60; echo 'lattice nftpolicy: watchdog rollback fired' >&2; rollback ) &\n" +
		"WATCHDOG=$!\n" +
		"nft -f \"$CANDIDATE\"\n" +
		"AGENT_BIN=${LATTICE_AGENT_BIN:-lattice-agent}\n" +
		domainSetUpdate +
		"\"$AGENT_BIN\" --selfcheck-controlplane -server " + shellQuote(serverURL) + "\n" +
		domainRefresh +
		"trap - ERR\n" +
		"cleanup_watchdog\n" +
		"mv \"$CANDIDATE\" \"$ACTIVE\"\n" +
		"echo 'lattice nftpolicy: applied and verified'\n"
}

func controlPlaneDomainSetHost(serverURL string) (string, bool) {
	u, err := url.Parse(strings.TrimRight(serverURL, "/"))
	if err != nil || u.Hostname() == "" {
		return "", false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is4() {
		return "", false
	}
	host, err = normalizeControlPlaneHost(host)
	if err != nil {
		return "", false
	}
	return host, true
}

func nftPolicyDomainSetUpdateScripts(domainSets []nftPolicyDomainSetBinding) string {
	var b strings.Builder
	for _, set := range domainSets {
		b.WriteString(nftPolicyDomainSetUpdateScript(set))
	}
	return b.String()
}

func nftPolicyDomainSetUpdateScript(set nftPolicyDomainSetBinding) string {
	cmd := "\"$AGENT_BIN\" --update-nft-domain-set -host " + shellQuote(set.Host) + " -family inet -table lattice_policy"
	if set.Set4 != "" {
		cmd += " -set " + set.Set4
	}
	if set.Set6 != "" {
		cmd += " -set6 " + set.Set6
	}
	return cmd + "\n"
}

func nftPolicyDomainRefreshInstallScript(updateCommands string) string {
	const (
		refreshScript = "/etc/lattice/nftpolicy-domain-refresh.sh"
		servicePath   = "/etc/systemd/system/lattice-nftpolicy-domain-refresh.service"
		timerPath     = "/etc/systemd/system/lattice-nftpolicy-domain-refresh.timer"
		cronPath      = "/etc/cron.d/lattice-nftpolicy-domain-refresh"
		systemdCheck  = "command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]"
	)
	script := "#!/bin/sh\n" +
		"set -e\n" +
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n" +
		"AGENT_BIN=${LATTICE_AGENT_BIN:-lattice-agent}\n" +
		updateCommands
	service := "[Unit]\n" +
		"Description=Lattice nftpolicy domain set refresh\n" +
		"Documentation=https://github.com/LatticeNet/lattice\n\n" +
		"[Service]\n" +
		"Type=oneshot\n" +
		"ExecStart=" + refreshScript + "\n"
	timer := "[Unit]\n" +
		"Description=Run Lattice nftpolicy domain set refresh\n\n" +
		"[Timer]\n" +
		"OnBootSec=30s\n" +
		"OnUnitActiveSec=60s\n" +
		"AccuracySec=10s\n" +
		"Persistent=true\n" +
		"Unit=lattice-nftpolicy-domain-refresh.service\n\n" +
		"[Install]\n" +
		"WantedBy=timers.target\n"
	cron := "SHELL=/bin/sh\n" +
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n" +
		"* * * * * root " + refreshScript + " >/dev/null 2>&1\n"
	return "if " + systemdCheck + "; then\n" +
		"  systemctl disable --now lattice-nftpolicy-domain-refresh.timer 2>/dev/null || true\n" +
		"  rm -f " + shellQuote(cronPath) + "\n" +
		"fi\n" +
		heredocWrite(refreshScript, "LATTICE_NFT_DOMAIN_REFRESH_EOF", script) +
		"chmod 0700 " + shellQuote(refreshScript) + "\n" +
		"if " + systemdCheck + "; then\n" +
		heredocWrite(servicePath, "LATTICE_NFT_DOMAIN_REFRESH_SERVICE_EOF", service) +
		heredocWrite(timerPath, "LATTICE_NFT_DOMAIN_REFRESH_TIMER_EOF", timer) +
		"  chmod 0644 " + shellQuote(servicePath) + " " + shellQuote(timerPath) + "\n" +
		"  systemctl daemon-reload\n" +
		"  systemctl enable --now lattice-nftpolicy-domain-refresh.timer\n" +
		"  echo 'lattice nftpolicy: periodic domain refresh timer installed'\n" +
		"else\n" +
		"  rm -f " + shellQuote(servicePath) + " " + shellQuote(timerPath) + "\n" +
		"  if [ -d /etc/cron.d ]; then\n" +
		heredocWrite(cronPath, "LATTICE_NFT_DOMAIN_REFRESH_CRON_EOF", cron) +
		"    chmod 0644 " + shellQuote(cronPath) + "\n" +
		"    echo 'lattice nftpolicy: periodic domain refresh cron installed'\n" +
		"  else\n" +
		"    rm -f " + shellQuote(cronPath) + "\n" +
		"    echo 'lattice nftpolicy: no systemd runtime or /etc/cron.d; periodic domain refresh scheduler skipped' >&2\n" +
		"  fi\n" +
		"fi\n"
}

func nftPolicyDomainRefreshCleanupScript() string {
	const (
		cronPath     = "/etc/cron.d/lattice-nftpolicy-domain-refresh"
		systemdCheck = "command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]"
	)
	return "if " + systemdCheck + "; then\n" +
		"  systemctl disable --now lattice-nftpolicy-domain-refresh.timer 2>/dev/null || true\n" +
		"fi\n" +
		"rm -f /etc/systemd/system/lattice-nftpolicy-domain-refresh.service /etc/systemd/system/lattice-nftpolicy-domain-refresh.timer " + shellQuote(cronPath) + "\n" +
		"if " + systemdCheck + "; then\n" +
		"  systemctl daemon-reload 2>/dev/null || true\n" +
		"fi\n" +
		"rm -f /etc/lattice/nftpolicy-domain-refresh.sh\n"
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func heredocWrite(dst, prefix, content string) string {
	delimiter := heredocDelimiter(prefix, content)
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return fmt.Sprintf("cat > %s <<'%s'\n%s%s\n", dst, delimiter, content, delimiter)
}

func heredocDelimiter(prefix, content string) string {
	sum := sha256.Sum256([]byte(prefix + "\x00" + content))
	base := prefix + "_" + hex.EncodeToString(sum[:])[:24]
	delimiter := base
	for i := 0; containsHeredocLine(content, delimiter); i++ {
		delimiter = fmt.Sprintf("%s_%d", base, i)
	}
	return delimiter
}

func containsHeredocLine(content, delimiter string) bool {
	normalized := strings.ReplaceAll(content, "\r\n", "\n")
	for _, line := range strings.Split(normalized, "\n") {
		if line == delimiter {
			return true
		}
	}
	return false
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		ApprovalID string `json:"approval_id"`
		QueueApply bool   `json:"queue_apply"`
		// PlanSHA256 binds high-risk pending approvals to the exact plan the
		// reviewer saw. It must match the stored plan's hash, so a plan that
		// changed between review and approval is rejected (TOCTOU / plan-swap
		// defense). The client computes it over the Plan text it received from
		// /api/network/approvals.
		PlanSHA256 string `json:"plan_sha256,omitempty"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.PlanSHA256 = strings.TrimSpace(req.PlanSHA256)
	approval, ok := s.store.Approval(req.ApprovalID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("approval not found"))
		return
	}
	if !s.requireNodeScope(w, p, "network:apply", approval.NodeID) {
		return
	}
	if approval.Status != model.ApprovalPending {
		writeJSON(w, http.StatusOK, toApprovalView(approval))
		return
	}
	if approvalRequiresPlanHash(approval) && req.PlanSHA256 == "" {
		writeError(w, http.StatusBadRequest, apiError(model.APIErrorBadRequest, "plan_sha256 is required for this approval"))
		return
	}
	if req.PlanSHA256 != "" {
		sum := sha256.Sum256([]byte(approval.Plan))
		if !strings.EqualFold(req.PlanSHA256, hex.EncodeToString(sum[:])) {
			writeError(w, http.StatusConflict, apiError(model.APIErrorBadRequest, "plan changed since review; re-review before approving"))
			return
		}
	}
	if approval.Plugin == "nftpolicy" {
		if err := s.requireCurrentNetPolicyApproval(approval); err != nil {
			writeError(w, http.StatusConflict, apiError(model.APIErrorBadRequest, err.Error()))
			return
		}
	}
	if approval.Plugin == proxyCorePlugin {
		if err := s.requireCurrentProxyCoreApproval(approval); err != nil {
			writeError(w, http.StatusConflict, apiError(model.APIErrorBadRequest, err.Error()))
			return
		}
	}
	if approval.Plugin == agentUpdatePlugin {
		if err := s.requireCurrentAgentUpdateApproval(approval); err != nil {
			writeError(w, http.StatusConflict, apiError(model.APIErrorBadRequest, err.Error()))
			return
		}
	}
	applyScript := ""
	if req.QueueApply {
		switch approval.Plugin {
		case "selfdns":
			var err error
			applyScript, err = selfdns.ApplyScriptFromPlan(approval.Plan)
			if err != nil {
				writeError(w, http.StatusConflict, apiError(model.APIErrorBadRequest, "selfdns plan is no longer applyable; re-plan before approving"))
				return
			}
			if err := s.requireSelfDNSDeploymentForApproval(approval); err != nil {
				writeError(w, http.StatusConflict, apiError(model.APIErrorBadRequest, err.Error()))
				return
			}
		case proxyCorePlugin:
			var err error
			applyScript, err = s.proxyCoreApplyScript(approval)
			if err != nil {
				writeError(w, http.StatusConflict, apiError(model.APIErrorBadRequest, err.Error()))
				return
			}
		case agentUpdatePlugin:
			var err error
			applyScript, err = agentUpdateApplyScript(approval)
			if err != nil {
				writeError(w, http.StatusConflict, apiError(model.APIErrorBadRequest, err.Error()))
				return
			}
		default:
			applyScript = s.applyScriptFor(approval)
		}
	}
	approval.Status = model.ApprovalApproved
	approval.ApprovedBy = p.ActorID
	if err := s.store.UpsertApproval(approval); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if req.QueueApply {
		timeoutSec := 30
		if approval.Plugin == agentUpdatePlugin {
			timeoutSec = 300
		}
		task := model.Task{
			ID:          id.New("task"),
			ApprovalID:  approval.ID,
			ActorID:     p.ActorID,
			TokenID:     p.TokenID,
			Targets:     []string{approval.NodeID},
			Interpreter: "sh",
			Script:      applyScript,
			TimeoutSec:  timeoutSec,
			OutputLimit: 65536,
			Status:      model.TaskQueued,
			CreatedAt:   time.Now().UTC(),
		}
		if err := s.store.CreateTask(task); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if approval.Plugin == "selfdns" {
			if err := s.markSelfDNSApplying(approval); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
		}
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), NodeID: approval.NodeID, Action: "network." + approval.Plugin + ".approve", Scope: "network:apply", Metadata: map[string]string{"approval_id": approval.ID}})
	writeJSON(w, http.StatusOK, toApprovalView(approval))
}

func approvalRequiresPlanHash(approval model.Approval) bool {
	switch approval.Plugin {
	case "nft", "nftpolicy", "wireguard", "cftunnel", "selfdns", "proxycore", "agentupdate":
		return true
	default:
		// Approvals are the host-mutation gate. Unknown future plugins carrying a
		// reviewable plan should fail closed until they make an explicit choice.
		return strings.TrimSpace(approval.Plan) != ""
	}
}

func (s *Server) requireCurrentNetPolicyApproval(approval model.Approval) error {
	policy, ok := s.store.NetPolicy(approval.NodeID)
	if !ok {
		return fmt.Errorf("netpolicy %q not found; re-plan before approving", approval.NodeID)
	}
	planSHA := approvalPlanSHA(approval)
	if policy.LastPlanSHA == "" || !strings.EqualFold(policy.LastPlanSHA, planSHA) {
		return errors.New("netpolicy changed since this plan was created; re-plan before approving")
	}
	return nil
}

func approvalPlanSHA(approval model.Approval) string {
	sum := sha256.Sum256([]byte(approval.Plan))
	return hex.EncodeToString(sum[:])
}

func (s *Server) handleAgentHello(w http.ResponseWriter, r *http.Request) {
	var req agentAuthRequest
	if !decodeAgentJSON(w, r, &req) {
		return
	}
	n, ok := s.authenticateAgentRequest(r, req.NodeID)
	if !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	if err := validateAgentNetworkMetadata(req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	oldV4, oldV6 := n.PublicIP, n.PublicIPv6
	v4, v6 := s.resolvePublicIPs(r, req.PublicIP, req.PublicIPv6)
	n.AgentVersion = req.Version
	n.PublicIP = v4
	n.PublicIPv6 = v6
	n.WireGuardIP = req.WireGuardIP
	if req.WGPublicKey != "" {
		n.WireGuardPublicKey = req.WGPublicKey
	}
	if req.WGEndpoint != "" {
		n.WireGuardEndpoint = req.WGEndpoint
	}
	if req.WGPort != 0 {
		n.WireGuardPort = req.WGPort
	}
	if hostFacts, ok := normalizeHostFacts(req.HostFacts, s.now()); ok {
		n.HostFacts = hostFacts
	}
	n.LastSeen = time.Now().UTC()
	n.Online = true
	if err := s.store.UpsertNode(n); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.maybeTriggerDDNS(req.NodeID, oldV4, oldV6, v4, v6)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAgentMetrics(w http.ResponseWriter, r *http.Request) {
	var req struct {
		agentAuthRequest
		Metrics model.Metrics `json:"metrics"`
	}
	if !decodeAgentJSON(w, r, &req) {
		return
	}
	old, ok := s.authenticateAgentRequest(r, req.NodeID)
	if !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	if err := validateAgentNetworkMetadata(req.agentAuthRequest); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	v4, v6 := s.resolvePublicIPs(r, req.PublicIP, req.PublicIPv6)
	hostFacts, _ := normalizeHostFacts(req.HostFacts, s.now())
	if err := s.store.UpdateMetrics(req.NodeID, req.Metrics, req.Version, v4, v6, req.WireGuardIP, hostFacts); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.maybeTriggerDDNS(req.NodeID, old.PublicIP, old.PublicIPv6, v4, v6)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAgentTasks(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	// Token must arrive in the Authorization header only. Accepting it from the
	// query string would leak the credential into access logs and proxy caches.
	token := bearerToken(r)
	if _, ok := s.authenticateNode(nodeID, token); !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	tasks, err := s.store.LeaseTasks(nodeID, 3)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	views := make([]agentTaskView, 0, len(tasks))
	for _, task := range tasks {
		views = append(views, toAgentTaskView(task))
	}
	writeJSON(w, http.StatusOK, views)
}

type agentTaskView struct {
	ID          string `json:"id"`
	LeaseID     string `json:"lease_id"`
	Interpreter string `json:"interpreter"`
	Script      string `json:"script"`
	TimeoutSec  int    `json:"timeout_sec"`
	OutputLimit int    `json:"output_limit"`
}

func toAgentTaskView(t model.Task) agentTaskView {
	return agentTaskView{
		ID:          t.ID,
		LeaseID:     t.LeaseID,
		Interpreter: t.Interpreter,
		Script:      t.Script,
		TimeoutSec:  t.TimeoutSec,
		OutputLimit: t.OutputLimit,
	}
}

func (s *Server) handleAgentTaskResult(w http.ResponseWriter, r *http.Request) {
	var req struct {
		agentAuthRequest
		Result model.TaskResult `json:"result"`
	}
	if !decodeAgentJSON(w, r, &req) {
		return
	}
	if _, ok := s.authenticateAgentRequest(r, req.NodeID); !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	req.Result.NodeID = req.NodeID
	if !s.requireTaskLease(w, r, req.NodeID, req.Result) {
		return
	}
	if err := s.validateTaskResultOutput(req.Result); err != nil {
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   req.NodeID,
			Action:   "task.result",
			Decision: "deny",
			Reason:   "task output limit exceeded",
			Metadata: map[string]string{"task_id": req.Result.TaskID},
		})
		writeError(w, http.StatusBadRequest, err)
		return
	}
	task, ok := s.store.Task(req.Result.TaskID)
	if !ok {
		writeError(w, http.StatusForbidden, apiError(model.APIErrorInvalidTaskLease, "invalid task lease"))
		return
	}
	if req.Result.FinishedAt.IsZero() {
		req.Result.FinishedAt = time.Now().UTC()
	}
	req.Result.LeaseID = ""
	if err := s.store.AddTaskResult(req.Result); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.handleApprovalTaskResult(r, task, req.Result); err != nil {
		s.logger.Printf("approval task result update failed: %v", err)
	}
	s.recordRequestAudit(r, model.AuditEvent{ID: id.New("audit"), NodeID: req.NodeID, Action: "task.result", Decision: "allow", Metadata: map[string]string{"task_id": req.Result.TaskID}})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleApprovalTaskResult(r *http.Request, task model.Task, result model.TaskResult) error {
	if task.ApprovalID == "" {
		return nil
	}
	approval, ok := s.store.Approval(task.ApprovalID)
	if !ok {
		return nil
	}
	if approval.Plugin == "selfdns" {
		return s.handleSelfDNSTaskResult(r, approval, task, result)
	}
	if approval.Plugin == proxyCorePlugin {
		return s.handleProxyCoreTaskResult(r, approval, task, result)
	}
	if approval.Plugin == agentUpdatePlugin {
		return s.handleAgentUpdateTaskResult(r, approval, result)
	}
	if approval.Plugin != "nftpolicy" {
		return nil
	}
	policy, ok := s.store.NetPolicy(approval.NodeID)
	if !ok {
		return fmt.Errorf("netpolicy %q not found for approval %s", approval.NodeID, approval.ID)
	}
	planSHA := approvalPlanSHA(approval)
	metadata := map[string]string{
		"approval_id": approval.ID,
		"task_id":     task.ID,
		"plan_sha":    planSHA,
	}
	if policy.LastPlanSHA == "" || !strings.EqualFold(policy.LastPlanSHA, planSHA) {
		reason := "task result belongs to a stale netpolicy plan; re-plan before applying current policy"
		policy.LastError = reason
		if err := s.store.UpsertNetPolicy(policy); err != nil {
			return fmt.Errorf("mark stale netpolicy result: %w", err)
		}
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   approval.NodeID,
			Action:   "network.policy.failed",
			Decision: "deny",
			Reason:   reason,
			Metadata: metadata,
		})
		return nil
	}
	if result.Error == "" && result.ExitCode == 0 {
		if result.FinishedAt.IsZero() {
			result.FinishedAt = time.Now().UTC()
		}
		policy.LastAppliedAt = result.FinishedAt
		policy.LastError = ""
		approval.Status = model.ApprovalApplied
		approval.UpdatedAt = time.Now().UTC()
		if err := s.store.UpsertApproval(approval); err != nil {
			return fmt.Errorf("mark approval applied: %w", err)
		}
		if err := s.store.UpsertNetPolicy(policy); err != nil {
			return fmt.Errorf("mark netpolicy applied: %w", err)
		}
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   approval.NodeID,
			Action:   "network.policy.applied",
			Decision: "allow",
			Metadata: metadata,
		})
		return nil
	}
	reason := taskFailureSummary(result)
	policy.LastError = reason
	if err := s.store.UpsertNetPolicy(policy); err != nil {
		return fmt.Errorf("mark netpolicy failed: %w", err)
	}
	s.recordRequestAudit(r, model.AuditEvent{
		ID:       id.New("audit"),
		NodeID:   approval.NodeID,
		Action:   "network.policy.failed",
		Decision: "deny",
		Reason:   reason,
		Metadata: metadata,
	})
	return nil
}

func taskFailureSummary(result model.TaskResult) string {
	switch {
	case strings.TrimSpace(result.Error) != "":
		return truncateMetadataValue(result.Error, 240)
	case strings.TrimSpace(result.Stderr) != "":
		return truncateMetadataValue(result.Stderr, 240)
	case result.ExitCode != 0:
		return fmt.Sprintf("task exited with code %d", result.ExitCode)
	default:
		return "task failed"
	}
}

func truncateMetadataValue(value string, max int) string {
	value = strings.TrimSpace(value)
	if max <= 0 {
		return value
	}
	runes := []rune(value)
	if len(runes) <= max {
		return value
	}
	return string(runes[:max]) + "..."
}

func (s *Server) requireTaskLease(w http.ResponseWriter, r *http.Request, nodeID string, result model.TaskResult) bool {
	task, ok := s.store.Task(result.TaskID)
	if !ok {
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   nodeID,
			Action:   "task.result",
			Decision: "deny",
			Reason:   "invalid task lease",
			Metadata: map[string]string{"task_id": result.TaskID},
		})
		writeError(w, http.StatusForbidden, apiError(model.APIErrorInvalidTaskLease, "invalid task lease"))
		return false
	}
	if task.Status != model.TaskLeased || task.LeasedBy != nodeID ||
		task.LeaseID == "" || result.LeaseID == "" || task.LeaseID != result.LeaseID {
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   nodeID,
			Action:   "task.result",
			Decision: "deny",
			Reason:   "invalid task lease",
			Metadata: map[string]string{"task_id": result.TaskID},
		})
		writeError(w, http.StatusForbidden, apiError(model.APIErrorInvalidTaskLease, "invalid task lease"))
		return false
	}
	return true
}

func (s *Server) validateTaskResultOutput(result model.TaskResult) error {
	task, ok := s.store.Task(result.TaskID)
	if !ok {
		return errors.New("task not found")
	}
	limit := task.OutputLimit
	if limit <= 0 {
		limit = defaultTaskOutputLimit
	}
	if limit > maxTaskOutputLimit {
		limit = maxTaskOutputLimit
	}
	for field, value := range map[string]string{
		"stdout": result.Stdout,
		"stderr": result.Stderr,
		"error":  result.Error,
	} {
		if len([]byte(value)) > limit {
			return apiErrorf(model.APIErrorTaskOutputLimitExceeded, "%s exceeds task output limit", field)
		}
	}
	return nil
}

type agentAuthRequest struct {
	NodeID      string          `json:"node_id"`
	Version     string          `json:"version"`
	PublicIP    string          `json:"public_ip"`
	PublicIPv6  string          `json:"public_ipv6"`
	WireGuardIP string          `json:"wireguard_ip"`
	WGPublicKey string          `json:"wireguard_public_key"`
	WGEndpoint  string          `json:"wireguard_endpoint"`
	WGPort      int             `json:"wireguard_port"`
	HostFacts   model.HostFacts `json:"host_facts"`
}

var blockedReportedPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func validateAgentNetworkMetadata(req agentAuthRequest) error {
	if err := validateReportedPublicIP(req.PublicIP, true, "public_ip"); err != nil {
		return err
	}
	if err := validateReportedPublicIP(req.PublicIPv6, false, "public_ipv6"); err != nil {
		return err
	}
	if err := validateWireGuardIP(req.WireGuardIP); err != nil {
		return err
	}
	if req.WGPublicKey != "" && !wireguard.ValidatePublicKey(req.WGPublicKey) {
		return errors.New("invalid wireguard_public_key")
	}
	if err := wireguard.ValidateEndpoint(req.WGEndpoint); err != nil {
		return err
	}
	if req.WGPort < 0 || req.WGPort > 65535 {
		return fmt.Errorf("invalid wireguard_port %d", req.WGPort)
	}
	return nil
}

const (
	maxHostFactShort = 96
	maxHostFactLong  = 192
	maxHostCPUCores  = 4096
	maxHostMemory    = uint64(16) << 50 // 16 PiB: reject obviously corrupt node-reported facts.
)

func normalizeHostFacts(in model.HostFacts, now time.Time) (model.HostFacts, bool) {
	if hostFactsEmpty(in) {
		return model.HostFacts{}, false
	}
	out := model.HostFacts{
		Hostname:        clampPrintable(in.Hostname, maxHostFactShort),
		OS:              clampPrintable(in.OS, maxHostFactShort),
		Platform:        clampPrintable(in.Platform, maxHostFactShort),
		PlatformVersion: clampPrintable(in.PlatformVersion, maxHostFactShort),
		KernelVersion:   clampPrintable(in.KernelVersion, maxHostFactShort),
		Arch:            clampPrintable(in.Arch, maxHostFactShort),
		CPUModel:        clampPrintable(in.CPUModel, maxHostFactLong),
		Virtualization:  clampPrintable(in.Virtualization, maxHostFactShort),
	}
	if in.CPUCores > 0 && in.CPUCores <= maxHostCPUCores {
		out.CPUCores = in.CPUCores
	}
	if in.MemoryTotal <= maxHostMemory {
		out.MemoryTotal = in.MemoryTotal
	}
	if in.SwapTotal <= maxHostMemory {
		out.SwapTotal = in.SwapTotal
	}
	if !in.BootTime.IsZero() && !in.BootTime.After(now.Add(5*time.Minute)) {
		out.BootTime = in.BootTime.UTC()
	}
	// Server receipt time wins over the node clock for freshness display.
	out.ReportedAt = now.UTC()
	return out, true
}

func hostFactsEmpty(f model.HostFacts) bool {
	return f.Hostname == "" && f.OS == "" && f.Platform == "" &&
		f.PlatformVersion == "" && f.KernelVersion == "" && f.Arch == "" &&
		f.CPUCores == 0 && f.CPUModel == "" && f.MemoryTotal == 0 &&
		f.SwapTotal == 0 && f.Virtualization == "" && f.BootTime.IsZero() &&
		f.ReportedAt.IsZero()
}

func clampPrintable(value string, max int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if b.Len()+len(string(r)) > max {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

func validateReportedPublicIP(value string, wantIPv4 bool, field string) error {
	if value == "" {
		return nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", field, err)
	}
	if wantIPv4 && !addr.Is4() {
		return fmt.Errorf("%s must be IPv4", field)
	}
	if !wantIPv4 && !addr.Is6() {
		return fmt.Errorf("%s must be IPv6", field)
	}
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return fmt.Errorf("%s is not a routable public address", field)
	}
	for _, prefix := range blockedReportedPublicPrefixes {
		if prefix.Contains(addr) {
			return fmt.Errorf("%s is reserved for special use", field)
		}
	}
	return nil
}

func validateWireGuardIP(value string) error {
	if value == "" {
		return nil
	}
	if strings.ContainsAny(value, " \t\n\r") {
		return errors.New("invalid wireguard_ip")
	}
	if strings.Contains(value, "/") {
		if _, _, err := net.ParseCIDR(value); err != nil {
			return fmt.Errorf("invalid wireguard_ip: %w", err)
		}
		return nil
	}
	if net.ParseIP(value) == nil {
		return errors.New("invalid wireguard_ip")
	}
	return nil
}

func (s *Server) authenticateNode(nodeID, token string) (model.Node, bool) {
	if nodeID == "" || token == "" {
		return model.Node{}, false
	}
	n, ok := s.store.Node(nodeID)
	if !ok {
		return model.Node{}, false
	}
	if n.Disabled {
		return model.Node{}, false
	}
	return n, auth.VerifySecret(n.TokenHash, token)
}

func (s *Server) authenticateAgentRequest(r *http.Request, nodeID string) (model.Node, bool) {
	// Agent credentials are accepted only from Authorization. JSON body tokens
	// are easy to leak through logs, traces, and failed request captures.
	return s.authenticateNode(nodeID, bearerToken(r))
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'")
		// HSTS is only meaningful (and only safe) over HTTPS, which we proxy
		// for via secure cookies being enabled.
		if s.secureCookies {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := w.Header().Get(requestIDHeader)
		if requestID == "" {
			requestID = id.New("req")
			w.Header().Set(requestIDHeader, requestID)
		}
		r = r.WithContext(context.WithValue(r.Context(), requestIDContextKey{}, requestID))
		next.ServeHTTP(w, r)
	})
}

func requestIDFromRequest(r *http.Request) string {
	requestID, _ := r.Context().Value(requestIDContextKey{}).(string)
	return requestID
}

// logResponseWriter records the status code and byte count of a response so the
// request-logging middleware can report them. It forwards Flush so streaming
// handlers keep working.
type logResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
	wrote  bool
}

func (w *logResponseWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status = code
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *logResponseWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status = http.StatusOK
		w.wrote = true
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (w *logResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack forwards to the underlying ResponseWriter so WebSocket upgrades (the
// terminal stream/attach routes) keep working. Without it this logging wrapper
// would mask the connection's http.Hijacker and every upgrade would fail.
func (w *logResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response does not support hijacking")
	}
	return hj.Hijack()
}

// withRequestLog logs HTTP requests with method, path, status, response size,
// latency, client IP, and request id. It is quiet by default: only requests
// slower than the threshold (or 5xx) are logged, so it is safe to leave enabled
// in production. Tunables (read at startup):
//
//	LATTICE_ACCESS_LOG=1            log every request (verbose)
//	LATTICE_SLOW_REQUEST_MS=<n>     slow-request threshold in ms (default 1000)
func (s *Server) withRequestLog(next http.Handler) http.Handler {
	logAll := os.Getenv("LATTICE_ACCESS_LOG") == "1"
	slowMS := 1000
	if v := strings.TrimSpace(os.Getenv("LATTICE_SLOW_REQUEST_MS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			slowMS = n
		}
	}
	slow := time.Duration(slowMS) * time.Millisecond
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &logResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(lw, r)
		dur := time.Since(start)
		if !logAll && dur < slow && lw.status < 500 {
			return
		}
		tag := "request"
		if dur >= slow {
			tag = "SLOW request"
		}
		s.logger.Printf("%s: %s %s -> %d %dB %s (ip=%s id=%s)",
			tag, r.Method, r.URL.Path, lw.status, lw.bytes,
			dur.Round(time.Millisecond), s.clientIP(r), requestIDFromRequest(r))
	})
}

// recordAudit writes an audit event and, unlike a bare best-effort call, logs
// when the sink fails so audit gaps are visible instead of silent.
func (s *Server) recordAudit(ev model.AuditEvent) {
	if err := audit.Record(s.store, ev); err != nil {
		s.logger.Printf("audit: failed to record %q: %v", ev.Action, err)
	}
}

func (s *Server) recordPrincipalAudit(p principal, ev model.AuditEvent) {
	if ev.ActorID == "" {
		ev.ActorID = p.ActorID
	}
	if ev.TokenID == "" {
		ev.TokenID = p.TokenID
	}
	if ev.CorrelationID == "" {
		ev.CorrelationID = p.CorrelationID
	}
	s.recordAudit(ev)
}

func (s *Server) recordRequestAudit(r *http.Request, ev model.AuditEvent) {
	if ev.CorrelationID == "" {
		ev.CorrelationID = requestIDFromRequest(r)
	}
	s.recordAudit(ev)
}

// clientIP resolves the address used as a rate-limit key. Proxy headers are
// only honored when TrustProxy is set, preventing key spoofing in the direct
// exposure case.
func (s *Server) clientIP(r *http.Request) string {
	if s.trustProxy {
		if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
			return cf
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if comma := strings.IndexByte(xff, ','); comma >= 0 {
				xff = xff[:comma]
			}
			if xff = strings.TrimSpace(xff); xff != "" {
				return xff
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func unsafeMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	}
	return ""
}

// errInvalidBody is the generic client-facing 400 for malformed request bodies.
// Raw encoding/json decoder strings are not echoed to the caller (they leak
// internal type/field detail); the request id still allows server-side
// correlation.
func errInvalidBody() error {
	return apiError(model.APIErrorBadRequest, "invalid request body")
}

const defaultJSONBodyLimit = 1 << 20

// decodeClientJSON is the default for dashboard/operator/public API request
// bodies. It rejects unknown fields and trailing JSON values, uses a fixed body
// cap, and returns only a generic error to callers. Agent ingestion uses
// decodeAgentJSON instead because agents must remain forward-compatible with a
// newer agent sending fields an older server does not yet understand. [C9/C10]
func decodeClientJSON(w http.ResponseWriter, r *http.Request, dest any) bool {
	return decodeJSONBody(w, r, dest, defaultJSONBodyLimit, true)
}

// decodeAgentJSON is deliberately forward-compatible: unknown fields are
// tolerated so a new agent can talk to an older server. It still enforces the
// same body cap and rejects malformed/trailing values.
func decodeAgentJSON(w http.ResponseWriter, r *http.Request, dest any) bool {
	return decodeJSONBody(w, r, dest, defaultJSONBodyLimit, false)
}

func decodeLimitedJSON(w http.ResponseWriter, r *http.Request, dest any, limit int64) bool {
	return decodeJSONBody(w, r, dest, limit, true)
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dest any, limit int64, strict bool) bool {
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(dest); err != nil {
		writeError(w, http.StatusBadRequest, errInvalidBody())
		return false
	}
	var extra any
	if err := dec.Decode(&extra); err == io.EOF {
		return true
	} else if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidBody())
		return false
	}
	writeError(w, http.StatusBadRequest, errInvalidBody())
	return false
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	requestID := w.Header().Get(requestIDHeader)
	if requestID == "" {
		requestID = id.New("req")
		w.Header().Set(requestIDHeader, requestID)
	}
	writeJSON(w, status, model.APIErrorResponse{
		Error: model.APIError{
			Code:      publicAPIErrorCode(status, err),
			Message:   apiErrorMessage(status, err),
			RequestID: requestID,
		},
	})
}

type codedAPIError struct {
	code string
	err  error
}

func (e codedAPIError) Error() string {
	return e.err.Error()
}

func (e codedAPIError) Unwrap() error {
	return e.err
}

func (e codedAPIError) APIErrorCode() string {
	return e.code
}

func apiError(code, message string) error {
	return codedAPIError{code: code, err: errors.New(message)}
}

func apiErrorf(code, format string, args ...any) error {
	return codedAPIError{code: code, err: fmt.Errorf(format, args...)}
}

func publicAPIErrorCode(status int, err error) string {
	var coded interface{ APIErrorCode() string }
	if errors.As(err, &coded) && coded.APIErrorCode() != "" {
		return coded.APIErrorCode()
	}
	return apiErrorCode(status)
}

func apiErrorCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return model.APIErrorBadRequest
	case http.StatusUnauthorized:
		return model.APIErrorUnauthorized
	case http.StatusForbidden:
		return model.APIErrorForbidden
	case http.StatusNotFound:
		return model.APIErrorNotFound
	case http.StatusMethodNotAllowed:
		return model.APIErrorMethodNotAllowed
	case http.StatusTooManyRequests:
		return model.APIErrorRateLimited
	case http.StatusBadGateway:
		return model.APIErrorBadGateway
	case http.StatusInternalServerError:
		return model.APIErrorInternal
	default:
		if status >= 500 {
			return model.APIErrorInternal
		}
		return model.APIErrorRequestFailed
	}
}

func apiErrorMessage(status int, err error) string {
	switch status {
	case http.StatusBadGateway:
		return "upstream service error"
	case http.StatusInternalServerError:
		return "internal server error"
	default:
		if status >= 500 {
			return "internal server error"
		}
		return err.Error()
	}
}

// validateStorageName rejects names that would collide or corrupt the composite
// "bucket/key" keys used by the KV and static stores. A slash in either half
// would let one record masquerade as another; control characters are refused
// defensively.
func validateStorageName(value string) error {
	if value == "" {
		return errors.New("must not be empty")
	}
	if len(value) > 256 {
		return errors.New("must be at most 256 characters")
	}
	if strings.ContainsAny(value, "/\\") {
		return errors.New("must not contain slashes")
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return errors.New("must not contain control characters")
		}
	}
	return nil
}

func cleanObjectPath(value string) (string, error) {
	if value == "" {
		return "", errors.New("path is required")
	}
	value = strings.ReplaceAll(value, "\\", "/")
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return "", errors.New("invalid object path")
		}
	}
	clean := strings.TrimPrefix(path.Clean("/"+value), "/")
	if clean == "." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return "", errors.New("invalid object path")
	}
	return clean, nil
}
