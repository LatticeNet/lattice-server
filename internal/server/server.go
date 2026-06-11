package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/audit"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/ddns"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/network"
	"github.com/LatticeNet/lattice-server/internal/notify"
	"github.com/LatticeNet/lattice-server/internal/ratelimit"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
	"github.com/LatticeNet/lattice-server/internal/wireguard"
	"github.com/LatticeNet/lattice-server/internal/worker"
)

type Options struct {
	Store         *store.Store
	WebFS         fs.FS
	AdminPassword string
	SecureCookies bool
	// TrustProxy enables reading the client address from proxy headers
	// (CF-Connecting-IP, then X-Forwarded-For). Only enable when the server
	// sits behind a trusted reverse proxy / Cloudflare; otherwise clients can
	// spoof the header and evade per-IP rate limiting.
	TrustProxy bool
	Logger     *log.Logger
}

type Server struct {
	store         *store.Store
	webFS         fs.FS
	secureCookies bool
	trustProxy    bool
	logger        *log.Logger
	loginLimiter  *ratelimit.Limiter
	agentLimiter  *ratelimit.Limiter
	apiLimiter    *ratelimit.Limiter
	// ddnsProvider builds a DNS provider from a profile; overridable in tests.
	ddnsProvider func(model.DDNSProfile) (ddns.Provider, error)
	// emitNotify dispatches an event notification; overridable in tests.
	emitNotify func(title, body string)
}

type principal struct {
	rbac.Principal
	CSRFToken string
	sessionID string
	viaBearer bool
}

func New(opts Options) (*Server, error) {
	if opts.Store == nil {
		return nil, errors.New("store is required")
	}
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}
	s := &Server{
		store:         opts.Store,
		webFS:         opts.WebFS,
		secureCookies: opts.SecureCookies,
		trustProxy:    opts.TrustProxy,
		logger:        opts.Logger,
		// Login is intentionally strict: 5/min sustained, small burst, to slow
		// password guessing without locking out legitimate retries.
		loginLimiter: ratelimit.New(ratelimit.Config{Rate: 5.0 / 60.0, Burst: 5}),
		// Agents poll on an interval; allow generous but bounded throughput.
		agentLimiter: ratelimit.New(ratelimit.Config{Rate: 10, Burst: 40}),
		// General authenticated API surface.
		apiLimiter: ratelimit.New(ratelimit.Config{Rate: 30, Burst: 60}),
		ddnsProvider: func(p model.DDNSProfile) (ddns.Provider, error) {
			return ddns.NewProvider(p, nil)
		},
	}
	s.emitNotify = s.notifyEvent
	if err := s.ensureAdmin(opts.AdminPassword); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/logout", s.withAuth("", s.handleLogout))
	mux.HandleFunc("/api/me", s.withAuth("", s.handleMe))
	mux.HandleFunc("/api/nodes", s.withAuth("node:read", s.handleNodes))
	mux.HandleFunc("/api/nodes/enroll-token", s.withAuth("node:admin", s.handleEnrollNode))
	mux.HandleFunc("/api/tasks", s.withAuth("task:run", s.handleTasks))
	mux.HandleFunc("/api/task-results", s.withAuth("task:run", s.handleTaskResults))
	mux.HandleFunc("/api/audit", s.withAuth("audit:read", s.handleAudit))
	mux.HandleFunc("/api/kv", s.withAuth("kv:read", s.handleKV))
	mux.HandleFunc("/api/static", s.withAuth("static:read", s.handleStatic))
	mux.HandleFunc("/api/workers", s.withAuth("worker:deploy", s.handleWorkers))
	mux.HandleFunc("/api/workers/run", s.withAuth("worker:deploy", s.handleWorkerRun))
	mux.HandleFunc("/api/notify/test", s.withAuth("notify:send", s.handleNotifyTest))
	mux.HandleFunc("/api/notify/channels", s.withAuth("notify:send", s.handleNotifyChannels))
	mux.HandleFunc("/api/notify/channels/delete", s.withAuth("notify:send", s.handleDeleteNotifyChannel))
	mux.HandleFunc("/api/ddns", s.withAuth("ddns:admin", s.handleDDNS))
	mux.HandleFunc("/api/ddns/delete", s.withAuth("ddns:admin", s.handleDeleteDDNS))
	mux.HandleFunc("/api/ddns/run", s.withAuth("ddns:admin", s.handleRunDDNS))
	mux.HandleFunc("/api/monitors", s.withAuth("monitor:read", s.handleMonitors))
	mux.HandleFunc("/api/monitors/delete", s.withAuth("monitor:admin", s.handleDeleteMonitor))
	mux.HandleFunc("/api/monitors/results", s.withAuth("monitor:read", s.handleMonitorResults))
	mux.HandleFunc("/api/tokens", s.withAuth("token:admin", s.handleTokens))
	mux.HandleFunc("/api/tokens/revoke", s.withAuth("token:admin", s.handleRevokeToken))
	mux.HandleFunc("/api/network/nft/plan", s.withAuth("network:plan", s.handleNFTPlan))
	mux.HandleFunc("/api/network/wireguard/plan", s.withAuth("network:plan", s.handleWireGuardPlan))
	mux.HandleFunc("/api/network/approvals", s.withAuth("network:plan", s.handleApprovals))
	mux.HandleFunc("/api/network/approvals/approve", s.withAuth("network:apply", s.handleApprove))
	mux.HandleFunc("/api/agent/hello", s.withAgentLimit(s.handleAgentHello))
	mux.HandleFunc("/api/agent/metrics", s.withAgentLimit(s.handleAgentMetrics))
	mux.HandleFunc("/api/agent/tasks", s.withAgentLimit(s.handleAgentTasks))
	mux.HandleFunc("/api/agent/task-result", s.withAgentLimit(s.handleAgentTaskResult))
	mux.HandleFunc("/api/agent/monitors", s.withAgentLimit(s.handleAgentMonitors))
	mux.HandleFunc("/api/agent/monitor-result", s.withAgentLimit(s.handleAgentMonitorResult))
	mux.HandleFunc("/api/agent/event", s.withAgentLimit(s.handleAgentEvent))
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("/", s.staticHandler())
	return s.securityHeaders(mux)
}

func (s *Server) ensureAdmin(password string) error {
	if _, ok := s.store.UserByUsername("admin"); ok {
		return nil
	}
	if password == "" {
		generated, err := auth.NewRandomToken(24)
		if err != nil {
			return err
		}
		password = generated
		s.logger.Printf("bootstrap admin password: %s", generated)
	}
	hash, err := auth.HashSecret(password)
	if err != nil {
		return err
	}
	return s.store.UpsertUser(model.User{
		ID:           "user_admin",
		Username:     "admin",
		PasswordHash: hash,
		Scopes:       []string{"*"},
		CreatedAt:    time.Now().UTC(),
	})
}

func (s *Server) staticHandler() http.Handler {
	if s.webFS == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
	}
	fileServer := http.FileServer(http.FS(s.webFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "." || name == "" {
			name = "index.html"
		}
		if _, err := fs.Stat(s.webFS, name); err != nil {
			r.URL.Path = "/index.html"
		}
		fileServer.ServeHTTP(w, r)
	})
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
				ID:       id.New("audit"),
				ActorID:  p.ActorID,
				TokenID:  p.TokenID,
				Action:   r.Method + " " + r.URL.Path,
				Scope:    scope,
				Decision: "deny",
				Reason:   "missing scope or server allowlist denied",
			})
			writeError(w, http.StatusForbidden, errors.New("forbidden"))
			return
		}
		if !p.viaBearer && unsafeMethod(r.Method) {
			if r.Header.Get("X-Lattice-CSRF") != p.CSRFToken {
				writeError(w, http.StatusForbidden, errors.New("invalid csrf token"))
				return
			}
		}
		next(w, r, p)
	}
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
			viaBearer: true,
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
	return principal{
		Principal: rbac.Principal{
			ActorID: user.ID,
			Scopes:  user.Scopes,
		},
		CSRFToken: session.CSRFToken,
		sessionID: session.ID,
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
	if !decodeJSON(w, r, &req) {
		return
	}
	user, ok := s.store.UserByUsername(req.Username)
	if !ok {
		// Spend comparable CPU so response time does not reveal whether the
		// username exists.
		auth.DummyVerify(req.Password)
		writeError(w, http.StatusUnauthorized, errors.New("invalid credentials"))
		return
	}
	if !auth.VerifySecret(user.PasswordHash, req.Password) {
		writeError(w, http.StatusUnauthorized, errors.New("invalid credentials"))
		return
	}
	session, err := auth.NewSession(user.ID, 12*time.Hour)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.store.PutSession(session); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
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
	s.recordAudit(model.AuditEvent{ID: id.New("audit"), ActorID: user.ID, Action: "login", Decision: "allow"})
	writeJSON(w, http.StatusOK, map[string]string{"csrf_token": session.CSRFToken, "actor_id": user.ID})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, p principal) {
	if p.sessionID != "" {
		if err := s.store.DeleteSession(p.sessionID); err != nil {
			s.logger.Printf("logout: delete session: %v", err)
		}
	}
	s.recordAudit(model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, Action: "logout", Decision: "allow"})
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
	writeJSON(w, http.StatusOK, map[string]any{
		"actor_id":   p.ActorID,
		"token_id":   p.TokenID,
		"scopes":     p.Scopes,
		"csrf_token": p.CSRFToken,
	})
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	writeJSON(w, http.StatusOK, s.store.Nodes())
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
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.NodeID == "" {
		req.NodeID = id.New("node")
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
	s.recordAudit(model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, Action: "node.enroll", Scope: "node:admin", NodeID: req.NodeID})
	writeJSON(w, http.StatusOK, map[string]string{
		"node_id": req.NodeID,
		"token":   token,
		"command": fmt.Sprintf("lattice-agent -server http://127.0.0.1:8088 -node-id %s -token %s", req.NodeID, token),
	})
}

func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.store.Tasks())
	case http.MethodPost:
		var req struct {
			Targets     []string `json:"targets"`
			Interpreter string   `json:"interpreter"`
			Script      string   `json:"script"`
			TimeoutSec  int      `json:"timeout_sec"`
			OutputLimit int      `json:"output_limit"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		if len(req.Targets) == 0 || strings.TrimSpace(req.Script) == "" {
			writeError(w, http.StatusBadRequest, errors.New("targets and script are required"))
			return
		}
		if req.Interpreter == "" {
			req.Interpreter = "sh"
		}
		if req.TimeoutSec == 0 {
			req.TimeoutSec = 30
		}
		if req.OutputLimit == 0 {
			req.OutputLimit = 65536
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
		s.recordAudit(model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, TokenID: p.TokenID, Action: "task.create", Scope: "task:run", Metadata: map[string]string{"task_id": task.ID}})
		writeJSON(w, http.StatusOK, task)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleTaskResults(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	writeJSON(w, http.StatusOK, s.store.Results())
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	writeJSON(w, http.StatusOK, s.store.AuditEvents())
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
			writeError(w, http.StatusForbidden, errors.New("missing kv:write"))
			return
		}
		var req struct {
			Bucket string `json:"bucket"`
			Key    string `json:"key"`
			Value  string `json:"value"`
		}
		if !decodeJSON(w, r, &req) {
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
		s.recordAudit(model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, Action: "kv.put", Scope: "kv:write", Metadata: map[string]string{"bucket": req.Bucket, "key": req.Key}})
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
			writeError(w, http.StatusForbidden, errors.New("missing static:write"))
			return
		}
		var req struct {
			Bucket      string `json:"bucket"`
			Path        string `json:"path"`
			Content     string `json:"content"`
			ContentType string `json:"content_type"`
		}
		if !decodeJSON(w, r, &req) {
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
		s.recordAudit(model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, Action: "static.put", Scope: "static:write", Metadata: map[string]string{"bucket": req.Bucket, "path": clean}})
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
		if !decodeJSON(w, r, &req) {
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
		s.recordAudit(model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, Action: "worker.upsert", Scope: "worker:deploy", Metadata: map[string]string{"worker_id": wk.ID}})
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
	if !decodeJSON(w, r, &req) {
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
	if !decodeJSON(w, r, &req) {
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
	s.recordAudit(model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, Action: "notify.test", Scope: "notify:send", Metadata: map[string]string{"channel": req.Channel, "ok": fmt.Sprintf("%t", sendErr == nil)}})
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
		writeJSON(w, http.StatusOK, s.store.Monitors())
	case http.MethodPost:
		if !rbac.Allows(p.Principal, "monitor:admin", "") {
			writeError(w, http.StatusForbidden, errors.New("missing monitor:admin"))
			return
		}
		var req model.Monitor
		if !decodeJSON(w, r, &req) {
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
		s.recordAudit(model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, Action: "monitor.create", Scope: "monitor:admin", Metadata: map[string]string{"monitor_id": req.ID, "type": req.Type}})
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
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.store.DeleteMonitor(req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordAudit(model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, Action: "monitor.delete", Scope: "monitor:admin", Metadata: map[string]string{"monitor_id": req.ID}})
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
	writeJSON(w, http.StatusOK, s.store.MonitorResults(monitorID))
}

// handleAgentMonitors returns the monitors an authenticated agent should run.
func (s *Server) handleAgentMonitors(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	if _, ok := s.authenticateNode(nodeID, bearerToken(r)); !ok {
		writeError(w, http.StatusUnauthorized, errors.New("invalid node token"))
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
	if !decodeJSON(w, r, &req) {
		return
	}
	if _, ok := s.authenticateNode(req.NodeID, req.Token); !ok {
		writeError(w, http.StatusUnauthorized, errors.New("invalid node token"))
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
			Name    string            `json:"name"`
			Kind    string            `json:"kind"`
			Config  map[string]string `json:"config"`
			Enabled *bool             `json:"enabled"`
		}
		if !decodeJSON(w, r, &req) {
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
		channel := model.NotifyChannel{
			ID:      id.New("notify"),
			Name:    req.Name,
			Kind:    req.Kind,
			Config:  req.Config,
			Enabled: req.Enabled == nil || *req.Enabled,
		}
		if err := s.store.UpsertNotifyChannel(channel); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordAudit(model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, Action: "notify.channel.create", Scope: "notify:send", Metadata: map[string]string{"channel_id": channel.ID, "kind": channel.Kind}})
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
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.store.DeleteNotifyChannel(req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordAudit(model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, Action: "notify.channel.delete", Scope: "notify:send", Metadata: map[string]string{"channel_id": req.ID}})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// notifyEvent fans a message out to every enabled notification channel,
// asynchronously so it never blocks the triggering request.
func (s *Server) notifyEvent(title, body string) {
	channels := s.store.EnabledNotifyChannels()
	built := make([]notify.Channel, 0, len(channels))
	for _, c := range channels {
		ch, err := buildChannel(c.Kind, c.Config)
		if err != nil {
			s.logger.Printf("notify: channel %s misconfigured: %v", c.ID, err)
			continue
		}
		built = append(built, ch)
	}
	if len(built) == 0 {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for _, res := range notify.NewDispatcher(built...).Send(ctx, notify.Message{Title: title, Body: body}) {
			if res.Err != nil {
				s.logger.Printf("notify: %s delivery failed: %v", res.Kind, res.Err)
			}
		}
	}()
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
	if !decodeJSON(w, r, &req) {
		return
	}
	if _, ok := s.authenticateNode(req.NodeID, req.Token); !ok {
		writeError(w, http.StatusUnauthorized, errors.New("invalid node token"))
		return
	}
	switch req.Kind {
	case "ssh_login":
		s.recordAudit(model.AuditEvent{ID: id.New("audit"), NodeID: req.NodeID, Action: "ssh.login", Decision: "observe", Metadata: map[string]string{"user": req.User, "address": req.Address, "method": req.Method}})
		s.emitNotify("🔐 SSH login", fmt.Sprintf("node %s: %s logged in from %s (%s)", req.NodeID, req.User, req.Address, req.Method))
	default:
		s.recordAudit(model.AuditEvent{ID: id.New("audit"), NodeID: req.NodeID, Action: "agent.event", Decision: "observe", Metadata: map[string]string{"kind": req.Kind, "message": req.Message}})
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
			views = append(views, toDDNSView(pr))
		}
		writeJSON(w, http.StatusOK, views)
	case http.MethodPost:
		var req model.DDNSProfile
		if !decodeJSON(w, r, &req) {
			return
		}
		if strings.TrimSpace(req.Name) == "" || req.NodeID == "" || len(req.Domains) == 0 {
			writeError(w, http.StatusBadRequest, errors.New("name, node_id and at least one domain are required"))
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
		s.recordAudit(model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, NodeID: req.NodeID, Action: "ddns.create", Scope: "ddns:admin", Metadata: map[string]string{"ddns_id": req.ID, "provider": req.Provider}})
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
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.store.DeleteDDNSProfile(req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordAudit(model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, Action: "ddns.delete", Scope: "ddns:admin", Metadata: map[string]string{"ddns_id": req.ID}})
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
	if !decodeJSON(w, r, &req) {
		return
	}
	profile, ok := s.store.DDNSProfile(req.ID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("ddns profile not found"))
		return
	}
	node, _ := s.store.Node(profile.NodeID)
	if err := s.runDDNS(profile, node.PublicIP, node.PublicIPv6); err != nil {
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
}

// runDDNS applies a profile and records the run outcome on the profile.
func (s *Server) runDDNS(profile model.DDNSProfile, v4, v6 string) error {
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
	s.recordAudit(model.AuditEvent{ID: id.New("audit"), NodeID: profile.NodeID, Action: "ddns.run", Scope: "ddns:admin", Metadata: map[string]string{"ddns_id": profile.ID, "ok": fmt.Sprintf("%t", applyErr == nil)}})
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
		if !decodeJSON(w, r, &req) {
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
		s.recordAudit(model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, Action: "token.create", Scope: "token:admin", Metadata: map[string]string{"token_id": tok.ID}})
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
	if !decodeJSON(w, r, &req) {
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
	s.recordAudit(model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, Action: "token.revoke", Scope: "token:admin", Metadata: map[string]string{"token_id": tok.ID}})
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
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	plan, err := network.GenerateNFTPlan(req.NFTPlan)
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
	s.recordAudit(model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, NodeID: req.NodeID, Action: "network.nft.plan", Scope: "network:plan", Metadata: map[string]string{"approval_id": approval.ID}})
	writeJSON(w, http.StatusOK, approval)
}

func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	writeJSON(w, http.StatusOK, s.store.Approvals())
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
	if !decodeJSON(w, r, &req) {
		return
	}
	target, ok := s.store.Node(req.NodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
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
	s.recordAudit(model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, NodeID: req.NodeID, Action: "network.wireguard.plan", Scope: "network:plan", Metadata: map[string]string{"approval_id": approval.ID, "peers": fmt.Sprintf("%d", len(peers))}})
	writeJSON(w, http.StatusOK, approval)
}

// applyScriptFor builds the bounded shell that applies an approved plan on the
// agent, branching by plugin. nft is validated (nft -c) rather than committed;
// wireguard substitutes the node-local private key and brings the interface up.
func applyScriptFor(approval model.Approval) string {
	switch approval.Plugin {
	case "wireguard":
		return "set -e\n" +
			"umask 077\n" +
			"mkdir -p /etc/wireguard\n" +
			"KEY_FILE=${LATTICE_WG_KEY:-/etc/wireguard/lattice.key}\n" +
			"if [ ! -f \"$KEY_FILE\" ]; then echo \"missing wireguard private key at $KEY_FILE\" >&2; exit 1; fi\n" +
			"PRIV=$(cat \"$KEY_FILE\")\n" +
			"cat > /etc/wireguard/wg0.conf.new <<'LATTICE_WG_EOF'\n" +
			approval.Plan +
			"LATTICE_WG_EOF\n" +
			"sed -i \"s|" + wireguard.PrivateKeyPlaceholder + "|$PRIV|\" /etc/wireguard/wg0.conf.new\n" +
			"mv /etc/wireguard/wg0.conf.new /etc/wireguard/wg0.conf\n" +
			"wg-quick down wg0 2>/dev/null || true\n" +
			"wg-quick up wg0\n"
	default:
		return "cat > /tmp/lattice-nft-plan.nft <<'EOF'\n" + approval.Plan + "EOF\nnft -c -f /tmp/lattice-nft-plan.nft\n"
	}
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		ApprovalID string `json:"approval_id"`
		QueueApply bool   `json:"queue_apply"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	approval, ok := s.store.Approval(req.ApprovalID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("approval not found"))
		return
	}
	approval.Status = model.ApprovalApproved
	approval.ApprovedBy = p.ActorID
	if err := s.store.UpsertApproval(approval); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if req.QueueApply {
		task := model.Task{
			ID:          id.New("task"),
			ActorID:     p.ActorID,
			TokenID:     p.TokenID,
			Targets:     []string{approval.NodeID},
			Interpreter: "sh",
			Script:      applyScriptFor(approval),
			TimeoutSec:  30,
			OutputLimit: 65536,
			Status:      model.TaskQueued,
			CreatedAt:   time.Now().UTC(),
		}
		if err := s.store.CreateTask(task); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	s.recordAudit(model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, NodeID: approval.NodeID, Action: "network.nft.approve", Scope: "network:apply", Metadata: map[string]string{"approval_id": approval.ID}})
	writeJSON(w, http.StatusOK, approval)
}

func (s *Server) handleAgentHello(w http.ResponseWriter, r *http.Request) {
	var req agentAuthRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	n, ok := s.authenticateNode(req.NodeID, req.Token)
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("invalid node token"))
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
	if !decodeJSON(w, r, &req) {
		return
	}
	old, ok := s.authenticateNode(req.NodeID, req.Token)
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("invalid node token"))
		return
	}
	v4, v6 := s.resolvePublicIPs(r, req.PublicIP, req.PublicIPv6)
	if err := s.store.UpdateMetrics(req.NodeID, req.Metrics, req.Version, v4, v6, req.WireGuardIP); err != nil {
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
		writeError(w, http.StatusUnauthorized, errors.New("invalid node token"))
		return
	}
	tasks, err := s.store.LeaseTasks(nodeID, 3)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, tasks)
}

func (s *Server) handleAgentTaskResult(w http.ResponseWriter, r *http.Request) {
	var req struct {
		agentAuthRequest
		Result model.TaskResult `json:"result"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if _, ok := s.authenticateNode(req.NodeID, req.Token); !ok {
		writeError(w, http.StatusUnauthorized, errors.New("invalid node token"))
		return
	}
	req.Result.NodeID = req.NodeID
	if req.Result.FinishedAt.IsZero() {
		req.Result.FinishedAt = time.Now().UTC()
	}
	if err := s.store.AddTaskResult(req.Result); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordAudit(model.AuditEvent{ID: id.New("audit"), NodeID: req.NodeID, Action: "task.result", Decision: "allow", Metadata: map[string]string{"task_id": req.Result.TaskID}})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type agentAuthRequest struct {
	NodeID      string `json:"node_id"`
	Token       string `json:"token"`
	Version     string `json:"version"`
	PublicIP    string `json:"public_ip"`
	PublicIPv6  string `json:"public_ipv6"`
	WireGuardIP string `json:"wireguard_ip"`
	WGPublicKey string `json:"wireguard_public_key"`
	WGEndpoint  string `json:"wireguard_endpoint"`
	WGPort      int    `json:"wireguard_port"`
}

func (s *Server) authenticateNode(nodeID, token string) (model.Node, bool) {
	if nodeID == "" || token == "" {
		return model.Node{}, false
	}
	n, ok := s.store.Node(nodeID)
	if !ok {
		return model.Node{}, false
	}
	return n, auth.VerifySecret(n.TokenHash, token)
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

// recordAudit writes an audit event and, unlike a bare best-effort call, logs
// when the sink fails so audit gaps are visible instead of silent.
func (s *Server) recordAudit(ev model.AuditEvent) {
	if err := audit.Record(s.store, ev); err != nil {
		s.logger.Printf("audit: failed to record %q: %v", ev.Action, err)
	}
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

func decodeJSON(w http.ResponseWriter, r *http.Request, dest any) bool {
	defer r.Body.Close()
	body := io.LimitReader(r.Body, 1<<20)
	if err := json.NewDecoder(body).Decode(dest); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
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
