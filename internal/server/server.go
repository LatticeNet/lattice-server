package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/audit"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/network"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
	"github.com/LatticeNet/lattice-server/internal/worker"
)

type Options struct {
	Store         *store.Store
	WebFS         fs.FS
	AdminPassword string
	SecureCookies bool
	Logger        *log.Logger
}

type Server struct {
	store         *store.Store
	webFS         fs.FS
	secureCookies bool
	logger        *log.Logger
	sessionsMu    sync.Mutex
	sessions      map[string]auth.Session
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
		logger:        opts.Logger,
		sessions:      map[string]auth.Session{},
	}
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
	mux.HandleFunc("/api/network/nft/plan", s.withAuth("network:plan", s.handleNFTPlan))
	mux.HandleFunc("/api/network/approvals", s.withAuth("network:plan", s.handleApprovals))
	mux.HandleFunc("/api/network/approvals/approve", s.withAuth("network:apply", s.handleApprove))
	mux.HandleFunc("/api/agent/hello", s.handleAgentHello)
	mux.HandleFunc("/api/agent/metrics", s.handleAgentMetrics)
	mux.HandleFunc("/api/agent/tasks", s.handleAgentTasks)
	mux.HandleFunc("/api/agent/task-result", s.handleAgentTaskResult)
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("/", s.staticHandler())
	return securityHeaders(mux)
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

func (s *Server) withAuth(scope string, next func(http.ResponseWriter, *http.Request, principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := s.principalFromRequest(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err)
			return
		}
		if scope != "" && !rbac.Allows(p.Principal, scope, r.URL.Query().Get("node_id")) {
			_ = audit.Record(s.store, model.AuditEvent{
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
		for _, token := range s.store.Tokens() {
			if !token.RevokedAt.IsZero() {
				continue
			}
			if auth.VerifySecret(token.TokenHash, bearer) {
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
		}
		return principal{}, errors.New("invalid bearer token")
	}
	cookie, err := r.Cookie("lattice_session")
	if err != nil {
		return principal{}, errors.New("missing session")
	}
	s.sessionsMu.Lock()
	session, ok := s.sessions[cookie.Value]
	s.sessionsMu.Unlock()
	if !ok || !session.Active(time.Now().UTC()) {
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
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	user, ok := s.store.UserByUsername(req.Username)
	if !ok || !auth.VerifySecret(user.PasswordHash, req.Password) {
		writeError(w, http.StatusUnauthorized, errors.New("invalid credentials"))
		return
	}
	session, err := auth.NewSession(user.ID, 12*time.Hour)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.sessionsMu.Lock()
	s.sessions[session.ID] = session
	s.sessionsMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     "lattice_session",
		Value:    session.ID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   s.secureCookies,
		Expires:  session.ExpiresAt,
	})
	_ = audit.Record(s.store, model.AuditEvent{ID: id.New("audit"), ActorID: user.ID, Action: "login", Decision: "allow"})
	writeJSON(w, http.StatusOK, map[string]string{"csrf_token": session.CSRFToken, "actor_id": user.ID})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, p principal) {
	s.sessionsMu.Lock()
	if session, ok := s.sessions[p.sessionID]; ok {
		session.Revoked = true
		s.sessions[p.sessionID] = session
	}
	s.sessionsMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "lattice_session", Value: "", Path: "/", MaxAge: -1})
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
	_ = audit.Record(s.store, model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, Action: "node.enroll", Scope: "node:admin", NodeID: req.NodeID})
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
		if !rbac.Allows(p.Principal, "static:write", "") {
			writeError(w, http.StatusForbidden, errors.New("missing static:write"))
			return
		}
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
		_ = audit.Record(s.store, model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, TokenID: p.TokenID, Action: "task.create", Scope: "task:run", Metadata: map[string]string{"task_id": task.ID}})
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
		entry := model.KVEntry{Bucket: req.Bucket, Key: req.Key, Value: req.Value}
		if err := s.store.PutKV(entry); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		_ = audit.Record(s.store, model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, Action: "kv.put", Scope: "kv:write", Metadata: map[string]string{"bucket": req.Bucket, "key": req.Key}})
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
		_ = audit.Record(s.store, model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, Action: "static.put", Scope: "static:write", Metadata: map[string]string{"bucket": req.Bucket, "path": clean}})
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
		_ = audit.Record(s.store, model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, Action: "worker.upsert", Scope: "worker:deploy", Metadata: map[string]string{"worker_id": wk.ID}})
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
	_ = audit.Record(s.store, model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, NodeID: req.NodeID, Action: "network.nft.plan", Scope: "network:plan", Metadata: map[string]string{"approval_id": approval.ID}})
	writeJSON(w, http.StatusOK, approval)
}

func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	writeJSON(w, http.StatusOK, s.store.Approvals())
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
			Script:      "cat > /tmp/lattice-nft-plan.nft <<'EOF'\n" + approval.Plan + "EOF\nnft -c -f /tmp/lattice-nft-plan.nft\n",
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
	_ = audit.Record(s.store, model.AuditEvent{ID: id.New("audit"), ActorID: p.ActorID, NodeID: approval.NodeID, Action: "network.nft.approve", Scope: "network:apply", Metadata: map[string]string{"approval_id": approval.ID}})
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
	n.AgentVersion = req.Version
	n.PublicIP = req.PublicIP
	n.WireGuardIP = req.WireGuardIP
	n.LastSeen = time.Now().UTC()
	n.Online = true
	if err := s.store.UpsertNode(n); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
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
	if _, ok := s.authenticateNode(req.NodeID, req.Token); !ok {
		writeError(w, http.StatusUnauthorized, errors.New("invalid node token"))
		return
	}
	if err := s.store.UpdateMetrics(req.NodeID, req.Metrics, req.Version, req.PublicIP, req.WireGuardIP); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAgentTasks(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	token := r.URL.Query().Get("token")
	if token == "" {
		token = bearerToken(r)
	}
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
	_ = audit.Record(s.store, model.AuditEvent{ID: id.New("audit"), NodeID: req.NodeID, Action: "task.result", Decision: "allow", Metadata: map[string]string{"task_id": req.Result.TaskID}})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type agentAuthRequest struct {
	NodeID      string `json:"node_id"`
	Token       string `json:"token"`
	Version     string `json:"version"`
	PublicIP    string `json:"public_ip"`
	WireGuardIP string `json:"wireguard_ip"`
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

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
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
