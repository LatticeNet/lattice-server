package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/id"
)

const maxStoragePublicWriteBytes = 1 << 20

type storageTokenView struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Kind       string    `json:"kind"`
	Access     string    `json:"access"`
	Buckets    []string  `json:"buckets,omitempty"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type storageTokenCreateResponse struct {
	storageTokenView
	Token string `json:"token"`
}

func (s *Server) handleStorageBuckets(w http.ResponseWriter, r *http.Request, p principal) {
	kind, ok := requireStorageKind(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !s.requireScope(w, p, storageReadScope(kind)) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"buckets": s.store.StorageBuckets(kind)})
	case http.MethodPost:
		if !s.requireScope(w, p, storageAdminScope(kind)) {
			return
		}
		var req struct {
			Name             string `json:"name"`
			DisplayName      string `json:"display_name"`
			Description      string `json:"description"`
			IndexDocument    string `json:"index_document"`
			NotFoundDocument string `json:"not_found_document"`
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		bucket, err := normalizeStorageBucket(kind, req.Name, req.DisplayName, req.Description, req.IndexDocument, req.NotFoundDocument)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if existing, ok := s.store.StorageBucket(kind, bucket.Name); ok {
			bucket.ID = existing.ID
			bucket.CreatedAt = existing.CreatedAt
		}
		if err := s.store.UpsertStorageBucket(bucket); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "storage.bucket.upsert", Scope: storageAdminScope(kind), Metadata: map[string]string{"kind": kind, "bucket": bucket.Name}})
		writeJSON(w, http.StatusOK, bucket)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleStorageBindings(w http.ResponseWriter, r *http.Request, p principal) {
	kind, ok := requireStorageKind(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !s.requireScope(w, p, storageReadScope(kind)) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"bindings": s.store.StorageBindings(kind)})
	case http.MethodPost:
		if !s.requireScope(w, p, storageAdminScope(kind)) {
			return
		}
		var req struct {
			ID         string `json:"id"`
			Bucket     string `json:"bucket"`
			Hostname   string `json:"hostname"`
			PathPrefix string `json:"path_prefix"`
			Enabled    *bool  `json:"enabled"`
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		binding, err := normalizeStorageBinding(kind, req.ID, req.Bucket, req.Hostname, req.PathPrefix, req.Enabled)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if _, ok := s.store.StorageBucket(kind, binding.Bucket); !ok {
			writeError(w, http.StatusBadRequest, fmt.Errorf("%s bucket %q does not exist", kind, binding.Bucket))
			return
		}
		for _, existing := range s.store.StorageBindings(kind) {
			if existing.ID != binding.ID && sameStorageBindingRoute(existing, binding) {
				writeError(w, http.StatusConflict, errors.New("storage binding route already exists"))
				return
			}
		}
		if err := s.store.UpsertStorageBinding(binding); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "storage.binding.upsert", Scope: storageAdminScope(kind), Metadata: map[string]string{"kind": kind, "bucket": binding.Bucket, "hostname": binding.Hostname}})
		writeJSON(w, http.StatusOK, binding)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleDeleteStorageBinding(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	kind, err := normalizeStorageKind(req.Kind)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.requireScope(w, p, storageAdminScope(kind)) {
		return
	}
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	found := false
	for _, binding := range s.store.StorageBindings(kind) {
		if binding.ID == req.ID {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, errors.New("storage binding not found"))
		return
	}
	if err := s.store.DeleteStorageBinding(req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "storage.binding.delete", Scope: storageAdminScope(kind), Metadata: map[string]string{"kind": kind, "binding_id": req.ID}})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleStorageTokens(w http.ResponseWriter, r *http.Request, p principal) {
	kind, ok := requireStorageKind(w, r)
	if !ok {
		return
	}
	if !s.requireScope(w, p, storageAdminScope(kind)) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		tokens := s.store.StorageAccessTokens(kind)
		views := make([]storageTokenView, 0, len(tokens))
		for _, token := range tokens {
			views = append(views, toStorageTokenView(token))
		}
		writeJSON(w, http.StatusOK, map[string]any{"tokens": views})
	case http.MethodPost:
		var req struct {
			Name    string   `json:"name"`
			Access  string   `json:"access"`
			Buckets []string `json:"buckets"`
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		token, plaintext, err := newStorageAccessToken(kind, req.Name, req.Access, req.Buckets)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.store.UpsertStorageAccessToken(token); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "storage.token.create", Scope: storageAdminScope(kind), Metadata: map[string]string{"kind": kind, "token_id": token.ID, "access": token.Access}})
		writeJSON(w, http.StatusOK, storageTokenCreateResponse{storageTokenView: toStorageTokenView(token), Token: plaintext})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleRevokeStorageToken(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		Kind    string `json:"kind"`
		TokenID string `json:"token_id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	kind, err := normalizeStorageKind(req.Kind)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.requireScope(w, p, storageAdminScope(kind)) {
		return
	}
	token, ok := s.store.StorageAccessToken(req.TokenID)
	if !ok || token.Kind != kind {
		writeError(w, http.StatusNotFound, errors.New("storage token not found"))
		return
	}
	token, ok, err = s.store.RevokeStorageAccessToken(req.TokenID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("storage token not found"))
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "storage.token.revoke", Scope: storageAdminScope(kind), Metadata: map[string]string{"kind": kind, "token_id": req.TokenID}})
	writeJSON(w, http.StatusOK, toStorageTokenView(token))
}

func (s *Server) serveKVBinding(w http.ResponseWriter, r *http.Request, binding model.StorageBinding) {
	key, ok := bindingObjectPath(binding, r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if key == "" {
		key = r.URL.Query().Get("key")
	}
	switch r.Method {
	case http.MethodGet:
		if !s.authorizeStorageToken(w, r, model.StorageKindKV, binding.Bucket, model.StorageAccessRead) {
			return
		}
		if key == "" {
			writeJSON(w, http.StatusOK, map[string]any{"entries": s.store.KV(binding.Bucket)})
			return
		}
		entry, found := s.store.KVEntry(binding.Bucket, key)
		if !found {
			writeError(w, http.StatusNotFound, errors.New("kv key not found"))
			return
		}
		writeJSON(w, http.StatusOK, entry)
	case http.MethodPost, http.MethodPut:
		if !s.authorizeStorageToken(w, r, model.StorageKindKV, binding.Bucket, model.StorageAccessWrite) {
			return
		}
		if key == "" {
			writeError(w, http.StatusBadRequest, errors.New("key is required"))
			return
		}
		if err := validateStorageName(key); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("key: %w", err))
			return
		}
		value, err := readKVBindingValue(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		entry := model.KVEntry{Bucket: binding.Bucket, Key: key, Value: value}
		if err := s.store.PutKV(entry); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, entry)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) serveStaticBinding(w http.ResponseWriter, r *http.Request, binding model.StorageBinding) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	objectPath, ok := bindingObjectPath(binding, r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	bucket, _ := s.store.StorageBucket(model.StorageKindStatic, binding.Bucket)
	index := firstNonEmpty(bucket.IndexDocument, "index.html")
	notFound := bucket.NotFoundDocument
	if objectPath == "" || strings.HasSuffix(r.URL.Path, "/") {
		objectPath = index
	}
	obj, found := s.store.StaticObject(binding.Bucket, objectPath)
	status := http.StatusOK
	if !found && notFound != "" {
		obj, found = s.store.StaticObject(binding.Bucket, notFound)
		status = http.StatusNotFound
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	contentType := obj.ContentType
	if contentType == "" {
		contentType = mime.TypeByExtension(path.Ext(obj.Path))
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, obj.Content)
	}
}

func requestHost(hostport string) string {
	hostport = strings.TrimSpace(strings.ToLower(hostport))
	if hostport == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		hostport = host
	}
	return strings.TrimSuffix(hostport, ".")
}

func requireStorageKind(w http.ResponseWriter, r *http.Request) (string, bool) {
	kind, err := normalizeStorageKind(r.URL.Query().Get("kind"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return "", false
	}
	return kind, true
}

func normalizeStorageKind(kind string) (string, error) {
	switch strings.TrimSpace(strings.ToLower(kind)) {
	case model.StorageKindKV:
		return model.StorageKindKV, nil
	case model.StorageKindStatic:
		return model.StorageKindStatic, nil
	default:
		return "", errors.New("kind must be kv or static")
	}
}

func storageReadScope(kind string) string {
	return kind + ":read"
}

func storageAdminScope(kind string) string {
	return kind + ":admin"
}

func normalizeStorageBucket(kind, name, displayName, description, indexDocument, notFoundDocument string) (model.StorageBucket, error) {
	name = strings.TrimSpace(name)
	if err := validateStorageName(name); err != nil {
		return model.StorageBucket{}, fmt.Errorf("name: %w", err)
	}
	bucket := model.StorageBucket{
		ID:          kind + "_" + name,
		Kind:        kind,
		Name:        name,
		DisplayName: strings.TrimSpace(displayName),
		Description: strings.TrimSpace(description),
	}
	if kind == model.StorageKindStatic {
		bucket.IndexDocument = strings.TrimSpace(indexDocument)
		bucket.NotFoundDocument = strings.TrimSpace(notFoundDocument)
		if bucket.IndexDocument == "" {
			bucket.IndexDocument = "index.html"
		}
		if bucket.IndexDocument != "" {
			clean, err := cleanObjectPath(bucket.IndexDocument)
			if err != nil {
				return model.StorageBucket{}, fmt.Errorf("index_document: %w", err)
			}
			bucket.IndexDocument = clean
		}
		if bucket.NotFoundDocument != "" {
			clean, err := cleanObjectPath(bucket.NotFoundDocument)
			if err != nil {
				return model.StorageBucket{}, fmt.Errorf("not_found_document: %w", err)
			}
			bucket.NotFoundDocument = clean
		}
	}
	return bucket, nil
}

func normalizeStorageBinding(kind, bindingID, bucket, hostname, prefix string, enabled *bool) (model.StorageBinding, error) {
	bucket = strings.TrimSpace(bucket)
	if err := validateStorageName(bucket); err != nil {
		return model.StorageBinding{}, fmt.Errorf("bucket: %w", err)
	}
	host, err := normalizeStorageHostname(hostname)
	if err != nil {
		return model.StorageBinding{}, err
	}
	cleanPrefix := ""
	if strings.TrimSpace(prefix) != "" {
		cleanPrefix, err = cleanObjectPath(prefix)
		if err != nil {
			return model.StorageBinding{}, fmt.Errorf("path_prefix: %w", err)
		}
	}
	if bindingID == "" {
		bindingID = id.New("bind")
	}
	binding := model.StorageBinding{ID: bindingID, Kind: kind, Bucket: bucket, Hostname: host, PathPrefix: cleanPrefix, Enabled: true}
	if enabled != nil {
		binding.Enabled = *enabled
	}
	return binding, nil
}

func normalizeStorageHostname(hostname string) (string, error) {
	hostname = requestHost(hostname)
	if hostname == "" {
		return "", errors.New("hostname is required")
	}
	if strings.Contains(hostname, "://") || strings.ContainsAny(hostname, "/\\") {
		return "", errors.New("hostname must not include a scheme or path")
	}
	if len(hostname) > 255 {
		return "", errors.New("hostname must be at most 255 characters")
	}
	for _, r := range hostname {
		if r < 0x20 || r == 0x7f || r == ' ' {
			return "", errors.New("hostname must not contain spaces or control characters")
		}
	}
	if _, err := netip.ParseAddr(hostname); err == nil {
		return hostname, nil
	}
	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return "", errors.New("invalid hostname")
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return "", errors.New("invalid hostname")
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("invalid hostname")
		}
	}
	return hostname, nil
}

func newStorageAccessToken(kind, name, access string, buckets []string) (model.StorageAccessToken, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return model.StorageAccessToken{}, "", errors.New("name is required")
	}
	access = strings.TrimSpace(strings.ToLower(access))
	switch access {
	case model.StorageAccessAdmin, model.StorageAccessRead, model.StorageAccessWrite:
	default:
		return model.StorageAccessToken{}, "", errors.New("access must be admin, read, or write")
	}
	cleanBuckets, err := normalizeTokenBuckets(buckets)
	if err != nil {
		return model.StorageAccessToken{}, "", err
	}
	secret, err := auth.NewRandomToken(32)
	if err != nil {
		return model.StorageAccessToken{}, "", err
	}
	token := model.StorageAccessToken{ID: id.New("st"), Name: name, Kind: kind, Access: access, Buckets: cleanBuckets}
	hash, err := auth.HashSecret(secret)
	if err != nil {
		return model.StorageAccessToken{}, "", err
	}
	token.TokenHash = hash
	return token, auth.FormatToken(token.ID, secret), nil
}

func normalizeTokenBuckets(buckets []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, bucket := range buckets {
		bucket = strings.TrimSpace(bucket)
		if bucket == "" {
			continue
		}
		if bucket == "*" {
			out = append(out, "*")
			return out, nil
		}
		if err := validateStorageName(bucket); err != nil {
			return nil, fmt.Errorf("bucket %q: %w", bucket, err)
		}
		if !seen[bucket] {
			seen[bucket] = true
			out = append(out, bucket)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, errors.New("at least one bucket or * is required")
	}
	return out, nil
}

func toStorageTokenView(token model.StorageAccessToken) storageTokenView {
	return storageTokenView{
		ID: token.ID, Name: token.Name, Kind: token.Kind, Access: token.Access, Buckets: token.Buckets,
		RevokedAt: token.RevokedAt, LastUsedAt: token.LastUsedAt, CreatedAt: token.CreatedAt, UpdatedAt: token.UpdatedAt,
	}
}

func (s *Server) authorizeStorageToken(w http.ResponseWriter, r *http.Request, kind, bucket, required string) bool {
	presented := bearerToken(r)
	tokenID, secret, ok := auth.SplitToken(presented)
	if !ok {
		auth.DummyVerify(presented)
		writeError(w, http.StatusUnauthorized, errors.New("missing or invalid storage token"))
		return false
	}
	token, found := s.store.StorageAccessToken(tokenID)
	if !found || !token.RevokedAt.IsZero() {
		auth.DummyVerify(secret)
		writeError(w, http.StatusUnauthorized, errors.New("missing or invalid storage token"))
		return false
	}
	if token.Kind != kind || !auth.VerifySecret(token.TokenHash, secret) {
		writeError(w, http.StatusUnauthorized, errors.New("missing or invalid storage token"))
		return false
	}
	if !storageTokenAllows(token, bucket, required) {
		writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "storage token lacks permission"))
		return false
	}
	if err := s.store.TouchStorageAccessToken(token.ID); err != nil {
		s.logger.Printf("storage token touch: %v", err)
	}
	return true
}

func storageTokenAllows(token model.StorageAccessToken, bucket, required string) bool {
	if len(token.Buckets) > 0 {
		allowed := false
		for _, b := range token.Buckets {
			if b == "*" || b == bucket {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	if token.Access == model.StorageAccessAdmin {
		return true
	}
	return token.Access == required
}

func (s *Server) storageBindingForRequest(kind, hostname, urlPath string) (model.StorageBinding, bool) {
	var best model.StorageBinding
	bestPrefixLen := -1
	for _, binding := range s.store.StorageBindings(kind) {
		if !binding.Enabled || !strings.EqualFold(binding.Hostname, hostname) {
			continue
		}
		if _, ok := bindingObjectPath(binding, urlPath); !ok {
			continue
		}
		prefixLen := len(strings.Trim(binding.PathPrefix, "/"))
		if prefixLen > bestPrefixLen || (prefixLen == bestPrefixLen && binding.ID < best.ID) {
			best = binding
			bestPrefixLen = prefixLen
		}
	}
	return best, bestPrefixLen >= 0
}

func sameStorageBindingRoute(a, b model.StorageBinding) bool {
	return a.Kind == b.Kind &&
		strings.EqualFold(a.Hostname, b.Hostname) &&
		strings.Trim(a.PathPrefix, "/") == strings.Trim(b.PathPrefix, "/")
}

func bindingObjectPath(binding model.StorageBinding, urlPath string) (string, bool) {
	clean := strings.TrimPrefix(path.Clean("/"+urlPath), "/")
	if clean == "." {
		clean = ""
	}
	prefix := strings.Trim(binding.PathPrefix, "/")
	if prefix == "" {
		return clean, true
	}
	if clean == prefix {
		return "", true
	}
	if strings.HasPrefix(clean, prefix+"/") {
		return strings.TrimPrefix(clean, prefix+"/"), true
	}
	return "", false
}

func readKVBindingValue(r *http.Request) (string, error) {
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "application/json") {
		var req struct {
			Value string `json:"value"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, maxStoragePublicWriteBytes)).Decode(&req); err != nil {
			return "", err
		}
		return req.Value, nil
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxStoragePublicWriteBytes))
	if err != nil {
		return "", err
	}
	return string(data), nil
}
