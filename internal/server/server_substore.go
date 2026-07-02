package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Sub-Store companion (design-09 §G), internal-only per the operator decision:
// it imports live node connection info from the in-core vpn-core service (over
// the inter-plugin RPC bus) into the operator's existing Sub-Store backend, and
// reports reachability. No public links/downloads, no CF Worker — the Sub-Store
// backend stays on the operator's private network; the dashboard is the only
// viewer. The full edge-delivery design is deferred (design-09 §G.4).

const (
	// subStorePluginID is the companion provider identity; it must be granted to
	// call the vpn-core/nodes service on the RPC bus.
	subStorePluginID = "latticenet.sub-store"
	// defaultSubStoreSubName is the managed local subscription the companion
	// owns inside Sub-Store. The companion only ever touches THIS subscription,
	// never the operator's others.
	defaultSubStoreSubName = "lattice-vpn-core"
)

// subStoreClient performs the trusted, operator-configured call to the Sub-Store
// backend. It is NOT the SSRF-guarded broker client: the backend is typically on
// loopback/private network, which the egress guard would (correctly) block for
// untrusted plugins — but this is an authenticated admin action to a target the
// operator explicitly named.
var subStoreClient = &http.Client{Timeout: 15 * time.Second}

// importToSubStore pulls the vpn-core node links and upserts them as the managed
// local subscription in the Sub-Store backend at baseURL. Returns the number of
// links pushed.
func (s *Server) importToSubStore(ctx context.Context, baseURL, subName, userID string) (int, error) {
	normalizedBaseURL, err := normalizeSubStoreBaseURL(baseURL)
	if err != nil {
		return 0, err
	}
	baseURL = normalizedBaseURL
	if subName == "" {
		subName = defaultSubStoreSubName
	}
	if s.pluginRPC == nil {
		return 0, errors.New("rpc bus unavailable")
	}

	payload, _ := json.Marshal(map[string]string{"user_id": userID})
	raw, err := s.pluginRPC.Call(ctx, subStorePluginID, vpnCoreNodesService, "export", payload)
	if err != nil {
		return 0, fmt.Errorf("export vpn-core nodes: %w", err)
	}
	var exp struct {
		Links []string `json:"links"`
	}
	if err := json.Unmarshal(raw, &exp); err != nil {
		return 0, fmt.Errorf("decode vpn-core export: %w", err)
	}

	sub := map[string]any{
		"name":        subName,
		"source":      "local",
		"displayName": "Lattice vpn-core",
		"content":     strings.Join(exp.Links, "\n"),
		"tag":         []string{"lattice", "vpn-core"},
	}
	if err := s.upsertSubStoreSub(ctx, baseURL, subName, sub); err != nil {
		return 0, err
	}
	return len(exp.Links), nil
}

// upsertSubStoreSub updates the managed subscription if it exists, otherwise
// creates it — so it is idempotent and NEVER replaces the whole subs array
// (which PUT /api/subs would, wiping the operator's other subscriptions).
func (s *Server) upsertSubStoreSub(ctx context.Context, baseURL, subName string, sub map[string]any) error {
	body, err := json.Marshal(sub)
	if err != nil {
		return err
	}
	status, err := subStoreDo(ctx, http.MethodPatch, baseURL+"/api/sub/"+url.PathEscape(subName), body)
	if err != nil {
		return fmt.Errorf("sub-store update: %w", err)
	}
	if status >= 200 && status < 300 {
		return nil
	}
	status, err = subStoreDo(ctx, http.MethodPost, baseURL+"/api/subs", body)
	if err != nil {
		return fmt.Errorf("sub-store create: %w", err)
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("sub-store create returned status %d", status)
	}
	return nil
}

func subStoreDo(ctx context.Context, method, target string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := subStoreClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, nil
}

func (s *Server) handleSubStoreImport(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireGlobalProxyScope(w, p, "proxy:admin") {
		return
	}
	var req struct {
		BaseURL string `json:"base_url"`
		SubName string `json:"sub_name"`
		UserID  string `json:"user_id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.BaseURL) == "" {
		writeError(w, http.StatusBadRequest, errors.New("base_url is required"))
		return
	}
	baseURL, err := normalizeSubStoreBaseURL(req.BaseURL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	pushed, err := s.importToSubStore(ctx, baseURL, req.SubName, req.UserID)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	name := strings.TrimSpace(req.SubName)
	if name == "" {
		name = defaultSubStoreSubName
	}
	s.logger.Printf("sub-store: imported %d vpn-core links into %q", pushed, name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sub_name": name, "pushed": pushed})
}

func (s *Server) handleSubStoreStatus(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireGlobalProxyScope(w, p, "proxy:read") {
		return
	}
	baseURL, err := normalizeSubStoreBaseURL(r.URL.Query().Get("base_url"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	status, err := subStoreDo(ctx, http.MethodGet, baseURL+"/api/utils/env", nil)
	reachable := err == nil && status >= 200 && status < 500
	writeJSON(w, http.StatusOK, map[string]any{"reachable": reachable, "sub_name": defaultSubStoreSubName})
}

func normalizeSubStoreBaseURL(value string) (string, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return "", errors.New("base_url is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" {
		return "", errors.New("base_url must be an absolute http(s) URL")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return "", errors.New("base_url must use http or https")
	}
	if parsed.Host == "" {
		return "", errors.New("base_url must be an absolute http(s) URL")
	}
	if parsed.User != nil {
		return "", errors.New("base_url must not include credentials")
	}
	if strings.EqualFold(parsed.Scheme, "http") && !isSubStoreLoopbackHost(parsed.Hostname()) {
		return "", errors.New("base_url may use http only for localhost or loopback; use https for remote Sub-Store backends")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("base_url must not include query or fragment")
	}
	if parsed.Path == "" || parsed.Path == "/" {
		return "", errors.New("base_url must include the Sub-Store secret path")
	}
	hasSecretPathSegment := false
	for _, segment := range strings.Split(parsed.Path, "/") {
		switch segment {
		case "":
			continue
		case ".", "..":
			return "", errors.New("base_url path must not contain dot segments")
		default:
			hasSecretPathSegment = true
		}
	}
	if !hasSecretPathSegment {
		return "", errors.New("base_url must include the Sub-Store secret path")
	}
	if parsed.Hostname() == "" {
		return "", errors.New("base_url must include a host")
	}
	if port := parsed.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("base_url port is invalid")
		}
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func isSubStoreLoopbackHost(host string) bool {
	h := strings.TrimSpace(strings.ToLower(host))
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
