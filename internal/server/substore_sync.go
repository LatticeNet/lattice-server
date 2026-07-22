package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// design-15 §7: Sub-Store deep integration without merging the plugins.
//
// Two pieces live in core:
//
//  1. secret:// operator-target resolution (handlePluginCall): a payload
//     operator-target field may carry secret://<key>, resolved from the
//     plugin's own encrypted secret bucket (pluginsecret:<pluginID>) before
//     binding. The plugin's saved endpoint can therefore back http.operator.do
//     calls without the URL ever round-tripping through the browser again.
//  2. Auto-sync: every committed vpn-core mutation re-arms a debounced trigger
//     (30s); when it fires and the Sub-Store companion has both a saved
//     endpoint and autosync enabled, the server invokes its import method as
//     the system actor with a full audit trail. There is deliberately no
//     generic plugin event bus (design-15 appendix C).
const (
	subStorePluginID     = "latticenet.sub-store"
	subStoreImportSvc    = "latticenet.sub-store/import"
	subStoreDefaultSub   = "lattice-vpn-core"
	subStoreAutoSyncWait = 30 * time.Second
)

type subStoreEndpointSecret struct {
	BaseURL  string `json:"base_url"`
	AutoSync bool   `json:"autosync"`
}

// parsePluginSecretRef accepts the canonical, namespace-bound
// secret://<plugin-id>/<key> form. The historical secret://<key> shorthand is
// retained only as a lookup in the current plugin's own namespace.
func parsePluginSecretRef(currentPluginID, ref string) (string, error) {
	name := strings.TrimPrefix(ref, "secret://")
	if name == "" || len(name) > 256 || strings.ContainsRune(name, '\x00') {
		return "", errors.New("invalid secret reference")
	}
	if !strings.Contains(name, "/") {
		if len(name) > 128 {
			return "", errors.New("invalid secret reference")
		}
		return name, nil
	}
	pluginID, key, ok := strings.Cut(name, "/")
	if !ok || pluginID != currentPluginID || key == "" || len(key) > 128 || strings.Contains(key, "/") {
		return "", errors.New("secret reference is outside the current plugin namespace")
	}
	return key, nil
}

func subStoreEndpointValue(raw string) (string, bool, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false, false
	}
	if !strings.HasPrefix(raw, "{") {
		return raw, false, true // legacy plain URL; autosync lives in its old key
	}
	var saved subStoreEndpointSecret
	if err := json.Unmarshal([]byte(raw), &saved); err != nil || strings.TrimSpace(saved.BaseURL) == "" {
		return "", false, false
	}
	return strings.TrimSpace(saved.BaseURL), saved.AutoSync, true
}

// resolveSecretOperatorTargets rewrites declared payload operator-target fields
// that carry a secret:// reference into the resolved value from the plugin's
// encrypted secret store, returning the rewritten payload. Only declared fields
// are touched; the resolved value never appears in audits or errors.
func (s *Server) resolveSecretOperatorTargets(p principal, pluginID string, payload json.RawMessage, fields []string) (json.RawMessage, error) {
	if len(fields) == 0 || len(payload) == 0 {
		return payload, nil
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(payload, &values); err != nil {
		return payload, nil // not an object: extractOperatorTargets reports the canonical error
	}
	changed := false
	for _, field := range fields {
		raw, ok := values[field]
		if !ok {
			continue
		}
		var ref string
		if err := json.Unmarshal(raw, &ref); err != nil || !strings.HasPrefix(ref, "secret://") {
			continue
		}
		key, err := parsePluginSecretRef(pluginID, ref)
		if err != nil {
			return nil, fmt.Errorf("operator target field %q has an invalid secret reference", field)
		}
		value, ok := s.pluginSecretValue(pluginID, key)
		if !ok || strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("operator target field %q references a secret that is not saved; save the endpoint first", field)
		}
		resolved := strings.TrimSpace(value)
		if pluginID == subStorePluginID && key == "endpoint" {
			var valid bool
			resolved, _, valid = subStoreEndpointValue(value)
			if !valid {
				return nil, fmt.Errorf("operator target field %q references an invalid saved endpoint", field)
			}
		}
		values[field] = json.RawMessage(strconv.Quote(resolved))
		changed = true
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID: id.New("audit"), Action: "plugin.operator_target.secret_resolve", Scope: "proxy:read",
			Metadata: map[string]string{"plugin_id": pluginID, "field": field, "key": key},
		})
	}
	if !changed {
		return payload, nil
	}
	return json.Marshal(values)
}

// ── auto-sync on vpn-core mutations ───────────────────────────────────────────

// subStoreSyncState holds the debounced auto-sync trigger state. invoke is a
// test seam; production leaves it nil and falls back to callRuntimePluginService.
type subStoreSyncState struct {
	mu      sync.Mutex
	timer   *time.Timer
	running bool
	dirty   bool
	invoke  func(ctx context.Context, pluginID, service, method string, payload json.RawMessage, operatorTargets []string) ([]byte, error)
}

// triggerVPNCoreMutation re-arms the debounced auto-sync. It is called after
// every committed vpn-core write (identity CRUD, bindings, rotation, and
// applied line-user changes) and never blocks the write path.
func (s *Server) triggerVPNCoreMutation() {
	if s.subStoreSync == nil {
		return
	}
	s.subStoreSync.mu.Lock()
	defer s.subStoreSync.mu.Unlock()
	if s.subStoreSync.running {
		s.subStoreSync.dirty = true
		return
	}
	if s.subStoreSync.timer != nil {
		s.subStoreSync.timer.Stop()
	}
	s.subStoreSync.timer = time.AfterFunc(subStoreAutoSyncWait, func() {
		if err := s.runSubStoreAutoSync(); err != nil {
			s.logger.Printf("sub-store autosync: %v", err)
		}
	})
}

type subStoreAutoSyncStatus struct {
	State         string `json:"state"`
	AttemptedAt   string `json:"attempted_at,omitempty"`
	LastSuccessAt string `json:"last_success_at,omitempty"`
	Error         string `json:"error,omitempty"`
}

func (s *Server) writeSubStoreAutoSyncStatus(status subStoreAutoSyncStatus) {
	if previous, ok := s.pluginSecretValue(subStorePluginID, "autosync_status"); ok && status.LastSuccessAt == "" {
		var old subStoreAutoSyncStatus
		if json.Unmarshal([]byte(previous), &old) == nil {
			status.LastSuccessAt = old.LastSuccessAt
		}
	}
	raw, err := json.Marshal(status)
	if err != nil || len(raw) > 1024 {
		s.logger.Printf("sub-store autosync: encode bounded status failed")
		return
	}
	if err := s.putPluginSecretValue(subStorePluginID, "autosync_status", string(raw)); err != nil {
		s.logger.Printf("sub-store autosync: persist status failed: %v", err)
	}
}

// subStoreAutoSyncTarget reads the companion's saved endpoint + autosync flag
// from its encrypted secret namespace. (endpoint, true) only when both exist.
func (s *Server) subStoreAutoSyncTarget() (string, bool) {
	raw, ok := s.pluginSecretValue(subStorePluginID, "endpoint")
	if !ok {
		return "", false
	}
	endpoint, embeddedAutoSync, valid := subStoreEndpointValue(raw)
	if !valid {
		return "", false
	}
	if strings.HasPrefix(strings.TrimSpace(raw), "{") {
		return endpoint, embeddedAutoSync
	}
	flag, ok := s.pluginSecretValue(subStorePluginID, "autosync")
	if !ok || strings.TrimSpace(flag) != "1" {
		return "", false
	}
	return endpoint, true
}

// runSubStoreAutoSync performs one debounced sync. Skipping (no saved endpoint,
// autosync off, plugin inactive, no runtime) is silent; invoking is audited
// with the system actor, and a failed import surfaces as a deny audit — never
// a retry storm.
func (s *Server) runSubStoreAutoSync() error {
	if s.subStoreSync == nil || s.pluginRuntime == nil {
		return nil
	}
	s.subStoreSync.mu.Lock()
	if s.subStoreSync.running {
		s.subStoreSync.dirty = true
		s.subStoreSync.mu.Unlock()
		return nil
	}
	s.subStoreSync.running = true
	s.subStoreSync.timer = nil
	s.subStoreSync.mu.Unlock()

	var firstErr error
	for {
		err := s.runOneSubStoreAutoSync()
		if firstErr == nil {
			firstErr = err
		}
		s.subStoreSync.mu.Lock()
		if s.subStoreSync.dirty {
			s.subStoreSync.dirty = false
			s.subStoreSync.mu.Unlock()
			continue
		}
		s.subStoreSync.running = false
		s.subStoreSync.mu.Unlock()
		return firstErr
	}
}

func (s *Server) runOneSubStoreAutoSync() error {
	endpoint, enabled := s.subStoreAutoSyncTarget()
	if !enabled || !s.pluginIsActive(subStorePluginID) {
		return nil
	}
	payload, err := json.Marshal(map[string]string{"base_url": endpoint, "sub_name": subStoreDefaultSub})
	if err != nil {
		return err
	}
	audit := model.AuditEvent{
		ID: id.New("audit"), At: s.now(), Action: "substore.autosync", Scope: "proxy:admin", ActorID: "system",
		Metadata: map[string]string{"plugin_id": subStorePluginID, "method": "import"},
	}
	invoke := s.subStoreSync.invoke
	if invoke == nil {
		invoke = s.callRuntimePluginService
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	attemptedAt := s.now().UTC().Format(time.RFC3339)
	s.writeSubStoreAutoSyncStatus(subStoreAutoSyncStatus{State: "running", AttemptedAt: attemptedAt})
	if _, err := invoke(ctx, subStorePluginID, subStoreImportSvc, "import", payload, []string{endpoint}); err != nil {
		audit.Decision = "deny"
		audit.Reason = "autosync import failed"
		s.recordAudit(audit)
		s.writeSubStoreAutoSyncStatus(subStoreAutoSyncStatus{
			State: "error", AttemptedAt: attemptedAt, Error: "autosync import failed",
		})
		s.notifyEvent("Sub-Store auto-sync failed", "The automatic Sub-Store import failed. Review the audit log and retry.")
		return fmt.Errorf("autosync import: %w", err)
	}
	audit.Decision = "allow"
	s.recordAudit(audit)
	s.writeSubStoreAutoSyncStatus(subStoreAutoSyncStatus{
		State: "success", AttemptedAt: attemptedAt, LastSuccessAt: s.now().UTC().Format(time.RFC3339),
	})
	return nil
}
