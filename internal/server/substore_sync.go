package server

import (
	"context"
	"encoding/json"
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
		key := strings.TrimPrefix(ref, "secret://")
		if key == "" || len(key) > 128 || strings.ContainsAny(key, "/\x00") {
			return nil, fmt.Errorf("operator target field %q has an invalid secret reference", field)
		}
		value, ok := s.pluginSecretValue(pluginID, key)
		if !ok || strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("operator target field %q references a secret that is not saved; save the endpoint first", field)
		}
		values[field] = json.RawMessage(strconv.Quote(strings.TrimSpace(value)))
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
	mu     sync.Mutex
	timer  *time.Timer
	invoke func(ctx context.Context, pluginID, service, method string, payload json.RawMessage, operatorTargets []string) ([]byte, error)
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
	if s.subStoreSync.timer != nil {
		s.subStoreSync.timer.Stop()
	}
	s.subStoreSync.timer = time.AfterFunc(subStoreAutoSyncWait, func() {
		if err := s.runSubStoreAutoSync(); err != nil {
			s.logger.Printf("sub-store autosync: %v", err)
		}
	})
}

// subStoreAutoSyncTarget reads the companion's saved endpoint + autosync flag
// from its encrypted secret namespace. (endpoint, true) only when both exist.
func (s *Server) subStoreAutoSyncTarget() (string, bool) {
	endpoint, ok := s.pluginSecretValue(subStorePluginID, "endpoint")
	if !ok || strings.TrimSpace(endpoint) == "" {
		return "", false
	}
	flag, ok := s.pluginSecretValue(subStorePluginID, "autosync")
	if !ok || strings.TrimSpace(flag) != "1" {
		return "", false
	}
	return strings.TrimSpace(endpoint), true
}

// runSubStoreAutoSync performs one debounced sync. Skipping (no saved endpoint,
// autosync off, plugin inactive, no runtime) is silent; invoking is audited
// with the system actor, and a failed import surfaces as a deny audit — never
// a retry storm.
func (s *Server) runSubStoreAutoSync() error {
	if s.subStoreSync == nil || s.pluginRuntime == nil {
		return nil
	}
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
	if _, err := invoke(ctx, subStorePluginID, subStoreImportSvc, "import", payload, []string{endpoint}); err != nil {
		audit.Decision = "deny"
		audit.Reason = "autosync import failed"
		s.recordAudit(audit)
		return fmt.Errorf("autosync import: %w", err)
	}
	audit.Decision = "allow"
	s.recordAudit(audit)
	return nil
}
