package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/plugin"
)

// contributionsIfActive returns a plugin's UI contributions only when the plugin
// is active, so the dashboard renders a plugin's UI exactly when it is active.
func contributionsIfActive(ui *plugin.ManifestUI, status string) *plugin.ManifestUI {
	if status == model.PluginStatusActive {
		return ui
	}
	return nil
}

// handlePluginCall is the design-10 dashboard->plugin gateway. The dashboard
// calls a plugin's declared interface method; the server checks the interface's
// declared scopes against the principal, then dispatches through the RPC registry
// (operator-initiated: the directed plugin->plugin allow-list does not apply —
// RBAC scopes + audit are the gate). Routes uniformly to in-core services (e.g.
// latticenet.vpn-core/nodes) and runner-backed plugin services.
func (s *Server) handlePluginCall(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		ID      string          `json:"id"`
		Service string          `json:"service"`
		Method  string          `json:"method"`
		Payload json.RawMessage `json:"payload"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.ID == "" || req.Service == "" || req.Method == "" {
		writeError(w, http.StatusBadRequest, errors.New("id, service and method are required"))
		return
	}
	// The plugin must be ACTIVE and must DECLARE this service+method (with its
	// required scopes) in its manifest interfaces — a call to an undeclared
	// service is refused even if the registry has it.
	scopes, ok := s.pluginInterfaceScopes(req.ID, req.Service, req.Method)
	if !ok {
		writeError(w, http.StatusBadRequest, errors.New("plugin does not expose this interface/method (or is not active)"))
		return
	}
	for _, sc := range scopes {
		if !s.requireScope(w, p, sc) {
			return
		}
	}
	if s.pluginRPC == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("plugin rpc bus unavailable"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	out, err := s.pluginRPC.CallOperator(ctx, req.Service, req.Method, []byte(req.Payload))
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: "plugin.call", Scope: "plugin",
		Metadata: map[string]string{"plugin_id": req.ID, "service": req.Service, "method": req.Method},
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if len(out) == 0 {
		_, _ = w.Write([]byte("null"))
		return
	}
	_, _ = w.Write(out)
}

// pluginInterfaceScopes returns the declared scopes for an ACTIVE plugin's
// service+method, and whether that interface/method is declared.
func (s *Server) pluginInterfaceScopes(pluginID, service, method string) ([]string, bool) {
	inst, ok := s.store.PluginInstallation(pluginID)
	if !ok || inst.Status != model.PluginStatusActive {
		return nil, false
	}
	for _, pl := range s.plugins {
		if pl.Manifest.ID != pluginID {
			continue
		}
		for _, c := range pl.Manifest.Interfaces {
			if c.Service != service {
				continue
			}
			for _, m := range c.Methods {
				if m == method {
					return c.Scopes, true
				}
			}
		}
	}
	return nil, false
}

// handlePluginInvoke runs one action on an ACTIVE plugin via the runtime (the
// Tier-2 system runner execs the artifact's {action,payload}->{ok,result}
// protocol). This is the minimal seed of the design-10 dashboard->plugin gateway:
// it makes plugin EXECUTION reachable (the system runner otherwise stages the
// artifact but nothing triggers it). Gated by plugin:admin + audited. A plugin
// that is not armed, or whose runner cannot invoke (noop), returns an error
// rather than silently doing nothing.
func (s *Server) handlePluginInvoke(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireScope(w, p, "plugin:admin") {
		return
	}
	var req struct {
		ID      string          `json:"id"`
		Action  string          `json:"action"`
		Payload json.RawMessage `json:"payload"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.ID == "" || req.Action == "" {
		writeError(w, http.StatusBadRequest, errors.New("id and action are required"))
		return
	}
	if s.pluginRuntime == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("plugin runtime unavailable"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	resp, err := s.pluginRuntime.Invoke(ctx, req.ID, req.Action, req.Payload)
	if err != nil {
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID: id.New("audit"), Action: "plugin.invoke", Scope: "plugin:admin", Decision: "deny",
			Reason: err.Error(), Metadata: map[string]string{"plugin_id": req.ID, "plugin_action": req.Action},
		})
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: "plugin.invoke", Scope: "plugin:admin", Decision: "allow",
		Metadata: map[string]string{"plugin_id": req.ID, "plugin_action": req.Action},
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": resp.OK, "message": resp.Message, "result": resp.Result})
}
