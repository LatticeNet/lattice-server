package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// contributionsIfActive returns a plugin's UI contributions only when the plugin
// is active, so the dashboard renders a plugin's UI exactly when it is active.
func contributionsIfActive(ui *plugin.ManifestUI, status string) *plugin.ManifestUI {
	if status == model.PluginStatusActive {
		return ui
	}
	return nil
}

// handlePluginContributions is the low-sensitivity discovery endpoint the
// dashboard sidebar uses. It intentionally does NOT expose lifecycle controls,
// bundle paths, signatures, digests, or inactive plugins, and it filters
// contributed nav/views/actions by the caller's RBAC scopes. The full plugin
// registry remains behind /api/plugins (audit:read).
func (s *Server) handlePluginContributions(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	views := make([]pluginView, 0, len(s.plugins))
	for _, pl := range s.plugins {
		inst, ok := s.store.PluginInstallation(pl.Manifest.ID)
		if !ok || inst.Status != model.PluginStatusActive || pl.Manifest.UI == nil {
			continue
		}
		ui := filterPluginUIForPrincipal(pl.Manifest.UI, pl.Manifest.Interfaces, p)
		if ui == nil || (len(ui.Nav) == 0 && len(ui.Views) == 0) {
			continue
		}
		views = append(views, pluginView{
			ID: pl.Manifest.ID, Name: pl.Manifest.Name, Type: pl.Manifest.Type,
			Version: pl.Manifest.Version, Publisher: pl.Manifest.Publisher,
			Capabilities: []string{},
			Status:       inst.Status, Active: true, UI: ui,
			Interfaces: filterPluginInterfacesForUI(ui, pl.Manifest.Interfaces),
		})
	}
	writeJSON(w, http.StatusOK, views)
}

func filterPluginUIForPrincipal(ui *plugin.ManifestUI, contracts []plugin.InterfaceContract, p principal) *plugin.ManifestUI {
	if ui == nil {
		return nil
	}
	contractScopes := map[string][]string{}
	for _, c := range contracts {
		for _, m := range c.Methods {
			contractScopes[c.Service+"/"+m] = c.Scopes
		}
	}
	visibleRoutes := map[string]struct{}{}
	out := &plugin.ManifestUI{}
	for _, n := range ui.Nav {
		if !principalHasScopes(p, n.Scopes) {
			continue
		}
		out.Nav = append(out.Nav, n)
		visibleRoutes[n.Route] = struct{}{}
	}
	for _, v := range ui.Views {
		viewHasVisibleNav := false
		if _, ok := visibleRoutes[v.Route]; ok {
			viewHasVisibleNav = true
		}
		viewSourceAllowed := v.Source != nil && principalHasScopes(p, contractScopes[v.Source.Interface+"/"+v.Source.Method])
		if !viewHasVisibleNav && !viewSourceAllowed {
			continue
		}
		vv := v
		if len(v.Actions) > 0 {
			vv.Actions = nil
			for _, a := range v.Actions {
				required := uniqueStrings(append(append([]string(nil), contractScopes[a.Interface+"/"+a.Method]...), a.Scopes...))
				if principalHasScopes(p, required) {
					vv.Actions = append(vv.Actions, a)
				}
			}
		}
		out.Views = append(out.Views, vv)
	}
	return out
}

func filterPluginInterfacesForUI(ui *plugin.ManifestUI, contracts []plugin.InterfaceContract) []plugin.InterfaceContract {
	if ui == nil {
		return nil
	}
	needed := map[string]map[string]struct{}{}
	add := func(service, method string) {
		if service == "" || method == "" {
			return
		}
		if needed[service] == nil {
			needed[service] = map[string]struct{}{}
		}
		needed[service][method] = struct{}{}
	}
	for _, v := range ui.Views {
		if v.Source != nil {
			add(v.Source.Interface, v.Source.Method)
		}
		for _, a := range v.Actions {
			add(a.Interface, a.Method)
		}
	}
	if len(needed) == 0 {
		return nil
	}
	out := []plugin.InterfaceContract{}
	for _, c := range contracts {
		methodSet := needed[c.Service]
		if len(methodSet) == 0 {
			continue
		}
		methods := []string{}
		for _, m := range c.Methods {
			if _, ok := methodSet[m]; ok {
				methods = append(methods, m)
			}
		}
		if len(methods) == 0 {
			continue
		}
		out = append(out, plugin.InterfaceContract{
			Service: c.Service,
			Methods: methods,
			Scopes:  append([]string(nil), c.Scopes...),
		})
	}
	return out
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
		s.recordPluginCallAudit(p, req.ID, req.Service, req.Method, nil, "deny", "id, service and method are required")
		writeError(w, http.StatusBadRequest, errors.New("id, service and method are required"))
		return
	}
	// The plugin must be ACTIVE and must DECLARE this service+method (with its
	// required scopes) in its manifest interfaces — a call to an undeclared
	// service is refused even if the registry has it.
	scopes, ok := s.pluginCallScopes(req.ID, req.Service, req.Method)
	if !ok {
		s.recordPluginCallAudit(p, req.ID, req.Service, req.Method, nil, "deny", "plugin does not expose this interface/method (or is not active)")
		writeError(w, http.StatusBadRequest, errors.New("plugin does not expose this interface/method (or is not active)"))
		return
	}
	for _, sc := range scopes {
		if !rbac.Allows(p.Principal, sc, "") {
			s.recordPluginCallAudit(p, req.ID, req.Service, req.Method, scopes, "deny", "missing scope "+sc)
			writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
			return
		}
	}
	if s.pluginRPC == nil {
		s.recordPluginCallAudit(p, req.ID, req.Service, req.Method, scopes, "deny", "plugin rpc bus unavailable")
		writeError(w, http.StatusServiceUnavailable, errors.New("plugin rpc bus unavailable"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	out, err := s.pluginRPC.CallOperator(ctx, req.Service, req.Method, []byte(req.Payload))
	if err != nil {
		s.recordPluginCallAudit(p, req.ID, req.Service, req.Method, scopes, "deny", err.Error())
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.recordPluginCallAudit(p, req.ID, req.Service, req.Method, scopes, "allow", "")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if len(out) == 0 {
		_, _ = w.Write([]byte("null"))
		return
	}
	_, _ = w.Write(out)
}

// pluginCallScopes returns all scopes required to call an ACTIVE plugin's
// service+method. It includes the interface contract scopes and any stricter
// matching UI action scopes, because ViewAction.Scopes are part of the security
// contract and must not be frontend-only.
func (s *Server) pluginCallScopes(pluginID, service, method string) ([]string, bool) {
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
					scopes := append([]string(nil), c.Scopes...)
					if pl.Manifest.UI != nil {
						for _, v := range pl.Manifest.UI.Views {
							for _, a := range v.Actions {
								if a.Interface == service && a.Method == method {
									scopes = append(scopes, a.Scopes...)
								}
							}
						}
					}
					return uniqueStrings(scopes), true
				}
			}
		}
	}
	return nil, false
}

func (s *Server) recordPluginCallAudit(p principal, pluginID, service, method string, scopes []string, decision, reason string) {
	scope := "plugin"
	if len(scopes) > 0 {
		scope = strings.Join(scopes, ",")
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: "plugin.call", Scope: scope, Decision: decision, Reason: reason,
		Metadata: map[string]string{"plugin_id": pluginID, "service": service, "method": method},
	})
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func principalHasScopes(p principal, scopes []string) bool {
	for _, sc := range scopes {
		if !rbac.Allows(p.Principal, sc, "") {
			return false
		}
	}
	return true
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
