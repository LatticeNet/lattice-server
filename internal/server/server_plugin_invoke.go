package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/outbound"
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
			Interfaces: filterPluginInterfacesForUI(ui, pl.Manifest.Interfaces, p),
			UIRuntime:  pluginUIRuntimeForLoaded(pl),
		})
	}
	writeJSON(w, http.StatusOK, views)
}

func pluginUIRuntimeForLoaded(loaded plugin.Loaded) *pluginUIRuntimeView {
	ui := loaded.Manifest.UIRuntime
	if loaded.Manifest.Schema != plugin.ManifestSchemaV2 || ui == nil || loaded.ArtifactDigest == "" {
		return nil
	}
	return &pluginUIRuntimeView{
		Mode:          ui.Mode,
		EntryURL:      "/api/plugins/assets/" + loaded.Manifest.ID + "/" + strings.ToLower(loaded.ArtifactDigest) + "/" + ui.Entrypoint,
		BridgeVersion: ui.BridgeVersion,
		AssetDigest:   strings.ToLower(loaded.ArtifactDigest),
	}
}

func filterPluginUIForPrincipal(ui *plugin.ManifestUI, contracts []plugin.InterfaceContract, p principal) *plugin.ManifestUI {
	if ui == nil {
		return nil
	}
	contractScopes := map[string][]string{}
	for _, c := range contracts {
		for _, method := range c.MethodContracts() {
			scopes, _ := c.EffectiveMethodScopes(method.Name)
			contractScopes[c.Service+"/"+method.Name] = scopes
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

func filterPluginInterfacesForUI(ui *plugin.ManifestUI, contracts []plugin.InterfaceContract, p principal) []plugin.InterfaceContract {
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
		if v.Kind == "sandbox" {
			for _, contract := range contracts {
				for _, method := range contract.MethodContracts() {
					add(contract.Service, method.Name)
				}
			}
		}
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
		methodSpecs := []plugin.InterfaceMethod{}
		for _, method := range c.MethodContracts() {
			scopes, _ := c.EffectiveMethodScopes(method.Name)
			if _, ok := methodSet[method.Name]; ok && principalHasScopes(p, scopes) {
				methods = append(methods, method.Name)
				methodSpecs = append(methodSpecs, method)
			}
		}
		if len(methods) == 0 {
			continue
		}
		filtered := plugin.InterfaceContract{
			Service: c.Service,
			Methods: methods,
			Scopes:  append([]string(nil), c.Scopes...),
		}
		if c.TypedMethods() {
			filtered.Methods = nil
			filtered.MethodSpecs = methodSpecs
		}
		out = append(out, filtered)
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
	methodContract, ok := s.pluginCallMethod(req.ID, req.Service, req.Method)
	if !ok {
		s.recordPluginCallAudit(p, req.ID, req.Service, req.Method, nil, "deny", "plugin does not expose this interface/method (or is not active)")
		writeError(w, http.StatusBadRequest, errors.New("plugin does not expose this interface/method (or is not active)"))
		return
	}
	scopes := methodContract.Scopes
	for _, sc := range scopes {
		if ok, reason := pluginGatewayScopeAllowed(p, sc); !ok {
			s.recordPluginCallAudit(p, req.ID, req.Service, req.Method, scopes, "deny", reason)
			writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, pluginOperatorPrincipalKey{}, p)
	operatorTargets, err := extractOperatorTargets(req.Payload, methodContract.OperatorTargetFields)
	if err != nil {
		s.recordPluginCallAudit(p, req.ID, req.Service, req.Method, scopes, "deny", err.Error())
		writeError(w, http.StatusBadRequest, err)
		return
	}
	loaded, loadedOK := s.loadedPlugin(req.ID)
	var out []byte
	err = nil
	if loadedOK && loaded.Manifest.Schema == plugin.ManifestSchemaV2 &&
		loaded.Manifest.Publisher == "latticenet" && s.pluginRPC != nil &&
		s.pluginRPC.Owns(req.ID, req.Service) {
		out, err = s.pluginRPC.CallOperator(ctx, req.Service, req.Method, []byte(req.Payload))
	} else if loadedOK && loaded.Manifest.Schema == plugin.ManifestSchemaV2 {
		out, err = s.callRuntimePluginService(ctx, req.ID, req.Service, req.Method, req.Payload, operatorTargets)
	} else if s.pluginRPC == nil {
		err = errors.New("plugin rpc bus unavailable")
	} else {
		out, err = s.pluginRPC.CallOperator(ctx, req.Service, req.Method, []byte(req.Payload))
		if errors.Is(err, plugin.ErrRPCNoService) {
			out, err = s.callRuntimePluginService(ctx, req.ID, req.Service, req.Method, req.Payload, nil)
		}
	}
	if err != nil {
		s.recordPluginCallAudit(p, req.ID, req.Service, req.Method, scopes, "deny", err.Error())
		var operationErr *pluginOperationError
		if errors.As(err, &operationErr) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(operationErr.StatusCode)
			_, _ = w.Write(operationErr.Body)
			return
		}
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

func (s *Server) callRuntimePluginService(ctx context.Context, pluginID, service, method string, payload json.RawMessage, operatorTargets []string) ([]byte, error) {
	if s.pluginRuntime == nil {
		return nil, errors.New("plugin runtime unavailable")
	}
	body, err := json.Marshal(struct {
		Service string          `json:"service"`
		Method  string          `json:"method"`
		Payload json.RawMessage `json:"payload,omitempty"`
	}{Service: service, Method: method, Payload: payload})
	if err != nil {
		return nil, fmt.Errorf("marshal plugin call payload: %w", err)
	}
	resp, err := s.pluginRuntime.InvokeConstrained(ctx, pluginID, "call", body, plugin.InvokeConstraints{OperatorTargets: operatorTargets})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		if resp.Message == "" {
			resp.Message = "plugin call failed"
		}
		return nil, errors.New(resp.Message)
	}
	return resp.Result, nil
}

// pluginCallScopes returns all scopes required to call an ACTIVE plugin's
// service+method. It includes the interface contract scopes and any stricter
// matching UI action scopes, because ViewAction.Scopes are part of the security
// contract and must not be frontend-only.
func (s *Server) pluginCallScopes(pluginID, service, method string) ([]string, bool) {
	contract, ok := s.pluginCallMethod(pluginID, service, method)
	return contract.Scopes, ok
}

func (s *Server) pluginCallMethod(pluginID, service, method string) (plugin.InterfaceMethod, bool) {
	inst, ok := s.store.PluginInstallation(pluginID)
	if !ok || inst.Status != model.PluginStatusActive {
		return plugin.InterfaceMethod{}, false
	}
	for _, pl := range s.plugins {
		if pl.Manifest.ID != pluginID {
			continue
		}
		for _, c := range pl.Manifest.Interfaces {
			if c.Service != service {
				continue
			}
			if methodContract, declared := c.MethodContract(method); declared {
				methodScopes, _ := c.EffectiveMethodScopes(method)
				scopes := append([]string(nil), methodScopes...)
				if pl.Manifest.UI != nil {
					for _, v := range pl.Manifest.UI.Views {
						for _, a := range v.Actions {
							if a.Interface == service && a.Method == method {
								scopes = append(scopes, a.Scopes...)
							}
						}
					}
				}
				methodContract.Scopes = uniqueStrings(scopes)
				return methodContract, true
			}
		}
	}
	return plugin.InterfaceMethod{}, false
}

func extractOperatorTargets(payload json.RawMessage, fields []string) ([]string, error) {
	if len(fields) == 0 {
		return nil, nil
	}
	var values map[string]json.RawMessage
	if len(payload) == 0 || json.Unmarshal(payload, &values) != nil {
		return nil, errors.New("plugin method payload must be an object with operator target fields")
	}
	targets := make([]string, 0, len(fields))
	for _, field := range fields {
		var target string
		if raw := values[field]; len(raw) == 0 || json.Unmarshal(raw, &target) != nil || strings.TrimSpace(target) == "" {
			return nil, fmt.Errorf("operator target field %q must be a non-empty string", field)
		}
		target = strings.TrimSpace(target)
		if err := outbound.GuardOperatorURL(target); err != nil {
			return nil, fmt.Errorf("operator target field %q is invalid: %s", field, redactOperatorTarget(err, target))
		}
		targets = append(targets, target)
	}
	return uniqueStrings(targets), nil
}

// redactOperatorTarget keeps a guard failure's reason but strips the secret-bearing
// target out of it. An operator target may carry its secret in the URL path, and this
// text reaches both the audit record and the API response — the audit record must
// never contain it.
func redactOperatorTarget(err error, target string) string {
	message := err.Error()
	// *url.Error renders as `parse "<url>": <reason>` with the URL quoted and escaped,
	// so scrubbing the raw target cannot remove it. Keep only the reason, which never
	// carries the URL.
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		message = urlErr.Err.Error()
	}
	if target == "" {
		return message
	}
	// Any other guard that echoes the target does so either raw or Go-escaped.
	escaped := strconv.Quote(target)
	for _, form := range []string{target, escaped, escaped[1 : len(escaped)-1]} {
		message = strings.ReplaceAll(message, form, "[redacted]")
	}
	return message
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
		if ok, _ := pluginGatewayScopeAllowed(p, sc); !ok {
			return false
		}
	}
	return true
}

func pluginGatewayScopeAllowed(p principal, scope string) (bool, string) {
	if !rbac.Allows(p.Principal, scope, "") {
		return false, "missing scope " + scope
	}
	if pluginGatewayScopeRequiresUnrestrictedAllowlist(scope) && principalHasNodeRestriction(p) {
		if strings.HasPrefix(scope, "proxy:") {
			return false, "global proxy plugin views require an unrestricted server allowlist"
		}
		return false, "global network plugin views require an unrestricted server allowlist"
	}
	return true, ""
}

func pluginGatewayScopeRequiresUnrestrictedAllowlist(scope string) bool {
	switch scope {
	case "proxy:*", "proxy:read", "proxy:admin",
		"node:read", "node:admin",
		"network:plan", "network:apply",
		"netguard:read", "netguard:admin":
		return true
	default:
		return false
	}
}

// diagnosticPluginActions is the closed set of actions reachable through the raw
// invoke channel. Everything with an effect on domain state must go through
// /api/plugins/call, which is the only path that enforces the manifest's
// per-method scopes, binds operator targets to a single invocation, and (for
// host-risk work) requires a plan and an approval.
//
// This list must stay closed. `call` and `plan` would bypass per-method scopes;
// `execute` would bypass the whole plan/approval/one-time-capability binding, so
// an operator holding only plugin:admin could apply host changes unreviewed.
var diagnosticPluginActions = map[string]bool{
	"describe": true,
	"health":   true,
}

// handlePluginInvoke runs one DIAGNOSTIC action on an ACTIVE plugin via the
// runtime (the Tier-2 system runner execs the artifact's {action,payload}->
// {ok,result} protocol). It exists so an operator can interrogate a staged
// artifact directly; it is not a gateway. Gated by plugin:admin, restricted to
// diagnosticPluginActions, and audited. A plugin that is not armed, or whose
// runner cannot invoke (noop), returns an error rather than silently doing
// nothing.
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
	if !diagnosticPluginActions[req.Action] {
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID: id.New("audit"), Action: "plugin.invoke", Scope: "plugin:admin", Decision: "deny",
			Reason:   "action is not a diagnostic action; use /api/plugins/call",
			Metadata: map[string]string{"plugin_id": req.ID, "plugin_action": req.Action},
		})
		writeError(w, http.StatusForbidden, errors.New("only diagnostic actions may be invoked directly; use /api/plugins/call"))
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
