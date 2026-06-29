package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

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
