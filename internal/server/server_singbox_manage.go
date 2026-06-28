package server

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// Adoption bridge — manage side (Model-B write path, design-09 §E.3). Instead of
// Model-A (render config.json + atomic overwrite, which clobbers a 233boy box),
// these endpoints drive the on-box `sb --json add/del` interface via the existing
// agent task pipeline, so the operator can ADD/REMOVE nodes on an existing
// machine from the dashboard without taking over its config. The command is
// constructed ONLY from validated, allowlisted, shell-quoted inputs — node/raw
// strings never reach the shell unquoted — and runs under the same task:run trust
// as the generic task API (the agent must have exec enabled).

// singBoxAddProtocols is the allowlist of `sb add <protocol>` tokens (the 233boy
// protocol shortcuts). A protocol outside this set is rejected before any command
// is built, so the protocol field can never carry shell metacharacters.
var singBoxAddProtocols = map[string]bool{
	"reality": true, "rh2": true, "vless": true, "vmess": true,
	"tcp": true, "ws": true, "h2": true, "quic": true,
	"wss": true, "vws": true, "vh2": true, "vhu": true,
	"tws": true, "th2": true, "thu": true,
	"trojan": true, "tuic": true, "hy2": true, "hysteria2": true,
	"ss": true, "shadowsocks": true, "anytls": true, "socks": true,
}

// singBoxNodeNameRe bounds a conf node name (the `sb del <name>` argument and the
// filenames `sb list` reports). Conservative: the 233boy filename charset.
var singBoxNodeNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// singBoxArgRe bounds an optional free arg value (uuid / sni / password / path).
var singBoxArgRe = regexp.MustCompile(`^[A-Za-z0-9._:/@-]{1,128}$`)

// queueSingBoxTask builds the sh script and queues it as a task:run task to one
// node, returning the created task.
func (s *Server) queueSingBoxTask(p principal, nodeID, script string) (model.Task, error) {
	task := model.Task{
		ID:          id.New("task"),
		ActorID:     p.ActorID,
		TokenID:     p.TokenID,
		Targets:     []string{nodeID},
		Interpreter: "sh",
		Script:      script,
		TimeoutSec:  defaultTaskTimeoutSec,
		OutputLimit: defaultTaskOutputLimit,
		Status:      model.TaskQueued,
		CreatedAt:   s.now(),
	}
	if err := s.store.CreateTask(task); err != nil {
		return model.Task{}, err
	}
	return task, nil
}

// nodeSBAddr returns the address to pass as `sb --addr` so share links render
// with the right host: the node's public IP (falls back to empty -> the script
// keeps whatever it autodetects, but we always try to provide one).
func (s *Server) nodeSBAddr(nodeID string) string {
	if n, ok := s.store.Node(nodeID); ok {
		if ip := strings.TrimSpace(n.PublicIP); ip != "" {
			return ip
		}
	}
	return ""
}

func (s *Server) handleSingBoxManageAdd(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		NodeID   string   `json:"node_id"`
		Protocol string   `json:"protocol"`
		Port     int      `json:"port"`
		Args     []string `json:"args"` // optional positional args after [port], e.g. [uuid]/[sni]
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	proto := strings.ToLower(strings.TrimSpace(req.Protocol))
	if !singBoxAddProtocols[proto] {
		writeError(w, http.StatusBadRequest, fmt.Errorf("unsupported sing-box protocol %q", req.Protocol))
		return
	}
	if !s.requireNodeScope(w, p, "task:run", req.NodeID) {
		return
	}

	// Build the arg-vector as quoted shell words. Every value is validated then
	// shellQuote'd, so no input can break out of its argument.
	parts := []string{"sb"}
	if addr := s.nodeSBAddr(req.NodeID); addr != "" {
		parts = append(parts, "--addr", shellQuote(addr))
	}
	parts = append(parts, "--json", "add", shellQuote(proto))
	if req.Port != 0 {
		if req.Port < 1 || req.Port > 65535 {
			writeError(w, http.StatusBadRequest, errors.New("port must be 1-65535"))
			return
		}
		parts = append(parts, strconv.Itoa(req.Port))
	}
	for _, a := range req.Args {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if !singBoxArgRe.MatchString(a) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid argument %q", a))
			return
		}
		parts = append(parts, shellQuote(a))
	}
	script := "set -e\n" + strings.Join(parts, " ") + "\n"

	task, err := s.queueSingBoxTask(p, req.NodeID, script)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), NodeID: req.NodeID, Action: "singbox.manage.add", Scope: "task:run",
		Metadata: map[string]string{"task_id": task.ID, "protocol": proto},
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "task_id": task.ID})
}

func (s *Server) handleSingBoxManageDelete(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
		Name   string `json:"name"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.NodeID == "" || strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id and name are required"))
		return
	}
	name := strings.TrimSpace(req.Name)
	if !singBoxNodeNameRe.MatchString(name) {
		writeError(w, http.StatusBadRequest, errors.New("invalid node name"))
		return
	}
	// Defense in depth: only allow deleting a name the machine actually reported,
	// so this endpoint can never be used to run `sb del` with a crafted argument
	// against an arbitrary on-box path.
	if !s.singBoxInventoryHasNode(req.NodeID, name) {
		writeError(w, http.StatusBadRequest, errors.New("name is not a discovered node on this machine"))
		return
	}
	if !s.requireNodeScope(w, p, "task:run", req.NodeID) {
		return
	}
	parts := []string{"sb", "--json", "del", shellQuote(name)}
	script := "set -e\n" + strings.Join(parts, " ") + "\n"
	task, err := s.queueSingBoxTask(p, req.NodeID, script)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), NodeID: req.NodeID, Action: "singbox.manage.delete", Scope: "task:run",
		Metadata: map[string]string{"task_id": task.ID, "name": name},
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "task_id": task.ID})
}

// singBoxInventoryHasNode reports whether name is one of the nodes the machine
// most recently reported via discovery.
func (s *Server) singBoxInventoryHasNode(nodeID, name string) bool {
	s.singboxInvMu.RLock()
	defer s.singboxInvMu.RUnlock()
	inv, ok := s.singboxInv[nodeID]
	if !ok {
		return false
	}
	for _, n := range inv.Nodes {
		if n.Name == name {
			return true
		}
	}
	return false
}
