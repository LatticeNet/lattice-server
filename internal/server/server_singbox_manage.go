package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

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

const (
	singBoxProbeScriptMarker      = "# lattice:singbox-probe-v1 task="
	singBoxProbeListMarker        = "__LATTICE_SINGBOX_PROBE_LIST_V1__"
	singBoxProbeProvisionMarker   = "__LATTICE_SINGBOX_PROBE_PROVISION_V1__"
	singBoxProbeResultAction      = "singbox.manage.probe.result"
	singBoxProbeResultParseFailed = "parse_failed"
	// singBoxProbeOutputLimit is larger than defaultTaskOutputLimit because
	// sb --json list output grows linearly with the number of managed configs.
	// Using the global maximum prevents silent inventory truncation on hosts
	// with many nodes.
	singBoxProbeOutputLimit = maxTaskOutputLimit
)

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

func (s *Server) queueSingBoxProbeTask(p principal, nodeID string) (model.Task, error) {
	task := model.Task{
		ID:          id.New("task"),
		ActorID:     p.ActorID,
		TokenID:     p.TokenID,
		Targets:     []string{nodeID},
		Interpreter: "sh",
		TimeoutSec:  defaultTaskTimeoutSec,
		OutputLimit: singBoxProbeOutputLimit,
		Status:      model.TaskQueued,
		CreatedAt:   s.now(),
	}
	task.Script = buildSingBoxProbeScript(task.ID, s.nodeSBAddr(nodeID))
	if err := s.store.CreateTask(task); err != nil {
		return model.Task{}, err
	}
	return task, nil
}

func buildSingBoxProbeScript(taskID, addr string) string {
	parts := []string{"sb"}
	if addr = strings.TrimSpace(addr); addr != "" {
		parts = append(parts, "--addr", shellQuote(addr))
	}
	parts = append(parts, "--json")
	base := strings.Join(parts, " ")
	return "set -u\n" +
		singBoxProbeScriptMarker + taskID + "\n" +
		"SB_ADDR=" + shellQuote(addr) + "\n" +
		"lattice_singbox_runtime_files() {\n" +
		"  line=\"$(ps -eo args 2>/dev/null | grep '[s]ing-box run' | head -n 1 || true)\"\n" +
		"  [ -n \"$line\" ] || line=\"$(systemctl cat sing-box 2>/dev/null | sed -n 's/^ExecStart=//p' | head -n 1 || true)\"\n" +
		"  if [ -n \"$line\" ]; then\n" +
		"    set -- $line\n" +
		"    while [ \"$#\" -gt 0 ]; do\n" +
		"      case \"$1\" in\n" +
		"        -c|--config) shift; [ \"$#\" -gt 0 ] && [ -f \"$1\" ] && printf '%s\\n' \"$1\" ;;\n" +
		"        -C|--config-directory) shift; [ \"$#\" -gt 0 ] && [ -d \"$1\" ] && find \"$1\" -maxdepth 1 -type f -name '*.json' 2>/dev/null ;;\n" +
		"        -c=*|--config=*) f=\"${1#*=}\"; [ -f \"$f\" ] && printf '%s\\n' \"$f\" ;;\n" +
		"        -C=*|--config-directory=*) d=\"${1#*=}\"; [ -d \"$d\" ] && find \"$d\" -maxdepth 1 -type f -name '*.json' 2>/dev/null ;;\n" +
		"      esac\n" +
		"      shift || break\n" +
		"    done\n" +
		"  fi\n" +
		"  [ -f /etc/sing-box/config.json ] && printf '%s\\n' /etc/sing-box/config.json\n" +
		"  [ -d /etc/sing-box/conf ] && find /etc/sing-box/conf -maxdepth 1 -type f -name '*.json' 2>/dev/null\n" +
		"}\n" +
		"lattice_singbox_runtime_list() {\n" +
		"  command -v jq >/dev/null 2>&1 || { printf '%s\\n' '{\"ok\":true,\"count\":0,\"nodes\":[]}'; return 0; }\n" +
		"  files=\"$(lattice_singbox_runtime_files | sort -u)\"\n" +
		"  [ -n \"$files\" ] || { printf '%s\\n' '{\"ok\":true,\"count\":0,\"nodes\":[]}'; return 0; }\n" +
		"  # shellcheck disable=SC2086 # config paths are sing-box runtime paths; no spaces in supported installs.\n" +
		"  jq -s --arg addr \"$SB_ADDR\" '\n" +
		"    . as $cfgs\n" +
		"    | ([ $cfgs[].route.rules[]? | select((.outbound // \"\") != \"\") | . as $r | ($r.inbound // [])[]? | {key:., value:$r.outbound} ] | from_entries) as $routes\n" +
		"    | [ $cfgs[] | .inbounds[]? | . as $in | {\n" +
		"        name: ($in.tag // \"\"),\n" +
		"        protocol: ($in.type // \"\"),\n" +
		"        network: (if ($in.tls.reality.enabled // false) then \"reality\" elif (($in.transport.type // \"\") != \"\") then $in.transport.type else \"tcp\" end),\n" +
		"        address: $addr,\n" +
		"        port: (($in.listen_port // \"\") | tostring),\n" +
		"        sni: ($in.tls.server_name // $in.tls.reality.handshake.server // \"\"),\n" +
		"        listen_host: ($in.listen // \"\"),\n" +
		"        outbound_ref: ($routes[$in.tag] // \"\"),\n" +
		"        user_count: (($in.users // []) | length),\n" +
		"        user_known: ($in.users != null),\n" +
		"        metadata: (($in._lattice // {}) | with_entries(select((.value|type) == \"string\")))\n" +
		"      } ] as $nodes | {ok:true,count:($nodes|length),nodes:$nodes}\n" +
		"  ' $files\n" +
		"}\n" +
		"lattice_singbox_try_sb() {\n" +
		"  mode=\"$1\"; shift\n" +
		"  out=\"$(mktemp \"${TMPDIR:-/tmp}/lattice-sb-${mode}.out.XXXXXX\")\" || exit 1\n" +
		"  err=\"$(mktemp \"${TMPDIR:-/tmp}/lattice-sb-${mode}.err.XXXXXX\")\" || exit 1\n" +
		"  if \"$@\" >\"$out\" 2>\"$err\"; then cat \"$out\"; rm -f \"$out\" \"$err\"; return 0; fi\n" +
		"  code=$?\n" +
		"  [ -s \"$err\" ] && { printf 'sb %s failed with exit %s:\\n' \"$mode\" \"$code\" >&2; cat \"$err\" >&2; }\n" +
		"  [ -s \"$out\" ] && { printf 'sb %s stdout before fallback:\\n' \"$mode\" >&2; cat \"$out\" >&2; }\n" +
		"  rm -f \"$out\" \"$err\"\n" +
		"  return \"$code\"\n" +
		"}\n" +
		"echo " + shellQuote(singBoxProbeListMarker) + "\n" +
		"if ! lattice_singbox_try_sb list " + base + " list; then lattice_singbox_runtime_list; fi\n" +
		"echo " + shellQuote(singBoxProbeProvisionMarker) + "\n" +
		"if ! lattice_singbox_try_sb provision " + base + " provision; then command -v sing-box >/dev/null 2>&1 && sing-box version 2>/dev/null | awk 'NR==1{gsub(/\\033\\[[0-9;]*m/,\"\"); print \"{\\\"version\\\":\\\"\" $2 \"\\\"}\"; exit}' || printf '%s\\n' '{}'; fi\n"
}

// nodeSBAddr returns the address to pass as `sb --addr` so share links render
// with the right host: the node's public IP (falls back to empty -> the script
// keeps whatever it autodetects, but we always try to provide one).
//
// PublicIP is agent-reported and therefore only as trustworthy as the agent.
// shellQuote already neutralises any injection, but a malformed value (a stray
// hostname fragment, an unbracketed IPv6 address, garbage) would make `sb --addr`
// fail or emit wrong share URLs with no diagnostic. So we only forward a value
// that parses as a real IP and otherwise fall back to "" (the script then keeps
// whatever sb autodetects), keeping the probe robust against bad heartbeat data.
func (s *Server) nodeSBAddr(nodeID string) string {
	if n, ok := s.store.Node(nodeID); ok {
		if ip := strings.TrimSpace(n.PublicIP); ip != "" && net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

func (s *Server) handleSingBoxManageProbe(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	if !s.requireNodeScope(w, p, "task:run", req.NodeID) {
		return
	}
	s.pendingSingboxProbeMu.Lock()
	if s.pendingSingboxProbeNodeIDs == nil {
		s.pendingSingboxProbeNodeIDs = map[string]string{}
	}
	if pendingTaskID, alreadyPending := s.pendingSingboxProbeNodeIDs[req.NodeID]; alreadyPending {
		// Check whether the stored task is still active. If the agent went offline
		// or timed out without reporting a result, the entry is stale and should be
		// evicted so the operator can retry without restarting the server.
		taskStillActive := false
		if t, ok := s.store.Task(pendingTaskID); ok {
			taskStillActive = t.Status == model.TaskQueued || t.Status == model.TaskLeased
		}
		if taskStillActive {
			s.pendingSingboxProbeMu.Unlock()
			writeError(w, http.StatusConflict, errors.New("a probe is already in progress for this node"))
			return
		}
		// Stale entry: evict and allow a fresh probe.
		delete(s.pendingSingboxProbeNodeIDs, req.NodeID)
	}
	// Hold the mutex through task creation so the task ID is recorded
	// atomically — no concurrent probe can observe a blank-ID placeholder.
	task, err := s.queueSingBoxProbeTask(p, req.NodeID)
	if err != nil {
		s.pendingSingboxProbeMu.Unlock()
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.pendingSingboxProbeNodeIDs[req.NodeID] = task.ID
	s.pendingSingboxProbeMu.Unlock()
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), NodeID: req.NodeID, Action: "singbox.manage.probe", Scope: "task:run",
		Metadata: map[string]string{"task_id": task.ID},
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "task_id": task.ID})
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

func isSingBoxProbeTask(task model.Task) bool {
	return strings.Contains(task.Script, singBoxProbeScriptMarker+task.ID)
}

func (s *Server) handleSingBoxProbeTaskResult(r *http.Request, task model.Task, result model.TaskResult) {
	if !isSingBoxProbeTask(task) {
		return
	}
	inv := model.SingBoxInventory{
		NodeID: result.NodeID,
		At:     taskResultInventoryTime(result, s.now()),
		Status: "ok",
		Nodes:  []model.SingBoxNode{},
	}
	status := "ok"
	updateInventory := true
	if result.ExitCode != 0 || strings.TrimSpace(result.Error) != "" {
		status = "error"
		inv.Status = "error"
		inv.Error = taskFailureSummary(result)
		if isAgentExecDisabledTaskResult(result) {
			// This is a task-execution capability failure, not a sing-box
			// discovery failure. Do not erase a good read-only inventory reported
			// by an agent-side discovery source or sidecar; the operator should
			// still see the runtime config that is actually present on the box.
			status = "exec_disabled"
			updateInventory = false
		}
	} else if parsed, err := parseSingBoxProbeStdout(result.NodeID, inv.At, result.Stdout); err != nil {
		status = singBoxProbeResultParseFailed
		inv.Status = "error"
		inv.Error = truncateMetadataValue(fmt.Sprintf("%s (task %s; inspect Task History for stdout/stderr)", err.Error(), task.ID), 240)
	} else {
		inv = parsed
	}

	if updateInventory {
		s.singboxInvMu.Lock()
		if s.singboxInv == nil {
			s.singboxInv = map[string]model.SingBoxInventory{}
		}
		s.singboxInv[result.NodeID] = inv
		s.singboxInvMu.Unlock()
	}

	// Intentionally does NOT touch pendingSingboxProbeNodeIDs here.
	// Entries are evicted exclusively by handleSingBoxManageProbe during
	// stale detection (when the stored task is no longer Queued or Leased).
	// Clearing the entry here would race with a concurrent probe that has
	// already read a terminal task status, evicted the old entry, and written
	// a new task ID — this delete would silently remove that new entry.

	nodes := strconv.Itoa(len(inv.Nodes))
	s.recordRequestAudit(r, model.AuditEvent{
		ID:       id.New("audit"),
		NodeID:   result.NodeID,
		Action:   singBoxProbeResultAction,
		Decision: "allow",
		Metadata: singBoxProbeResultMetadata(task.ID, status, nodes, inv.Error),
	})
}

func singBoxProbeResultMetadata(taskID, status, nodes, errText string) map[string]string {
	metadata := map[string]string{
		"task_id": taskID,
		"status":  status,
		"nodes":   nodes,
	}
	if errText = strings.TrimSpace(errText); errText != "" {
		metadata["error"] = truncateMetadataValue(errText, 240)
	}
	return metadata
}

func isAgentExecDisabledTaskResult(result model.TaskResult) bool {
	msg := strings.ToLower(strings.TrimSpace(result.Error + "\n" + result.Stderr))
	return strings.Contains(msg, "agent task execution disabled") ||
		strings.Contains(msg, "restart with -allow-exec=true")
}

func taskResultInventoryTime(result model.TaskResult, fallback time.Time) time.Time {
	if !result.FinishedAt.IsZero() {
		return result.FinishedAt.UTC()
	}
	return fallback.UTC()
}

func parseSingBoxProbeStdout(nodeID string, at time.Time, stdout string) (model.SingBoxInventory, error) {
	listJSON, ok := probeSection(stdout, singBoxProbeListMarker, singBoxProbeProvisionMarker)
	if !ok {
		return model.SingBoxInventory{}, errors.New("probe stdout missing list marker")
	}
	var listResp struct {
		OK    bool                `json:"ok"`
		Count int                 `json:"count"`
		Nodes []model.SingBoxNode `json:"nodes"`
	}
	if err := decodeProbeJSONSection(listJSON, &listResp); err != nil {
		return model.SingBoxInventory{}, fmt.Errorf("decode probe list: %w", err)
	}
	inv := model.SingBoxInventory{
		NodeID: nodeID,
		At:     at.UTC(),
		Status: "ok",
		Nodes:  []model.SingBoxNode{},
	}
	if listResp.Nodes != nil {
		inv.Nodes = listResp.Nodes
	}
	if provisionJSON, ok := probeSection(stdout, singBoxProbeProvisionMarker, ""); ok {
		var provision struct {
			Version string `json:"version"`
		}
		if err := decodeProbeJSONSection(provisionJSON, &provision); err == nil {
			inv.CoreVersion = strings.TrimSpace(provision.Version)
		}
	}
	return inv, nil
}

func probeSection(stdout, startMarker, endMarker string) (string, bool) {
	start := strings.Index(stdout, startMarker)
	if start < 0 {
		return "", false
	}
	body := stdout[start+len(startMarker):]
	body = strings.TrimLeft(body, "\r\n")
	if endMarker != "" {
		if end := strings.Index(body, endMarker); end >= 0 {
			body = body[:end]
		}
	}
	return strings.TrimSpace(body), true
}

func decodeProbeJSONSection(section string, target any) error {
	jsonText, err := firstJSONObject(section)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(jsonText), target)
}

func firstJSONObject(section string) (string, error) {
	start := strings.Index(section, "{")
	if start < 0 {
		return "", errors.New("no JSON object found")
	}
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(section); i++ {
		ch := section[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}
		switch ch {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return section[start : i+1], nil
			}
		}
	}
	return "", errors.New("unterminated JSON object")
}
