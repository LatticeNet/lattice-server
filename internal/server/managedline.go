package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/proxycore"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// design-17: managed line overlay on adopted nodes. This file is the rollout
// compiler (S1) and the apply mechanics (S2) for one server-owned
// VLESS+REALITY+TCP inbound per node, applied as a conf-dir fragment alongside
// the node's existing 233boy lines — the 140 adopted lines are never
// re-rendered, converted, or restarted for their own sake.
//
// S2 channel decision (evidence-based, 2026-08-12): the apply rides the
// existing server→agent task pipeline as a server-rendered sh script — the
// same channel every adopted-track mutation already uses (probe/add/del/users
// in server_singbox_manage.go, and the lineuser approval flow in
// lineusers.go). A new agent verb was rejected: it would require a fleet-wide
// agent rollout before the feature could move a single line, and the task
// pipeline already delivers script + result + audit. The §9.3
// plugin-operation channel was rejected too: that path is for PLUGIN-compiled
// plans executed under a one-time grant, while the rollout is compiled by the
// server from the fleet projection. The atomicity contract lives in the
// script: write fragment → sing-box check → restart → verify → rollback, each
// failure exit leaving the node in its prior state.
//
// Secret discipline mirrors lineusers.go: the approval Plan is redacted
// (public key, hashes, names — never the REALITY private key, never the user
// credential). The private key is generated once at plan time and persisted in
// the server-side definition record (KV); the apply re-derives the user
// credential from the write-only VpnUser store, rebuilds the fragment, and
// fails closed when the bytes no longer match the approved SHA.
const (
	// singBoxManagedLinePlugin routes managed-line approvals through
	// managedLineApplyScript / handleManagedLineTaskResult.
	singBoxManagedLinePlugin = "singbox-managedline"
	// managedLineActionPrefix prefixes the fragment SHA-256 in approval.Action.
	managedLineActionPrefix = "apply-managed-line:"

	managedLinePluginVersion = "design-17"
	managedLineService       = "network/lines"
	managedLineMethod        = "managed_rollout_apply"

	// managedLineDefBucket stores the server-owned definition (secret-bearing:
	// reality private key) keyed by line_uuid.
	managedLineDefBucket = "managedline/def"

	managedLineDefaultCandidatePort = 24443
	// managedLinePortScanWindow bounds the upward scan from the candidate when
	// the candidate is taken, so port planning stays deliberate (design-17 D3)
	// instead of wandering the whole range.
	managedLinePortScanWindow = 64

	managedLineStatusPlanned = "planned"
	managedLineStatusApplied = "applied"
	managedLineStatusFailed  = "failed"
)

// managedLineDef is the server-owned definition of one overlay line. It is the
// record the read model and the future drift check compare discovery against
// (design-17 D7). Secret-bearing (RealityPrivateKey); it never serializes into
// an approval Plan or an HTTP response.
type managedLineDef struct {
	LineUUID          string    `json:"line_uuid"`
	NodeID            string    `json:"node_id"`
	LineHashID        string    `json:"line_hash_id"`
	Tag               string    `json:"tag"`
	Port              int       `json:"port"`
	SNI               string    `json:"sni"`
	HandshakeServer   string    `json:"handshake_server"`
	HandshakePort     int       `json:"handshake_port"`
	RealityPrivateKey string    `json:"reality_private_key"`
	RealityPublicKey  string    `json:"reality_public_key"`
	ShortID           string    `json:"short_id"`
	UserID            string    `json:"user_id"`
	UserName          string    `json:"user_name"`
	FragmentSHA256    string    `json:"fragment_sha256"`
	Status            string    `json:"status"`
	ApprovalID        string    `json:"approval_id"`
	LastError         string    `json:"last_error,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// managedLinePlan is the redacted, operator-reviewed approval payload.
type managedLinePlan struct {
	NodeID           string `json:"node_id"`
	LineUUID         string `json:"line_uuid"`
	LineHashID       string `json:"line_hash_id"`
	Tag              string `json:"tag"`
	Port             int    `json:"port"`
	SNI              string `json:"sni"`
	HandshakeServer  string `json:"handshake_server"`
	HandshakePort    int    `json:"handshake_port"`
	RealityPublicKey string `json:"reality_public_key"`
	ShortID          string `json:"short_id"`
	UserID           string `json:"user_id"`
	UserName         string `json:"user_name"`
	FragmentSHA256   string `json:"fragment_sha256"`
	Summary          string `json:"summary"`
}

// The fragment is a conf-dir partial config: exactly one vless+reality+tcp
// inbound and nothing else. It intentionally has NO "listen" key and no route
// rules — discovery then reports listen_host="" and outbound_ref="" for it,
// which is what the plan-time line_hash_id was computed over (the parity test
// pins this). Field order is fixed so the SHA-256 is stable.
type managedLineFragment struct {
	Inbounds []managedLineFragmentInbound `json:"inbounds"`
}

type managedLineFragmentInbound struct {
	Type       string                    `json:"type"`
	Tag        string                    `json:"tag"`
	ListenPort int                       `json:"listen_port"`
	Users      []managedLineFragmentUser `json:"users"`
	TLS        managedLineFragmentTLS    `json:"tls"`
}

type managedLineFragmentUser struct {
	Name string `json:"name"`
	UUID string `json:"uuid"`
	Flow string `json:"flow,omitempty"`
}

type managedLineFragmentTLS struct {
	Enabled    bool                       `json:"enabled"`
	ServerName string                     `json:"server_name"`
	Reality    managedLineFragmentReality `json:"reality"`
}

type managedLineFragmentReality struct {
	Enabled           bool                         `json:"enabled"`
	Handshake         managedLineFragmentHandshake `json:"handshake"`
	PrivateKey        string                       `json:"private_key"`
	ShortID           []string                     `json:"short_id"`
	MaxTimeDifference string                       `json:"max_time_difference"`
}

type managedLineFragmentHandshake struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
}

// managedLineFragmentBytes renders the canonical fragment for a definition plus
// the (re-derived) user credential. Both plan and apply call this; the SHA-256
// over the bytes is what the approval binds.
func managedLineFragmentBytes(def managedLineDef, cred lineUserCredentialPayload) ([]byte, error) {
	fragment := managedLineFragment{Inbounds: []managedLineFragmentInbound{{
		Type:       model.ProxyProtocolVLESS,
		Tag:        def.Tag,
		ListenPort: def.Port,
		Users: []managedLineFragmentUser{{
			Name: def.UserName,
			UUID: cred.UUID,
			Flow: cred.Flow,
		}},
		TLS: managedLineFragmentTLS{
			Enabled:    true,
			ServerName: def.SNI,
			Reality: managedLineFragmentReality{
				Enabled: true,
				Handshake: managedLineFragmentHandshake{
					Server:     def.HandshakeServer,
					ServerPort: def.HandshakePort,
				},
				PrivateKey:        def.RealityPrivateKey,
				ShortID:           []string{def.ShortID},
				MaxTimeDifference: "1m",
			},
		},
	}}}
	raw, err := json.Marshal(fragment)
	if err != nil {
		return nil, fmt.Errorf("render managed line fragment: %w", err)
	}
	return raw, nil
}

func managedLineFragmentSHA(def managedLineDef, cred lineUserCredentialPayload) (string, error) {
	raw, err := managedLineFragmentBytes(def, cred)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// managedLinePlannedHash recomputes the line_hash_id discovery will assign to
// the overlay line once it appears: the probe reports protocol=vless, no
// listen host, the fragment's tag, and no route-rule outbound for it.
func managedLinePlannedHash(nodeID, tag string, port int) string {
	return lineHash(nodeID, model.ProxyCoreSingbox, model.ProxyProtocolVLESS, "", port, tag, "")
}

func (s *Server) putManagedLineDef(def managedLineDef) error {
	public, private := splitManagedLineRecord(def)
	return s.store.PutManagedLineRecord(public, private)
}

func (s *Server) managedLineDefByUUID(lineUUID string) (managedLineDef, bool, error) {
	public, private, ok := s.store.ManagedLineRecord(lineUUID)
	if !ok {
		return managedLineDef{}, false, nil
	}
	return joinManagedLineRecord(public, private), true, nil
}

func (s *Server) managedLineDefs() ([]managedLineDef, error) {
	publicRecords, privateRecords := s.store.ManagedLineRecords()
	defs := make([]managedLineDef, 0, len(publicRecords))
	for lineUUID, public := range publicRecords {
		private, ok := privateRecords[lineUUID]
		if !ok {
			return nil, fmt.Errorf("managed line def %s is missing private material", lineUUID)
		}
		defs = append(defs, joinManagedLineRecord(public, private))
	}
	sort.Slice(defs, func(i, j int) bool {
		if defs[i].NodeID != defs[j].NodeID {
			return defs[i].NodeID < defs[j].NodeID
		}
		return defs[i].Tag < defs[j].Tag
	})
	return defs, nil
}

func splitManagedLineRecord(def managedLineDef) (store.ManagedLinePublicRecord, store.ManagedLineSecretRecord) {
	return store.ManagedLinePublicRecord{
		LineUUID: def.LineUUID, NodeID: def.NodeID, LineHashID: def.LineHashID, Tag: def.Tag,
		Port: def.Port, SNI: def.SNI, HandshakeServer: def.HandshakeServer, HandshakePort: def.HandshakePort,
		RealityPublicKey: def.RealityPublicKey, ShortID: def.ShortID, UserID: def.UserID, UserName: def.UserName,
		FragmentSHA256: def.FragmentSHA256, Status: def.Status, ApprovalID: def.ApprovalID,
		LastError: def.LastError, CreatedAt: def.CreatedAt, UpdatedAt: def.UpdatedAt,
	}, store.ManagedLineSecretRecord{RealityPrivateKey: def.RealityPrivateKey}
}

func joinManagedLineRecord(public store.ManagedLinePublicRecord, private store.ManagedLineSecretRecord) managedLineDef {
	return managedLineDef{
		LineUUID: public.LineUUID, NodeID: public.NodeID, LineHashID: public.LineHashID, Tag: public.Tag,
		Port: public.Port, SNI: public.SNI, HandshakeServer: public.HandshakeServer, HandshakePort: public.HandshakePort,
		RealityPrivateKey: private.RealityPrivateKey, RealityPublicKey: public.RealityPublicKey,
		ShortID: public.ShortID, UserID: public.UserID, UserName: public.UserName,
		FragmentSHA256: public.FragmentSHA256, Status: public.Status, ApprovalID: public.ApprovalID,
		LastError: public.LastError, CreatedAt: public.CreatedAt, UpdatedAt: public.UpdatedAt,
	}
}

// managedLineDefByNode returns the node's live definition (planned/applied),
// or the most recent failed one — design-17 D2 is one managed line per node,
// so at most one live definition exists.
func managedLineDefForNode(defs []managedLineDef, nodeID string) (managedLineDef, bool) {
	var failed *managedLineDef
	for i := range defs {
		if defs[i].NodeID != nodeID {
			continue
		}
		if defs[i].Status == managedLineStatusPlanned || defs[i].Status == managedLineStatusApplied {
			return defs[i], true
		}
		copy := defs[i]
		failed = &copy
	}
	if failed != nil {
		return *failed, true
	}
	return managedLineDef{}, false
}

// managedLineCamouflage picks the REALITY dest/SNI for the overlay from the
// node's existing reality lines (design-17 D6): the most common SNI wins,
// ties break lexicographically so re-plans are deterministic. A node with no
// reality line offers no camouflage evidence and is refused.
func managedLineCamouflage(inv model.SingBoxInventory) (string, bool) {
	counts := map[string]int{}
	for _, n := range inv.Nodes {
		if n.Network != "reality" {
			continue
		}
		sni := strings.TrimSpace(n.SNI)
		if sni == "" {
			continue
		}
		counts[sni]++
	}
	best := ""
	for sni, count := range counts {
		if count > counts[best] || (count == counts[best] && sni < best) {
			best = sni
		}
	}
	return best, best != ""
}

// managedLinePlanPort picks the line's port: the fleet-consistent candidate
// when free on this node, else the next free port above it (design-17 D3).
// Tags derive from the port, so a free port with a taken tag keeps scanning.
func managedLinePlanPort(candidate int, usedPorts map[int]bool, usedTags map[string]bool) (int, string, bool) {
	for port := candidate; port < candidate+managedLinePortScanWindow && port <= 65535; port++ {
		tag := "lattice-mng-" + strconv.Itoa(port)
		if usedPorts[port] || usedTags[tag] {
			continue
		}
		return port, tag, true
	}
	return 0, "", false
}

type managedLineRolloutRequest struct {
	UserID        string   `json:"user_id"`
	CandidatePort int      `json:"candidate_port,omitempty"`
	NodeIDs       []string `json:"node_ids,omitempty"`
}

type managedLinePlannedView struct {
	NodeID     string `json:"node_id"`
	ApprovalID string `json:"approval_id"`
	LineUUID   string `json:"line_uuid"`
	Tag        string `json:"tag"`
	Port       int    `json:"port"`
	SNI        string `json:"sni"`
}

type managedLineSkippedView struct {
	NodeID string `json:"node_id"`
	Reason string `json:"reason"`
}

// managedLineDefView is the redacted operator view of a definition (no private
// key, no user credential — the public key and names are not secret).
type managedLineDefView struct {
	LineUUID         string    `json:"line_uuid"`
	NodeID           string    `json:"node_id"`
	LineHashID       string    `json:"line_hash_id"`
	Tag              string    `json:"tag"`
	Port             int       `json:"port"`
	SNI              string    `json:"sni"`
	RealityPublicKey string    `json:"reality_public_key"`
	ShortID          string    `json:"short_id"`
	UserID           string    `json:"user_id"`
	UserName         string    `json:"user_name"`
	FragmentSHA256   string    `json:"fragment_sha256"`
	Status           string    `json:"status"`
	ApprovalID       string    `json:"approval_id"`
	LastError        string    `json:"last_error,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func toManagedLineDefView(def managedLineDef) managedLineDefView {
	return managedLineDefView{
		LineUUID: def.LineUUID, NodeID: def.NodeID, LineHashID: def.LineHashID,
		Tag: def.Tag, Port: def.Port, SNI: def.SNI,
		RealityPublicKey: def.RealityPublicKey, ShortID: def.ShortID,
		UserID: def.UserID, UserName: def.UserName, FragmentSHA256: def.FragmentSHA256,
		Status: def.Status, ApprovalID: def.ApprovalID, LastError: def.LastError,
		CreatedAt: def.CreatedAt, UpdatedAt: def.UpdatedAt,
	}
}

// handleManagedLineRollout is the design-17 S1 endpoint. GET lists the
// server-owned overlay definitions with their apply status. POST compiles
// per-node plans and files them as one approval batch (one event via the
// shared actor/action grouping) — it mutates nothing on any node.
func (s *Server) handleManagedLineRollout(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		defs, err := s.managedLineDefs()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		views := make([]managedLineDefView, 0, len(defs))
		for _, def := range defs {
			views = append(views, toManagedLineDefView(def))
		}
		writeJSON(w, http.StatusOK, map[string]any{"managed_lines": views})
	case http.MethodPost:
		var req managedLineRolloutRequest
		if !decodeClientJSON(w, r, &req) {
			return
		}
		planned, skipped, err := s.compileManagedLineRollout(r.Context(), p, req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID: id.New("audit"), Action: "network.lines.managed_rollout", Scope: "network:plan",
			Metadata: map[string]string{
				"user_id": strings.TrimSpace(req.UserID),
				"planned": strconv.Itoa(len(planned)),
				"skipped": strconv.Itoa(len(skipped)),
			},
		})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "planned": planned, "skipped": skipped})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

// compileManagedLineRollout builds one managed-line plan per eligible node and
// files each as a pending approval. Per-node isolation is structural: a node
// that fails validation is listed in skipped with its reason and never affects
// the batch (design-17 D5).
func (s *Server) compileManagedLineRollout(ctx context.Context, p principal, req managedLineRolloutRequest) ([]managedLinePlannedView, []managedLineSkippedView, error) {
	userID := strings.TrimSpace(req.UserID)
	if userID == "" {
		return nil, nil, errors.New("user_id is required")
	}
	u, ok := s.getVpnUser(userID)
	if !ok || !u.Enabled {
		return nil, nil, fmt.Errorf("vpn user %q not found or disabled", userID)
	}
	candidate := req.CandidatePort
	if candidate == 0 {
		candidate = managedLineDefaultCandidatePort
	}
	if candidate < 1 || candidate > 65535 {
		return nil, nil, fmt.Errorf("candidate_port must be 1-65535")
	}

	inventories := map[string]model.SingBoxInventory{}
	for _, inv := range s.liveSingBoxInventories(s.now()) {
		inventories[inv.NodeID] = inv
	}
	nodeIDs := uniqueNonEmpty(req.NodeIDs)
	if len(nodeIDs) == 0 {
		for nodeID := range inventories {
			nodeIDs = append(nodeIDs, nodeID)
		}
		sort.Strings(nodeIDs)
	}
	defs, err := s.managedLineDefs()
	if err != nil {
		return nil, nil, err
	}
	groups, _ := s.lineReadModel()
	usedPortsByNode := map[string]map[int]bool{}
	usedTagsByNode := map[string]map[string]bool{}
	for _, g := range groups {
		ports := map[int]bool{}
		tags := map[string]bool{}
		for _, ln := range g.Lines {
			if ln.ListenPort > 0 {
				ports[ln.ListenPort] = true
			}
			if ln.Tag != "" {
				tags[ln.Tag] = true
			}
		}
		usedPortsByNode[g.NodeID] = ports
		usedTagsByNode[g.NodeID] = tags
	}

	planned := []managedLinePlannedView{}
	skipped := []managedLineSkippedView{}
	for _, nodeID := range nodeIDs {
		skip := func(reason string) {
			skipped = append(skipped, managedLineSkippedView{NodeID: nodeID, Reason: reason})
		}
		if _, ok := s.store.Node(nodeID); !ok {
			skip("node not found")
			continue
		}
		inv, ok := inventories[nodeID]
		if !ok {
			skip("no sing-box inventory; probe the node first")
			continue
		}
		if inv.Status != "ok" {
			skip("sing-box inventory is not healthy: " + firstNonEmpty(inv.Error, inv.Status))
			continue
		}
		existing, hadExisting := managedLineDefForNode(defs, nodeID)
		if hadExisting &&
			(existing.Status == managedLineStatusPlanned || existing.Status == managedLineStatusApplied) {
			skip("managed line already " + existing.Status + " (tag " + existing.Tag + ")")
			continue
		}
		sni, ok := managedLineCamouflage(inv)
		if !ok {
			skip("no existing reality line to inherit camouflage from")
			continue
		}
		usedPorts := usedPortsByNode[nodeID]
		usedTags := usedTagsByNode[nodeID]
		if usedPorts == nil {
			usedPorts = map[int]bool{}
		}
		if usedTags == nil {
			usedTags = map[string]bool{}
		}
		// A failed definition re-plans in place: same port/tag/line_uuid (so the
		// on-box user name and the audit trail stay continuous), fresh keypair
		// and approval. Only when the failed line's own port has since been
		// taken does the node get a fresh identity.
		port, tag := 0, ""
		if hadExisting && !usedPorts[existing.Port] && !usedTags[existing.Tag] {
			port, tag = existing.Port, existing.Tag
		} else {
			var ok bool
			port, tag, ok = managedLinePlanPort(candidate, usedPorts, usedTags)
			if !ok {
				skip(fmt.Sprintf("no free port in [%d, %d)", candidate, candidate+managedLinePortScanWindow))
				continue
			}
		}

		now := s.now()
		lineHashID := managedLinePlannedHash(nodeID, tag, port)
		lineUUID, err := s.ensureLineUUID(lineHashID, nodeID)
		if err != nil {
			skip("allocate line_uuid: " + err.Error())
			continue
		}
		userName := userLineName(u.ID, lineUUID)
		cred, err := lineUserCredential(u, model.ProxyProtocolVLESS, userName)
		if err != nil {
			return nil, nil, fmt.Errorf("user %s: %w", u.ID, err)
		}
		priv, pub, err := proxycore.GenerateRealityKeypair()
		if err != nil {
			return nil, nil, err
		}
		shortID, err := proxycore.GenerateRealityShortID(4)
		if err != nil {
			return nil, nil, err
		}
		def := managedLineDef{
			LineUUID: lineUUID, NodeID: nodeID, LineHashID: lineHashID,
			Tag: tag, Port: port, SNI: sni,
			HandshakeServer: sni, HandshakePort: 443,
			RealityPrivateKey: priv, RealityPublicKey: pub, ShortID: shortID,
			UserID: u.ID, UserName: userName,
			Status: managedLineStatusPlanned, CreatedAt: now, UpdatedAt: now,
		}
		fragSHA, err := managedLineFragmentSHA(def, cred)
		if err != nil {
			return nil, nil, err
		}
		def.FragmentSHA256 = fragSHA

		summary := fmt.Sprintf("add lattice-managed vless+reality line %s on node %s (port %d, sni %s, user %s as %s, fragment sha %s…)",
			tag, nodeID, port, sni, u.Email, userName, fragSHA[:12])
		planJSON, err := json.Marshal(managedLinePlan{
			NodeID: nodeID, LineUUID: lineUUID, LineHashID: lineHashID,
			Tag: tag, Port: port, SNI: sni,
			HandshakeServer: def.HandshakeServer, HandshakePort: def.HandshakePort,
			RealityPublicKey: pub, ShortID: shortID,
			UserID: u.ID, UserName: userName, FragmentSHA256: fragSHA,
			Summary: summary,
		})
		if err != nil {
			return nil, nil, err
		}
		requestSHA := managedLineRequestSHA(u.ID, nodeID, port)
		approval := model.Approval{
			ID:             id.New("approval"),
			NodeID:         nodeID,
			Plugin:         singBoxManagedLinePlugin,
			Action:         managedLineActionPrefix + fragSHA,
			Plan:           string(planJSON),
			Status:         model.ApprovalPending,
			ActorID:        p.ActorID,
			CreatedAt:      now,
			UpdatedAt:      now,
			PluginVersion:  managedLinePluginVersion,
			Service:        managedLineService,
			Method:         managedLineMethod,
			RequestSHA256:  requestSHA,
			Targets:        []string{nodeID},
			ArtifactDigest: fragSHA,
		}
		if err := s.putManagedLineDef(def); err != nil {
			return nil, nil, err
		}
		stored, err := s.submitApproval(ctx, approval)
		if err != nil {
			return nil, nil, err
		}
		def.ApprovalID = stored.ID
		def.UpdatedAt = s.now()
		if err := s.putManagedLineDef(def); err != nil {
			return nil, nil, err
		}
		defs = append(defs, def)
		planned = append(planned, managedLinePlannedView{
			NodeID: nodeID, ApprovalID: stored.ID, LineUUID: lineUUID,
			Tag: tag, Port: port, SNI: sni,
		})
	}
	return planned, skipped, nil
}

func managedLineRequestSHA(userID, nodeID string, port int) string {
	raw, _ := json.Marshal(struct {
		UserID string `json:"user_id"`
		NodeID string `json:"node_id"`
		Port   int    `json:"port"`
	}{UserID: strings.TrimSpace(userID), NodeID: strings.TrimSpace(nodeID), Port: port})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// validateManagedLineApproval re-derives everything an approved plan depends
// on and fails closed on any drift — the same discipline as
// validateLineUserApproval. It runs at approve time, at apply-script render
// time, and again when the task result arrives.
func (s *Server) validateManagedLineApproval(approval model.Approval) (managedLinePlan, managedLineDef, lineUserCredentialPayload, error) {
	var zeroPlan managedLinePlan
	var zeroDef managedLineDef
	var zeroCred lineUserCredentialPayload
	if approval.Plugin != singBoxManagedLinePlugin || approval.PluginVersion != managedLinePluginVersion ||
		approval.Service != managedLineService || approval.Method != managedLineMethod {
		return zeroPlan, zeroDef, zeroCred, errors.New("typed approval plugin/service binding is invalid")
	}
	if len(approval.Targets) != 1 || approval.Targets[0] != approval.NodeID {
		return zeroPlan, zeroDef, zeroCred, errors.New("typed approval target binding is invalid")
	}
	if !strings.HasPrefix(approval.Action, managedLineActionPrefix) {
		return zeroPlan, zeroDef, zeroCred, fmt.Errorf("invalid approval action %q", approval.Action)
	}
	var plan managedLinePlan
	if err := json.Unmarshal([]byte(approval.Plan), &plan); err != nil {
		return zeroPlan, zeroDef, zeroCred, fmt.Errorf("invalid approval plan: %w", err)
	}
	if plan.NodeID != approval.NodeID || plan.FragmentSHA256 != strings.TrimPrefix(approval.Action, managedLineActionPrefix) ||
		plan.FragmentSHA256 != approval.ArtifactDigest ||
		managedLineRequestSHA(plan.UserID, plan.NodeID, plan.Port) != approval.RequestSHA256 {
		return zeroPlan, zeroDef, zeroCred, errors.New("typed approval plan binding changed; re-plan")
	}
	def, ok, err := s.managedLineDefByUUID(plan.LineUUID)
	if err != nil {
		return zeroPlan, zeroDef, zeroCred, err
	}
	if !ok {
		return zeroPlan, zeroDef, zeroCred, fmt.Errorf("managed line definition %s no longer exists; re-plan", plan.LineUUID)
	}
	if def.NodeID != plan.NodeID || def.LineHashID != plan.LineHashID || def.Tag != plan.Tag ||
		def.Port != plan.Port || def.SNI != plan.SNI || def.RealityPublicKey != plan.RealityPublicKey ||
		def.ShortID != plan.ShortID || def.UserID != plan.UserID || def.UserName != plan.UserName {
		return zeroPlan, zeroDef, zeroCred, errors.New("managed line definition changed since approval; re-plan")
	}
	if def.Status == managedLineStatusApplied {
		return zeroPlan, zeroDef, zeroCred, errors.New("managed line already applied")
	}
	if _, ok := s.store.Node(plan.NodeID); !ok {
		return zeroPlan, zeroDef, zeroCred, fmt.Errorf("node %q no longer exists; re-plan", plan.NodeID)
	}
	u, ok := s.getVpnUser(plan.UserID)
	if !ok || !u.Enabled {
		return zeroPlan, zeroDef, zeroCred, fmt.Errorf("vpn user %q no longer exists or is disabled; re-plan", plan.UserID)
	}
	cred, err := lineUserCredential(u, model.ProxyProtocolVLESS, plan.UserName)
	if err != nil {
		return zeroPlan, zeroDef, zeroCred, fmt.Errorf("re-derive credential: %w; re-plan", err)
	}
	fragSHA, err := managedLineFragmentSHA(def, cred)
	if err != nil {
		return zeroPlan, zeroDef, zeroCred, err
	}
	if fragSHA != plan.FragmentSHA256 {
		return zeroPlan, zeroDef, zeroCred, errors.New("credential or fragment changed since approval; re-plan")
	}
	// The port and tag must still be unclaimed on the node — by anything other
	// than this definition. A discovered or managed line that appeared since
	// planning turns the apply into a conflict instead of a clobber.
	for _, g := range s.buildLineGroups() {
		if g.NodeID != plan.NodeID {
			continue
		}
		for _, ln := range g.Lines {
			if ln.LineHashID == plan.LineHashID {
				return zeroPlan, zeroDef, zeroCred, errors.New("line already present on the node; rediscover and re-plan")
			}
			if ln.ListenPort == plan.Port {
				return zeroPlan, zeroDef, zeroCred, fmt.Errorf("port %d is now used by line %q on the node; re-plan", plan.Port, ln.Tag)
			}
			if ln.Tag == plan.Tag {
				return zeroPlan, zeroDef, zeroCred, fmt.Errorf("tag %q is now used by another line on the node; re-plan", plan.Tag)
			}
		}
	}
	return plan, def, cred, nil
}

// managedLineApplyScript renders the on-box apply for an approved plan. The
// atomicity contract (design-17 S2): write the fragment → sing-box check →
// restart → verify active → rollback on any failure. A check failure never
// restarts the service; a post-restart failure removes the fragment and
// restarts back onto the prior config.
func (s *Server) managedLineApplyScript(approval model.Approval) string {
	fail := func(err error) string {
		return "set -e\n" +
			"echo " + shellQuote("lattice managed-line: "+err.Error()) + " >&2\n" +
			"exit 1\n"
	}
	_, def, cred, err := s.validateManagedLineApproval(approval)
	if err != nil {
		return fail(err)
	}
	raw, err := managedLineFragmentBytes(def, cred)
	if err != nil {
		return fail(err)
	}
	fragB64 := base64.StdEncoding.EncodeToString(raw)
	return "set -e\n" +
		"TAG=" + shellQuote(def.Tag) + "\n" +
		"FRAG_B64=" + shellQuote(fragB64) + "\n" +
		"line=\"$(ps -eo args 2>/dev/null | grep '[s]ing-box run' | head -n 1 || true)\"\n" +
		"[ -n \"$line\" ] || line=\"$(systemctl cat sing-box 2>/dev/null | sed -n 's/^ExecStart=//p' | head -n 1 || true)\"\n" +
		"CONFDIR=\"\"\nSINGLEFILE=\"\"\n" +
		"if [ -n \"$line\" ]; then\n" +
		"  set -- $line\n" +
		"  while [ \"$#\" -gt 0 ]; do\n" +
		"    case \"$1\" in\n" +
		"      -C|--config-directory) shift; [ \"$#\" -gt 0 ] && [ -d \"$1\" ] && CONFDIR=\"$1\" ;;\n" +
		"      -C=*|--config-directory=*) d=\"${1#*=}\"; [ -d \"$d\" ] && CONFDIR=\"$d\" ;;\n" +
		"      -c|--config) shift; [ \"$#\" -gt 0 ] && SINGLEFILE=\"$1\" ;;\n" +
		"      -c=*|--config=*) SINGLEFILE=\"${1#*=}\" ;;\n" +
		"    esac\n" +
		"    shift || break\n" +
		"  done\n" +
		"fi\n" +
		"if [ -z \"$CONFDIR\" ] && [ -z \"$SINGLEFILE\" ] && [ -d /etc/sing-box/conf ]; then CONFDIR=/etc/sing-box/conf; fi\n" +
		"[ -n \"$CONFDIR\" ] || { echo " + shellQuote("lattice managed-line: node runs a single-file config; the overlay requires a -C config directory") + " >&2; exit 1; }\n" +
		"FRAG=\"$CONFDIR/$TAG.json\"\n" +
		"[ ! -e \"$FRAG\" ] || { echo " + shellQuote("lattice managed-line: fragment already exists on box; refusing to overwrite") + " >&2; exit 1; }\n" +
		"SB=\"$(command -v sing-box || true)\"\n" +
		"[ -n \"$SB\" ] || { echo " + shellQuote("lattice managed-line: sing-box binary not found") + " >&2; exit 1; }\n" +
		"printf '%s' \"$FRAG_B64\" | base64 -d > \"$FRAG.tmp\"\n" +
		"mv \"$FRAG.tmp\" \"$FRAG\"\n" +
		"if ! \"$SB\" check -C \"$CONFDIR\" > /tmp/lattice-managed-line-check.out 2>&1; then\n" +
		"  cat /tmp/lattice-managed-line-check.out >&2; rm -f \"$FRAG\" /tmp/lattice-managed-line-check.out\n" +
		"  echo " + shellQuote("lattice managed-line: sing-box check failed; fragment removed, service never restarted") + " >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"rm -f /tmp/lattice-managed-line-check.out\n" +
		"if ! systemctl restart sing-box 2>/dev/null; then\n" +
		"  rm -f \"$FRAG\"\n" +
		"  echo " + shellQuote("lattice managed-line: restart failed; fragment removed") + " >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"sleep 1\n" +
		"if ! systemctl is-active --quiet sing-box; then\n" +
		"  rm -f \"$FRAG\"\n" +
		"  systemctl restart sing-box >/dev/null 2>&1 || true\n" +
		"  echo " + shellQuote("lattice managed-line: service failed after apply; rolled back to the prior config") + " >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"echo " + shellQuote("__LATTICE_MANAGED_LINE_OK__") + " \"$TAG\"\n"
}

// handleManagedLineTaskResult reconciles a managed-line approval once the
// agent reports back. A failed task marks the definition failed with the
// reason (the node itself was rolled back by the script). A successful task
// marks the definition applied, queues rediscovery so the read model picks the
// line up on its planned identity, and re-arms the vpn-core auto-sync so fleet
// subscriptions gain the line (design-18 D8).
func (s *Server) handleManagedLineTaskResult(r *http.Request, approval model.Approval, task model.Task, result model.TaskResult) error {
	metadata := map[string]string{
		"approval_id": approval.ID, "task_id": task.ID, "plugin_id": approval.Plugin,
	}
	plan, def, _, validateErr := s.validateManagedLineApproval(approval)
	if result.Error != "" || result.ExitCode != 0 {
		reason := result.Error
		if reason == "" {
			reason = fmt.Sprintf("managed-line task exited %d", result.ExitCode)
		}
		if def.LineUUID != "" {
			def.Status = managedLineStatusFailed
			def.LastError = truncateMetadataValue(reason, 240)
			def.UpdatedAt = s.now()
			if err := s.putManagedLineDef(def); err != nil {
				return fmt.Errorf("persist failed managed line def: %w", err)
			}
		}
		// Execution failure is not a decision: the approval returns to pending
		// with the reason so the operator can fix the cause and re-approve the
		// same plan (the definition's status keeps the script-side outcome).
		approval.Status = model.ApprovalPending
		approval.Reason = "execution failed: " + reason
		approval.UpdatedAt = time.Now().UTC()
		if err := s.store.UpsertApproval(approval); err != nil {
			return fmt.Errorf("return failed managed-line approval to pending: %w", err)
		}
		s.recordRequestAudit(r, model.AuditEvent{
			ID: id.New("audit"), NodeID: approval.NodeID, Action: "network.lines.managed_rollout.failed",
			Decision: "deny", Reason: reason, Metadata: metadata,
		})
		return nil
	}
	if validateErr != nil {
		s.recordRequestAudit(r, model.AuditEvent{
			ID: id.New("audit"), NodeID: approval.NodeID, Action: "network.lines.managed_rollout.stale_result",
			Decision: "deny", Reason: "successful task belongs to a stale managed-line plan; runtime rediscovery required",
			Metadata: map[string]string{"approval_id": approval.ID, "task_id": task.ID, "validation_error": validateErr.Error()},
		})
		return nil
	}
	def.Status = managedLineStatusApplied
	def.LastError = ""
	def.UpdatedAt = s.now()
	if err := s.putManagedLineDef(def); err != nil {
		return fmt.Errorf("persist applied managed line def: %w", err)
	}
	approval.Status = model.ApprovalApplied
	approval.Reason = ""
	approval.UpdatedAt = time.Now().UTC()
	if err := s.store.UpsertApproval(approval); err != nil {
		return fmt.Errorf("mark managed-line approval applied: %w", err)
	}
	probeTaskID, probeErr := s.queueLineUserRediscovery(plan.NodeID)
	if probeErr != nil {
		metadata["rediscovery"] = "queue_failed"
	} else {
		metadata["rediscovery_task_id"] = probeTaskID
	}
	metadata["line_uuid"] = def.LineUUID
	metadata["tag"] = def.Tag
	s.invalidateLineReadModel()
	s.recordRequestAudit(r, model.AuditEvent{
		ID: id.New("audit"), NodeID: approval.NodeID, Action: "network.lines.managed_rollout.applied",
		Decision: "allow", Metadata: metadata,
	})
	// A new fleet line alters what subscriptions should serve (design-15 §7).
	s.triggerVPNCoreMutation()
	return nil
}
