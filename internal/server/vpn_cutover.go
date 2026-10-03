package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// The subscription hard cutover, prepared and never run on its own
// (operator answer 2026-10-02: "直接硬轮换吧"; r1-critic S-8; identity-sub
// 4.10). Every action here is an explicit operator call; nothing runs at
// boot or on deploy.
//
//	GET  /api/vpn/cutover                   what the cutover would do now, with a digest,
//	                                        and the batches it already filed
//	POST /api/vpn/cutover/rotate            rotate every exposed identity credential and file
//	                                        one plan_update per (identity, line) pair under
//	                                        one batch id; the request carries the digest the
//	                                        operator was shown
//	POST /api/vpn/cutover/retire-autosync   stop the external Sub-Store auto-sync for good
//
// What was exposed. The auto-sync (substore_sync.go) pushed the vpn-core
// fleet export, every legacy user's links and every adopted line's owner
// share_url, to the operator's external Sub-Store. Its plugin half, the
// latticenet.sub-store/import service, was dropped in Sub-Store
// 0.7.0-alpha.1 (2026-08-06, "drop the outbound push"), so a current plugin
// refuses the call and nothing has been pushed since. What the external
// store holds is what was pushed before that, and the credentials in it
// that still work are the ones nobody has rotated since. The preview
// approximates that set with the credentials the export would carry now:
// it can only over-count (a credential minted after the push looks exposed
// too), and over-rotating is harmless when every device is the operator's.
//
// What the line-user path can rotate is a Lattice identity's credential.
// The export exposes an identity's credential when it equals a credential
// in the export: a migrated identity carries its legacy user's uuid, which a
// managed render puts in a link, and an identity created with a line
// owner's credential is in that owner's share_url. Each exposed (identity,
// protocol) gets a fresh credential and a plan_update on every bound line of
// that protocol, so approving the batch re-sends the identity to each node
// with the new credential and the old one stops working there. An approval
// targets one node (model.Approval.Targets), so the batch is one approval
// per pair, each naming the batch in its hashed plan and its summary; a
// single approval spanning nodes would be a change to the approval model.
//
// What it cannot rotate: the owner entry of each adopted line (the line's
// first user, written by the node script before Lattice) is in its
// share_url, and it is not a Lattice identity, so no line-user plan touches
// it. The preview lists every such line under owner_entries; rotating them
// needs a line-level credential change on the node, which is not built.
//
// The auto-sync's only payload is the fleet export, and a link without its
// credential connects nothing, so nothing legitimate remains for it to
// carry. Retiring it records the decision in core-owned state and makes the
// sync a no-op with a status that says why, instead of pushing redacted
// links that would replace a client's working nodes with dead ones.

const (
	// subStoreAutoSyncRetiredMarker records the retirement in core-owned
	// state, out of the plugin's reach (store/state_markers.go).
	subStoreAutoSyncRetiredMarker = "decision:substore-autosync-retired"
	subStoreAutoSyncRetiredReason = "retired at the subscription cutover: the auto-sync pushed every user's credentials to the external Sub-Store; each person now gets their identity's own link"

	apiErrorCutoverPlanChanged = "cutover_plan_changed"

	cutoverBatchPrefix = "cutover"

	auditActionCutoverRotate   = "vpn.cutover.rotate"
	auditActionAutoSyncRetired = "substore.autosync.retire"
)

// cutoverPair is one (identity, line) plan_update the batch files.
type cutoverPair struct {
	LineHashID string `json:"line_hash_id"`
	NodeID     string `json:"node_id,omitempty"`
	NodeName   string `json:"node_name,omitempty"`
	LineName   string `json:"line_name,omitempty"`
	// Plannable is false when the pair cannot be planned now; Reason says
	// why (line_unknown, identity_disabled, identity_suspended, or the
	// line resolver's refusal).
	Plannable bool   `json:"plannable"`
	Reason    string `json:"reason,omitempty"`
}

// cutoverRotation is one exposed identity credential.
type cutoverRotation struct {
	IdentityID string `json:"identity_id"`
	Email      string `json:"email"`
	Protocol   string `json:"protocol"`
	// Exposure is where the export carries it: owner_share_url (an adopted
	// line's owner entry has the same credential) or managed_link (a
	// legacy user's rendered link).
	Exposure []string      `json:"exposure"`
	Pairs    []cutoverPair `json:"pairs"`
}

// cutoverOwnerEntry is an adopted line whose owner credential the export
// carries and no line-user plan can rotate.
type cutoverOwnerEntry struct {
	NodeID     string `json:"node_id"`
	NodeName   string `json:"node_name,omitempty"`
	LineHashID string `json:"line_hash_id,omitempty"`
	LineName   string `json:"line_name"`
	Protocol   string `json:"protocol,omitempty"`
	// SharedWithIdentity says a Lattice identity holds the same credential;
	// rotating that identity does not change the owner entry.
	SharedWithIdentity bool `json:"shared_with_identity"`
}

type cutoverAutoSyncView struct {
	// Configured is a saved external endpoint in the plugin's vault;
	// Enabled is that endpoint with the auto-sync flag set.
	Configured bool       `json:"configured"`
	Enabled    bool       `json:"enabled"`
	Retired    bool       `json:"retired"`
	RetiredAt  *time.Time `json:"retired_at,omitempty"`
	Reason     string     `json:"reason,omitempty"`
}

type cutoverLinksView struct {
	Identities int      `json:"identities"`
	Issued     int      `json:"issued"`
	NotIssued  []string `json:"not_issued"`
}

// cutoverBatchView is one rotate run's approvals, counted by status.
type cutoverBatchView struct {
	Batch     string         `json:"batch"`
	FiledAt   time.Time      `json:"filed_at"`
	Counts    map[string]int `json:"counts"`
	Pending   []string       `json:"pending"`
	Approvals int            `json:"approvals"`
}

// cutoverView is the preview. Digest covers exactly what rotate would do.
type cutoverView struct {
	Digest       string              `json:"digest"`
	GeneratedAt  time.Time           `json:"generated_at"`
	Rotations    []cutoverRotation   `json:"rotations"`
	OwnerEntries []cutoverOwnerEntry `json:"owner_entries"`
	AutoSync     cutoverAutoSyncView `json:"autosync"`
	Links        cutoverLinksView    `json:"links"`
	Batches      []cutoverBatchView  `json:"batches"`
	// Remaining names what this cutover cannot do, in the operator's words.
	Remaining []string `json:"remaining"`
}

// exportedSecrets returns every uuid and password the vpn-core export
// carries when it runs as the auto-sync ran it, split by where it came
// from. They never leave this function's callers.
func (s *Server) exportedSecrets() (owner, managed map[string]bool) {
	collect := func(request string) map[string]bool {
		out := map[string]bool{}
		raw, err := s.vpnCoreExportNodes([]byte(request), true)
		if err != nil {
			return out
		}
		var exp struct {
			Links []string `json:"links"`
		}
		if json.Unmarshal(raw, &exp) != nil {
			return out
		}
		for _, link := range exp.Links {
			for _, secret := range linkSecrets(link) {
				out[secret] = true
			}
		}
		return out
	}
	return collect(`{"include_managed":false}`), collect(`{"include_discovered":false}`)
}

// linkSecrets is every credential string one share link carries: the uuid
// and password shareURLCredential finds, and the password inside a socks
// link's base64 user:password.
func linkSecrets(link string) []string {
	var out []string
	uuid, password := shareURLCredential(link)
	if uuid != "" {
		out = append(out, strings.ToLower(uuid))
	}
	if password != "" {
		out = append(out, password)
		if decoded, ok := decodeLooseBase64(password); ok {
			if _, pass, ok := strings.Cut(string(decoded), ":"); ok && pass != "" {
				out = append(out, pass)
			}
		}
	}
	return out
}

func credentialExposed(c VpnCredential, secrets map[string]bool) bool {
	return (c.UUID != "" && secrets[strings.ToLower(c.UUID)]) || (c.Password != "" && secrets[c.Password])
}

// vpnCutoverPlan builds the preview from current state.
func (s *Server) vpnCutoverPlan() cutoverView {
	now := s.now()
	ownerSecrets, managedSecrets := s.exportedSecrets()
	groups, index := s.lineReadModel()
	nodeNames := map[string]string{}
	lineByNodeTag := map[string]string{}
	for _, g := range groups {
		nodeNames[g.NodeID] = g.NodeName
		for _, ln := range g.Lines {
			lineByNodeTag[g.NodeID+"\x00"+ln.Tag] = ln.LineHashID
		}
	}
	view := cutoverView{GeneratedAt: now.UTC(), Rotations: []cutoverRotation{}, OwnerEntries: []cutoverOwnerEntry{}}
	identitySecrets := map[string]bool{}
	view.Links.NotIssued = []string{}
	for _, u := range s.listVpnUsers() {
		view.Links.Identities++
		if u.Link != nil {
			view.Links.Issued++
		} else {
			view.Links.NotIssued = append(view.Links.NotIssued, u.ID)
		}
		for _, c := range u.Credentials {
			if c.UUID != "" {
				identitySecrets[strings.ToLower(c.UUID)] = true
			}
			if c.Password != "" {
				identitySecrets[c.Password] = true
			}
			var exposure []string
			if credentialExposed(c, ownerSecrets) {
				exposure = append(exposure, "owner_share_url")
			}
			if credentialExposed(c, managedSecrets) {
				exposure = append(exposure, "managed_link")
			}
			if len(exposure) == 0 {
				continue
			}
			protocol := normalizeSingBoxCredentialProtocol(c.Protocol)
			rotation := cutoverRotation{IdentityID: u.ID, Email: u.Email, Protocol: c.Protocol, Exposure: exposure, Pairs: []cutoverPair{}}
			for _, b := range u.Bindings {
				if !b.Enabled {
					continue
				}
				ln, known := index[b.LineHashID]
				if known && strings.ToLower(strings.TrimSpace(ln.Type)) != protocol {
					continue
				}
				pair := cutoverPair{LineHashID: b.LineHashID}
				if known {
					pair.NodeID, pair.NodeName, pair.LineName = ln.NodeID, nodeNames[ln.NodeID], identityLinkLineName(ln)
				}
				switch {
				case !known:
					pair.Reason = identityLineUnknown
				case !u.Enabled:
					pair.Reason = "identity_disabled"
				case vpnUserOperatorSuspension(u, now) != nil:
					pair.Reason = "identity_suspended"
				default:
					if _, err := s.resolveLineUserTarget(b.LineHashID); err != nil {
						pair.Reason = err.Error()
					} else {
						pair.Plannable = true
					}
				}
				rotation.Pairs = append(rotation.Pairs, pair)
			}
			view.Rotations = append(view.Rotations, rotation)
		}
	}
	for _, inv := range s.liveSingBoxInventories(now) {
		if inv.Status != "" && inv.Status != "ok" {
			continue
		}
		for _, n := range inv.Nodes {
			if strings.TrimSpace(n.ShareURL) == "" {
				continue
			}
			entry := cutoverOwnerEntry{NodeID: inv.NodeID, NodeName: nodeNames[inv.NodeID], LineName: strings.TrimSuffix(n.Name, ".json"), Protocol: n.Protocol,
				LineHashID: lineByNodeTag[inv.NodeID+"\x00"+n.Name]}
			for _, secret := range linkSecrets(n.ShareURL) {
				if identitySecrets[secret] {
					entry.SharedWithIdentity = true
				}
			}
			view.OwnerEntries = append(view.OwnerEntries, entry)
		}
	}
	sort.Slice(view.Rotations, func(i, j int) bool {
		if view.Rotations[i].IdentityID != view.Rotations[j].IdentityID {
			return view.Rotations[i].IdentityID < view.Rotations[j].IdentityID
		}
		return view.Rotations[i].Protocol < view.Rotations[j].Protocol
	})
	sort.Slice(view.OwnerEntries, func(i, j int) bool {
		if view.OwnerEntries[i].NodeID != view.OwnerEntries[j].NodeID {
			return view.OwnerEntries[i].NodeID < view.OwnerEntries[j].NodeID
		}
		return view.OwnerEntries[i].LineName < view.OwnerEntries[j].LineName
	})
	view.AutoSync = s.cutoverAutoSyncState()
	view.Batches = s.cutoverBatches()
	view.Digest = cutoverDigest(view.Rotations)
	view.Remaining = []string{}
	if len(view.OwnerEntries) > 0 {
		view.Remaining = append(view.Remaining, strconv.Itoa(len(view.OwnerEntries))+
			" adopted lines carry their owner's credential in the export; that entry is not a Lattice identity and needs a line-level credential change on the node, which Lattice cannot plan yet")
	}
	if len(view.Links.NotIssued) > 0 {
		view.Remaining = append(view.Remaining, strconv.Itoa(len(view.Links.NotIssued))+" identities have no link yet; issue one each before handing links out")
	}
	if !view.AutoSync.Retired {
		view.Remaining = append(view.Remaining, "the external Sub-Store auto-sync is not retired yet")
	}
	return view
}

// cutoverDigest hashes exactly what rotate acts on: each exposed identity
// credential and its pairs with their plannable state. A change to any of
// it between the preview and the action refuses the action.
func cutoverDigest(rotations []cutoverRotation) string {
	type pairKey struct {
		Line      string `json:"l"`
		Plannable bool   `json:"p"`
	}
	type rotationKey struct {
		Identity string    `json:"i"`
		Protocol string    `json:"r"`
		Pairs    []pairKey `json:"x"`
	}
	keys := make([]rotationKey, 0, len(rotations))
	for _, r := range rotations {
		k := rotationKey{Identity: r.IdentityID, Protocol: r.Protocol, Pairs: []pairKey{}}
		for _, p := range r.Pairs {
			k.Pairs = append(k.Pairs, pairKey{Line: p.LineHashID, Plannable: p.Plannable})
		}
		sort.Slice(k.Pairs, func(i, j int) bool { return k.Pairs[i].Line < k.Pairs[j].Line })
		keys = append(keys, k)
	}
	raw, _ := json.Marshal(keys)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// cutoverBatches lists the approvals each rotate run filed, newest batch
// first, so the console can show and approve a batch after a reload.
func (s *Server) cutoverBatches() []cutoverBatchView {
	byBatch := map[string]*cutoverBatchView{}
	for _, a := range s.store.Approvals() {
		if a.Plugin != singBoxLineUserPlugin || !strings.Contains(a.Plan, `"batch":"`+cutoverBatchPrefix+`_`) {
			continue
		}
		var plan lineUserPlan
		if json.Unmarshal([]byte(a.Plan), &plan) != nil || !strings.HasPrefix(plan.Batch, cutoverBatchPrefix+"_") {
			continue
		}
		b, ok := byBatch[plan.Batch]
		if !ok {
			b = &cutoverBatchView{Batch: plan.Batch, FiledAt: a.CreatedAt.UTC(), Counts: map[string]int{}, Pending: []string{}}
			byBatch[plan.Batch] = b
		}
		if a.CreatedAt.Before(b.FiledAt) {
			b.FiledAt = a.CreatedAt.UTC()
		}
		b.Approvals++
		b.Counts[a.Status]++
		if a.Status == model.ApprovalPending {
			b.Pending = append(b.Pending, a.ID)
		}
	}
	out := make([]cutoverBatchView, 0, len(byBatch))
	for _, b := range byBatch {
		sort.Strings(b.Pending)
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FiledAt.After(out[j].FiledAt) })
	return out
}

func (s *Server) cutoverAutoSyncState() cutoverAutoSyncView {
	view := cutoverAutoSyncView{}
	if raw, ok := s.pluginSecretValue(subStorePluginID, "endpoint"); ok && strings.TrimSpace(raw) != "" {
		view.Configured = true
	}
	_, view.Enabled = s.subStoreAutoSyncTarget()
	if at, ok := s.store.StateMarker(subStoreAutoSyncRetiredMarker); ok {
		view.Retired, view.Reason = true, subStoreAutoSyncRetiredReason
		at = at.UTC()
		view.RetiredAt = &at
	}
	return view
}

// subStoreAutoSyncRetired reports whether the operator retired the auto-sync.
func (s *Server) subStoreAutoSyncRetired() bool {
	_, ok := s.store.StateMarker(subStoreAutoSyncRetiredMarker)
	return ok
}

// cutoverRotateResult is what rotate did.
type cutoverRotateResult struct {
	Batch     string                 `json:"batch"`
	Digest    string                 `json:"digest"`
	Rotated   []cutoverRotatedResult `json:"rotated"`
	Approvals []string               `json:"approvals"`
	Skipped   []cutoverRotatedResult `json:"skipped"`
}

type cutoverRotatedResult struct {
	IdentityID string              `json:"identity_id"`
	Protocol   string              `json:"protocol"`
	Pairs      []cutoverPairResult `json:"pairs"`
	Reason     string              `json:"reason,omitempty"`
}

type cutoverPairResult struct {
	LineHashID string `json:"line_hash_id"`
	ApprovalID string `json:"approval_id,omitempty"`
	Error      string `json:"error,omitempty"`
}

var errCutoverPlanChanged = errors.New("the cutover plan changed since it was shown; review the new plan")

// runVpnCutoverRotate rotates each exposed identity credential that has at
// least one plannable pair, then files a plan_update for each plannable pair
// under one batch id. An identity credential with no plannable pair is
// left alone and reported: rotating it would only take its lines out of its
// link while the old credential kept working on the node.
//
// Rotate runs under cutoverMu. Two calls with one digest (a double click, an
// agent retry) would otherwise both pass the check, rotate the same
// credentials twice and file a second batch, leaving the first batch's
// approvals with a stale credential hash. Under the lock the second call
// builds its plan after the first rotated: a rotated credential no longer
// matches the export, its rotation leaves the plan, the digest moves, and
// the call is refused with cutover_plan_changed.
func (s *Server) runVpnCutoverRotate(p principal, digest string) (cutoverRotateResult, cutoverView, error) {
	s.cutoverMu.Lock()
	defer s.cutoverMu.Unlock()
	plan := s.vpnCutoverPlan()
	if strings.TrimSpace(digest) == "" || digest != plan.Digest {
		return cutoverRotateResult{}, plan, errCutoverPlanChanged
	}
	batch := id.New(cutoverBatchPrefix)
	result := cutoverRotateResult{Batch: batch, Digest: plan.Digest, Rotated: []cutoverRotatedResult{}, Approvals: []string{}, Skipped: []cutoverRotatedResult{}}
	for _, rotation := range plan.Rotations {
		plannable := 0
		for _, pair := range rotation.Pairs {
			if pair.Plannable {
				plannable++
			}
		}
		if plannable == 0 {
			result.Skipped = append(result.Skipped, cutoverRotatedResult{IdentityID: rotation.IdentityID, Protocol: rotation.Protocol, Pairs: []cutoverPairResult{},
				Reason: "no line can be planned for this credential now"})
			continue
		}
		request, _ := json.Marshal(map[string]string{"user_id": rotation.IdentityID, "protocol": rotation.Protocol})
		if _, err := s.vpnUserRotateCredential(p, request); err != nil {
			result.Skipped = append(result.Skipped, cutoverRotatedResult{IdentityID: rotation.IdentityID, Protocol: rotation.Protocol, Pairs: []cutoverPairResult{},
				Reason: "rotate failed: " + err.Error()})
			continue
		}
		done := cutoverRotatedResult{IdentityID: rotation.IdentityID, Protocol: rotation.Protocol, Pairs: []cutoverPairResult{}}
		for _, pair := range rotation.Pairs {
			if !pair.Plannable {
				done.Pairs = append(done.Pairs, cutoverPairResult{LineHashID: pair.LineHashID, Error: pair.Reason})
				continue
			}
			planRequest, _ := json.Marshal(map[string]string{"user_id": rotation.IdentityID, "line_hash_id": pair.LineHashID})
			out, err := s.vpnUserLinePlanInBatch(p, planRequest, lineUserOpUpdate, batch)
			if err != nil {
				done.Pairs = append(done.Pairs, cutoverPairResult{LineHashID: pair.LineHashID, Error: err.Error()})
				continue
			}
			var filed struct {
				Approval model.Approval `json:"approval"`
			}
			_ = json.Unmarshal(out, &filed)
			done.Pairs = append(done.Pairs, cutoverPairResult{LineHashID: pair.LineHashID, ApprovalID: filed.Approval.ID})
			if filed.Approval.ID != "" {
				result.Approvals = append(result.Approvals, filed.Approval.ID)
			}
		}
		result.Rotated = append(result.Rotated, done)
	}
	if len(result.Rotated) > 0 {
		s.triggerVPNCoreMutation()
		s.invalidateLineReadModel()
		s.invalidateCoreSourceShares()
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: auditActionCutoverRotate, Scope: "vpncore:admin", Decision: "allow",
		Metadata: map[string]string{"batch": batch, "digest": plan.Digest, "rotated": strconv.Itoa(len(result.Rotated)),
			"approvals": strconv.Itoa(len(result.Approvals)), "skipped": strconv.Itoa(len(result.Skipped))}})
	return result, plan, nil
}

// handleVpnCutover serves /api/vpn/cutover and its actions.
func (s *Server) handleVpnCutover(w http.ResponseWriter, r *http.Request, p principal) {
	action := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/api/vpn/cutover"), "/")
	if !s.requireGlobalProxyScope(w, p, "vpncore:admin") {
		return
	}
	switch {
	case action == "" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, s.vpnCutoverPlan())
	case action == "rotate" && r.Method == http.MethodPost:
		// Filing a plan per node is planning network changes.
		if !s.requireScope(w, p, "network:plan") {
			return
		}
		var req struct {
			Digest string `json:"digest"`
		}
		if !decodeLimitedJSON(w, r, &req, 4<<10) {
			return
		}
		result, plan, err := s.runVpnCutoverRotate(p, req.Digest)
		if errors.Is(err, errCutoverPlanChanged) {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error": model.APIError{Code: apiErrorCutoverPlanChanged, Message: err.Error()},
				"plan":  plan,
			})
			return
		}
		writeJSON(w, http.StatusOK, result)
	case action == "retire-autosync" && r.Method == http.MethodPost:
		if !s.requireScope(w, p, "substore:admin") {
			return
		}
		var req struct {
			Confirm bool `json:"confirm"`
		}
		if !decodeLimitedJSON(w, r, &req, 4<<10) {
			return
		}
		if !req.Confirm {
			writeError(w, http.StatusBadRequest, apiError(model.APIErrorBadRequest, "confirm must be true"))
			return
		}
		if !s.subStoreAutoSyncRetired() {
			if err := s.store.SetStateMarker(subStoreAutoSyncRetiredMarker, s.now()); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			s.writeSubStoreAutoSyncStatus(subStoreAutoSyncStatus{State: "retired", AttemptedAt: s.now().UTC().Format(time.RFC3339), Error: subStoreAutoSyncRetiredReason})
			s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: auditActionAutoSyncRetired, Scope: "substore:admin", Decision: "allow"})
		}
		writeJSON(w, http.StatusOK, s.cutoverAutoSyncState())
	default:
		writeError(w, http.StatusNotFound, errors.New("not found"))
	}
}
