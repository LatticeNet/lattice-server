package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// latticenet.sub-store/plans: the privileged-change path of design 28
// ("Security model"). Publishing a staged revision of a fleet-bound record to
// its live shares changes what existing token holders receive, so it rides
// plan, approve, apply like every other privileged change:
//
//  1. propose computes, for every live share on the record that names an
//     identity, which lines that identity gains, loses, receives changed and
//     has excluded when the record moves from its live revision to the staged
//     one; lists every live share that names no identity beside them; writes
//     that as the approval's plan; and files it through submitApproval;
//  2. the operator reads the plan and approves it with its plan_sha256, which
//     the generic approval path checks against the stored bytes, so the
//     approval covers exactly the text that was shown;
//  3. at the decision core previews both revisions again, and rejects the
//     plan as stale unless the record's live shares, its live revision and
//     every identity's diff are still what the operator read;
//  4. only then does core call the plugin's apply_revision, under the same
//     subscription mutation gate a record save takes, carrying a one-time
//     grant the plugin claims through claim_apply.
//
// The line diff needs the validate-and-bind step, which lives with the line
// catalogue. propose reaches it through subStoreBindPreviewer, a narrow
// interface the bind code implements; until it is wired, propose refuses.
//
// The plugin's half of the contract (design 28, slice S2), which core cannot
// enforce from this side and which the plugin's tests must:
//
//   - apply_revision first calls latticenet.sub-store/plans claim_apply with
//     its own request, and publishes nothing unless the answer is granted.
//     The grant exists only inside core's own call, once, so the method does
//     nothing when it is reached any other way: through the gateway (which
//     refuses it as well), from a schedule, or as a replay of an approved
//     plan whose apply failed. The manifest grants the plugin rpc.call on
//     plans/claim_apply for this;
//   - it makes Revision live only while ExpectedRevision is live;
//   - a revision id names fixed content: an edit stages a new revision id
//     and never rewrites a staged one, so the revision core previewed at the
//     decision is the revision the plugin publishes.

const (
	// subStorePlanApprovalPlugin is the approval's plugin column. It is a
	// core name, not the plugin's id: the plan is core's, and core applies
	// it, so nothing that routes plugin operations may mistake it for one.
	subStorePlanApprovalPlugin = "substore-plan"
	// subStorePlanActionPrefix starts the approval's action; the record id
	// follows, so a newer plan for one record supersedes only that record's.
	subStorePlanActionPrefix = "apply_revision:"
	// subStoreApplyRevisionMethod is the plugin method that publishes a
	// staged revision. This is the one non-test file that names it
	// (TestSubStoreApplyRevisionIsNamedOnlyByThePlanApplier).
	subStoreApplyRevisionMethod = "apply_revision"
	// subStorePlanKind names the plan document.
	subStorePlanKind = "substore.revision"
	// subStorePlanMaxBytes bounds one plan. A revision that changes every
	// line of a 4096-line record for many identities is split by the
	// operator rather than filed as a plan nobody can read.
	subStorePlanMaxBytes = 1 << 20
	// subStorePlanLineNameBytes and subStorePlanReasonBytes bound the two
	// free-text fields of a plan line.
	subStorePlanLineNameBytes = 120
	subStorePlanReasonBytes   = 64
	// subStorePlanUnboundCoverage is the plan's statement about the shares
	// it lists without a diff.
	subStorePlanUnboundCoverage = "unbound_shares receive the staged revision without identity binding; their lines are not diffed in this plan"

	auditActionSubStorePlanPropose = "substore.plan.propose"
	auditActionSubStorePlanApply   = "substore.plan.apply"
	auditActionSubStorePlanStale   = "substore.plan.stale"
	auditActionSubStorePlanClaim   = "substore.plan.claim"
)

// subStoreCoreOnlyReason is the gateway's refusal of apply_revision.
const subStoreCoreOnlyReason = "apply_revision runs only as the apply step of an approved Sub-Store plan"

// subStoreCoreOnlyMethod reports a plugin method that only core calls: the
// Sub-Store's apply_revision changes what existing share holders receive,
// so it runs as the apply step of an approved plan and never as an
// operator's gateway call, whatever a manifest declares.
// errSubStoreCoreOnlyMethod is the refusal of a core-only method called
// outside an approved plan apply.
var errSubStoreCoreOnlyMethod = errors.New("sub-store: apply_revision runs only inside an approved plan apply")

func subStoreCoreOnlyMethod(service, method string) bool {
	return service == subStorePluginID+"/subscription" && method == subStoreApplyRevisionMethod
}

// subStoreBindQuery asks for the validate-and-bind result of one record
// revision for one identity.
type subStoreBindQuery struct {
	PluginID       string
	SubscriptionID string
	// Revision is the record revision to render. Never empty: propose
	// names the live revision and the staged one explicitly.
	Revision   string
	IdentityID string
}

// subStoreBindLine is one entry in a bind result, or one exclusion in a
// plan. It carries no credential, no host and no template: a line is named
// by its line_uuid and its label.
type subStoreBindLine struct {
	// LineUUID is the line. Empty only for an exclusion of a plan node that
	// had no line (reason no_line).
	LineUUID string `json:"line_uuid,omitempty"`
	// Name is the entry's label, "<node name> <line name>" as identity
	// links write it.
	Name string `json:"name,omitempty"`
	// Reason is why the line is excluded (plan_rejected:<field>, no_line,
	// placeholder_count, service_down, lossy_template, graph_drifted, ...).
	// Empty for an included line.
	Reason string `json:"reason,omitempty"`
	// Digest is the previewer's digest of the bound, credential-free entry:
	// its label, its server and port, its transport and every other field
	// that decides what a client dials, and never a credential. Two entries
	// a client would use differently have different digests. A plan never
	// shows it; it folds it into the line's digest (subStorePlanFold).
	Digest string `json:"-"`
}

// subStoreBindResult is what one identity would receive from one revision.
type subStoreBindResult struct {
	// Included is every entry the identity would receive, one per clone.
	Included []subStoreBindLine
	// Excluded is every node the revision selects that would not be bound,
	// each with its Reason.
	Excluded []subStoreBindLine
	// LiveRevision is the record's live revision as the preview read it.
	// propose refuses a from_revision that is not live, and the decision
	// rejects a plan whose record has moved.
	LiveRevision string
}

// subStoreBindPreviewer runs validate-and-bind without serving anything:
// fetch or reuse the record's snapshot, render the named revision to a plan,
// validate every node against the catalogue, bind the identity, and report
// the entries included and excluded, credential-free, with the record's
// live revision. bind.preview answers the UI from the same step.
type subStoreBindPreviewer interface {
	PreviewBind(ctx context.Context, q subStoreBindQuery) (subStoreBindResult, error)
}

// subStoreApplyRevisionRequest is the payload of the plugin's
// latticenet.sub-store/subscription apply_revision method, and of the
// claim_apply call the plugin makes from inside it. The plugin makes
// Revision the record's live revision only when the live revision is still
// ExpectedRevision, and answers with the record and revision it applied.
type subStoreApplyRevisionRequest struct {
	SubscriptionID   string `json:"subscription_id"`
	Revision         string `json:"revision"`
	ExpectedRevision string `json:"expected_revision"`
	ApprovalID       string `json:"approval_id"`
	PlanSHA256       string `json:"plan_sha256"`
}

// subStoreApplyRevisionReply is apply_revision's reply.
type subStoreApplyRevisionReply struct {
	SubscriptionID string `json:"subscription_id"`
	Revision       string `json:"revision"`
}

// subStorePlan is the approval's plan: what the operator reads and what the
// approval's hash covers. Shares are listed one by one with their identity
// and their counts; the lines are listed once per identity, because every
// share of one identity on one record receives the same lines.
type subStorePlan struct {
	Kind           string              `json:"kind"`
	PluginID       string              `json:"plugin_id"`
	SubscriptionID string              `json:"subscription_id"`
	FromRevision   string              `json:"from_revision"`
	ToRevision     string              `json:"to_revision"`
	Totals         subStorePlanTotals  `json:"totals"`
	Shares         []subStorePlanShare `json:"shares"`
	// UnboundShares are the live shares that name no identity. They
	// receive the staged revision too; Coverage says what the plan does not
	// show about them.
	UnboundShares []subStorePlanUnboundShare `json:"unbound_shares"`
	Coverage      string                     `json:"coverage,omitempty"`
	Identities    []subStorePlanIdentity     `json:"identities"`
}

type subStorePlanTotals struct {
	Shares        int `json:"shares"`
	UnboundShares int `json:"unbound_shares"`
	Identities    int `json:"identities"`
	Added         int `json:"added"`
	Removed       int `json:"removed"`
	Changed       int `json:"changed"`
	Excluded      int `json:"excluded"`
}

type subStorePlanShare struct {
	ShareID     string     `json:"share_id"`
	Slug        string     `json:"slug"`
	DisplayName string     `json:"display_name,omitempty"`
	IdentityID  string     `json:"identity_id"`
	Enabled     bool       `json:"enabled"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Added       int        `json:"added"`
	Removed     int        `json:"removed"`
	Changed     int        `json:"changed"`
	Excluded    int        `json:"excluded"`
}

// subStorePlanUnboundShare is a live share on the record that names no
// identity. Its holders receive the staged revision rendered without
// identity binding, so the plan names them, and a share added or removed
// among them makes the plan stale like any other.
type subStorePlanUnboundShare struct {
	ShareID     string     `json:"share_id"`
	Slug        string     `json:"slug"`
	DisplayName string     `json:"display_name,omitempty"`
	Enabled     bool       `json:"enabled"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	// FleetCredentials marks a share created to publish the vpn-core fleet
	// export with no identity (share_fleet_feed.go).
	FleetCredentials bool `json:"fleet_credentials"`
}

// subStorePlanLineState is what one identity receives for one line from one
// revision: every entry's label, one per clone, and a digest over the
// entries.
type subStorePlanLineState struct {
	Names []string `json:"names"`
	// Digest is the SHA-256 over every entry's label and bound digest, so
	// a rename, a clone added or dropped, or a server or port moved inside
	// the line's allowed set changes it.
	Digest string `json:"digest"`
}

// subStorePlanLine is one line added or removed. Reason is set on a removed
// line the staged revision still selects and excludes.
type subStorePlanLine struct {
	LineUUID string `json:"line_uuid"`
	subStorePlanLineState
	Reason string `json:"reason,omitempty"`
}

// subStorePlanLineChange is a line received from both revisions, received
// differently.
type subStorePlanLineChange struct {
	LineUUID string                `json:"line_uuid"`
	Before   subStorePlanLineState `json:"before"`
	After    subStorePlanLineState `json:"after"`
}

type subStorePlanIdentity struct {
	IdentityID string `json:"identity_id"`
	// Added are lines the identity receives from the staged revision and
	// not from the live one.
	Added []subStorePlanLine `json:"added"`
	// Removed are lines the identity receives now and would no longer
	// receive.
	Removed []subStorePlanLine `json:"removed"`
	// Changed are lines received from both revisions whose entries differ.
	Changed []subStorePlanLineChange `json:"changed"`
	// Excluded is every exclusion of the staged revision for the identity.
	Excluded []subStoreBindLine `json:"excluded"`
	// Unchanged counts the lines received identically from both revisions.
	Unchanged int `json:"unchanged"`
}

type subStorePlansProposeRequest struct {
	SubscriptionID string `json:"subscription_id"`
	// FromRevision is the record's live revision, ToRevision the staged one
	// to publish.
	FromRevision string `json:"from_revision"`
	ToRevision   string `json:"to_revision"`
}

// subStorePlansProposeReply answers propose. Required is false when no live
// share on the record is fleet-bound (none names an identity and none
// publishes the fleet export): the record publishes without a plan.
type subStorePlansProposeReply struct {
	Required   bool   `json:"required"`
	Reason     string `json:"reason,omitempty"`
	ApprovalID string `json:"approval_id,omitempty"`
	PlanSHA256 string `json:"plan_sha256,omitempty"`
	// Plan is the approval's plan text, byte for byte: plan_sha256 is its
	// SHA-256, and approving with that hash approves exactly this text.
	Plan   string `json:"plan,omitempty"`
	Status string `json:"status,omitempty"`
}

type subStorePlansStatusRequest struct {
	ApprovalID     string `json:"approval_id"`
	SubscriptionID string `json:"subscription_id"`
}

type subStorePlanStatusRow struct {
	ApprovalID     string    `json:"approval_id"`
	Status         string    `json:"status"`
	Reason         string    `json:"reason,omitempty"`
	PlanSHA256     string    `json:"plan_sha256"`
	SubscriptionID string    `json:"subscription_id"`
	FromRevision   string    `json:"from_revision"`
	ToRevision     string    `json:"to_revision"`
	ActorID        string    `json:"actor_id,omitempty"`
	ApprovedBy     string    `json:"approved_by,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func (s *Server) subStorePlansRPC(ctx context.Context, method string, request []byte) ([]byte, error) {
	switch method {
	case "propose":
		p, err := s.subStoreSvcOperator(ctx, subStorePlansService, true, "proxy:admin")
		if err != nil {
			return nil, err
		}
		return s.subStorePlansPropose(ctx, p, request)
	case "status":
		// Reading a plan's state needs the domain's read scope; an
		// administrator who may propose may read what was proposed, which
		// the read scope alone does not imply.
		p, err := s.subStoreSvcOperator(ctx, subStorePlansService, false)
		if err != nil {
			return nil, err
		}
		readOK, reason := pluginGatewayScopeAllowed(p, "substore:read")
		if adminOK, _ := pluginGatewayScopeAllowed(p, "proxy:admin"); !readOK && !adminOK {
			return nil, rpcAPIError(http.StatusForbidden, model.APIErrorForbidden, subStorePlansService+": "+reason)
		}
		return s.subStorePlansStatus(request)
	case "claim_apply":
		// No operator scope: the grant on the context is the authority, and
		// only core's own apply call carries one.
		return s.subStorePlansClaimApply(ctx, request)
	default:
		return nil, fmt.Errorf("sub-store/plans: unknown method %q", method)
	}
}

// subStorePlanLiveShares is every live (not archived) share on a record,
// sorted by id: the shares whose holders a revision change reaches.
// Disabled and expired shares are included, because re-enabling or
// extending one would serve the new revision to its holders without a
// second review.
func (s *Server) subStorePlanLiveShares(subscriptionID string) []model.SubscriptionShare {
	var out []model.SubscriptionShare
	for _, share := range s.store.SubscriptionSharesUnordered() {
		if isSubStoreShare(share) && share.Source.SubscriptionID == subscriptionID && share.ArchivedAt == nil {
			out = append(out, share)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// subStorePlanRequired reports whether publishing to these shares is a
// privileged change: one of them names an identity, so core binds what its
// holders receive, or publishes the fleet export with no identity.
func subStorePlanRequired(shares []model.SubscriptionShare) bool {
	for _, share := range shares {
		if share.Source.IdentityID != "" || shareFleetCredentials(share) {
			return true
		}
	}
	return false
}

func (s *Server) subStorePlansPropose(ctx context.Context, p principal, request []byte) ([]byte, error) {
	var req subStorePlansProposeRequest
	if err := subStoreSvcDecode(subStorePlansService, "propose", request, &req); err != nil {
		return nil, err
	}
	if !subStoreSvcValidID(req.SubscriptionID) || !subStoreSvcValidID(req.FromRevision) || !subStoreSvcValidID(req.ToRevision) {
		return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "subscription_id, from_revision and to_revision are required")
	}
	if req.FromRevision == req.ToRevision {
		return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "from_revision and to_revision are the same revision")
	}
	shares := s.subStorePlanLiveShares(req.SubscriptionID)
	if !subStorePlanRequired(shares) {
		return json.Marshal(subStorePlansProposeReply{Required: false, Reason: "no live share on this record is fleet-bound"})
	}
	plan, err := s.subStoreBuildPlan(ctx, req, shares)
	if err != nil {
		return nil, err
	}
	text, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(text) > subStorePlanMaxBytes {
		return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest,
			fmt.Sprintf("the plan is %d bytes, over %d; publish the change in smaller revisions", len(text), subStorePlanMaxBytes))
	}
	canonicalRequest, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	requestSum := sha256.Sum256(canonicalRequest)
	now := s.now()
	approval := model.Approval{
		ID:            id.New("approval"),
		Plugin:        subStorePlanApprovalPlugin,
		Action:        subStorePlanActionPrefix + req.SubscriptionID,
		Plan:          string(text),
		Status:        model.ApprovalPending,
		ActorID:       p.ActorID,
		CreatedAt:     now,
		UpdatedAt:     now,
		RequestSHA256: hex.EncodeToString(requestSum[:]),
	}
	// The approval binds the plugin that will apply it: a plan proposed
	// against one build of the plugin is not applied by another.
	if loaded, ok := s.loadedPlugin(subStorePluginID); ok {
		approval.PluginVersion, approval.ArtifactDigest = loaded.Manifest.Version, loaded.ArtifactDigest
	}
	stored, err := s.submitApproval(ctx, approval)
	if err != nil {
		return nil, err
	}
	planSHA := approvalPlanSHA(approval)
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: auditActionSubStorePlanPropose, Scope: "proxy:admin", Decision: "allow",
		Metadata: map[string]string{
			"approval_id": approval.ID, "plan_sha256": planSHA, "subscription_id": req.SubscriptionID,
			"from_revision": req.FromRevision, "to_revision": req.ToRevision,
			"shares": fmt.Sprint(plan.Totals.Shares), "unbound_shares": fmt.Sprint(plan.Totals.UnboundShares),
			"added": fmt.Sprint(plan.Totals.Added), "removed": fmt.Sprint(plan.Totals.Removed),
			"changed": fmt.Sprint(plan.Totals.Changed), "excluded": fmt.Sprint(plan.Totals.Excluded),
			"via_rpc": subStorePlansService,
		},
	})
	return json.Marshal(subStorePlansProposeReply{
		Required: true, ApprovalID: approval.ID, PlanSHA256: planSHA, Plan: approval.Plan, Status: stored.Status,
	})
}

// subStorePlanProposeError maps a preview failure to propose's reply.
func subStorePlanProposeError(err error) error {
	var previewErr *subStorePlanPreviewError
	switch {
	case errors.Is(err, errSubStorePlanNotLive):
		return rpcAPIError(http.StatusConflict, subStoreSvcErrConflict, "from_revision is not the record's live revision; propose from the live revision")
	case errors.Is(err, errSubStorePlanNoPreviewer):
		return rpcAPIError(http.StatusServiceUnavailable, model.APIErrorBadGateway, err.Error())
	case errors.As(err, &previewErr):
		return rpcAPIError(http.StatusBadGateway, model.APIErrorBadGateway, err.Error())
	default:
		return err
	}
}

// subStoreBuildPlan previews both revisions once per identity, diffs them,
// and lists every live share.
func (s *Server) subStoreBuildPlan(ctx context.Context, req subStorePlansProposeRequest, shares []model.SubscriptionShare) (subStorePlan, error) {
	plan := subStorePlan{
		Kind: subStorePlanKind, PluginID: subStorePluginID, SubscriptionID: req.SubscriptionID,
		FromRevision: req.FromRevision, ToRevision: req.ToRevision,
		Shares: []subStorePlanShare{}, UnboundShares: []subStorePlanUnboundShare{},
	}
	var identityIDs []string
	seen := map[string]bool{}
	for _, share := range shares {
		if identityID := share.Source.IdentityID; identityID != "" && !seen[identityID] {
			seen[identityID] = true
			identityIDs = append(identityIDs, identityID)
		}
	}
	identities, err := s.subStorePlanIdentities(ctx, req.SubscriptionID, req.FromRevision, req.ToRevision, identityIDs)
	if err != nil {
		return subStorePlan{}, subStorePlanProposeError(err)
	}
	plan.Identities = identities
	byIdentity := make(map[string]subStorePlanIdentity, len(identities))
	for _, diff := range identities {
		byIdentity[diff.IdentityID] = diff
		plan.Totals.Added += len(diff.Added)
		plan.Totals.Removed += len(diff.Removed)
		plan.Totals.Changed += len(diff.Changed)
		plan.Totals.Excluded += len(diff.Excluded)
	}
	for _, share := range shares {
		identityID := share.Source.IdentityID
		if identityID == "" {
			plan.UnboundShares = append(plan.UnboundShares, subStorePlanUnboundShare{
				ShareID: share.ID, Slug: share.Slug, DisplayName: share.DisplayName,
				Enabled: share.Enabled, ExpiresAt: share.ExpiresAt, FleetCredentials: shareFleetCredentials(share),
			})
			continue
		}
		diff := byIdentity[identityID]
		plan.Shares = append(plan.Shares, subStorePlanShare{
			ShareID: share.ID, Slug: share.Slug, DisplayName: share.DisplayName, IdentityID: identityID,
			Enabled: share.Enabled, ExpiresAt: share.ExpiresAt,
			Added: len(diff.Added), Removed: len(diff.Removed), Changed: len(diff.Changed), Excluded: len(diff.Excluded),
		})
	}
	if len(plan.UnboundShares) > 0 {
		plan.Coverage = subStorePlanUnboundCoverage
	}
	plan.Totals.Shares, plan.Totals.UnboundShares, plan.Totals.Identities = len(plan.Shares), len(plan.UnboundShares), len(plan.Identities)
	return plan, nil
}

var (
	// errSubStorePlanNotLive: a preview read a live revision other than the
	// plan's from_revision.
	errSubStorePlanNotLive = errors.New("sub-store plans: from_revision is not the record's live revision")
	// errSubStorePlanNoPreviewer: the bind code is not wired on this server.
	errSubStorePlanNoPreviewer = errors.New("bind preview is not available on this server")
)

// subStorePlanPreviewError is a failed preview. It names the revision and
// the identity and nothing the previewer said, which may carry plugin
// diagnostics.
type subStorePlanPreviewError struct {
	revision, identityID string
}

func (e *subStorePlanPreviewError) Error() string {
	return fmt.Sprintf("bind preview failed for revision %s and identity %s", e.revision, e.identityID)
}

// subStorePlanIdentities previews both revisions once per identity, checks
// that every preview read from as the record's live revision, and diffs
// them, sorted by identity. With no identity it previews nothing.
func (s *Server) subStorePlanIdentities(ctx context.Context, subscriptionID, from, to string, identityIDs []string) ([]subStorePlanIdentity, error) {
	out := []subStorePlanIdentity{}
	if len(identityIDs) == 0 {
		return out, nil
	}
	previewer := s.subStoreSvc.previewer
	if previewer == nil {
		return nil, errSubStorePlanNoPreviewer
	}
	sorted := append([]string(nil), identityIDs...)
	sort.Strings(sorted)
	preview := func(revision, identityID string) (subStoreBindResult, error) {
		result, err := previewer.PreviewBind(ctx, subStoreBindQuery{
			PluginID: subStorePluginID, SubscriptionID: subscriptionID, Revision: revision, IdentityID: identityID,
		})
		if err != nil {
			s.logger.Printf("sub-store plans: bind preview failed for record %s revision %s identity %s (%s)",
				subscriptionID, revision, identityID, subscriptionDiagnosticSummary(err))
			return subStoreBindResult{}, &subStorePlanPreviewError{revision: revision, identityID: identityID}
		}
		if result.LiveRevision != from {
			return subStoreBindResult{}, errSubStorePlanNotLive
		}
		return result, nil
	}
	for _, identityID := range sorted {
		before, err := preview(from, identityID)
		if err != nil {
			return nil, err
		}
		after, err := preview(to, identityID)
		if err != nil {
			return nil, err
		}
		out = append(out, subStorePlanDiff(identityID, before, after))
	}
	return out, nil
}

// subStorePlanIdentityIDs is every identity a plan's shares name.
func subStorePlanIdentityIDs(plan subStorePlan) []string {
	var out []string
	seen := map[string]bool{}
	for _, share := range plan.Shares {
		if !seen[share.IdentityID] {
			seen[share.IdentityID] = true
			out = append(out, share.IdentityID)
		}
	}
	return out
}

// subStorePlanDiff compares what one identity receives from two revisions,
// line by line. A line received from both is unchanged only when its
// entries are: a rename, a clone added or dropped, or an entry the
// previewer digests differently makes it changed.
func subStorePlanDiff(identityID string, before, after subStoreBindResult) subStorePlanIdentity {
	was, now := subStorePlanFold(before.Included), subStorePlanFold(after.Included)
	excludedNow := map[string]string{}
	diff := subStorePlanIdentity{IdentityID: identityID, Added: []subStorePlanLine{}, Removed: []subStorePlanLine{},
		Changed: []subStorePlanLineChange{}, Excluded: []subStoreBindLine{}}
	for _, line := range after.Excluded {
		line = subStorePlanCleanLine(line)
		if line.Reason == "" {
			line.Reason = "excluded"
		}
		diff.Excluded = append(diff.Excluded, line)
		if line.LineUUID != "" {
			if _, seen := excludedNow[line.LineUUID]; !seen {
				excludedNow[line.LineUUID] = line.Reason
			}
		}
	}
	for lineUUID, state := range now {
		previous, ok := was[lineUUID]
		switch {
		case !ok:
			diff.Added = append(diff.Added, subStorePlanLine{LineUUID: lineUUID, subStorePlanLineState: state})
		case previous.Digest != state.Digest:
			diff.Changed = append(diff.Changed, subStorePlanLineChange{LineUUID: lineUUID, Before: previous, After: state})
		default:
			diff.Unchanged++
		}
	}
	for lineUUID, state := range was {
		if _, ok := now[lineUUID]; ok {
			continue
		}
		diff.Removed = append(diff.Removed, subStorePlanLine{LineUUID: lineUUID, subStorePlanLineState: state, Reason: excludedNow[lineUUID]})
	}
	for _, lines := range [][]subStorePlanLine{diff.Added, diff.Removed} {
		sort.Slice(lines, func(i, j int) bool { return lines[i].LineUUID < lines[j].LineUUID })
	}
	sort.Slice(diff.Changed, func(i, j int) bool { return diff.Changed[i].LineUUID < diff.Changed[j].LineUUID })
	sort.Slice(diff.Excluded, func(i, j int) bool {
		a, b := diff.Excluded[i], diff.Excluded[j]
		if a.LineUUID != b.LineUUID {
			return a.LineUUID < b.LineUUID
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Reason < b.Reason
	})
	return diff
}

// subStorePlanFold folds the entries of one bind result into one state per
// line. The digest is taken over the entries as the previewer gave them,
// length-prefixed and sorted, so it sees a difference the bounded label
// shown in the plan would hide; the names are the bounded labels.
func subStorePlanFold(entries []subStoreBindLine) map[string]subStorePlanLineState {
	type entry struct{ shown, name, digest string }
	byLine := map[string][]entry{}
	for _, raw := range entries {
		clean := subStorePlanCleanLine(raw)
		if clean.LineUUID == "" {
			continue
		}
		byLine[clean.LineUUID] = append(byLine[clean.LineUUID], entry{shown: clean.Name, name: raw.Name, digest: raw.Digest})
	}
	out := make(map[string]subStorePlanLineState, len(byLine))
	for lineUUID, list := range byLine {
		sort.Slice(list, func(i, j int) bool {
			if list[i].name != list[j].name {
				return list[i].name < list[j].name
			}
			return list[i].digest < list[j].digest
		})
		sum := sha256.New()
		names := make([]string, 0, len(list))
		for _, e := range list {
			names = append(names, e.shown)
			fmt.Fprintf(sum, "%d:%s|%d:%s\n", len(e.name), e.name, len(e.digest), e.digest)
		}
		out[lineUUID] = subStorePlanLineState{Names: names, Digest: hex.EncodeToString(sum.Sum(nil))}
	}
	return out
}

// subStorePlanCleanLine bounds a line's text fields and drops control
// characters, so a plan reads as one line per entry whatever a record named
// its nodes. The digest is dropped: a plan never shows it.
func subStorePlanCleanLine(line subStoreBindLine) subStoreBindLine {
	clean := func(value string, limit int) string {
		value = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, strings.TrimSpace(value))
		for len(value) > limit {
			_, size := utf8.DecodeLastRuneInString(value)
			value = value[:len(value)-size]
		}
		return value
	}
	return subStoreBindLine{
		LineUUID: clean(line.LineUUID, 36),
		Name:     clean(line.Name, subStorePlanLineNameBytes),
		Reason:   clean(line.Reason, subStorePlanReasonBytes),
	}
}

func (s *Server) subStorePlansStatus(request []byte) ([]byte, error) {
	var req subStorePlansStatusRequest
	if err := subStoreSvcDecode(subStorePlansService, "status", request, &req); err != nil {
		return nil, err
	}
	if (req.ApprovalID == "") == (req.SubscriptionID == "") {
		return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "status takes approval_id or subscription_id, not both")
	}
	rows := []subStorePlanStatusRow{}
	add := func(approval model.Approval) {
		var plan subStorePlan
		if approval.Plugin != subStorePlanApprovalPlugin || json.Unmarshal([]byte(approval.Plan), &plan) != nil {
			return
		}
		if req.SubscriptionID != "" && plan.SubscriptionID != req.SubscriptionID {
			return
		}
		rows = append(rows, subStorePlanStatusRow{
			ApprovalID: approval.ID, Status: approval.Status, Reason: approval.Reason, PlanSHA256: approvalPlanSHA(approval),
			SubscriptionID: plan.SubscriptionID, FromRevision: plan.FromRevision, ToRevision: plan.ToRevision,
			ActorID: approval.ActorID, ApprovedBy: approval.ApprovedBy, CreatedAt: approval.CreatedAt, UpdatedAt: approval.UpdatedAt,
		})
	}
	if req.ApprovalID != "" {
		approval, ok := s.store.Approval(req.ApprovalID)
		if ok {
			add(approval)
		}
		if len(rows) == 0 {
			return nil, rpcAPIError(http.StatusNotFound, model.APIErrorNotFound, "plan not found")
		}
	} else {
		for _, approval := range s.store.Approvals() {
			add(approval)
		}
		sort.Slice(rows, func(i, j int) bool {
			if !rows[i].CreatedAt.Equal(rows[j].CreatedAt) {
				return rows[i].CreatedAt.After(rows[j].CreatedAt)
			}
			return rows[i].ApprovalID < rows[j].ApprovalID
		})
	}
	return json.Marshal(map[string]any{"plans": rows})
}

// isSubStorePlanApproval reports an approval this file files and applies.
func isSubStorePlanApproval(approval model.Approval) bool {
	return approval.Plugin == subStorePlanApprovalPlugin
}

// subStorePlanApprove is approveApprovalCore's branch for a Sub-Store plan,
// reached after the generic path has checked the plan hash against the
// stored bytes. It previews the plan's revisions again, checks under the
// share-write lock that the plan still describes the record, moves the
// approval from pending to approved exactly once, releases the lock, and
// only then calls apply_revision.
//
// What is checked is everything the plan was computed from: the plugin
// build, the set of live shares on the record with the identity each
// serves, the record's live revision, and what each identity would receive
// from each revision. A share created, archived or restored, a revision
// re-staged under its id, or a catalogue change that binds a line
// differently all mean an existing holder would receive what nobody
// reviewed, so the plan is rejected as stale. That includes an exclusion a
// service outage or a probe verdict causes: a plan approved while a line
// flaps is proposed again rather than applied over a diff nobody read.
func (s *Server) subStorePlanApprove(ctx context.Context, p principal, approval model.Approval, queueApply bool) (model.Approval, error) {
	if !queueApply {
		return approval, &approvalDecisionError{status: http.StatusBadRequest, err: apiError(model.APIErrorBadRequest,
			"a sub-store plan is applied when it is approved: approve with queue_apply")}
	}
	var plan subStorePlan
	if err := json.Unmarshal([]byte(approval.Plan), &plan); err != nil || plan.Kind != subStorePlanKind ||
		plan.PluginID != subStorePluginID || !subStoreSvcValidID(plan.SubscriptionID) {
		return approval, &approvalDecisionError{status: http.StatusConflict, err: apiError(model.APIErrorApprovalStale, "the plan is not a sub-store revision plan")}
	}
	// A decision that arrives after another answers what the first one
	// left, rather than previewing a plan that is no longer pending.
	current, ok := s.store.Approval(approval.ID)
	if !ok {
		return approval, &approvalDecisionError{status: http.StatusNotFound, err: apiError(model.APIErrorNotFound, "approval not found")}
	}
	if current.Status != model.ApprovalPending {
		return current, nil
	}

	// The previews run outside the share-write lock: one may fetch and
	// render, and no share write waits on it. The lock below then checks
	// that the shares the previews were made for are still the record's.
	identities, err := s.subStorePlanIdentities(ctx, plan.SubscriptionID, plan.FromRevision, plan.ToRevision, subStorePlanIdentityIDs(plan))
	staleReason := ""
	var previewErr *subStorePlanPreviewError
	switch {
	case err == nil:
	case errors.Is(err, errSubStorePlanNotLive):
		staleReason = "the record's live revision moved since this plan was proposed; propose it again"
	case errors.Is(err, errSubStorePlanNoPreviewer):
		// A preview that could not run says nothing about the plan: it
		// stays pending, and the operator decides again.
		return approval, &approvalDecisionError{status: http.StatusServiceUnavailable,
			err: apiError(model.APIErrorBadGateway, "bind preview is not available on this server; the plan stays pending")}
	case errors.As(err, &previewErr):
		return approval, &approvalDecisionError{status: http.StatusBadGateway,
			err: apiError(model.APIErrorBadGateway, previewErr.Error()+"; the plan stays pending")}
	default:
		return approval, &approvalDecisionError{status: http.StatusInternalServerError, err: err}
	}

	release := s.subStoreSvcLockShareWrites()
	decided, approvedNow, err := s.subStorePlanDecide(p, approval, plan, identities, staleReason)
	release()
	if err != nil || !approvedNow {
		return decided, err
	}

	planSHA := approvalPlanSHA(approval)
	applyReq := subStoreApplyRevisionRequest{
		SubscriptionID: plan.SubscriptionID, Revision: plan.ToRevision, ExpectedRevision: plan.FromRevision,
		ApprovalID: approval.ID, PlanSHA256: planSHA,
	}
	claimed, err := s.subStorePlanApply(ctx, applyReq)
	if err != nil {
		// The approval stays approved and unapplied, as a plugin operation's
		// does: the record did not move, and the operator proposes again.
		// Nothing can apply it later: its grant died with this call. The
		// reason is fixed text, because the plugin's message is not trusted
		// to be free of record content.
		const reason = "apply_revision failed; the record is unchanged, propose the revision again"
		if current, ok, _ := s.store.MutateApproval(approval.ID, func(a *model.Approval) bool {
			if a.Status != model.ApprovalApproved {
				return false
			}
			a.Reason, a.UpdatedAt = reason, s.now()
			return true
		}); ok {
			decided = current
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID: id.New("audit"), Action: auditActionSubStorePlanApply, Scope: "proxy:admin", Decision: "deny",
			Reason: "apply_revision failed",
			Metadata: map[string]string{"approval_id": approval.ID, "plan_sha256": planSHA, "subscription_id": plan.SubscriptionID,
				"to_revision": plan.ToRevision, "grant_claimed": strconv.FormatBool(claimed)},
		})
		return decided, &approvalDecisionError{status: http.StatusBadGateway, err: apiError(model.APIErrorBadGateway, reason)}
	}
	if !claimed {
		// The plugin published without asking whether core called it, so it
		// would publish for any caller. The apply is real and is recorded
		// as applied; the audit and the log say the contract was not kept.
		s.logger.Printf("sub-store plans: apply_revision for approval %s answered without claiming its grant; the plugin does not check that core called it", approval.ID)
	}
	applied, _, err := s.store.MutateApproval(approval.ID, func(a *model.Approval) bool {
		if a.Status != model.ApprovalApproved {
			return false
		}
		a.Status, a.Reason, a.UpdatedAt = model.ApprovalApplied, "", s.now()
		return true
	})
	if err != nil {
		return decided, &approvalDecisionError{status: http.StatusInternalServerError, err: err}
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: auditActionSubStorePlanApply, Scope: "proxy:admin", Decision: "allow",
		Metadata: map[string]string{
			"approval_id": approval.ID, "plan_sha256": planSHA, "subscription_id": plan.SubscriptionID,
			"from_revision": plan.FromRevision, "to_revision": plan.ToRevision,
			"shares": fmt.Sprint(len(plan.Shares)), "unbound_shares": fmt.Sprint(len(plan.UnboundShares)),
			"grant_claimed": strconv.FormatBool(claimed),
		},
	})
	return applied, nil
}

// subStorePlanDecide runs under the share-write lock. It answers the
// approval as another decision left it, rejects the plan as stale, or moves
// it from pending to approved; approved is true only in the last case.
func (s *Server) subStorePlanDecide(p principal, approval model.Approval, plan subStorePlan, identities []subStorePlanIdentity, staleReason string) (model.Approval, bool, error) {
	current, ok := s.store.Approval(approval.ID)
	if !ok {
		return approval, false, &approvalDecisionError{status: http.StatusNotFound, err: apiError(model.APIErrorNotFound, "approval not found")}
	}
	if current.Status != model.ApprovalPending {
		return current, false, nil
	}
	if staleReason == "" {
		staleReason = s.subStorePlanStaleReason(approval, plan, identities)
	}
	if staleReason != "" {
		rejected, ok, err := s.store.MutateApproval(approval.ID, func(a *model.Approval) bool {
			if a.Status != model.ApprovalPending {
				return false
			}
			a.Status, a.Reason, a.UpdatedAt = model.ApprovalRejected, staleReason, s.now()
			return true
		})
		if err != nil {
			return approval, false, &approvalDecisionError{status: http.StatusInternalServerError, err: err}
		}
		if !ok {
			return rejected, false, nil
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID: id.New("audit"), Action: auditActionSubStorePlanStale, Scope: "proxy:admin", Decision: "deny", Reason: staleReason,
			Metadata: map[string]string{"approval_id": approval.ID, "subscription_id": plan.SubscriptionID},
		})
		return approval, false, &approvalDecisionError{status: http.StatusConflict, err: apiError(model.APIErrorApprovalStale, staleReason)}
	}
	// Pending to approved exactly once: of two decisions racing on one
	// approval, one applies and the other answers what it finds.
	approved, ok, err := s.store.MutateApproval(approval.ID, func(a *model.Approval) bool {
		if a.Status != model.ApprovalPending {
			return false
		}
		a.Status, a.ApprovedBy, a.UpdatedAt = model.ApprovalApproved, p.ActorID, s.now()
		return true
	})
	if err != nil {
		return approval, false, &approvalDecisionError{status: http.StatusInternalServerError, err: err}
	}
	if !ok {
		current, _ := s.store.Approval(approval.ID)
		return current, false, nil
	}
	return approved, true, nil
}

// subStorePlanStaleReason names what moved since the plan was proposed, or
// returns "". identities is what each of the plan's identities would
// receive, previewed at this decision.
func (s *Server) subStorePlanStaleReason(approval model.Approval, plan subStorePlan, identities []subStorePlanIdentity) string {
	if approval.PluginVersion != "" {
		loaded, ok := s.loadedPlugin(subStorePluginID)
		if !ok || loaded.Manifest.Version != approval.PluginVersion || !equalFoldHex(loaded.ArtifactDigest, approval.ArtifactDigest) {
			return "the sub-store plugin changed since this plan was proposed; propose it again"
		}
	}
	const sharesMoved = "the record's live shares changed since this plan was proposed; propose it again"
	want := make(map[string]string, len(plan.Shares)+len(plan.UnboundShares))
	for _, share := range plan.Shares {
		want[share.ShareID] = share.IdentityID
	}
	for _, share := range plan.UnboundShares {
		want[share.ShareID] = ""
	}
	live := s.subStorePlanLiveShares(plan.SubscriptionID)
	if len(live) != len(want) {
		return sharesMoved
	}
	for _, share := range live {
		if identityID, ok := want[share.ID]; !ok || identityID != share.Source.IdentityID {
			return sharesMoved
		}
	}
	got, errGot := json.Marshal(identities)
	reviewed, errReviewed := json.Marshal(plan.Identities)
	if errGot != nil || errReviewed != nil || !bytes.Equal(got, reviewed) {
		return "what the record's shares would receive changed since this plan was proposed; propose it again"
	}
	return ""
}

// subStoreApplyGrant is core's authority for one apply_revision call: bound
// to one approved plan, claimable once, and only while core's call is in
// flight. It travels on the call's context, which the plugin's host calls
// inherit (plugin.SystemRunner hands the invocation context to the broker)
// and which never crosses into the plugin, so nothing the plugin or an
// operator holds can mint one. The plugin operation grant of section 9.3
// travels the same way.
type subStoreApplyGrant struct {
	mu      sync.Mutex
	req     subStoreApplyRevisionRequest
	claimed bool
	closed  bool
}

type subStoreApplyGrantKey struct{}

// claim grants once, for the request core made, while the call runs.
func (g *subStoreApplyGrant) claim(req subStoreApplyRevisionRequest) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.claimed || req != g.req {
		return false
	}
	g.claimed = true
	return true
}

// close ends the grant when core's call returns and reports whether the
// plugin claimed it.
func (g *subStoreApplyGrant) close() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	return g.claimed
}

// subStorePlansClaimApply answers claim_apply, which the plugin calls from
// inside apply_revision. It grants once, and only when the call it is made
// from is core's own apply of the approved plan the request names.
func (s *Server) subStorePlansClaimApply(ctx context.Context, request []byte) ([]byte, error) {
	var req subStoreApplyRevisionRequest
	if err := subStoreSvcDecode(subStorePlansService, "claim_apply", request, &req); err != nil {
		return nil, err
	}
	grant, _ := ctx.Value(subStoreApplyGrantKey{}).(*subStoreApplyGrant)
	if grant != nil && grant.claim(req) {
		return json.Marshal(map[string]bool{"granted": true})
	}
	const reason = "no apply of this approved plan by core is in flight"
	ev := model.AuditEvent{
		ID: id.New("audit"), Action: auditActionSubStorePlanClaim, Scope: "proxy:admin", Decision: "deny", Reason: reason,
		Metadata: map[string]string{"via_rpc": subStorePlansService},
	}
	if subStoreSvcValidID(req.ApprovalID) {
		ev.Metadata["approval_id"] = req.ApprovalID
	}
	if p, err := pluginOperatorPrincipal(ctx); err == nil {
		s.recordPrincipalAudit(p, ev)
	} else {
		ev.ActorID = "system"
		s.recordAudit(ev)
	}
	return nil, rpcAPIError(http.StatusForbidden, model.APIErrorForbidden, "claim_apply: "+reason)
}

// subStorePlanApply calls the plugin's apply_revision under the subscription
// mutation gate, exactly as the gateway runs a record save
// (server_plugin_invoke.go): the plugin's snapshots are marked stale and the
// cached bodies of its shares dropped before the call, so no body rendered
// from the old revision is served after it. The call carries the one-time
// grant; claimed reports whether the plugin claimed it.
func (s *Server) subStorePlanApply(ctx context.Context, req subStoreApplyRevisionRequest) (claimed bool, err error) {
	state, release, err := s.acquireSubscriptionPluginGate(ctx, subStorePluginID)
	if err != nil {
		return false, err
	}
	defer func() {
		state.mu.Lock()
		state.generation++
		state.mu.Unlock()
		release()
	}()
	persist := s.store.MarkPluginSubscriptionSnapshotsStale
	if s.subscriptionMutationPersist != nil {
		persist = s.subscriptionMutationPersist
	}
	committed, err := persist(subStorePluginID, s.now())
	if committed {
		state.mu.Lock()
		state.generation++
		state.mu.Unlock()
		s.invalidateSharesForPlugin(subStorePluginID)
	}
	if err != nil {
		return false, err
	}
	grant := &subStoreApplyGrant{req: req}
	callCtx := context.WithValue(ctx, subStoreApplyGrantKey{}, grant)
	var reply subStoreApplyRevisionReply
	if s.subStoreSvc.applyRevision != nil {
		reply, err = s.subStoreSvc.applyRevision(callCtx, req)
	} else {
		reply, err = s.subStoreCallApplyRevision(callCtx, req)
	}
	claimed = grant.close()
	if err != nil {
		s.logger.Printf("sub-store plans: apply_revision failed for record %s (%s)", req.SubscriptionID, subscriptionDiagnosticSummary(err))
		return claimed, err
	}
	if reply.SubscriptionID != req.SubscriptionID || reply.Revision != req.Revision {
		return claimed, errors.New("apply_revision answered for another record or revision")
	}
	return claimed, nil
}

// subStoreCallApplyRevision is the plugin call, under the method's signed
// budget.
func (s *Server) subStoreCallApplyRevision(ctx context.Context, req subStoreApplyRevisionRequest) (subStoreApplyRevisionReply, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return subStoreApplyRevisionReply{}, err
	}
	out, err := s.callRuntimePluginService(ctx, subStorePluginID, subStorePluginID+"/subscription", subStoreApplyRevisionMethod, payload, nil, nil)
	if err != nil {
		return subStoreApplyRevisionReply{}, err
	}
	var reply subStoreApplyRevisionReply
	if err := json.Unmarshal(out, &reply); err != nil {
		return subStoreApplyRevisionReply{}, errors.New("apply_revision reply does not decode")
	}
	return reply, nil
}
