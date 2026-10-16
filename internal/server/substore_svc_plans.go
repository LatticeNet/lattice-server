package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
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
//  1. propose computes the fleet closure of the changed records over the
//     plugin's depends_on v2 (substore_svc_plans_closure.go): every
//     collection that reads one of them now or would read it at its staged
//     revision. It refuses a closure no apply can carry out (a file in it, a
//     migration that leaves a collection mixed, a delete under an explicit
//     member), and for every record of the closure lists its live shares and
//     what each identity they serve gains, loses, receives changed and has
//     excluded (substore_svc_plans_build.go), together with the identities
//     the plan gives or clears and the shares it archives; writes that as
//     the approval's plan; and files it through submitApproval;
//  2. the operator reads the plan and approves it with its plan_sha256, which
//     the generic approval path checks against the stored bytes, so the
//     approval covers exactly the text that was shown;
//  3. at the decision core previews every record again, then, holding the
//     share-write lock, computes the closure once more, and rejects the plan
//     as stale unless the closure, every record's live shares, its live and
//     staged revisions and every identity's diff are still what the operator
//     read (substore_svc_plans_decide.go);
//  4. only then, still under the lock, does core call the plugin's
//     apply_revision once per promoted record, members before the
//     collections that gather them, under the subscription mutation gate,
//     each call carrying a one-time grant the plugin claims through
//     claim_apply. Each record is finished before the next starts: its
//     snapshot dropped, its own shares' identity changes and archivals
//     written. After the last, the closure's snapshots are dropped and its
//     bodies invalidated.
//
// An assignment-only plan (from_revision equal to to_revision) gives shares
// identities on a record that does not move and calls no apply_revision; a
// clear-only plan only clears identities and archives shares and makes no
// plugin call at all. plans.publish (substore_svc_plans_publish.go) promotes
// a staged revision without an approval when no live share in its closure is
// fleet-bound.
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
	subStorePlanUnboundCoverage = "unbound_shares name no identity: on a fleet-bound record each answers the decoy (no lines), " +
		"on any other record it receives the revision without identity binding; their lines are not diffed in this plan"

	auditActionSubStorePlanPropose = "substore.plan.propose"
	auditActionSubStorePlanApply   = "substore.plan.apply"
	auditActionSubStorePlanStale   = "substore.plan.stale"
	auditActionSubStorePlanClaim   = "substore.plan.claim"
	auditActionSubStorePlanPublish = "substore.plan.publish"
)

// subStorePlansMethods is every method of the plans service.
var subStorePlansMethods = []string{"propose", "status", "claim_apply", "publish"}

// The reasons a stale plan is rejected with. The status row's stale flag is
// derived from them, so the UI never parses a sentence.
const (
	subStorePlanStalePlugin  = "the sub-store plugin changed since this plan was proposed; propose it again"
	subStorePlanStaleShares  = "a record's live shares changed since this plan was proposed; propose it again"
	subStorePlanStaleReceive = "what the record's shares would receive changed since this plan was proposed; propose it again"
	subStorePlanStaleLive    = "the record's live revision moved since this plan was proposed; propose it again"
	subStorePlanStaleStaged  = "the staged revision this plan publishes was replaced or discarded since it was proposed; propose the new one"
	subStorePlanStaleClosure = "the records this plan covers changed since it was proposed: a collection started or stopped reading one of them; propose it again"
)

// subStorePlanStaleReasons are the stale reasons, for the status row.
var subStorePlanStaleReasons = []string{subStorePlanStalePlugin, subStorePlanStaleShares, subStorePlanStaleReceive,
	subStorePlanStaleLive, subStorePlanStaleStaged, subStorePlanStaleClosure}

// subStoreCoreOnlyReason is the gateway's refusal of apply_revision, and
// subStoreFetchCoreOnlyReason its refusal of fetch.
const (
	subStoreCoreOnlyReason      = "apply_revision runs only as the apply step of an approved Sub-Store plan"
	subStoreFetchCoreOnlyReason = "fetch runs only as core's own refresh of a Sub-Store record"
	// subStoreFetchMethod is the plugin method core's refresh calls.
	subStoreFetchMethod = "fetch"
)

// errSubStoreCoreOnlyMethod is the refusal of apply_revision called outside
// an approved plan apply, and errSubStoreFetchCoreOnly the refusal of fetch
// called outside core's refresh.
var (
	errSubStoreCoreOnlyMethod = errors.New("sub-store: apply_revision runs only inside an approved plan apply")
	errSubStoreFetchCoreOnly  = errors.New("sub-store: fetch runs only inside core's refresh")
)

// subStoreCoreOnlyMethod reports a plugin method that only core calls, each
// on one path of its own, never as an operator's gateway call and never from
// any other core path, whatever a manifest declares:
//
//   - apply_revision changes what existing share holders receive, so it runs
//     as the apply step of an approved plan, which puts the one-time grant on
//     the call's context;
//   - fetch returns the envelope with every selected row's addresses,
//     template parameters, geo and renewal date, and the legacy export with
//     owner credentials for a record not yet migrated; nothing in the UI calls
//     it, so it runs only as core's refresh (fetchSubscriptionSource), which
//     marks the context it calls with (S2 plan section 2.6). Closing the path
//     is smaller than guarding it with a scope.
func subStoreCoreOnlyMethod(service, method string) bool {
	return service == subStorePluginID+"/subscription" && (method == subStoreApplyRevisionMethod || method == subStoreFetchMethod)
}

// subStoreCoreOnlyRefusal is the gateway's reason for refusing a core-only
// method.
func subStoreCoreOnlyRefusal(method string) string {
	if method == subStoreFetchMethod {
		return subStoreFetchCoreOnlyReason
	}
	return subStoreCoreOnlyReason
}

// subStoreRefreshCallKey marks the context of core's own refresh fetch, the
// one path a core-only fetch is admitted on, as the apply grant marks
// apply_revision's.
type subStoreRefreshCallKey struct{}

// withSubStoreRefreshCall marks ctx as core's refresh.
func withSubStoreRefreshCall(ctx context.Context) context.Context {
	return context.WithValue(ctx, subStoreRefreshCallKey{}, true)
}

// subStoreCoreOnlyCallAllowed admits a core-only method only on its own core
// path: apply_revision with an apply grant on the context, fetch with the
// refresh mark.
func subStoreCoreOnlyCallAllowed(ctx context.Context, method string) error {
	if method == subStoreFetchMethod {
		if marked, _ := ctx.Value(subStoreRefreshCallKey{}).(bool); !marked {
			return errSubStoreFetchCoreOnly
		}
		return nil
	}
	if grant, _ := ctx.Value(subStoreApplyGrantKey{}).(*subStoreApplyGrant); grant == nil {
		return errSubStoreCoreOnlyMethod
	}
	return nil
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
	// Action is "delete" for a delete plan, which archives the live
	// record (Revision is then the live revision deleted); empty promotes.
	Action string `json:"action,omitempty"`
}

// subStoreApplyRevisionReply is apply_revision's reply.
type subStoreApplyRevisionReply struct {
	SubscriptionID string `json:"subscription_id"`
	Revision       string `json:"revision"`
}

// subStorePlan is the approval's plan: what the operator reads and what the
// approval's hash covers. Shares are listed one by one with their identity
// and their counts; the lines are listed once per identity, because every
// share of one identity on one record receives the same lines. The top level
// is the record the request names; every other record of the fleet closure
// is a section of its own in Records.
type subStorePlan struct {
	Kind           string `json:"kind"`
	PluginID       string `json:"plugin_id"`
	SubscriptionID string `json:"subscription_id"`
	FromRevision   string `json:"from_revision"`
	ToRevision     string `json:"to_revision"`
	// Action is "delete" for a delete plan.
	Action string `json:"action,omitempty"`
	// Mode is what the apply does: promote, assign, clear or delete.
	Mode string `json:"mode,omitempty"`
	// Role, RecordKind, MemberRevisions and BeforeEmpty describe the
	// request's own record as a section does (subStorePlanRecord).
	Role            string            `json:"role,omitempty"`
	RecordKind      string            `json:"record_kind,omitempty"`
	MemberRevisions map[string]string `json:"member_revisions,omitempty"`
	BeforeEmpty     bool              `json:"before_empty,omitempty"`
	// Totals counts every record the plan covers; PrimaryTotals the
	// request's own record.
	Totals        subStorePlanTotals  `json:"totals"`
	PrimaryTotals subStorePlanTotals  `json:"primary_totals"`
	Shares        []subStorePlanShare `json:"shares"`
	// UnboundShares are the live shares that name no identity. Coverage
	// says what the plan does not show about them.
	UnboundShares []subStorePlanUnboundShare `json:"unbound_shares"`
	Coverage      string                     `json:"coverage,omitempty"`
	Identities    []subStorePlanIdentity     `json:"identities"`
	// Records is every other record the plan covers: the other promoted
	// records, the collections that read a changed one, and the staged-only
	// records, which serve no one now and are listed but not previewed.
	Records []subStorePlanRecord `json:"records,omitempty"`
	// ApplyOrder is the records apply_revision runs for, members before the
	// collections that gather them.
	ApplyOrder []string `json:"apply_order,omitempty"`
	// Closure is every record the plan covers, sorted; the decision
	// computes it again and finds the plan stale if it moved.
	Closure []string `json:"closure,omitempty"`
	// Assignments are the identity-less shares the plan gives an identity,
	// Clearings the shares it clears of one, Archivals the shares it
	// archives.
	Assignments []subStorePlanAssignment `json:"assignments,omitempty"`
	Clearings   []subStorePlanAssignment `json:"clearings,omitempty"`
	Archivals   []subStorePlanArchival   `json:"archivals,omitempty"`
}

// subStorePlanRecord is one record's section of a plan.
type subStorePlanRecord struct {
	SubscriptionID string `json:"subscription_id"`
	Kind           string `json:"kind,omitempty"`
	// Role is promote, delete, self (an assignment's own record),
	// dependent (a collection previewed at its live revision over the
	// changed members) or staged_only.
	Role         string `json:"role"`
	FromRevision string `json:"from_revision"`
	ToRevision   string `json:"to_revision,omitempty"`
	// MemberRevisions is what the record's after side resolves each changed
	// member at ("" names a deleted member).
	MemberRevisions map[string]string `json:"member_revisions,omitempty"`
	// BeforeEmpty says the before side was taken as empty without a render:
	// a restored record has no live revision, and a collection mixed by a
	// partial migration serves nothing to anyone.
	BeforeEmpty   bool                       `json:"before_empty,omitempty"`
	Totals        subStorePlanTotals         `json:"totals"`
	Shares        []subStorePlanShare        `json:"shares"`
	UnboundShares []subStorePlanUnboundShare `json:"unbound_shares"`
	Coverage      string                     `json:"coverage,omitempty"`
	Identities    []subStorePlanIdentity     `json:"identities"`
}

// subStorePlanAssignment is one share the plan gives an identity, or clears
// of one, with the lines that identity receives after the plan (an
// assignment) or received before it (a clearing).
type subStorePlanAssignment struct {
	ShareID        string `json:"share_id"`
	SubscriptionID string `json:"subscription_id"`
	Slug           string `json:"slug"`
	DisplayName    string `json:"display_name,omitempty"`
	IdentityID     string `json:"identity_id"`
	Lines          int    `json:"lines"`
}

// subStorePlanArchival is one share the plan archives.
type subStorePlanArchival struct {
	ShareID        string `json:"share_id"`
	SubscriptionID string `json:"subscription_id"`
	Slug           string `json:"slug"`
	DisplayName    string `json:"display_name,omitempty"`
	IdentityID     string `json:"identity_id,omitempty"`
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
	// Assigned says the plan gives this identity-less share IdentityID.
	Assigned bool `json:"assigned,omitempty"`
	// Archive says the plan archives the share.
	Archive bool `json:"archive,omitempty"`
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
	// ClearedIdentityID is the identity the plan clears from the share.
	ClearedIdentityID string `json:"cleared_identity_id,omitempty"`
	// Archive says the plan archives the share.
	Archive bool `json:"archive,omitempty"`
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
	// FromRevision is the record's live revision ("" for a restored record
	// that has none), ToRevision the staged one to publish. Equal, they
	// promote nothing: the plan only changes shares. A delete takes no
	// ToRevision at all.
	FromRevision string  `json:"from_revision"`
	ToRevision   *string `json:"to_revision,omitempty"`
	// Action is promote (the default) or delete.
	Action string `json:"action,omitempty"`
	// Records are further records to promote in the same apply: a
	// collection over two legacy members has no order in which one can go
	// first.
	Records []subStorePlanRecordRequest `json:"records,omitempty"`
	// ShareIdentities gives an identity-less share of the closure an
	// identity, or clears one share's identity with "".
	ShareIdentities map[string]string `json:"share_identities,omitempty"`
	// ArchiveShares are shares of the closure the apply archives.
	ArchiveShares []string `json:"archive_shares,omitempty"`
}

// subStorePlanRecordRequest is one more record a plan promotes.
type subStorePlanRecordRequest struct {
	SubscriptionID string `json:"subscription_id"`
	FromRevision   string `json:"from_revision"`
	ToRevision     string `json:"to_revision"`
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
	ApprovalID string `json:"approval_id"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	// Stale is set when the plan was rejected as stale (one of the stale
	// reasons), so the UI never parses the reason.
	Stale bool `json:"stale,omitempty"`
	// Action is promote or delete; Mode adds assign and clear.
	Action         string    `json:"action"`
	Mode           string    `json:"mode"`
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
	case "publish":
		// An ordinary record edit by design 28: substore:admin, and only the
		// operator's own call.
		p, err := s.subStoreSvcOperator(ctx, subStorePlansService, true, "substore:admin")
		if err != nil {
			return nil, err
		}
		return s.subStorePlansPublish(ctx, p, request)
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
	spec, err := subStorePlanSpecOf(req)
	if err != nil {
		return nil, err
	}
	var plan subStorePlan
	if spec.mode == subStorePlanModeClear {
		// A clearing or an archival never widens what any holder receives
		// and the record does not move: no closure, no preview, no plugin
		// call, so a plugin outage never blocks one.
		shares := s.subStorePlanSharesOf([]string{spec.primary})
		if err := s.subStorePlanChangeRefusal(spec.changes, shares, func(string) bool { return false }); err != nil {
			return nil, err
		}
		plan = subStoreBuildClearPlan(spec, shares[spec.primary])
	} else {
		roots := spec.promotedIDs()
		if spec.mode == subStorePlanModeAssign {
			roots = []string{spec.primary}
		}
		g, err := s.subStorePlanGraphFor(ctx, roots, spec.mode == subStorePlanModePromote)
		if err != nil {
			return nil, s.subStorePlanDependsError(err)
		}
		if err := subStorePlanProposeRefusal(spec, g); err != nil {
			return nil, err
		}
		sections := s.subStorePlanSections(spec, g)
		previewed := make([]string, 0, len(sections))
		for _, section := range sections {
			if section.Role != subStorePlanRoleStagedOnly {
				previewed = append(previewed, section.SubscriptionID)
			}
		}
		shares := s.subStorePlanSharesOf(previewed)
		fleetAfter := func(id string) bool {
			facts, _ := g.facts(id)
			live := facts.FleetBound || facts.Source == subStoreSourceFleet
			if spec.mode == subStorePlanModeAssign {
				return live
			}
			return live || g.closure.fleetBound[id]
		}
		if err := s.subStorePlanChangeRefusal(spec.changes, shares, fleetAfter); err != nil {
			return nil, err
		}
		var all []model.SubscriptionShare
		for _, id := range previewed {
			all = append(all, shares[id]...)
		}
		// A propose that changes a share's identity or archives one is
		// privileged whatever the shares are (design 28 makes changing a
		// share's identity privileged); otherwise a plan is required when
		// any live share of the closure is fleet-bound.
		if len(spec.changes) == 0 && !subStorePlanRequired(all) {
			return json.Marshal(subStorePlansProposeReply{Required: false, Reason: "no live share in this record's fleet closure is fleet-bound; publish it"})
		}
		plan, err = s.subStoreBuildPlan(ctx, spec, g, shares)
		if err != nil {
			return nil, err
		}
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
	named := plan.applyOrder()
	if len(named) == 0 {
		named = []string{plan.SubscriptionID}
	}
	approval := model.Approval{
		ID:      id.New("approval"),
		Plugin:  subStorePlanApprovalPlugin,
		Action:  subStorePlanActionPrefix + strings.Join(named, ","),
		Plan:    string(text),
		Status:  model.ApprovalPending,
		ActorID: p.ActorID, CreatedAt: now, UpdatedAt: now,
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
			"approval_id": approval.ID, "plan_sha256": planSHA, "subscription_id": plan.SubscriptionID,
			"from_revision": plan.FromRevision, "to_revision": plan.ToRevision, "mode": plan.mode(),
			"records": fmt.Sprint(max(len(plan.Closure), 1)), "assignments": fmt.Sprint(len(plan.Assignments)),
			"clearings": fmt.Sprint(len(plan.Clearings)), "archivals": fmt.Sprint(len(plan.Archivals)),
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

// subStorePlanProposeRefusal checks what the closure says against the
// request before anything is previewed: every promoted record is live at its
// from_revision and staged at its to_revision, a delete's record is live at
// its from_revision, an assignment's record is live at the revision named,
// and the plan is one an apply can carry out.
func subStorePlanProposeRefusal(spec subStorePlanSpec, g subStorePlanGraph) error {
	notLive := func(id string) error {
		return rpcAPIError(http.StatusConflict, subStoreSvcErrConflict,
			"from_revision is not the live revision of record "+id+"; propose from the live revision")
	}
	switch spec.mode {
	case subStorePlanModeAssign:
		if facts, _ := g.facts(spec.primary); facts.Revision != spec.from {
			return notLive(spec.primary)
		}
		return nil
	case subStorePlanModeDelete:
		if facts, _ := g.facts(spec.primary); facts.Revision != spec.from {
			return notLive(spec.primary)
		}
		if dependents := subStorePlanExplicitDependents(g, spec.primary); len(dependents) > 0 {
			return rpcAPIError(http.StatusConflict, apiErrorFleetDeleteHasExplicitDependents, fmt.Sprintf(
				"fleet_delete_has_explicit_dependents: collections %s list record %s as a member, and a member that does not resolve fails "+
					"the collection's fetch; remove it from them first, then propose the delete", strings.Join(dependents, ", "), spec.primary))
		}
		return subStorePlanFileRefusal(g)
	}
	for _, record := range spec.promoted {
		facts, _ := g.facts(record.SubscriptionID)
		if facts.StagedRevision != record.ToRevision {
			return rpcAPIError(http.StatusConflict, apiErrorRevisionUnknown, fmt.Sprintf(
				"revision_unknown: %s is not the staged revision of record %s; propose the revision staged now", record.ToRevision, record.SubscriptionID))
		}
		if facts.Revision != record.FromRevision {
			return notLive(record.SubscriptionID)
		}
	}
	if err := subStorePlanFileRefusal(g); err != nil {
		return err
	}
	return subStorePlanMigrationRefusal(subStorePlanMissingMigrations(g, spec.promotedByID()))
}

// subStoreBuildClearPlan is a clear-only plan: the record's live shares, the
// identities cleared and the shares archived, and nothing previewed.
func subStoreBuildClearPlan(spec subStorePlanSpec, shares []model.SubscriptionShare) subStorePlan {
	section := subStorePlanRecord{SubscriptionID: spec.primary, Role: subStorePlanRoleSelf, FromRevision: spec.from}
	subStorePlanSectionRows(&section, shares, spec.changes)
	subStorePlanFillSection(&section, nil)
	plan := subStorePlan{Kind: subStorePlanKind, PluginID: subStorePluginID, SubscriptionID: spec.primary, FromRevision: spec.from, ToRevision: spec.to,
		Mode: subStorePlanModeClear, Role: subStorePlanRoleSelf, Totals: section.Totals, PrimaryTotals: section.Totals,
		Shares: section.Shares, UnboundShares: section.UnboundShares, Coverage: section.Coverage, Identities: section.Identities,
		Closure: []string{spec.primary}}
	subStorePlanListChanges(&plan, []subStorePlanRecord{section}, nil)
	return plan
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
		if req.SubscriptionID != "" && plan.SubscriptionID != req.SubscriptionID && !slices.Contains(plan.Closure, req.SubscriptionID) {
			return
		}
		action := subStorePlanActionPromote
		if plan.Action == subStorePlanActionDelete {
			action = subStorePlanActionDelete
		}
		rows = append(rows, subStorePlanStatusRow{
			ApprovalID: approval.ID, Status: approval.Status, Reason: approval.Reason, PlanSHA256: approvalPlanSHA(approval),
			Stale:  approval.Status == model.ApprovalRejected && slices.Contains(subStorePlanStaleReasons, approval.Reason),
			Action: action, Mode: plan.mode(),
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

// subStorePlanApply calls the plugin's apply_revision for one record under
// the subscription mutation gate, exactly as the gateway runs a record save
// (server_plugin_invoke.go), with the generation bumped when the gate is
// released so a refresh that was in flight is discarded. The call carries the
// one-time grant; claimed reports whether the plugin claimed it. Once the
// plugin answered, whatever it answered, every cached body of the plugin's
// shares is dropped and each source's epoch advanced, which also voids the
// bind policy memo (substore_bind_serve.go). after, when given, then runs
// still under the gate with the call's outcome: the caller drops the record's
// snapshot on success and stale-marks the closure on a failure there, so no
// refresh lands between the plugin's write and core's reaction to it. The
// snapshots are not touched before the call: a failed apply usually leaves
// the record unchanged, and the last-good snapshot should keep serving
// through the next provider outage.
func (s *Server) subStorePlanApply(ctx context.Context, req subStoreApplyRevisionRequest, after ...func(error)) (claimed bool, err error) {
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
	grant := &subStoreApplyGrant{req: req}
	callCtx := context.WithValue(ctx, subStoreApplyGrantKey{}, grant)
	var reply subStoreApplyRevisionReply
	if s.subStoreSvc.applyRevision != nil {
		reply, err = s.subStoreSvc.applyRevision(callCtx, req)
	} else {
		reply, err = s.subStoreCallApplyRevision(callCtx, req)
	}
	claimed = grant.close()
	switch {
	case err != nil:
		s.logger.Printf("sub-store plans: apply_revision failed for record %s (%s)", req.SubscriptionID, subscriptionDiagnosticSummary(err))
	case reply.SubscriptionID != req.SubscriptionID || reply.Revision != req.Revision:
		err = errors.New("apply_revision answered for another record or revision")
	}
	s.invalidateSharesForPlugin(subStorePluginID)
	for _, fn := range after {
		fn(err)
	}
	return claimed, err
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
