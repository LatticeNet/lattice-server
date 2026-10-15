package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"github.com/LatticeNet/lattice-sdk/model"
)

// latticenet.sub-store/bind (design 28, "Core-backed services the UI
// needs"): the validate-and-bind step as the Sub-Store UI reaches it.
//
//	preview      {"subscription_id","revision"?,"identity_id"}
//	             -> what one identity would receive from one record
//	                revision: credential-free entries and every exclusion
//	                with its reason. Scopes vpncore:read and substore:read.
//	reveal_entry {"identity_id","line_uuid","step_up_grant"?}
//	             -> {"identity_id","line_uuid","label","uri"}: one bound
//	                line's client URI for one identity, for the node detail
//	                and its QR code. vpncore:admin, the operator's own call
//	                through the plugin gateway, and the step-up reveal gate;
//	                every answer is audited and no audit field holds the URI.
//
// Both answer in core whatever scopes a manifest declares for them.

const (
	substoreBindService = "latticenet.sub-store/bind"

	// substoreBindMaxRequestBytes bounds a request to the service.
	substoreBindMaxRequestBytes = 4 << 10
	// substoreBindMaxIDBytes bounds an id or a revision in a request.
	substoreBindMaxIDBytes = 256

	// apiErrorSubstoreNotFleetBound: preview named a record whose render
	// returned a document, so there is nothing to bind.
	apiErrorSubstoreNotFleetBound = "record_not_fleet_bound"
	// apiErrorSubstoreLineExcluded: reveal_entry named a line the identity
	// cannot be bound to now; the message names the reason.
	apiErrorSubstoreLineExcluded = "line_excluded"

	auditActionSubstoreBindRevealEntry = "substore.bind.reveal_entry"
)

// registerSubStoreBindRPC registers the bind service to the Sub-Store
// plugin.
func (s *Server) registerSubStoreBindRPC() {
	if s.pluginRPC == nil {
		return
	}
	if err := s.pluginRPC.Register(subStorePluginID, substoreBindService, "v1", []string{"preview", "reveal_entry"}, s.substoreBindRPC); err != nil {
		s.logger.Printf("sub-store: register %s failed: %v", substoreBindService, err)
	}
}

func (s *Server) substoreBindRPC(ctx context.Context, method string, request []byte) ([]byte, error) {
	switch method {
	case "preview":
		return s.substoreBindPreviewRPC(ctx, request)
	case "reveal_entry":
		return s.substoreBindRevealEntryRPC(ctx, request)
	default:
		return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "sub-store/bind: unknown method "+method)
	}
}

// substoreBindOperator returns the operator a call is made for after the
// scope checks this service makes in core.
func substoreBindOperator(ctx context.Context, scopes ...string) (principal, error) {
	p, err := pluginOperatorPrincipal(ctx)
	if err != nil {
		return principal{}, rpcAPIError(http.StatusForbidden, model.APIErrorForbidden, "sub-store/bind: an operator principal is required")
	}
	for _, scope := range scopes {
		if ok, reason := pluginGatewayScopeAllowed(p, scope); !ok {
			return principal{}, rpcAPIError(http.StatusForbidden, model.APIErrorForbidden, "sub-store/bind: "+reason)
		}
	}
	return p, nil
}

// substoreBindDecode decodes a request strictly: bounded, one object, no
// unknown field, nothing after it.
func substoreBindDecode(method string, request []byte, out any) error {
	trimmed := bytes.TrimSpace(request)
	if len(trimmed) > substoreBindMaxRequestBytes {
		return rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "sub-store/bind "+method+": request is too large")
	}
	if len(trimmed) == 0 {
		trimmed = []byte("{}")
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil || decoder.More() {
		return rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "sub-store/bind "+method+": invalid request")
	}
	return nil
}

// substoreBindValidID reports whether value is a usable id or revision.
func substoreBindValidID(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= substoreBindMaxIDBytes &&
		!strings.ContainsFunc(value, unicode.IsControl)
}

type substoreBindPreviewRequest struct {
	SubscriptionID string `json:"subscription_id"`
	// Revision is the record revision to render; empty renders the live one.
	Revision   string `json:"revision,omitempty"`
	IdentityID string `json:"identity_id"`
}

type substoreBindPreviewReply struct {
	SubscriptionID string `json:"subscription_id"`
	Revision       string `json:"revision,omitempty"`
	IdentityID     string `json:"identity_id"`
	// IdentityStatus is the identity's policy now. A share for an identity
	// that is not active serves a placeholder, whatever the plan binds.
	IdentityStatus string `json:"identity_status"`
	// Kind is the plan's kind, nodes or document.
	Kind string `json:"kind"`
	// SourceVersion is the snapshot's version the plan was rendered from.
	SourceVersion string `json:"source_version,omitempty"`
	// LiveRevision is the record's live revision as the plugin's render
	// reported it beside the plan, empty when it reported none.
	LiveRevision string                  `json:"live_revision,omitempty"`
	Entries      []substoreBindEntry     `json:"entries"`
	Excluded     []substoreBindExclusion `json:"excluded"`
	// Refused names why a share would answer the decoy for this plan.
	Refused    string `json:"refused,omitempty"`
	FleetNodes int    `json:"fleet_nodes"`
}

// substoreBindPreviewRPC runs validate-and-bind for one record revision and
// one identity without serving anything.
func (s *Server) substoreBindPreviewRPC(ctx context.Context, request []byte) ([]byte, error) {
	if _, err := substoreBindOperator(ctx, "vpncore:read", "substore:read"); err != nil {
		return nil, err
	}
	var req substoreBindPreviewRequest
	if err := substoreBindDecode("preview", request, &req); err != nil {
		return nil, err
	}
	if !substoreBindValidID(req.SubscriptionID) || !substoreBindValidID(req.IdentityID) || (req.Revision != "" && !substoreBindValidID(req.Revision)) {
		return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "sub-store/bind preview: subscription_id and identity_id are required")
	}
	reply, err := s.substoreBindPreview(ctx, subStorePluginID, req.SubscriptionID, req.Revision, req.IdentityID)
	if err != nil {
		return nil, err
	}
	return json.Marshal(reply)
}

// substoreBindPreview renders one record revision to its plan and binds one
// identity into it, credential-free.
func (s *Server) substoreBindPreview(ctx context.Context, pluginID, subscriptionID, revision, identityID string) (substoreBindPreviewReply, error) {
	u, ok := s.getVpnUser(identityID)
	if !ok {
		return substoreBindPreviewReply{}, rpcAPIError(http.StatusNotFound, model.APIErrorNotFound, "sub-store/bind preview: identity_id names no identity")
	}
	prepared, err := s.substoreBindPrepare(ctx, pluginID, subscriptionID, revision, nil)
	if err != nil {
		return substoreBindPreviewReply{}, err
	}
	if prepared.plan == nil {
		return substoreBindPreviewReply{}, substoreBindNotFleetBound{liveRevision: prepared.liveRevision, err: rpcAPIError(http.StatusConflict, apiErrorSubstoreNotFleetBound,
			"sub-store/bind preview: the record renders a document, not a plan, so it binds no identity")}
	}
	return s.substoreBindPreviewFor(prepared, u), nil
}

// substoreBindPrepared is one record revision rendered to its plan once,
// with one catalogue build, ready to bind for any number of identities.
type substoreBindPrepared struct {
	subscriptionID string
	revision       string
	// plan is nil when the revision rendered a document.
	plan         *model.SelectionPlan
	liveRevision string
	snap         model.SubscriptionSnapshot
	// staged is set when the render named a revision or member revisions:
	// the plan's selection is then the revision's own, used as it is. A
	// render of the live revision with nothing named is checked against
	// the snapshot as the serve path checks it.
	staged    bool
	catalogue *lineCatalogue
	names     map[string][]string
}

// substoreBindPrepare renders a record revision for the bind step. It reads
// the record's snapshot through snapshotFor, which refreshes a missing or
// stale one, because a plan apply drops the snapshots it promoted and the
// next propose previews before any client polls. Only when that refresh
// fails and the render is a staged one (a revision named that is not the
// live one, or member revisions) does it render with an empty raw, which
// makes the plugin read the catalogue live for the staged selection; a
// render of the live revision with a failed refresh fails as before.
func (s *Server) substoreBindPrepare(ctx context.Context, pluginID, subscriptionID, revision string, memberRevisions map[string]string) (*substoreBindPrepared, error) {
	staged := revision != "" || len(memberRevisions) > 0
	unavailable := func() error {
		return rpcAPIError(http.StatusBadGateway, model.APIErrorBadGateway, "sub-store/bind preview: the record's snapshot is unavailable")
	}
	snap, snapErr := s.snapshotFor(ctx, pluginID, subscriptionID, false)
	if snapErr != nil {
		s.logger.Printf("sub-store bind: preview snapshot failed for record %s (%s)", subscriptionID, subscriptionDiagnosticSummary(snapErr))
		if !staged {
			return nil, unavailable()
		}
		snap = model.SubscriptionSnapshot{PluginID: pluginID, SubscriptionID: subscriptionID}
	}
	plan, liveRevision, err := s.substoreBindRenderPlan(ctx, substoreBindRenderQuery{PluginID: pluginID, SubscriptionID: subscriptionID,
		Revision: revision, MemberRevisions: memberRevisions, Snapshot: snap})
	if err != nil {
		s.logger.Printf("sub-store bind: preview render failed for record %s (%s)", subscriptionID, subscriptionDiagnosticSummary(err))
		if snapErr != nil {
			return nil, unavailable()
		}
		return nil, rpcAPIError(http.StatusBadGateway, model.APIErrorBadGateway, "sub-store/bind preview: the record did not render")
	}
	if snapErr != nil && revision == liveRevision && len(memberRevisions) == 0 {
		// The revision named was the live one: not a staged render after
		// all, and a live render never stands on a missing snapshot.
		return nil, unavailable()
	}
	prepared := &substoreBindPrepared{subscriptionID: subscriptionID, revision: revision, plan: plan, liveRevision: liveRevision, snap: snap, staged: staged}
	if plan == nil {
		return prepared, nil
	}
	if prepared.catalogue, err = s.buildLineCatalogue(""); err != nil {
		return nil, err
	}
	prepared.names = s.substoreCatalogue.names.snapshot()
	return prepared, nil
}

// substoreBindPreviewFor binds one identity into a prepared plan,
// credential-free. It never writes the policy memo: a preview may bind a
// staged revision, whose policy is not the one live shares are served
// under.
func (s *Server) substoreBindPreviewFor(p *substoreBindPrepared, u VpnUser) substoreBindPreviewReply {
	plan := *p.plan
	identity, usage := s.substoreBindIdentityState(u, s.now(), plan.Policy != nil && plan.Policy.Usage != nil)
	var result substoreBindResult
	if refused := substoreBindCheckSelection(plan, p.snap); refused != "" && !p.staged {
		result = substoreBindResult{Kind: plan.Kind, Refused: refused}
		for _, node := range plan.Nodes {
			if !node.Provider && node.LineUUID != "" {
				result.FleetNodes++
			}
		}
	} else {
		result = substoreBindPlan(plan, u, p.catalogue, substoreBindInputs{selected: substoreBindSelection(p.snap), usage: usage, names: p.names})
	}
	reply := substoreBindPreviewReply{SubscriptionID: p.subscriptionID, Revision: p.revision, IdentityID: u.ID,
		IdentityStatus: identity.Status, Kind: result.Kind, SourceVersion: p.snap.SourceVersion, LiveRevision: p.liveRevision,
		Entries: result.Entries, Excluded: result.Excluded, Refused: result.Refused, FleetNodes: result.FleetNodes}
	if reply.Entries == nil {
		reply.Entries = []substoreBindEntry{}
	}
	if reply.Excluded == nil {
		reply.Excluded = []substoreBindExclusion{}
	}
	return reply
}

// substoreBindNotFleetBound is preview's refusal of a record revision that
// renders a document. It unwraps to the 409 the bind service answers, and it
// carries the live revision the render reported for the plans previewer.
type substoreBindNotFleetBound struct {
	liveRevision string
	err          error
}

func (e substoreBindNotFleetBound) Error() string { return e.err.Error() }
func (e substoreBindNotFleetBound) Unwrap() error { return e.err }

// substoreBindRenderQuery is one render of a record for the bind step.
type substoreBindRenderQuery struct {
	PluginID       string
	SubscriptionID string
	// Revision is the record revision to render; empty renders the live one.
	Revision string
	// MemberRevisions names, for a collection, the revision each named
	// member resolves at ("" names a deleted member), so a collection's
	// preview follows a member's staged revision.
	MemberRevisions map[string]string
	// Snapshot is the record's snapshot whose raw the render reads; its raw
	// is empty for a staged render of a record whose snapshot could not be
	// refreshed.
	Snapshot model.SubscriptionSnapshot
}

// substoreBindRenderPlan asks the plugin's render for a record revision's
// plan, as a share's render asks (the URI list, no client), with the
// revision and member revisions named, and returns the record's live
// revision the reply reports beside it. nil means the record rendered a
// document.
func (s *Server) substoreBindRenderPlan(ctx context.Context, q substoreBindRenderQuery) (*model.SelectionPlan, string, error) {
	if hook := s.substoreCatalogue.bind.renderPlan; hook != nil {
		return hook(ctx, q)
	}
	fields := map[string]any{"subscription_id": q.SubscriptionID, "format": "plain", "ua_class": pluginUAClass("other"), "raw": q.Snapshot.Raw}
	if q.Revision != "" {
		fields["revision"] = q.Revision
	}
	if len(q.MemberRevisions) > 0 {
		fields["member_revisions"] = q.MemberRevisions
	}
	payload, err := json.Marshal(fields)
	if err != nil {
		return nil, "", err
	}
	out, err := s.callRuntimePluginService(ctx, q.PluginID, q.PluginID+"/subscription", "render", payload, nil, nil)
	if err != nil {
		return nil, "", err
	}
	var reply struct {
		Content string          `json:"content"`
		Plan    json.RawMessage `json:"plan"`
		// LiveRevision is the record's live revision when the plugin
		// rendered (design 28, S2): what plans.propose checks from_revision
		// against.
		LiveRevision string `json:"live_revision"`
	}
	if err := json.Unmarshal(out, &reply); err != nil {
		return nil, "", fmt.Errorf("decode plugin render reply: %w", err)
	}
	plan, err := substoreDecodeRenderPlan(reply.Content, reply.Plan)
	return plan, reply.LiveRevision, err
}

type substoreBindRevealEntryRequest struct {
	IdentityID  string `json:"identity_id"`
	LineUUID    string `json:"line_uuid"`
	StepUpGrant string `json:"step_up_grant,omitempty"`
}

type substoreBindRevealEntryReply struct {
	IdentityID string `json:"identity_id"`
	LineUUID   string `json:"line_uuid"`
	Label      string `json:"label"`
	URI        string `json:"uri"`
}

// substoreBindRevealEntryRPC returns one bound line's client URI for one
// identity: the entry the identity's link and a fleet share bind for that
// line, built by lineClientURI from the line's catalogue template. The
// reveal gate runs before anything about the identity or the line is read,
// so a caller without step-up learns nothing about either, and every answer
// after it, an excluded line included, is audited.
func (s *Server) substoreBindRevealEntryRPC(ctx context.Context, request []byte) ([]byte, error) {
	p, err := substoreBindOperator(ctx, "vpncore:admin")
	if err != nil {
		return nil, err
	}
	// The URI is the identity's credential. Only the operator's own call
	// through the gateway gets it, never a plugin method's rpc.call made
	// while serving an operator.
	if operatorCalledCoreService(ctx) != substoreBindService {
		return nil, rpcAPIError(http.StatusForbidden, model.APIErrorForbidden,
			"sub-store/bind reveal_entry answers only the operator's own call through the plugin gateway")
	}
	var req substoreBindRevealEntryRequest
	if err := substoreBindDecode("reveal_entry", request, &req); err != nil {
		return nil, err
	}
	if !substoreBindValidID(req.IdentityID) || !validLineUUIDv4(req.LineUUID) {
		return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "sub-store/bind reveal_entry: identity_id and a lowercase uuidv4 line_uuid are required")
	}
	ev := model.AuditEvent{Action: auditActionSubstoreBindRevealEntry, Scope: "vpncore:admin",
		Metadata: map[string]string{"identity_id": req.IdentityID, "line_uuid": req.LineUUID, "via_rpc": substoreBindService}}
	reveal := s.decideSecretReveal(p, req.StepUpGrant)
	if !reveal.Allowed {
		s.refuseSecretReveal(p, reveal, ev)
		return nil, secretRevealRPCError(reveal)
	}
	excluded := func(why string) error {
		s.refuseSecretReveal(p, secretRevealDecision{Reason: "line excluded for the identity: " + why}, ev)
		return rpcAPIError(http.StatusConflict, apiErrorSubstoreLineExcluded, "sub-store/bind reveal_entry: the line is excluded for this identity: "+why)
	}
	u, ok := s.getVpnUser(req.IdentityID)
	if !ok {
		s.refuseSecretReveal(p, secretRevealDecision{Reason: "identity_id names no identity"}, ev)
		return nil, rpcAPIError(http.StatusNotFound, model.APIErrorNotFound, "sub-store/bind reveal_entry: identity_id names no identity")
	}
	catalogue, err := s.buildLineCatalogue("")
	if err != nil {
		return nil, err
	}
	line := substoreBindLineOf(u, substoreBindBindings(u), catalogue, substoreBindRules{names: s.substoreCatalogue.names.snapshot()}, req.LineUUID)
	if line.row.LineHashID != "" {
		ev.Metadata["line_hash_id"] = line.row.LineHashID
	}
	if why := firstNonEmpty(line.refuse.reason, line.exclude.reason); why != "" {
		return nil, excluded(why)
	}
	uri, err := lineClientURI(line.template, line.payload, line.label)
	if err != nil {
		return nil, excluded(identityLineTemplateUnusable)
	}
	s.recordSecretReveal(p, reveal, ev)
	return json.Marshal(substoreBindRevealEntryReply{IdentityID: u.ID, LineUUID: req.LineUUID, Label: line.label, URI: uri})
}
