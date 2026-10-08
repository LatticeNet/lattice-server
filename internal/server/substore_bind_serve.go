package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/proxycore"
)

// Serving a fleet-bound record through a share (design 28, "The line
// catalogue and identity-rendered entries").
//
// A record whose render returns a plan instead of a document is fleet-bound.
// Its share names the identity it serves (Source.IdentityID); core validates
// the plan against a fresh catalogue build, binds that identity's
// credentials (substore_bind.go), and asks the plugin's convert, which has
// no network, no store and no host calls, to write the client's document
// from the bound nodes or the bound document. No plugin method that runs a
// script with network or reaches the network holds the credential.
//
// What the share answers:
//
//   - a plan with includable lines: the converted document, with
//     Subscription-Userinfo from the identity's policy, never the provider's;
//   - a plan with fleet nodes and none includable, a document plan that
//     fails validation, a plan whose record's snapshot does not say which
//     lines it selected, a plugin whose signed convert budget allows host
//     calls, a share that names no identity, an identity that is missing or
//     not in service: the decoy, audited with the reason, so a client keeps
//     the nodes it has.
//
// The selection a plan is checked against is read from the record's
// snapshot, which the plugin's fetch wrote from catalogue rows. Render and
// its scripts cannot change it, so a script cannot widen it. The plugin
// itself is trusted for it: the record and its selector live in the plugin,
// and core holds no copy to recompute it from. A snapshot core cannot read a
// selection from refuses the plan rather than letting the identity's
// bindings stand in for it.
//
// The record's snapshot is identity-free, so its content version cannot see
// an identity rotate a credential, gain a line or get parked. A share that
// names an identity therefore caches its body under a key that also carries
// a digest of that identity's bind state (substoreBindStateDigest): a change
// to it is a cache miss and a fresh bind, not an extension of the old body.

// substoreBindState is the bind step's state on the server. It lives in
// substoreCatalogueState.
type substoreBindState struct {
	// convert replaces the plugin's convert call in tests.
	convert func(ctx context.Context, pluginID string, req model.ConvertRequest) (model.ConvertReply, error)
	// renderPlan replaces the plugin's render call of bind.preview in tests.
	renderPlan func(ctx context.Context, pluginID, subscriptionID, revision string, snap model.SubscriptionSnapshot) (*model.SelectionPlan, error)
}

// substoreBindRefusal is a render the bind step refused. The share answers
// the decoy and the refusal audit names reason.
type substoreBindRefusal struct{ reason string }

func (e substoreBindRefusal) Error() string { return "fleet bind refused: " + e.reason }

// Refusal reasons of a fleet-bound share, as its refusal audit names them.
const (
	substoreBindDenyNoIdentity      = "fleet_share_without_identity"
	substoreBindDenyIdentityMissing = "fleet_identity_missing"
	substoreBindDenyIdentityPrefix  = "fleet_identity_"
	substoreBindDenyPrefix          = "fleet_"
)

// substoreDecodeRenderPlan reads the plan of a render reply: nil when the
// reply carries none, an error when it carries a plan that fails the SDK's
// strict decode (size, duplicate keys, unknown fields, structure) or a plan
// beside a document.
func substoreDecodeRenderPlan(content string, raw json.RawMessage) (*model.SelectionPlan, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, nil
	}
	if content != "" {
		return nil, errors.New("render returned both a document and a plan")
	}
	plan, err := model.DecodeSelectionPlan(trimmed)
	if err != nil {
		return nil, fmt.Errorf("render plan: %w", err)
	}
	return &plan, nil
}

// substoreBindSelection is the line set a fleet snapshot selected, read from
// a snapshot whose content is a catalogue document (its catalogue_version
// and its rows' line_uuid). Nil when the snapshot is not one (a collection, a
// provider record that pulled a fleet record, an envelope this core cannot
// read), and substoreBindPlan then refuses a plan with fleet nodes with
// selection_unknown.
func substoreBindSelection(snap model.SubscriptionSnapshot) map[string]bool {
	raw := strings.TrimSpace(snap.Raw)
	if !strings.HasPrefix(raw, "{") {
		return nil
	}
	var doc struct {
		CatalogueVersion string `json:"catalogue_version"`
		Rows             []struct {
			LineUUID string `json:"line_uuid"`
		} `json:"rows"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil || !strings.HasPrefix(doc.CatalogueVersion, lineCatalogueVersionPrefix) {
		return nil
	}
	selected := make(map[string]bool, len(doc.Rows))
	for _, row := range doc.Rows {
		if validLineUUIDv4(row.LineUUID) {
			selected[row.LineUUID] = true
		}
	}
	return selected
}

// substoreBindServeState is what a request for a share that names an
// identity needs before the cache: the cache-key fragment that carries the
// identity's bind state, and its policy for the quota header. refusal is set
// when the identity is missing or not in service.
func (s *Server) substoreBindServeState(share model.SubscriptionShare, now time.Time) (string, vpnUserPolicy, string) {
	u, ok := s.getVpnUser(share.Source.IdentityID)
	if !ok {
		return "", vpnUserPolicy{}, substoreBindDenyIdentityMissing
	}
	policy := s.vpnUserPolicyAt(u, now)
	if !policy.Active() {
		return "", policy, substoreBindDenyIdentityPrefix + firstNonEmpty(policy.Reason, policy.Status)
	}
	return ";bind=" + s.substoreBindStateDigest(u), policy, ""
}

// substoreBindStateDigest digests what binding this identity reads beyond
// the record's snapshot: its credentials, its bindings and their applied
// credential, and for each enabled binding the line's service state, whether
// the identity is parked on it and its stored template. It is derived from
// credentials, so it stays in the process: a cache key, never a log line or
// an audit field.
func (s *Server) substoreBindStateDigest(u VpnUser) string {
	_, index := s.lineReadModel()
	h := sha256.New()
	write := func(parts ...string) {
		for _, part := range parts {
			h.Write([]byte(part))
			h.Write([]byte{0})
		}
	}
	write("lattice substore bind state v1", u.ID)
	for _, c := range u.Credentials {
		write(c.Protocol, c.UUID, c.Password, c.Flow)
	}
	bindings := slices.Clone(u.Bindings)
	slices.SortFunc(bindings, func(a, b LineBinding) int { return strings.Compare(a.LineHashID, b.LineHashID) })
	for _, b := range bindings {
		write(b.LineHashID, strconv.FormatBool(b.Enabled), b.AppliedCredentialSHA256)
		if !b.Enabled {
			continue
		}
		ln, ok := index[b.LineHashID]
		if !ok {
			write("unknown")
			continue
		}
		write(ln.LineUUID, ln.ServiceState, strconv.FormatBool(identityLinkParked(ln, userLineName(u.ID, ln.LineUUID))))
		if t, ok := s.store.LineClientTemplate(b.LineHashID); ok {
			write(t.Host, strconv.Itoa(t.Port), t.UpdatedAt.UTC().Format(time.RFC3339Nano))
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// substoreBindRendered binds a rendered plan and converts it. A render that
// carried a document is returned as it was.
func (s *Server) substoreBindRendered(ctx context.Context, share model.SubscriptionShare, format string, variant shareRenderVariant,
	snap model.SubscriptionSnapshot, rendered renderedSubscription) (renderedSubscription, error) {
	if rendered.Plan == nil {
		return rendered, nil
	}
	plan := *rendered.Plan
	rendered.Plan = nil
	if share.Source.IdentityID == "" {
		return renderedSubscription{}, substoreBindRefusal{reason: substoreBindDenyNoIdentity}
	}
	u, ok := s.getVpnUser(share.Source.IdentityID)
	if !ok {
		return renderedSubscription{}, substoreBindRefusal{reason: substoreBindDenyIdentityMissing}
	}
	policy := s.vpnUserPolicyAt(u, s.now())
	if !policy.Active() {
		return renderedSubscription{}, substoreBindRefusal{reason: substoreBindDenyIdentityPrefix + firstNonEmpty(policy.Reason, policy.Status)}
	}
	catalogue, err := s.buildLineCatalogue("")
	if err != nil {
		return renderedSubscription{}, err
	}
	result := substoreBindPlan(plan, u, catalogue, substoreBindSelection(snap))
	for _, x := range result.Excluded {
		if x.Reason == substoreBindRejectedPrefix+"skip-cert-verify" {
			s.logger.Printf("sub-store bind: share %s: line %s excluded: the plan turns certificate checks off where the line's template does not", share.ID, x.LineUUID)
		}
	}
	if result.Refused != "" {
		return renderedSubscription{}, substoreBindRefusal{reason: substoreBindDenyPrefix + result.Refused}
	}

	target := firstNonEmpty(reportedRenderTarget(rendered.Target), variant.Target, variant.UATarget)
	req := model.ConvertRequest{Target: target, Options: variant.options(), ResponseChain: plan.ResponseChain}
	if result.document != nil {
		req.Document = result.document
	} else {
		if req.Target == "" {
			req.Target = "URI"
		}
		if req.Target == "URI" {
			req.Format = proxycore.SubscriptionFormatPlain
			if format == proxycore.SubscriptionFormatBase64 {
				req.Format = proxycore.SubscriptionFormatBase64
			}
		}
		req.Nodes = result.nodes
	}
	reply, err := s.substoreBindConvert(ctx, share.Source.PluginID, req)
	if err != nil {
		return renderedSubscription{}, err
	}
	if len(reply.Log) > 0 {
		// The response chain ran over the bound document, so what it wrote
		// may carry a credential: counted, never copied.
		s.logger.Printf("sub-store bind: share %s: the response chain wrote %d log line(s)", share.ID, len(reply.Log))
	}
	rendered.Body = []byte(reply.Content)
	rendered.ContentType = reply.ContentType
	rendered.Target = firstNonEmpty(reportedRenderTarget(reply.Target), req.Target)
	rendered.Userinfo = identityLinkUserinfo(policy, false)
	rendered.Bound = true
	return rendered, nil
}

// substoreBindDenyConvertUnsealed refuses a bound plan when the plugin's
// signed manifest does not hold its convert method to zero host calls.
const substoreBindDenyConvertUnsealed = "fleet_convert_not_sealed"

// substoreBindConvertSealed reports whether the plugin's signed manifest
// gives its convert method a complete budget of zero host calls. The
// runtime enforces that budget per invocation, so a convert that holds a
// bound credential can reach no host function: no network, no store, no
// rpc.call and no log.write. An absent budget resolves to the default host
// call allowance, so it does not count.
func (s *Server) substoreBindConvertSealed(pluginID string) bool {
	budget := s.pluginMethodBudget(pluginID, pluginID+"/subscription", "convert")
	return budget != nil && budget.HostCalls == 0
}

// substoreBindConvert calls the plugin's convert with a bound plan.
func (s *Server) substoreBindConvert(ctx context.Context, pluginID string, req model.ConvertRequest) (model.ConvertReply, error) {
	payload, err := model.EncodeConvertRequest(req)
	if err != nil {
		return model.ConvertReply{}, fmt.Errorf("convert request: %w", err)
	}
	var reply model.ConvertReply
	if hook := s.substoreCatalogue.bind.convert; hook != nil {
		// The hook sees the request as the plugin would, decoded from the
		// encoded bytes.
		decoded, err := model.DecodeConvertRequest(payload)
		if err != nil {
			return model.ConvertReply{}, err
		}
		if reply, err = hook(ctx, pluginID, decoded); err != nil {
			return model.ConvertReply{}, err
		}
	} else {
		if !s.substoreBindConvertSealed(pluginID) {
			return model.ConvertReply{}, substoreBindRefusal{reason: substoreBindDenyConvertUnsealed}
		}
		out, err := s.callRuntimePluginService(ctx, pluginID, pluginID+"/subscription", "convert", payload, nil, nil)
		if err != nil {
			return model.ConvertReply{}, err
		}
		if err := json.Unmarshal(out, &reply); err != nil {
			return model.ConvertReply{}, fmt.Errorf("decode convert reply: %w", err)
		}
	}
	if err := reply.Validate(); err != nil {
		return model.ConvertReply{}, err
	}
	return reply, nil
}
