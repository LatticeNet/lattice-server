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
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/proxycore"
	"github.com/LatticeNet/lattice-server/internal/store"
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
//     Subscription-Userinfo from the identity's policy, never the provider's,
//     and the record headers the allow-list admits (shareRecordHeaders),
//     each screened for the identity's credentials;
//   - a plan with fleet nodes and none includable, a document plan that
//     fails validation, a plan whose selection core cannot establish or
//     that disagrees with the record's snapshot, a plugin whose signed
//     convert budget allows host calls, a share that names no identity, an
//     identity that is missing or not in service: the decoy, audited with
//     the reason, so a client keeps the nodes it has;
//   - a share that names an identity on a record that rendered a document
//     instead of a plan: the decoy (fleet_share_legacy_document), whatever
//     the record is. A legacy record's document carries the line owners'
//     credentials, and an identity holder must never receive it, not after
//     a migration whose last-good snapshot is still the legacy envelope and
//     not after an approved plan that previewed "every line removed".
//
// The selection a plan is checked against is the plan's own (PlanSelection):
// the plugin rendered it from the record's snapshot, and on the serve path
// core requires it to name the snapshot's catalogue version and only lines
// among the snapshot's rows, which the plugin's fetch wrote from catalogue
// rows. Render and its scripts cannot change the snapshot, so a script
// cannot widen the selection, and a plugin bug that builds the wrong one is
// refused rather than bound. A plan from a plugin that predates PlanSelection
// is checked against the snapshot's selection directly. A snapshot core
// cannot read a selection from refuses the plan rather than letting the
// identity's bindings stand in for it.
//
// The record's snapshot is identity-free, so its content version cannot see
// an identity rotate a credential, gain a line or get parked. A share that
// names an identity therefore caches its body under a key that also carries
// a digest of that identity's bind state (substoreBindStateDigest): a change
// to it is a cache miss and a fresh bind, not an extension of the old body.
// The digest also carries the inputs of the record's opt-in bind rules
// (probe and usage exclusion, DDNS dialling), which can exclude or admit a
// line without the snapshot moving. The key is built before any snapshot or
// plan is read, so the record's policy comes from a memo that a serve-path
// bind of the live revision fills from the plan it bound
// (substoreBindPolicyMemo).

// substoreBindState is the bind step's state on the server. It lives in
// substoreCatalogueState.
type substoreBindState struct {
	// convert replaces the plugin's convert call in tests.
	convert func(ctx context.Context, pluginID string, req model.ConvertRequest) (model.ConvertReply, error)
	// renderPlan replaces the plugin's render call of a bind preview in
	// tests.
	renderPlan func(ctx context.Context, q substoreBindRenderQuery) (*model.SelectionPlan, string, error)
	// probe reads a line's last probe verdict for the cache digest. Nil
	// until a probe history records lines (design 27), and then the
	// catalogue's row.Probe must come from the same reader, since the bind's
	// probe rule reads the row and the digest reads this.
	probe func(lineUUID string) *model.LineCatalogueProbe
	// dayRows replaces the identity day-row read of the bind step in tests,
	// which count it.
	dayRows func(userID string, from, to time.Time) []store.UsageDayUser
	// memo is the per-record policy the cache digest reads.
	memo substoreBindPolicyMemo
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
	// substoreBindDenyLegacyDocument: a share that names an identity got a
	// document from its record's render instead of a plan.
	substoreBindDenyLegacyDocument = "fleet_share_legacy_document"
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

// substoreBindSelection is the line set a fleet snapshot selected
// (substoreBindSnapshotSelection without the version).
func substoreBindSelection(snap model.SubscriptionSnapshot) map[string]bool {
	_, selected := substoreBindSnapshotSelection(snap)
	return selected
}

// substoreBindSnapshotSelection is the catalogue version and the line set a
// fleet snapshot selected, read from a snapshot whose content is a catalogue
// document (its top-level catalogue_version and its rows' line_uuid; a
// collection with fleet members writes a derived version and one union row
// per line there). The set is nil when the snapshot is not one (a provider
// record, a legacy envelope, an envelope this core cannot read).
func substoreBindSnapshotSelection(snap model.SubscriptionSnapshot) (string, map[string]bool) {
	raw := strings.TrimSpace(snap.Raw)
	if !strings.HasPrefix(raw, "{") {
		return "", nil
	}
	var doc struct {
		CatalogueVersion string `json:"catalogue_version"`
		Rows             []struct {
			LineUUID string `json:"line_uuid"`
		} `json:"rows"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil || !strings.HasPrefix(doc.CatalogueVersion, lineCatalogueVersionPrefix) {
		return "", nil
	}
	selected := make(map[string]bool, len(doc.Rows))
	for _, row := range doc.Rows {
		if validLineUUIDv4(row.LineUUID) {
			selected[row.LineUUID] = true
		}
	}
	return doc.CatalogueVersion, selected
}

// substoreBindCheckSelection is the serve path's check of a plan's own
// selection against the record's snapshot: the same catalogue version, and
// only lines the snapshot's rows hold. It returns selection_mismatch or "".
// A plan without a selection passes; substoreBindPlan then reads the
// snapshot's.
func substoreBindCheckSelection(plan model.SelectionPlan, snap model.SubscriptionSnapshot) string {
	if plan.Selection == nil {
		return ""
	}
	version, selected := substoreBindSnapshotSelection(snap)
	if selected == nil || plan.Selection.CatalogueVersion != version {
		return substoreBindRefusedSelectionMismatch
	}
	for _, lineUUID := range plan.Selection.LineUUIDs {
		if !selected[lineUUID] {
			return substoreBindRefusedSelectionMismatch
		}
	}
	return ""
}

// substoreBindServeState is what a request for a share that names an
// identity needs before the cache: the cache-key fragment that carries the
// identity's bind state and the record's policy inputs, and the identity's
// policy for the quota header. refusal is set when the identity is missing
// or not in service. It reads the identity's day rows at most once, and only
// when its quota or the record's usage rule needs them.
func (s *Server) substoreBindServeState(share model.SubscriptionShare, now time.Time) (string, vpnUserPolicy, string) {
	u, ok := s.getVpnUser(share.Source.IdentityID)
	if !ok {
		return "", vpnUserPolicy{}, substoreBindDenyIdentityMissing
	}
	policy := s.substoreBindPolicyFor(share.Source.PluginID, share.Source.SubscriptionID)
	identity, usage := s.substoreBindIdentityState(u, now, policy != nil && policy.Usage != nil)
	if !identity.Active() {
		return "", identity, substoreBindDenyIdentityPrefix + firstNonEmpty(identity.Reason, identity.Status)
	}
	return ";bind=" + s.substoreBindStateDigest(u, policy, usage), identity, ""
}

// substoreBindIdentityState is the identity's policy at now, as
// vpnUserPolicyAt decides it, and, when wantUsage, its traffic per
// line_hash_id in its current period (its monthly quota period, or the
// calendar month when it has none, as the catalogue reports usage), from one
// read of its day rows. The rows are read only when the quota or the usage
// rule needs them: an identity with no quota and no usage rule costs none.
func (s *Server) substoreBindIdentityState(u VpnUser, now time.Time, wantUsage bool) (vpnUserPolicy, map[string]int64) {
	periodStart, _, monthly := vpnUserQuotaPeriod(u, now)
	if !monthly {
		periodStart, _ = quotaPeriodBounds(now, 1)
	}
	var total int64
	var from time.Time
	read, coverRetention := wantUsage, false
	if wantUsage {
		from = periodStart
	}
	if u.QuotaBytes > 0 {
		total = s.vpnUserAccountTotal(u)
		switch {
		case monthly:
			read, from = true, periodStart
		case proxyQuotaExhausted(total, u.QuotaBytes):
			// The retained rows cover the calendar month the usage rule reads.
			read, from, coverRetention = true, now.AddDate(0, 0, -store.UsageDayRetentionDays), true
		}
	}
	var rows []store.UsageDayUser
	if read {
		rows = s.substoreBindDayRows(u.ID, from, now)
	}
	policy := decideVpnUserPolicy(u, vpnUserQuotaUsage{}, now)
	if u.QuotaBytes > 0 {
		policyRows := rows
		if !monthly && !coverRetention {
			policyRows = nil
		}
		policy = decideVpnUserPolicy(u, vpnUserQuotaMeasure(u, total, policyRows, coverRetention, now, usageCounter{}), now)
	}
	if !wantUsage {
		return policy, nil
	}
	usage := map[string]int64{}
	first := store.UsageDay(periodStart)
	for _, row := range rows {
		if row.Day < first {
			continue
		}
		for hash, line := range row.ByLine {
			usage[hash] += line.Uplink + line.Downlink
		}
	}
	return policy, usage
}

// substoreBindDayRows reads an identity's day rows for the bind step.
func (s *Server) substoreBindDayRows(userID string, from, to time.Time) []store.UsageDayUser {
	if hook := s.substoreCatalogue.bind.dayRows; hook != nil {
		return hook(userID, from, to)
	}
	return s.usageDayUserRows(userID, from, to)
}

// substoreBindLineProbe is a line's last probe verdict as the digest reads
// it; nil while no probe history records lines.
func (s *Server) substoreBindLineProbe(lineUUID string) *model.LineCatalogueProbe {
	if probe := s.substoreCatalogue.bind.probe; probe != nil {
		return probe(lineUUID)
	}
	return nil
}

// substoreBindStateDigest digests what binding this identity reads beyond
// the record's snapshot: its credentials, its bindings and their applied
// credential, and for each enabled binding the line's service state,
// whether the identity is parked on it, its stored template and the
// addresses its hosts resolved to (check 3 and the NAT rule read them).
// When the record's policy is known it also covers the policy itself and,
// per enabled binding, the outcome of each rule the policy names: whether
// the probe rule excludes the line, whether the identity's usage on the
// line is over the threshold (the rule fires strictly above it, so the
// boolean flips exactly where the exclusion does), and, for DDNS dialling,
// every input of the line's DDNS verification (each name's resolved
// addresses, the node's public addresses, a cname profile's target and the
// provider edge's addresses). Every input comes from memory: the read
// model, the store's in-memory state and the names the template sync
// resolved, never a DNS query or a node call. It is derived from
// credentials, so it stays in the process: a cache key, never a log line
// or an audit field.
func (s *Server) substoreBindStateDigest(u VpnUser, policy *model.BindPolicy, usage map[string]int64) string {
	_, index := s.lineReadModel()
	names := s.substoreCatalogue.names.snapshot()
	h := sha256.New()
	write := func(parts ...string) {
		for _, part := range parts {
			h.Write([]byte(part))
			h.Write([]byte{0})
		}
	}
	resolved := func(host string) string {
		return strings.Join(names[lineCatalogueNameKey(strings.Trim(strings.TrimSpace(host), "[]"))], ",")
	}
	write("lattice substore bind state v2", u.ID)
	for _, c := range u.Credentials {
		write(c.Protocol, c.UUID, c.Password, c.Flow)
	}
	if policy != nil {
		probe, threshold := 0, int64(0)
		if policy.Probe != nil {
			probe = policy.Probe.ConsecutiveFailures
		}
		if policy.Usage != nil {
			threshold = policy.Usage.MaxBytesPerLine
		}
		write("policy", strconv.Itoa(probe), strconv.FormatInt(threshold, 10), strconv.FormatBool(policy.DDNSDial))
	}
	ddnsNodes := map[string]bool{}
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
		templateHost := ""
		if t, ok := s.store.LineClientTemplate(b.LineHashID); ok {
			templateHost = t.Host
			write(t.Host, strconv.Itoa(t.Port), t.UpdatedAt.UTC().Format(time.RFC3339Nano))
		}
		write("addresses", resolved(ln.PublicHost), resolved(ln.ProviderEdge), resolved(templateHost))
		if policy == nil {
			continue
		}
		if p := policy.Probe; p != nil {
			probe := s.substoreBindLineProbe(ln.LineUUID)
			excluded := probe != nil && probe.Verdict == model.LineProbeVerdictFail && probe.ConsecutiveFailures >= p.ConsecutiveFailures
			write("probe", strconv.FormatBool(excluded))
		}
		if p := policy.Usage; p != nil {
			write("usage", strconv.FormatBool(usage[b.LineHashID] > p.MaxBytesPerLine))
		}
		if policy.DDNSDial && !ddnsNodes[ln.NodeID] {
			ddnsNodes[ln.NodeID] = true
			s.substoreBindDigestDDNS(write, resolved, ln.NodeID)
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// substoreBindDigestDDNS writes every input of one node's DDNS name
// verification: the node's public addresses and, for each profile, its
// record type, its cname target and that target's addresses, and each
// name's resolved addresses. Whatever rule decides Verified and Target over
// these, a change to its outcome changes one of them.
func (s *Server) substoreBindDigestDDNS(write func(...string), resolved func(string) string, nodeID string) {
	node, _ := s.store.Node(nodeID)
	write("ddns", nodeID, strings.TrimSpace(node.PublicIP), strings.TrimSpace(node.PublicIPv6))
	profiles := s.store.DDNSProfilesForNode(nodeID)
	slices.SortFunc(profiles, func(a, b model.DDNSProfile) int { return strings.Compare(a.ID, b.ID) })
	for _, profile := range profiles {
		write(profile.ID, profile.RecordType, profile.CNAMETarget, resolved(profile.CNAMETarget))
		domains := slices.Clone(profile.Domains)
		slices.Sort(domains)
		for _, domain := range domains {
			write(lineCatalogueNameKey(domain), resolved(domain))
		}
	}
}

// substoreBindPolicyMemo is the policy of each fleet-bound record that
// carries one, as the plan of its live revision stated it, so the cache
// key of a share can cover the policy's inputs before any snapshot or plan
// is read. A serve-path bind miss of the live revision fills it; previews
// never write it, since they bind staged revisions.
//
// An entry is valid only at the publication epoch of its record that it was
// written under. Every epoch bump drops the record's cached bodies too (a
// plan apply through invalidateSharesForPlugin, a refresh whose content
// moved), so an entry stops counting exactly when the bodies keyed with it
// are gone, and the next miss writes it again. A write carries the epoch
// the render read before it started and the plugin generation read before
// the bind, and is dropped when either has moved, so a miss that started
// before an apply cannot write the old policy back. Entries are never
// evicted: an evicted entry would bring back the policy-free key, which can
// hit a body cached before the entry was written. The memo holds one small
// entry per record that carries a policy and, like the body cache, lives in
// memory, so after a restart both are empty together and the first request
// is a miss that binds in full.
type substoreBindPolicyMemo struct {
	mu      sync.Mutex
	entries map[subscriptionRefreshKey]substoreBindPolicyEntry
}

type substoreBindPolicyEntry struct {
	epoch  uint64
	policy model.BindPolicy
}

// substoreBindPolicyFor is the record's policy from the memo, nil when the
// memo holds none valid now.
func (s *Server) substoreBindPolicyFor(pluginID, subscriptionID string) *model.BindPolicy {
	key := subscriptionRefreshKey{pluginID: pluginID, subscriptionID: subscriptionID}
	publication := s.subscriptionPublicationStateFor(key)
	publication.mu.Lock()
	defer publication.mu.Unlock()
	memo := &s.substoreCatalogue.bind.memo
	memo.mu.Lock()
	defer memo.mu.Unlock()
	entry, ok := memo.entries[key]
	if !ok || entry.epoch != publication.epoch {
		return nil
	}
	return substoreBindClonePolicy(&entry.policy)
}

// substoreBindRememberPolicy records the policy of the plan a serve-path
// bind of the record's live revision bound. epoch is the record's
// publication epoch the render read, generation the plugin generation read
// before the bind; the write is dropped when either has moved. A plan
// without a policy removes the record's entry.
func (s *Server) substoreBindRememberPolicy(pluginID, subscriptionID string, epoch, generation uint64, policy *model.BindPolicy) {
	if s.substoreBindPluginGeneration(pluginID) != generation {
		return
	}
	key := subscriptionRefreshKey{pluginID: pluginID, subscriptionID: subscriptionID}
	publication := s.subscriptionPublicationStateFor(key)
	publication.mu.Lock()
	defer publication.mu.Unlock()
	if publication.epoch != epoch {
		return
	}
	memo := &s.substoreCatalogue.bind.memo
	memo.mu.Lock()
	defer memo.mu.Unlock()
	if policy == nil {
		delete(memo.entries, key)
		return
	}
	if memo.entries == nil {
		memo.entries = map[subscriptionRefreshKey]substoreBindPolicyEntry{}
	}
	memo.entries[key] = substoreBindPolicyEntry{epoch: epoch, policy: *substoreBindClonePolicy(policy)}
}

// substoreBindPluginGeneration is the plugin's subscription mutation
// generation, which every gated write and plan apply moves.
func (s *Server) substoreBindPluginGeneration(pluginID string) uint64 {
	state := s.subscriptionPluginMutationStateFor(pluginID)
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.generation
}

func substoreBindClonePolicy(p *model.BindPolicy) *model.BindPolicy {
	if p == nil {
		return nil
	}
	out := *p
	if p.Probe != nil {
		probe := *p.Probe
		out.Probe = &probe
	}
	if p.Usage != nil {
		usage := *p.Usage
		out.Usage = &usage
	}
	return &out
}

// substoreBindRendered binds a rendered plan and converts it. A render that
// carried a document is returned as it was to a share that names no
// identity, and refused to one that does. Either way the record headers
// pass the allow-list here, before anything is cached. It runs on the serve
// path only, where the render was of the record's live revision, so it is
// what fills the policy memo.
func (s *Server) substoreBindRendered(ctx context.Context, share model.SubscriptionShare, format string, variant shareRenderVariant,
	snap model.SubscriptionSnapshot, rendered renderedSubscription) (renderedSubscription, error) {
	if rendered.Plan == nil {
		if share.Source.IdentityID != "" {
			return renderedSubscription{}, substoreBindRefusal{reason: substoreBindDenyLegacyDocument}
		}
		rendered.Headers = shareRecordHeaders(lineCatalogueSecrets{}, rendered.Headers)
		return rendered, nil
	}
	plan := *rendered.Plan
	rendered.Plan = nil
	generation := s.substoreBindPluginGeneration(share.Source.PluginID)
	s.substoreBindRememberPolicy(share.Source.PluginID, share.Source.SubscriptionID, rendered.SourceEpoch, generation, plan.Policy)
	if share.Source.IdentityID == "" {
		return renderedSubscription{}, substoreBindRefusal{reason: substoreBindDenyNoIdentity}
	}
	u, ok := s.getVpnUser(share.Source.IdentityID)
	if !ok {
		return renderedSubscription{}, substoreBindRefusal{reason: substoreBindDenyIdentityMissing}
	}
	policy, usage := s.substoreBindIdentityState(u, s.now(), plan.Policy != nil && plan.Policy.Usage != nil)
	if !policy.Active() {
		return renderedSubscription{}, substoreBindRefusal{reason: substoreBindDenyIdentityPrefix + firstNonEmpty(policy.Reason, policy.Status)}
	}
	if refused := substoreBindCheckSelection(plan, snap); refused != "" {
		return renderedSubscription{}, substoreBindRefusal{reason: substoreBindDenyPrefix + refused}
	}
	catalogue, err := s.buildLineCatalogue("")
	if err != nil {
		return renderedSubscription{}, err
	}
	result := substoreBindPlan(plan, u, catalogue, substoreBindInputs{selected: substoreBindSelection(snap), usage: usage,
		names: s.substoreCatalogue.names.snapshot()})
	for _, x := range result.Excluded {
		if x.Reason == substoreBindRejectedPrefix+"skip-cert-verify" {
			s.logger.Printf("sub-store bind: share %s: line %s excluded: the plan turns certificate checks off where the line's template does not", share.ID, x.LineUUID)
		}
	}
	if result.Refused != "" {
		return renderedSubscription{}, substoreBindRefusal{reason: substoreBindDenyPrefix + result.Refused}
	}

	target := firstNonEmpty(reportedRenderTarget(rendered.Target), variant.Target, variant.UATarget)
	req := model.ConvertRequest{Target: target, Options: variant.options()}
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
	var chainHeaders map[string]string
	if len(plan.ResponseChain) > 0 {
		chainHeaders = s.substoreBindChainHeaders(ctx, share, req, plan.ResponseChain, reply.Content)
	}
	rendered.Body = []byte(reply.Content)
	rendered.ContentType = reply.ContentType
	rendered.Target = firstNonEmpty(reportedRenderTarget(reply.Target), req.Target)
	rendered.Userinfo = identityLinkUserinfo(policy, false)
	rendered.Bound = true
	rendered.Headers = shareRecordHeaders(newLineCatalogueSecrets(lineCatalogueIdentitySecrets(u)), rendered.Headers, chainHeaders)
	return rendered, nil
}

// substoreBindChainHeaders runs a fleet-bound record's Response Transformers
// for the headers they set and for nothing else (design 28, the 2026-10-09
// decision). Convert runs a second time over the same bound input with the
// chain, and the body it returns is discarded: the share serves the first
// call's body, which no script touched after binding, because a rewrite
// after binding could move a line to a host the script controls, and core
// does not parse every target format to catch it. A chain that fails leaves
// the share served without the chain's headers. It costs a second convert
// only on a render of a record that has a chain; a cached body costs nothing.
func (s *Server) substoreBindChainHeaders(ctx context.Context, share model.SubscriptionShare, req model.ConvertRequest,
	chain []model.ResponseTransformerStep, body string) map[string]string {
	req.ResponseChain = chain
	reply, err := s.substoreBindConvert(ctx, share.Source.PluginID, req)
	if err != nil {
		s.logger.Printf("sub-store bind: share %s: the response chain failed (%s); served without its headers", share.ID, subscriptionDiagnosticSummary(err))
		return nil
	}
	if len(reply.Log) > 0 {
		// The response chain ran over the bound document, so what it wrote
		// may carry a credential: counted, never copied.
		s.logger.Printf("sub-store bind: share %s: the response chain wrote %d log line(s)", share.ID, len(reply.Log))
	}
	if reply.Content != body {
		s.logger.Printf("sub-store bind: share %s: the response chain rewrote the body; the rewrite was discarded", share.ID)
	}
	return reply.Headers
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
