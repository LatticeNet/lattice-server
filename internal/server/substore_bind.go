package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Validate-and-bind (design 28, pipeline stage 5).
//
// A fleet-bound record renders to a selection plan: the record's chain ran
// in the plugin over catalogue rows that carry placeholder credentials, and
// the plan lists what came out. Before the share's identity is bound, every
// fleet node in the plan is checked against the line catalogue, because a
// script (a remote one included) could otherwise point a node at a host it
// controls and have core put the identity's credential into it. A node is
// bound only when:
//
//  1. it names a line (no_line), it is at most the MaxPlanClonesPerLine-th
//     node naming that line (clone_limit), the catalogue holds the line
//     (line_unknown), the plan's selection selected it, or the record's
//     snapshot for a plan from a plugin that states none
//     (plan_rejected:line_uuid), and the identity has an enabled binding to
//     it (not_bound, binding_disabled);
//  2. its type, transport, security and credential fields are the
//     template's: the credential fields are exactly the template protocol's,
//     each still holding its own placeholder, unmodified and nowhere else in
//     the node (plan_rejected:credential); type, network, tls, reality-opts,
//     sni and the protocol fields the template fixes equal the template
//     (plan_rejected:<field>);
//  3. its server is the template host, the line's provider edge, one of its
//     verified DDNS names or one of the catalogue's addresses for it, and its
//     port is the template port (plan_rejected:server, plan_rejected:port).
//     A line behind NAT, whose template host is its provider edge, narrows
//     the set to the edge, the edge's own addresses and the verified names
//     whose Target is the edge: the node's own public addresses are the
//     provider's shared egress, where another node may be listening.
//     Design 28 also admits a port inside the line's port-hopping range, but
//     no template records one (see substoreBindCheckNode), so the port is
//     the template's exactly;
//  4. every other field is in the named mutable set or is one this file
//     lists as carried without effect on where or how the client connects;
//     anything else is plan_rejected:<field>. skip-cert-verify is in the
//     mutable set only as false, or as true where the template itself turns
//     certificate checks off: a script that turns them off for a line whose
//     template verifies would let anyone on the path read the credential.
//
// A transport options object (ws-opts, xhttp-opts and the like) is checked
// key by key (substoreBindTransportOptions): it must belong to the node's
// network, carry only the keys the URI parsers set from a catalogue
// template, and every key that names a host (a Host header, h2's host list,
// xhttp's host) must name one of the line's hosts. Path and framing values
// are not compared, because the parser rewrites them (early data cut from a
// path, a default path added) and they route only inside the server check 3
// fixed. A key that names a second endpoint, such as xhttp's
// download-settings, is refused, and so are the parser annotations that
// carry raw extra options (_extra, _extra_unsupported) or a gRPC authority:
// a catalogue template carries no parameter that sets them.
//
// A validated node is then bound the way an identity link binds the line
// (identityLinkLineCheck): the same exclusions with the same reasons, plus,
// for a committed chain root, the path state (graph_drifted, graph_busy),
// plus the record's opt-in policy (model.BindPolicy): a line whose probe
// failed at least N times in a row (probe_failed; a null probe block never
// excludes) and a line on which the identity used more than the threshold in
// its current period (usage_exceeded).
// Binding writes the identity's credential where each placeholder was and,
// for vless, the identity's flow.
//
// A document plan cannot drop a node's text. A node that fails validation
// (plan_rejected:*, no_line, clone_limit) refuses the whole document with its
// reason. A node excluded for an operational reason (the line is down, not
// bound to the identity, its credential not applied, and the like) keeps its
// text with an inert credential in place of each placeholder, so one line
// cannot take the identity's whole document offline, and is listed as
// excluded. Each placeholder must occur in the text exactly as many times as
// there are plan nodes carrying it (placeholder_count), and every occurrence
// of a placeholder that receives a real credential must be that credential's
// own value inside a proxy mapping that passes checks 2 to 4 for the
// placeholder's line, at the text position the parser read it from
// (substore_bind_document.go). A script can therefore neither move such a
// node's server in the text while leaving the typed nodes honest, nor reach
// the credential through a comment, an alias or a merge key.

// Exclusion reasons and whole-plan refusals of the bind step. The identity
// link's line reasons (identityLine*) apply as well.
const (
	substoreBindReasonNoLine           = "no_line"
	substoreBindReasonCloneLimit       = "clone_limit"
	substoreBindReasonPlaceholderCount = "placeholder_count"
	substoreBindReasonNotBound         = "not_bound"
	substoreBindReasonGraphDrifted     = "graph_drifted"
	substoreBindReasonGraphBusy        = "graph_busy"
	// substoreBindReasonProbeFailed: the record's policy excludes a line
	// whose last probe failed at least its threshold of times in a row.
	substoreBindReasonProbeFailed = "probe_failed"
	// substoreBindReasonUsageExceeded: the record's policy excludes a line
	// on which the identity used more than its threshold this period.
	substoreBindReasonUsageExceeded = "usage_exceeded"
	substoreBindRejectedPrefix      = "plan_rejected:"

	// substoreBindRefusedEmpty: the plan carries no node.
	substoreBindRefusedEmpty = "empty_plan"
	// substoreBindRefusedNoLine: the plan has fleet nodes and none could be
	// bound. The share answers the decoy so clients keep the nodes they have.
	substoreBindRefusedNoLine = "no_includable_line"
	// substoreBindRefusedSelection: the plan has fleet nodes, states no
	// selection, and the record's snapshot does not say which lines it
	// selected, so check 1 cannot run. The identity's bindings alone never
	// stand in for the selection.
	substoreBindRefusedSelection = "selection_unknown"
	// substoreBindRefusedSelectionMismatch: on the serve path, the plan's
	// selection names another catalogue version than the record's snapshot,
	// or a line the snapshot's rows do not hold. A plugin bug in building the
	// selection cannot widen a share past its own fetch output.
	substoreBindRefusedSelectionMismatch = "selection_mismatch"
)

// Fields of a fleet node, by what the bind step does with them.
var (
	// substoreBindMutableFields may differ from the template freely
	// (design 28's named mutable set), except skip-cert-verify, which
	// substoreBindCheckNode holds to the template.
	substoreBindMutableFields = map[string]bool{
		"name": true, "udp": true, "tfo": true, "mptcp": true, "ip-version": true, "block-quic": true,
		"ecn": true, "alpn": true, "client-fingerprint": true, "skip-cert-verify": true, "script": true,
	}
	// substoreBindComparedFields are checked against the template or the
	// catalogue row. The transport options objects are checked key by key
	// (substoreBindTransportOptions).
	substoreBindComparedFields = map[string]bool{
		"type": true, "server": true, "port": true, "uuid": true, "password": true, "username": true,
		"network": true, "tls": true, "sni": true, "servername": true, "reality-opts": true,
		"encryption": true, "cipher": true, "alterId": true, "tls-fingerprint": true, "line_uuid": true,
		"ws-opts": true, "grpc-opts": true, "h2-opts": true, "http-opts": true, "xhttp-opts": true,
	}
	// substoreBindCarriedFields are carried and not compared. None of them
	// moves the connection off the line's server or weakens its security:
	// flow is replaced by the identity's own, the protocol tuning fields
	// change framing only, the Lattice fields are the catalogue's own
	// metadata and the parser annotations are the ones the URI parsers set
	// from a catalogue template's parameters. The SDK owns the list, so the
	// plugin's plan encoder, convert's strip and this set cannot drift.
	substoreBindCarriedFields = substoreBindFieldSet(model.SelectionPlanCarriedFields)
	// substoreBindTransportOptions are the transport options objects a node
	// may carry: the network each belongs to and the keys the URI parsers set
	// in it from a catalogue template's parameters, by kind.
	substoreBindTransportOptions = map[string]substoreBindOptions{
		"ws-opts": {network: "ws", keys: map[string]substoreBindOptKind{
			"path": substoreBindOptPath, "headers": substoreBindOptHeaders, "max-early-data": substoreBindOptScalar,
			"early-data-header-name": substoreBindOptEarlyDataHeader, "v2ray-http-upgrade": substoreBindOptScalar,
			"v2ray-http-upgrade-fast-open": substoreBindOptScalar, "_v2ray-http-upgrade-ed": substoreBindOptScalar}},
		"http-opts": {network: "http", keys: map[string]substoreBindOptKind{
			"path": substoreBindOptPath, "headers": substoreBindOptHeaders, "method": substoreBindOptScalar}},
		"h2-opts": {network: "h2", keys: map[string]substoreBindOptKind{
			"path": substoreBindOptPath, "host": substoreBindOptHosts}},
		"grpc-opts": {network: "grpc", keys: map[string]substoreBindOptKind{
			"grpc-service-name": substoreBindOptScalar}},
		"xhttp-opts": {network: "xhttp", keys: map[string]substoreBindOptKind{
			"path": substoreBindOptPath, "host": substoreBindOptHosts, "mode": substoreBindOptScalar,
			"headers": substoreBindOptHeaders}},
	}
	// substoreBindCredentialFields are the credential fields of any protocol.
	substoreBindCredentialFields = []string{"password", "username", "uuid"}

	// substoreBindFieldName is a field name a reason may quote.
	substoreBindFieldName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
)

// substoreBindFieldSet is a field list as a set.
func substoreBindFieldSet(fields []string) map[string]bool {
	out := make(map[string]bool, len(fields))
	for _, field := range fields {
		out[field] = true
	}
	return out
}

// substoreBindInputs is what binding a plan reads beside the plan, the
// identity and the catalogue.
type substoreBindInputs struct {
	// selected is the line set the record's snapshot selected, which a plan
	// that states no selection of its own is checked against (a plan from a
	// plugin that predates PlanSelection). Nil means the snapshot does not
	// say. A plan that carries a selection is checked against it instead.
	selected map[string]bool
	// usage is the identity's traffic per line_hash_id in its current
	// period, read only when the plan's policy names usage.
	usage map[string]int64
	// names are the host names the catalogue resolved at the last template
	// sync, from which the NAT rule takes a provider edge's own addresses.
	names map[string][]string
}

// substoreBindRules are the per-line rules of one bind: the selection check
// 1 reads and the record's policy.
type substoreBindRules struct {
	selected map[string]bool
	policy   *model.BindPolicy
	usage    map[string]int64
	names    map[string][]string
}

// substoreBindEntry is one node the bind step includes, as a preview shows
// it: no credential.
type substoreBindEntry struct {
	// Index is the node's position in the plan.
	Index    int    `json:"index"`
	LineUUID string `json:"line_uuid,omitempty"`
	// Provider marks a node from provider content, which is not bound.
	Provider bool `json:"provider,omitempty"`
	// Name is the node's name after the chain.
	Name string `json:"name,omitempty"`
	// Label is the line's own name, "<node name> <line name>", as an
	// identity link writes it.
	Label    string `json:"label,omitempty"`
	NodeID   string `json:"node_id,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Server   string `json:"server,omitempty"`
	Port     int    `json:"port,omitempty"`
	// Clone is the node's position among the plan's nodes for its line,
	// from 1.
	Clone int `json:"clone,omitempty"`
	// Digest identifies the entry as a client receives it, its credential
	// fields left out: everything that decides where and how the client
	// dials, the identity's flow included. Two entries a client would use
	// differently have different digests, and a new placeholder draw does
	// not change it.
	Digest string `json:"digest"`
}

// substoreBindExclusion is one node the bind step left out, and why.
type substoreBindExclusion struct {
	Index    int    `json:"index"`
	LineUUID string `json:"line_uuid,omitempty"`
	Name     string `json:"name,omitempty"`
	Reason   string `json:"reason"`
	Fix      string `json:"fix,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// substoreBindResult is what one identity receives from one plan. Entries
// and Excluded are credential-free; nodes and document carry the identity's
// credentials and never leave the serving path.
type substoreBindResult struct {
	Kind     string
	Entries  []substoreBindEntry
	Excluded []substoreBindExclusion
	// Refused names why the plan cannot be served at all; empty when it can.
	Refused string
	// FleetNodes counts the plan's fleet nodes.
	FleetNodes int

	nodes    []json.RawMessage
	document *model.ConvertDocument
}

// substoreBindShape is what a line's template fixes about a node.
type substoreBindShape struct {
	typ string
	// credential is the protocol's credential fields, sorted.
	credential []string
	network    string
	// anyNetwork accepts tcp as well: a vmess template with neither a path
	// nor a host, whose network the parser drops.
	anyNetwork bool
	// tls is compared unless the protocol always runs over TLS or QUIC.
	compareTLS, tls bool
	reality         bool
	publicKey       string
	shortID         string
	sni             string
	encryption      string
	alterID         int
	pin             string
	// insecure is set when the template itself turns certificate checks off.
	insecure bool
}

// substoreBindTemplateShape reads what a template fixes, in the field names
// and values the URI parsers give a node built from it. ok is false for a
// protocol the binder has no shape for.
func substoreBindTemplateShape(t store.LineClientTemplate) (substoreBindShape, bool) {
	p := t.Params
	security := strings.ToLower(p["security"])
	shape := substoreBindShape{network: "tcp", sni: p["sni"], insecure: substoreBindTruthy(p["insecure"]) || substoreBindTruthy(p["allowInsecure"])}
	switch t.Protocol {
	case "vless":
		shape.typ, shape.credential = "vless", []string{"uuid"}
		shape.network = substoreBindURINetwork(p)
		shape.compareTLS, shape.tls = true, security != "" && security != "none"
		shape.reality = security == "reality" || p["pbk"] != ""
		shape.encryption = p["encryption"]
	case "trojan", "anytls":
		shape.typ, shape.credential = t.Protocol, []string{"password"}
		shape.network = substoreBindURINetwork(p)
		shape.compareTLS, shape.tls = true, true
		shape.reality = security == "reality"
	case "hysteria2":
		shape.typ, shape.credential = "hysteria2", []string{"password"}
		shape.pin = p["pinSHA256"]
	case "tuic":
		shape.typ, shape.credential = "tuic", []string{"password", "uuid"}
	case "vmess":
		shape.typ, shape.credential = "vmess", []string{"uuid"}
		shape.network = substoreBindVMessNetwork(p)
		shape.anyNetwork = p["path"] == "" && p["host"] == ""
		shape.compareTLS = true
		shape.tls = p["tls"] == "tls" || p["tls"] == "1"
		if !shape.tls {
			shape.sni = ""
		}
		if aid, err := strconv.Atoi(strings.TrimSpace(p["aid"])); err == nil {
			shape.alterID = aid
		}
	case "socks":
		shape.typ, shape.credential = "socks5", []string{"password", "username"}
		shape.compareTLS = true
	default:
		return substoreBindShape{}, false
	}
	if shape.reality {
		shape.publicKey, shape.shortID = p["pbk"], p["sid"]
	}
	return shape, true
}

// substoreBindURINetwork is the network the URI parsers give a link's type
// and headerType parameters.
func substoreBindURINetwork(p map[string]string) string {
	switch network := strings.ToLower(p["type"]); network {
	case "", "tcp":
		if strings.EqualFold(p["headerType"], "http") {
			return "http"
		}
		return "tcp"
	case "http":
		return "h2"
	case "websocket", "httpupgrade":
		return "ws"
	default:
		return network
	}
}

// substoreBindVMessNetwork is the network the vmess parser gives a v2rayN
// document's net and type fields.
func substoreBindVMessNetwork(p map[string]string) string {
	network, kind := strings.ToLower(p["net"]), strings.ToLower(p["type"])
	switch {
	case network == "ws":
		return "ws"
	case kind == "http":
		return "http"
	case network == "http":
		return "h2"
	case network == "grpc" || network == "kcp" || network == "quic" || network == "h2":
		return network
	case network == "httpupgrade":
		return "ws"
	}
	return "tcp"
}

// substoreBindTruthy is the parsers' contains-true-or-1 test.
func substoreBindTruthy(value string) bool {
	value = strings.ToLower(value)
	return strings.Contains(value, "true") || strings.Contains(value, "1")
}

// substoreNodeObject is a node's top-level fields in their order, so a bound
// node keeps the order the plugin wrote.
type substoreNodeObject struct {
	keys   []string
	values map[string]json.RawMessage
}

// parseSubstoreNodeObject reads one JSON object, refusing a duplicate key
// and anything after the object.
func parseSubstoreNodeObject(raw json.RawMessage) (substoreNodeObject, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return substoreNodeObject{}, errors.New("node is not a JSON object")
	}
	obj := substoreNodeObject{values: map[string]json.RawMessage{}}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return substoreNodeObject{}, errors.New("node key is not a string")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return substoreNodeObject{}, err
		}
		if _, dup := obj.values[key]; dup {
			return substoreNodeObject{}, errors.New("node repeats a key")
		}
		obj.keys = append(obj.keys, key)
		obj.values[key] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return substoreNodeObject{}, errors.New("node object is not closed")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return substoreNodeObject{}, errors.New("node has trailing data")
	}
	return obj, nil
}

// string returns a field's string value; ok is false when it is absent or
// not a string.
func (o substoreNodeObject) string(key string) (string, bool) {
	raw, present := o.values[key]
	if !present {
		return "", false
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

// with returns a copy with key set to value, appended when it is new.
func (o substoreNodeObject) with(key string, value json.RawMessage) substoreNodeObject {
	out := substoreNodeObject{keys: slices.Clone(o.keys), values: make(map[string]json.RawMessage, len(o.values)+1)}
	for k, v := range o.values {
		out.values[k] = v
	}
	if _, present := out.values[key]; !present {
		out.keys = append(out.keys, key)
	}
	out.values[key] = value
	return out
}

// without returns a copy with key removed.
func (o substoreNodeObject) without(key string) substoreNodeObject {
	if _, present := o.values[key]; !present {
		return o
	}
	out := substoreNodeObject{values: make(map[string]json.RawMessage, len(o.values))}
	for _, k := range o.keys {
		if k != key {
			out.keys = append(out.keys, k)
			out.values[k] = o.values[k]
		}
	}
	return out
}

func (o substoreNodeObject) encode() json.RawMessage {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, key := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		name, _ := json.Marshal(key)
		buf.Write(name)
		buf.WriteByte(':')
		buf.Write(o.values[key])
	}
	buf.WriteByte('}')
	return buf.Bytes()
}

// substoreBindNodeName is a node's name as a preview reports it, cleaned and
// bounded the way an identity link cleans an entry label.
func substoreBindNodeName(obj substoreNodeObject) string {
	name, _ := obj.string("name")
	return identityLinkEntryLabel(name, "")
}

// substoreBindLine is what the bind step knows about one line of the plan,
// computed once however many nodes name it.
type substoreBindLine struct {
	row      model.LineCatalogueRow
	template store.LineClientTemplate
	shape    substoreBindShape
	label    string
	// refuse is why the line cannot carry a plan node at all: the catalogue
	// does not hold it, the snapshot did not select it, the identity is not
	// bound to it, or it has no template.
	refuse identityLinkExclusion
	// exclude is why a validated node of the line is not bound.
	exclude identityLinkExclusion
	payload lineUserCredentialPayload
	// edgeAddrs are the provider edge's own addresses, set for a line behind
	// NAT (its template host is its provider edge), where they replace the
	// row's flat address list in check 3.
	edgeAddrs []string
}

// substoreBindBindings indexes an identity's bindings by line_hash_id; the
// first binding of a line wins, as an identity link reads them.
func substoreBindBindings(u VpnUser) map[string]LineBinding {
	out := make(map[string]LineBinding, len(u.Bindings))
	for _, b := range u.Bindings {
		if _, seen := out[b.LineHashID]; !seen {
			out[b.LineHashID] = b
		}
	}
	return out
}

// substoreBindLineOf works out one line for one identity, whose bindings
// substoreBindBindings indexed. A nil rules.selected checks no selection
// (reveal_entry, which binds one line outside any plan).
func substoreBindLineOf(u VpnUser, bindings map[string]LineBinding, c *lineCatalogue, rules substoreBindRules, lineUUID string) *substoreBindLine {
	out := &substoreBindLine{}
	row, ok := c.Row(lineUUID)
	if !ok {
		out.refuse = identityLinkExclusion{reason: identityLineUnknown, fix: identityFixWaitDiscovery}
		return out
	}
	out.row = row
	if selected := rules.selected; selected != nil && !selected[lineUUID] {
		out.refuse = identityLinkExclusion{reason: substoreBindRejectedPrefix + "line_uuid"}
		return out
	}
	binding, bound := bindings[row.LineHashID]
	switch {
	case !bound:
		out.refuse = identityLinkExclusion{reason: substoreBindReasonNotBound}
		return out
	case !binding.Enabled:
		out.refuse = identityLinkExclusion{reason: identityLineBindingDisabled}
		return out
	}
	template, ok := c.BindTemplate(lineUUID)
	if !ok {
		out.refuse = identityLinkExclusion{reason: identityLineNoTemplate, fix: identityFixWaitTemplate}
		return out
	}
	shape, ok := substoreBindTemplateShape(template)
	if !ok {
		out.refuse = identityLinkExclusion{reason: identityLineProtocol}
		return out
	}
	out.template, out.shape = template, shape
	ln, _ := c.Line(lineUUID)
	out.label = identityLinkEntryLabel(row.NodeName, identityLinkLineName(ln))
	if row.Chain.Root {
		out.payload, out.exclude = substoreBindRootCheck(u, ln, row, template)
	} else {
		out.payload, out.exclude = identityLinkLineCheck(u, binding, ln, template, true)
	}
	if out.exclude.reason == "" {
		if _, err := lineClientURI(template, out.payload, out.label); err != nil {
			out.exclude = identityLinkExclusion{reason: identityLineTemplateUnusable}
		}
	}
	if out.exclude.reason == "" {
		out.exclude = substoreBindPolicyExclusion(rules, row)
	}
	if substoreBindBehindNAT(template, row) {
		out.edgeAddrs = lineCatalogueAddresses([]string{row.ProviderEdge}, rules.names)
	}
	return out
}

// substoreBindPolicyExclusion applies the record's opt-in rules to a line
// that passed every other one. A null probe block never excludes, and usage
// is compared strictly above the threshold.
func substoreBindPolicyExclusion(rules substoreBindRules, row model.LineCatalogueRow) identityLinkExclusion {
	policy := rules.policy
	if policy == nil {
		return identityLinkExclusion{}
	}
	if p := policy.Probe; p != nil && row.Probe != nil && row.Probe.Verdict == model.LineProbeVerdictFail &&
		row.Probe.ConsecutiveFailures >= p.ConsecutiveFailures {
		return identityLinkExclusion{reason: substoreBindReasonProbeFailed,
			detail: strconv.Itoa(row.Probe.ConsecutiveFailures) + " consecutive probe failures"}
	}
	if p := policy.Usage; p != nil && rules.usage[row.LineHashID] > p.MaxBytesPerLine {
		return identityLinkExclusion{reason: substoreBindReasonUsageExceeded}
	}
	return identityLinkExclusion{}
}

// substoreBindBehindNAT reports whether a line is reached through its
// provider edge: the template's host is the edge.
func substoreBindBehindNAT(t store.LineClientTemplate, row model.LineCatalogueRow) bool {
	edge := strings.Trim(strings.TrimSpace(row.ProviderEdge), "[]")
	return edge != "" && strings.EqualFold(strings.Trim(strings.TrimSpace(t.Host), "[]"), edge)
}

// substoreBindRootCheck is identityLinkLineCheck for a committed chain root,
// whose template is the composed vless Reality entry: compose's rules, which
// take the identity's vless credential on any line it is bound to and need
// the path converged, plus the identity link's service rule.
func substoreBindRootCheck(u VpnUser, ln Line, row model.LineCatalogueRow, t store.LineClientTemplate) (lineUserCredentialPayload, identityLinkExclusion) {
	exclude := func(reason, fix string) (lineUserCredentialPayload, identityLinkExclusion) {
		return lineUserCredentialPayload{}, identityLinkExclusion{reason: reason, fix: fix}
	}
	if row.ServiceState == "down" {
		return exclude(identityLineServiceDown, identityFixCheckService)
	}
	switch row.Chain.PathState {
	case model.LinePathConverged:
	case model.LinePathBusy:
		return exclude(substoreBindReasonGraphBusy, "")
	default:
		return exclude(substoreBindReasonGraphDrifted, "")
	}
	if t.Lossy() {
		return lineUserCredentialPayload{}, identityLinkExclusion{reason: identityLineTemplateLossy, detail: strings.Join(t.Dropped, ", ")}
	}
	payload, err := lineUserCredential(u, t.Protocol, userLineName(u.ID, ln.LineUUID))
	if err != nil {
		return exclude(identityLineTemplateUnusable, "")
	}
	if t.Protocol == "vless" && payload.Flow == "" {
		payload.Flow = lineCatalogueComposeFlow
	}
	return payload, identityLinkExclusion{}
}

// substoreBindCheckNode runs checks 2 to 4 on one fleet node. It returns the
// field to reject the node for, or "".
func substoreBindCheckNode(raw json.RawMessage, obj substoreNodeObject, node model.SelectionPlanNode, line *substoreBindLine) string {
	shape, t, row := line.shape, line.template, line.row
	for _, key := range obj.keys {
		if !substoreBindComparedFields[key] && !substoreBindMutableFields[key] && !substoreBindCarriedFields[key] {
			if !substoreBindFieldName.MatchString(key) {
				return "field"
			}
			return key
		}
	}
	if value, present := obj.values["line_uuid"]; present && string(value) != strconv.Quote(node.LineUUID) {
		return "line_uuid"
	}
	if typ, _ := obj.string("type"); typ != shape.typ {
		return "type"
	}
	if !substoreBindCredentialIntact(raw, obj, node, shape) {
		return "credential"
	}
	if server, _ := obj.string("server"); !substoreBindServerAllowed(server, t, row, line.edgeAddrs) {
		return "server"
	}
	// The port is the template's. Design 28's check admits a port inside the
	// line's port-hopping range too, but no template carries a range to admit
	// it from: the template builder keeps one port per share URL, refuses a
	// URL whose authority holds a range, and drops a hysteria2 mport
	// parameter, which makes the template lossy so the line never binds. A
	// hopping range needs a field on the template before this can widen.
	var port json.Number
	if json.Unmarshal(obj.values["port"], &port) != nil || port.String() != strconv.Itoa(t.Port) {
		return "port"
	}
	network := "tcp"
	if value, present := obj.values["network"]; present {
		var text string
		if json.Unmarshal(value, &text) != nil {
			return "network"
		}
		if text != "" {
			network = strings.ToLower(text)
		}
	}
	if network != shape.network && !(shape.anyNetwork && network == "tcp") {
		return "network"
	}
	if field := substoreBindCheckTransport(obj, network, t, row); field != "" {
		return field
	}
	if shape.compareTLS && (string(obj.values["tls"]) == "true") != shape.tls {
		return "tls"
	}
	if !substoreBindRealityMatches(obj, shape) {
		return "reality-opts"
	}
	if !substoreBindSNIAllowed(obj, shape, t, row) {
		return "sni"
	}
	if value, present := obj.values["encryption"]; present {
		var text string
		if shape.typ != "vless" || json.Unmarshal(value, &text) != nil || firstNonEmpty(text, "none") != firstNonEmpty(shape.encryption, "none") {
			return "encryption"
		}
	}
	if value, present := obj.values["cipher"]; present {
		var text string
		if shape.typ != "vmess" || json.Unmarshal(value, &text) != nil || (text != "" && text != "auto") {
			return "cipher"
		}
	}
	if value, present := obj.values["alterId"]; present {
		var aid json.Number
		if shape.typ != "vmess" || json.Unmarshal(value, &aid) != nil || aid.String() != strconv.Itoa(shape.alterID) {
			return "alterId"
		}
	}
	if pin, _ := obj.string("tls-fingerprint"); pin != shape.pin {
		if _, present := obj.values["tls-fingerprint"]; present || shape.pin != "" {
			return "tls-fingerprint"
		}
	}
	// Certificate checks stay what the template says: off only where the
	// template turns them off, and a JSON boolean, so no client reads a
	// string as true where this check read it as false.
	if value, present := obj.values["skip-cert-verify"]; present {
		switch string(value) {
		case "false":
		case "true":
			if !shape.insecure {
				return "skip-cert-verify"
			}
		default:
			return "skip-cert-verify"
		}
	}
	return ""
}

// substoreBindCredentialIntact reports whether a node carries exactly the
// template protocol's credential fields, each holding its own placeholder
// verbatim, and no placeholder anywhere else: not a second time in a name,
// and not another line's.
func substoreBindCredentialIntact(raw json.RawMessage, obj substoreNodeObject, node model.SelectionPlanNode, shape substoreBindShape) bool {
	fields := make([]string, 0, len(node.Placeholders))
	for field := range node.Placeholders {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	if !slices.Equal(fields, shape.credential) {
		return false
	}
	for _, field := range substoreBindCredentialFields {
		if _, present := obj.values[field]; present && !slices.Contains(shape.credential, field) {
			return false
		}
	}
	for field, placeholder := range node.Placeholders {
		if string(obj.values[field]) != strconv.Quote(placeholder) {
			return false
		}
	}
	counts := model.CountPlanPlaceholders(string(raw))
	if len(counts) != len(node.Placeholders) {
		return false
	}
	for _, placeholder := range node.Placeholders {
		if counts[placeholder] != 1 {
			return false
		}
	}
	return true
}

// substoreBindServerAllowed reports whether server is in the line's allowed
// set: the template host, the provider edge, a verified DDNS name, or one of
// the catalogue's addresses for the line. Names compare without case and
// addresses by value. For a line behind NAT (substoreBindBehindNAT) the set
// is the edge, edgeAddrs (the edge's own addresses) and the verified names
// whose Target is the edge; the row's flat address list, which also holds
// the node's own public addresses, does not count.
func substoreBindServerAllowed(server string, t store.LineClientTemplate, row model.LineCatalogueRow, edgeAddrs []string) bool {
	host := strings.TrimSpace(server)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		addresses := row.Addresses
		if substoreBindBehindNAT(t, row) {
			addresses = edgeAddrs
		}
		for _, candidate := range append([]string{t.Host}, addresses...) {
			if other := net.ParseIP(strings.Trim(candidate, "[]")); other != nil && other.Equal(ip) {
				return true
			}
		}
		return false
	}
	return slices.ContainsFunc(substoreBindNames(t, row), func(name string) bool { return strings.EqualFold(name, host) })
}

// substoreBindNames are the names a line's node may be dialled by. A line
// behind NAT takes only the verified names whose Target is its edge: an A
// record name points at the node's own public address, which for such a
// line is the provider's shared egress.
func substoreBindNames(t store.LineClientTemplate, row model.LineCatalogueRow) []string {
	var names []string
	for _, name := range []string{t.Host, row.ProviderEdge} {
		if name = strings.TrimSpace(name); name != "" && net.ParseIP(strings.Trim(name, "[]")) == nil {
			names = append(names, name)
		}
	}
	nat := substoreBindBehindNAT(t, row)
	for _, ddns := range row.DDNSNames {
		if ddns.Verified && (!nat || strings.EqualFold(strings.TrimSpace(ddns.Target), strings.TrimSpace(row.ProviderEdge))) {
			names = append(names, ddns.Name)
		}
	}
	return names
}

// substoreBindRealityMatches reports whether a node's Reality options are
// the template's: present exactly when the template uses Reality, with its
// public key and short id.
func substoreBindRealityMatches(obj substoreNodeObject, shape substoreBindShape) bool {
	raw, present := obj.values["reality-opts"]
	if !shape.reality {
		return !present
	}
	var opts map[string]json.RawMessage
	if !present || json.Unmarshal(raw, &opts) != nil {
		return false
	}
	if string(opts["public-key"]) != strconv.Quote(shape.publicKey) {
		return false
	}
	shortID, ok := opts["short-id"]
	if !ok {
		return shape.shortID == ""
	}
	return string(shortID) == strconv.Quote(shape.shortID)
}

// substoreBindSNIAllowed reports whether a node's server name is the
// template's, or, where the template names none, empty or one of the names
// the line may be dialled by (a resolved server keeps its name as sni).
func substoreBindSNIAllowed(obj substoreNodeObject, shape substoreBindShape, t store.LineClientTemplate, row model.LineCatalogueRow) bool {
	sni, sniOK := obj.string("sni")
	servername, servernameOK := obj.string("servername")
	_, sniPresent := obj.values["sni"]
	_, servernamePresent := obj.values["servername"]
	if (sniPresent && !sniOK) || (servernamePresent && !servernameOK) || (sniOK && servernameOK && sni != servername) {
		return false
	}
	actual := firstNonEmpty(sni, servername)
	if shape.sni != "" {
		return strings.EqualFold(actual, shape.sni)
	}
	return actual == "" || slices.ContainsFunc(substoreBindNames(t, row), func(name string) bool { return strings.EqualFold(name, actual) })
}

// substoreBindEntryDigest digests a node with its credential fields left
// out.
func substoreBindEntryDigest(obj substoreNodeObject) string {
	for _, field := range substoreBindCredentialFields {
		obj = obj.without(field)
	}
	sum := sha256.Sum256(obj.encode())
	return "sha256:" + hex.EncodeToString(sum[:])
}

// substoreBindNodeCredential writes the identity's credential where each
// placeholder of a validated node was and, for vless, the identity's flow.
func substoreBindNodeCredential(obj substoreNodeObject, node model.SelectionPlanNode, line *substoreBindLine) (substoreNodeObject, error) {
	for field := range node.Placeholders {
		value := substoreBindCredentialValue(line.payload, field)
		if value == "" {
			return substoreNodeObject{}, errors.New("the identity's credential has no " + field)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return substoreNodeObject{}, err
		}
		obj = obj.with(field, encoded)
	}
	if line.shape.typ == "vless" {
		if line.payload.Flow == "" {
			obj = obj.without("flow")
		} else {
			flow, _ := json.Marshal(line.payload.Flow)
			obj = obj.with("flow", flow)
		}
	}
	return obj, nil
}

// substoreBindCredentialValue is the identity's value for one credential
// field of a node.
func substoreBindCredentialValue(payload lineUserCredentialPayload, field string) string {
	switch field {
	case "uuid":
		return payload.UUID
	case "password":
		return payload.Password
	case "username":
		return payload.Username
	}
	return ""
}

// substoreBindOperationalReasons are the exclusions that describe the line
// or the identity now rather than the plan: the line is gone, down, parked,
// not bound to the identity, its credential not applied, its template
// unusable, its chain path not converged. A document plan keeps such a
// node's text with an inert credential. Every other reason (plan_rejected:*,
// no_line, clone_limit) says the plan is not what the catalogue allows, and
// refuses a document whole.
var substoreBindOperationalReasons = map[string]bool{
	identityLineUnknown: true, substoreBindReasonNotBound: true, identityLineBindingDisabled: true,
	identityLineManaged: true, identityLineProtocol: true, identityLineNotApplied: true,
	identityLineRotationPending: true, identityLineCredentialUnknown: true, identityLineParked: true,
	identityLineNoTemplate: true, identityLineTemplateLossy: true, identityLineTemplateUnusable: true,
	identityLineServiceDown: true, substoreBindReasonGraphDrifted: true, substoreBindReasonGraphBusy: true,
	substoreBindReasonProbeFailed: true, substoreBindReasonUsageExceeded: true,
}

// substoreBindInertValue is what a document carries in place of a
// placeholder whose line is excluded for an operational reason: a value of
// the credential's shape that authenticates nowhere, so the document still
// loads in a client and only that line's node fails.
func substoreBindInertValue(field string) string {
	if field == "uuid" {
		return lineCatalogueValidationUUID
	}
	return "lattice-line-excluded"
}

// substoreBindPlan validates a plan against the catalogue and binds the
// identity's credentials into it. The selected line set is the plan's own
// selection when it states one, else in.selected, the record's snapshot's;
// with neither, a plan with fleet nodes is refused with selection_unknown
// rather than bound to every line the identity holds. Whether a plan's
// selection agrees with the snapshot is the serve path's check
// (substoreBindCheckSelection), made before this. It reads nothing but its
// arguments.
func substoreBindPlan(plan model.SelectionPlan, u VpnUser, c *lineCatalogue, in substoreBindInputs) substoreBindResult {
	result := substoreBindResult{Kind: plan.Kind}
	selected := in.selected
	if plan.Selection != nil {
		selected = make(map[string]bool, len(plan.Selection.LineUUIDs))
		for _, lineUUID := range plan.Selection.LineUUIDs {
			selected[lineUUID] = true
		}
	}
	rules := substoreBindRules{selected: selected, policy: plan.Policy, usage: in.usage, names: in.names}
	for _, node := range plan.Nodes {
		if !node.Provider && node.LineUUID != "" {
			result.FleetNodes++
		}
	}
	switch {
	case len(plan.Nodes) == 0:
		result.Refused = substoreBindRefusedEmpty
		return result
	case selected == nil && (result.FleetNodes > 0 || plan.Kind == model.SelectionPlanKindDocument):
		result.Refused = substoreBindRefusedSelection
		return result
	}
	excess := map[int]bool{}
	for _, i := range plan.ExcessClones() {
		excess[i] = true
	}
	bindings := substoreBindBindings(u)
	lines := map[string]*substoreBindLine{}
	clones := map[string]int{}
	type candidate struct {
		index int
		node  model.SelectionPlanNode
		obj   substoreNodeObject
		line  *substoreBindLine
		entry substoreBindEntry
	}
	var validated []candidate
	bound := make([]json.RawMessage, len(plan.Nodes))
	exclude := func(index int, lineUUID, name string, why identityLinkExclusion) {
		result.Excluded = append(result.Excluded, substoreBindExclusion{Index: index, LineUUID: lineUUID, Name: name,
			Reason: why.reason, Fix: why.fix, Detail: why.detail})
	}
	// carried are the fleet nodes whose placeholders a document keeps, bound
	// or inert; inert are those excluded for an operational reason.
	var carried, inert []model.SelectionPlanNode
	for i, node := range plan.Nodes {
		obj, err := parseSubstoreNodeObject(node.Node)
		name := ""
		if err == nil {
			name = substoreBindNodeName(obj)
		}
		if node.Provider {
			if err != nil {
				exclude(i, "", "", identityLinkExclusion{reason: substoreBindRejectedPrefix + "node"})
				continue
			}
			server, _ := obj.string("server")
			var port int
			_ = json.Unmarshal(obj.values["port"], &port)
			typ, _ := obj.string("type")
			result.Entries = append(result.Entries, substoreBindEntry{Index: i, Provider: true, Name: name, Protocol: typ, Server: server, Port: port,
				Digest: substoreBindEntryDigest(obj)})
			bound[i] = node.Node
			continue
		}
		if node.LineUUID == "" {
			exclude(i, "", name, identityLinkExclusion{reason: substoreBindReasonNoLine})
			continue
		}
		clones[node.LineUUID]++
		if excess[i] {
			exclude(i, node.LineUUID, name, identityLinkExclusion{reason: substoreBindReasonCloneLimit})
			continue
		}
		line := lines[node.LineUUID]
		if line == nil {
			line = substoreBindLineOf(u, bindings, c, rules, node.LineUUID)
			lines[node.LineUUID] = line
		}
		if line.refuse.reason != "" {
			exclude(i, node.LineUUID, name, line.refuse)
			if substoreBindOperationalReasons[line.refuse.reason] {
				inert = append(inert, node)
			}
			continue
		}
		if err != nil {
			exclude(i, node.LineUUID, name, identityLinkExclusion{reason: substoreBindRejectedPrefix + "node"})
			continue
		}
		if field := substoreBindCheckNode(node.Node, obj, node, line); field != "" {
			exclude(i, node.LineUUID, name, identityLinkExclusion{reason: substoreBindRejectedPrefix + field})
			continue
		}
		server, _ := obj.string("server")
		validated = append(validated, candidate{index: i, node: node, obj: obj, line: line, entry: substoreBindEntry{
			Index: i, LineUUID: node.LineUUID, Name: name, Label: line.label, NodeID: line.row.NodeID,
			Protocol: line.row.Protocol, Server: server, Port: line.template.Port, Clone: clones[node.LineUUID]}})
	}
	substitutions := map[string]string{}
	placed := map[string]substoreBindPlaced{}
	for _, v := range validated {
		if v.line.exclude.reason != "" {
			exclude(v.index, v.node.LineUUID, v.entry.Name, v.line.exclude)
			inert = append(inert, v.node)
			continue
		}
		boundObj, err := substoreBindNodeCredential(v.obj, v.node, v.line)
		if err != nil {
			exclude(v.index, v.node.LineUUID, v.entry.Name, identityLinkExclusion{reason: identityLineTemplateUnusable})
			inert = append(inert, v.node)
			continue
		}
		for field, placeholder := range v.node.Placeholders {
			substitutions[placeholder] = substoreBindCredentialValue(v.line.payload, field)
			placed[placeholder] = substoreBindPlaced{node: v.node, line: v.line}
		}
		carried = append(carried, v.node)
		bound[v.index] = boundObj.encode()
		v.entry.Digest = substoreBindEntryDigest(boundObj)
		result.Entries = append(result.Entries, v.entry)
	}
	sort.SliceStable(result.Entries, func(i, j int) bool { return result.Entries[i].Index < result.Entries[j].Index })
	sort.SliceStable(result.Excluded, func(i, j int) bool { return result.Excluded[i].Index < result.Excluded[j].Index })

	if plan.Kind == model.SelectionPlanKindDocument {
		for _, node := range inert {
			for field, placeholder := range node.Placeholders {
				if _, real := placed[placeholder]; !real {
					substitutions[placeholder] = substoreBindInertValue(field)
				}
			}
		}
		result.Refused = substoreBindDocumentRefusal(plan.Document, result.Excluded, append(carried, inert...), placed)
	}
	boundFleet := 0
	for _, entry := range result.Entries {
		if !entry.Provider {
			boundFleet++
		}
	}
	if result.Refused == "" && boundFleet == 0 && (result.FleetNodes > 0 || plan.Kind == model.SelectionPlanKindDocument) {
		result.Refused = substoreBindRefusedNoLine
	}
	if result.Refused != "" {
		return result
	}
	if plan.Kind == model.SelectionPlanKindDocument {
		result.document = &model.ConvertDocument{Content: plan.Document, Substitutions: substitutions}
		return result
	}
	for _, node := range bound {
		if node != nil {
			result.nodes = append(result.nodes, node)
		}
	}
	return result
}

// substoreBindDocumentRefusal is why a document plan cannot be served, or
// "": the first exclusion that is not operational, a placeholder count that
// differs from the plan nodes the document keeps, or a placeholder that
// receives a real credential somewhere other than a validated proxy
// mapping's credential value (substoreBindDocumentCheck).
func substoreBindDocumentRefusal(document string, excluded []substoreBindExclusion, carried []model.SelectionPlanNode, placed map[string]substoreBindPlaced) string {
	for _, x := range excluded {
		if !substoreBindOperationalReasons[x.Reason] {
			return x.Reason
		}
	}
	expected := map[string]int{}
	for _, node := range carried {
		for _, placeholder := range node.Placeholders {
			expected[placeholder]++
		}
	}
	if !maps.Equal(expected, model.CountPlanPlaceholders(document)) {
		return substoreBindReasonPlaceholderCount
	}
	return substoreBindDocumentCheck(document, placed, expected)
}
