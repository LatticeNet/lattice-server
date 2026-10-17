package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// The core half of the S2 security review's S2-SR-2 refusal (design 28).
// The Sub-Store plugin withholds the script network from every render or
// preview that reaches fleet nodes, and a step that asks for it fails the
// call with an error that leads with fleet_script_network_unavailable
// (fleet_script_network.go in the plugin). Core read that as one more failed
// render: plans.propose answered "bind preview failed", bind.preview "the
// record did not render", and the editor's preview relays the plugin's text
// as a 400. Here core lifts the leading code, from that one fixed value and
// only from the plugin's own refusal channel, into a typed refusal that
// names the record and the step to open, and relays none of the plugin's
// text:
//
//	{"error":{"code":"fleet_script_network_unavailable","record":"<id>",
//	          "step":{"position":<1-based>,"type":"<step type>"},
//	          "message":"fleet_script_network_unavailable: ...","request_id":"..."}}
//
// It answers 409, as core answers every other refusal of a plan's content
// (revision_unknown, fleet_file_unavailable, record_not_fleet_bound): the
// request was well formed, and the record as it stands cannot render until
// its chain changes.
//
// The plugin's error names no step, because the engine does not say which
// step's script asked. Core names the first enabled step that can ask (a
// Script Operator, a Script Filter or a Resolve Domain Operator), read from
// the record documents it already reads for a plan's chain, in the record's
// own chain first and then in the chains of the records it reads. The
// message says so: it is the first candidate, not a proven culprit. A
// refusal where no such step is found names the rendered record and no step.

const (
	// apiErrorFleetScriptNetworkUnavailable is the plugin's code
	// (codeFleetScriptNetworkUnavailable in its subscription_fleet.go), and
	// the code of core's typed refusal.
	apiErrorFleetScriptNetworkUnavailable = "fleet_script_network_unavailable"

	// substoreScriptNetworkMaxRecords bounds the records whose chains are
	// read to find the step.
	substoreScriptNetworkMaxRecords = 64
)

// substoreNetworkStepTypes are the step types whose run can ask for the
// network: the two scripting steps, and Resolve Domain Operator, which
// queries a resolver. They are compared after subStorePlanStepType cleans
// the stored type.
var substoreNetworkStepTypes = map[string]bool{
	"Script Operator":         true,
	"Script Filter":           true,
	"Resolve Domain Operator": true,
}

// substoreScriptNetworkRefused reports whether err is the plugin's own
// refusal of a render or preview whose chain asked for the network over
// fleet nodes: a plugin service error whose message begins with the code and
// a colon. A message that only carries the code later in its text, or any
// other error (a transport failure, a decode error, a core refusal), is not
// one.
func substoreScriptNetworkRefused(err error) bool {
	var serviceErr *pluginServiceError
	if !errors.As(err, &serviceErr) {
		return false
	}
	return strings.HasPrefix(serviceErr.message, apiErrorFleetScriptNetworkUnavailable+":")
}

// substoreScriptNetworkStep is a step a refusal names: its position in the
// chain, from 1, counting every stored step, disabled ones included, as a
// plan's chain lines and the editor number them; and its type, cleaned.
type substoreScriptNetworkStep struct {
	Position int    `json:"position"`
	Type     string `json:"type"`
}

// substoreScriptNetworkRefusal is core's typed refusal. Error is the
// message; Unwrap is the 409 the plugin gateway and the core services write
// through.
type substoreScriptNetworkRefusal struct {
	Record  string
	Step    *substoreScriptNetworkStep
	message string
	op      *pluginOperationError
}

func (e *substoreScriptNetworkRefusal) Error() string { return e.message }
func (e *substoreScriptNetworkRefusal) Unwrap() error { return e.op }

// substoreScriptNetworkBody is the refusal's error object. RequestID is
// written by the gateway (withAPIErrorRequestID).
type substoreScriptNetworkBody struct {
	Code      string                     `json:"code"`
	Message   string                     `json:"message"`
	RequestID string                     `json:"request_id"`
	Record    string                     `json:"record,omitempty"`
	Step      *substoreScriptNetworkStep `json:"step,omitempty"`
}

// newSubstoreScriptNetworkRefusal builds the refusal of a render of the
// record rendered ("" for an unsaved draft), naming the step found in the
// record holding it, or no step when none was found. The message carries
// record ids and the cleaned step type, nothing the plugin or a script said.
func newSubstoreScriptNetworkRefusal(rendered, holder string, step *substoreScriptNetworkStep) *substoreScriptNetworkRefusal {
	name := func(id string) string {
		if id == "" {
			return "the draft"
		}
		return fmt.Sprintf("record %q", id)
	}
	message := fmt.Sprintf("%s: a step asked for the network while %s rendered, and a chain that reaches fleet nodes runs without one until S3",
		apiErrorFleetScriptNetworkUnavailable, name(rendered))
	if step != nil {
		message += fmt.Sprintf("; step %d (%s) of %s is the first step in that render that can ask for it, so remove the network call or the step",
			step.Position, step.Type, name(holder))
	} else {
		holder = rendered
		message += "; remove the network call or the Script or Resolve Domain step that makes it"
	}
	body, _ := json.Marshal(struct {
		Error substoreScriptNetworkBody `json:"error"`
	}{substoreScriptNetworkBody{Code: apiErrorFleetScriptNetworkUnavailable, Message: message, Record: holder, Step: step}})
	return &substoreScriptNetworkRefusal{Record: holder, Step: step, message: message,
		op: &pluginOperationError{StatusCode: http.StatusConflict, Body: body}}
}

// substoreFirstNetworkStep is the first enabled step of a chain that can ask
// for the network, or nil.
func substoreFirstNetworkStep(steps []json.RawMessage) *substoreScriptNetworkStep {
	for i, raw := range steps {
		var meta struct {
			Type     string `json:"type"`
			Disabled bool   `json:"disabled"`
		}
		if json.Unmarshal(raw, &meta) != nil || meta.Disabled {
			continue
		}
		if kind := subStorePlanStepType(meta.Type); substoreNetworkStepTypes[kind] {
			return &substoreScriptNetworkStep{Position: i + 1, Type: kind}
		}
	}
	return nil
}

// substoreScriptNetworkRender is one render or preview the plugin refused.
type substoreScriptNetworkRender struct {
	// SubscriptionID is the record rendered; "" is an unsaved draft.
	SubscriptionID string
	// Revision is the revision rendered; "" is the live one.
	Revision string
	// MemberRevisions names the revision each named member renders at; ""
	// is a deleted member.
	MemberRevisions map[string]string
	// Operators, when Override is set, is the chain the caller sent in place
	// of a sub's stored one (an editor preview of unsaved steps, a draft).
	// The plugin ignores it for a collection, and so does the search.
	Operators []json.RawMessage
	Override  bool
}

// substoreScriptNetworkRefusalFor is core's refusal of a render the plugin
// refused with fleet_script_network_unavailable.
func (s *Server) substoreScriptNetworkRefusalFor(r substoreScriptNetworkRender) *substoreScriptNetworkRefusal {
	holder, step := s.substoreScriptNetworkStepFor(r)
	return newSubstoreScriptNetworkRefusal(r.SubscriptionID, holder, step)
}

// substoreScriptNetworkRecord is what the step search reads of a record
// document.
type substoreScriptNetworkRecord struct {
	ID         string            `json:"id"`
	Kind       string            `json:"kind"`
	Members    []string          `json:"members"`
	MemberTags []string          `json:"member_tags"`
	NodeSource string            `json:"node_source"`
	Process    []json.RawMessage `json:"process"`
	Operators  []json.RawMessage `json:"operators"`
}

// substoreScriptNetworkStepFor finds the step a refusal names: the first
// enabled step that can ask for the network in the rendered record's chain,
// else in the chains of the records it reads (a collection's members, by id
// and then by tag in the index's order, and a file's node source), breadth
// first. A member renders at its named revision, or live. It answers the
// record holding the step and the step, or "" and nil.
func (s *Server) substoreScriptNetworkStepFor(r substoreScriptNetworkRender) (string, *substoreScriptNetworkStep) {
	index := s.subStoreIndexV2()
	live := make(map[string]string, len(index.entries))
	for _, entry := range index.entries {
		live[entry.ID] = entry.Revision
	}
	// read reads a record's document at a revision: the live document for
	// the live revision, the staged one for any other, which is the only
	// other revision the plugin renders.
	read := func(id, revision string) (substoreScriptNetworkRecord, bool) {
		staged := false
		if revision != "" {
			liveRevision, ok := live[id]
			staged = !ok || liveRevision != revision
		}
		raw, ok := s.subStoreRecordJSON(id, staged)
		if !ok {
			return substoreScriptNetworkRecord{}, false
		}
		var doc substoreScriptNetworkRecord
		if json.Unmarshal(raw, &doc) != nil || doc.ID != id {
			return substoreScriptNetworkRecord{}, false
		}
		return doc, true
	}
	if r.SubscriptionID == "" {
		if !r.Override {
			return "", nil
		}
		return "", substoreFirstNetworkStep(r.Operators)
	}
	type visit struct{ id, revision string }
	queue := []visit{{r.SubscriptionID, r.Revision}}
	seen := map[string]bool{r.SubscriptionID: true}
	enqueue := func(id string) {
		if seen[id] || !substoreBindValidID(id) || len(seen) >= substoreScriptNetworkMaxRecords {
			return
		}
		seen[id] = true
		revision, named := r.MemberRevisions[id]
		if named && revision == "" {
			return
		}
		queue = append(queue, visit{id, revision})
	}
	for i := 0; i < len(queue); i++ {
		at := queue[i]
		doc, ok := read(at.id, at.revision)
		if !ok && !(i == 0 && r.Override) {
			continue
		}
		steps := doc.Process
		if len(steps) == 0 {
			steps = doc.Operators
		}
		if i == 0 && r.Override && doc.Kind != subStoreRecordKindCollection {
			steps = r.Operators
		}
		if step := substoreFirstNetworkStep(steps); step != nil {
			return at.id, step
		}
		switch doc.Kind {
		case subStoreRecordKindCollection:
			for _, member := range doc.Members {
				enqueue(member)
			}
			if len(doc.MemberTags) == 0 {
				continue
			}
			for _, entry := range index.entries {
				if entry.Kind != "" && entry.Kind != "sub" {
					continue
				}
				if slices.ContainsFunc(entry.Tags, func(tag string) bool { return slices.Contains(doc.MemberTags, tag) }) {
					enqueue(entry.ID)
				}
			}
		case subStoreRecordKindFile:
			if doc.NodeSource != "" {
				enqueue(doc.NodeSource)
			}
		}
	}
	return "", nil
}

// substoreScriptNetworkRelayMethod reports whether a gateway call is one of
// the Sub-Store renders an editor reaches: preview, preview_draft, render.
func substoreScriptNetworkRelayMethod(pluginID, service, method string) bool {
	if pluginID != subStorePluginID || service != subStorePluginID+"/subscription" {
		return false
	}
	switch method {
	case "preview", "preview_draft", "render":
		return true
	}
	return false
}

// substoreScriptNetworkRelayRefusal is the refusal of a preview, a draft
// preview or a render relayed through the plugin gateway, read from the
// payload the gateway sent: the record and revision named, and the chain the
// caller sent in place of the stored one. The plugin decoded the payload
// strictly before it refused, so a payload that does not decode here names
// no record.
func (s *Server) substoreScriptNetworkRelayRefusal(payload json.RawMessage) *substoreScriptNetworkRefusal {
	var req struct {
		SubscriptionID  string            `json:"subscription_id"`
		Revision        string            `json:"revision"`
		MemberRevisions map[string]string `json:"member_revisions"`
		Operators       []json.RawMessage `json:"operators"`
	}
	if json.Unmarshal(payload, &req) != nil || (req.SubscriptionID != "" && !substoreBindValidID(req.SubscriptionID)) {
		req.SubscriptionID, req.Revision, req.MemberRevisions, req.Operators = "", "", nil, nil
	}
	return s.substoreScriptNetworkRefusalFor(substoreScriptNetworkRender{SubscriptionID: req.SubscriptionID, Revision: req.Revision,
		MemberRevisions: req.MemberRevisions, Operators: req.Operators, Override: req.Operators != nil})
}
