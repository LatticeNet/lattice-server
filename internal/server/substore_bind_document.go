package server

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-sdk/model"
	"gopkg.in/yaml.v3"
)

// The text of a document plan (design 28, bind stage, document plans).
//
// A document plan carries the text a file or mihomo config record produced,
// placeholders still in it, beside the typed fleet nodes it was produced
// from. convert substitutes each bound credential where its placeholder
// stands in the text, so validating the typed nodes is not enough: a script
// can leave them honest and rewrite the proxy around the placeholder in the
// text, server included. The text is therefore parsed here, as YAML (JSON is
// a subset of it), and every occurrence of a placeholder that receives a
// real credential must be:
//
//   - the whole value of that credential's key (uuid, password or
//     username) in a mapping, not part of a longer string, a key, a tag or
//     a comment;
//   - at the place in the text the parser read it from, so the textual
//     substitution convert makes lands exactly there. Together with the
//     count of textual occurrences that substoreBindDocumentRefusal already
//     checked, every textual occurrence is then one of these values;
//   - inside a mapping that, read as a node, passes checks 2 to 4 for the
//     placeholder's line (substoreBindCheckNode): its server, port,
//     transport options and every other field are what the line allows;
//   - reachable by no alias, so no other mapping can reuse the value or
//     the mapping, and its mapping uses no alias and no merge key.
//
// A text that is not one YAML document is refused with
// plan_rejected:document, a misplaced occurrence with placeholder_context,
// and a mapping that fails a check with that check's plan_rejected:<field>.
// Placeholders of lines excluded for an operational reason receive an inert
// value and are not held to this: no credential reaches them.

// substoreBindReasonPlaceholderContext refuses a document in which a
// placeholder that receives a real credential stands anywhere but as the
// credential value of a validated proxy mapping.
const substoreBindReasonPlaceholderContext = "placeholder_context"

// substoreBindDocumentMaxDepth bounds the nesting the document walk and the
// mapping conversion follow.
const substoreBindDocumentMaxDepth = 64

// substoreBindPlaced is a placeholder that receives a real credential: the
// plan node that carries it and the node's line.
type substoreBindPlaced struct {
	node model.SelectionPlanNode
	line *substoreBindLine
}

// substoreBindYAML11Bools are the plain scalars YAML 1.1 reads as booleans
// and yaml.v3 reads as strings. A client that decodes YAML 1.1 into a typed
// boolean field reads them as booleans, so a proxy mapping that holds one is
// refused rather than read two ways.
var substoreBindYAML11Bools = map[string]bool{
	"y": true, "Y": true, "yes": true, "Yes": true, "YES": true, "n": true, "N": true, "no": true, "No": true, "NO": true,
	"on": true, "On": true, "ON": true, "off": true, "Off": true, "OFF": true,
}

// substoreBindDocumentCheck checks a document's text against the
// placeholders that receive a real credential, each expected to occur
// expected[placeholder] times. It returns the refusal reason, or "".
func substoreBindDocumentCheck(document string, placed map[string]substoreBindPlaced, expected map[string]int) string {
	if len(placed) == 0 {
		return ""
	}
	decoder := yaml.NewDecoder(strings.NewReader(document))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		return substoreBindRejectedPrefix + "document"
	}
	var next yaml.Node
	if err := decoder.Decode(&next); !errors.Is(err, io.EOF) {
		return substoreBindRejectedPrefix + "document"
	}
	w := &substoreBindDocumentWalk{text: document, placed: placed, seen: map[string]int{},
		mappings: map[*yaml.Node]string{}, reaches: map[*yaml.Node]int{}}
	w.lineStarts = append(w.lineStarts, 0)
	for i := 0; i < len(document); i++ {
		if document[i] == '\n' {
			w.lineStarts = append(w.lineStarts, i+1)
		}
	}
	if reason := w.walk(&root, nil, nil, 0); reason != "" {
		return reason
	}
	for placeholder := range placed {
		if w.seen[placeholder] != expected[placeholder] {
			return substoreBindReasonPlaceholderContext
		}
	}
	return ""
}

// substoreBindDocumentWalk is one walk over a parsed document.
type substoreBindDocumentWalk struct {
	text       string
	lineStarts []int
	placed     map[string]substoreBindPlaced
	// seen counts each placed placeholder's checked occurrences.
	seen map[string]int
	// mappings memoises each proxy mapping's check: "" passed, else the
	// reason.
	mappings map[*yaml.Node]string
	// reaches memoises whether a node's subtree, aliases followed, holds a
	// placed placeholder: 1 while it is being walked, 2 no, 3 yes.
	reaches map[*yaml.Node]int
}

// placedIn returns the placed placeholders a string holds.
func (w *substoreBindDocumentWalk) placedIn(value string) []string {
	if !strings.Contains(value, model.PlanPlaceholderPrefix) {
		return nil
	}
	var out []string
	for placeholder := range model.CountPlanPlaceholders(value) {
		if _, ok := w.placed[placeholder]; ok {
			out = append(out, placeholder)
		}
	}
	return out
}

// walk visits every node of the tree once, without following aliases.
// parent and key are set for a mapping's value.
func (w *substoreBindDocumentWalk) walk(n, parent, key *yaml.Node, depth int) string {
	if depth > substoreBindDocumentMaxDepth {
		return substoreBindRejectedPrefix + "document"
	}
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range n.Content {
			if reason := w.walk(child, nil, nil, depth+1); reason != "" {
				return reason
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if reason := w.walk(n.Content[i], nil, nil, depth+1); reason != "" {
				return reason
			}
			if reason := w.walk(n.Content[i+1], n, n.Content[i], depth+1); reason != "" {
				return reason
			}
		}
	case yaml.ScalarNode:
		for _, placeholder := range w.placedIn(n.Value) {
			if reason := w.occurrence(n, parent, key, placeholder); reason != "" {
				return reason
			}
			w.seen[placeholder]++
		}
	case yaml.AliasNode:
		if n.Alias == nil || w.reachesPlaced(n.Alias, 0) {
			return substoreBindReasonPlaceholderContext
		}
	}
	return ""
}

// occurrence checks one scalar holding a placed placeholder.
func (w *substoreBindDocumentWalk) occurrence(n, parent, key *yaml.Node, placeholder string) string {
	p := w.placed[placeholder]
	_, field, err := model.ParsePlanPlaceholder(placeholder)
	if err != nil || n.Value != placeholder || parent == nil || key == nil || key.Kind != yaml.ScalarNode ||
		key.Value != field || p.node.Placeholders[field] != placeholder || !w.atPosition(n, placeholder) {
		return substoreBindReasonPlaceholderContext
	}
	reason, checked := w.mappings[parent]
	if !checked {
		reason = w.checkMapping(parent, p)
		w.mappings[parent] = reason
	}
	return reason
}

// atPosition reports whether the text at the node's position is the
// placeholder itself, plain or right after the quote that opens it.
func (w *substoreBindDocumentWalk) atPosition(n *yaml.Node, placeholder string) bool {
	if n.Line < 1 || n.Line > len(w.lineStarts) || n.Column < 1 {
		return false
	}
	rest := w.text[w.lineStarts[n.Line-1]:]
	// The parser counts columns in characters.
	for column := 1; column < n.Column; column++ {
		if rest == "" || rest[0] == '\n' {
			return false
		}
		_, size := utf8.DecodeRuneInString(rest)
		rest = rest[size:]
	}
	switch n.Style {
	case 0:
		return strings.HasPrefix(rest, placeholder)
	case yaml.DoubleQuotedStyle:
		return strings.HasPrefix(rest, `"`+placeholder+`"`)
	case yaml.SingleQuotedStyle:
		return strings.HasPrefix(rest, `'`+placeholder+`'`)
	}
	return false
}

// checkMapping reads a proxy mapping as a node and runs checks 2 to 4 for
// the placeholder's line.
func (w *substoreBindDocumentWalk) checkMapping(m *yaml.Node, p substoreBindPlaced) string {
	raw, ok := substoreBindYAMLJSON(m, 0)
	if !ok {
		return substoreBindReasonPlaceholderContext
	}
	obj, err := parseSubstoreNodeObject(raw)
	if err != nil {
		return substoreBindReasonPlaceholderContext
	}
	if field := substoreBindCheckNode(raw, obj, p.node, p.line); field != "" {
		return substoreBindRejectedPrefix + field
	}
	return ""
}

// reachesPlaced reports whether a node's subtree, aliases followed, holds a
// placed placeholder anywhere.
func (w *substoreBindDocumentWalk) reachesPlaced(n *yaml.Node, depth int) bool {
	if depth > substoreBindDocumentMaxDepth {
		return true
	}
	switch w.reaches[n] {
	case 1, 2:
		return false
	case 3:
		return true
	}
	w.reaches[n] = 1
	found := len(w.placedIn(n.Value)) > 0 || len(w.placedIn(n.Tag)) > 0 || len(w.placedIn(n.Anchor)) > 0
	for _, child := range n.Content {
		if found {
			break
		}
		found = w.reachesPlaced(child, depth+1)
	}
	if !found && n.Kind == yaml.AliasNode && n.Alias != nil {
		found = w.reachesPlaced(n.Alias, depth+1)
	}
	w.reaches[n] = map[bool]int{false: 2, true: 3}[found]
	return found
}

// substoreBindYAMLJSON converts a proxy mapping to the JSON a plan node
// would carry. It refuses what two YAML readers may read differently or
// what lets text outside the mapping feed it: an alias, a merge key, a
// duplicate or non-string key, a tag other than the core schema's, and a
// plain YAML 1.1 boolean word.
func substoreBindYAMLJSON(n *yaml.Node, depth int) (json.RawMessage, bool) {
	if depth > substoreBindDocumentMaxDepth {
		return nil, false
	}
	switch n.Kind {
	case yaml.MappingNode:
		var b strings.Builder
		b.WriteByte('{')
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Kind != yaml.ScalarNode || k.ShortTag() != "!!str" || seen[k.Value] {
				return nil, false
			}
			seen[k.Value] = true
			value, ok := substoreBindYAMLJSON(v, depth+1)
			if !ok {
				return nil, false
			}
			name, _ := json.Marshal(k.Value)
			if i > 0 {
				b.WriteByte(',')
			}
			b.Write(name)
			b.WriteByte(':')
			b.Write(value)
		}
		b.WriteByte('}')
		return json.RawMessage(b.String()), true
	case yaml.SequenceNode:
		var b strings.Builder
		b.WriteByte('[')
		for i, child := range n.Content {
			value, ok := substoreBindYAMLJSON(child, depth+1)
			if !ok {
				return nil, false
			}
			if i > 0 {
				b.WriteByte(',')
			}
			b.Write(value)
		}
		b.WriteByte(']')
		return json.RawMessage(b.String()), true
	case yaml.ScalarNode:
		var out any
		switch n.ShortTag() {
		case "!!str":
			if n.Style == 0 && substoreBindYAML11Bools[n.Value] {
				return nil, false
			}
			out = n.Value
		case "!!bool":
			var v bool
			if n.Decode(&v) != nil {
				return nil, false
			}
			out = v
		case "!!int":
			var v int64
			if n.Decode(&v) != nil {
				return nil, false
			}
			out = v
		case "!!float":
			var v float64
			if n.Decode(&v) != nil || math.IsNaN(v) || math.IsInf(v, 0) {
				return nil, false
			}
			out = v
		case "!!null":
			out = nil
		default:
			return nil, false
		}
		raw, err := json.Marshal(out)
		return raw, err == nil
	}
	return nil, false
}
