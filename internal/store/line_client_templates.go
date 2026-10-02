package store

import (
	"errors"
	"fmt"
	"maps"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Client templates for adopted lines (identity-sub P4).
//
// An adopted line's client parameters reach the server only inside the
// discovery inventory, an in-memory mirror that a restart empties and a
// silent agent drops, and only as the share_url the node script builds,
// which carries the credential of the line's first user. A template is that
// URI with the credential taken out: the public endpoint and the allowlisted
// connection parameters, enough to build one client entry per identity once
// the identity's own credential is filled in. It is persisted so a
// subscription can still be built after a restart or while an agent is
// quiet, and so the server stops needing the owner's credential for it.
//
// The server builds templates from the line read model on a timer and hands
// each live node's whole set here. A set equal to the stored one costs no
// write; a template changes only when its line's configuration does, so the
// steady state writes nothing and the store takes no write per agent report.
// A node that is not live keeps its templates, which is the point of keeping
// them; a node delete removes them.

// LineClientTemplate is one adopted line's credential-free client template,
// keyed by the line's line_hash_id.
type LineClientTemplate struct {
	LineHashID string `json:"line_hash_id"`
	NodeID     string `json:"node_id"`
	// Tag is the on-box conf name, the line's name in sb.
	Tag      string `json:"tag"`
	LineUUID string `json:"line_uuid,omitempty"`
	// Protocol is the line's protocol, one of the per-line user protocols.
	Protocol string `json:"protocol"`
	// Host and Port are the endpoint a client dials: the provider edge and
	// the declared public port for a node behind NAT, otherwise what the
	// node script put in the share URL.
	Host string `json:"host"`
	Port int    `json:"port"`
	// Params are the allowlisted connection parameters, never a credential.
	Params map[string]string `json:"params,omitempty"`
	// UpdatedAt is when this template last changed.
	UpdatedAt time.Time `json:"updated_at"`
}

const (
	maxLineClientTemplateParams     = 24
	maxLineClientTemplateValueBytes = 512
)

// LineClientTemplateProtocols are the protocols a template may carry: the
// ones the per-line user CLI can put an identity's credential on.
var LineClientTemplateProtocols = map[string]bool{
	"vless": true, "vmess": true, "trojan": true, "hysteria2": true, "tuic": true, "anytls": true, "socks": true,
}

func validLineClientTemplateText(value string, maxBytes int) bool {
	return len(value) <= maxBytes && !strings.ContainsFunc(value, unicode.IsControl)
}

// ValidateLineClientTemplate checks a template's shape. It cannot tell a
// credential from a parameter; the server's builder keeps credentials out,
// and this keeps the record bounded and printable.
func ValidateLineClientTemplate(t LineClientTemplate) error {
	switch {
	case strings.TrimSpace(t.LineHashID) == "" || !validLineClientTemplateText(t.LineHashID, 128):
		return errors.New("line client template needs a line_hash_id")
	case strings.TrimSpace(t.NodeID) == "" || !validLineClientTemplateText(t.NodeID, 128):
		return fmt.Errorf("line client template %q needs a node_id", t.LineHashID)
	case !LineClientTemplateProtocols[t.Protocol]:
		return fmt.Errorf("line client template %q has unsupported protocol %q", t.LineHashID, t.Protocol)
	case strings.TrimSpace(t.Host) == "" || !validLineClientTemplateText(t.Host, 253) || strings.ContainsAny(t.Host, "/@?#[] "):
		return fmt.Errorf("line client template %q has an invalid host", t.LineHashID)
	case t.Port < 1 || t.Port > 65535:
		return fmt.Errorf("line client template %q has an invalid port", t.LineHashID)
	case !validLineClientTemplateText(t.Tag, 256) || !validLineClientTemplateText(t.LineUUID, 64):
		return fmt.Errorf("line client template %q has an invalid tag or line uuid", t.LineHashID)
	case len(t.Params) > maxLineClientTemplateParams:
		return fmt.Errorf("line client template %q has more than %d params", t.LineHashID, maxLineClientTemplateParams)
	}
	for key, value := range t.Params {
		if key == "" || !validLineClientTemplateText(key, 64) || !validLineClientTemplateText(value, maxLineClientTemplateValueBytes) {
			return fmt.Errorf("line client template %q has an invalid param %q", t.LineHashID, key)
		}
	}
	return nil
}

// lineClientTemplateDurablyEqual compares two templates without UpdatedAt.
func lineClientTemplateDurablyEqual(a, b LineClientTemplate) bool {
	return a.LineHashID == b.LineHashID && a.NodeID == b.NodeID && a.Tag == b.Tag && a.LineUUID == b.LineUUID &&
		a.Protocol == b.Protocol && a.Host == b.Host && a.Port == b.Port && maps.Equal(a.Params, b.Params)
}

func cloneLineClientTemplate(t LineClientTemplate) LineClientTemplate {
	t.Params = maps.Clone(t.Params)
	return t
}

// SyncLineClientTemplates makes the stored templates of each node in byNode
// exactly the given set: templates it lists are added or replaced, the node's
// other templates are removed. Nodes not in byNode are untouched. A template
// equal to the stored one keeps its UpdatedAt; a new or changed one takes
// now. Nothing is written when nothing changed, and memory takes the new set
// only once the write committed. written reports whether a write happened.
func (s *Store) SyncLineClientTemplates(byNode map[string][]LineClientTemplate, now time.Time) (written bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMaps()
	next := make(map[string]LineClientTemplate, len(s.state.LineClientTemplates))
	for hash, t := range s.state.LineClientTemplates {
		if _, replaced := byNode[t.NodeID]; !replaced {
			next[hash] = t
		}
	}
	seen := map[string]bool{}
	for nodeID, templates := range byNode {
		for _, t := range templates {
			if t.NodeID != nodeID {
				return false, fmt.Errorf("line client template %q is listed under node %q but names node %q", t.LineHashID, nodeID, t.NodeID)
			}
			if err := ValidateLineClientTemplate(t); err != nil {
				return false, err
			}
			if seen[t.LineHashID] {
				return false, fmt.Errorf("line client template %q is listed twice", t.LineHashID)
			}
			seen[t.LineHashID] = true
			t = cloneLineClientTemplate(t)
			if current, ok := s.state.LineClientTemplates[t.LineHashID]; ok && lineClientTemplateDurablyEqual(current, t) {
				t.UpdatedAt = current.UpdatedAt
			} else {
				t.UpdatedAt = now.UTC()
			}
			next[t.LineHashID] = t
		}
	}
	if len(next) == len(s.state.LineClientTemplates) {
		same := true
		for hash, t := range next {
			current, ok := s.state.LineClientTemplates[hash]
			if !ok || !lineClientTemplateDurablyEqual(current, t) {
				same = false
				break
			}
		}
		if same {
			return false, nil
		}
	}
	staged := s.state
	staged.LineClientTemplates = next
	if committed, err := s.persistState(s.jsonPersistStateFrom(staged)); !committed {
		return false, err
	}
	s.state.LineClientTemplates = next
	return true, nil
}

// LineClientTemplate returns one line's template.
func (s *Store) LineClientTemplate(lineHashID string) (LineClientTemplate, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMaps()
	t, ok := s.state.LineClientTemplates[lineHashID]
	return cloneLineClientTemplate(t), ok
}

// LineClientTemplates returns every template, sorted by node then tag.
func (s *Store) LineClientTemplates() []LineClientTemplate {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMaps()
	out := make([]LineClientTemplate, 0, len(s.state.LineClientTemplates))
	for _, t := range s.state.LineClientTemplates {
		out = append(out, cloneLineClientTemplate(t))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].NodeID != out[j].NodeID {
			return out[i].NodeID < out[j].NodeID
		}
		if out[i].Tag != out[j].Tag {
			return out[i].Tag < out[j].Tag
		}
		return out[i].LineHashID < out[j].LineHashID
	})
	return out
}
