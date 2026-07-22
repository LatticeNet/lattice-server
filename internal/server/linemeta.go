package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// design-15 D1/§4: line_uuid is the durable, control-plane-assigned identity of a
// Line (line_hash_id stays the recomputable topology fingerprint). The mapping is
// persisted in the KV bucket below, and the schema-v2 sidecar file rendered here
// carries it onto each sing-box node.
const (
	lineUUIDKVBucket     = "vpnmeta/lineuuid"
	lineMetadataSchemaV2 = "lattice.singbox-metadata.v2"
	lineMetadataWriter   = "lattice-server"
	// lineMetadataPath is the on-box sidecar location. It must stay OUTSIDE the
	// sing-box -C directory's *.json glob — stock sing-box rejects unknown config
	// keys, so the metadata file is never consumed by the core (design-15 §4.3).
	lineMetadataPath = "/etc/sing-box/lattice-metadata.json"
)

// ensureLineUUID returns the persisted line_uuid for a line_hash_id, allocating
// and persisting a fresh UUIDv4 on first sight. Idempotent; serialized by
// s.lineUUIDMu so concurrent read-model builds cannot double-allocate.
func (s *Server) ensureLineUUID(lineHashID string) (string, error) {
	lineHashID = strings.TrimSpace(lineHashID)
	if lineHashID == "" {
		return "", errors.New("line_hash_id is required")
	}
	s.lineUUIDMu.Lock()
	defer s.lineUUIDMu.Unlock()
	if e, ok := s.store.KVEntry(lineUUIDKVBucket, lineHashID); ok && strings.TrimSpace(e.Value) != "" {
		return e.Value, nil
	}
	uuid, err := newProxyUUID()
	if err != nil {
		return "", err
	}
	if err := s.store.PutKV(model.KVEntry{Bucket: lineUUIDKVBucket, Key: lineHashID, Value: uuid}); err != nil {
		return "", err
	}
	return uuid, nil
}

// ── schema-v2 sidecar rendering (contract lattice.singbox-metadata.v2) ───────

type lineMetadataDocV2 struct {
	Schema    string                  `json:"schema"`
	NodeID    string                  `json:"node_id"`
	NodeUUID  string                  `json:"node_uuid,omitempty"`
	UpdatedAt string                  `json:"updated_at"`
	Writer    string                  `json:"writer"`
	Inbounds  []lineMetadataInboundV2 `json:"inbounds"`
	Reserved  lineMetadataReservedV2  `json:"reserved"`
}

type lineMetadataInboundV2 struct {
	Tag        string               `json:"tag"`
	LineUUID   string               `json:"line_uuid"`
	LineHashID string               `json:"line_hash_id,omitempty"`
	Chain      *lineMetadataChainV2 `json:"chain,omitempty"`
}

// lineMetadataChainV2 is emitted whenever a line has a declared or resolvable
// downstream; downstream_line_uuid serializes as explicit null when unknown (the
// contract requires the key, nullable).
type lineMetadataChainV2 struct {
	DownstreamLineUUID *string `json:"downstream_line_uuid"`
	DownstreamNode     string  `json:"downstream_node,omitempty"`
}

// lineMetadataReservedV2 is the frozen documentation-only block: no writer emits
// `_lattice` into sing-box config, no reader requires it (design-15 §4.4).
type lineMetadataReservedV2 struct {
	InConfigKey string                     `json:"in_config_key"`
	Fields      lineMetadataReservedFields `json:"fields"`
}

type lineMetadataReservedFields struct {
	LineUUID   string `json:"line_uuid"`
	NodeUUID   string `json:"node_uuid"`
	LineHashID string `json:"line_hash_id"`
}

// renderLineMetadataJSON renders the schema-v2 sidecar for one node from the
// current line read model. Output is deterministic (inbounds sorted by tag, fixed
// field order) so re-renders of unchanged state are byte-identical. A line whose
// line_uuid allocation degraded fails the render: a schema-invalid sidecar must
// never reach the box.
func (s *Server) renderLineMetadataJSON(nodeID string) ([]byte, error) {
	if _, ok := s.store.Node(nodeID); !ok {
		return nil, fmt.Errorf("node %q not found", nodeID)
	}
	groups := s.buildLineGroups()
	lineOwner := map[string]string{} // line_hash_id -> node_id, for naming resolved downstreams
	var lines []Line
	for _, g := range groups {
		for _, ln := range g.Lines {
			lineOwner[ln.LineHashID] = g.NodeID
		}
		if g.NodeID == nodeID {
			lines = g.Lines
		}
	}
	inbounds := make([]lineMetadataInboundV2, 0, len(lines))
	for _, ln := range lines {
		tag := firstNonEmpty(ln.Tag, ln.Name)
		if tag == "" {
			return nil, fmt.Errorf("line %s has no tag", ln.LineHashID)
		}
		if !validLineUUIDv4(ln.LineUUID) {
			return nil, fmt.Errorf("line %s has invalid line_uuid %q (want UUIDv4)", ln.LineHashID, ln.LineUUID)
		}
		ib := lineMetadataInboundV2{Tag: tag, LineUUID: ln.LineUUID, LineHashID: ln.LineHashID}
		ds := strings.TrimSpace(ln.DownstreamLineUUID)
		ref := strings.ToLower(strings.TrimSpace(ln.OutboundRef))
		if ds != "" || (ref != "" && ref != "direct") {
			chain := &lineMetadataChainV2{}
			if ds != "" {
				chain.DownstreamLineUUID = &ds
			}
			// Name the known downstream node when the relay edge resolved fleet-wide.
			for _, edge := range ln.JumpEdges {
				if owner, ok := lineOwner[edge]; ok && owner != nodeID {
					chain.DownstreamNode = s.nodeDisplayName(owner)
					break
				}
			}
			ib.Chain = chain
		}
		inbounds = append(inbounds, ib)
	}
	sort.Slice(inbounds, func(i, j int) bool { return inbounds[i].Tag < inbounds[j].Tag })
	doc := lineMetadataDocV2{
		Schema:    lineMetadataSchemaV2,
		NodeID:    nodeID,
		NodeUUID:  s.nodeIdentityUUID(nodeID),
		UpdatedAt: s.now().UTC().Format(time.RFC3339),
		Writer:    lineMetadataWriter,
		Inbounds:  inbounds,
		Reserved: lineMetadataReservedV2{
			InConfigKey: "_lattice",
			Fields:      lineMetadataReservedFields{LineUUID: "string", NodeUUID: "string", LineHashID: "string"},
		},
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// ── sidecar apply task (reviewed script; trigger wiring is a later slice) ─────

// lineMetadataApplyScript renders the on-box apply script for the v2 sidecar:
// validated JSON merge, atomic tmp+mv write, sibling .bak backup, 0644
// root:root. sing-box never reads the file, so no service reload follows.
func lineMetadataApplyScript(payload []byte) string {
	return lineMetadataApplyScriptForTarget(payload, lineMetadataPath)
}

// lineMetadataApplyScriptForTarget keeps the production path fixed at the
// caller while allowing execution tests to prove the reviewed shell workflow
// without touching /etc. When a prior document exists its unknown top-level
// fields survive; the freshly rendered canonical v2 fields always win.
func lineMetadataApplyScriptForTarget(payload []byte, target string) string {
	generated := target + ".lattice-generated"
	candidate := target + ".lattice-new"
	backup := target + ".bak"
	validateV2 := "type == \"object\" and " +
		".schema == \"" + lineMetadataSchemaV2 + "\" and " +
		"(.node_id | type == \"string\") and " +
		"((has(\"node_uuid\") | not) or (.node_uuid | type == \"string\")) and " +
		"(.updated_at | type == \"string\") and " +
		".writer == \"" + lineMetadataWriter + "\" and " +
		"(.inbounds | type == \"array\") and " +
		"all(.inbounds[]; type == \"object\" and (.tag | type == \"string\") and (.line_uuid | type == \"string\")) and " +
		"(.reserved | type == \"object\") and " +
		".reserved.in_config_key == \"_lattice\" and " +
		"(.reserved.fields | type == \"object\")"
	return "set -e\n" +
		"umask 022\n" +
		"TARGET=" + shellQuote(target) + "\n" +
		"GENERATED=" + shellQuote(generated) + "\n" +
		"CANDIDATE=" + shellQuote(candidate) + "\n" +
		"BACKUP=" + shellQuote(backup) + "\n" +
		"mkdir -p " + shellQuote(path.Dir(target)) + "\n" +
		"trap 'rm -f \"$GENERATED\" \"$CANDIDATE\"' 0\n" +
		"command -v jq >/dev/null 2>&1 || { echo 'lattice linemeta: jq is required' >&2; exit 1; }\n" +
		heredocWrite("\"$GENERATED\"", "LATTICE_LINEMETA", string(payload)) +
		"jq -e '" + validateV2 + "' \"$GENERATED\" >/dev/null\n" +
		"if [ -f \"$TARGET\" ]; then\n" +
		"  jq -e 'type == \"object\"' \"$TARGET\" >/dev/null\n" +
		"  cp -p \"$TARGET\" \"$BACKUP\"\n" +
		"  jq -s '.[0] + .[1]' \"$TARGET\" \"$GENERATED\" >\"$CANDIDATE\"\n" +
		"else\n" +
		"  cp \"$GENERATED\" \"$CANDIDATE\"\n" +
		"fi\n" +
		"jq -e '" + validateV2 + "' \"$CANDIDATE\" >/dev/null\n" +
		"chmod 0644 \"$CANDIDATE\"\n" +
		"chown root:root \"$CANDIDATE\" 2>/dev/null || true\n" +
		"mv -f \"$CANDIDATE\" \"$TARGET\"\n" +
		"trap - 0\n" +
		"rm -f \"$GENERATED\"\n" +
		"echo " + shellQuote("lattice linemeta: "+target+" applied") + "\n"
}

// newLineMetadataApplyTask builds (but does NOT queue) the reviewed task that
// applies the rendered sidecar on one node. plan→approve→apply trigger wiring is
// a later design-15 slice; this helper only fixes the task shape.
func (s *Server) newLineMetadataApplyTask(p principal, nodeID string) (model.Task, error) {
	payload, err := s.renderLineMetadataJSON(nodeID)
	if err != nil {
		return model.Task{}, err
	}
	return model.Task{
		ID:          id.New("task"),
		ActorID:     p.ActorID,
		TokenID:     p.TokenID,
		Targets:     []string{nodeID},
		Interpreter: "sh",
		Script:      lineMetadataApplyScript(payload),
		TimeoutSec:  defaultTaskTimeoutSec,
		OutputLimit: defaultTaskOutputLimit,
		Status:      model.TaskQueued,
		CreatedAt:   s.now(),
	}, nil
}
