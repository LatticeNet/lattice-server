// Package traceattr resolves the identity half of a sing-box connection record:
// which Lattice line an inbound tag belongs to, and which Lattice user a
// sing-box user name reverses to.
//
// It is deliberately pure logic over an injected snapshot (SINGBOX-TRACE-DESIGN
// section 4.4). The caller owns every store read; this package owns the rules,
// so the rules can be tested without a server.
//
// The whole point of the package is the honesty discipline. Every field it
// writes is either something the snapshot proved or nothing at all. There is no
// fuzzy tag matching and no "there is only one user on that line, so it must be
// them" fallback: a record that cannot be placed is marked so it gets retried
// after the topology refreshes, because a wrong answer written once is
// indistinguishable from a right one forever after.
package traceattr

import (
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// NodeTag is the join key from a log line to a line: sing-box logs an inbound
// tag, and a tag is only unique within one node.
type NodeTag struct {
	NodeID string
	Tag    string
}

// LineRef is the pair of line identities a record carries. LineUUID is the
// durable control-plane identity; LineHashID is the read-model handle the rest
// of the server indexes by.
type LineRef struct {
	LineUUID   string
	LineHashID string
}

// Topology is an immutable snapshot the caller builds from the line read model
// and the user-name index. Callers must not mutate the maps after handing them
// to New: an Attributor is read-only and may be shared across goroutines, and
// the refresh path is meant to build a new snapshot rather than edit a live one.
type Topology struct {
	// LinesByNodeTag maps (node_id, inbound_tag) to the line that tag serves.
	LinesByNodeTag map[NodeTag]LineRef
	// UserIDByName maps the on-box u_<16hex> name to a Lattice user id. It is
	// the same reversal userLineNameIndex already performs for per-user stats;
	// there is exactly one naming scheme and this consumes it.
	UserIDByName map[string]string
	// BuiltAt is when the snapshot was taken. The line read model is behind a
	// 60s cache and the sing-box inventory is memory-only, so knowing the age of
	// the answer matters when explaining why a record is still unresolved.
	BuiltAt time.Time
}

// Attributor applies one topology snapshot to records.
type Attributor struct {
	topo Topology
}

// New returns an Attributor over t. Nil maps are legal and simply resolve
// nothing, which is the correct behaviour for a cold server that has not built
// its first snapshot yet.
func New(t Topology) *Attributor {
	return &Attributor{topo: t}
}

// Topology returns the snapshot this Attributor was built with, so a caller can
// report how stale an attribution run was. The maps are shared, not copied;
// treat the result as read-only.
func (a *Attributor) Topology() Topology {
	return a.topo
}

// Result counts one AttributeAll run. Attributed plus Unresolved always equals
// the number of records passed in: Unresolved counts exactly the records
// NeedsRetry would return true for, so the caller can size its retry queue from
// this alone.
type Result struct {
	Attributed int
	Unresolved int
}

// Attribute fills LineUUID, LineHashID, UserID, and UserKind on r in place.
//
// The output depends only on the record's raw fields (NodeID, InboundTag,
// UserName) and the snapshot, never on what a previous run wrote. That purity
// is what makes the retry path safe: re-running a record against a fresher
// topology cannot leave a half-updated mix of two snapshots behind.
func (a *Attributor) Attribute(r *model.ConnRecord) {
	if r == nil {
		return
	}
	a.attributeLine(r)
	a.attributeUser(r)
}

// AttributeAll attributes every record in place and reports the split.
func (a *Attributor) AttributeAll(rs []model.ConnRecord) Result {
	var res Result
	for i := range rs {
		a.Attribute(&rs[i])
		if a.NeedsRetry(rs[i]) {
			res.Unresolved++
			continue
		}
		res.Attributed++
	}
	return res
}

// NeedsRetry reports whether r should be attributed again after the topology
// refreshes.
//
// Both failure modes are expected on a cold or just-restarted server rather
// than permanent: the line read model is behind a 60s cache, and the sing-box
// inventory is memory-only and lost on restart. A record captured inside that
// window must self-heal on a later pass instead of having the gap baked into it
// as a wrong answer.
func (a *Attributor) NeedsRetry(r model.ConnRecord) bool {
	return r.UserKind == model.UserKindUnresolved || strings.TrimSpace(r.LineUUID) == ""
}

// attributeLine resolves (node_id, inbound_tag) to a line by exact match only.
//
// Nothing fuzzier is allowed. Tags repeat across nodes, an operator can rename
// one, and a prefix match would silently attribute a connection to a line that
// never carried it. On a miss the fields are cleared rather than left as they
// were: a line identity is only ever as good as the snapshot that proved it, so
// carrying an older one forward would present an unverified value as fact.
// Clearing also keeps NeedsRetry true, which is what actually repairs the row.
func (a *Attributor) attributeLine(r *model.ConnRecord) {
	tag := strings.TrimSpace(r.InboundTag)
	node := strings.TrimSpace(r.NodeID)
	if tag == "" || node == "" {
		r.LineUUID, r.LineHashID = "", ""
		return
	}
	ref := a.topo.LinesByNodeTag[NodeTag{NodeID: node, Tag: tag}]
	r.LineUUID, r.LineHashID = ref.LineUUID, ref.LineHashID
}

// attributeUser classifies the sing-box user name and reverses it when it can.
//
// The agent can already tell a managed name from a legacy label by shape alone,
// but only the server holds the index that separates a managed name it can
// place from one it cannot, so the value written here wins over whatever the
// agent guessed.
//
// UserKindDiscovered is never produced here on purpose: the snapshot carries
// nothing that distinguishes a third-party adopted node's named user from a
// legacy operator label, and inventing that distinction is exactly the kind of
// guess this package exists to refuse.
func (a *Attributor) attributeUser(r *model.ConnRecord) {
	name := strings.TrimSpace(r.UserName)
	switch {
	case name == "":
		// sing-box logged an index rather than a name. There is nothing to look
		// up, and this is a config problem to fix on the node, not a lookup
		// failure to retry.
		r.UserID, r.UserKind = "", model.UserKindUnnamed
	case managedNameShape(name):
		id := strings.TrimSpace(a.topo.UserIDByName[name])
		if id == "" {
			// Right shape, no match. Either the binding is newer than the
			// snapshot or the user was removed; the retry pass decides which.
			r.UserID, r.UserKind = "", model.UserKindUnresolved
			return
		}
		r.UserID, r.UserKind = id, model.UserKindManaged
	default:
		// A free-text label on a legacy ProxyUser. It is not reversible to a
		// Lattice user and never will be, so it is not a retry candidate.
		r.UserID, r.UserKind = "", model.UserKindLegacy
	}
}

// managedNamePrefix and managedNameHexLen mirror userLineName: the on-box name
// is "u_" plus the first 16 lowercase hex characters of
// sha256(user_id + "|" + line_uuid). Uppercase hex is rejected because
// hex.EncodeToString never emits it, so an uppercase name did not come from
// that derivation and must not be treated as if it had.
const (
	managedNamePrefix = "u_"
	managedNameHexLen = 16
)

func managedNameShape(name string) bool {
	if len(name) != len(managedNamePrefix)+managedNameHexLen {
		return false
	}
	if !strings.HasPrefix(name, managedNamePrefix) {
		return false
	}
	for i := len(managedNamePrefix); i < len(name); i++ {
		c := name[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
