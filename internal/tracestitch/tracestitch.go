// Package tracestitch joins connection records that belong to one logical flow
// across machines, and states how confident that join is.
//
// The shape of the problem comes from the two-hop rig
// (SINGBOX-TRACE-DESIGN section 4.5). Inside one sing-box process the hops
// already share a log id, so the assembler links them itself. Across machines
// there is no shared id: hop 2 sees an inbound connection from hop 1's public
// address, and sing-box does not log the local port it dialled from, so the
// downstream record's SrcPort is not a join key and is never used here.
//
// What is left is an inference, and the confidence is part of the answer rather
// than a footnote. An operator who can see what the stitcher could not decide
// is better served than one handed a confident wrong path.
package tracestitch

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// DefaultWindow is how long after an upstream record a downstream one may start
// and still be considered the same flow. Three seconds covers a chained dial
// over a slow link without stretching far enough to swallow the next
// connection to the same destination.
const DefaultWindow = 3 * time.Second

// Edge is one declared chain edge, the skeleton every join hangs from. It
// mirrors store.LineChainDefinition{SourceLineUUID, TargetLineUUID}: only a
// chain an operator declared and the server compiled can carry a flow.
type Edge struct {
	SourceLineUUID string
	TargetLineUUID string
}

// Options tunes the join.
type Options struct {
	// Window bounds how long after the upstream record a downstream one may
	// start. Zero or negative means DefaultWindow.
	Window time.Duration
	// NodePublicIPs maps node_id to the addresses that node dials out from.
	// The downstream record's SrcIP has to be one of the upstream node's, which
	// is the only physical evidence tying the two records together.
	NodePublicIPs map[string][]string
}

// Stitch groups records into hop paths.
//
// Every input record appears in exactly one returned path's RecordKeys, so a
// caller can stamp HopPathID onto records without a record belonging to two
// paths. A record that joined nothing is its own single-hop path with
// confidence none, which is a statement ("no downstream matched"), not a gap.
//
// The input slice is not reordered or modified.
func Stitch(records []model.ConnRecord, edges []Edge, opts Options) []model.HopPath {
	n := len(records)
	if n == 0 {
		return nil
	}
	window := opts.Window
	if window <= 0 {
		window = DefaultWindow
	}

	// Positions are the identity used throughout: a stable sort up front means
	// every later decision, and therefore the output, is deterministic.
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(x, y int) int {
		return compareRecord(records[x], records[y])
	})
	rec := func(p int) model.ConnRecord { return records[order[p]] }

	edgeSet := buildEdgeSet(edges)
	nodeIPs := buildNodeIPs(opts.NodePublicIPs)
	byUser, byDst := buildIndexes(n, rec)

	// candidates[p] holds every downstream record p could have flowed into,
	// kinds[p] says on what evidence.
	candidates := make([][]int, n)
	kinds := make([]string, n)
	for p := range n {
		candidates[p], kinds[p] = candidatesFor(p, rec, edgeSet, nodeIPs, byUser, byDst, window)
	}

	// A single candidate is only a decision if no other upstream record claims
	// the same downstream. Two entries pointing at one exit is undecidable in
	// the other direction, and picking the first would be a guess dressed up as
	// a fact, so both sides degrade to ambiguous with the contested record
	// listed.
	choice := make([]int, n)
	claims := make([]int, n)
	for p := range n {
		choice[p] = -1
		if len(candidates[p]) == 1 {
			choice[p] = candidates[p][0]
		}
	}
	for p := range n {
		if choice[p] >= 0 {
			claims[choice[p]]++
		}
	}
	accepted := make([]bool, n)
	inbound := make([]bool, n)
	for p := range n {
		switch {
		case len(candidates[p]) == 0:
			kinds[p] = model.HopConfidenceNone
		case len(candidates[p]) > 1, claims[choice[p]] > 1:
			kinds[p] = model.HopConfidenceAmbiguous
		default:
			accepted[p] = true
			inbound[choice[p]] = true
		}
	}

	visited := make([]bool, n)
	paths := make([][]int, 0, n)
	confidences := make([]string, 0, n)
	pending := make([][]int, 0, n)

	fold := func(head int) {
		path := []int{head}
		visited[head] = true
		conf := ""
		var cands []int
		cur := head
		for {
			if kinds[cur] == model.HopConfidenceAmbiguous {
				// Stop at the fork and hand the operator the branches. An
				// ambiguous link makes the whole path undecided, however solid
				// the hops before it were.
				conf = model.HopConfidenceAmbiguous
				cands = candidates[cur]
				break
			}
			if !accepted[cur] {
				break
			}
			next := choice[cur]
			if visited[next] {
				// Cycle guard. The server rejects cyclic chains when it compiles
				// them, so this is a safety net rather than a supported shape:
				// truncate the fold instead of walking forever.
				break
			}
			visited[next] = true
			path = append(path, next)
			conf = weakerConfidence(conf, kinds[cur])
			cur = next
		}
		if conf == "" {
			conf = model.HopConfidenceNone
		}
		paths = append(paths, path)
		confidences = append(confidences, conf)
		pending = append(pending, cands)
	}

	for p := range n {
		if !inbound[p] && !visited[p] {
			fold(p)
		}
	}
	// A cycle leaves every record claimed, so it produces no head at all. Seed
	// the leftovers in position order; the cycle guard above ends each walk.
	for p := range n {
		if !visited[p] {
			fold(p)
		}
	}

	out := make([]model.HopPath, 0, len(paths))
	for i, path := range paths {
		keys := make([]model.ConnRecordKey, 0, len(path))
		for _, p := range path {
			keys = append(keys, recordKey(rec(p)))
		}
		hop := model.HopPath{
			ID:         hopPathID(keys),
			Confidence: confidences[i],
			RecordKeys: keys,
		}
		// The contract populates Candidates only for an ambiguous path, and the
		// candidates are exactly the records that were NOT put in RecordKeys.
		if hop.Confidence == model.HopConfidenceAmbiguous {
			hop.Candidates = make([]model.ConnRecordKey, 0, len(pending[i]))
			for _, p := range pending[i] {
				hop.Candidates = append(hop.Candidates, recordKey(rec(p)))
			}
		}
		out = append(out, hop)
	}
	// Paths come out in head order, but the leftover pass can emit a path whose
	// head sorts before an earlier one. One final sort keeps the order a pure
	// function of the input.
	slices.SortStableFunc(out, func(x, y model.HopPath) int {
		return compareKey(x.RecordKeys[0], y.RecordKeys[0])
	})
	return out
}

// candidatesFor returns the downstream records p may have flowed into.
//
// Two tests, in order of strength:
//
// A shared user id narrows the search; it never proves the flow. The same
// credential is on every connection that user opens, so identity alone would
// join a parallel connection headed somewhere else. Exact is therefore not
// reachable from equal user ids and is reserved for a per-flow correlation the
// record does not carry yet (design section 4.5 step two, carry_identity). The
// time window is the causal bound that stops one user's morning connection from
// joining their afternoon one.
//
// Otherwise the heuristic from the rig: the downstream record started inside
// the window, its SrcIP is one of the upstream node's public addresses, and the
// destination is identical. The rig confirmed the upstream logs the FINAL
// destination rather than the next hop, which is what makes that last test
// usable.
func candidatesFor(
	p int,
	rec func(int) model.ConnRecord,
	edgeSet map[Edge]struct{},
	nodeIPs map[string]map[string]struct{},
	byUser map[string][]int,
	byDst map[dstKey][]int,
	window time.Duration,
) ([]int, string) {
	up := rec(p)
	if strings.TrimSpace(up.LineUUID) == "" || up.StartedAt.IsZero() {
		// An unattributed record has no place in the declared chain, and one
		// without a start time cannot be placed on the causal timeline. Either
		// way there is nothing to join it by.
		return nil, model.HopConfidenceNone
	}

	// A shared user id narrows the candidates; it does not identify the flow.
	//
	// The same credential appears on every connection that user opens, so
	// "same user, declared edge, inside the window" is satisfied by a parallel
	// connection to somewhere else entirely. Treating that as exact published
	// a guess as a proven join. Exact is reserved for a per-flow correlation,
	// which nothing in the record carries yet, so identity is used to narrow
	// and the flow evidence still has to hold.
	var sameUser []int
	for _, q := range byUser[strings.TrimSpace(up.UserID)] {
		if q == p {
			continue
		}
		down := rec(q)
		if !edgeAllows(edgeSet, up, down) || !withinWindow(up, down, window) {
			continue
		}
		if !flowEvidence(up, down, nodeIPs) {
			continue
		}
		sameUser = append(sameUser, q)
	}
	if len(sameUser) == 1 {
		return sameUser, model.HopConfidenceInferred
	}
	if len(sameUser) > 1 {
		slices.Sort(sameUser)
		return sameUser, model.HopConfidenceAmbiguous
	}

	key, ok := dstKeyOf(up)
	if !ok {
		return nil, model.HopConfidenceNone
	}
	var inferred []int
	for _, q := range byDst[key] {
		if q == p {
			continue
		}
		down := rec(q)
		if !edgeAllows(edgeSet, up, down) || !withinWindow(up, down, window) {
			continue
		}
		if !dialedFrom(nodeIPs, up.NodeID, down.SrcIP) {
			continue
		}
		inferred = append(inferred, q)
	}
	if len(inferred) == 0 {
		return nil, model.HopConfidenceNone
	}
	slices.Sort(inferred)
	return inferred, model.HopConfidenceInferred
}

func edgeAllows(edgeSet map[Edge]struct{}, up, down model.ConnRecord) bool {
	source := strings.TrimSpace(up.LineUUID)
	target := strings.TrimSpace(down.LineUUID)
	if source == "" || target == "" {
		// Never let two unattributed records match each other on empty strings.
		return false
	}
	_, ok := edgeSet[Edge{SourceLineUUID: source, TargetLineUUID: target}]
	return ok
}

// withinWindow reports whether down could causally follow up: at or after the
// upstream start, and no later than the window allows.
func withinWindow(up, down model.ConnRecord, window time.Duration) bool {
	if up.StartedAt.IsZero() || down.StartedAt.IsZero() {
		return false
	}
	if down.StartedAt.Before(up.StartedAt) {
		return false
	}
	return !down.StartedAt.After(up.StartedAt.Add(window))
}

func dialedFrom(nodeIPs map[string]map[string]struct{}, upstreamNodeID, downstreamSrcIP string) bool {
	ips, ok := nodeIPs[strings.TrimSpace(upstreamNodeID)]
	if !ok {
		return false
	}
	src := canonicalIP(downstreamSrcIP)
	if src == "" {
		return false
	}
	_, ok = ips[src]
	return ok
}

type dstKey struct {
	host string
	port int
}

// dstKeyOf returns the destination join key. A record whose destination was
// never parsed has no key: equality between two unknowns proves nothing.
func dstKeyOf(r model.ConnRecord) (dstKey, bool) {
	host := strings.ToLower(strings.TrimSpace(r.DstHost))
	if host == "" || r.DstPort <= 0 {
		return dstKey{}, false
	}
	return dstKey{host: host, port: r.DstPort}, true
}

func buildIndexes(n int, rec func(int) model.ConnRecord) (map[string][]int, map[dstKey][]int) {
	byUser := map[string][]int{}
	byDst := map[dstKey][]int{}
	for p := range n {
		r := rec(p)
		if id := strings.TrimSpace(r.UserID); id != "" {
			byUser[id] = append(byUser[id], p)
		}
		if key, ok := dstKeyOf(r); ok {
			byDst[key] = append(byDst[key], p)
		}
	}
	return byUser, byDst
}

func buildEdgeSet(edges []Edge) map[Edge]struct{} {
	set := make(map[Edge]struct{}, len(edges))
	for _, e := range edges {
		source := strings.TrimSpace(e.SourceLineUUID)
		target := strings.TrimSpace(e.TargetLineUUID)
		if source == "" || target == "" || source == target {
			// A self edge would let a record join itself or its own siblings on
			// one line, which is the in-process case the assembler already owns.
			continue
		}
		set[Edge{SourceLineUUID: source, TargetLineUUID: target}] = struct{}{}
	}
	return set
}

func buildNodeIPs(raw map[string][]string) map[string]map[string]struct{} {
	out := make(map[string]map[string]struct{}, len(raw))
	for node, ips := range raw {
		node = strings.TrimSpace(node)
		if node == "" {
			continue
		}
		set := out[node]
		if set == nil {
			set = map[string]struct{}{}
			out[node] = set
		}
		for _, ip := range ips {
			if c := canonicalIP(ip); c != "" {
				set[c] = struct{}{}
			}
		}
	}
	return out
}

// canonicalIP normalises an address so textual variants of the same IPv6
// address, and IPv4-mapped forms, compare equal. A value that is not an
// address at all (a hostname a caller configured by mistake) falls back to a
// trimmed lowercase string so it can still match itself.
func canonicalIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.Unmap().String()
	}
	return strings.ToLower(value)
}

// weakerConfidence keeps the least certain link in a folded path. A chain is
// only as trustworthy as its weakest join, so an exact hop followed by an
// inferred one is an inferred path.
func weakerConfidence(have, add string) string {
	if have == "" {
		return add
	}
	if confidenceRank(add) < confidenceRank(have) {
		return add
	}
	return have
}

func confidenceRank(c string) int {
	switch c {
	case model.HopConfidenceExact:
		return 3
	case model.HopConfidenceInferred:
		return 2
	case model.HopConfidenceAmbiguous:
		return 1
	default:
		return 0
	}
}

func recordKey(r model.ConnRecord) model.ConnRecordKey {
	return model.KeyOf(r)
}

// hopPathID derives a stable id from the ordered record keys, so re-stitching
// the same flow after a retry or a restart lands on the same id instead of
// churning one the UI has already shown. Confidence is deliberately left out of
// the hash: a path whose confidence improves is the same path.
func hopPathID(keys []model.ConnRecordKey) string {
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k.NodeID))
		h.Write([]byte{0})
		h.Write([]byte(strconv.FormatUint(k.CoreGeneration, 10)))
		h.Write([]byte{0})
		h.Write([]byte(strconv.FormatUint(uint64(k.LogID), 10)))
		h.Write([]byte{'\n'})
	}
	return "hp_" + hex.EncodeToString(h.Sum(nil))[:16]
}

func compareRecord(a, b model.ConnRecord) int {
	if c := a.StartedAt.Compare(b.StartedAt); c != 0 {
		return c
	}
	return compareKey(recordKey(a), recordKey(b))
}

func compareKey(a, b model.ConnRecordKey) int {
	if c := strings.Compare(a.NodeID, b.NodeID); c != 0 {
		return c
	}
	switch {
	case a.CoreGeneration < b.CoreGeneration:
		return -1
	case a.CoreGeneration > b.CoreGeneration:
		return 1
	case a.LogID < b.LogID:
		return -1
	case a.LogID > b.LogID:
		return 1
	}
	return 0
}

// flowEvidence is the physical part of the join, independent of who the user
// is: the downstream connection was dialled from the upstream node and is
// headed to the same destination. A shared credential says which user; only
// this says which connection.
func flowEvidence(up, down model.ConnRecord, nodeIPs map[string]map[string]struct{}) bool {
	if !dialedFrom(nodeIPs, up.NodeID, down.SrcIP) {
		return false
	}
	upKey, ok := dstKeyOf(up)
	if !ok {
		return false
	}
	downKey, ok := dstKeyOf(down)
	if !ok {
		return false
	}
	return upKey == downKey
}
