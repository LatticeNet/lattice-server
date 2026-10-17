package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"unicode"
)

// A record's process chain in a Sub-Store plan (S2 security review,
// S2-SR-2). A section's diff shows what each identity receives line by line,
// and a step can change what a record does without moving a line a preview
// shows: a Script Operator that passes every node through, or one that reads
// them and sends them somewhere. So every section a plan previews carries
// the chain of each side, hashed, and one plain line per step added, removed
// or changed, by position and type, never a step's arguments, name or script
// body. The steps are read from the record documents core reads at the
// plugin's keys: record-v2-<id> for the live revision and staged-v2-<id> for
// the staged one. The approval's hash covers the chain, and the decision
// reads the documents again and rejects the plan as stale when a chain
// moved, whatever depends_on says about the revisions.

const (
	// subStoreStagedKeyPrefix starts a record's staged document key
	// (stagedKey in the plugin's store_staged.go).
	subStoreStagedKeyPrefix = "staged-v2-"
	// subStorePlanChainDiffSteps bounds the chains whose steps are listed
	// one by one. The plugin stores at most 64 steps; a longer chain still
	// hashes in full and is summarised in one line.
	subStorePlanChainDiffSteps = 256
	// subStorePlanChainLines bounds the change lines of one section.
	subStorePlanChainLines = 128
	// subStorePlanStepTypeBytes bounds a step type as a plan shows it. The
	// longest type the plugin knows is 38 bytes.
	subStorePlanStepTypeBytes = 48
)

// subStorePlanChain is a section's process chain: the steps the record runs
// over its nodes, and over the document it produces, before a share serves
// them.
type subStorePlanChain struct {
	// Before and After are the SHA-256 of each side's steps in order,
	// disabled steps included, since re-enabling one is a revision change
	// too. A side the record does not have (no live revision, the after
	// side of a delete) is empty. Equal digests mean the chain is unchanged.
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
	// Changes is one plain line per step added, removed or changed between
	// the sides, by type: a removed step is numbered by its position in
	// the before chain, an added or changed one by its position in the
	// after chain.
	Changes []string `json:"changes,omitempty"`
}

// errSubStorePlanChainUnreadable is a record document a section's chain
// could not be read from.
type errSubStorePlanChainUnreadable struct{ subscriptionID string }

func (e *errSubStorePlanChainUnreadable) Error() string {
	return fmt.Sprintf("the stored steps of record %s could not be read", e.subscriptionID)
}

// subStoreStagedKey is a record's staged document key as the plugin writes
// it, escaped as subStoreRecordKey escapes the live one.
func subStoreStagedKey(id string) string {
	return subStoreStagedKeyPrefix + strings.TrimPrefix(subStoreRecordKey(id), subStoreRecordKeyPrefix)
}

// subStoreRecordSteps reads a record's process steps from its live document,
// or from its staged one, as the plugin reads them (processSteps: process,
// or the pre-collections operators when process is empty). ok is false when
// the document is missing, over the bound, does not decode or names another
// record.
func (s *Server) subStoreRecordSteps(id string, staged bool) ([]json.RawMessage, bool) {
	var doc struct {
		ID        string            `json:"id"`
		Process   []json.RawMessage `json:"process"`
		Operators []json.RawMessage `json:"operators"`
	}
	raw, ok := s.subStoreRecordJSON(id, staged)
	if !ok || json.Unmarshal(raw, &doc) != nil || doc.ID != id {
		return nil, false
	}
	if len(doc.Process) > 0 {
		return doc.Process, true
	}
	return doc.Operators, true
}

// subStoreRecordJSON is the record object of a record's live document, or
// of its staged one taken out of its wrapper, as the store holds it and
// bounded. ok is false when the document is missing, over the bound or, for
// a staged one, does not decode; the caller decodes the record and checks
// its id.
func (s *Server) subStoreRecordJSON(id string, staged bool) (json.RawMessage, bool) {
	key := subStoreRecordKey(id)
	if staged {
		key = subStoreStagedKey(id)
	}
	entry, ok := s.store.KVEntry(usageSubStoreKVBucket, key)
	if !ok || len(entry.Value) == 0 || len(entry.Value) > usageMaxSubStoreRecordsLen {
		return nil, false
	}
	if !staged {
		return json.RawMessage(entry.Value), true
	}
	var wrapper struct {
		Record json.RawMessage `json:"record"`
	}
	if err := json.Unmarshal([]byte(entry.Value), &wrapper); err != nil || len(wrapper.Record) == 0 {
		return nil, false
	}
	return wrapper.Record, true
}

// subStorePlanStep is one step as a plan sees it: a digest of its stored
// bytes, its type cleaned for display, and whether it is disabled.
type subStorePlanStep struct {
	digest   [sha256.Size]byte
	kind     string
	disabled bool
}

// subStorePlanStepsOf reads each step's digest, type and disabled flag.
func subStorePlanStepsOf(raw []json.RawMessage) []subStorePlanStep {
	out := make([]subStorePlanStep, 0, len(raw))
	for _, step := range raw {
		var compact bytes.Buffer
		if json.Compact(&compact, step) != nil {
			compact.Reset()
			compact.Write(step)
		}
		var meta struct {
			Type     string `json:"type"`
			Disabled bool   `json:"disabled"`
		}
		kind := "unreadable step"
		if json.Unmarshal(step, &meta) == nil {
			kind = subStorePlanStepType(meta.Type)
		}
		out = append(out, subStorePlanStep{digest: sha256.Sum256(compact.Bytes()), kind: kind, disabled: meta.Disabled})
	}
	return out
}

// subStorePlanStepType cleans a step type for a plan line: ASCII letters
// and digits, any run of white space written as one space, bounded. The
// plugin checks types against its vocabulary when it writes, but core shows
// what the store holds and trusts none of it.
func subStorePlanStepType(value string) string {
	var b strings.Builder
	space := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			if space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			space = false
			b.WriteRune(r)
		case unicode.IsSpace(r):
			space = true
		}
		if b.Len() >= subStorePlanStepTypeBytes {
			break
		}
	}
	out := b.String()
	if len(out) > subStorePlanStepTypeBytes {
		out = strings.TrimSpace(out[:subStorePlanStepTypeBytes])
	}
	if out == "" {
		return "step with no type"
	}
	return out
}

// subStorePlanStepsDigest is the SHA-256 over every step's digest in order.
func subStorePlanStepsDigest(steps []subStorePlanStep) string {
	h := sha256.New()
	for _, step := range steps {
		h.Write(step.digest[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// subStorePlanChainChanges lists the steps added, removed and changed from
// before to after. Steps are matched by digest along the longest common
// subsequence, and a matched step is unchanged. Between two matches the
// unmatched steps are matched again by type, along the longest common
// subsequence of their types: a pair is a step changed in place, and what
// is left over was removed or added.
func subStorePlanChainChanges(before, after []subStorePlanStep) []string {
	if len(before) > subStorePlanChainDiffSteps || len(after) > subStorePlanChainDiffSteps {
		if subStorePlanStepsDigest(before) == subStorePlanStepsDigest(after) {
			return nil
		}
		return []string{fmt.Sprintf("the steps changed: %d before, %d after, too many to list one by one", len(before), len(after))}
	}
	var lines []string
	describe := func(verb string, position int, step subStorePlanStep, notes ...string) {
		if step.disabled && len(notes) == 0 {
			notes = append(notes, "disabled")
		}
		line := fmt.Sprintf("step %d %s: %s", position, verb, step.kind)
		if len(notes) > 0 {
			line += " (" + strings.Join(notes, ", ") + ")"
		}
		lines = append(lines, line)
	}
	changed := func(i, j int) {
		b, a := before[i], after[j]
		var notes []string
		if i != j {
			notes = append(notes, fmt.Sprintf("was step %d", i+1))
		}
		switch {
		case b.disabled && !a.disabled:
			notes = append(notes, "now enabled")
		case !b.disabled && a.disabled:
			notes = append(notes, "now disabled")
		case a.disabled:
			notes = append(notes, "disabled")
		}
		describe("changed", j+1, a, notes...)
	}
	// run lists before[fromI:toI] against after[fromJ:toJ], matched by type.
	run := func(fromI, fromJ, toI, toJ int) {
		walkCommon(toI-fromI, toJ-fromJ,
			func(i, j int) bool { return before[fromI+i].kind == after[fromJ+j].kind },
			func(i, j int) { changed(fromI+i, fromJ+j) },
			func(i int) { describe("removed", fromI+i+1, before[fromI+i]) },
			func(j int) { describe("added", fromJ+j+1, after[fromJ+j]) })
	}
	startI, startJ := 0, 0
	walkCommon(len(before), len(after),
		func(i, j int) bool { return before[i].digest == after[j].digest },
		func(i, j int) {
			run(startI, startJ, i, j)
			startI, startJ = i+1, j+1
		},
		func(int) {}, func(int) {})
	run(startI, startJ, len(before), len(after))
	if len(lines) > subStorePlanChainLines {
		more := len(lines) - (subStorePlanChainLines - 1)
		lines = append(lines[:subStorePlanChainLines-1], fmt.Sprintf("and %d more step changes", more))
	}
	return lines
}

// walkCommon walks two sequences of n and m items along a longest common
// subsequence under equal, in order: match for each pair on it, onlyA for
// each item of the first left out, onlyB for each of the second.
func walkCommon(n, m int, equal func(i, j int) bool, match func(i, j int), onlyA, onlyB func(int)) {
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if equal(i, j) {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case equal(i, j):
			match(i, j)
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
			onlyA(i)
			i++
		default:
			onlyB(j)
			j++
		}
	}
	for ; i < n; i++ {
		onlyA(i)
	}
	for ; j < m; j++ {
		onlyB(j)
	}
}

// chainSides names the documents a section's chain is read from on each
// side: the live document for a revision that is live, the staged document
// for the revision a promotion publishes, nothing for a side the record does
// not have. A staged-only section serves no one and has no chain.
func (section subStorePlanRecord) chainSides() (before, after string, ok bool) {
	const live, staged = "live", "staged"
	switch section.Role {
	case subStorePlanRolePromote:
		if section.FromRevision != "" {
			before = live
		}
		return before, staged, true
	case subStorePlanRoleDelete:
		return live, "", true
	case subStorePlanRoleSelf, subStorePlanRoleDependent:
		return live, live, true
	default:
		return "", "", false
	}
}

// subStorePlanSectionChain reads a section's chain on each side. It answers
// nil for a section that has none, and errSubStorePlanChainUnreadable when a
// side's document could not be read.
func (s *Server) subStorePlanSectionChain(section subStorePlanRecord) (*subStorePlanChain, error) {
	beforeDoc, afterDoc, ok := section.chainSides()
	if !ok {
		return nil, nil
	}
	read := func(doc string) ([]subStorePlanStep, string, error) {
		if doc == "" {
			return nil, "", nil
		}
		raw, ok := s.subStoreRecordSteps(section.SubscriptionID, doc == "staged")
		if !ok {
			return nil, "", &errSubStorePlanChainUnreadable{subscriptionID: section.SubscriptionID}
		}
		steps := subStorePlanStepsOf(raw)
		return steps, subStorePlanStepsDigest(steps), nil
	}
	before, beforeDigest, err := read(beforeDoc)
	if err != nil {
		return nil, err
	}
	after, afterDigest, err := read(afterDoc)
	if err != nil {
		return nil, err
	}
	chain := &subStorePlanChain{Before: beforeDigest, After: afterDigest}
	if beforeDoc != "" && afterDoc != "" && beforeDigest != afterDigest {
		chain.Changes = subStorePlanChainChanges(before, after)
	}
	if beforeDoc == "" && afterDoc != "" {
		// A record with no live revision gains every step it has.
		chain.Changes = subStorePlanChainChanges(nil, after)
	}
	return chain, nil
}

// subStorePlanChainHolds reports whether a section's chain is still the one
// the plan shows. A section that should carry a chain and carries none (a
// plan written before the chain was folded in) does not hold.
func (s *Server) subStorePlanChainHolds(section subStorePlanRecord) bool {
	current, err := s.subStorePlanSectionChain(section)
	if err != nil {
		return false
	}
	if current == nil || section.Chain == nil {
		return current == nil && section.Chain == nil
	}
	return current.Before == section.Chain.Before && current.After == section.Chain.After
}

// subStorePlanChainProposeError is propose's answer to a chain it could not
// read: the record moved between depends_on and the read, or the store is
// inconsistent, and a plan that cannot show the steps is not filed.
func subStorePlanChainProposeError(err *errSubStorePlanChainUnreadable) error {
	return rpcAPIError(http.StatusConflict, subStoreSvcErrConflict, err.Error()+"; propose it again")
}
