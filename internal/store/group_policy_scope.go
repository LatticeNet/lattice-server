package store

import (
	"github.com/LatticeNet/lattice-sdk/model"
)

// ScopeGroupAlias is the scope_group_id an outbound policy carries for a
// stored scope: the group when the scope is exactly one group and nothing
// else, so a reader that knows only the older field still sees the right
// group, and "" otherwise.
func ScopeGroupAlias(sel model.TargetSelector) string {
	if len(sel.Groups) == 1 && len(sel.Nodes) == 0 && !sel.All && len(sel.Exclude) == 0 {
		return sel.Groups[0]
	}
	return ""
}
