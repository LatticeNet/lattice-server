package store

import (
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The task list resolves the approvals behind a page of rows with one read;
// it must return exactly the stored ones among the ids it names.
func TestApprovalsByIDReturnsOnlyStoredApprovalsAmongTheIDs(t *testing.T) {
	st, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"ap-1", "ap-2", "ap-3"} {
		if err := st.UpsertApproval(model.Approval{ID: id, NodeID: "node-a", Plugin: "nft", Action: "apply", Status: model.ApprovalApplied}); err != nil {
			t.Fatal(err)
		}
	}
	got := st.ApprovalsByID([]string{"ap-3", "ap-gone", "", "ap-1"})
	if len(got) != 2 || got[0].ID != "ap-3" || got[1].ID != "ap-1" {
		t.Fatalf("ApprovalsByID = %d approvals %v, want ap-3 then ap-1", len(got), got)
	}
	if got := st.ApprovalsByID(nil); len(got) != 0 {
		t.Fatalf("no ids returned %d approvals", len(got))
	}
}
