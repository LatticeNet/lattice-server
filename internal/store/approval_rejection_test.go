package store

import (
	"path/filepath"
	"testing"
	"time"
)

// The rejecting actor has to outlive the process, or the console goes back to
// guessing who said no from the fields that are left.
func TestApprovalRejectionSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 29, 4, 27, 50, 0, time.UTC)
	if err := st.SetApprovalRejection(ApprovalRejection{ApprovalID: "approval_x", ActorID: "user_admin", At: at}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetApprovalRejection(ApprovalRejection{ApprovalID: "", ActorID: "user_admin", At: at}); err == nil {
		t.Fatal("a rejection with no approval must be refused")
	}
	st.Close()

	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	got, ok := again.ApprovalRejection("approval_x")
	if !ok || got.ActorID != "user_admin" || !got.At.Equal(at) {
		t.Fatalf("rejection did not survive reopen: %+v (found=%v)", got, ok)
	}
	if _, ok := again.ApprovalRejection("approval_y"); ok {
		t.Fatal("an approval nobody rejected must have no record")
	}
}
