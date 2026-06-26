package store

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// TestAddTaskResultRetention verifies task results are bounded to maxTaskResults
// (oldest evicted) so on-disk state cannot grow without limit.
func TestAddTaskResultRetention(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	// Seed state at exactly the cap (direct, to avoid maxTaskResults disk writes).
	s.state.Results = make([]model.TaskResult, 0, maxTaskResults)
	for i := 0; i < maxTaskResults; i++ {
		s.state.Results = append(s.state.Results, model.TaskResult{TaskID: fmt.Sprintf("old-%d", i)})
	}
	if err := s.AddTaskResult(model.TaskResult{TaskID: "newest"}); err != nil {
		t.Fatalf("AddTaskResult: %v", err)
	}
	if got := len(s.state.Results); got != maxTaskResults {
		t.Fatalf("retained %d results, want cap %d", got, maxTaskResults)
	}
	last := s.state.Results[len(s.state.Results)-1]
	if last.TaskID != "newest" {
		t.Fatalf("newest result evicted; last TaskID = %q", last.TaskID)
	}
	if first := s.state.Results[0].TaskID; first == "old-0" {
		t.Fatalf("oldest result (old-0) should have been evicted, still at front")
	}
}
