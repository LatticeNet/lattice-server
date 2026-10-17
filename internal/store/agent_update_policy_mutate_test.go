package store

import (
	"sync"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestMutateAgentUpdatePolicy(t *testing.T) {
	st, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	set := func(p *model.AgentUpdatePolicy) bool { p.LastError = "x"; return true }

	if written, err := st.MutateAgentUpdatePolicy("node-a", false, set); err != nil || written {
		t.Fatalf("no policy and no create must write nothing: written=%t err=%v", written, err)
	}
	if _, ok := st.AgentUpdatePolicy("node-a"); ok {
		t.Fatal("a policy appeared without create")
	}

	if written, err := st.MutateAgentUpdatePolicy("node-a", true, set); err != nil || !written {
		t.Fatalf("create must write: written=%t err=%v", written, err)
	}
	created, ok := st.AgentUpdatePolicy("node-a")
	if !ok || created.NodeID != "node-a" || created.LastError != "x" || created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Fatalf("created policy = %+v", created)
	}

	if written, err := st.MutateAgentUpdatePolicy("node-a", false, func(p *model.AgentUpdatePolicy) bool { p.LastError = "y"; return false }); err != nil || written {
		t.Fatalf("a declined mutation must write nothing: written=%t err=%v", written, err)
	}
	if p, _ := st.AgentUpdatePolicy("node-a"); p.LastError != "x" {
		t.Fatalf("a declined mutation changed the stored policy: %q", p.LastError)
	}

	// Writers of different fields do not lose each other's writes.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = st.MutateAgentUpdatePolicy("node-a", false, func(p *model.AgentUpdatePolicy) bool { p.LastAppliedVersion = "0.3.4"; return true })
		}()
		go func() {
			defer wg.Done()
			_, _ = st.MutateAgentUpdatePolicy("node-a", false, func(p *model.AgentUpdatePolicy) bool {
				p.LastFetch = &model.AgentUpdateFetch{ApprovalID: "approval_a", Stage: "done"}
				return true
			})
		}()
	}
	wg.Wait()
	if p, _ := st.AgentUpdatePolicy("node-a"); p.LastAppliedVersion != "0.3.4" || p.LastFetch == nil || p.LastError != "x" {
		t.Fatalf("concurrent field writers lost a write: %+v", p)
	}
}
