package store

import (
	"encoding/json"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func cloneNodeFixture() model.Node {
	purity := 80
	return model.Node{
		ID:                   "node-a",
		Name:                 "node-a",
		Tags:                 []string{"edge"},
		AgentSourceAllowlist: []string{"203.0.113.7"},
		GroupIDs:             []string{"group-1"},
		Inventory:            &model.NodeInventory{PurityPercent: &purity},
		Geo:                  &model.NodeGeo{},
		AgentLaunch:          &model.AgentLaunchConfig{AllowExec: true},
		IPConfig:             &model.NodeIPConfig{Resolvers: []string{"https://ip.example/"}},
		Trace:                model.TracePolicy{NodeID: "node-a", Enabled: true, Raw: &model.RawLinePolicy{Enabled: true}},
	}
}

// A node read from the store shares no memory with the stored one: writing
// through any pointer or slice of the copy leaves the next read unchanged.
func TestNodeCopiesShareNoMemoryWithTheStore(t *testing.T) {
	st, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNode(cloneNodeFixture()); err != nil {
		t.Fatal(err)
	}
	before, _ := st.Node("node-a")
	want, _ := json.Marshal(before)

	for _, got := range [][]model.Node{{before}, st.Nodes()} {
		n := got[0]
		n.Tags[0] = "changed"
		n.AgentSourceAllowlist[0] = "198.51.100.1"
		n.GroupIDs[0] = "group-2"
		*n.Inventory.PurityPercent = 1
		n.AgentLaunch.AllowExec = false
		n.IPConfig.Resolvers[0] = "https://changed.example/"
		n.Trace.Raw.Enabled = false
	}

	after, _ := st.Node("node-a")
	if have, _ := json.Marshal(after); string(have) != string(want) {
		t.Fatalf("writing through a copy changed the stored node:\nbefore %s\nafter  %s", want, have)
	}
}

// The deep copy keeps the encoded form: an empty slice stays empty and a nil
// one stays nil, so a node's JSON does not change on the way through.
func TestNodeCopyKeepsEmptyAndNilSlices(t *testing.T) {
	n := model.Node{ID: "node-b", Tags: []string{}}
	c := cloneNode(n)
	if c.Tags == nil || len(c.Tags) != 0 {
		t.Fatalf("empty Tags became %#v", c.Tags)
	}
	if c.GroupIDs != nil {
		t.Fatalf("nil GroupIDs became %#v", c.GroupIDs)
	}
	a, _ := json.Marshal(n)
	b, _ := json.Marshal(c)
	if string(a) != string(b) {
		t.Fatalf("copy encodes differently:\n%s\n%s", a, b)
	}
}
