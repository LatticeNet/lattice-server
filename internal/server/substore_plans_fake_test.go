package server

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// subStoreFakeGraph answers depends_on v2 the way the plugin does
// (system-go/subscription_depends.go): with subscription_id, the record and
// every record that reads it, transitively, over the union edges, and the
// edges among them; without one, every record and every edge. The record
// facts and the union closures are the test's to state.
type subStoreFakeGraph struct {
	mu      sync.Mutex
	records map[string]fleetDependsFacts
	edges   []fleetDependsEdge
	// unionFleet is the fleet_bound closure over live and staged state;
	// unionOwner the owner_credentials one.
	unionFleet map[string]bool
	unionOwner map[string]bool
	err        error
	calls      []fleetDependsRequest
	// onQuery runs before each answer, outside the lock.
	onQuery func(fleetDependsRequest)
	// st holds the record documents a plan reads each section's process
	// chain from (substore_svc_plans_chain.go). put writes a document with
	// no steps for each revision a record states, unless one is there:
	// setSteps writes the steps a test needs.
	st *store.Store
}

func newSubStoreFakeGraph() *subStoreFakeGraph {
	return &subStoreFakeGraph{records: map[string]fleetDependsFacts{}, unionFleet: map[string]bool{}, unionOwner: map[string]bool{}}
}

// put states a record's facts; a fleet record or one staged as fleet is in
// the union fleet closure, a legacy one in the owner closure.
func (f *subStoreFakeGraph) put(facts fleetDependsFacts) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[facts.ID] = facts
	if f.st != nil {
		f.putDocumentIfAbsent(subStoreRecordKey(facts.ID), facts.Revision != "", map[string]any{"id": facts.ID})
		f.putDocumentIfAbsent(subStoreStagedKey(facts.ID), facts.StagedRevision != "", map[string]any{"record": map[string]any{"id": facts.ID}})
	}
	if facts.FleetBound || facts.Source == subStoreSourceFleet || facts.StagedSource == subStoreSourceFleet {
		f.unionFleet[facts.ID] = true
	}
	if facts.OwnerCredentials || subStoreLegacySource(facts.Source) {
		f.unionOwner[facts.ID] = true
	}
}

// putDocumentIfAbsent writes a record document under key when want is set
// and none is stored there.
func (f *subStoreFakeGraph) putDocumentIfAbsent(key string, want bool, doc map[string]any) {
	if !want {
		return
	}
	if _, ok := f.st.KVEntry(usageSubStoreKVBucket, key); ok {
		return
	}
	raw, _ := json.Marshal(doc)
	if err := f.st.PutKV(model.KVEntry{Bucket: usageSubStoreKVBucket, Key: key, Value: string(raw)}); err != nil {
		panic(err)
	}
}

// putSubStoreChainDocuments writes a live and a staged record document with
// no steps for id where none is stored, for a test that answers depends_on
// with a fake of its own: propose reads each side's process chain from them
// (substore_svc_plans_chain.go).
func putSubStoreChainDocuments(t testing.TB, st *store.Store, id string) {
	t.Helper()
	for key, doc := range map[string]any{
		subStoreRecordKey(id): map[string]any{"id": id},
		subStoreStagedKey(id): map[string]any{"record": map[string]any{"id": id}},
	} {
		if _, ok := st.KVEntry(usageSubStoreKVBucket, key); ok {
			continue
		}
		raw, _ := json.Marshal(doc)
		if err := st.PutKV(model.KVEntry{Bucket: usageSubStoreKVBucket, Key: key, Value: string(raw)}); err != nil {
			t.Fatal(err)
		}
	}
}

// setSteps stores a record's process steps in its live document, or in its
// staged one, as the plugin's store writes them.
func (f *subStoreFakeGraph) setSteps(t testing.TB, id string, staged bool, steps ...json.RawMessage) {
	t.Helper()
	record := map[string]any{"id": id, "process": steps}
	var doc any = record
	key := subStoreRecordKey(id)
	if staged {
		doc, key = map[string]any{"record": record, "base_revision": f.records[id].Revision, "staged_at": "2026-10-16T00:00:00Z"}, subStoreStagedKey(id)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.PutKV(model.KVEntry{Bucket: usageSubStoreKVBucket, Key: key, Value: string(raw)}); err != nil {
		t.Fatal(err)
	}
}

// markUnionFleet puts a record in the union fleet closure, as the plugin's
// closure over its members' staged sources would.
func (f *subStoreFakeGraph) markUnionFleet(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unionFleet[id] = true
}

// edge states that from reads to.
func (f *subStoreFakeGraph) edge(from, to, via string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.edges = append(f.edges, fleetDependsEdge{From: from, To: to, Via: via})
}

// update edits one record's facts.
func (f *subStoreFakeGraph) update(id string, edit func(*fleetDependsFacts)) {
	f.mu.Lock()
	facts := f.records[id]
	f.mu.Unlock()
	edit(&facts)
	f.put(facts)
}

func (f *subStoreFakeGraph) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *subStoreFakeGraph) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *subStoreFakeGraph) answer(_ context.Context, _ string, payload []byte) ([]byte, error) {
	var req fleetDependsRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	f.mu.Lock()
	hook := f.onQuery
	f.mu.Unlock()
	if hook != nil {
		hook(req)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, req)
	if f.err != nil {
		return nil, f.err
	}
	selected := map[string]bool{}
	if req.SubscriptionID != "" {
		if _, ok := f.records[req.SubscriptionID]; !ok {
			return nil, errors.New("subscription was not found")
		}
		selected[req.SubscriptionID] = true
		for changed := true; changed; {
			changed = false
			for _, e := range f.edges {
				if selected[e.To] && !selected[e.From] {
					selected[e.From] = true
					changed = true
				}
			}
		}
	} else {
		for id := range f.records {
			selected[id] = true
		}
	}
	reply := struct {
		Records          []fleetDependsFacts `json:"records"`
		FleetBound       []string            `json:"fleet_bound"`
		OwnerCredentials []string            `json:"owner_credentials"`
		Edges            []fleetDependsEdge  `json:"edges"`
		Version          string              `json:"version"`
	}{Records: []fleetDependsFacts{}, FleetBound: []string{}, OwnerCredentials: []string{}, Edges: []fleetDependsEdge{}, Version: "fake"}
	for id := range selected {
		facts, ok := f.records[id]
		if !ok {
			continue
		}
		reply.Records = append(reply.Records, facts)
		if f.unionFleet[id] {
			reply.FleetBound = append(reply.FleetBound, id)
		}
		if f.unionOwner[id] {
			reply.OwnerCredentials = append(reply.OwnerCredentials, id)
		}
	}
	for _, e := range f.edges {
		if selected[e.From] && selected[e.To] {
			reply.Edges = append(reply.Edges, e)
		}
	}
	sort.Slice(reply.Records, func(i, j int) bool { return reply.Records[i].ID < reply.Records[j].ID })
	sort.Strings(reply.FleetBound)
	sort.Strings(reply.OwnerCredentials)
	return json.Marshal(reply)
}

// installSubStoreFakeGraph wires a fake depends_on into a server.
func installSubStoreFakeGraph(t testing.TB, srv *Server) *subStoreFakeGraph {
	t.Helper()
	g := newSubStoreFakeGraph()
	g.st = srv.store
	srv.substoreCatalogue.deps.query = g.answer
	return g
}
