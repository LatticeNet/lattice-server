package server

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"testing"
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
	if facts.FleetBound || facts.Source == subStoreSourceFleet || facts.StagedSource == subStoreSourceFleet {
		f.unionFleet[facts.ID] = true
	}
	if facts.OwnerCredentials || subStoreLegacySource(facts.Source) {
		f.unionOwner[facts.ID] = true
	}
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
	srv.substoreCatalogue.deps.query = g.answer
	return g
}
