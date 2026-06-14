package store

import (
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestNodeGeoIsCopiedOnStoreBoundaries(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	geo := &model.NodeGeo{Country: "JP", City: "Tokyo", Lat: 35.6762, Lon: 139.6503}
	if err := s.UpsertNode(model.Node{ID: "node-a", Name: "Node A", Geo: geo}); err != nil {
		t.Fatal(err)
	}
	geo.Country = "US"

	got, ok := s.Node("node-a")
	if !ok || got.Geo == nil || got.Geo.Country != "JP" {
		t.Fatalf("upsert leaked caller geo pointer: ok=%v node=%+v", ok, got)
	}
	got.Geo.Country = "GB"

	gotAgain, ok := s.Node("node-a")
	if !ok || gotAgain.Geo == nil || gotAgain.Geo.Country != "JP" {
		t.Fatalf("Node returned mutable geo pointer: ok=%v node=%+v", ok, gotAgain)
	}

	nodes := s.Nodes()
	if len(nodes) != 1 || nodes[0].Geo == nil {
		t.Fatalf("expected one node with geo, got %+v", nodes)
	}
	nodes[0].Geo.Country = "DE"

	gotAgain, ok = s.Node("node-a")
	if !ok || gotAgain.Geo == nil || gotAgain.Geo.Country != "JP" {
		t.Fatalf("Nodes returned mutable geo pointer: ok=%v node=%+v", ok, gotAgain)
	}
}
