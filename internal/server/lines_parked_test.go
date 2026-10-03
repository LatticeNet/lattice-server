package server

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The parked users a node reports per line, decoded with the same caution as
// the naming counts: only a count a conf file could hold, only Lattice's own
// names, never more names than the count, and the damaged-file marker kept
// apart from a count of zero.
func TestDiscoveredParkedUsersKeepsOnlyWhatTheNodeCanVouchFor(t *testing.T) {
	for _, tc := range []struct {
		name      string
		meta      map[string]string
		wantCount int
		wantNames []string
		wantErr   string
	}{
		{"alpha.8 report", map[string]string{singBoxParkedUsersKey: "2", singBoxParkedNamesKey: `["u_2222222222222222","u_1111111111111111"]`},
			2, []string{"u_1111111111111111", "u_2222222222222222"}, ""},
		{"a hand-parked user is counted, not named", map[string]string{singBoxParkedUsersKey: "2", singBoxParkedNamesKey: `["u_1111111111111111"]`},
			2, []string{"u_1111111111111111"}, ""},
		{"a name that is not Lattice's is dropped", map[string]string{singBoxParkedUsersKey: "3", singBoxParkedNamesKey: `["alice@example.com","u_1111111111111111","U_1111111111111111"]`},
			3, []string{"u_1111111111111111"}, ""},
		{"more names than the count", map[string]string{singBoxParkedUsersKey: "1", singBoxParkedNamesKey: `["u_1111111111111111","u_2222222222222222"]`},
			1, nil, ""},
		{"names that are not a JSON array", map[string]string{singBoxParkedUsersKey: "1", singBoxParkedNamesKey: `u_1111111111111111`},
			1, nil, ""},
		{"names without a count", map[string]string{singBoxParkedNamesKey: `["u_1111111111111111"]`}, 0, nil, ""},
		{"not a number", map[string]string{singBoxParkedUsersKey: "some"}, 0, nil, ""},
		{"absurd", map[string]string{singBoxParkedUsersKey: "999999999"}, 0, nil, ""},
		{"damaged parked file", map[string]string{singBoxParkedErrorKey: "parked_invalid"}, 0, nil, "parked_invalid"},
		{"an error that is not the script's", map[string]string{singBoxParkedErrorKey: "<b>oops</b>"}, 0, nil, ""},
		{"nothing reported", nil, 0, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			count, names, parkedErr := discoveredParkedUsers(model.SingBoxNode{Metadata: tc.meta})
			if count != tc.wantCount || !reflect.DeepEqual(names, tc.wantNames) || parkedErr != tc.wantErr {
				t.Fatalf("got %d %v %q, want %d %v %q", count, names, parkedErr, tc.wantCount, tc.wantNames, tc.wantErr)
			}
		})
	}
}

// From the node's list metadata, exactly as alpha.8 emits it (both values are
// strings, because the agent decodes the map as map[string]string), to the
// line the console reads.
func TestALinesParkedUsersComeFromTheNodesReport(t *testing.T) {
	srv := newLinemetaTestServer(t, mustOpenStore(t))
	if err := srv.store.UpsertNode(model.Node{ID: "node-a", Name: "Node A", PublicIP: "203.0.113.5"}); err != nil {
		t.Fatal(err)
	}
	srv.singboxInvMu.Lock()
	srv.singboxInv = map[string]model.SingBoxInventory{"node-a": {NodeID: "node-a", At: srv.now(), Status: "ok", Nodes: []model.SingBoxNode{
		{Name: "parked.json", Protocol: "vless", Network: "tcp", Address: "203.0.113.5", Port: "443", UserKnown: true, UserCount: 2,
			Metadata: map[string]string{"named_users": "2", "unnamed_users": "0", "parked_users": "1", "parked_names": `["u_2222222222222222"]`}},
		{Name: "damaged.json", Protocol: "vless", Network: "tcp", Address: "203.0.113.5", Port: "8443", UserKnown: true, UserCount: 1,
			Metadata: map[string]string{"parked_error": "parked_invalid"}},
		{Name: "plain.json", Protocol: "vless", Network: "tcp", Address: "203.0.113.5", Port: "9443", UserKnown: true, UserCount: 1},
	}}}
	srv.singboxInvMu.Unlock()
	srv.invalidateLineReadModel()
	groups := srv.buildLineGroups()

	parked := findLine(t, groups, "node-a", "parked.json")
	if parked.ParkedUsers != 1 || !reflect.DeepEqual(parked.ParkedNames, []string{"u_2222222222222222"}) || parked.ParkedError != "" {
		t.Fatalf("parked line = %d %v %q", parked.ParkedUsers, parked.ParkedNames, parked.ParkedError)
	}
	raw, err := json.Marshal(parked)
	if err != nil {
		t.Fatal(err)
	}
	var view map[string]any
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	if view["parked_users"] != float64(1) || !reflect.DeepEqual(view["parked_names"], []any{"u_2222222222222222"}) {
		t.Fatalf("line JSON carries parked_users %v parked_names %v", view["parked_users"], view["parked_names"])
	}

	if damaged := findLine(t, groups, "node-a", "damaged.json"); damaged.ParkedUsers != 0 || damaged.ParkedError != singBoxParkedInvalid {
		t.Fatalf("damaged line = %d %q, want the marker and no count", damaged.ParkedUsers, damaged.ParkedError)
	}
	plain := findLine(t, groups, "node-a", "plain.json")
	raw, _ = json.Marshal(plain)
	view = nil
	_ = json.Unmarshal(raw, &view)
	for _, key := range []string{"parked_users", "parked_names", "parked_error"} {
		if _, ok := view[key]; ok {
			t.Fatalf("a line with nothing parked must not carry %s: %s", key, raw)
		}
	}
}
