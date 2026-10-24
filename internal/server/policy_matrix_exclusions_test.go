package server

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
)

// Design 32 S3b: the policy matrix shows a group or fleet target's
// exclusions. A group row used to read a cell as the group's even when the
// policy left some members out, and a whole-fleet policy had no row at all.

type matrixExclusionsOut struct {
	Cells []struct {
		From string `json:"from"`
		To   string `json:"to"`
	} `json:"cells"`
	Exclusions []matrixExclusion `json:"exclusions"`
	Fleet      *matrixFleetRow   `json:"fleet"`
}

func readMatrix(t *testing.T, res *http.Response) matrixExclusionsOut {
	t.Helper()
	raw := readBody(t, res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("matrix = %d %s", res.StatusCode, raw)
	}
	var out matrixExclusionsOut
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func excludedIDs(ex matrixExclusion) []string {
	out := make([]string, 0, len(ex.Nodes))
	for _, n := range ex.Nodes {
		out = append(out, n.ID)
	}
	return out
}

func TestNetPolicyMatrixShowsGroupAndFleetExclusions(t *testing.T) {
	handler, _, cookies, csrf := outboundFleet(t, "n1", "n2", "n3", "n4")
	a := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups", `{"name":"A","slug":"a","members":["n1","n2"]}`, cookies, csrf))
	c := decodeGroup(t, doJSON(t, handler, http.MethodPost, "/api/groups", `{"name":"C","slug":"c","members":["n3"]}`, cookies, csrf))
	toC := `"rules":[{"id":"r","action":"allow","direction":"egress","protocol":"tcp","ports":[22],"remote":{"kind":"group","group_id":"` + c.ID + `"}}]`
	_, groupPolicy, raw := postPolicy(t, handler, cookies, csrf, `{"name":"a-to-c","scope":{"groups":["`+a.ID+`"],"exclude":["n2","n4"]},"enabled":true,`+toC+`}`)
	if groupPolicy.ID == "" {
		t.Fatalf("group policy: %s", raw)
	}
	_, fleetPolicy, raw := postPolicy(t, handler, cookies, csrf, `{"scope":{"all":true,"exclude":["n3"]},"enabled":true,"priority":5,`+toC+`}`)
	if fleetPolicy.ID == "" {
		t.Fatalf("fleet policy: %s", raw)
	}

	out := readMatrix(t, doJSON(t, handler, http.MethodGet, "/api/netpolicy/matrix", "", cookies, csrf))
	if len(out.Exclusions) != 1 {
		t.Fatalf("exclusions = %+v, want one for row A", out.Exclusions)
	}
	ex := out.Exclusions[0]
	// n4 is not a member of A, so excluding it changes nothing on this row.
	if ex.From != a.ID || ex.PolicyID != groupPolicy.ID || ex.Label != "a-to-c" || !reflect.DeepEqual(excludedIDs(ex), []string{"n2"}) || ex.Hidden != 0 {
		t.Fatalf("row A exclusion = %+v", ex)
	}
	if out.Fleet == nil || len(out.Fleet.Cells) != 1 || out.Fleet.Cells[0].To != c.ID || out.Fleet.Cells[0].From != "" {
		t.Fatalf("fleet row = %+v", out.Fleet)
	}
	if len(out.Fleet.Exclusions) != 1 || !reflect.DeepEqual(excludedIDs(out.Fleet.Exclusions[0]), []string{"n3"}) || out.Fleet.Exclusions[0].PolicyID != fleetPolicy.ID {
		t.Fatalf("fleet exclusions = %+v", out.Fleet.Exclusions)
	}
	for _, cell := range out.Cells {
		if cell.From == "" {
			t.Fatalf("fleet cells stay in the fleet row: %+v", out.Cells)
		}
	}

	// A reader confined to n1 sees the exclusions counted, not named.
	confined := createPAT(t, handler, cookies, csrf, []string{"netpolicy:read"}, []string{"n1"})
	out = readMatrix(t, doBearerJSON(t, handler, http.MethodGet, "/api/netpolicy/matrix", "", confined))
	if len(out.Exclusions) != 1 || len(out.Exclusions[0].Nodes) != 0 || out.Exclusions[0].Hidden != 1 {
		t.Fatalf("confined row A exclusion = %+v", out.Exclusions)
	}
	if out.Fleet == nil || len(out.Fleet.Exclusions) != 1 || len(out.Fleet.Exclusions[0].Nodes) != 0 || out.Fleet.Exclusions[0].Hidden != 1 {
		t.Fatalf("confined fleet exclusions = %+v", out.Fleet)
	}
}

// Without a fleet-wide policy there is no fleet row, so the answer stays
// what an older console reads.
func TestNetPolicyMatrixOmitsTheFleetRowWithoutAFleetPolicy(t *testing.T) {
	handler, _, cookies, csrf := outboundFleet(t, "n1")
	out := readMatrix(t, doJSON(t, handler, http.MethodGet, "/api/netpolicy/matrix", "", cookies, csrf))
	if out.Fleet != nil || out.Exclusions == nil || len(out.Exclusions) != 0 {
		t.Fatalf("matrix without policies = %+v", out)
	}
}
