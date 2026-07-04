package server

import (
	"encoding/json"
	"net/http"
	"testing"
)

type inventoryTestView struct {
	PurityPercent *int   `json:"purity_percent"`
	Quality       string `json:"quality"`
	Notes         string `json:"notes"`
}

// nodeInventoryView fetches the node list and returns the inventory carried on
// the DTO for nodeID, proving toNodeView copies the field end to end.
func nodeInventoryView(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, nodeID string) *inventoryTestView {
	t.Helper()
	res := doJSON(t, handler, http.MethodGet, "/api/nodes", "", cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("node list status = %d", res.StatusCode)
	}
	var views []struct {
		ID        string             `json:"id"`
		Inventory *inventoryTestView `json:"inventory"`
	}
	if err := json.NewDecoder(res.Body).Decode(&views); err != nil {
		t.Fatal(err)
	}
	for _, v := range views {
		if v.ID == nodeID {
			return v.Inventory
		}
	}
	t.Fatalf("node %q missing from node views", nodeID)
	return nil
}

func TestNodeInventoryEnrollPersistsAndEchoes(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	res := doJSON(t, handler, http.MethodPost, "/api/nodes/enroll-token",
		`{"node_id":"inv-node","name":"Inv","inventory":{"purity_percent":98,"quality":"high","notes":"residential ISP, 98% pure"}}`,
		cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("enroll: %d", res.StatusCode)
	}

	n, ok := st.Node("inv-node")
	if !ok || n.Inventory == nil {
		t.Fatalf("inventory not persisted: %+v", n)
	}
	if n.Inventory.PurityPercent == nil || *n.Inventory.PurityPercent != 98 ||
		n.Inventory.Quality != "high" || n.Inventory.Notes != "residential ISP, 98% pure" {
		t.Fatalf("stored inventory fields wrong: %+v", n.Inventory)
	}

	view := nodeInventoryView(t, handler, cookies, csrf, "inv-node")
	if view == nil || view.PurityPercent == nil || *view.PurityPercent != 98 || view.Quality != "high" {
		t.Fatalf("node view omitted inventory: %+v", view)
	}
}

func TestNodeInventoryUpdateSemantics(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	enroll := doJSON(t, handler, http.MethodPost, "/api/nodes/enroll-token",
		`{"node_id":"inv-node","name":"Inv","inventory":{"purity_percent":90,"quality":"medium"}}`,
		cookies, csrf)
	if enroll.StatusCode != http.StatusOK {
		t.Fatalf("enroll: %d", enroll.StatusCode)
	}
	enroll.Body.Close()

	// (b) an update that omits inventory leaves the stored value untouched.
	res := doJSON(t, handler, http.MethodPost, "/api/nodes/update",
		`{"node_id":"inv-node","name":"Renamed","tags":[]}`, cookies, csrf)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("update (omit inventory): %d", res.StatusCode)
	}
	res.Body.Close()
	if n, _ := st.Node("inv-node"); n.Inventory == nil || n.Inventory.Quality != "medium" ||
		n.Inventory.PurityPercent == nil || *n.Inventory.PurityPercent != 90 {
		t.Fatalf("omitted inventory must be unchanged: %+v", n.Inventory)
	}

	// (c) an update carrying inventory replaces it, and the response echoes it.
	res = doJSON(t, handler, http.MethodPost, "/api/nodes/update",
		`{"node_id":"inv-node","inventory":{"purity_percent":99,"quality":"high","notes":"clean"}}`, cookies, csrf)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("update (set inventory): %d", res.StatusCode)
	}
	var upd struct {
		Inventory *inventoryTestView `json:"inventory"`
	}
	if err := json.NewDecoder(res.Body).Decode(&upd); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if upd.Inventory == nil || upd.Inventory.PurityPercent == nil || *upd.Inventory.PurityPercent != 99 ||
		upd.Inventory.Quality != "high" || upd.Inventory.Notes != "clean" {
		t.Fatalf("update response must echo replaced inventory: %+v", upd.Inventory)
	}
	if n, _ := st.Node("inv-node"); n.Inventory == nil || n.Inventory.PurityPercent == nil || *n.Inventory.PurityPercent != 99 {
		t.Fatalf("inventory not replaced in store: %+v", n.Inventory)
	}

	// (d) an empty inventory object clears the stored value.
	res = doJSON(t, handler, http.MethodPost, "/api/nodes/update",
		`{"node_id":"inv-node","inventory":{}}`, cookies, csrf)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("update (clear inventory): %d", res.StatusCode)
	}
	res.Body.Close()
	if n, _ := st.Node("inv-node"); n.Inventory != nil {
		t.Fatalf("empty inventory object must clear stored value: %+v", n.Inventory)
	}
}

func TestNodeInventoryRejectsOutOfRangePurity(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	// (e) enroll with purity 101 is rejected before the node is created.
	bad := doJSON(t, handler, http.MethodPost, "/api/nodes/enroll-token",
		`{"node_id":"bad-node","name":"Bad","inventory":{"purity_percent":101}}`, cookies, csrf)
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("enroll purity 101 must be 400, got %d", bad.StatusCode)
	}
	bad.Body.Close()

	ok := doJSON(t, handler, http.MethodPost, "/api/nodes/enroll-token",
		`{"node_id":"ok-node","name":"OK"}`, cookies, csrf)
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("enroll: %d", ok.StatusCode)
	}
	ok.Body.Close()

	// (e) update with purity 101 is likewise a 400.
	upd := doJSON(t, handler, http.MethodPost, "/api/nodes/update",
		`{"node_id":"ok-node","inventory":{"purity_percent":101}}`, cookies, csrf)
	if upd.StatusCode != http.StatusBadRequest {
		t.Fatalf("update purity 101 must be 400, got %d", upd.StatusCode)
	}
	upd.Body.Close()
}
