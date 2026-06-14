package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestNodeGeoUpdateListAndClear(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")

	update := doJSON(t, handler, http.MethodPost, "/api/nodes/geo", `{
		"node_id":"node-a",
		"geo":{
			"country":" jp ",
			"city":"Tokyo\nControl",
			"lat":35.6762,
			"lon":139.6503,
			"asn":2516,
			"as_org":"KDDI",
			"provider":"oracle jp"
		}
	}`, cookies, csrf)
	defer update.Body.Close()
	if update.StatusCode != http.StatusOK {
		t.Fatalf("geo update failed: %d", update.StatusCode)
	}
	var view nodeGeoView
	if err := json.NewDecoder(update.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	if view.Geo == nil || view.Geo.Country != "JP" || view.Geo.City != "TokyoControl" || view.Geo.ASN != 2516 || view.Geo.UpdatedAt.IsZero() {
		t.Fatalf("geo was not normalized: %+v", view.Geo)
	}
	node, ok := st.Node("node-a")
	if !ok || node.Geo == nil || node.Geo.Provider != "oracle jp" {
		t.Fatalf("geo not stored: ok=%v node=%+v", ok, node)
	}

	nodes := doJSON(t, handler, http.MethodGet, "/api/nodes", "", cookies, "")
	defer nodes.Body.Close()
	var nodeViews []struct {
		ID  string         `json:"id"`
		Geo *model.NodeGeo `json:"geo,omitempty"`
	}
	if err := json.NewDecoder(nodes.Body).Decode(&nodeViews); err != nil {
		t.Fatal(err)
	}
	if len(nodeViews) != 1 || nodeViews[0].Geo == nil || nodeViews[0].Geo.Country != "JP" {
		t.Fatalf("/api/nodes must expose geo to node readers: %+v", nodeViews)
	}

	list := doJSON(t, handler, http.MethodGet, "/api/nodes/geo", "", cookies, "")
	defer list.Body.Close()
	var geoViews []nodeGeoView
	if err := json.NewDecoder(list.Body).Decode(&geoViews); err != nil {
		t.Fatal(err)
	}
	if len(geoViews) != 1 || geoViews[0].ID != "node-a" || geoViews[0].Geo == nil {
		t.Fatalf("bad geo list: %+v", geoViews)
	}

	clear := doJSON(t, handler, http.MethodPost, "/api/nodes/geo", `{"node_id":"node-a","clear":true}`, cookies, csrf)
	clear.Body.Close()
	if clear.StatusCode != http.StatusOK {
		t.Fatalf("geo clear failed: %d", clear.StatusCode)
	}
	node, ok = st.Node("node-a")
	if !ok || node.Geo != nil {
		t.Fatalf("geo not cleared: ok=%v node=%+v", ok, node)
	}
	if !auditActionSeen(st, "node.geo.update") || !auditActionSeen(st, "node.geo.clear") {
		t.Fatalf("missing geo audit events: %+v", st.AuditEvents())
	}
}

func TestNodeGeoValidationAndAllowlist(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	enrollNamedNode(t, handler, cookies, csrf, "node-b", "Node B")

	cases := []struct {
		name string
		body string
	}{
		{"missing coords", `{"node_id":"node-a","geo":{"country":"JP"}}`},
		{"bad latitude", `{"node_id":"node-a","geo":{"lat":91,"lon":139}}`},
		{"bad longitude", `{"node_id":"node-a","geo":{"lat":35,"lon":181}}`},
		{"bad country", `{"node_id":"node-a","geo":{"country":"JPN","lat":35,"lon":139}}`},
		{"bad asn", `{"node_id":"node-a","geo":{"lat":35,"lon":139,"asn":-1}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := doJSON(t, handler, http.MethodPost, "/api/nodes/geo", tc.body, cookies, csrf)
			res.Body.Close()
			if res.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected bad request, got %d", res.StatusCode)
			}
		})
	}

	tokenA := createPAT(t, handler, cookies, csrf, []string{"node:read", "node:admin"}, []string{"node-a"})
	denied := doBearerJSON(t, handler, http.MethodPost, "/api/nodes/geo", `{"node_id":"node-b","geo":{"lat":1,"lon":2}}`, tokenA)
	denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("allowlisted token must not update node-b geo, got %d", denied.StatusCode)
	}
	allowed := doBearerJSON(t, handler, http.MethodPost, "/api/nodes/geo", `{"node_id":"node-a","geo":{"country":"US","city":"San Francisco","lat":37.7749,"lon":-122.4194}}`, tokenA)
	allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("allowlisted token should update node-a geo, got %d", allowed.StatusCode)
	}
	list := doBearerJSON(t, handler, http.MethodGet, "/api/nodes/geo", "", tokenA)
	defer list.Body.Close()
	var out []nodeGeoView
	if err := json.NewDecoder(list.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].ID != "node-a" || out[0].Geo == nil || !strings.EqualFold(out[0].Geo.Country, "US") {
		t.Fatalf("geo list did not honor allowlist: %+v", out)
	}
}
