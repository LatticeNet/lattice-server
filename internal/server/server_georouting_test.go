package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func seedGeoNode(t *testing.T, st interface {
	UpsertNode(model.Node) error
}, id, ip string, lat, lon float64) {
	t.Helper()
	if err := st.UpsertNode(model.Node{
		ID: id, Name: id, Online: true, PublicIP: ip,
		Geo: &model.NodeGeo{Lat: lat, Lon: lon},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestGeoRoutingCreateListPlanDelete(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	seedGeoNode(t, st, "eu1", "192.0.2.1", 50.1, 8.7)
	seedGeoNode(t, st, "as1", "192.0.2.2", 35.7, 139.7)
	seedGeoNode(t, st, "na1", "192.0.2.3", 39.0, -77.5)
	_ = srv
	cookies, csrf := loginSession(t, handler)

	create := doJSON(t, handler, http.MethodPost, "/api/geo-routing", `{
		"name":"roobli dns",
		"hostname":"dns.roobli.org",
		"node_ids":["eu1","as1","na1"],
		"dns_node_ids":["eu1"]
	}`, cookies, csrf)
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create: %d", create.StatusCode)
	}
	var gr model.GeoRouting
	json.NewDecoder(create.Body).Decode(&gr)
	create.Body.Close()
	if gr.ID == "" || gr.Strategy != model.GeoRoutingStrategyGeoIP || gr.TTL != 60 {
		t.Fatalf("unexpected record: %+v", gr)
	}

	list := doJSON(t, handler, http.MethodGet, "/api/geo-routing", "", cookies, csrf)
	var lr struct {
		GeoRoutings []model.GeoRouting `json:"geo_routings"`
	}
	json.NewDecoder(list.Body).Decode(&lr)
	list.Body.Close()
	if len(lr.GeoRoutings) != 1 {
		t.Fatalf("expected 1 record, got %d", len(lr.GeoRoutings))
	}

	plan := doJSON(t, handler, http.MethodPost, "/api/geo-routing/plan", `{"id":"`+gr.ID+`"}`, cookies, csrf)
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("plan: %d", plan.StatusCode)
	}
	var pv geoRoutingPlanView
	json.NewDecoder(plan.Body).Decode(&pv)
	plan.Body.Close()
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		if !strings.Contains(pv.Config, ip) {
			t.Fatalf("plan config missing %s:\n%s", ip, pv.Config)
		}
	}
	if !strings.Contains(pv.Config, "geoip ") || pv.SHA256 == "" {
		t.Fatalf("plan should be geoip + have a sha:\n%s", pv.Config)
	}
	if pv.ContinentChoice["EU"] != "eu1" || pv.ContinentChoice["AS"] != "as1" {
		t.Fatalf("unexpected continent choices: %+v", pv.ContinentChoice)
	}

	del := doJSON(t, handler, http.MethodPost, "/api/geo-routing/delete", `{"id":"`+gr.ID+`"}`, cookies, csrf)
	if del.StatusCode != http.StatusOK {
		t.Fatalf("delete: %d", del.StatusCode)
	}
	del.Body.Close()
	list2 := doJSON(t, handler, http.MethodGet, "/api/geo-routing", "", cookies, csrf)
	var lr2 struct {
		GeoRoutings []model.GeoRouting `json:"geo_routings"`
	}
	json.NewDecoder(list2.Body).Decode(&lr2)
	list2.Body.Close()
	if len(lr2.GeoRoutings) != 0 {
		t.Fatalf("expected empty after delete, got %d", len(lr2.GeoRoutings))
	}
}

func TestGeoRoutingAdminOnlyPATCanWriteButNotRead(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedGeoNode(t, st, "eu1", "192.0.2.1", 50.1, 8.7)
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"geo:admin"}, nil)

	create := doBearerJSON(t, handler, http.MethodPost, "/api/geo-routing", `{
		"name":"admin only",
		"hostname":"geo.roobli.org",
		"node_ids":["eu1"],
		"dns_node_ids":["eu1"]
	}`, token)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("geo:admin-only token should create geo-routing, got %d", create.StatusCode)
	}

	list := doBearerJSON(t, handler, http.MethodGet, "/api/geo-routing", "", token)
	defer list.Body.Close()
	if list.StatusCode != http.StatusForbidden {
		t.Fatalf("geo:admin-only token should not read geo-routing list, got %d", list.StatusCode)
	}
}

func TestGeoRoutingValidation(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedGeoNode(t, st, "eu1", "192.0.2.1", 50, 8)
	cookies, csrf := loginSession(t, handler)
	bad := []string{
		`{"hostname":"dns.roobli.org","node_ids":["eu1"],"dns_node_ids":["eu1"]}`,             // no name
		`{"name":"x","hostname":"bad host","node_ids":["eu1"],"dns_node_ids":["eu1"]}`,        // bad hostname
		`{"name":"x","hostname":"dns.roobli.org","node_ids":["nope"],"dns_node_ids":["eu1"]}`, // missing node
		`{"name":"x","hostname":"dns.roobli.org","node_ids":["eu1"],"dns_node_ids":[]}`,       // no dns node
		`{"name":"x","hostname":"dns.roobli.org","strategy":"weird","node_ids":["eu1"],"dns_node_ids":["eu1"]}`,
		`{"name":"x","hostname":"dns.roobli.org","node_ids":["eu1"],"dns_node_ids":["eu1"],"geoip_db_path":"relative/path"}`,
	}
	for i, body := range bad {
		res := doJSON(t, handler, http.MethodPost, "/api/geo-routing", body, cookies, csrf)
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("case %d should be 400, got %d", i, res.StatusCode)
		}
		res.Body.Close()
	}
}

func TestTouchGeoRoutingsForNodeFlagsDependents(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	if err := st.UpsertGeoRouting(model.GeoRouting{ID: "gr1", Name: "x", Hostname: "dns.roobli.org", NodeIDs: []string{"eu1"}, DNSNodeIDs: []string{"eu1"}, Status: "configured"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertGeoRouting(model.GeoRouting{ID: "gr2", Name: "y", Hostname: "x.roobli.org", NodeIDs: []string{"as1"}, DNSNodeIDs: []string{"as1"}, Status: "configured"}); err != nil {
		t.Fatal(err)
	}
	srv.touchGeoRoutingsForNode("eu1")
	if gr, _ := st.GeoRouting("gr1"); gr.Status != geoRoutingStatusNodeChanged {
		t.Fatalf("gr1 should be flagged, got %q", gr.Status)
	}
	if gr, _ := st.GeoRouting("gr2"); gr.Status != "configured" {
		t.Fatalf("gr2 (unrelated node) must not be flagged, got %q", gr.Status)
	}
	// Idempotent: a second touch does not bump UpdatedAt.
	before, _ := st.GeoRouting("gr1")
	srv.touchGeoRoutingsForNode("eu1")
	after, _ := st.GeoRouting("gr1")
	if !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatal("already-flagged record must not be re-written")
	}
}
