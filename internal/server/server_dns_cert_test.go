package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

type measureCertAnswer struct {
	Deployment struct {
		ID         string             `json:"id"`
		CertChecks []dnsCertCheckView `json:"cert_checks"`
		CertExpiry *dnsCertExpiryView `json:"cert_expiry"`
	} `json:"deployment"`
	Created []string `json:"created"`
	Linked  []string `json:"linked"`
}

func measureCert(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, body string) measureCertAnswer {
	t.Helper()
	code, raw := postBody(t, handler, "/api/dns/measure-cert", body, cookies, csrf)
	if code != http.StatusOK {
		t.Fatalf("measure %s = %d %s", body, code, raw)
	}
	var out measureCertAnswer
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func tlsMonitorsOf(st *store.Store) []model.Monitor {
	var out []model.Monitor
	for _, mon := range st.Monitors() {
		if mon.Type == model.MonitorTypeTLS {
			out = append(out, mon)
		}
	}
	return out
}

// Design 32 S5c: "Measure this certificate" creates one tls check per named
// listener, an ordinary operator check named after the deployment, links an
// existing check on the same endpoint instead of duplicating it, and the
// sheet then prefers the measured expiry over the typed one and says which
// it shows.
func TestDNSMeasureCertCreatesOneTLSCheckPerListener(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	seedNodeListeners(t, st, "n1", dnsproxyListeners())
	dep := createExternalDNS(t, handler, cookies, csrf)
	typed := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)

	// The operator already watches one of the endpoints by hand.
	code, body := postBody(t, handler, "/api/monitors", `{"name":"doh by hand","type":"tls","target":"DNS.roobli.org:2053"}`, cookies, csrf)
	if code != http.StatusOK {
		t.Fatalf("hand-made tls check: %d %s", code, body)
	}
	var byHand model.Monitor
	if err := json.Unmarshal([]byte(body), &byHand); err != nil {
		t.Fatal(err)
	}

	got := measureCert(t, handler, cookies, csrf, `{"id":"`+dep.ID+`","ports":[8443,2053,8443]}`)
	if len(got.Created) != 1 || !slices.Equal(got.Linked, []string{byHand.ID}) {
		t.Fatalf("want one check created and the hand-made one linked, got created %v linked %v", got.Created, got.Linked)
	}
	created, ok := st.Monitor(got.Created[0])
	if !ok || created.Target != "dns.roobli.org:8443" || created.ManagedBy != "" || created.CheckDefinitionID != "" ||
		created.AssignAll || len(created.NodeIDs) != 0 || !created.Enabled || created.ThresholdDays != tlsMonitorDefaultThresholdDays ||
		!strings.Contains(created.Name, "operator dnsproxy") {
		t.Fatalf("the created check is an ordinary tls check named after the deployment: %+v", created)
	}
	if len(got.Deployment.CertChecks) != 2 {
		t.Fatalf("both checks are linked: %+v", got.Deployment.CertChecks)
	}
	if e := got.Deployment.CertExpiry; e == nil || e.Source != dnsCertSourceTyped || !e.NotAfter.Equal(typed) {
		t.Fatalf("before any measurement the sheet shows the typed date and says so: %+v", e)
	}

	// Measuring again creates nothing.
	again := measureCert(t, handler, cookies, csrf, `{"id":"`+dep.ID+`","ports":[2053,8443]}`)
	if len(again.Created) != 0 || len(again.Linked) != 2 || len(tlsMonitorsOf(st)) != 2 {
		t.Fatalf("a second measure duplicated a check: %+v, %d tls checks", again, len(tlsMonitorsOf(st)))
	}

	// A measurement later than the typed date still wins: the sheet shows
	// what the endpoint presents, not the sooner of the two.
	measured := time.Date(2027, 1, 20, 0, 0, 0, 0, time.UTC)
	if _, err := st.AddMonitorResult(model.MonitorResult{MonitorID: created.ID, At: time.Now().UTC(), Success: true, CertNotAfter: measured}); err != nil {
		t.Fatal(err)
	}
	// An operator save of the record keeps the link.
	edit := strings.Replace(externalDNSBody, `"name":"operator dnsproxy",`, `"id":"`+dep.ID+`","name":"operator dnsproxy",`, 1)
	if code, body := postBody(t, handler, "/api/dns/deployments", edit, cookies, csrf); code != http.StatusOK {
		t.Fatalf("edit: %d %s", code, body)
	}
	view := externalView(t, handler, cookies, csrf, dep.ID)
	if e := view.CertExpiry; e == nil || e.Source != dnsCertSourceMeasured || !e.NotAfter.Equal(measured) || e.MonitorID != created.ID {
		t.Fatalf("the sheet prefers the measured expiry: %+v", e)
	}
	if len(view.CertChecks) != 2 {
		t.Fatalf("the edit dropped the link: %+v", view.CertChecks)
	}

	// Deleting a check unlinks it.
	if code, body := postBody(t, handler, "/api/monitors/delete", `{"id":"`+created.ID+`"}`, cookies, csrf); code != http.StatusOK {
		t.Fatalf("delete: %d %s", code, body)
	}
	view = externalView(t, handler, cookies, csrf, dep.ID)
	if len(view.CertChecks) != 1 || view.CertChecks[0].MonitorID != byHand.ID {
		t.Fatalf("a deleted check is skipped: %+v", view.CertChecks)
	}
	if e := view.CertExpiry; e == nil || e.Source != dnsCertSourceTyped {
		t.Fatalf("with no measurement left the sheet falls back to the typed date: %+v", e)
	}
}

type externalCertView struct {
	ID         string             `json:"id"`
	CertChecks []dnsCertCheckView `json:"cert_checks"`
	CertExpiry *dnsCertExpiryView `json:"cert_expiry"`
}

func externalView(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, id string) externalCertView {
	t.Helper()
	res := doJSON(t, handler, http.MethodGet, "/api/dns/deployments", "", cookies, csrf)
	defer res.Body.Close()
	var listed struct {
		Deployments []externalCertView `json:"deployments"`
	}
	if err := json.NewDecoder(res.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	for _, v := range listed.Deployments {
		if v.ID == id {
			return v
		}
	}
	t.Fatalf("deployment %s not listed", id)
	return externalCertView{}
}

// The action names its refusals: no ports, a port the record does not list
// as tcp, a CoreDNS deployment, and a token that may not create a
// server-evaluated check. Nothing is created by any of them.
func TestDNSMeasureCertRefusals(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	seedNodeListeners(t, st, "n1", dnsproxyListeners())
	dep := createExternalDNS(t, handler, cookies, csrf)
	core := createDNSDeployment(t, handler, cookies, csrf)

	for _, tc := range []struct {
		body  string
		code  int
		field string
		says  string
	}{
		{`{"id":"` + dep.ID + `"}`, http.StatusBadRequest, "ports", "not which of them speak TLS"},
		{`{"id":"` + dep.ID + `","ports":[8443,9999]}`, http.StatusBadRequest, "ports[1]", "tcp/9999 is not a recorded listener"},
		{`{"id":"` + dep.ID + `","ports":[8443],"threshold_days":9999}`, http.StatusBadRequest, "threshold_days", "threshold_days"},
		{`{"id":"` + core + `","ports":[53]}`, http.StatusBadRequest, "id", "only an external engine"},
		{`{"id":"dns_missing","ports":[53]}`, http.StatusNotFound, "", "not found"},
	} {
		code, body := postBody(t, handler, "/api/dns/measure-cert", tc.body, cookies, csrf)
		refusal := apiErrorOf(t, body)
		if code != tc.code || refusal.Field != tc.field || !strings.Contains(refusal.Message, tc.says) {
			t.Fatalf("%s = %d %s, want %d on %q saying %q", tc.body, code, body, tc.code, tc.field, tc.says)
		}
	}

	token := createPAT(t, handler, cookies, csrf, []string{"dns:admin", "monitor:admin", "monitor:read"}, []string{"n1"})
	res := doBearerJSON(t, handler, http.MethodPost, "/api/dns/measure-cert", `{"id":"`+dep.ID+`","ports":[8443]}`, token)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a node-confined token = %d, want 403", res.StatusCode)
	}
	if n := len(tlsMonitorsOf(st)); n != 0 {
		t.Fatalf("a refused measure created %d checks", n)
	}
}
