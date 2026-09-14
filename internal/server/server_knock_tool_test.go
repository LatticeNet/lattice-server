package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/knocktool"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func knockToolHandler(t *testing.T, publicURL string) http.Handler {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, PublicURL: publicURL, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	return srv.Handler()
}

func fetchKnockTool(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

// Public on purpose: an operator who cannot reach GitHub fetches the client
// with no session, and gets exactly the vendored release bytes.
func TestKnockToolServesTheClientWithoutASession(t *testing.T) {
	h := knockToolHandler(t, "https://lattice.example.com/")
	rec := fetchKnockTool(t, h, http.MethodGet, "/tools/knock/knock")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /tools/knock/knock: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != string(knocktool.Knock()) {
		t.Fatal("the served client is not the vendored release script")
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("a script must not be served as something a browser renders: %q", ct)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("nosniff missing")
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control: want no-store, as /install.sh sends, got %q", cc)
	}
	sums := fetchKnockTool(t, h, http.MethodGet, "/tools/knock/SHA256SUMS")
	if sums.Code != http.StatusOK || sums.Body.String() != knocktool.KnockSHA256()+"  knock\n" {
		t.Fatalf("SHA256SUMS: %d %q", sums.Code, sums.Body.String())
	}
}

// The install one-liner needs no arguments from a server that knows its public
// URL: the script it hands out already names this control plane and pins the
// client's checksum.
func TestKnockToolInstallScriptPointsAtThisControlPlane(t *testing.T) {
	rec := fetchKnockTool(t, knockToolHandler(t, "https://lattice.example.com/"), http.MethodGet, "/tools/knock/install.sh")
	body := rec.Body.String()
	if rec.Code != http.StatusOK ||
		!strings.Contains(body, `server="${KNOCK_SERVER:-https://lattice.example.com}"`) ||
		!strings.Contains(body, `pin="${KNOCK_SHA256:-`+knocktool.KnockSHA256()+`}"`) {
		t.Fatalf("install.sh does not default to this control plane and the pinned checksum: %d\n%s", rec.Code, body)
	}
	bare := fetchKnockTool(t, knockToolHandler(t, ""), http.MethodGet, "/tools/knock/install.sh")
	if bare.Code != http.StatusOK || bare.Body.String() != string(knocktool.UnrenderedInstallScript()) {
		t.Fatalf("without a public URL the script must be served as released: %d", bare.Code)
	}
}

func TestKnockToolRefusesOtherMethodsAndPaths(t *testing.T) {
	h := knockToolHandler(t, "https://lattice.example.com")
	if rec := fetchKnockTool(t, h, http.MethodPost, "/tools/knock/knock"); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: want 405, got %d", rec.Code)
	}
	head := fetchKnockTool(t, h, http.MethodHead, "/tools/knock/knock")
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD: want 200 with no body, got %d with %d bytes", head.Code, head.Body.Len())
	}
	for _, p := range []string{"/tools/knock/", "/tools/knock/knock.conf", "/tools/knock/../knock", "/tools/knock/sub/knock"} {
		rec := fetchKnockTool(t, h, http.MethodGet, p)
		if rec.Code == http.StatusOK {
			t.Fatalf("%s: must not be served, got 200 with %d bytes", p, rec.Body.Len())
		}
	}
}

// The reveal is where an operator on a network without GitHub looks for the
// client, so the server's public URL has to reach it through the handler, not
// only through the renderer's own test.
func TestKnockRevealOffersThisControlPlaneFirst(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, PublicURL: "https://lattice.example.com/", DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	seedAgentUpdateNode(t, st)
	enrolSSHGuard(t, st, "node-a")
	seedArmApproval(t, st, "approval_arm", "node-a", model.ApprovalApplied, knockTestPorts, time.Now().UTC())
	cookies, csrf := loginSession(t, handler)
	grant := issueStepUpGrant(t, handler, cookies, csrf)

	res := doJSON(t, handler, http.MethodPost, "/api/sshguard/knock/reveal",
		`{"node_id":"node-a","step_up_grant":"`+grant+`"}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("reveal: want 200, got %d (%s)", res.StatusCode, raw)
	}
	var out struct {
		Commands []struct {
			ID      string `json:"id"`
			Install []struct {
				Platform string `json:"platform"`
				Command  string `json:"command"`
			} `json:"install"`
		} `json:"commands"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Commands) == 0 || out.Commands[0].ID != "knock" || len(out.Commands[0].Install) < 2 {
		t.Fatalf("the reveal must open with the knock client and its install lines: %+v", out.Commands)
	}
	first, second := out.Commands[0].Install[0], out.Commands[0].Install[1]
	if first.Platform != "This control plane" || first.Command != "curl -fsSL https://lattice.example.com/tools/knock/install.sh | sh" {
		t.Fatalf("the first install line must be this control plane: %+v", first)
	}
	if second.Platform != "GitHub" {
		t.Fatalf("GitHub must follow the control plane: %+v", second)
	}
}
