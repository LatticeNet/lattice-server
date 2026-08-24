package server

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// CodeMirror, and any editor like it, installs its layout and highlighting as
// stylesheets it creates at runtime. The plugin policy has no 'unsafe-inline',
// so every one of those was silently dropped and the editors rendered as
// unstyled text with no way to notice. A per-response nonce lets the document
// mount its own styles without opening the door to anything else.

var noncePattern = regexp.MustCompile(`'nonce-([A-Za-z0-9+/]{22})'`)

func activatePluginForAssets(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf string) {
	t.Helper()
	for _, status := range []string{"installed", "active"} {
		res := doJSON(t, handler, http.MethodPost, "/api/plugins/lifecycle", `{"id":"test.assets","status":"`+status+`"}`, cookies, csrf)
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("lifecycle %s status=%d", status, res.StatusCode)
		}
	}
}

func TestPluginEntrypointStyleNonceMatchesTheDocumentItServes(t *testing.T) {
	_, handler, cookies, csrf, base := newPluginAssetTestServerWithUI(t, map[string][]byte{
		"ui/index.html":                  []byte(`<!doctype html><meta name="lattice-csp-nonce" content="__LATTICE_CSP_NONCE__"><main>Plugin UI</main>`),
		"ui/assets/app.0123456789ab.css": []byte("main { display: block; }"),
		"ui/assets/app.0123456789ab.js":  []byte("globalThis.pluginLoaded = true"),
	})
	activatePluginForAssets(t, handler, cookies, csrf)

	res := doJSON(t, handler, http.MethodGet, base+"/ui/index.html", "", cookies, "")
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("entrypoint status=%d", res.StatusCode)
	}
	document := string(body)
	if strings.Contains(document, "__LATTICE_CSP_NONCE__") {
		t.Fatalf("the placeholder reached the browser: %q", document)
	}
	csp := res.Header.Get("Content-Security-Policy")
	match := noncePattern.FindStringSubmatch(csp)
	if match == nil {
		t.Fatalf("policy carries no style nonce: %q", csp)
	}
	// A nonce in the policy that the document does not carry is the same
	// failure as no nonce at all: the styles still never mount.
	if !strings.Contains(document, `content="`+match[1]+`"`) {
		t.Fatalf("the document does not carry the nonce the policy names: policy=%q document=%q", csp, document)
	}
	if !strings.Contains(csp, "style-src 'self' https://lattice.example.test 'nonce-"+match[1]+"'") {
		t.Fatalf("the nonce must extend style-src, not replace its sources: %q", csp)
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("a nonce must not be traded for unsafe-inline: %q", csp)
	}
	if got := res.Header.Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("a body unique to one response must not be stored: Cache-Control=%q", got)
	}

	// Two loads must not share a nonce, or one captured document would keep
	// working as an injection vehicle.
	second := doJSON(t, handler, http.MethodGet, base+"/ui/index.html", "", cookies, "")
	secondBody, _ := io.ReadAll(second.Body)
	second.Body.Close()
	secondMatch := noncePattern.FindStringSubmatch(second.Header.Get("Content-Security-Policy"))
	if secondMatch == nil || secondMatch[1] == match[1] {
		t.Fatalf("the nonce was reused across responses: %q then %q", match, secondMatch)
	}
	if strings.Contains(string(secondBody), match[1]) {
		t.Fatalf("the second document still carries the first nonce")
	}
}

func TestPluginEntrypointWithoutThePlaceholderIsUnchanged(t *testing.T) {
	_, handler, cookies, csrf, base := newPluginAssetTestServer(t)
	activatePluginForAssets(t, handler, cookies, csrf)

	res := doJSON(t, handler, http.MethodGet, base+"/ui/index.html", "", cookies, "")
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if got := string(body); got != "<!doctype html><main>Plugin UI</main>" {
		t.Fatalf("a document that asked for nothing was rewritten: %q", got)
	}
	csp := res.Header.Get("Content-Security-Policy")
	if strings.Contains(csp, "nonce-") {
		t.Fatalf("a policy gained a nonce no document can use: %q", csp)
	}
	if got := res.Header.Get("Cache-Control"); got != "private, no-cache, max-age=0, must-revalidate" {
		t.Fatalf("caching changed for a document that was not rewritten: %q", got)
	}
}

// The substitution is for the entrypoint alone. A content-hashed subresource is
// served with a year of immutable caching, so a nonce baked into one would be
// handed to every later load under a policy that no longer names it.
func TestPluginSubresourcesNeverReceiveANonce(t *testing.T) {
	const asset = "ui/assets/app.0123456789ab.js"
	_, handler, cookies, csrf, base := newPluginAssetTestServerWithUI(t, map[string][]byte{
		"ui/index.html":                  []byte(`<!doctype html><meta name="lattice-csp-nonce" content="__LATTICE_CSP_NONCE__">`),
		"ui/assets/app.0123456789ab.css": []byte("main { display: block; }"),
		asset:                            []byte(`const wanted = "__LATTICE_CSP_NONCE__";`),
	})
	activatePluginForAssets(t, handler, cookies, csrf)

	res := doJSON(t, handler, http.MethodGet, base+"/"+asset, "", nil, "")
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("subresource status=%d", res.StatusCode)
	}
	if got := string(body); got != `const wanted = "__LATTICE_CSP_NONCE__";` {
		t.Fatalf("a subresource was rewritten: %q", got)
	}
	if got := res.Header.Get("Cache-Control"); !strings.Contains(got, "immutable") {
		t.Fatalf("the fixture is wrong: this asset should be immutably cached, got %q", got)
	}
}
