package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestKVStorageBindingTokenReadWrite(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	createBucket := doJSON(t, handler, http.MethodPost, "/api/storage/buckets?kind=kv",
		`{"name":"cfg","display_name":"Config"}`, cookies, csrf)
	createBucket.Body.Close()
	if createBucket.StatusCode != http.StatusOK {
		t.Fatalf("create kv bucket failed: %d", createBucket.StatusCode)
	}

	createBinding := doJSON(t, handler, http.MethodPost, "/api/storage/bindings?kind=kv",
		`{"bucket":"cfg","hostname":"kv.example.com"}`, cookies, csrf)
	createBinding.Body.Close()
	if createBinding.StatusCode != http.StatusOK {
		t.Fatalf("create kv binding failed: %d", createBinding.StatusCode)
	}

	createToken := doJSON(t, handler, http.MethodPost, "/api/storage/tokens?kind=kv",
		`{"name":"ci","access":"admin","buckets":["cfg"]}`, cookies, csrf)
	defer createToken.Body.Close()
	if createToken.StatusCode != http.StatusOK {
		t.Fatalf("create kv token failed: %d", createToken.StatusCode)
	}
	var tokenOut struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(createToken.Body).Decode(&tokenOut); err != nil {
		t.Fatal(err)
	}
	if tokenOut.Token == "" {
		t.Fatal("storage token not returned")
	}

	put := httptest.NewRequest(http.MethodPut, "http://kv.example.com/site-title", bytes.NewBufferString(`{"value":"Lattice"}`))
	put.Header.Set("Authorization", "Bearer "+tokenOut.Token)
	put.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	handler.ServeHTTP(putRec, put)
	if putRec.Code != http.StatusOK {
		t.Fatalf("kv binding put failed: %d %s", putRec.Code, putRec.Body.String())
	}

	get := httptest.NewRequest(http.MethodGet, "http://kv.example.com/site-title", nil)
	get.Header.Set("Authorization", "Bearer "+tokenOut.Token)
	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, get)
	if getRec.Code != http.StatusOK || !strings.Contains(getRec.Body.String(), `"value":"Lattice"`) {
		t.Fatalf("kv binding get failed: %d %s", getRec.Code, getRec.Body.String())
	}
}

func TestStaticStorageBindingServesSite(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	createBucket := doJSON(t, handler, http.MethodPost, "/api/storage/buckets?kind=static",
		`{"name":"site","index_document":"index.html","not_found_document":"404.html"}`, cookies, csrf)
	createBucket.Body.Close()
	if createBucket.StatusCode != http.StatusOK {
		t.Fatalf("create static bucket failed: %d", createBucket.StatusCode)
	}
	putIndex := doJSON(t, handler, http.MethodPost, "/api/static",
		`{"bucket":"site","path":"index.html","content":"<h1>Hello</h1>","content_type":"text/html"}`, cookies, csrf)
	putIndex.Body.Close()
	if putIndex.StatusCode != http.StatusOK {
		t.Fatalf("put static index failed: %d", putIndex.StatusCode)
	}
	createBinding := doJSON(t, handler, http.MethodPost, "/api/storage/bindings?kind=static",
		`{"bucket":"site","hostname":"static.example.com"}`, cookies, csrf)
	createBinding.Body.Close()
	if createBinding.StatusCode != http.StatusOK {
		t.Fatalf("create static binding failed: %d", createBinding.StatusCode)
	}

	req := httptest.NewRequest(http.MethodGet, "http://static.example.com/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("static binding get failed: %d", rec.Code)
	}
	if got := rec.Body.String(); got != "<h1>Hello</h1>" {
		t.Fatalf("unexpected static body: %q", got)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html" {
		t.Fatalf("unexpected content type: %q", ct)
	}
}

func TestStorageTokenRequiresExplicitBuckets(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	createToken := doJSON(t, handler, http.MethodPost, "/api/storage/tokens?kind=kv",
		`{"name":"wide","access":"read","buckets":[]}`, cookies, csrf)
	defer createToken.Body.Close()
	if createToken.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected empty token buckets to be rejected, got %d", createToken.StatusCode)
	}
}

func TestStorageBindingDeleteChecksObjectKind(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	createBucket := doJSON(t, handler, http.MethodPost, "/api/storage/buckets?kind=static",
		`{"name":"site","index_document":"index.html"}`, cookies, csrf)
	createBucket.Body.Close()
	if createBucket.StatusCode != http.StatusOK {
		t.Fatalf("create static bucket failed: %d", createBucket.StatusCode)
	}
	putIndex := doJSON(t, handler, http.MethodPost, "/api/static",
		`{"bucket":"site","path":"index.html","content":"ok","content_type":"text/plain"}`, cookies, csrf)
	putIndex.Body.Close()
	if putIndex.StatusCode != http.StatusOK {
		t.Fatalf("put static index failed: %d", putIndex.StatusCode)
	}
	createBinding := doJSON(t, handler, http.MethodPost, "/api/storage/bindings?kind=static",
		`{"bucket":"site","hostname":"static.example.com"}`, cookies, csrf)
	defer createBinding.Body.Close()
	if createBinding.StatusCode != http.StatusOK {
		t.Fatalf("create static binding failed: %d", createBinding.StatusCode)
	}
	var binding struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createBinding.Body).Decode(&binding); err != nil {
		t.Fatal(err)
	}

	kvAdmin := createPAT(t, handler, cookies, csrf, []string{"kv:admin"}, nil)
	deleteAsKV := doBearerJSON(t, handler, http.MethodPost, "/api/storage/bindings/delete",
		`{"kind":"kv","id":"`+binding.ID+`"}`, kvAdmin)
	deleteAsKV.Body.Close()
	if deleteAsKV.StatusCode != http.StatusNotFound {
		t.Fatalf("expected cross-kind binding delete to be hidden, got %d", deleteAsKV.StatusCode)
	}

	req := httptest.NewRequest(http.MethodGet, "http://static.example.com/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("static binding was deleted across kind boundary: %d %q", rec.Code, rec.Body.String())
	}
}

func TestStorageTokenRevokeChecksObjectKindBeforeMutation(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	createBucket := doJSON(t, handler, http.MethodPost, "/api/storage/buckets?kind=static",
		`{"name":"site","index_document":"index.html"}`, cookies, csrf)
	createBucket.Body.Close()
	if createBucket.StatusCode != http.StatusOK {
		t.Fatalf("create static bucket failed: %d", createBucket.StatusCode)
	}
	createToken := doJSON(t, handler, http.MethodPost, "/api/storage/tokens?kind=static",
		`{"name":"publisher","access":"write","buckets":["site"]}`, cookies, csrf)
	defer createToken.Body.Close()
	if createToken.StatusCode != http.StatusOK {
		t.Fatalf("create static token failed: %d", createToken.StatusCode)
	}
	var token struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createToken.Body).Decode(&token); err != nil {
		t.Fatal(err)
	}

	kvAdmin := createPAT(t, handler, cookies, csrf, []string{"kv:admin"}, nil)
	revokeAsKV := doBearerJSON(t, handler, http.MethodPost, "/api/storage/tokens/revoke",
		`{"kind":"kv","token_id":"`+token.ID+`"}`, kvAdmin)
	revokeAsKV.Body.Close()
	if revokeAsKV.StatusCode != http.StatusNotFound {
		t.Fatalf("expected cross-kind token revoke to be hidden, got %d", revokeAsKV.StatusCode)
	}

	list := doJSON(t, handler, http.MethodGet, "/api/storage/tokens?kind=static", "", cookies, csrf)
	defer list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list static tokens failed: %d", list.StatusCode)
	}
	var out struct {
		Tokens []struct {
			ID        string    `json:"id"`
			RevokedAt time.Time `json:"revoked_at"`
		} `json:"tokens"`
	}
	if err := json.NewDecoder(list.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	for _, visible := range out.Tokens {
		if visible.ID == token.ID {
			if !visible.RevokedAt.IsZero() {
				t.Fatalf("cross-kind revoke mutated static token: %+v", visible)
			}
			return
		}
	}
	t.Fatalf("static token %q missing from list: %+v", token.ID, out.Tokens)
}

func TestStorageHostBindingsSelectByPathPrefix(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	createStaticBucket := doJSON(t, handler, http.MethodPost, "/api/storage/buckets?kind=static",
		`{"name":"site","index_document":"index.html"}`, cookies, csrf)
	createStaticBucket.Body.Close()
	if createStaticBucket.StatusCode != http.StatusOK {
		t.Fatalf("create static bucket failed: %d", createStaticBucket.StatusCode)
	}
	putIndex := doJSON(t, handler, http.MethodPost, "/api/static",
		`{"bucket":"site","path":"index.html","content":"home","content_type":"text/plain"}`, cookies, csrf)
	putIndex.Body.Close()
	if putIndex.StatusCode != http.StatusOK {
		t.Fatalf("put static index failed: %d", putIndex.StatusCode)
	}
	staticBinding := doJSON(t, handler, http.MethodPost, "/api/storage/bindings?kind=static",
		`{"bucket":"site","hostname":"edge.example.com"}`, cookies, csrf)
	staticBinding.Body.Close()
	if staticBinding.StatusCode != http.StatusOK {
		t.Fatalf("create static binding failed: %d", staticBinding.StatusCode)
	}

	createKVBucket := doJSON(t, handler, http.MethodPost, "/api/storage/buckets?kind=kv",
		`{"name":"cfg"}`, cookies, csrf)
	createKVBucket.Body.Close()
	if createKVBucket.StatusCode != http.StatusOK {
		t.Fatalf("create kv bucket failed: %d", createKVBucket.StatusCode)
	}
	kvBinding := doJSON(t, handler, http.MethodPost, "/api/storage/bindings?kind=kv",
		`{"bucket":"cfg","hostname":"edge.example.com","path_prefix":"kv"}`, cookies, csrf)
	kvBinding.Body.Close()
	if kvBinding.StatusCode != http.StatusOK {
		t.Fatalf("create kv binding failed: %d", kvBinding.StatusCode)
	}
	createToken := doJSON(t, handler, http.MethodPost, "/api/storage/tokens?kind=kv",
		`{"name":"ci","access":"admin","buckets":["cfg"]}`, cookies, csrf)
	defer createToken.Body.Close()
	if createToken.StatusCode != http.StatusOK {
		t.Fatalf("create kv token failed: %d", createToken.StatusCode)
	}
	var tokenOut struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(createToken.Body).Decode(&tokenOut); err != nil {
		t.Fatal(err)
	}

	root := httptest.NewRequest(http.MethodGet, "http://edge.example.com/", nil)
	rootRec := httptest.NewRecorder()
	handler.ServeHTTP(rootRec, root)
	if rootRec.Code != http.StatusOK || rootRec.Body.String() != "home" {
		t.Fatalf("root should route to static binding, got %d %q", rootRec.Code, rootRec.Body.String())
	}

	put := httptest.NewRequest(http.MethodPut, "http://edge.example.com/kv/site-title", bytes.NewBufferString(`{"value":"Lattice"}`))
	put.Header.Set("Authorization", "Bearer "+tokenOut.Token)
	put.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	handler.ServeHTTP(putRec, put)
	if putRec.Code != http.StatusOK {
		t.Fatalf("prefixed kv binding put failed: %d %s", putRec.Code, putRec.Body.String())
	}
}

func TestStorageBindingRejectsDuplicateRoute(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	createBucket := doJSON(t, handler, http.MethodPost, "/api/storage/buckets?kind=static",
		`{"name":"site","index_document":"index.html"}`, cookies, csrf)
	createBucket.Body.Close()
	if createBucket.StatusCode != http.StatusOK {
		t.Fatalf("create static bucket failed: %d", createBucket.StatusCode)
	}
	first := doJSON(t, handler, http.MethodPost, "/api/storage/bindings?kind=static",
		`{"bucket":"site","hostname":"static.example.com","path_prefix":"docs"}`, cookies, csrf)
	first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("create static binding failed: %d", first.StatusCode)
	}
	duplicate := doJSON(t, handler, http.MethodPost, "/api/storage/bindings?kind=static",
		`{"bucket":"site","hostname":"STATIC.example.com","path_prefix":"/docs/"}`, cookies, csrf)
	duplicate.Body.Close()
	if duplicate.StatusCode != http.StatusConflict {
		t.Fatalf("expected duplicate binding route to be rejected, got %d", duplicate.StatusCode)
	}
}

// A demo written through the console surface must be removable through the
// same surface, or every demo is a permanent write into production.
func TestKVAndStaticEntriesDeleteThroughTheConsoleSurface(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	put := doJSON(t, handler, http.MethodPost, "/api/kv",
		`{"bucket":"demo","key":"greeting","value":"hello"}`, cookies, csrf)
	put.Body.Close()
	if put.StatusCode != http.StatusOK {
		t.Fatalf("kv put failed: %d", put.StatusCode)
	}
	del := doJSON(t, handler, http.MethodPost, "/api/kv/delete", `{"bucket":"demo","key":"greeting"}`, cookies, csrf)
	del.Body.Close()
	if del.StatusCode != http.StatusOK {
		t.Fatalf("kv delete answered %d, want 200", del.StatusCode)
	}
	list := doJSON(t, handler, http.MethodGet, "/api/kv?bucket=demo", "", cookies, csrf)
	defer list.Body.Close()
	body, _ := io.ReadAll(list.Body)
	if strings.Contains(string(body), "greeting") {
		t.Fatalf("kv entry still listed after delete: %s", body)
	}
	again := doJSON(t, handler, http.MethodPost, "/api/kv/delete", `{"bucket":"demo","key":"greeting"}`, cookies, csrf)
	again.Body.Close()
	if again.StatusCode != http.StatusNotFound {
		t.Fatalf("deleting a missing kv entry answered %d, want 404", again.StatusCode)
	}
	reserved := doJSON(t, handler, http.MethodPost, "/api/kv/delete", `{"bucket":"vpn_users","key":"x"}`, cookies, csrf)
	reserved.Body.Close()
	if reserved.StatusCode != http.StatusForbidden {
		t.Fatalf("deleting from a reserved kv bucket answered %d, want 403", reserved.StatusCode)
	}

	putObj := doJSON(t, handler, http.MethodPost, "/api/static",
		`{"bucket":"demo","path":"index.html","content":"<h1>hi</h1>","content_type":"text/html"}`, cookies, csrf)
	putObj.Body.Close()
	if putObj.StatusCode != http.StatusOK {
		t.Fatalf("static put failed: %d", putObj.StatusCode)
	}
	delObj := doJSON(t, handler, http.MethodPost, "/api/static/delete", `{"bucket":"demo","path":"/index.html"}`, cookies, csrf)
	delObj.Body.Close()
	if delObj.StatusCode != http.StatusOK {
		t.Fatalf("static delete answered %d, want 200", delObj.StatusCode)
	}
	listObj := doJSON(t, handler, http.MethodGet, "/api/static?bucket=demo", "", cookies, csrf)
	defer listObj.Body.Close()
	body, _ = io.ReadAll(listObj.Body)
	if strings.Contains(string(body), "index.html") {
		t.Fatalf("static object still listed after delete: %s", body)
	}
	againObj := doJSON(t, handler, http.MethodPost, "/api/static/delete", `{"bucket":"demo","path":"index.html"}`, cookies, csrf)
	againObj.Body.Close()
	if againObj.StatusCode != http.StatusNotFound {
		t.Fatalf("deleting a missing static object answered %d, want 404", againObj.StatusCode)
	}
}

// Deleting is a write. A reader must be refused by the scope gate before the
// handler looks at the body.
func TestKVAndStaticDeleteNeedTheWriteScope(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	put := doJSON(t, handler, http.MethodPost, "/api/kv",
		`{"bucket":"demo","key":"greeting","value":"hello"}`, cookies, csrf)
	put.Body.Close()
	if put.StatusCode != http.StatusOK {
		t.Fatalf("kv put failed: %d", put.StatusCode)
	}
	putObj := doJSON(t, handler, http.MethodPost, "/api/static",
		`{"bucket":"demo","path":"index.html","content":"<h1>hi</h1>","content_type":"text/html"}`, cookies, csrf)
	putObj.Body.Close()
	if putObj.StatusCode != http.StatusOK {
		t.Fatalf("static put failed: %d", putObj.StatusCode)
	}
	reader := createPAT(t, handler, cookies, csrf, []string{"kv:read", "static:read"}, nil)
	for _, tc := range []struct{ path, body string }{
		{"/api/kv/delete", `{"bucket":"demo","key":"greeting"}`},
		{"/api/static/delete", `{"bucket":"demo","path":"index.html"}`},
	} {
		res := doBearerJSON(t, handler, http.MethodPost, tc.path, tc.body, reader)
		res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("%s with a read-only token answered %d, want 403", tc.path, res.StatusCode)
		}
	}
	list := doJSON(t, handler, http.MethodGet, "/api/kv?bucket=demo", "", cookies, csrf)
	defer list.Body.Close()
	body, _ := io.ReadAll(list.Body)
	if !strings.Contains(string(body), "greeting") {
		t.Fatal("a refused kv delete must leave the entry in place")
	}
	listObj := doJSON(t, handler, http.MethodGet, "/api/static?bucket=demo", "", cookies, csrf)
	defer listObj.Body.Close()
	body, _ = io.ReadAll(listObj.Body)
	if !strings.Contains(string(body), "index.html") {
		t.Fatal("a refused static delete must leave the object in place")
	}
}
