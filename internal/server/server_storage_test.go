package server

import (
	"bytes"
	"encoding/json"
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
