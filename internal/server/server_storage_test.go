package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
