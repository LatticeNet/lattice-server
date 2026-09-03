package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

type inventoryResponse struct {
	Buckets   []model.StorageBucket `json:"buckets"`
	Inventory []struct {
		Name       string `json:"name"`
		Kind       string `json:"kind"`
		Entries    int    `json:"entries"`
		Registered bool   `json:"registered"`
		Reserved   bool   `json:"reserved"`
	} `json:"inventory"`
}

func readInventory(t *testing.T, handler http.Handler, kind string, cookies []*http.Cookie, csrf string) inventoryResponse {
	t.Helper()
	resp := doJSON(t, handler, http.MethodGet, "/api/storage/buckets?kind="+kind, "", cookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list buckets: %d", resp.StatusCode)
	}
	var out inventoryResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// A bucket a plugin wrote into without registering it was invisible to the
// console, so a store holding real data reported itself empty. In production
// the sub-store plugin kept eighteen entries, several of them tens of
// kilobytes, in a bucket that appeared in no listing.
func TestStorageBucketsListUnregisteredBuckets(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	for _, key := range []string{"subscription-a", "subscription-b"} {
		if err := st.PutKV(model.KVEntry{Bucket: "plugin:latticenet.sub-store", Key: key, Value: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.PutKV(model.KVEntry{Bucket: "vpn_user_secrets", Key: "secret", Value: "z"}); err != nil {
		t.Fatal(err)
	}

	got := readInventory(t, handler, model.StorageKindKV, cookies, csrf)
	byName := map[string]int{}
	flags := map[string][2]bool{}
	for _, e := range got.Inventory {
		byName[e.Name] = e.Entries
		flags[e.Name] = [2]bool{e.Registered, e.Reserved}
	}

	if n, ok := byName["plugin:latticenet.sub-store"]; !ok || n != 2 {
		t.Fatalf("plugin bucket entries = %d present=%v, want 2 present, which is the bug this guards", n, ok)
	}
	if flags["plugin:latticenet.sub-store"][0] {
		t.Fatal("bucket was never registered, so it must not claim to be")
	}
	if _, ok := byName["vpn_user_secrets"]; !ok {
		t.Fatal("a reserved bucket must still be named, so the operator knows the space is taken")
	}
	if !flags["vpn_user_secrets"][1] {
		t.Fatal("vpn_user_secrets is reserved and must be marked, so its contents are not offered")
	}
}

// A registered bucket with nothing in it is still real: registering one and
// then not finding it would read as a failure.
func TestStorageBucketsKeepEmptyRegisteredBuckets(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	created := doJSON(t, handler, http.MethodPost, "/api/storage/buckets?kind=static",
		`{"name":"site","display_name":"Site"}`, cookies, csrf)
	created.Body.Close()
	if created.StatusCode != http.StatusOK {
		t.Fatalf("create bucket: %d", created.StatusCode)
	}

	for _, e := range readInventory(t, handler, model.StorageKindStatic, cookies, csrf).Inventory {
		if e.Name == "site" {
			if e.Entries != 0 || !e.Registered {
				t.Fatalf("registered empty bucket = %+v, want 0 entries and registered", e)
			}
			return
		}
	}
	t.Fatal("registered bucket missing from the inventory")
}
