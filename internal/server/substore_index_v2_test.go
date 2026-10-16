package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// putSubStoreRecords writes Sub-Store records into the plugin's KV in the
// split layout the plugin uses since 0.17.0-alpha.2: one index entry per
// record (subscriptions-index-v2) and each record's own document under
// record-v2-<escaped id>. doc is a {"records":[...]} list in the record
// shape. A doc that does not decode, or one over the read bound, is written
// as the index itself, which is how a test makes the index unreadable.
func putSubStoreRecords(t testing.TB, st *store.Store, doc string) {
	t.Helper()
	var parsed struct {
		Records []map[string]any `json:"records"`
	}
	if len(doc) > usageMaxSubStoreRecordsLen || json.Unmarshal([]byte(doc), &parsed) != nil {
		if err := st.PutKV(model.KVEntry{Bucket: usageSubStoreKVBucket, Key: subStoreIndexKey, Value: doc}); err != nil {
			t.Fatal(err)
		}
		return
	}
	entries := make([]map[string]any, 0, len(parsed.Records))
	for i, rec := range parsed.Records {
		id, _ := rec["id"].(string)
		entry := map[string]any{"id": id, "revision": "rev-" + id, "order": i, "has_url": rec["url"] != nil}
		for _, field := range []string{"kind", "name", "display_name", "tags", "source", "members", "member_tags", "node_source"} {
			if value, ok := rec[field]; ok {
				entry[field] = value
			}
		}
		if _, ok := entry["kind"]; !ok {
			entry["kind"] = "sub"
		}
		entries = append(entries, entry)
		raw, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.PutKV(model.KVEntry{Bucket: usageSubStoreKVBucket, Key: subStoreRecordKey(id), Value: string(raw)}); err != nil {
			t.Fatal(err)
		}
	}
	index, err := json.Marshal(map[string]any{"version": 2, "records": entries})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutKV(model.KVEntry{Bucket: usageSubStoreKVBucket, Key: subStoreIndexKey, Value: string(index)}); err != nil {
		t.Fatal(err)
	}
}

// TestFleetFeedGuardReadsIndexV2: the guard walks the index's records,
// members, member tags and node sources, and reads a vpn-core record's
// identity from the record's own document; subscriptions-v1 is not read, so
// a legacy document that disagrees changes nothing.
func TestFleetFeedGuardReadsIndexV2(t *testing.T) {
	h := newSubStoreSvcHarness(t)
	putSubStoreRecords(t, h.st, `{"records":[
		{"id":"fleet","name":"Everyone","source":"vpn-core","tags":["home"]},
		{"id":"alice-only","name":"Alice","source":"vpn-core","vpn_identity":"vpnuser_alice"},
		{"id":"provider","name":"Provider","url":"https://provider.example/sub"},
		{"id":"combo-tag","kind":"collection","name":"Tagged","member_tags":["home"]},
		{"id":"combo-clean","kind":"collection","name":"Clean","members":["provider","alice-only"]},
		{"id":"clash-file","kind":"file","name":"Clash file","node_source":"combo-tag"}
	]}`)
	// A stale legacy document that would call every record clean.
	if err := h.st.PutKV(model.KVEntry{Bucket: usageSubStoreKVBucket, Key: "subscriptions-v1",
		Value: `{"records":[{"id":"fleet","source":"vpn-core","vpn_identity":"vpnuser_alice"}]}`}); err != nil {
		t.Fatal(err)
	}
	for record, want := range map[string]fleetFeedVerdict{
		"fleet":       {Fleet: true, Via: "Everyone"},
		"combo-tag":   {Fleet: true, Via: "Everyone"},
		"clash-file":  {Fleet: true, Via: "Everyone"},
		"alice-only":  {},
		"provider":    {},
		"combo-clean": {},
		"absent":      {},
	} {
		if got := h.srv.subStoreFleetFeed(record); got != want {
			t.Fatalf("%s: verdict %+v, want %+v", record, got, want)
		}
	}
	// The record key escapes as the plugin's storeKeyComponent does.
	for id, want := range map[string]string{"plain-id": "record-v2-plain-id", "a/b": "record-v2-a%2Fb", "50%": "record-v2-50%25",
		"x\\y": "record-v2-x%5Cy", "c\x01d": "record-v2-c%01d", "del\x7f": "record-v2-del%7F", "名前": "record-v2-名前"} {
		if got := subStoreRecordKey(id); got != want {
			t.Fatalf("subStoreRecordKey(%q) = %q, want %q", id, got, want)
		}
	}
}

// TestFleetFeedGuardTreatsUnreadableLegacyRecordAsFlagged: a vpn-core entry
// whose own document is missing, does not decode or names another record is
// unknown, and the guard asks for the flag for it and for every reader of it,
// as it does for an unreadable index; a record found to publish the feed
// still answers fleet.
func TestFleetFeedGuardTreatsUnreadableLegacyRecordAsFlagged(t *testing.T) {
	h := newSubStoreSvcHarness(t)
	putSubStoreRecords(t, h.st, `{"records":[
		{"id":"legacy","name":"Legacy","source":"vpn-core","vpn_identity":"vpnuser_alice"},
		{"id":"fleet","name":"Everyone","source":"vpn-core"},
		{"id":"reader","kind":"collection","name":"Reader","members":["legacy"]},
		{"id":"both","kind":"collection","name":"Both","members":["legacy","fleet"]}
	]}`)
	if got := h.srv.subStoreFleetFeed("legacy"); got != (fleetFeedVerdict{}) {
		t.Fatalf("a readable identity record = %+v", got)
	}
	for _, broken := range []string{"", "{", `{"id":"someone-else","source":"vpn-core","vpn_identity":"vpnuser_alice"}`} {
		if broken == "" {
			if err := h.st.DeleteKV(usageSubStoreKVBucket, subStoreRecordKey("legacy")); err != nil {
				t.Fatal(err)
			}
		} else if err := h.st.PutKV(model.KVEntry{Bucket: usageSubStoreKVBucket, Key: subStoreRecordKey("legacy"), Value: broken}); err != nil {
			t.Fatal(err)
		}
		for _, record := range []string{"legacy", "reader"} {
			if got := h.srv.subStoreFleetFeed(record); !got.Unknown || got.Fleet {
				t.Fatalf("document %q: %s = %+v, want unknown", broken, record, got)
			}
		}
		if got := h.srv.subStoreFleetFeed("both"); !got.Fleet {
			t.Fatalf("document %q: a collection over the fleet feed = %+v", broken, got)
		}
		if _, err := h.call(subStoreSvcAdmin, subStoreSharesService, "create", `{"subscription_id":"reader","slug":"reader-`+strings.Repeat("x", len(broken)%5)+`"}`); subStoreSvcErrStatus(err) != 400 ||
			!strings.Contains(subStoreSvcErrBody(err), apiErrorFleetFeedFlagRequired) {
			t.Fatalf("document %q: a share of the reader without the flag: %v", broken, err)
		}
	}
}

// TestUsageAttributionReadsLegacyRecordDocument: attribution takes a graph
// record's identity and roots from the record's own document, keyed by the
// plugin's escaped key, skips an entry whose document is unreadable, and
// ignores sources other than vpn-core-graph.
func TestUsageAttributionReadsLegacyRecordDocument(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	putSubStoreRecords(t, srv.store, `{"records":[
		{"id":"graph/one","source":"vpn-core-graph","vpn_identity":"vpnuser_one","entry_roots":["root-a","root-b"]},
		{"id":"graph-two","source":"vpn-core-graph","vpn_identity":"vpnuser_two","entry_roots":["root-c"]},
		{"id":"no-identity","source":"vpn-core-graph","entry_roots":["root-d"]},
		{"id":"export","source":"vpn-core","vpn_identity":"vpnuser_one"},
		{"id":"provider","url":"https://example/sub"}
	]}`)
	got := srv.subStoreGraphRecords()
	if len(got) != 2 || got[0].ID != "graph/one" || got[0].VPNIdentity != "vpnuser_one" || strings.Join(got[0].EntryRoots, ",") != "root-a,root-b" ||
		got[1].ID != "graph-two" {
		t.Fatalf("graph records = %+v", got)
	}
	if err := srv.store.PutKV(model.KVEntry{Bucket: usageSubStoreKVBucket, Key: subStoreRecordKey("graph-two"), Value: "not json"}); err != nil {
		t.Fatal(err)
	}
	if got := srv.subStoreGraphRecords(); len(got) != 1 || got[0].ID != "graph/one" {
		t.Fatalf("an unreadable document was attributed: %+v", got)
	}
	if _, ok := srv.store.KVEntry(usageSubStoreKVBucket, "record-v2-graph%2Fone"); !ok {
		t.Fatal("the fixture did not write the escaped key")
	}
}

// TestExpiringReadsIndexV2Names: the expiring view names a share's record by
// the index's display name, then its name.
func TestExpiringReadsIndexV2Names(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{store: st}
	putSubStoreRecords(t, st, `{"records":[
		{"id":"for-cdcd-loon","name":"for-cdcd-loon","display_name":"cdcd Loon"},
		{"id":"plain","name":"Plain name"},
		{"id":"unnamed","name":""}
	]}`)
	names := srv.subStoreRecordNames()
	if names["for-cdcd-loon"] != "cdcd Loon" || names["plain"] != "Plain name" || len(names) != 2 {
		t.Fatalf("names = %v", names)
	}
}
