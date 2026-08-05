package server

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The export format is defined now rather than when migration needs it. A format
// designed after the fact gets shaped by whatever the implementation happened to
// store; this round trip is what keeps it independent of that.
func TestShareExportImportRoundTripIsStable(t *testing.T) {
	shares := []model.SubscriptionShare{{
		ID: "b", SchemaVersion: 1, Slug: "second", Token: strings.Repeat("b", 32), Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourceCoreProxyUser, ProxyUserID: "u1"},
	}, {
		ID: "a", SchemaVersion: 1, Slug: "first", Token: strings.Repeat("a", 32), Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "s"},
		Extra:  map[string]json.RawMessage{"future": json.RawMessage(`"kept"`)},
	}}

	first, err := exportSubscriptionShares(shares)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	back, err := importSubscriptionShares(first)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	second, err := exportSubscriptionShares(back)
	if err != nil {
		t.Fatalf("re-export: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("round trip was not stable:\nfirst:  %s\nsecond: %s", first, second)
	}
	if !bytes.Contains(second, []byte(`"future"`)) {
		t.Fatal("an unknown field was lost across export and import")
	}
}

// Export must be deterministic regardless of the order it is handed records, or
// two exports of the same data would diff.
func TestShareExportIsOrderIndependent(t *testing.T) {
	a := model.SubscriptionShare{ID: "a", SchemaVersion: 1, Slug: "a", Token: strings.Repeat("a", 32)}
	b := model.SubscriptionShare{ID: "b", SchemaVersion: 1, Slug: "b", Token: strings.Repeat("b", 32)}

	one, err := exportSubscriptionShares([]model.SubscriptionShare{a, b})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	other, err := exportSubscriptionShares([]model.SubscriptionShare{b, a})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !bytes.Equal(one, other) {
		t.Fatalf("export depends on input order:\n%s\n%s", one, other)
	}
}

func TestShareImportRejectsAnUnknownFormat(t *testing.T) {
	if _, err := importSubscriptionShares([]byte(`{"format":"something.else.v1","shares":[]}`)); err == nil {
		t.Fatal("an unknown format was accepted")
	}
	if _, err := importSubscriptionShares([]byte(`{"shares":[]}`)); err == nil {
		t.Fatal("a missing format was accepted")
	}
	if _, err := importSubscriptionShares([]byte(`not json`)); err == nil {
		t.Fatal("malformed input was accepted")
	}
}
