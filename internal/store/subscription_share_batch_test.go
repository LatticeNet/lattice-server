package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// A batch keeps every operator field of a share across a reopen, in the JSON
// store and in the record-level hot store, and seals each token at rest.
func TestUpsertSubscriptionSharesPersistsOperatorFields(t *testing.T) {
	for _, hot := range []bool{false, true} {
		name := "json"
		if hot {
			name = "bolt"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "state.json")
			cipher := testCipher(t)
			open := func() *Store {
				s, err := OpenWithCipher(path, cipher)
				if err != nil {
					t.Fatal(err)
				}
				if hot {
					if err := s.EnableRuntimeBoltHotStore(filepath.Join(dir, "state-hot.db")); err != nil {
						t.Fatal(err)
					}
				}
				return s
			}
			s := open()
			archived := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
			shares := []model.SubscriptionShare{
				{ID: "sh-a", Slug: "a", Token: strings.Repeat("a", 43), Enabled: true, Order: 2, DisplayName: "Alpha", Tags: []string{"team"},
					Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "latticenet.sub-store", SubscriptionID: "rec", IdentityID: "id-1"}},
				{ID: "sh-b", Slug: "b", Token: strings.Repeat("b", 43), Enabled: true, Order: 0, Remark: "line one\nline two", ArchivedAt: &archived,
					Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "latticenet.sub-store", SubscriptionID: "rec"}},
				{ID: "sh-c", Slug: "c", Token: strings.Repeat("c", 43), Enabled: false, Order: 1,
					Icon:   &model.ShareIcon{URL: "https://icons.example.com/c.png", Color: "#3b82f6"},
					Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "latticenet.sub-store", SubscriptionID: "rec"}},
			}
			if err := s.UpsertSubscriptionShares(shares); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			for _, file := range []string{path, filepath.Join(dir, "state-hot.db")} {
				raw, err := os.ReadFile(file)
				if err != nil {
					continue
				}
				for _, share := range shares {
					if strings.Contains(string(raw), share.Token) {
						t.Fatalf("%s holds share %s's token in the clear", filepath.Base(file), share.ID)
					}
				}
			}

			reopened := open()
			defer reopened.Close()
			for _, want := range shares {
				got, ok := reopened.SubscriptionShare(want.ID)
				if !ok {
					t.Fatalf("share %s missing after reopen", want.ID)
				}
				if got.Token != want.Token || got.Order != want.Order || got.DisplayName != want.DisplayName ||
					got.Remark != want.Remark || got.Source != want.Source || len(got.Tags) != len(want.Tags) ||
					(got.ArchivedAt == nil) != (want.ArchivedAt == nil) || (got.Icon == nil) != (want.Icon == nil) {
					t.Fatalf("share %s after reopen = %+v, want %+v", want.ID, got, want)
				}
				if got.UpdatedAt.IsZero() || got.CreatedAt.IsZero() || got.SchemaVersion != model.SubscriptionShareSchemaVersion {
					t.Fatalf("share %s was written without its times or schema version: %+v", want.ID, got)
				}
				if byToken, ok := reopened.SubscriptionShareByToken(want.Token); !ok || byToken.ID != want.ID {
					t.Fatalf("share %s does not resolve by token after reopen", want.ID)
				}
			}
		})
	}
}

// A batch with one bad share writes none of them.
func TestUpsertSubscriptionSharesRefusesWholeBatch(t *testing.T) {
	s, _ := newShareStore(t)
	err := s.UpsertSubscriptionShares([]model.SubscriptionShare{
		{ID: "sh-ok", Slug: "ok", Enabled: true},
		{ID: "", Slug: "no-id", Enabled: true},
	})
	if err == nil {
		t.Fatal("a batch with a share without an id was written")
	}
	if _, ok := s.SubscriptionShare("sh-ok"); ok {
		t.Fatal("a refused batch wrote part of itself")
	}
	if err := s.UpsertSubscriptionShares(nil); err != nil {
		t.Fatalf("an empty batch is a no-op, got %v", err)
	}
}
