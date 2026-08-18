package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// subStorePluginID is declared in substore_sync.go.
const subStoreSharesService = "latticenet.sub-store/shares"

// registerSubStorePluginRPC gives the sub-store plugin one core-backed service:
// a read-only bridge from its subscription records to the share URLs core holds
// for them. Share tokens deliberately live in core and never cross into the
// plugin sandbox, so "copy this subscription's link" in the plugin UI can only
// exist as a core-backed method — the same pattern the NetGuard firewall
// service uses.
func (s *Server) registerSubStorePluginRPC() {
	if s.pluginRPC == nil {
		return
	}
	if err := s.pluginRPC.Register(subStorePluginID, subStoreSharesService, "v1", []string{"list"}, s.subStoreSharesRPC); err != nil {
		s.logger.Printf("sub-store: register %s failed: %v", subStoreSharesService, err)
	}
}

type subStoreShareRow struct {
	SubscriptionID string     `json:"subscription_id"`
	ShareID        string     `json:"share_id"`
	Slug           string     `json:"slug"`
	Enabled        bool       `json:"enabled"`
	DefaultFormat  string     `json:"default_format,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	// Path is the serve path including the token; URL is the same prefixed with
	// the configured public base, present only when the server knows one. The
	// token appears here because the URL is the product — a link without it is
	// not a subscription a client can use.
	Path string `json:"path"`
	URL  string `json:"url,omitempty"`
}

func (s *Server) subStoreSharesRPC(ctx context.Context, method string, _ []byte) ([]byte, error) {
	switch method {
	case "list":
		p, err := pluginOperatorPrincipal(ctx)
		if err != nil {
			return nil, err
		}
		// The gateway already enforced the manifest scopes, but this method hands
		// out URLs embedding share tokens — the material the REST share API
		// guards behind proxy:admin. Re-checking here means a manifest mistake
		// can never widen who reads them.
		if ok, reason := pluginGatewayScopeAllowed(p, "proxy:admin"); !ok {
			return nil, errors.New(reason)
		}
		rows := make([]subStoreShareRow, 0)
		for _, share := range s.store.SubscriptionShares() {
			if share.Source.Kind != model.ShareSourcePlugin || share.Source.PluginID != subStorePluginID {
				continue
			}
			path := "/sub/" + share.Slug + "/" + share.Token
			row := subStoreShareRow{
				SubscriptionID: share.Source.SubscriptionID,
				ShareID:        share.ID,
				Slug:           share.Slug,
				Enabled:        share.Enabled,
				DefaultFormat:  share.DefaultFormat,
				ExpiresAt:      share.ExpiresAt,
				Path:           path,
			}
			if s.publicURL != "" {
				row.URL = s.publicURL + path
			}
			rows = append(rows, row)
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Slug < rows[j].Slug })
		return json.Marshal(map[string]any{"shares": rows})
	default:
		return nil, fmt.Errorf("sub-store/shares: unknown method %q", method)
	}
}
