package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
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
	// Path is the serve path including the token, and URL the same under the
	// configured public base (present only when the server knows one). Both
	// are set only on a row the caller asked to reveal and the reveal gate
	// admitted (secret_reveal.go); Revealed says so. Every other row carries
	// neither, because the token in them is the subscription's credential.
	// Path stays in the answer as an empty string: Sub-Store's Shares screen
	// up to 0.16.0-alpha.1 reads share.path as a string and would throw on a
	// missing field, while an empty one leaves its copy button disabled.
	Path     string `json:"path"`
	URL      string `json:"url,omitempty"`
	Revealed bool   `json:"revealed,omitempty"`
}

// subStoreSharesListRequest is list's optional input. With ShareID and a
// StepUpGrant (or a token carrying secrets:reveal), that one row carries its
// link. The plugin keeps one method, so revealing a link needs no manifest
// change and no signing ceremony.
type subStoreSharesListRequest struct {
	ShareID     string `json:"share_id,omitempty"`
	StepUpGrant string `json:"step_up_grant,omitempty"`
}

func (s *Server) subStoreSharesRPC(ctx context.Context, method string, request []byte) ([]byte, error) {
	switch method {
	case "list":
		p, err := pluginOperatorPrincipal(ctx)
		if err != nil {
			return nil, err
		}
		// The gateway already enforced the manifest scopes, but this method can
		// hand out URLs embedding share tokens, the material the REST share API
		// guards behind proxy:admin. Re-checking here means a manifest mistake
		// can never widen who reads them.
		if ok, reason := pluginGatewayScopeAllowed(p, "proxy:admin"); !ok {
			return nil, errors.New(reason)
		}
		var req subStoreSharesListRequest
		if len(bytes.TrimSpace(request)) > 0 && string(bytes.TrimSpace(request)) != "null" {
			if err := json.Unmarshal(request, &req); err != nil {
				return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "sub-store/shares list: invalid request")
			}
		}
		req.ShareID = strings.TrimSpace(req.ShareID)
		var reveal secretRevealDecision
		if req.ShareID != "" {
			share, ok := s.store.SubscriptionShare(req.ShareID)
			if !ok || share.Source.Kind != model.ShareSourcePlugin || share.Source.PluginID != subStorePluginID {
				return nil, rpcAPIError(http.StatusNotFound, model.APIErrorNotFound, "share not found")
			}
			ev := model.AuditEvent{Action: auditActionShareReveal, Scope: "proxy:admin",
				Metadata: map[string]string{"share_id": share.ID, "slug": share.Slug, "token_sha256": proxySubTokenAuditHash(share.Token), "via_rpc": subStoreSharesService}}
			reveal = s.decideSecretReveal(p, req.StepUpGrant)
			if !reveal.Allowed {
				s.refuseSecretReveal(p, reveal, ev)
				return nil, secretRevealRPCError(reveal)
			}
			s.recordSecretReveal(p, reveal, ev)
		}
		rows := make([]subStoreShareRow, 0)
		for _, share := range s.store.SubscriptionShares() {
			if share.Source.Kind != model.ShareSourcePlugin || share.Source.PluginID != subStorePluginID {
				continue
			}
			row := subStoreShareRow{
				SubscriptionID: share.Source.SubscriptionID,
				ShareID:        share.ID,
				Slug:           share.Slug,
				Enabled:        share.Enabled,
				DefaultFormat:  share.DefaultFormat,
				ExpiresAt:      share.ExpiresAt,
			}
			if reveal.Allowed && share.ID == req.ShareID {
				link := s.linkRevealViewOf("share", share.ID, share.Slug, share.Token)
				row.Path, row.URL, row.Revealed = link.Path, link.URL, true
			}
			rows = append(rows, row)
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Slug < rows[j].Slug })
		return json.Marshal(map[string]any{"shares": rows})
	default:
		return nil, fmt.Errorf("sub-store/shares: unknown method %q", method)
	}
}
