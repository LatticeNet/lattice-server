package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// latticenet.sub-store/shares beyond list: the share lifecycle in core. A
// share is named, tagged, ordered, archived to a recycle bin, restored and
// purged here, over the operator fields of the SDK share model, and its URL
// is still revealed only through list's step-up reveal gate: no reply below
// carries a token, a path or a URL.
//
// Every method answers only the operator's own gateway call, re-checks
// proxy:admin in core (the scope the REST share API asks for), and writes
// one audit event per change. A change that would bind a different
// identity's credentials into an existing link is not offered: the identity
// is fixed when the share is created.

// subStoreSharesMethods is every method of the shares service.
var subStoreSharesMethods = []string{"list", "create", "update", "rotate", "set_enabled", "archive", "restore", "purge", "reorder"}

// Audit actions of the share lifecycle beside create, update, rotate and
// delete (server_subscription_share_api.go).
const (
	auditActionShareArchive = "subscription.share.archive"
	auditActionShareRestore = "subscription.share.restore"
	auditActionSharePurge   = "subscription.share.purge"
	auditActionShareReorder = "subscription.share.reorder"
)

// subStoreSvcShareReply is the reply of every single-share method.
type subStoreSvcShareReply struct {
	Share subStoreShareRow `json:"share"`
}

// subStoreSvcShareRow is a share as the services show it: every operator
// field, and no token. Path stays an empty string for the reason
// subStoreShareRow gives.
func subStoreSvcShareRow(share model.SubscriptionShare) subStoreShareRow {
	return subStoreShareRow{
		SubscriptionID:      share.Source.SubscriptionID,
		ShareID:             share.ID,
		Slug:                share.Slug,
		Enabled:             share.Enabled,
		DefaultFormat:       share.DefaultFormat,
		ExpiresAt:           share.ExpiresAt,
		DisplayName:         share.DisplayName,
		Remark:              share.Remark,
		Icon:                share.Icon,
		Tags:                share.Tags,
		Order:               share.Order,
		ArchivedAt:          share.ArchivedAt,
		IdentityID:          share.Source.IdentityID,
		UpdateIntervalHours: shareUpdateIntervalHours(share),
		AgeRecipient:        subStoreSvcShareAgeRecipient(share),
		CreatedAt:           share.CreatedAt,
		UpdatedAt:           share.UpdatedAt,
		RotatedAt:           share.RotatedAt,
	}
}

// subStoreSvcSharesRPC serves every shares method but list.
func (s *Server) subStoreSvcSharesRPC(ctx context.Context, method string, request []byte) ([]byte, error) {
	switch method {
	case "create", "update", "rotate", "set_enabled", "archive", "restore", "purge", "reorder":
	default:
		return nil, fmt.Errorf("sub-store/shares: unknown method %q", method)
	}
	p, err := s.subStoreSvcOperator(ctx, subStoreSharesService, true, "proxy:admin")
	if err != nil {
		return nil, err
	}
	s.subStoreSvc.mu.Lock()
	defer s.subStoreSvc.mu.Unlock()
	switch method {
	case "create":
		return s.subStoreSvcShareCreate(p, request)
	case "update":
		return s.subStoreSvcShareUpdate(p, request)
	case "rotate":
		return s.subStoreSvcShareRotate(p, request)
	case "set_enabled":
		return s.subStoreSvcShareSetEnabled(p, request)
	case "archive":
		return s.subStoreSvcShareArchive(p, request)
	case "restore":
		return s.subStoreSvcShareRestore(p, request)
	case "purge":
		return s.subStoreSvcSharePurge(p, request)
	default:
		return s.subStoreSvcShareReorder(p, request)
	}
}

// subStoreSvcShareFor loads one Sub-Store share by id. A share of another
// source is not found, as list treats it.
func (s *Server) subStoreSvcShareFor(shareID string) (model.SubscriptionShare, error) {
	shareID = strings.TrimSpace(shareID)
	share, ok := s.store.SubscriptionShare(shareID)
	if shareID == "" || !ok || !isSubStoreShare(share) {
		return model.SubscriptionShare{}, rpcAPIError(http.StatusNotFound, model.APIErrorNotFound, "share not found")
	}
	return share, nil
}

// subStoreSvcRefuseArchived refuses an edit of a share in the recycle bin:
// restore it first, or purge it.
func subStoreSvcRefuseArchived(share model.SubscriptionShare, method string) error {
	if share.ArchivedAt == nil {
		return nil
	}
	return rpcAPIError(http.StatusConflict, subStoreSvcErrConflict,
		fmt.Sprintf("share %s is archived; restore it before %s", share.ID, method))
}

// subStoreSvcShareAudit records one share change by the operator.
func (s *Server) subStoreSvcShareAudit(p principal, action string, share model.SubscriptionShare, metadata map[string]string) {
	meta := map[string]string{
		"share_id": share.ID, "slug": share.Slug, "subscription_id": share.Source.SubscriptionID,
		"via_rpc": subStoreSharesService,
	}
	if share.Token != "" {
		meta["token_sha256"] = proxySubTokenAuditHash(share.Token)
	}
	if share.Source.IdentityID != "" {
		meta["identity_id"] = share.Source.IdentityID
	}
	for k, v := range metadata {
		meta[k] = v
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: action, Scope: "proxy:admin", Decision: "allow", Metadata: meta,
	})
}

// subStoreSvcShareReplyFor answers with the stored share.
func (s *Server) subStoreSvcShareReplyFor(shareID string) ([]byte, error) {
	stored, ok := s.store.SubscriptionShare(shareID)
	if !ok {
		return nil, rpcAPIError(http.StatusInternalServerError, model.APIErrorInternal, "share not readable after write")
	}
	return json.Marshal(subStoreSvcShareReply{Share: subStoreSvcShareRow(stored)})
}

type subStoreSvcCreateRequest struct {
	SubscriptionID string           `json:"subscription_id"`
	Slug           string           `json:"slug"`
	DisplayName    string           `json:"display_name"`
	Remark         string           `json:"remark"`
	Icon           *model.ShareIcon `json:"icon"`
	Tags           []string         `json:"tags"`
	// Order is the share's place in the manual order; absent puts it
	// after every live share.
	Order         *int       `json:"order"`
	DefaultFormat string     `json:"default_format"`
	ExpiresAt     *time.Time `json:"expires_at"`
	// UpdateIntervalHours is 0 for the default.
	UpdateIntervalHours int `json:"update_interval_hours"`
	// IdentityID names the identity a fleet-bound record is served for.
	IdentityID string `json:"identity_id"`
	// AgeRecipient, when set, has the share served as an age file for it.
	AgeRecipient string `json:"age_recipient"`
	// PublishesFleetCredentials is the REST create's explicit flag for a
	// record that reads the identity-less vpn-core export.
	PublishesFleetCredentials bool `json:"publishes_fleet_credentials"`
}

func (s *Server) subStoreSvcShareCreate(p principal, request []byte) ([]byte, error) {
	var req subStoreSvcCreateRequest
	if err := subStoreSvcDecode(subStoreSharesService, "create", request, &req); err != nil {
		return nil, err
	}
	bad := func(message string) error {
		return rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, message)
	}
	req.SubscriptionID = strings.TrimSpace(req.SubscriptionID)
	if !subStoreSvcValidID(req.SubscriptionID) {
		return nil, bad("subscription_id is required")
	}
	req.Slug = strings.TrimSpace(req.Slug)
	if !shareSlugRe.MatchString(req.Slug) {
		return nil, bad("slug must be lowercase letters, digits and hyphens, starting with a letter or digit")
	}
	if s.store.LinkSlugInUse(req.Slug, "") {
		return nil, rpcAPIError(http.StatusConflict, subStoreSvcErrConflict, "a share or an identity link with this slug already exists")
	}
	if req.DefaultFormat != "" {
		if _, err := normalizeProxySubscriptionFormat(req.DefaultFormat); err != nil {
			return nil, bad(err.Error())
		}
	}
	var expires *time.Time
	if req.ExpiresAt != nil {
		when := req.ExpiresAt.UTC()
		// A share dead on arrival answers exactly like a wrong token, so
		// the operator would get no feedback at all.
		if !when.After(s.now()) {
			return nil, bad("expires_at must be in the future")
		}
		expires = &when
	}
	req.IdentityID = strings.TrimSpace(req.IdentityID)
	if req.IdentityID != "" {
		if _, ok := s.getVpnUser(req.IdentityID); !ok {
			return nil, bad("identity_id names no identity")
		}
	}
	recipient := ""
	if strings.TrimSpace(req.AgeRecipient) != "" {
		parsed, err := subStoreSvcParseAgeRecipient(req.AgeRecipient)
		if err != nil {
			return nil, bad(err.Error())
		}
		recipient = parsed
	}
	// The same guard as the REST create: a record that reads the
	// identity-less vpn-core export hands out every user's credentials.
	verdict := s.subStoreFleetFeed(req.SubscriptionID)
	fleetFeed := verdict.Fleet || verdict.Unknown
	switch {
	case req.PublishesFleetCredentials:
	case verdict.Fleet:
		return nil, rpcAPIError(http.StatusBadRequest, apiErrorFleetFeedFlagRequired, fmt.Sprintf(
			"subscription %s publishes every user's credentials: it reads the vpn-core fleet export with no identity. "+
				"Give each person their identity's own link instead; to publish the fleet feed anyway, send publishes_fleet_credentials: true",
			req.SubscriptionID))
	case verdict.Unknown:
		return nil, rpcAPIError(http.StatusBadRequest, apiErrorFleetFeedFlagRequired, fmt.Sprintf(
			"cannot check whether subscription %s publishes every user's credentials. To share it anyway, send publishes_fleet_credentials: true",
			req.SubscriptionID))
	}

	share := model.SubscriptionShare{
		ID: id.New("share"), SchemaVersion: model.SubscriptionShareSchemaVersion, Slug: req.Slug,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: subStorePluginID,
			SubscriptionID: req.SubscriptionID, IdentityID: req.IdentityID},
		DefaultFormat: req.DefaultFormat, Enabled: true, ExpiresAt: expires,
		DisplayName: req.DisplayName, Remark: req.Remark, Icon: req.Icon, Tags: req.Tags,
	}
	if req.Order != nil {
		share.Order = *req.Order
	} else {
		share.Order = s.subStoreSvcNextOrder()
	}
	if err := share.ValidateOperatorFields(); err != nil {
		return nil, bad(err.Error())
	}
	share, err := withShareUpdateIntervalHours(share, req.UpdateIntervalHours)
	if err != nil {
		return nil, bad(err.Error())
	}
	if fleetFeed {
		share = withShareFleetCredentials(share)
	}
	share = subStoreSvcWithAgeRecipient(share, recipient)
	token, err := s.newUniqueShareToken()
	if err != nil {
		return nil, err
	}
	share.Token = token
	if err := s.store.UpsertSubscriptionShare(share); err != nil {
		return nil, err
	}
	meta := map[string]string{"order": strconv.Itoa(share.Order), "age": strconv.FormatBool(recipient != "")}
	if fleetFeed {
		meta[shareExtraFleetCredentials] = "true"
	}
	s.subStoreSvcShareAudit(p, auditActionShareCreate, share, meta)
	return s.subStoreSvcShareReplyFor(share.ID)
}

// subStoreSvcNextOrder is the order that puts a new share after every live
// Sub-Store share.
func (s *Server) subStoreSvcNextOrder() int {
	next := 0
	for _, share := range s.store.SubscriptionSharesUnordered() {
		if isSubStoreShare(share) && share.ArchivedAt == nil && share.Order >= next {
			next = share.Order + 1
		}
	}
	return min(next, model.MaxShareOrder)
}

// subStoreSvcUpdateRequest names only what changes. A pointer that is nil
// was not supplied; ClearIcon and ClearExpiry remove a value, because null
// and absent are the same thing to a Go decoder.
type subStoreSvcUpdateRequest struct {
	ShareID             string           `json:"share_id"`
	DisplayName         *string          `json:"display_name"`
	Remark              *string          `json:"remark"`
	Icon                *model.ShareIcon `json:"icon"`
	ClearIcon           bool             `json:"clear_icon"`
	Tags                *[]string        `json:"tags"`
	Order               *int             `json:"order"`
	DefaultFormat       *string          `json:"default_format"`
	UpdateIntervalHours *int             `json:"update_interval_hours"`
	ExpiresAt           *time.Time       `json:"expires_at"`
	ClearExpiry         bool             `json:"clear_expiry"`
	// AgeRecipient sets the recipient; "" serves the share in the clear.
	AgeRecipient *string `json:"age_recipient"`
	// IdentityID is accepted only when it equals the share's own, so a
	// client that sends back the whole row is not refused for it.
	IdentityID *string `json:"identity_id"`
}

func (s *Server) subStoreSvcShareUpdate(p principal, request []byte) ([]byte, error) {
	var req subStoreSvcUpdateRequest
	if err := subStoreSvcDecode(subStoreSharesService, "update", request, &req); err != nil {
		return nil, err
	}
	bad := func(message string) error {
		return rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, message)
	}
	share, err := s.subStoreSvcShareFor(req.ShareID)
	if err != nil {
		return nil, err
	}
	if err := subStoreSvcRefuseArchived(share, "editing it"); err != nil {
		return nil, err
	}
	if req.IdentityID != nil && strings.TrimSpace(*req.IdentityID) != share.Source.IdentityID {
		// A link already handed to someone must never start serving another
		// identity's credentials. A new identity gets a new link, so no
		// existing holder receives what was not meant for them.
		return nil, rpcAPIError(http.StatusConflict, subStoreSvcErrConflict,
			"a share's identity is fixed when the share is created; create a share for the other identity and archive this one")
	}
	if req.ClearIcon && req.Icon != nil {
		return nil, bad("icon and clear_icon cannot both be set")
	}
	if req.ClearExpiry && req.ExpiresAt != nil {
		return nil, bad("expires_at and clear_expiry cannot both be set")
	}
	var changed []string
	if req.DisplayName != nil {
		share.DisplayName, changed = *req.DisplayName, append(changed, "display_name")
	}
	if req.Remark != nil {
		share.Remark, changed = *req.Remark, append(changed, "remark")
	}
	switch {
	case req.ClearIcon:
		share.Icon, changed = nil, append(changed, "icon")
	case req.Icon != nil:
		icon := *req.Icon
		share.Icon, changed = &icon, append(changed, "icon")
	}
	if req.Tags != nil {
		share.Tags, changed = append([]string(nil), (*req.Tags)...), append(changed, "tags")
	}
	if req.Order != nil {
		share.Order, changed = *req.Order, append(changed, "order")
	}
	if req.DefaultFormat != nil {
		format := strings.TrimSpace(*req.DefaultFormat)
		if format != "" && !subscriptionFormatIsKnown(format) {
			return nil, bad("unknown subscription format")
		}
		share.DefaultFormat, changed = format, append(changed, "default_format")
	}
	if req.UpdateIntervalHours != nil {
		updated, err := withShareUpdateIntervalHours(share, *req.UpdateIntervalHours)
		if err != nil {
			return nil, bad(err.Error())
		}
		share, changed = updated, append(changed, "update_interval_hours")
	}
	before := share.ExpiresAt
	switch {
	case req.ClearExpiry:
		share.ExpiresAt, changed = nil, append(changed, "expires_at")
	case req.ExpiresAt != nil:
		when := req.ExpiresAt.UTC()
		if !when.After(s.now()) {
			return nil, bad("expires_at must be in the future")
		}
		share.ExpiresAt, changed = &when, append(changed, "expires_at")
	}
	ageBefore := subStoreSvcShareAgeRecipient(share)
	if req.AgeRecipient != nil {
		recipient := ""
		if strings.TrimSpace(*req.AgeRecipient) != "" {
			parsed, err := subStoreSvcParseAgeRecipient(*req.AgeRecipient)
			if err != nil {
				return nil, bad(err.Error())
			}
			recipient = parsed
		}
		share, changed = subStoreSvcWithAgeRecipient(share, recipient), append(changed, "age_recipient")
	}
	if len(changed) == 0 {
		return nil, bad("update names no field to change")
	}
	if err := share.ValidateOperatorFields(); err != nil {
		return nil, bad(err.Error())
	}
	share.UpdatedAt = s.now()
	if err := s.store.UpsertSubscriptionShare(share); err != nil {
		return nil, err
	}
	// The cached bodies were rendered under the old settings; a format or
	// recipient change makes them the wrong bytes.
	s.subscriptionCache.InvalidateShare(share.ID)
	meta := map[string]string{
		"fields":       strings.Join(changed, ","),
		"expires_from": formatShareExpiry(before),
		"expires_to":   formatShareExpiry(share.ExpiresAt),
	}
	switch ageAfter := subStoreSvcShareAgeRecipient(share); {
	case ageAfter == ageBefore:
	case ageAfter == "":
		meta["age"] = "cleared"
	default:
		meta["age"] = "set"
	}
	s.subStoreSvcShareAudit(p, auditActionShareUpdate, share, meta)
	return s.subStoreSvcShareReplyFor(share.ID)
}

// subStoreSvcShareIDRequest is the input of the methods that name one share.
type subStoreSvcShareIDRequest struct {
	ShareID string `json:"share_id"`
}

func (s *Server) subStoreSvcShareRotate(p principal, request []byte) ([]byte, error) {
	var req subStoreSvcShareIDRequest
	if err := subStoreSvcDecode(subStoreSharesService, "rotate", request, &req); err != nil {
		return nil, err
	}
	share, err := s.subStoreSvcShareFor(req.ShareID)
	if err != nil {
		return nil, err
	}
	if err := subStoreSvcRefuseArchived(share, "rotating it"); err != nil {
		return nil, err
	}
	oldToken := share.Token
	token, err := s.newUniqueShareToken()
	if err != nil {
		return nil, err
	}
	now := s.now()
	share.Token, share.RotatedAt = token, &now
	if err := s.store.UpsertSubscriptionShare(share); err != nil {
		return nil, err
	}
	// A cached body is served without consulting the token, so rotation
	// drops it; the old token now resolves to nothing and gets the decoy.
	s.invalidateSharesForSource(share.Source.PluginID, share.Source.SubscriptionID)
	s.shareRenderBudget.reset(share.ID)
	s.subStoreSvcShareAudit(p, auditActionShareRotate, share, map[string]string{
		"old_token_sha256": proxySubTokenAuditHash(oldToken),
		"new_token_sha256": proxySubTokenAuditHash(token),
	})
	return s.subStoreSvcShareReplyFor(share.ID)
}

type subStoreSvcSetEnabledRequest struct {
	ShareID string `json:"share_id"`
	Enabled *bool  `json:"enabled"`
}

func (s *Server) subStoreSvcShareSetEnabled(p principal, request []byte) ([]byte, error) {
	var req subStoreSvcSetEnabledRequest
	if err := subStoreSvcDecode(subStoreSharesService, "set_enabled", request, &req); err != nil {
		return nil, err
	}
	if req.Enabled == nil {
		return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "enabled is required")
	}
	share, err := s.subStoreSvcShareFor(req.ShareID)
	if err != nil {
		return nil, err
	}
	if err := subStoreSvcRefuseArchived(share, "enabling or disabling it"); err != nil {
		return nil, err
	}
	if share.Enabled != *req.Enabled {
		share.Enabled = *req.Enabled
		share.UpdatedAt = s.now()
		if err := s.store.UpsertSubscriptionShare(share); err != nil {
			return nil, err
		}
		// A share just disabled must stop answering now, not when its
		// cached body expires.
		s.subscriptionCache.InvalidateShare(share.ID)
		s.subStoreSvcShareAudit(p, auditActionShareUpdate, share, map[string]string{
			"fields": "enabled", "enabled": strconv.FormatBool(share.Enabled),
		})
	}
	return s.subStoreSvcShareReplyFor(share.ID)
}

func (s *Server) subStoreSvcShareArchive(p principal, request []byte) ([]byte, error) {
	var req subStoreSvcShareIDRequest
	if err := subStoreSvcDecode(subStoreSharesService, "archive", request, &req); err != nil {
		return nil, err
	}
	share, err := s.subStoreSvcShareFor(req.ShareID)
	if err != nil {
		return nil, err
	}
	// Archiving an archived share changes nothing and records nothing.
	if share.ArchivedAt == nil {
		now := s.now()
		share.ArchivedAt, share.UpdatedAt = &now, now
		if err := s.store.UpsertSubscriptionShare(share); err != nil {
			return nil, err
		}
		s.subscriptionCache.InvalidateShare(share.ID)
		s.subStoreSvcShareAudit(p, auditActionShareArchive, share, nil)
	}
	return s.subStoreSvcShareReplyFor(share.ID)
}

func (s *Server) subStoreSvcShareRestore(p principal, request []byte) ([]byte, error) {
	var req subStoreSvcShareIDRequest
	if err := subStoreSvcDecode(subStoreSharesService, "restore", request, &req); err != nil {
		return nil, err
	}
	share, err := s.subStoreSvcShareFor(req.ShareID)
	if err != nil {
		return nil, err
	}
	if share.ArchivedAt == nil {
		return nil, rpcAPIError(http.StatusConflict, subStoreSvcErrConflict, "share "+share.ID+" is not archived")
	}
	archivedAt := share.ArchivedAt.UTC().Format(time.RFC3339)
	// Restoring keeps the token, so the link its holders have works again.
	share.ArchivedAt, share.UpdatedAt = nil, s.now()
	if err := s.store.UpsertSubscriptionShare(share); err != nil {
		return nil, err
	}
	s.subscriptionCache.InvalidateShare(share.ID)
	s.subStoreSvcShareAudit(p, auditActionShareRestore, share, map[string]string{"archived_at": archivedAt})
	return s.subStoreSvcShareReplyFor(share.ID)
}

func (s *Server) subStoreSvcSharePurge(p principal, request []byte) ([]byte, error) {
	var req subStoreSvcShareIDRequest
	if err := subStoreSvcDecode(subStoreSharesService, "purge", request, &req); err != nil {
		return nil, err
	}
	share, err := s.subStoreSvcShareFor(req.ShareID)
	if err != nil {
		return nil, err
	}
	// Purge deletes for good, so it takes only what the operator already
	// put in the recycle bin: a live link is never one call from gone.
	if share.ArchivedAt == nil {
		return nil, rpcAPIError(http.StatusConflict, subStoreSvcErrConflict,
			"purge deletes only an archived share; archive share "+share.ID+" first")
	}
	if err := s.store.DeleteSubscriptionShare(share.ID); err != nil {
		return nil, err
	}
	s.subscriptionCache.InvalidateShare(share.ID)
	s.shareRenderBudget.reset(share.ID)
	s.subStoreSvcShareAudit(p, auditActionSharePurge, share, map[string]string{
		"archived_at": share.ArchivedAt.UTC().Format(time.RFC3339),
	})
	return json.Marshal(map[string]string{"purged": share.ID})
}

type subStoreSvcReorderRequest struct {
	// ShareIDs is every live (not archived) Sub-Store share, once each, in
	// the new order.
	ShareIDs []string `json:"share_ids"`
}

func (s *Server) subStoreSvcShareReorder(p principal, request []byte) ([]byte, error) {
	var req subStoreSvcReorderRequest
	if err := subStoreSvcDecode(subStoreSharesService, "reorder", request, &req); err != nil {
		return nil, err
	}
	live := map[string]model.SubscriptionShare{}
	for _, share := range s.store.SubscriptionSharesUnordered() {
		if isSubStoreShare(share) && share.ArchivedAt == nil {
			live[share.ID] = share
		}
	}
	// A partial list would leave the unnamed shares tied with named ones at
	// whatever order they held, so the order the operator dragged is not the
	// order stored. The whole list is required.
	if len(req.ShareIDs) != len(live) {
		return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest,
			fmt.Sprintf("reorder names %d shares; it must name each of the %d live shares once", len(req.ShareIDs), len(live)))
	}
	seen := make(map[string]bool, len(req.ShareIDs))
	ordered := make([]model.SubscriptionShare, 0, len(req.ShareIDs))
	var writes []model.SubscriptionShare
	now := s.now()
	for i, shareID := range req.ShareIDs {
		share, ok := live[shareID]
		if !ok || seen[shareID] {
			return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest,
				"reorder must name each live share exactly once")
		}
		seen[shareID] = true
		if share.Order != i {
			share.Order, share.UpdatedAt = i, now
			writes = append(writes, share)
		}
		ordered = append(ordered, share)
	}
	if err := s.store.UpsertSubscriptionShares(writes); err != nil {
		return nil, err
	}
	if len(writes) > 0 {
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID: id.New("audit"), Action: auditActionShareReorder, Scope: "proxy:admin", Decision: "allow",
			Metadata: map[string]string{"shares": strconv.Itoa(len(ordered)), "moved": strconv.Itoa(len(writes)), "via_rpc": subStoreSharesService},
		})
	}
	rows := make([]subStoreShareRow, 0, len(ordered))
	for _, share := range ordered {
		if stored, ok := s.store.SubscriptionShare(share.ID); ok {
			share = stored
		}
		rows = append(rows, subStoreSvcShareRow(share))
	}
	return json.Marshal(map[string]any{"shares": rows})
}
