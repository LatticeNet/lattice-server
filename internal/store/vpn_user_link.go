package store

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"
)

// An identity's subscription link (identity-sub design B). The link is owned
// by the identity: its token is the identity's SubID, which lives in the
// sealed secret record and goes in the identity's own delete, and its route
// facts (slug, enabled, expiry) live on the public record. A record without a
// Link has no link, whatever its SubID holds: the SubID of a migrated
// identity is its legacy proxy user's old token, served until 2026-08-05, so
// nothing is served from a SubID until a link is issued, and issuing always
// mints a fresh one.

// VpnUserLink is the public half of an identity's link.
type VpnUserLink struct {
	// Slug is the URL's first segment, unique across share and identity
	// links, never derived from the email (it reaches access logs).
	Slug     string    `json:"slug"`
	Disabled bool      `json:"disabled,omitempty"`
	IssuedAt time.Time `json:"issued_at"`
	// RotatedAt is when the token last changed after issue.
	RotatedAt *time.Time `json:"rotated_at,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// UpdateIntervalHours is the refresh period the link advertises; 0 means
	// the default.
	UpdateIntervalHours int `json:"update_interval_hours,omitempty"`
}

// vpnUserLinkSlugRe is the share slug rule (shareSlugRe in the server).
var vpnUserLinkSlugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

const maxVpnUserLinkUpdateIntervalHours = 168

func cloneVpnUserLink(in *VpnUserLink) *VpnUserLink {
	if in == nil {
		return nil
	}
	out := *in
	if in.RotatedAt != nil {
		at := *in.RotatedAt
		out.RotatedAt = &at
	}
	if in.ExpiresAt != nil {
		at := *in.ExpiresAt
		out.ExpiresAt = &at
	}
	return &out
}

// validateVpnUserLink checks one identity's link against its secret record.
func validateVpnUserLink(id string, link *VpnUserLink, private VpnUserSecretRecord) error {
	if link == nil {
		return nil
	}
	if !vpnUserLinkSlugRe.MatchString(link.Slug) {
		return fmt.Errorf("vpn user %q link slug is invalid", id)
	}
	if link.UpdateIntervalHours < 0 || link.UpdateIntervalHours > maxVpnUserLinkUpdateIntervalHours {
		return fmt.Errorf("vpn user %q link update interval is out of range", id)
	}
	if private.SubID == "" {
		return fmt.Errorf("vpn user %q has a link and no token", id)
	}
	return nil
}

// validateLinkSlugsUnique refuses two links on one slug: two identities, or
// an identity and a share. Lookup is by token, but a reader of the URL would
// take the slug for the link's name.
func validateLinkSlugsUnique(public map[string]VpnUserPublicRecord, shareSlugs map[string]string) error {
	seen := make(map[string]string, len(public))
	for id, record := range public {
		if record.Link == nil {
			continue
		}
		if other, ok := seen[record.Link.Slug]; ok {
			return fmt.Errorf("vpn users %q and %q share the link slug %q", other, id, record.Link.Slug)
		}
		if share, ok := shareSlugs[record.Link.Slug]; ok {
			return fmt.Errorf("vpn user %q link slug %q is share %q's", id, record.Link.Slug, share)
		}
		seen[record.Link.Slug] = id
	}
	return nil
}

func (s *Store) shareSlugsLocked() map[string]string {
	out := make(map[string]string, len(s.state.SubscriptionShares))
	for id, share := range s.state.SubscriptionShares {
		out[share.Slug] = id
	}
	return out
}

// ErrLinkTokenNotFound is the one answer for any token that does not name
// exactly one live identity link.
var ErrLinkTokenNotFound = errors.New("link token not found")

// VpnUserIDByLinkToken resolves an identity link token. Like
// SubscriptionShareByToken it goes through the HMAC index, requires exactly
// one match across every link kind, and confirms the hit with a constant-time
// compare against the stored token; an identity whose record has no Link
// never matches.
func (s *Store) VpnUserIDByLinkToken(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	index := s.linkTokenIndexLocked()
	refs := index.byMAC[index.mac(token)]
	if len(refs) != 1 || refs[0].kind != linkKindIdentity {
		return "", false
	}
	public, ok := s.state.VpnUsers[refs[0].id]
	if !ok || public.Link == nil {
		return "", false
	}
	private, ok := s.state.VpnUserSecrets[refs[0].id]
	if !ok || subtle.ConstantTimeCompare([]byte(private.SubID), []byte(token)) != 1 {
		return "", false
	}
	return refs[0].id, true
}

// LinkTokenInUse reports whether any share, identity link or legacy proxy
// user holds token. It is the mint-time uniqueness check every link token
// passes, so a token is never resolved by two rules.
func (s *Store) LinkTokenInUse(token string) bool {
	if token == "" {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, share := range s.state.SubscriptionShares {
		if share.Token == token {
			return true
		}
	}
	for _, private := range s.state.VpnUserSecrets {
		if private.SubID == token {
			return true
		}
	}
	for _, user := range s.state.ProxyUsers {
		if user.SubToken == token {
			return true
		}
	}
	return false
}

// LinkSlugInUse reports whether a share or another identity's link holds
// slug. exceptIdentityID is the identity being edited.
func (s *Store) LinkSlugInUse(slug, exceptIdentityID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, share := range s.state.SubscriptionShares {
		if share.Slug == slug {
			return true
		}
	}
	for id, record := range s.state.VpnUsers {
		if id != exceptIdentityID && record.Link != nil && record.Link.Slug == slug {
			return true
		}
	}
	return false
}

// VpnUserLinkProjection is what the publishing plane needs of one identity
// link, read without cloning the whole record.
type VpnUserLinkProjection struct {
	IdentityID string
	Slug       string
	Disabled   bool
	ExpiresAt  *time.Time
}

// VpnUserLinkProjections lists every issued identity link, sorted by id.
func (s *Store) VpnUserLinkProjections() []VpnUserLinkProjection {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]VpnUserLinkProjection, 0)
	for id, record := range s.state.VpnUsers {
		if record.Link == nil {
			continue
		}
		var expires *time.Time
		if record.Link.ExpiresAt != nil {
			at := *record.Link.ExpiresAt
			expires = &at
		}
		out = append(out, VpnUserLinkProjection{IdentityID: id, Slug: record.Link.Slug, Disabled: record.Link.Disabled, ExpiresAt: expires})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IdentityID < out[j].IdentityID })
	return out
}

// ErrVpnUserNotFound answers a link write for an identity that does not
// exist.
var ErrVpnUserNotFound = errors.New("vpn user not found")

// UpdateVpnUserLink rewrites one identity's link and token in a single
// read and write under the store lock, so a concurrent identity write can
// neither undo a rotation nor be undone by one. fn receives copies of the
// current link (nil when none is issued) and token and returns the new ones;
// an error from fn writes nothing. It is the only writer of an existing
// identity's Link and SubID (PutVpnUserRecord keeps them).
func (s *Store) UpdateVpnUserLink(id string, fn func(link *VpnUserLink, token string) (*VpnUserLink, string, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.state.VpnUsers[id]
	if !ok {
		return ErrVpnUserNotFound
	}
	nextLink, nextToken, err := fn(cloneVpnUserLink(current.Link), s.state.VpnUserSecrets[id].SubID)
	if err != nil {
		return err
	}
	publicRecords := cloneVpnUserPublicRecords(s.state.VpnUsers)
	privateRecords := cloneVpnUserSecretRecords(s.state.VpnUserSecrets)
	record := publicRecords[id]
	record.Link = cloneVpnUserLink(nextLink)
	record.SubscriptionGeneration = 0
	if record.Link != nil || current.Link != nil {
		record.UpdatedAt = time.Now().UTC()
	}
	publicRecords[id] = record
	private := privateRecords[id]
	private.SubID = nextToken
	privateRecords[id] = private
	return s.replaceVpnUserRecordsLocked(publicRecords, privateRecords, nil)
}
