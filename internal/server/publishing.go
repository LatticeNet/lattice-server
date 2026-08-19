package server

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// The publishing plane answers one question for the whole product: what URL is
// this content visible at, and who may read it.
//
// Before this existed the answer was written twice. Storage bindings owned
// hostname, path prefix, an enabled flag, longest-prefix routing and bucket
// scoped access tokens; subscription shares owned a slug, a bearer token and an
// expiry, and shared none of it. Two schemes for one question meant two console
// vocabularies and two sets of rules that had to be kept in agreement by hand.
//
// The split that replaces it is the one Cloudflare settled on: a route decides
// the URL, an origin decides where the bytes come from. Everything about
// reachability lives here; everything about producing content stays with the
// origin.

const (
	// originKV serves values from a KV bucket.
	originKV = model.StorageKindKV
	// originStatic serves objects from a static bucket.
	originStatic = model.StorageKindStatic
	// originPlugin asks a plugin to render the body on each request. Subscription
	// shares are its first and currently only instance.
	originPlugin = "plugin"
)

// publishingOrigins is the set this slice supports, in console display order.
// A worker origin is the obvious next entry and is deliberately absent: nothing
// routes to a worker yet, and an origin that cannot serve should not be
// selectable.
var publishingOrigins = []string{originKV, originStatic, originPlugin}

// subscriptionMountPrefix is the reserved path every subscription share is
// published under. It is reserved rather than configurable because the URL
// already exists in clients that this server does not control.
const subscriptionMountPrefix = "sub"

// publishingRecord is one published route.
//
// For kv and static it is a stored binding. For plugin it is projected from the
// share that owns the route, because the share is still where a rotating token
// and a default format live, and because projecting costs no migration: the
// route these records describe is the one /sub/ already serves.
type publishingRecord struct {
	ID     string
	Origin string
	// Bucket is the origin's target: a bucket name for kv and static, the
	// owning share id for plugin.
	Bucket   string
	Hostname string
	// AnyHost makes the record answer on every hostname. It is a deliberate
	// property of reserved mounts, never inferred from a blank Hostname: a
	// stored binding that somehow lost its host must fail to match rather than
	// widen into a wildcard.
	AnyHost    bool
	PathPrefix string
	Enabled    bool
	// ExpiresAt bounds the route in time. Nil means no bound.
	ExpiresAt *time.Time
	// Reserved marks a route the operator cannot move or delete, because
	// something outside this server already depends on it.
	Reserved bool
	// ShareID is set for origin plugin and identifies the projected share.
	ShareID string
}

// publishingAdminScope names the scope that may publish an origin.
//
// Publishing makes content publicly reachable, so the scope that grants it is a
// security boundary rather than a naming detail. Each origin keeps exactly the
// scope it required before the plane existed: no scope gains the power to
// publish something it could not publish already, which is why this is a
// refactor and not a privilege change.
func publishingAdminScope(origin string) string {
	if origin == originPlugin {
		// Shares have always been gated on proxy:admin, and the content they
		// publish is proxy configuration.
		return "proxy:admin"
	}
	return origin + ":admin"
}

// publishingReadScope names the scope that may see an origin's routes.
func publishingReadScope(origin string) string {
	if origin == originPlugin {
		return "proxy:admin"
	}
	return origin + ":read"
}

// publishingRecordFromBinding lifts a stored storage binding into the plane.
func publishingRecordFromBinding(binding model.StorageBinding) publishingRecord {
	return publishingRecord{
		ID: binding.ID, Origin: binding.Kind, Bucket: binding.Bucket,
		Hostname: binding.Hostname, PathPrefix: binding.PathPrefix, Enabled: binding.Enabled,
	}
}

// publishingRecordFromShare projects a subscription share onto the plane.
//
// The share keeps what belongs to its origin: the rotating token, the default
// format, the per-client query parameters. It hands over what belongs to the
// route: where it is reachable, whether it is on, and until when.
func publishingRecordFromShare(share model.SubscriptionShare) publishingRecord {
	return publishingRecord{
		ID: share.ID, Origin: originPlugin, Bucket: share.ID,
		// The issued URL is used against whatever hostname the client was given,
		// and this server has never restricted that.
		Hostname:   "",
		AnyHost:    true,
		PathPrefix: subscriptionMountPrefix + "/" + share.Slug,
		Enabled:    share.Enabled,
		ExpiresAt:  share.ExpiresAt,
		Reserved:   true,
		ShareID:    share.ID,
	}
}

// publishingRecords returns every route for one origin, whatever it is stored
// as. Callers that need all origins ask for each in turn, so the per-origin
// authorization stays visible at the call site.
//
// The result is deliberately unsorted. This runs on the request path for every
// static, kv and subscription hit, and the resolver below breaks ties on id
// rather than on position, so ordering costs work without deciding anything.
// The listing endpoint sorts for itself.
func (s *Server) publishingRecords(origin string) []publishingRecord {
	var out []publishingRecord
	switch origin {
	case originPlugin:
		for _, share := range s.store.SubscriptionShares() {
			out = append(out, publishingRecordFromShare(share))
		}
	default:
		for _, binding := range s.store.StorageBindings(origin) {
			out = append(out, publishingRecordFromBinding(binding))
		}
	}
	return out
}

// sortedPublishingRecords is publishingRecords in a stable display order.
func (s *Server) sortedPublishingRecords(origin string) []publishingRecord {
	out := s.publishingRecords(origin)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// servable reports whether a record may answer a request now. Enabled and
// ExpiresAt are route facts, so they are enforced here rather than by each
// origin separately.
func (r publishingRecord) servable(now time.Time) bool {
	if !r.Enabled {
		return false
	}
	if r.ExpiresAt != nil && !now.Before(*r.ExpiresAt) {
		return false
	}
	return true
}

// matchesHost reports whether the record answers on a hostname.
func (r publishingRecord) matchesHost(hostname string) bool {
	if r.AnyHost {
		return true
	}
	return strings.EqualFold(r.Hostname, hostname)
}

// objectPath strips the record's prefix off a request path.
func (r publishingRecord) objectPath(urlPath string) (string, bool) {
	return bindingObjectPath(model.StorageBinding{PathPrefix: r.PathPrefix}, urlPath)
}

// publishingRecordForRequest resolves the route that serves a request.
//
// Longest prefix wins and ties break on id, which is the rule storage bindings
// already used; keeping it means a host binding routes exactly as it did before
// the plane existed.
func (s *Server) publishingRecordForRequest(origin, hostname, urlPath string) (publishingRecord, bool) {
	var best publishingRecord
	bestPrefixLen := -1
	now := s.now()
	for _, record := range s.publishingRecords(origin) {
		if !record.servable(now) || !record.matchesHost(hostname) {
			continue
		}
		if _, ok := record.objectPath(urlPath); !ok {
			continue
		}
		prefixLen := len(strings.Trim(record.PathPrefix, "/"))
		if prefixLen > bestPrefixLen || (prefixLen == bestPrefixLen && record.ID < best.ID) {
			best = record
			bestPrefixLen = prefixLen
		}
	}
	return best, bestPrefixLen >= 0
}

// publishingRecordView is the console shape of a route.
type publishingRecordView struct {
	ID         string     `json:"id"`
	Origin     string     `json:"origin"`
	Bucket     string     `json:"bucket"`
	Hostname   string     `json:"hostname"`
	AnyHost    bool       `json:"any_host"`
	PathPrefix string     `json:"path_prefix,omitempty"`
	Enabled    bool       `json:"enabled"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	Reserved   bool       `json:"reserved"`
	ShareID    string     `json:"share_id,omitempty"`
	// AdminScope tells the console which scope gates editing this route, so the
	// page can disable a control instead of offering an action that will 403.
	AdminScope string `json:"admin_scope"`
}

func publishingRecordViewOf(record publishingRecord) publishingRecordView {
	return publishingRecordView{
		ID: record.ID, Origin: record.Origin, Bucket: record.Bucket,
		Hostname: record.Hostname, AnyHost: record.AnyHost,
		PathPrefix: record.PathPrefix, Enabled: record.Enabled, ExpiresAt: record.ExpiresAt,
		Reserved: record.Reserved, ShareID: record.ShareID,
		AdminScope: publishingAdminScope(record.Origin),
	}
}

// handlePublishingRecords lists every route the caller is allowed to see.
//
// The filter is per origin and uses each origin's existing read scope, so this
// endpoint cannot show a caller a route they could not already list through the
// per-origin API it replaces in the console.
func (s *Server) handlePublishingRecords(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	records := []publishingRecordView{}
	visible := map[string]bool{}
	for _, origin := range publishingOrigins {
		if !rbac.Allows(p.Principal, publishingReadScope(origin), "") {
			continue
		}
		visible[origin] = true
		for _, record := range s.sortedPublishingRecords(origin) {
			records = append(records, publishingRecordViewOf(record))
		}
	}
	origins := make([]string, 0, len(visible))
	for _, origin := range publishingOrigins {
		if visible[origin] {
			origins = append(origins, origin)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"records": records,
		// The console needs to distinguish "no routes" from "not allowed to
		// look", so it never renders an empty table as though it were the truth.
		"origins": origins,
	})
}
