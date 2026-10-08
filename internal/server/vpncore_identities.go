package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// vpnCoreIdentitiesService lists identities for the native Sub-Store's
// identity pickers (design 28): who a fleet share may serve, and whether that
// identity can be served now. It is a credential-free subset of
// latticenet.vpn-core/users list, read at vpncore:read so a plugin can be
// granted it without the users service's other reads.
const vpnCoreIdentitiesService = "latticenet.vpn-core/identities"

// vpnCoreIdentityItem is one identity as the list carries it. It names no
// credential, no binding and no link.
type vpnCoreIdentityItem struct {
	ID    string `json:"id"`
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	Group string `json:"group,omitempty"`
	// Status is the identity's policy now: active, disabled, expired or
	// over_quota. A share for an identity that is not active serves the
	// placeholder entry naming why.
	Status string `json:"status"`
	// Reason is why an identity that is not active is suspended: disabled,
	// operator, expiry or quota.
	Reason string `json:"reason,omitempty"`
	// BoundLines counts the identity's enabled line bindings.
	BoundLines int        `json:"bound_lines"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

type vpnCoreIdentitiesListReply struct {
	Identities []vpnCoreIdentityItem `json:"identities"`
	Count      int                   `json:"count"`
}

// vpnCoreIdentitiesRPC serves latticenet.vpn-core/identities.
//
//	list {} -> {"identities":[{id,name,email,group,status,reason,bound_lines,expires_at}],"count":N}
func (s *Server) vpnCoreIdentitiesRPC(ctx context.Context, method string, request []byte) ([]byte, error) {
	if err := vpnCoreReadAllowed(ctx); err != nil {
		return nil, err
	}
	if method != "list" {
		return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "vpn-core/identities: unknown method "+method)
	}
	if err := decodeEmptyRequest(request); err != nil {
		return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "vpn-core/identities list takes an empty object")
	}
	now := s.now()
	users := s.listVpnUsers()
	reply := vpnCoreIdentitiesListReply{Identities: make([]vpnCoreIdentityItem, 0, len(users)), Count: len(users)}
	for _, u := range users {
		policy := s.vpnUserPolicyAt(u, now)
		item := vpnCoreIdentityItem{ID: u.ID, Name: u.Name, Email: u.Email, Group: u.Group, Status: policy.Status, Reason: policy.Reason}
		for _, binding := range u.Bindings {
			if binding.Enabled {
				item.BoundLines++
			}
		}
		if !u.ExpiresAt.IsZero() {
			at := u.ExpiresAt.UTC()
			item.ExpiresAt = &at
		}
		reply.Identities = append(reply.Identities, item)
	}
	return json.Marshal(reply)
}

// decodeEmptyRequest accepts an empty body or an empty JSON object, and
// nothing else.
func decodeEmptyRequest(raw []byte) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var empty struct{}
	if err := decoder.Decode(&empty); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return io.ErrUnexpectedEOF
	}
	return nil
}
