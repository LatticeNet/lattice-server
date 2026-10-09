package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"unicode"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The core-backed services the Sub-Store UI needs (design 28, "Core-backed
// services the UI needs"): latticenet.sub-store/shares grows from list to the
// full share lifecycle (substore_svc_shares.go), and latticenet.sub-store/plans
// carries the privileged-change path for fleet-bound records
// (substore_svc_plans.go). Both answer only the operator's own gateway call:
// share tokens never enter the plugin, and a change to what a token holder
// receives is made by a person or an agent the audit trail names.

const (
	// subStorePlansService is the privileged-change service.
	subStorePlansService = "latticenet.sub-store/plans"

	// subStoreSvcMaxRequestBytes bounds one request to either service. An
	// icon given as a data URL is the largest field, at 64 KiB.
	subStoreSvcMaxRequestBytes = 128 << 10
	// subStoreSvcMaxIDBytes bounds a record id, a share id and a revision.
	subStoreSvcMaxIDBytes = 256

	// subStoreSvcErrConflict is the code of a refusal that the share's
	// current state causes: a slug in use, an archived share edited, a purge
	// of a share that is not archived.
	subStoreSvcErrConflict = "conflict"
)

// subStoreSvcState is the state the two services keep on the server.
type subStoreSvcState struct {
	// mu is the share-write lock (subStoreSvcLockShareWrites). It is never
	// held across a plugin call.
	mu sync.Mutex
	// previewer runs validate-and-bind for one record revision and one
	// identity (substore_svc_plans.go). It is nil until the bind code is
	// wired, and plans.propose refuses while it is.
	previewer subStoreBindPreviewer
	// applyRevision replaces the plugin's apply_revision call in tests.
	applyRevision func(context.Context, subStoreApplyRevisionRequest) (subStoreApplyRevisionReply, error)
}

// registerSubStoreSvcRPC registers the plans service. The shares service is
// registered beside list in registerSubStorePluginRPC.
func (s *Server) registerSubStoreSvcRPC() {
	if s.pluginRPC == nil {
		return
	}
	if err := s.pluginRPC.Register(subStorePluginID, subStorePlansService, "v1", []string{"propose", "status", "claim_apply"}, s.subStorePlansRPC); err != nil {
		s.logger.Printf("sub-store: register %s failed: %v", subStorePlansService, err)
	}
}

// subStoreSvcLockShareWrites takes the share-write lock and returns its
// release. Every load, change and save of a share record holds it, through
// these services and through the REST share API
// (server_subscription_share_api.go) alike: both write the whole record
// back, so without one lock a rotate between the other's load and save would
// be written over, and the revoked token would serve again. A plan decision
// holds it from its last check of the record's shares to its approval, so
// no share appears in between.
func (s *Server) subStoreSvcLockShareWrites() func() {
	s.subStoreSvc.mu.Lock()
	return s.subStoreSvc.mu.Unlock
}

// subStoreSvcOperator returns the operator a call is made for, after the
// checks every method of these services makes in core whatever the manifest
// declares: an operator principal, each scope (the gateway's own rule, which
// also refuses a node-restricted principal a global scope), and, when direct
// is set, that the operator called this service through the gateway rather
// than reaching it through a plugin method's rpc.call.
func (s *Server) subStoreSvcOperator(ctx context.Context, service string, direct bool, scopes ...string) (principal, error) {
	p, err := pluginOperatorPrincipal(ctx)
	if err != nil {
		return principal{}, rpcAPIError(http.StatusForbidden, model.APIErrorForbidden, service+": an operator principal is required")
	}
	for _, scope := range scopes {
		if ok, reason := pluginGatewayScopeAllowed(p, scope); !ok {
			return principal{}, rpcAPIError(http.StatusForbidden, model.APIErrorForbidden, service+": "+reason)
		}
	}
	if direct && operatorCalledCoreService(ctx) != service {
		return principal{}, rpcAPIError(http.StatusForbidden, model.APIErrorForbidden,
			service+": this method answers only the operator's own call through the plugin gateway")
	}
	return p, nil
}

// subStoreSvcDecode decodes one request strictly: bounded, one JSON object,
// no unknown field, nothing after it. An unknown field is refused rather than
// ignored, so a caller who names a field this server does not know (or
// misspells one) learns that the edit was not made.
func subStoreSvcDecode(service, method string, request []byte, out any) error {
	trimmed := bytes.TrimSpace(request)
	if len(trimmed) > subStoreSvcMaxRequestBytes {
		return rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, service+" "+method+": request is too large")
	}
	if len(trimmed) == 0 || string(trimmed) == "null" {
		trimmed = []byte("{}")
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, service+" "+method+": invalid request: "+subStoreSvcDecodeReason(err))
	}
	if decoder.More() {
		return rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, service+" "+method+": invalid request: trailing data")
	}
	return nil
}

// subStoreSvcDecodeReason names what was wrong without quoting the request:
// encoding/json quotes field names only, and a value never, but the reason
// is cut to one bounded line anyway.
func subStoreSvcDecodeReason(err error) string {
	reason := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, err.Error())
	if len(reason) > 160 {
		reason = reason[:160]
	}
	return reason
}

// subStoreSvcValidID reports whether value is a usable record id, share id or
// revision: trimmed, bounded, with no control character.
func subStoreSvcValidID(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= subStoreSvcMaxIDBytes &&
		!strings.ContainsFunc(value, unicode.IsControl)
}
