package server

import (
	"net/http"
	"strconv"
	"strings"
)

// The public subscription endpoint answers every non-servable request the same
// way, and that answer carries no evidence that the endpoint exists.
//
// The threat is active probing: someone who can reach the URL should not be able
// to learn whether a token is valid, whether a slug is real, or even whether this
// server has a subscription endpoint at all. Distinguishable failures defeat the
// token, because a prober who can tell "valid token, empty content" from "no such
// token" has been told the answer the token exists to keep.
//
// Truth is not discarded, it is relocated: every rejection is still audited with
// its real reason, so the operator sees everything and the wire says nothing.
const (
	// defaultDecoyStatus is what an unknown path should look like. It is 404
	// rather than 403 or 429 because 404 is what a server says about a path it
	// does not have, which is precisely the impression this is meant to leave.
	defaultDecoyStatus = http.StatusNotFound
)

// subscriptionDecoyOptions lets an operator match whatever their reverse proxy
// returns for an unknown path, so /sub/<anything> and /a-path-that-never-existed
// are byte-identical from outside.
type subscriptionDecoyOptions struct {
	// Status is the status code every rejection returns.
	Status int
	// Body is returned verbatim. Empty means an empty body, which lets a front
	// proxy substitute its own error page via proxy_intercept_errors.
	Body string
	// ContentType is omitted entirely when empty, so the response carries no
	// header a bare 404 would not.
	ContentType string
}

func (o subscriptionDecoyOptions) withDefaults() subscriptionDecoyOptions {
	if o.Status == 0 {
		o.Status = defaultDecoyStatus
	}
	return o
}

// writeSubscriptionDecoy answers a non-servable subscription request.
//
// It deliberately does NOT go through writeError: that helper emits a JSON body
// naming the error and a request id, which identifies the software and confirms
// the endpoint. This writes only what was configured, and strips the request-id
// header the middleware may already have set.
func (s *Server) writeSubscriptionDecoy(w http.ResponseWriter) {
	opts := s.subscriptionDecoy.withDefaults()
	w.Header().Del(requestIDHeader)
	if opts.ContentType != "" {
		w.Header().Set("Content-Type", opts.ContentType)
	}
	if opts.Body != "" {
		w.Header().Set("Content-Length", strconv.Itoa(len(opts.Body)))
	}
	w.WriteHeader(opts.Status)
	if opts.Body != "" {
		_, _ = w.Write([]byte(opts.Body))
	}
}

// subscriptionFormatIsKnown reports whether a format string is one this server
// serves.
//
// Format is validated BEFORE a token is resolved, and a bad one produces the same
// decoy as an unknown token. Validating it afterwards created the sharpest leak
// of all: a valid token with a bad format answered 400 while an invalid token
// answered 404, which told a prober exactly which of its guesses was real.
func subscriptionFormatIsKnown(value string) bool {
	_, err := normalizeProxySubscriptionFormat(strings.TrimSpace(value))
	return err == nil
}
