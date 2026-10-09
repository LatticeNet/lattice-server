package server

import (
	"encoding/json"
	"net"
	"slices"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Transport options of a fleet node (design 28, bind check 2).
//
// A transport options object decides more than framing. Its Host header, h2
// host list and xhttp host pick the virtual host a CDN edge forwards to, and
// xhttp's download settings name a second endpoint that receives the same
// credential. A node whose server and port are the line's own could
// otherwise still hand the identity's credential to another origin. So
// every key of every options object is checked: the object must belong to
// the node's network, carry only the keys the URI parsers set from a
// catalogue template's parameters (substoreBindTransportOptions), hold the
// value kind that key holds, and every host it names must be one of the
// line's.

// substoreBindOptKind is what an options key may hold.
type substoreBindOptKind int

const (
	// substoreBindOptScalar: one string, number or boolean.
	substoreBindOptScalar substoreBindOptKind = iota
	// substoreBindOptPath: a string, or a list of strings (http-opts).
	substoreBindOptPath
	// substoreBindOptHosts: a host, or a list of hosts (h2-opts), each one
	// substoreBindHostAllowed admits.
	substoreBindOptHosts
	// substoreBindOptHeaders: an object whose only key is Host, in any case,
	// holding substoreBindOptHosts.
	substoreBindOptHeaders
	// substoreBindOptEarlyDataHeader: the WebSocket early-data header name,
	// which the parsers set to Sec-WebSocket-Protocol for every catalogue
	// template. Any other name would put the first bytes of the connection,
	// the credential among them, in a header of the script's choosing.
	substoreBindOptEarlyDataHeader
)

// substoreBindOptions is one transport options object: the network it
// belongs to and its keys.
type substoreBindOptions struct {
	network string
	keys    map[string]substoreBindOptKind
}

// substoreBindEarlyDataHeader is the early-data header the parsers set.
const substoreBindEarlyDataHeader = "Sec-WebSocket-Protocol"

// substoreBindCheckTransport checks every transport options object of a
// node whose network is network. It returns the field to reject the node
// for ("<object>" or "<object>.<key>"), or "".
func substoreBindCheckTransport(obj substoreNodeObject, network string, t store.LineClientTemplate, row model.LineCatalogueRow) string {
	for _, key := range obj.keys {
		spec, ok := substoreBindTransportOptions[key]
		if !ok {
			continue
		}
		if spec.network != network {
			return key
		}
		opts, err := parseSubstoreNodeObject(obj.values[key])
		if err != nil {
			return key
		}
		for _, name := range opts.keys {
			kind, known := spec.keys[name]
			if !known || !substoreBindOptionValid(kind, opts.values[name], t, row) {
				return substoreBindOptionField(key, name)
			}
		}
	}
	return ""
}

// substoreBindOptionField names a refused options key for a reason, or the
// object alone when the key is not a name a reason may quote.
func substoreBindOptionField(object, key string) string {
	if field := object + "." + key; substoreBindFieldName.MatchString(field) {
		return field
	}
	return object
}

// substoreBindOptionValid reports whether value is of kind and, where the
// kind names hosts, whether every host is the line's.
func substoreBindOptionValid(kind substoreBindOptKind, value json.RawMessage, t store.LineClientTemplate, row model.LineCatalogueRow) bool {
	switch kind {
	case substoreBindOptScalar:
		var scalar any
		if json.Unmarshal(value, &scalar) != nil {
			return false
		}
		switch scalar.(type) {
		case string, float64, bool:
			return true
		}
		return false
	case substoreBindOptPath:
		_, ok := substoreBindStrings(value)
		return ok
	case substoreBindOptHosts:
		hosts, ok := substoreBindStrings(value)
		if !ok {
			return false
		}
		for _, host := range hosts {
			if !substoreBindHostAllowed(host, t, row) {
				return false
			}
		}
		return true
	case substoreBindOptHeaders:
		headers, err := parseSubstoreNodeObject(value)
		if err != nil {
			return false
		}
		for _, name := range headers.keys {
			if !strings.EqualFold(name, "host") || !substoreBindOptionValid(substoreBindOptHosts, headers.values[name], t, row) {
				return false
			}
		}
		return true
	case substoreBindOptEarlyDataHeader:
		var name string
		return json.Unmarshal(value, &name) == nil && strings.EqualFold(name, substoreBindEarlyDataHeader)
	}
	return false
}

// substoreBindStrings reads a string or a list of strings.
func substoreBindStrings(value json.RawMessage) ([]string, bool) {
	var one string
	if json.Unmarshal(value, &one) == nil {
		return []string{one}, true
	}
	var list []string
	if json.Unmarshal(value, &list) == nil && list != nil {
		return list, true
	}
	return nil, false
}

// substoreBindHostAllowed reports whether a host a transport option names
// (an HTTP Host, an h2 host, an xhttp host) is the line's: empty, one of the
// names the line may be dialled by (substoreBindNames), the template's own
// host address, or a host the template itself sets (its host parameter,
// split on commas as the parsers split an h2 list, and its sni). Names
// compare without case.
func substoreBindHostAllowed(host string, t store.LineClientTemplate, row model.LineCatalogueRow) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return true
	}
	allowed := substoreBindNames(t, row)
	allowed = append(allowed, t.Host, t.Params["sni"])
	allowed = append(allowed, strings.Split(t.Params["host"], ",")...)
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return slices.ContainsFunc(allowed, func(candidate string) bool {
			other := net.ParseIP(strings.Trim(strings.TrimSpace(candidate), "[]"))
			return other != nil && other.Equal(ip)
		})
	}
	return slices.ContainsFunc(allowed, func(candidate string) bool {
		candidate = strings.TrimSpace(candidate)
		return candidate != "" && strings.EqualFold(candidate, host)
	})
}
