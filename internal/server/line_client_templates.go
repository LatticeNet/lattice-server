package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// Credential-free client templates for adopted lines (identity-sub P4). The
// store side says why they are persisted; this side builds them from the
// share_url each line's node script reports, which carries the credential of
// the line's first user, and fills an identity's own credential into one.
//
// A template is built by parsing the URI and copying allowlisted parts into a
// fresh record, never by editing the owner's URI, and the record is refused if
// any part of the owner's credential survives in it. Filling it builds a fresh
// URI the same way. Serving per-identity links (identity-sub P5) is not here;
// lineClientURI is the piece it calls.

// lineClientTemplateSyncInterval is how often templates are brought in line
// with the read model. A template changes only when a line's configuration
// does, so a minute of lag costs nothing, and the sync writes only on change.
const lineClientTemplateSyncInterval = time.Minute

// lineClientURIParams are the query parameters a template keeps: connection
// shape, never a credential. flow is left out on purpose: it is part of the
// identity's own credential payload, which fills it back in. obfs-password,
// and anything unknown, is dropped, so a parameter the fork adds later stays
// out until someone decides it is not a secret.
var lineClientURIParams = map[string]bool{
	"security": true, "type": true, "sni": true, "pbk": true, "sid": true, "fp": true, "spx": true,
	"host": true, "path": true, "encryption": true, "alpn": true, "insecure": true, "allowInsecure": true,
	"pinSHA256": true, "congestion_control": true, "serviceName": true, "headerType": true, "mode": true,
}

// lineClientVMessFields are the vmess JSON fields a template keeps, as params.
// id is the credential and ps the owner's label; neither is kept.
var lineClientVMessFields = map[string]bool{
	"aid": true, "net": true, "type": true, "host": true, "path": true, "tls": true, "sni": true, "alpn": true, "fp": true,
}

// lineClientSchemes maps a share URI scheme to the protocol it carries.
var lineClientSchemes = map[string]string{
	"vless": "vless", "vmess": "vmess", "trojan": "trojan", "hysteria2": "hysteria2", "hy2": "hysteria2",
	"tuic": "tuic", "anytls": "anytls", "socks": "socks", "socks5": "socks",
}

// lineClientTemplateFromShareURL builds a line's template from the share URI
// its node reported. protocol is the line's protocol as the read model has
// it; a URI of another scheme is refused rather than trusted.
func lineClientTemplateFromShareURL(shareURL, protocol string) (store.LineClientTemplate, error) {
	shareURL = strings.TrimSpace(shareURL)
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	scheme, body, ok := strings.Cut(shareURL, "://")
	if !ok {
		return store.LineClientTemplate{}, errors.New("share url has no scheme")
	}
	if lineClientSchemes[strings.ToLower(scheme)] != protocol || protocol == "" {
		return store.LineClientTemplate{}, fmt.Errorf("share url scheme %q does not carry line protocol %q", scheme, protocol)
	}
	var t store.LineClientTemplate
	var secrets []string
	var err error
	if protocol == "vmess" {
		t, secrets, err = lineClientVMessTemplate(body)
	} else {
		t, secrets, err = lineClientURITemplate(shareURL, protocol)
	}
	if err != nil {
		return store.LineClientTemplate{}, err
	}
	t.Protocol = protocol
	// The record is checked as it will be stored: no part of the owner's
	// credential may survive in it, whatever parameter it hid in.
	raw, err := json.Marshal(t)
	if err != nil {
		return store.LineClientTemplate{}, err
	}
	for _, secret := range secrets {
		if len(secret) >= 4 && strings.Contains(string(raw), secret) {
			return store.LineClientTemplate{}, errors.New("share url credential survives in the template")
		}
	}
	return t, nil
}

func lineClientURITemplate(shareURL, protocol string) (store.LineClientTemplate, []string, error) {
	var secrets []string
	if protocol == "socks" {
		// socks://BASE64(user:pass)@host:port#name. Standard base64 may hold
		// a slash, which a URL parser takes for the end of the authority, so
		// the userinfo is split off by hand before the rest is parsed.
		scheme, body, _ := strings.Cut(shareURL, "://")
		if i := strings.IndexByte(body, '#'); i >= 0 {
			body = body[:i]
		}
		at := strings.LastIndexByte(body, '@')
		if at <= 0 {
			return store.LineClientTemplate{}, nil, errors.New("socks share url has no credential")
		}
		userinfo := body[:at]
		secrets = append(secrets, userinfo)
		if decoded, ok := decodeLooseBase64(userinfo); ok {
			user, pass, _ := strings.Cut(string(decoded), ":")
			secrets = append(secrets, string(decoded), user, pass)
		}
		shareURL = scheme + "://" + body[at+1:]
	}
	parsed, err := url.Parse(shareURL)
	if err != nil || parsed.Host == "" {
		return store.LineClientTemplate{}, nil, errors.New("share url does not parse")
	}
	if parsed.User != nil {
		secrets = append(secrets, parsed.User.String(), parsed.User.Username())
		if password, ok := parsed.User.Password(); ok {
			secrets = append(secrets, password)
		}
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		return store.LineClientTemplate{}, nil, errors.New("share url has no port")
	}
	t := store.LineClientTemplate{Host: parsed.Hostname(), Port: port}
	if protocol != "socks" {
		for key, values := range parsed.Query() {
			if lineClientURIParams[key] && len(values) > 0 && values[0] != "" {
				if t.Params == nil {
					t.Params = map[string]string{}
				}
				t.Params[key] = values[0]
			}
		}
	}
	return t, secrets, nil
}

func lineClientVMessTemplate(body string) (store.LineClientTemplate, []string, error) {
	payload := body
	if i := strings.IndexAny(payload, "?#"); i >= 0 {
		payload = payload[:i]
	}
	decoded, ok := decodeLooseBase64(payload)
	if !ok {
		return store.LineClientTemplate{}, nil, errors.New("vmess share url does not decode")
	}
	var document map[string]any
	if err := json.Unmarshal(decoded, &document); err != nil || document == nil {
		return store.LineClientTemplate{}, nil, errors.New("vmess share url is not a JSON object")
	}
	text := func(key string) string {
		switch v := document[key].(type) {
		case string:
			return v
		case float64:
			return strconv.FormatInt(int64(v), 10)
		}
		return ""
	}
	port, err := strconv.Atoi(text("port"))
	if err != nil {
		return store.LineClientTemplate{}, nil, errors.New("vmess share url has no port")
	}
	t := store.LineClientTemplate{Host: strings.Trim(text("add"), "[]"), Port: port}
	for key := range lineClientVMessFields {
		if value := text(key); value != "" {
			if t.Params == nil {
				t.Params = map[string]string{}
			}
			t.Params[key] = value
		}
	}
	return t, []string{text("id")}, nil
}

// lineClientURI builds one client URI for an identity on a line: the line's
// template with the payload the identity's credential gives on that line
// (lineUserCredential) filled in, labelled with label. It builds a fresh URI
// from the template's parts and the payload's, the way the template was
// built, and checks that the credential it parses back is the payload's.
func lineClientURI(t store.LineClientTemplate, payload lineUserCredentialPayload, label string) (string, error) {
	hostPort := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	query := url.Values{}
	keys := make([]string, 0, len(t.Params))
	for key := range t.Params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		query.Set(key, t.Params[key])
	}
	fragment := ""
	if label != "" {
		fragment = "#" + url.PathEscape(label)
	}
	switch t.Protocol {
	case "vless":
		if payload.UUID == "" {
			return "", errors.New("vless needs a uuid")
		}
		if payload.Flow != "" {
			query.Set("flow", payload.Flow)
		}
		return lineClientURIWithUser(t.Protocol, url.User(payload.UUID), hostPort, query, fragment, payload.UUID, "")
	case "trojan", "hysteria2", "anytls":
		if payload.Password == "" {
			return "", fmt.Errorf("%s needs a password", t.Protocol)
		}
		return lineClientURIWithUser(t.Protocol, url.User(payload.Password), hostPort, query, fragment, payload.Password, "")
	case "tuic":
		if payload.UUID == "" || payload.Password == "" {
			return "", errors.New("tuic needs a uuid and a password")
		}
		return lineClientURIWithUser(t.Protocol, url.UserPassword(payload.UUID, payload.Password), hostPort, query, fragment, payload.UUID, payload.Password)
	case "socks":
		if payload.Username == "" || payload.Password == "" {
			return "", errors.New("socks needs a username and a password")
		}
		userinfo := base64.StdEncoding.EncodeToString([]byte(payload.Username + ":" + payload.Password))
		return "socks://" + userinfo + "@" + hostPort + fragment, nil
	case "vmess":
		if payload.UUID == "" {
			return "", errors.New("vmess needs a uuid")
		}
		document := map[string]string{"v": "2", "ps": label, "add": t.Host, "port": strconv.Itoa(t.Port), "id": payload.UUID}
		for key, value := range t.Params {
			document[key] = value
		}
		raw, err := json.Marshal(document)
		if err != nil {
			return "", err
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(raw), nil
	default:
		return "", fmt.Errorf("protocol %q has no client URI", t.Protocol)
	}
}

func lineClientURIWithUser(scheme string, user *url.Userinfo, hostPort string, query url.Values, fragment, wantUser, wantPassword string) (string, error) {
	out := (&url.URL{Scheme: scheme, User: user, Host: hostPort, RawQuery: query.Encode()}).String() + fragment
	parsed, err := url.Parse(out)
	if err != nil || parsed.User == nil || parsed.User.Username() != wantUser {
		return "", errors.New("built client uri does not carry the identity's credential")
	}
	if password, _ := parsed.User.Password(); password != wantPassword {
		return "", errors.New("built client uri does not carry the identity's credential")
	}
	return out, nil
}

// lineClientEndpoint is the endpoint a client dials for a line: a node behind
// NAT is reached at its provider's edge on the declared public port, and any
// other at what the node script reported.
func lineClientEndpoint(ln Line, reportedHost string, reportedPort int) (string, int) {
	host, port := reportedHost, reportedPort
	if ln.PublicPort > 0 {
		port = ln.PublicPort
		if edge := strings.TrimSpace(ln.ProviderEdge); edge != "" {
			host = edge
		}
	}
	return host, port
}

// syncLineClientTemplates brings the stored templates in line with every live
// node's adopted lines: each discovered line whose protocol takes per-line
// users and whose share URL yields a credential-free template. A node whose
// inventory is not live, or reported an error, keeps the templates it has.
// It writes only when a template changed.
func (s *Server) syncLineClientTemplates(now time.Time) error {
	byNode := map[string][]store.LineClientTemplate{}
	shareURLs := map[[2]string]string{} // (node, tag) -> share_url
	for _, inv := range s.liveSingBoxInventories(now) {
		if inv.Status != "" && inv.Status != "ok" {
			continue
		}
		byNode[inv.NodeID] = []store.LineClientTemplate{}
		for _, n := range inv.Nodes {
			if n.ShareURL != "" {
				shareURLs[[2]string{inv.NodeID, n.Name}] = n.ShareURL
			}
		}
	}
	if len(byNode) == 0 {
		return nil
	}
	groups, _ := s.lineReadModel()
	for _, group := range groups {
		if _, live := byNode[group.NodeID]; !live {
			continue
		}
		for _, ln := range group.Lines {
			if ln.Managed || ln.Source != "discovered" || !lineUserProtocols[strings.ToLower(strings.TrimSpace(ln.Type))] {
				continue
			}
			shareURL, ok := shareURLs[[2]string{ln.NodeID, ln.Tag}]
			if !ok {
				continue
			}
			t, err := lineClientTemplateFromShareURL(shareURL, ln.Type)
			if err != nil {
				continue
			}
			t.LineHashID, t.NodeID, t.Tag, t.LineUUID = ln.LineHashID, ln.NodeID, ln.Tag, ln.LineUUID
			t.Host, t.Port = lineClientEndpoint(ln, t.Host, t.Port)
			if store.ValidateLineClientTemplate(t) != nil {
				continue
			}
			byNode[group.NodeID] = append(byNode[group.NodeID], t)
		}
	}
	_, err := s.store.SyncLineClientTemplates(byNode, now)
	return err
}

// startLineClientTemplateSync keeps the templates in line with the read
// model on lineClientTemplateSyncInterval.
func (s *Server) startLineClientTemplateSync() {
	go func() {
		ticker := time.NewTicker(lineClientTemplateSyncInterval)
		defer ticker.Stop()
		for range ticker.C {
			if err := s.syncLineClientTemplates(s.now()); err != nil {
				s.logger.Printf("line client templates: %v", err)
			}
		}
	}()
}
