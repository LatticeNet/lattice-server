package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/outbound"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Operator-saved probe targets (design 27).
//
// lattice-probe ships three built-in targets. Operators save their own here:
// a label, an https URL, GET or HEAD, the statuses that count as a pass, and
// optionally text the body must contain. Reading the list needs vpn:probe,
// like the rest of the probe service; changing it also needs vpncore:admin,
// so an operator who may only run tests cannot point them somewhere new.
//
// A run still names targets by id. For each saved id the server sends the
// stored definition to the probe in custom_targets, and the probe checks it
// again before it fetches anything; the server never forwards a URL a caller
// put in a run. The checks here mirror the probe's so an operator hears
// about a bad URL when saving it, not at the next run; the probe stays the
// authority and adds what only it can do, such as resolving the host.

const (
	// probeTargetsAdminScope gates target_create, target_update and
	// target_delete, on top of probeScope.
	probeTargetsAdminScope = "vpncore:admin"
	// probeTargetsLimit is how many targets the list holds.
	probeTargetsLimit = 32
	// probeTargetIDPrefix starts every saved target's id. lattice-probe
	// reserves it, so a saved id can never name a built-in target.
	probeTargetIDPrefix = "custom-"
	// probeCapabilityCustomTargets is the probe's health capability for
	// accepting custom_targets.
	probeCapabilityCustomTargets = "custom_targets"

	probeTargetMaxEditBytes  = 8 << 10
	probeTargetMaxLabelRunes = 64
	probeTargetMaxURLBytes   = 2048
	probeTargetMaxBodyBytes  = 256
	probeTargetMaxStatuses   = 16
	probeTargetMinHighPort   = 1024

	// apiErrorProbeOutdated: the run names a saved target and the probe
	// does not accept custom targets yet.
	apiErrorProbeOutdated = "probe_outdated"

	auditActionVPNCoreProbeTargetCreate = "vpncore.probe_target.create"
	auditActionVPNCoreProbeTargetUpdate = "vpncore.probe_target.update"
	auditActionVPNCoreProbeTargetDelete = "vpncore.probe_target.delete"
)

// probeTargetSpecialSuffixes are names that resolve only on a local network
// or nowhere, as lattice-probe lists them.
var probeTargetSpecialSuffixes = []string{
	"localhost", "local", "internal", "test", "invalid", "example", "onion", "alt", "arpa",
	"lan", "home", "corp", "intranet", "localdomain",
}

// probeTargetInput is the editable part of a saved target.
type probeTargetInput struct {
	Label        string `json:"label"`
	URL          string `json:"url"`
	Method       string `json:"method"`
	ExpectStatus string `json:"expect_status"`
	BodyContains string `json:"body_contains"`
}

// probeTargetDefinition is what lattice-probe receives for a saved target.
type probeTargetDefinition struct {
	ID           string `json:"id"`
	URL          string `json:"url"`
	Method       string `json:"method"`
	ExpectStatus string `json:"expect_status"`
	BodyContains string `json:"body_contains,omitempty"`
}

// probeTargetView is one entry of the targets answer.
type probeTargetView struct {
	ID     string `json:"id"`
	Source string `json:"source"` // "builtin" or "custom"
	Label  string `json:"label,omitempty"`
	URL    string `json:"url"`
	Method string `json:"method"`
	// Expect is a built-in target's single status, kept for consoles that
	// read only it; ExpectStatus is every target's status set.
	Expect       int        `json:"expect,omitempty"`
	ExpectStatus string     `json:"expect_status"`
	BodyContains string     `json:"body_contains,omitempty"`
	Version      int64      `json:"version,omitempty"`
	CreatedAt    *time.Time `json:"created_at,omitempty"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
}

// probeTargetsAnswer is the targets method's answer.
type probeTargetsAnswer struct {
	Targets []probeTargetView `json:"targets"`
	Custom  probeCustomInfo   `json:"custom"`
}

// probeCustomInfo says whether saved targets can run now, and why not.
type probeCustomInfo struct {
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
	Limit     int    `json:"limit"`
}

func customTargetView(t store.ProbeTarget) probeTargetView {
	created, updated := t.CreatedAt, t.UpdatedAt
	return probeTargetView{
		ID: t.ID, Source: "custom", Label: t.Label, URL: t.URL, Method: t.Method,
		ExpectStatus: t.ExpectStatus, BodyContains: t.BodyContains, Version: t.Version,
		CreatedAt: &created, UpdatedAt: &updated,
	}
}

// probeTargets answers the built-in targets the probe reports, then the
// saved ones, with whether the probe can run the saved ones.
func (s *Server) probeTargets(ctx context.Context) ([]byte, error) {
	callCtx, cancel := context.WithTimeout(ctx, s.probe.callTimeout)
	defer cancel()
	status, body, err := s.probe.do(callCtx, http.MethodGet, "/v1/targets", nil)
	if err != nil {
		return nil, s.probeUnavailable(err)
	}
	var builtin struct {
		Targets []struct {
			ID     string `json:"id"`
			URL    string `json:"url"`
			Expect int    `json:"expect"`
		} `json:"targets"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &builtin) != nil {
		return nil, rpcAPIError(http.StatusBadGateway, model.APIErrorBadGateway, fmt.Sprintf("the probe answered its target list with HTTP %d", status))
	}
	answer := probeTargetsAnswer{Targets: []probeTargetView{}, Custom: probeCustomInfo{Limit: probeTargetsLimit}}
	for _, t := range builtin.Targets {
		answer.Targets = append(answer.Targets, probeTargetView{
			ID: auditTruncate(t.ID, 40), Source: "builtin", URL: auditTruncate(t.URL, probeTargetMaxURLBytes), Method: http.MethodGet,
			Expect: t.Expect, ExpectStatus: strconv.Itoa(t.Expect),
		})
	}
	for _, t := range s.store.ProbeTargets() {
		answer.Targets = append(answer.Targets, customTargetView(t))
	}
	answer.Custom.Supported, answer.Custom.Reason = s.probeTakesCustomTargets(ctx)
	return json.Marshal(answer)
}

// probeTakesCustomTargets reads the probe's health and says whether it
// accepts custom_targets, or why the saved targets cannot run.
func (s *Server) probeTakesCustomTargets(ctx context.Context) (bool, string) {
	view := s.probe.health(ctx, true)
	switch {
	case !view.Available:
		return false, "the probe's health could not be read: " + view.Reason
	case slices.Contains(view.Capabilities, probeCapabilityCustomTargets):
		return true, ""
	default:
		return false, fmt.Sprintf("lattice-probe %s does not run saved targets; a newer lattice-probe does", view.ProbeVersion)
	}
}

// probeTargetEdit serves target_create, target_update and target_delete.
func (s *Server) probeTargetEdit(p principal, method string, request []byte) ([]byte, error) {
	if ok, reason := pluginGatewayScopeAllowed(p, probeTargetsAdminScope); !ok {
		return nil, rpcAPIError(http.StatusForbidden, model.APIErrorCapabilityDenied, "changing saved probe targets needs "+probeTargetsAdminScope+": "+reason)
	}
	if len(request) > probeTargetMaxEditBytes {
		return nil, probeTargetBadRequest(fmt.Sprintf("the request is %d bytes; the limit is %d", len(request), probeTargetMaxEditBytes))
	}
	switch method {
	case "target_create":
		var in probeTargetInput
		if err := decodeProbeTargetRequest(request, &in); err != nil {
			return nil, err
		}
		t, host, err := normalizeProbeTarget(in)
		if err != nil {
			return nil, probeTargetBadRequest(err.Error())
		}
		t.ID = probeTargetIDPrefix + probeTargetSlug(t.Label)
		saved, err := s.store.CreateProbeTarget(t, probeTargetsLimit, s.now())
		if err != nil {
			return nil, probeTargetStoreError(err)
		}
		s.auditProbeTarget(p, auditActionVPNCoreProbeTargetCreate, saved.ID, host)
		return json.Marshal(customTargetView(saved))
	case "target_update":
		var in struct {
			ID      string `json:"id"`
			Version int64  `json:"version"`
			probeTargetInput
		}
		if err := decodeProbeTargetRequest(request, &in); err != nil {
			return nil, err
		}
		t, host, err := normalizeProbeTarget(in.probeTargetInput)
		if err != nil {
			return nil, probeTargetBadRequest(err.Error())
		}
		t.ID = in.ID
		saved, err := s.store.UpdateProbeTarget(t, in.Version, s.now())
		if err != nil {
			return nil, probeTargetStoreError(err)
		}
		s.auditProbeTarget(p, auditActionVPNCoreProbeTargetUpdate, saved.ID, host)
		return json.Marshal(customTargetView(saved))
	case "target_delete":
		var in struct {
			ID      string `json:"id"`
			Version int64  `json:"version"`
		}
		if err := decodeProbeTargetRequest(request, &in); err != nil {
			return nil, err
		}
		removed, err := s.store.DeleteProbeTarget(in.ID, in.Version)
		if err != nil {
			return nil, probeTargetStoreError(err)
		}
		s.auditProbeTarget(p, auditActionVPNCoreProbeTargetDelete, removed.ID, probeTargetHost(removed.URL))
		return json.Marshal(map[string]any{"id": removed.ID, "deleted": true})
	}
	return nil, probeTargetBadRequest("unknown method " + method)
}

func decodeProbeTargetRequest(request []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(request))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return probeTargetBadRequest("the request is not a probe target: " + jsonFieldProblem(err))
	}
	if dec.More() {
		return probeTargetBadRequest("the request carries more than one JSON value")
	}
	return nil
}

// jsonFieldProblem describes a decode error by field, never quoting input.
func jsonFieldProblem(err error) string {
	var typeErr *json.UnmarshalTypeError
	var syntaxErr *json.SyntaxError
	switch {
	case errors.As(err, &typeErr):
		return typeErr.Field + " has the wrong type"
	case errors.As(err, &syntaxErr):
		return "invalid JSON at byte " + strconv.FormatInt(syntaxErr.Offset, 10)
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		return "unknown field " + auditTruncate(strings.TrimPrefix(err.Error(), "json: unknown field "), 48)
	}
	return "invalid JSON"
}

func probeTargetBadRequest(message string) error {
	return rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, message)
}

func probeTargetStoreError(err error) error {
	switch {
	case errors.Is(err, store.ErrProbeTargetNotFound):
		return rpcAPIError(http.StatusNotFound, model.APIErrorNotFound, "no saved probe target has this id; it may have been deleted")
	case errors.Is(err, store.ErrProbeTargetVersion):
		return rpcAPIError(http.StatusConflict, subStoreSvcErrConflict, "someone changed this target since it was read; reload the list and try again")
	case errors.Is(err, store.ErrProbeTargetLimit):
		return rpcAPIError(http.StatusConflict, subStoreSvcErrConflict, fmt.Sprintf("the list holds at most %d saved targets; delete one first", probeTargetsLimit))
	}
	return rpcAPIError(http.StatusInternalServerError, model.APIErrorInternal, "the saved probe targets could not be written")
}

func (s *Server) auditProbeTarget(p principal, action, targetID, host string) {
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: action, Scope: probeTargetsAdminScope, Decision: "allow",
		Metadata: map[string]string{"id": targetID, "host": host},
	})
}

// normalizeProbeTarget checks an edit and returns it in stored form: the
// label trimmed, the method upper case, the status set sorted and merged.
// host is the URL's host[:port] for the audit record.
func normalizeProbeTarget(in probeTargetInput) (t store.ProbeTarget, host string, err error) {
	label := strings.TrimSpace(in.Label)
	switch {
	case label == "":
		return t, "", errors.New("label is required")
	case utf8.RuneCountInString(label) > probeTargetMaxLabelRunes:
		return t, "", fmt.Errorf("label is longer than %d characters", probeTargetMaxLabelRunes)
	case !utf8.ValidString(label) || strings.ContainsFunc(label, unicode.IsControl):
		return t, "", errors.New("label must be printable text")
	}
	host, err = checkProbeTargetURL(in.URL)
	if err != nil {
		return t, "", err
	}
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet && method != http.MethodHead {
		return t, "", errors.New("method must be GET or HEAD")
	}
	expect, err := canonicalExpectStatus(in.ExpectStatus)
	if err != nil {
		return t, "", err
	}
	body := in.BodyContains
	switch {
	case len(body) > probeTargetMaxBodyBytes:
		return t, "", fmt.Errorf("body text is longer than %d bytes", probeTargetMaxBodyBytes)
	case !utf8.ValidString(body) || strings.ContainsFunc(body, unicode.IsControl):
		return t, "", errors.New("body text must be printable text on one line")
	case body != "" && method == http.MethodHead:
		return t, "", errors.New("body text needs GET; a HEAD answer has no body")
	}
	return store.ProbeTarget{Label: label, URL: in.URL, Method: method, ExpectStatus: expect, BodyContains: body}, host, nil
}

// checkProbeTargetURL applies lattice-probe's URL rules for custom targets
// that need no network and returns the host[:port].
func checkProbeTargetURL(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("url is required")
	}
	if len(raw) > probeTargetMaxURLBytes {
		return "", fmt.Errorf("url is longer than %d bytes", probeTargetMaxURLBytes)
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= ' ' || raw[i] >= 0x7f {
			return "", errors.New("url must be printable ASCII without spaces; percent-encode anything else")
		}
	}
	if strings.Contains(raw, "#") {
		return "", errors.New("url must not carry a fragment")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("url does not parse")
	}
	if u.Scheme != "https" {
		return "", errors.New("url must be https")
	}
	if u.Opaque != "" || u.Host == "" {
		return "", errors.New("url must be absolute, with a host")
	}
	if u.User != nil || strings.Contains(u.Host, "@") {
		return "", errors.New("url must not carry credentials")
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", errors.New("url has an empty port")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		switch {
		case err != nil || n < 1 || n > 65535:
			return "", errors.New("url port must be a number from 1 to 65535")
		case len(port) > 1 && port[0] == '0':
			return "", errors.New("url port must not have a leading zero")
		case n != 443 && n < probeTargetMinHighPort:
			return "", fmt.Errorf("port %d is not allowed; use 443 or a port from %d to 65535", n, probeTargetMinHighPort)
		}
	}
	hostname := strings.ToLower(u.Hostname())
	if addr, err := netip.ParseAddr(hostname); err == nil {
		if addr.Zone() != "" || outbound.BlockedAddr(addr) || !addr.Unmap().IsGlobalUnicast() {
			return "", fmt.Errorf("%s is not a public address", addr)
		}
		return strings.ToLower(u.Host), nil
	}
	if err := checkProbeTargetHostName(hostname); err != nil {
		return "", err
	}
	return strings.ToLower(u.Host), nil
}

func checkProbeTargetHostName(h string) error {
	if len(h) > 253 {
		return errors.New("host name is longer than 253 characters")
	}
	if strings.HasSuffix(h, ".") {
		return errors.New("host name must not end with a dot")
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%s is a single-label name, which resolves only on a local network; use a fully qualified name", h)
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' ||
			strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			return fmt.Errorf("%s has an invalid label; labels are 1 to 63 letters, digits and inner hyphens", h)
		}
	}
	last := labels[len(labels)-1]
	if strings.Trim(last, "0123456789") == "" || strings.HasPrefix(last, "0x") {
		return fmt.Errorf("%s ends in a numeric label, which some resolvers read as an IPv4 address", h)
	}
	for _, suffix := range probeTargetSpecialSuffixes {
		if h == suffix || strings.HasSuffix(h, "."+suffix) {
			return fmt.Errorf("%s is under .%s, which resolves only on a local network or nowhere", h, suffix)
		}
	}
	return nil
}

// canonicalExpectStatus reads "204" or "200-299, 301" and returns the set
// sorted with overlapping and adjacent items merged, in the probe's form.
func canonicalExpectStatus(text string) (string, error) {
	text = strings.ReplaceAll(text, " ", "")
	if text == "" {
		return "", errors.New("expected status is required, for example 204 or 200-299,301")
	}
	items := strings.Split(text, ",")
	if len(items) > probeTargetMaxStatuses {
		return "", fmt.Errorf("expected status lists %d items; at most %d are allowed", len(items), probeTargetMaxStatuses)
	}
	type span struct{ lo, hi int }
	spans := make([]span, 0, len(items))
	status := func(s string) (int, error) {
		if len(s) != 3 || strings.Trim(s, "0123456789") != "" {
			return 0, fmt.Errorf("expected status %q is not a three-digit status; write 204 or 200-299,301", auditTruncate(s, 12))
		}
		n, _ := strconv.Atoi(s)
		if n < 100 || n > 599 {
			return 0, fmt.Errorf("expected status %d is not an HTTP status (100 to 599)", n)
		}
		return n, nil
	}
	for _, item := range items {
		lo, hi, isRange := strings.Cut(item, "-")
		low, err := status(lo)
		if err != nil {
			return "", err
		}
		high := low
		if isRange {
			if high, err = status(hi); err != nil {
				return "", err
			}
			if high < low {
				return "", fmt.Errorf("expected status range %d-%d runs backwards", low, high)
			}
		}
		spans = append(spans, span{low, high})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].lo < spans[j].lo })
	merged := spans[:1]
	for _, sp := range spans[1:] {
		last := &merged[len(merged)-1]
		if sp.lo <= last.hi+1 {
			last.hi = max(last.hi, sp.hi)
			continue
		}
		merged = append(merged, sp)
	}
	parts := make([]string, len(merged))
	for i, sp := range merged {
		parts[i] = strconv.Itoa(sp.lo)
		if sp.hi != sp.lo {
			parts[i] += "-" + strconv.Itoa(sp.hi)
		}
	}
	return strings.Join(parts, ","), nil
}

// probeTargetSlug turns a label into the part of an id after the prefix:
// lowercase ASCII letters and digits, other runs as one hyphen, at most 33
// characters, "target" when nothing is left.
func probeTargetSlug(label string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(label) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	slug := strings.Trim(b.String(), "-")
	if len(slug) > 33 {
		slug = strings.TrimRight(slug[:33], "-")
	}
	if slug == "" {
		slug = "target"
	}
	return slug
}

// probeTargetHost is a saved URL's host[:port], or "" when it does not parse.
func probeTargetHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}

// probeTargetDigest is a short hash of a saved target's definition, so an
// audit record can tell two runs of one id apart after an edit without
// carrying the URL's path or query.
func probeTargetDigest(t store.ProbeTarget) string {
	canonical, _ := json.Marshal(probeTargetDefinition{ID: t.ID, URL: t.URL, Method: t.Method, ExpectStatus: t.ExpectStatus, BodyContains: t.BodyContains})
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:6])
}

// resolveProbeRunTargets adds the definitions of the saved targets a run
// names to the request. It returns the request unchanged when the run names
// none, and the audit entries for the ones it adds. A run that brings its
// own custom_targets is refused: definitions come from the saved list only.
func (s *Server) resolveProbeRunTargets(ctx context.Context, request []byte) ([]byte, string, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(request, &fields); err != nil || fields == nil {
		return request, "", nil
	}
	if _, present := fields["custom_targets"]; present {
		return nil, "", probeTargetBadRequest("custom_targets is filled in by the server from the saved targets; name a saved target by its id in targets")
	}
	var ids []string
	if json.Unmarshal(fields["targets"], &ids) != nil {
		return request, "", nil
	}
	var wanted []string
	for _, targetID := range ids {
		if strings.HasPrefix(targetID, probeTargetIDPrefix) && !slices.Contains(wanted, targetID) {
			wanted = append(wanted, targetID)
		}
	}
	if len(wanted) == 0 {
		return request, "", nil
	}
	saved, missing := s.store.ProbeTargetsByID(wanted)
	if len(missing) > 0 {
		return nil, "", probeTargetBadRequest(fmt.Sprintf("target %s is not a saved target; it may have been deleted, so reload the target list", auditTruncate(missing[0], 40)))
	}
	if ok, reason := s.probeTakesCustomTargets(ctx); !ok {
		return nil, "", rpcAPIError(http.StatusConflict, apiErrorProbeOutdated, "saved targets cannot run: "+reason+". Built-in targets still can.")
	}
	defs := make([]probeTargetDefinition, len(saved))
	entries := make([]string, len(saved))
	for i, t := range saved {
		defs[i] = probeTargetDefinition{ID: t.ID, URL: t.URL, Method: t.Method, ExpectStatus: t.ExpectStatus, BodyContains: t.BodyContains}
		entries[i] = t.ID + " " + probeTargetHost(t.URL) + " " + probeTargetDigest(t)
	}
	raw, err := json.Marshal(defs)
	if err != nil {
		return nil, "", err
	}
	fields["custom_targets"] = raw
	// The outbounds go on as written apart from insignificant whitespace:
	// the encoder compacts a raw value and leaves its strings unescaped.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(fields); err != nil {
		return nil, "", err
	}
	out := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if len(out) > probeMaxRequestBytes {
		return nil, "", probeTargetBadRequest(fmt.Sprintf("with the saved targets' definitions the request is %d bytes; the probe takes at most %d, so choose fewer targets", len(out), probeMaxRequestBytes))
	}
	return out, joinBounded(entries, 16, 1024), nil
}
