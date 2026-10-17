package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/groups"
	"github.com/LatticeNet/lattice-server/internal/proxycore"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// The line catalogue (design 28), served as method catalogue of
// latticenet.vpn-core/lines under vpncore:read.
//
// One row per line the read model holds with a line_uuid: the line joined
// with its node's geo, machine profile, groups, tags and DDNS names, the
// addresses its host names resolved to at the last template sync, its status
// and service state, its place in a chain, a probe block (null until design
// 27's P2 history records lines), the named identity's usage, and its
// credential-free client template. A committed chain root carries the
// composed entry template that compose builds, without the credential.
//
// Credential-free is the contract, and this file keeps it two ways. Every
// template passes the SDK's allowlist and the template store's sync-time
// fragment-survival refusal against the owner's credential, and, when the
// node still reports the line's share URL, that refusal again. When the
// request names an identity, every row is also refused any whole part of
// that identity's credential four bytes or longer, in any of the encodings
// lineCatalogueSecrets lists: a row whose template carries one is served
// without its template, a row that still carries one is withheld, and a page
// that still carries one is refused whole. Without an identity there is no
// identity to screen for; the row's free-text fields (names, tags, group
// ids) are the operator's own labels.
//
// A Reality line's public key (pbk) and short id (sid) are public material by
// decision, not credentials: both are the line's, the same for every
// identity bound to it, carried in every subscriber's link, returned to the
// same plugin by compose today, and the bind step requires a planned node's
// short-id to equal the template's. They travel only as a template's pbk and
// sid params, and sid only in a short id's shape (at most eight bytes of
// hex), so that slot cannot carry anything else.
//
// The selector is pushed down here: set fields AND, the values of one field
// OR, and a field this core does not know, or a selector given twice, is
// refused with the fields it does know. Rows are paged by an offset cursor.
// catalogue_version hashes the identity named and the encoded rows of the
// whole selection, so it is the same on every page of one read and moves
// whenever any selected row does.

const (
	lineCatalogueVersionPrefix = "lcv1-"
	lineCatalogueCursorPrefix  = "lcc1."
	// apiErrorCatalogueSelectorUnsupported refuses a selector field this core
	// does not evaluate, and a selector it cannot read one way only: given
	// twice, or naming a field twice. The message ends in "selector_fields: "
	// followed by the comma-separated fields it does evaluate.
	apiErrorCatalogueSelectorUnsupported = "catalogue_selector_unsupported"
	// apiErrorCatalogueCredential refuses a page in which a credential
	// fragment survived every per-row check. It cannot happen while those
	// checks hold; it is the last line, not a path.
	apiErrorCatalogueCredential = "catalogue_credential_withheld"
	// lineCatalogueMaxChainHops bounds the walk to a chain's exit.
	lineCatalogueMaxChainHops = 64
	// lineCatalogueMaxAddresses bounds a row's Addresses.
	lineCatalogueMaxAddresses = 32
	// lineCatalogueComposeFingerprint and lineCatalogueComposeFlow are what
	// compose puts in every composed entry (subscription_compose.go). The
	// flow is the identity's; a binder fills this default when the
	// identity's vless credential names none.
	lineCatalogueComposeFingerprint = "chrome"
	lineCatalogueComposeFlow        = "xtls-rprx-vision"
	// lineCatalogueValidationUUID stands in for a credential when compose's
	// endpoint builder checks a root's public material, and for a line in a
	// row built only to check one field.
	lineCatalogueValidationUUID = "00000000-0000-4000-8000-000000000000"
)

// lineCatalogueSelectorFields is what this core evaluates: every selector
// field the SDK defines.
var lineCatalogueSelectorFields = model.LineCatalogueSelectorFields()

// substoreCatalogueState is the server's state for the native Sub-Store's
// fleet reads (design 28): the names the catalogue resolves on the template
// sync's clock, the builds a paged read is served from, and what the
// fleet-dependency answers need (share_fleet_depends.go).
type substoreCatalogueState struct {
	names lineCatalogueNames
	pages lineCataloguePageCache
	deps  fleetDependsState
	// bind is the validate-and-bind step's state (substore_bind_serve.go).
	bind substoreBindState
}

// lineCatalogue is one build of the catalogue: every line with a line_uuid,
// in catalogue order (node id, then listen port, then tag, as the read model
// sorts them). Rows, lines and templates are parallel. Nothing in it may be
// mutated by a caller.
type lineCatalogue struct {
	identityID string
	at         time.Time
	rows       []model.LineCatalogueRow
	encoded    [][]byte
	lines      []Line
	// templates is the bind form of each row's Template: what lineClientURI
	// fills. Nil where the row has no template.
	templates []*store.LineClientTemplate
	index     map[string]int
}

// Row returns one line's row as the catalogue serves it.
func (c *lineCatalogue) Row(lineUUID string) (model.LineCatalogueRow, bool) {
	i, ok := c.index[lineUUID]
	if !ok {
		return model.LineCatalogueRow{}, false
	}
	return c.rows[i], true
}

// Line returns the read-model line behind a row.
func (c *lineCatalogue) Line(lineUUID string) (Line, bool) {
	i, ok := c.index[lineUUID]
	if !ok {
		return Line{}, false
	}
	return c.lines[i], true
}

// BindTemplate returns the credential-free template behind a row's Template,
// in the form lineClientURI fills with lineUserCredential's payload. ok is
// false when the row has no template, which the binder treats as a line it
// cannot bind. For a committed chain root it is the composed entry template;
// compose fills the vless flow with lineCatalogueComposeFlow when the
// identity's credential names none, and a binder must do the same.
func (c *lineCatalogue) BindTemplate(lineUUID string) (store.LineClientTemplate, bool) {
	i, ok := c.index[lineUUID]
	if !ok || c.templates[i] == nil {
		return store.LineClientTemplate{}, false
	}
	t := *c.templates[i]
	t.Params = maps.Clone(t.Params)
	t.Dropped = slices.Clone(t.Dropped)
	return t, true
}

// Select returns the rows a selector selects: in the selector's line order
// when it names lines, else in catalogue order. A nil selector selects every
// row. The selector must already be valid.
func (c *lineCatalogue) Select(sel *model.LineCatalogueSelector) []model.LineCatalogueRow {
	indexes := c.selectIndexes(sel)
	out := make([]model.LineCatalogueRow, 0, len(indexes))
	for _, i := range indexes {
		out = append(out, c.rows[i])
	}
	return out
}

func (c *lineCatalogue) selectIndexes(sel *model.LineCatalogueSelector) []int {
	if sel == nil {
		out := make([]int, len(c.rows))
		for i := range out {
			out[i] = i
		}
		return out
	}
	var out []int
	if len(sel.LineUUIDs) > 0 {
		for _, id := range sel.LineUUIDs {
			if i, ok := c.index[id]; ok && lineCatalogueMatches(&c.rows[i], sel, c.at) {
				out = append(out, i)
			}
		}
		return out
	}
	for i := range c.rows {
		if lineCatalogueMatches(&c.rows[i], sel, c.at) {
			out = append(out, i)
		}
	}
	return out
}

// lineCatalogueMatches evaluates every selector field but the line list. It
// is the SDK's LineCatalogueSelectorMatches, the pushdown contract as one
// function, so core, the plugin's evaluator and the differential test run the
// same code. The one rule it adds to the server's former body: a relay whose
// chain is Unresolved has an unknown geo, so countries and regions never
// match it (S2 plan section 2.5).
func lineCatalogueMatches(row *model.LineCatalogueRow, sel *model.LineCatalogueSelector, now time.Time) bool {
	return model.LineCatalogueSelectorMatches(row, sel, now)
}

// buildLineCatalogue builds the catalogue now. identityID, when set, names
// the identity whose per-line usage each row carries and whose credential no
// row may carry; an unknown identity is refused.
func (s *Server) buildLineCatalogue(identityID string) (*lineCatalogue, error) {
	now := s.now().UTC()
	var identity *VpnUser
	if identityID != "" {
		u, ok := s.getVpnUser(identityID)
		if !ok {
			return nil, rpcAPIError(http.StatusNotFound, model.APIErrorNotFound, "catalogue identity_id names no identity")
		}
		identity = &u
	}
	lineGroups, byHash := s.lineReadModel()

	nodeList := s.store.Nodes()
	nodes := make(map[string]model.Node, len(nodeList))
	for _, n := range nodeList {
		nodes[n.ID] = n
	}
	resolvedGroups := groups.ResolveAll(s.store.Groups(), nodeList)
	machines := lineCatalogueMachines(s.store.MachineProfiles())
	names := s.substoreCatalogue.names.snapshot()
	ddns := lineCatalogueDDNS(s.store.DDNSProfiles(), nodes, lineCatalogueNodeEdges(lineGroups), names)
	templates := map[string]store.LineClientTemplate{}
	for _, t := range s.store.LineClientTemplates() {
		templates[t.LineHashID] = t
	}
	shareURLs := map[[2]string]string{}
	for _, inv := range s.liveSingBoxInventories(now) {
		for _, n := range inv.Nodes {
			if n.ShareURL != "" {
				shareURLs[[2]string{inv.NodeID, n.Name}] = n.ShareURL
			}
		}
	}

	// Catalogue order, one line per line_uuid and per line_hash_id.
	lines := make([]Line, 0, len(byHash))
	uuidByHash := make(map[string]string, len(byHash))
	seenUUID := make(map[string]bool, len(byHash))
	for _, g := range lineGroups {
		for _, ln := range g.Lines {
			uuid := strings.ToLower(strings.TrimSpace(ln.LineUUID))
			if !validLineUUIDv4(uuid) || seenUUID[uuid] {
				continue
			}
			if _, dup := uuidByHash[ln.LineHashID]; dup {
				continue
			}
			seenUUID[uuid] = true
			ln.LineUUID = uuid
			uuidByHash[ln.LineHashID] = uuid
			lines = append(lines, ln)
		}
	}
	nodeNames := make(map[string]string, len(lineGroups))
	for _, g := range lineGroups {
		nodeNames[g.NodeID] = g.NodeName
	}
	chains := s.lineCatalogueChains(lines, uuidByHash, nodes)

	var usage map[string]int64
	var usageFrom, usageTo time.Time
	var identitySecrets lineCatalogueSecrets
	if identity != nil {
		usage, usageFrom, usageTo = s.lineCatalogueIdentityUsage(*identity, now)
		identitySecrets = newLineCatalogueSecrets(lineCatalogueIdentitySecrets(*identity))
	}

	// newLineCatalogueSecrets is a pure function of the secrets it is given,
	// and lines of one node often share their owner's credential, so one
	// build computes each set once.
	var ownerSets sync.Map
	ownerSecrets := func(secrets []string) lineCatalogueSecrets {
		key := lineCatalogueSecretsKey(secrets)
		if set, ok := ownerSets.Load(key); ok {
			return set.(lineCatalogueSecrets)
		}
		set := newLineCatalogueSecrets(secrets)
		ownerSets.Store(key, set)
		return set
	}
	// Each line's row depends on nothing but the line and the inputs read
	// above, so rows are built in parallel and gathered in catalogue order;
	// the catalogue and its withheld list are what building them one by one
	// gives.
	type builtRow struct {
		row          model.LineCatalogueRow
		raw          []byte
		keptTemplate bool
		bind         *store.LineClientTemplate
		err          error
	}
	built := make([]builtRow, len(lines))
	substoreBindEach(len(lines), func(i int) {
		ln := lines[i]
		node := nodes[ln.NodeID]
		row := model.LineCatalogueRow{
			LineUUID: ln.LineUUID, LineHashID: ln.LineHashID, NodeID: ln.NodeID,
			NodeName: firstNonEmpty(nodeNames[ln.NodeID], ln.NodeID), Name: ln.Name,
			NodeTags: lineCatalogueTexts(node.Tags), GroupIDs: lineCatalogueTexts(groups.GroupIDsForNode(ln.NodeID, resolvedGroups)),
			Geo: lineCatalogueGeo(node.Geo), Machine: machines[ln.NodeID], DDNSNames: ddns[ln.NodeID],
			Protocol:  firstNonEmpty(strings.ToLower(strings.TrimSpace(ln.Type)), "unknown"),
			Transport: strings.ToLower(strings.TrimSpace(ln.Transport)), Security: strings.ToLower(strings.TrimSpace(ln.Security)),
			PublicHost: strings.TrimSpace(ln.PublicHost), PublicPort: ln.PublicPort, ProviderEdge: strings.TrimSpace(ln.ProviderEdge),
			Managed: ln.Managed, Overlay: ln.Overlay, OverlayStatus: strings.TrimSpace(ln.OverlayStatus),
			Status: strings.TrimSpace(ln.Status), ServiceState: strings.TrimSpace(ln.ServiceState),
			Chain: chains.chain(ln.LineUUID),
			// Label is the entry label bind shows for the line, from the
			// same call (substore_bind.go), so the plugin names a fleet node
			// by it and never re-derives it.
			Label: identityLinkEntryLabel(firstNonEmpty(nodeNames[ln.NodeID], ln.NodeID), identityLinkLineName(ln)),
		}
		if row.PublicPort < 0 || row.PublicPort > 65535 {
			row.PublicPort = 0
		}
		bind := chains.composedTemplate(ln.LineUUID)
		if !chains.root(ln.LineUUID) {
			if t, ok := templates[ln.LineHashID]; ok && t.NodeID == ln.NodeID && t.LineUUID == ln.LineUUID {
				bind = &t
			}
		}
		if bind != nil {
			template, err := lineCatalogueTemplate(*bind)
			// Defense in depth: the template store already refused, at
			// sync time, a template carrying the owner's credential from
			// the share URL it was built from. This repeats the check
			// against the share URL a live node reports now; a node that
			// no longer reports one leaves the sync-time refusal standing.
			if err == nil && !chains.root(ln.LineUUID) {
				if shareURL := shareURLs[[2]string{ln.NodeID, ln.Tag}]; shareURL != "" {
					owner := ownerSecrets(lineClientShareURLSecrets(shareURL, bind.Protocol))
					if raw, _ := json.Marshal(template); owner.in(raw) {
						err = errors.New("the owner's credential survives in the template")
					}
				}
			}
			if err != nil {
				bind = nil
			} else {
				row.Template = template
			}
		}
		if row.Security == "" && bind != nil {
			row.Security = lineCatalogueTemplateSecurity(*bind)
		}
		hosts := []string{row.PublicHost, row.ProviderEdge}
		if bind != nil {
			hosts = append(hosts, bind.Host)
		}
		row.Addresses = lineCatalogueAddresses(hosts, names)
		if identity != nil {
			row.Usage = &model.LineCatalogueUsage{IdentityID: identity.ID, UsedBytes: usage[ln.LineHashID], From: usageFrom, To: usageTo}
		}
		raw, keptTemplate, err := finishLineCatalogueRow(&row, identitySecrets)
		built[i] = builtRow{row: row, raw: raw, keptTemplate: keptTemplate, bind: bind, err: err}
	})
	c := &lineCatalogue{identityID: identityID, at: now, index: make(map[string]int, len(lines)),
		rows: make([]model.LineCatalogueRow, 0, len(lines)), encoded: make([][]byte, 0, len(lines)),
		lines: make([]Line, 0, len(lines)), templates: make([]*store.LineClientTemplate, 0, len(lines))}
	var withheld []string
	for i, ln := range lines {
		b := built[i]
		if b.err != nil {
			withheld = append(withheld, ln.LineUUID+": "+b.err.Error())
			continue
		}
		bind := b.bind
		if !b.keptTemplate {
			bind = nil
		}
		c.index[ln.LineUUID] = len(c.rows)
		c.rows = append(c.rows, b.row)
		c.encoded = append(c.encoded, b.raw)
		c.lines = append(c.lines, ln)
		c.templates = append(c.templates, bind)
	}
	if len(withheld) > 0 {
		s.logger.Printf("line catalogue: withheld %d row(s) that failed validation; first %s", len(withheld), withheld[0])
	}
	return c, nil
}

// finishLineCatalogueRow validates and encodes a row. A row that fails with
// its template is tried once more without it, which leaves the line in the
// catalogue but unbindable; keptTemplate reports which. A row that fails
// without a template too is withheld.
func finishLineCatalogueRow(row *model.LineCatalogueRow, identity lineCatalogueSecrets) (raw []byte, keptTemplate bool, err error) {
	for {
		// Validate's size bound encodes the row; ValidateTrustingEncoding
		// reads it from the encoding the row is served as, which is raw
		// right here, so each row is encoded once. A row that does not
		// encode is judged by Validate, which words the error as before.
		raw, err = json.Marshal(row)
		if err != nil {
			if verr := row.Validate(); verr != nil {
				err = verr
			}
		} else {
			err = row.ValidateTrustingEncoding(raw)
		}
		if err == nil {
			if identity.in(raw) {
				err = errors.New("the named identity's credential survives in the row")
			}
			if err == nil {
				return raw, row.Template != nil, nil
			}
		}
		if row.Template == nil {
			return nil, false, err
		}
		row.Template = nil
	}
}

// lineCatalogueTemplate is a stored template as a catalogue row carries it,
// with its digest, checked against the SDK's allowlist. A sid that is not a
// Reality short id is refused.
func lineCatalogueTemplate(t store.LineClientTemplate) (*model.LineCatalogueTemplate, error) {
	if sid, ok := t.Params["sid"]; ok && !lineCatalogueShortIDValid(sid) {
		return nil, errors.New("template sid is not a reality short id")
	}
	out := &model.LineCatalogueTemplate{Protocol: t.Protocol, Host: t.Host, Port: t.Port,
		Params: maps.Clone(t.Params), Dropped: slices.Clone(t.Dropped)}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	out.Digest = "sha256:" + hex.EncodeToString(sum[:])
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return out, nil
}

// lineCatalogueShortIDValid is proxycore's Reality short id rule: an even
// number of hex digits, at most sixteen. Empty is a valid short id.
func lineCatalogueShortIDValid(sid string) bool {
	_, err := hex.DecodeString(sid)
	return err == nil && len(sid) <= 16
}

// lineClientShareURLSecrets returns the credential parts of a share URL, as
// the template builder finds them, so a template can be checked against the
// URL it came from.
func lineClientShareURLSecrets(shareURL, protocol string) []string {
	shareURL = strings.TrimSpace(shareURL)
	_, body, ok := strings.Cut(shareURL, "://")
	if !ok {
		return nil
	}
	var secrets []string
	if protocol == "vmess" {
		_, secrets, _ = lineClientVMessTemplate(body)
	} else {
		_, secrets, _ = lineClientURITemplate(shareURL, protocol)
	}
	return secrets
}

// lineCatalogueIdentitySecrets are the parts of an identity's credentials a
// row must never carry.
func lineCatalogueIdentitySecrets(u VpnUser) []string {
	var out []string
	for _, c := range u.Credentials {
		out = append(out, c.UUID, c.Password)
	}
	return out
}

// lineCatalogueSecrets finds whole credential parts four bytes or longer in
// an encoded row, ignoring case, in every form a row could carry one in:
// raw, percent-encoded for a query or a path, base64 of the part on its own
// (either alphabet, padded or not), and for a uuid also without its dashes
// and as base64 of its sixteen bytes; each of those also JSON-escaped, which
// is how a quote, a backslash or an HTML character appears in JSON.
//
// A slice of a part is not looked for. Runs of four or eight hex digits of a
// uuid occur by chance in the digests and line uuids every row carries, so a
// slice check would withhold healthy rows, and a slice of a uuid or password
// does not let a client connect.
type lineCatalogueSecrets struct{ needles [][]byte }

// lineCatalogueSecretsKey is the memo key of a secret list: each secret
// prefixed by its length, so two different lists never share a key. A join
// on a separator byte did not hold that: ["ab\x00cd"] and ["ab", "cd"]
// joined the same, and the second line would have been checked against the
// first line's needles.
func lineCatalogueSecretsKey(secrets []string) string {
	var b strings.Builder
	for _, secret := range secrets {
		b.WriteString(strconv.Itoa(len(secret)))
		b.WriteByte(':')
		b.WriteString(secret)
	}
	return b.String()
}

func newLineCatalogueSecrets(secrets []string) lineCatalogueSecrets {
	var m lineCatalogueSecrets
	seen := map[string]bool{}
	for _, secret := range secrets {
		if len(secret) < 4 {
			continue
		}
		for _, form := range lineCatalogueSecretForms(secret) {
			if needle := strings.ToLower(form); !seen[needle] {
				seen[needle] = true
				m.needles = append(m.needles, []byte(needle))
			}
		}
	}
	return m
}

// lineCatalogueSecretForms is one credential part in every form
// lineCatalogueSecrets looks for. Padded base64 is the unpadded form plus
// '=', so the unpadded form finds both.
func lineCatalogueSecretForms(secret string) []string {
	raws := [][]byte{[]byte(secret)}
	forms := []string{secret, url.QueryEscape(secret), url.PathEscape(secret)}
	if dashless := strings.ReplaceAll(secret, "-", ""); dashless != secret {
		if id, err := hex.DecodeString(dashless); err == nil && len(id) == 16 {
			forms = append(forms, dashless)
			raws = append(raws, id)
		}
	}
	for _, raw := range raws {
		forms = append(forms, base64.RawStdEncoding.EncodeToString(raw), base64.RawURLEncoding.EncodeToString(raw))
	}
	for _, form := range slices.Clone(forms) {
		// A form with nothing JSON escapes is its own escaped form, which
		// would only repeat it.
		if !strings.ContainsFunc(form, jsonEscapes) {
			continue
		}
		if escaped, err := json.Marshal(form); err == nil {
			forms = append(forms, string(escaped[1:len(escaped)-1]))
		}
	}
	return forms
}

// jsonEscapes reports whether json.Marshal writes r other than as itself:
// the quote, the backslash, a control character, the three HTML characters,
// U+2028, U+2029 and the replacement character an invalid byte becomes.
func jsonEscapes(r rune) bool {
	return r < 0x20 || r == '"' || r == '\\' || r == '<' || r == '>' || r == '&' || r == '\u2028' || r == '\u2029' || r == utf8.RuneError
}

func (m lineCatalogueSecrets) in(raw []byte) bool {
	if len(m.needles) == 0 {
		return false
	}
	lower := bytes.ToLower(raw)
	for _, needle := range m.needles {
		if bytes.Contains(lower, needle) {
			return true
		}
	}
	return false
}

// lineCatalogueIdentityUsage sums the identity's traffic per line over its
// current period: its monthly quota period, or the calendar month when it
// has none.
func (s *Server) lineCatalogueIdentityUsage(u VpnUser, now time.Time) (map[string]int64, time.Time, time.Time) {
	start, end, ok := vpnUserQuotaPeriod(u, now)
	if !ok {
		start, end = quotaPeriodBounds(now, 1)
	}
	_, rows := s.periodUsage(u.ID, start, now)
	byHash := map[string]int64{}
	for _, row := range rows {
		for hash, line := range row.ByLine {
			byHash[hash] += line.Uplink + line.Downlink
		}
	}
	return byHash, start, end
}

// lineCatalogueGeo copies a node's geo without its bookkeeping fields, which
// move when the geo is re-read and would move catalogue_version with them.
func lineCatalogueGeo(geo *model.NodeGeo) *model.NodeGeo {
	if geo == nil {
		return nil
	}
	out := *geo
	out.Source, out.UpdatedAt = "", time.Time{}
	if out == (model.NodeGeo{}) {
		return nil
	}
	return &out
}

// lineCatalogueTexts drops empty values, which a row may not carry.
func lineCatalogueTexts(values []string) []string {
	var out []string
	for _, v := range values {
		if strings.TrimSpace(v) != "" && len(v) <= model.MaxSubscriptionURIBytes {
			out = append(out, v)
		}
	}
	return out
}

// lineCatalogueMachines picks one machine profile per node, the one that
// renews soonest, reduced to what filters use.
func lineCatalogueMachines(profiles []model.MachineProfile) map[string]*model.LineCatalogueMachine {
	chosen := map[string]model.MachineProfile{}
	for _, p := range profiles {
		node := strings.TrimSpace(p.NodeID)
		if node == "" {
			continue
		}
		current, ok := chosen[node]
		if !ok || lineCatalogueRenewsFirst(p, current) {
			chosen[node] = p
		}
	}
	out := make(map[string]*model.LineCatalogueMachine, len(chosen))
	for node, p := range chosen {
		m := model.LineCatalogueMachine{Vendor: strings.TrimSpace(p.Vendor), Region: strings.TrimSpace(p.Region)}
		if !p.NextRenewal.IsZero() {
			m.NextRenewal = p.NextRenewal.UTC()
		}
		if m != (model.LineCatalogueMachine{}) {
			out[node] = &m
		}
	}
	return out
}

func lineCatalogueRenewsFirst(a, b model.MachineProfile) bool {
	switch {
	case a.NextRenewal.IsZero() != b.NextRenewal.IsZero():
		return !a.NextRenewal.IsZero()
	case !a.NextRenewal.Equal(b.NextRenewal):
		return a.NextRenewal.Before(b.NextRenewal)
	}
	return a.ID < b.ID
}

// lineCatalogueDDNS lists each node's DDNS names, sorted, each verified by a
// DNS answer the last sync read, never by stored configuration:
//
//   - a name an address profile publishes is verified when it resolved to the
//     node's current public address;
//   - a name a cname profile publishes is verified when its resolved addresses
//     intersect the resolved addresses of a provider edge of the node's lines,
//     and its Target is that edge. The edge the profile names as its target is
//     tried first, then the node's other edges in order. Comparing the
//     profile's last published target with the edge instead would show a
//     hijacked CNAME as verified (S2 plan section 2.6), and a cname name is
//     never verified by the node's own public address, which for a node behind
//     NAT is the provider's shared egress.
//
// A name both kinds of profile publish is verified by either rule; only the
// cname rule sets Target.
func lineCatalogueDDNS(profiles []model.DDNSProfile, nodes map[string]model.Node, edges map[string][]string, names map[string][]string) map[string][]model.LineCatalogueDDNSName {
	type published struct {
		address bool
		targets []string // the cname targets of the profiles that publish it
		cname   bool
	}
	byNode := map[string]map[string]*published{}
	for _, profile := range profiles {
		nodeID := strings.TrimSpace(profile.NodeID)
		if nodeID == "" {
			continue
		}
		cname := strings.EqualFold(strings.TrimSpace(profile.RecordType), "cname")
		for _, domain := range profile.Domains {
			name := lineCatalogueNameKey(domain)
			if !lineCatalogueDDNSNameValid(name) {
				continue
			}
			if byNode[nodeID] == nil {
				byNode[nodeID] = map[string]*published{}
			}
			entry := byNode[nodeID][name]
			if entry == nil {
				entry = &published{}
				byNode[nodeID][name] = entry
			}
			if cname {
				entry.cname = true
				if target := lineCatalogueNameKey(profile.CNAMETarget); target != "" {
					entry.targets = append(entry.targets, target)
				}
			} else {
				entry.address = true
			}
		}
	}
	out := make(map[string][]model.LineCatalogueDDNSName, len(byNode))
	for nodeID, set := range byNode {
		public := map[string]bool{}
		node := nodes[nodeID]
		for _, raw := range []string{node.PublicIP, node.PublicIPv6} {
			if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil {
				public[ip.String()] = true
			}
		}
		list := make([]model.LineCatalogueDDNSName, 0, len(set))
		for name, how := range set {
			entry := model.LineCatalogueDDNSName{Name: name}
			resolved := names[name]
			if how.address {
				entry.Verified = slices.ContainsFunc(resolved, func(addr string) bool { return public[addr] })
			}
			if how.cname {
				if edge := lineCatalogueCNAMEEdge(resolved, how.targets, edges[nodeID], names); edge != "" {
					entry.Verified, entry.Target = true, edge
				}
			}
			list = append(list, entry)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		out[nodeID] = list
	}
	return out
}

// lineCatalogueCNAMEEdge returns the provider edge a cname name resolved to:
// the first edge, the profile's own targets first, whose resolved addresses
// share one with the name's. "" when none does or the name did not resolve.
func lineCatalogueCNAMEEdge(resolved, targets, edges []string, names map[string][]string) string {
	if len(resolved) == 0 || len(edges) == 0 {
		return ""
	}
	ordered := make([]string, 0, len(edges))
	for _, edge := range edges {
		if slices.ContainsFunc(targets, func(target string) bool { return strings.EqualFold(target, edge) }) {
			ordered = append(ordered, edge)
		}
	}
	for _, edge := range edges {
		if !slices.Contains(ordered, edge) {
			ordered = append(ordered, edge)
		}
	}
	for _, edge := range ordered {
		for _, addr := range lineCatalogueAddresses([]string{edge}, names) {
			if slices.Contains(resolved, addr) {
				return edge
			}
		}
	}
	return ""
}

// lineCatalogueNodeEdges is each node's distinct provider edges, in the
// order of its lines.
func lineCatalogueNodeEdges(lineGroups []LineGroup) map[string][]string {
	out := map[string][]string{}
	for _, g := range lineGroups {
		for _, ln := range g.Lines {
			edge := strings.TrimSpace(ln.ProviderEdge)
			if edge != "" && !slices.Contains(out[ln.NodeID], edge) {
				out[ln.NodeID] = append(out[ln.NodeID], edge)
			}
		}
	}
	return out
}

// lineCatalogueTemplateSecurity is a line's security layer as its client
// template states it, for a line whose inventory leaves the column empty
// (every discovered line today): the URI template's security parameter, or a
// vmess template's tls field. "" when the template states none or states it
// in a form a row cannot carry.
func lineCatalogueTemplateSecurity(t store.LineClientTemplate) string {
	key := "security"
	if strings.EqualFold(t.Protocol, "vmess") {
		key = "tls"
	}
	value := strings.ToLower(strings.TrimSpace(t.Params[key]))
	if value == "none" || !lineCatalogueTokenValid(value) {
		return ""
	}
	return value
}

// lineCatalogueTokenValid checks one enum-like column value by the SDK's own
// row rule.
func lineCatalogueTokenValid(value string) bool {
	if value == "" {
		return false
	}
	row := model.LineCatalogueRow{LineUUID: lineCatalogueValidationUUID, LineHashID: "h", NodeID: "n", Protocol: "p",
		Chain: model.LineCatalogueChain{Role: model.LineChainRoleSingle}, Security: value}
	return lineCatalogueProbeRowValid(row)
}

// lineCatalogueProbeRowValid is the SDK's row rule on a probe row that
// carries one value to check. A probe row is far under the row's size
// bound, so its fields are all the rule can refuse, and ValidateFields
// checks them without encoding the row (a catalogue build checks one value
// per line).
func lineCatalogueProbeRowValid(row model.LineCatalogueRow) bool {
	return row.ValidateFields() == nil
}

// lineCatalogueDDNSNameValid checks one name by the SDK's own row rule.
func lineCatalogueDDNSNameValid(name string) bool {
	row := model.LineCatalogueRow{LineUUID: lineCatalogueValidationUUID, LineHashID: "h", NodeID: "n", Protocol: "p",
		Chain: model.LineCatalogueChain{Role: model.LineChainRoleSingle}, DDNSNames: []model.LineCatalogueDDNSName{{Name: name}}}
	return lineCatalogueProbeRowValid(row)
}

// lineCatalogueAddresses are the public addresses behind a line's hosts: an
// address literal as itself, a name as the last sync resolved it. Sorted and
// bounded.
func lineCatalogueAddresses(hosts []string, names map[string][]string) []string {
	set := map[string]bool{}
	for _, host := range hosts {
		host = strings.Trim(strings.TrimSpace(host), "[]")
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			if addrs := lineCataloguePublicAddrs([]net.IPAddr{{IP: ip}}); addrs != nil {
				set[addrs[0]] = true
			}
			continue
		}
		for _, addr := range names[lineCatalogueNameKey(host)] {
			set[addr] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for addr := range set {
		out = append(out, addr)
	}
	sort.Strings(out)
	if len(out) > lineCatalogueMaxAddresses {
		out = out[:lineCatalogueMaxAddresses]
	}
	return out
}

// lineCatalogueChainSet is every row's chain block, plus the composed entry
// template of each committed chain root (nil when compose could not build
// one).
type lineCatalogueChainSet struct {
	blocks   map[string]model.LineCatalogueChain
	composed map[string]*store.LineClientTemplate
}

func (c lineCatalogueChainSet) chain(lineUUID string) model.LineCatalogueChain {
	if block, ok := c.blocks[lineUUID]; ok {
		return block
	}
	return model.LineCatalogueChain{Role: model.LineChainRoleSingle}
}

func (c lineCatalogueChainSet) root(lineUUID string) bool {
	_, ok := c.composed[lineUUID]
	return ok
}

func (c lineCatalogueChainSet) composedTemplate(lineUUID string) *store.LineClientTemplate {
	return c.composed[lineUUID]
}

// lineCatalogueChains places every line in its chain. Edges are the read
// model's jump edges, in which a declared or committed downstream already
// replaced the inferred ones. A line whose outbound names a server that
// resolves to no fleet line has an edge out to the unknown: it is Unresolved.
// A line with an edge out and none in is an entry, with both a relay, with
// only one in an exit. A line whose path to the end is one line per hop gets
// that last line's node geo as its exit geo, unless the path ends at an
// unresolved line, whose exit is unknown: then the line is Unresolved too, so
// no geo predicate reads a geo the traffic does not leave from. Every line
// with a path gets the worst service state along it. A committed chain root
// (the source of a committed definition that no committed definition targets)
// also gets its path state, judged the way compose judges it, and its composed
// entry template.
func (s *Server) lineCatalogueChains(lines []Line, uuidByHash map[string]string, nodes map[string]model.Node) lineCatalogueChainSet {
	set := lineCatalogueChainSet{blocks: map[string]model.LineCatalogueChain{}, composed: map[string]*store.LineClientTemplate{}}
	nodeOf := make(map[string]string, len(lines))
	serviceOf := make(map[string]string, len(lines))
	targets := map[string][]string{}
	incoming := map[string]bool{}
	unresolved := map[string]bool{}
	for _, ln := range lines {
		nodeOf[ln.LineUUID] = ln.NodeID
		serviceOf[ln.LineUUID] = ln.ServiceState
		for _, hash := range ln.JumpEdges {
			target := uuidByHash[hash]
			if target == "" || target == ln.LineUUID || slices.Contains(targets[ln.LineUUID], target) {
				continue
			}
			targets[ln.LineUUID] = append(targets[ln.LineUUID], target)
			incoming[target] = true
		}
	}
	for _, ln := range lines {
		if len(targets[ln.LineUUID]) == 0 && lineCatalogueRelaysOut(ln) {
			unresolved[ln.LineUUID] = true
		}
	}
	// pathOf walks the single-successor path from start: the lines on it,
	// start first, and whether it ends at its last line (a line with no edge
	// out, or an unresolved one) rather than at a fork or a loop.
	pathOf := func(start string) ([]string, bool) {
		path := []string{start}
		seen := map[string]bool{start: true}
		current := start
		for hop := 0; hop < lineCatalogueMaxChainHops; hop++ {
			next := targets[current]
			switch {
			case len(next) == 0:
				return path, true
			case len(next) > 1 || seen[next[0]]:
				return path, false
			}
			current = next[0]
			seen[current] = true
			path = append(path, current)
		}
		return path, false
	}
	for _, ln := range lines {
		out, in := len(targets[ln.LineUUID]) > 0 || unresolved[ln.LineUUID], incoming[ln.LineUUID]
		if !out && !in {
			continue
		}
		block := model.LineCatalogueChain{Role: model.LineChainRoleExit}
		switch {
		case out && in:
			block.Role = model.LineChainRoleRelay
		case out:
			block.Role = model.LineChainRoleEntry
		}
		if len(targets[ln.LineUUID]) == 1 {
			block.DownstreamLineUUID = targets[ln.LineUUID][0]
		}
		if out {
			path, ends := pathOf(ln.LineUUID)
			last := path[len(path)-1]
			switch {
			case ends && unresolved[last]:
				block.Unresolved = true
			case ends && last != ln.LineUUID:
				block.ExitGeo = lineCatalogueGeo(nodes[nodeOf[last]].Geo)
			}
			block.PathServiceState = lineCatalogueWorstServiceState(path, serviceOf)
		}
		set.blocks[ln.LineUUID] = block
	}

	committed := s.store.LineChainSnapshot()
	sources, targeted := map[string]bool{}, map[string]bool{}
	for source, definition := range committed.Definitions {
		target := strings.ToLower(strings.TrimSpace(definition.TargetLineUUID))
		if target == "" {
			continue
		}
		sources[strings.ToLower(strings.TrimSpace(source))] = true
		targeted[target] = true
	}
	var roots []string
	for source := range sources {
		if _, known := nodeOf[source]; known && !targeted[source] {
			roots = append(roots, source)
		}
	}
	if len(roots) == 0 {
		return set
	}
	compile, err := s.captureLineChainCompileSnapshot()
	if err != nil {
		s.logger.Printf("line catalogue: capture chain state: %v", err)
	}
	active := map[string]bool{}
	for _, attempt := range compile.Chains.Attempts {
		if attempt.Status == store.LineChainStatusPlanned || attempt.Status == store.LineChainStatusApplying {
			active[strings.ToLower(attempt.SourceLineUUID)] = true
		}
	}
	for _, root := range roots {
		block := set.blocks[root]
		if block.Role == "" {
			block.Role = model.LineChainRoleEntry
		}
		block.Root = true
		block.PathState = model.LinePathDrifted
		var template *store.LineClientTemplate
		if err == nil {
			visits := 0
			_, _, pathErr := composeDeclaredPath(compile, root, active, &visits)
			block.PathState = lineCataloguePathState(pathErr)
			template = lineCatalogueComposedTemplate(compile, root)
		}
		set.blocks[root] = block
		set.composed[root] = template
	}
	return set
}

// lineCataloguePathState names a compose path verdict as a path state: a
// path with a plan in flight is busy, any other failure drifted.
func lineCataloguePathState(err error) string {
	if err == nil {
		return model.LinePathConverged
	}
	var failure graphComposeFailure
	if errors.As(err, &failure) && failure.code == "graph_busy" {
		return model.LinePathBusy
	}
	return model.LinePathDrifted
}

// lineCatalogueRelaysOut reports a line whose outbound routes to a server
// rather than out directly: the condition under which the read model infers a
// jump edge (lines.go), so a line that meets it and has no edge relays to a
// server that is no fleet line.
func lineCatalogueRelaysOut(ln Line) bool {
	ref := strings.ToLower(strings.TrimSpace(ln.OutboundRef))
	return strings.TrimSpace(ln.OutboundServer) != "" && ln.OutboundPort > 0 && ref != "" && ref != "direct"
}

// lineCatalogueServiceRank orders service states from best to worst; a state
// a line did not report is unknown.
var lineCatalogueServiceRank = map[string]int{
	model.LineServiceStateRunning:    0,
	model.LineServiceStateUnknown:    1,
	model.LineServiceStateRestarting: 2,
	model.LineServiceStateDown:       3,
}

// lineCatalogueWorstServiceState is the worst service state of the lines on a
// path: down, then restarting, then unknown, then running.
func lineCatalogueWorstServiceState(path []string, serviceOf map[string]string) string {
	worst := model.LineServiceStateRunning
	for _, lineUUID := range path {
		state := strings.ToLower(strings.TrimSpace(serviceOf[lineUUID]))
		if _, known := lineCatalogueServiceRank[state]; !known {
			state = model.LineServiceStateUnknown
		}
		if lineCatalogueServiceRank[state] > lineCatalogueServiceRank[worst] {
			worst = state
		}
	}
	return worst
}

// lineCatalogueComposedTemplate is the entry compose builds for a root,
// without the identity's credential: the root's endpoint and its Reality
// public material. The endpoint builder runs with a placeholder credential so
// the root is checked exactly as compose checks it. Nil when compose would
// refuse the root.
func lineCatalogueComposedTemplate(compile lineChainCompileSnapshot, root string) *store.LineClientTemplate {
	line, definition, err := composeLine(compile, root)
	if err != nil {
		return nil
	}
	endpoint, err := proxycore.NewVLESSRealityEndpoint(proxycore.VLESSRealityEndpointOptions{
		Label: line.Name, Tag: line.Tag, NodeID: line.NodeID, InboundID: root,
		Server: firstNonEmpty(line.PublicHost, strings.TrimSpace(compile.Nodes[line.NodeID].PublicIP)), ServerPort: definition.Port,
		UUID: lineCatalogueValidationUUID, Flow: lineCatalogueComposeFlow, SNI: definition.SNI, Fingerprint: lineCatalogueComposeFingerprint,
		PublicKey: definition.RealityPublicKey, ShortID: definition.ShortID,
	})
	if err != nil {
		return nil
	}
	t := store.LineClientTemplate{LineHashID: line.LineHashID, NodeID: line.NodeID, Tag: line.Tag, LineUUID: root,
		Protocol: "vless", Host: endpoint.Server, Port: endpoint.ServerPort,
		Params: map[string]string{"type": endpoint.Network, "encryption": "none", "security": model.ProxySecurityReality,
			"pbk": endpoint.PublicKey, "sid": endpoint.ShortID, "fp": endpoint.Fingerprint}}
	if endpoint.SNI != "" {
		t.Params["sni"] = endpoint.SNI
	}
	if store.ValidateLineClientTemplate(t) != nil {
		return nil
	}
	return &t
}

// lineCataloguePage is model.LineCatalogueResponse with each row already
// encoded: the same field names in the same order, so it encodes to the same
// bytes.
type lineCataloguePage struct {
	CatalogueVersion string            `json:"catalogue_version"`
	Rows             []json.RawMessage `json:"rows"`
	Cursor           string            `json:"cursor,omitempty"`
	SelectorFields   []string          `json:"selector_fields,omitempty"`
	Unavailable      []string          `json:"unavailable,omitempty"`
}

// lineCatalogueUnavailable names the row blocks this core never fills: the
// probe block, while no probe history producer exists (design 27's P2), so a
// consumer offers no probe predicate and saves none.
var lineCatalogueUnavailable = []string{model.LineCatalogueUnavailableProbe}

// lineCatalogueVersion is the canonical version of a selection: the identity
// named and every selected row's encoding, in order.
func lineCatalogueVersion(identityID string, rows [][]byte) string {
	h := sha256.New()
	h.Write([]byte("lattice line catalogue v1\x00"))
	h.Write([]byte(identityID))
	h.Write([]byte{0})
	for _, row := range rows {
		h.Write(row)
		h.Write([]byte{'\n'})
	}
	return lineCatalogueVersionPrefix + hex.EncodeToString(h.Sum(nil))
}

// selection is the encoded rows a selector selects, in order, and their
// version.
func (c *lineCatalogue) selection(sel *model.LineCatalogueSelector) ([][]byte, string) {
	indexes := c.selectIndexes(sel)
	rows := make([][]byte, len(indexes))
	for i, index := range indexes {
		rows[i] = c.encoded[index]
	}
	return rows, lineCatalogueVersion(c.identityID, rows)
}

func lineCatalogueCursor(version string, offset int) string {
	return lineCatalogueCursorPrefix + strconv.Itoa(offset) + "." + version
}

// parseLineCatalogueCursor returns a cursor's offset and the version of the
// read it continues.
func parseLineCatalogueCursor(cursor string) (int, string, error) {
	body, ok := strings.CutPrefix(cursor, lineCatalogueCursorPrefix)
	if !ok {
		return 0, "", errors.New("not a catalogue cursor")
	}
	digits, version, _ := strings.Cut(body, ".")
	offset, err := strconv.Atoi(digits)
	if err != nil || offset < 0 || offset > model.MaxLineCataloguePageRows*1024 || !strings.HasPrefix(version, lineCatalogueVersionPrefix) {
		return 0, "", errors.New("not a catalogue cursor")
	}
	return offset, version, nil
}

// lineCataloguePageOf encodes the page of rows that starts at offset: at
// most limit rows (the page bound when zero) and at most
// MaxLineCataloguePageBytes. first adds selector_fields. more reports
// whether the page ends in a cursor.
func lineCataloguePageOf(rows [][]byte, version string, offset, limit int, first bool) (body []byte, more bool, err error) {
	if limit == 0 {
		limit = model.MaxLineCataloguePageRows
	}
	page := lineCataloguePage{CatalogueVersion: version, Rows: []json.RawMessage{}, Unavailable: lineCatalogueUnavailable}
	if first {
		page.SelectorFields = lineCatalogueSelectorFields
	}
	// The envelope as it would encode with the longest cursor this read can
	// produce, so the rows added below never take the page over its bound.
	head := page
	head.Cursor = lineCatalogueCursor(version, len(rows))
	headRaw, err := json.Marshal(head)
	if err != nil {
		return nil, false, err
	}
	size, end := len(headRaw), offset
	for end < len(rows) && end-offset < limit {
		add := len(rows[end])
		if end > offset {
			add++
		}
		if end > offset && size+add > model.MaxLineCataloguePageBytes {
			break
		}
		size += add
		page.Rows = append(page.Rows, rows[end])
		end++
	}
	if end < len(rows) {
		page.Cursor = lineCatalogueCursor(version, end)
	}
	body, err = json.Marshal(page)
	return body, page.Cursor != "", err
}

// A read that spans pages is served from one build. Building costs the
// whole fleet, so rebuilding for every page would make a read of n lines
// cost n squared over the page size, and a fleet change between pages would
// restart it. The first page always builds; when the selection does not fit
// it, its rows are kept under a key naming the identity, the selector and
// the version, and a cursor carrying that version reads the next pages from
// them. A cursor whose build has gone, or a request that differs from the
// one the cursor came from, builds afresh, and the page then carries the
// version of that build, which tells the reader to start over.
//
// The cache holds up to lineCataloguePageCacheEntries reads and
// lineCataloguePageCacheBytes of rows, and makes room by dropping the oldest
// build. The newest build is always kept, so even a selection larger than
// the byte bound pages from one build.
const (
	lineCataloguePageCacheEntries = 16
	lineCataloguePageCacheBytes   = 32 << 20
	lineCataloguePageCacheTTL     = 2 * time.Minute
)

type lineCataloguePageCache struct {
	mu      sync.Mutex
	entries []lineCataloguePageEntry
}

type lineCataloguePageEntry struct {
	key   string
	rows  [][]byte
	bytes int
	at    time.Time
}

func lineCataloguePageKey(req model.LineCatalogueRequest, version string) string {
	selector, _ := json.Marshal(req.Selector)
	return req.IdentityID + "\x00" + string(selector) + "\x00" + version
}

func (c *lineCataloguePageCache) get(key string, now time.Time) ([][]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, entry := range c.entries {
		if entry.key == key && now.Sub(entry.at) < lineCataloguePageCacheTTL {
			return entry.rows, true
		}
	}
	return nil, false
}

func (c *lineCataloguePageCache) put(key string, rows [][]byte, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	size := 0
	for _, row := range rows {
		size += len(row)
	}
	kept, total := c.entries[:0], 0
	for _, entry := range c.entries {
		if entry.key != key && now.Sub(entry.at) < lineCataloguePageCacheTTL {
			kept = append(kept, entry)
			total += entry.bytes
		}
	}
	for len(kept) > 0 && (len(kept) >= lineCataloguePageCacheEntries || total+size > lineCataloguePageCacheBytes) {
		oldest := 0
		for i, entry := range kept {
			if entry.at.Before(kept[oldest].at) {
				oldest = i
			}
		}
		total -= kept[oldest].bytes
		kept = slices.Delete(kept, oldest, oldest+1)
	}
	c.entries = append(kept, lineCataloguePageEntry{key: key, rows: rows, bytes: size, at: now})
}

// decodeLineCatalogueRequest decodes a catalogue request strictly. An empty
// request is the first page of everything. A selector field this core does
// not evaluate is refused by name, with the fields it does evaluate, and so
// is a selector given twice or naming a field twice.
func decodeLineCatalogueRequest(raw []byte) (model.LineCatalogueRequest, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = []byte("{}")
	}
	if len(raw) <= model.MaxLineCatalogueRequestBytes {
		if refusal := lineCatalogueSelectorRefusal(raw); refusal != "" {
			return model.LineCatalogueRequest{}, rpcAPIError(http.StatusBadRequest, apiErrorCatalogueSelectorUnsupported,
				refusal+"; selector_fields: "+strings.Join(lineCatalogueSelectorFields, ","))
		}
	}
	req, err := model.DecodeLineCatalogueRequest(raw)
	if err != nil {
		return model.LineCatalogueRequest{}, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "catalogue request: "+err.Error())
	}
	return req, nil
}

// lineCatalogueSelectorRefusal reads every selector a request carries, under
// every key the decoder would take for it (encoding/json matches field names
// ignoring case), and says why the selector is refused, or "" when it is not
// or when the request is not an object the strict decode would accept anyway.
// Decoding into a map instead would let a later selector key hide an earlier
// one: a null replaces the map, and two keys that differ only in case would
// both be merged into one selector.
func lineCatalogueSelectorRefusal(raw []byte) string {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return ""
	}
	selectors := 0
	var unknown []string
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return ""
		}
		key, _ := token.(string)
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return ""
		}
		if !strings.EqualFold(key, "selector") {
			continue
		}
		if selectors++; selectors > 1 {
			return "catalogue selector is given more than once"
		}
		fields := json.NewDecoder(bytes.NewReader(value))
		if token, err := fields.Token(); err != nil || token != json.Delim('{') {
			continue
		}
		seen := map[string]bool{}
		for fields.More() {
			token, err := fields.Token()
			field, ok := token.(string)
			if err != nil || !ok {
				break
			}
			if seen[field] {
				return fmt.Sprintf("catalogue selector field %s is given more than once", strconv.Quote(field))
			}
			seen[field] = true
			if !slices.Contains(lineCatalogueSelectorFields, field) {
				unknown = append(unknown, strconv.Quote(field))
			}
			var skip json.RawMessage
			if fields.Decode(&skip) != nil {
				break
			}
		}
	}
	if len(unknown) == 0 {
		return ""
	}
	sort.Strings(unknown)
	return fmt.Sprintf("catalogue selector field %s is not one this core evaluates", strings.Join(unknown, ", "))
}

// vpnCoreReadAllowed holds an operator's own gateway call to a vpn-core read
// service to vpncore:read in core, whatever scope a manifest declared for it.
// A plugin reaches the service over rpc:call under its signed, method-bounded
// host_access grant, which the registry checks.
func vpnCoreReadAllowed(ctx context.Context) error {
	if operatorCalledCoreService(ctx) == "" {
		return nil
	}
	p, err := pluginOperatorPrincipal(ctx)
	if err != nil {
		return rpcAPIError(http.StatusForbidden, model.APIErrorForbidden, "the operator's principal is unavailable")
	}
	if ok, reason := pluginGatewayScopeAllowed(p, "vpncore:read"); !ok {
		return rpcAPIError(http.StatusForbidden, model.APIErrorCapabilityDenied, reason)
	}
	return nil
}

// vpnCoreLinesCatalogueRPC serves latticenet.vpn-core/lines catalogue.
//
//	request:  model.LineCatalogueRequest (empty means {})
//	response: model.LineCatalogueResponse
//
// The reader's contract: a later page whose catalogue_version differs from
// the first page's comes from a fresh build (the first build aged out of the
// page cache, or the cursor was sent with another request), so the reader
// discards the rows it has read and starts again without a cursor.
func (s *Server) vpnCoreLinesCatalogueRPC(ctx context.Context, request []byte) ([]byte, error) {
	if err := vpnCoreReadAllowed(ctx); err != nil {
		return nil, err
	}
	req, err := decodeLineCatalogueRequest(request)
	if err != nil {
		return nil, err
	}
	now := s.now()
	offset := 0
	var rows [][]byte
	var version string
	if req.Cursor != "" {
		var cursorVersion string
		if offset, cursorVersion, err = parseLineCatalogueCursor(req.Cursor); err != nil {
			return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "catalogue cursor: "+err.Error())
		}
		if cached, ok := s.substoreCatalogue.pages.get(lineCataloguePageKey(req, cursorVersion), now); ok {
			rows, version = cached, cursorVersion
		}
	}
	built := rows == nil
	if built {
		catalogue, err := s.buildLineCatalogue(req.IdentityID)
		if err != nil {
			return nil, err
		}
		rows, version = catalogue.selection(req.Selector)
	}
	body, more, err := lineCataloguePageOf(rows, version, offset, req.Limit, req.Cursor == "")
	if err != nil {
		return nil, err
	}
	if built && more {
		s.substoreCatalogue.pages.put(lineCataloguePageKey(req, version), rows, now)
	}
	if req.IdentityID != "" {
		identity, _ := s.getVpnUser(req.IdentityID)
		if newLineCatalogueSecrets(lineCatalogueIdentitySecrets(identity)).in(body) {
			return nil, rpcAPIError(http.StatusInternalServerError, apiErrorCatalogueCredential, "the catalogue page was withheld: a credential survived in it")
		}
	}
	return body, nil
}

// lineCatalogueRows is the binder's read: one fresh build, and the rows of the
// named lines that it holds, keyed by line_uuid. A line the catalogue does not
// hold is absent. The catalogue is returned too, for BindTemplate and Line.
func (s *Server) lineCatalogueRows(lineUUIDs []string) (map[string]model.LineCatalogueRow, *lineCatalogue, error) {
	catalogue, err := s.buildLineCatalogue("")
	if err != nil {
		return nil, nil, err
	}
	out := make(map[string]model.LineCatalogueRow, len(lineUUIDs))
	for _, id := range lineUUIDs {
		if row, ok := catalogue.Row(id); ok {
			out[id] = row
		}
	}
	return out, catalogue, nil
}
