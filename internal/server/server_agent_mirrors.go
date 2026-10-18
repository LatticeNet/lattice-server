package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Design 31, S5: ordered download sources, a small reviewed mirror registry,
// and the chunk manifest that keeps a bad mirror from erasing what honest
// sources delivered.
//
// A mirror is any HTTPS server holding release binaries at
// <base_url>/<version>/<os>/<arch>/<sha256>, the control plane's own object
// path. It is untrusted transport: the node holds what it delivers to the
// plan's digest and, chunk by chunk, to the plan's manifest; it never
// receives a credential and is never followed through a redirect.

const (
	// agentChunkSize is the manifest's chunk: 54 chunks for a 14 MB agent,
	// about 3.5 KB of hex in the payload.
	agentChunkSize = 256 << 10

	// maxAgentUpdateSources bounds a plan's source list: four fit the
	// 640 characters taskFailureSummary keeps, with a second pass.
	maxAgentUpdateSources = 4

	maxAgentMirrors          = 16
	maxAgentMirrorPreferFor  = 64
	maxAgentMirrorPriority   = 1_000_000
	maxAgentMirrorNameRunes  = 80
	maxAgentUpdateReasonSize = 160

	eventAgentMirrorFirstPlan = "agent.mirror.first_plan"
)

var (
	agentMirrorIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)
	// agentMirrorRefRe is a node or group id named in prefer_for.
	agentMirrorRefRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	// agentMirrorPathRe is the path of a mirror base and of a mirror URL:
	// characters that need no quoting in a URL and are inert in a shell
	// word, so a mirror URL is safe even before shellQuote.
	agentMirrorPathRe = regexp.MustCompile(`^(/[A-Za-z0-9._~+-]+)*/?$`)
	agentDNSLabelRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	agentHexLabelRe   = regexp.MustCompile(`^0x[0-9a-f]*$`)
)

// agentMirrorPathHasDotSegment says whether a path holds a "." or ".."
// segment. A client resolves those away, so the URL it fetches would not be
// the one the approver read.
func agentMirrorPathHasDotSegment(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// ── The chunk manifest ─────────────────────────────────────────────────────

// agentChunkManifest is the SHA-256 of every agentChunkSize bytes of the
// pinned binary, hex, concatenated. It is part of the payload of any plan
// that lists a mirror, so the approval binds it.
type agentChunkManifest struct {
	ChunkSize int    `json:"chunk_size"`
	Size      int    `json:"size"`
	Chunks    string `json:"chunks"`
}

func computeAgentChunkManifest(data []byte) agentChunkManifest {
	var b strings.Builder
	b.Grow((len(data)/agentChunkSize + 1) * 64)
	for off := 0; off < len(data); off += agentChunkSize {
		sum := sha256.Sum256(data[off:min(off+agentChunkSize, len(data))])
		b.WriteString(hex.EncodeToString(sum[:]))
	}
	return agentChunkManifest{ChunkSize: agentChunkSize, Size: len(data), Chunks: b.String()}
}

func (m agentChunkManifest) count() int {
	if m.ChunkSize <= 0 {
		return 0
	}
	return (m.Size + m.ChunkSize - 1) / m.ChunkSize
}

// digest is what a plan prints for the manifest: the SHA-256 of
// "<chunk_size>\n<size>\n<chunks>\n".
func (m agentChunkManifest) digest() string {
	sum := sha256.Sum256([]byte(strconv.Itoa(m.ChunkSize) + "\n" + strconv.Itoa(m.Size) + "\n" + m.Chunks + "\n"))
	return hex.EncodeToString(sum[:])
}

func (m agentChunkManifest) validate() error {
	if m.ChunkSize != agentChunkSize {
		return fmt.Errorf("chunk_manifest chunk_size must be %d", agentChunkSize)
	}
	if m.Size <= 0 || m.Size > maxAgentArtifactBytes {
		return fmt.Errorf("chunk_manifest size must be between 1 and %d bytes", maxAgentArtifactBytes)
	}
	if len(m.Chunks) != m.count()*64 {
		return errors.New("chunk_manifest must name one digest per chunk")
	}
	for i := 0; i < len(m.Chunks); i++ {
		c := m.Chunks[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return errors.New("chunk_manifest digests must be lowercase hex")
		}
	}
	return nil
}

func manifestFromRecord(rec store.AgentArtifactManifest) agentChunkManifest {
	return agentChunkManifest{ChunkSize: rec.ChunkSize, Size: rec.Size, Chunks: rec.Chunks}
}

// recordAgentArtifactManifest keeps the manifest of bytes the caller has
// held to ref.SHA256.
func (s *Server) recordAgentArtifactManifest(ref agentArtifactRef, data []byte, source string) error {
	m := computeAgentChunkManifest(data)
	return s.store.PutAgentArtifactManifest(store.AgentArtifactManifest{
		Version: ref.Version, OS: ref.OS, Arch: ref.Arch, SHA256: ref.SHA256,
		Size: m.Size, ChunkSize: m.ChunkSize, Chunks: m.Chunks, Source: source, RecordedAt: s.now().UTC(),
	})
}

// agentArtifactManifest returns the manifest of one binary: the recorded
// one, or, for bytes the control plane already held before manifests were
// recorded, one computed from the stored copy and recorded then. Bytes the
// control plane has never verified have none, and a plan for them lists no
// mirror.
func (s *Server) agentArtifactManifest(version, osName, arch, sha string) (agentChunkManifest, bool) {
	if rec, ok := s.store.AgentArtifactManifest(version, osName, arch, sha); ok {
		m := manifestFromRecord(rec)
		return m, m.validate() == nil
	}
	ref, obj, ok := s.storedAgentArtifactObject(version, osName, arch)
	if !ok || ref.SHA256 != sha {
		return agentChunkManifest{}, false
	}
	data, err := s.agentArtifactBytes.verified(ref.objectPath(), obj.Content, ref.servedSHA256())
	if err != nil {
		return agentChunkManifest{}, false
	}
	if ref.GzipSHA256 != "" {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return agentChunkManifest{}, false
		}
		raw, err := io.ReadAll(io.LimitReader(zr, maxAgentArtifactBytes+1))
		if err != nil || len(raw) > maxAgentArtifactBytes {
			return agentChunkManifest{}, false
		}
		data = raw
	}
	plain := ref
	plain.GzipSHA256 = ""
	if verifyAgentArtifactBytes(plain, data) != nil {
		return agentChunkManifest{}, false
	}
	if err := s.recordAgentArtifactManifest(plain, data, "stored"); err != nil {
		s.logger.Printf("agent artifact manifest for %s not recorded: %v", plain.objectPath(), err)
	}
	return computeAgentChunkManifest(data), true
}

// importedAgentArtifactDigest is the digest an import verified against the
// release's SHA256SUMS for one version and platform, kept whether or not the
// bytes fit the store. A release whose assets were replaced and imported again
// answers with the latest import.
func (s *Server) importedAgentArtifactDigest(version, osName, arch string) (string, bool) {
	var latest *store.AgentArtifactManifest
	for _, rec := range s.store.AgentArtifactManifests() {
		if rec.Version == version && rec.OS == osName && rec.Arch == arch && rec.Source == "import" &&
			(latest == nil || rec.RecordedAt.After(latest.RecordedAt)) {
			latest = &rec
		}
	}
	if latest == nil {
		return "", false
	}
	return latest.SHA256, true
}

// agentArtifactImport is what an import did with a verified release binary.
type agentArtifactImport struct {
	View agentArtifactView
	// Stored says the control plane keeps the bytes and serves them;
	// Recorded that their digest and manifest are kept, which an import
	// always does once the bytes verify.
	Stored, Recorded bool
	Note             string
}

// importAgentArtifact is the verify-and-record import. It holds the release
// bytes to the digest the release publishes, records the manifest, and keeps
// the bytes, compressed, only when they fit the store. Bytes that do not fit
// are still recorded: a mirror can then serve an architecture the control
// plane has no room for, and a plan for that version needs no fetch to pin
// its digest.
func (s *Server) importAgentArtifact(ref agentArtifactRef, data []byte) (agentArtifactImport, error) {
	ref.GzipSHA256 = ""
	if err := verifyAgentArtifactBytes(ref, data); err != nil {
		return agentArtifactImport{}, err
	}
	if err := s.recordAgentArtifactManifest(ref, data, "import"); err != nil {
		return agentArtifactImport{}, err
	}
	view, err := s.storeCompressedAgentArtifact(ref, data)
	if errors.Is(err, errAgentArtifactStoreFull) {
		return agentArtifactImport{
			View:     agentArtifactView{Version: ref.Version, OS: ref.OS, Arch: ref.Arch, SHA256: ref.SHA256, SizeBytes: len(data)},
			Recorded: true,
			Note:     "recorded the verified digest and chunk manifest without storing the bytes: " + err.Error(),
		}, nil
	}
	if err != nil {
		return agentArtifactImport{}, err
	}
	return agentArtifactImport{View: view, Stored: true, Recorded: true}, nil
}

// ── The registry ───────────────────────────────────────────────────────────

// validateAgentMirror normalizes and checks one registry entry. The host
// list it refuses is hygiene, not a boundary: a fleet agent admin can
// already point a policy at any HTTPS URL.
func validateAgentMirror(m model.AgentMirror, controlPlaneBase string) (model.AgentMirror, error) {
	out := model.AgentMirror{
		ID:       strings.TrimSpace(m.ID),
		Name:     strings.TrimSpace(m.Name),
		Global:   m.Global,
		Priority: m.Priority,
		Enabled:  m.Enabled,
	}
	if !agentMirrorIDRe.MatchString(out.ID) {
		return model.AgentMirror{}, errors.New("mirror id must be 1 to 31 lowercase letters, digits or hyphens, starting with a letter or digit")
	}
	if utf8.RuneCountInString(out.Name) > maxAgentMirrorNameRunes {
		return model.AgentMirror{}, fmt.Errorf("mirror name must be at most %d characters", maxAgentMirrorNameRunes)
	}
	for _, r := range out.Name {
		if !unicode.IsPrint(r) {
			return model.AgentMirror{}, errors.New("mirror name must be printable text on one line")
		}
	}
	if out.Priority < 0 || out.Priority > maxAgentMirrorPriority {
		return model.AgentMirror{}, fmt.Errorf("mirror priority must be between 0 and %d", maxAgentMirrorPriority)
	}
	for _, ref := range m.PreferFor {
		ref = strings.TrimSpace(ref)
		if !agentMirrorRefRe.MatchString(ref) {
			return model.AgentMirror{}, fmt.Errorf("prefer_for names %q, which is not a node or group id", ref)
		}
		if !slices.Contains(out.PreferFor, ref) {
			out.PreferFor = append(out.PreferFor, ref)
		}
	}
	if len(out.PreferFor) > maxAgentMirrorPreferFor {
		return model.AgentMirror{}, fmt.Errorf("prefer_for names at most %d nodes and groups", maxAgentMirrorPreferFor)
	}
	sort.Strings(out.PreferFor)
	base, err := canonicalAgentMirrorBase(m.BaseURL, controlPlaneBase)
	if err != nil {
		return model.AgentMirror{}, err
	}
	out.BaseURL = base
	return out, nil
}

// canonicalAgentMirrorBase returns base_url as https://host[:port][/path]
// with the host lowercased and canonical and no trailing slash, or refuses
// it.
func canonicalAgentMirrorBase(raw, controlPlaneBase string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || !strings.HasPrefix(raw[len("https:"):], "//") {
		return "", errors.New("base_url must be an https:// URL")
	}
	if u.User != nil {
		return "", errors.New("base_url must not contain userinfo")
	}
	if u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "?") {
		return "", errors.New("base_url must not contain a query")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return "", errors.New("base_url must not contain a fragment")
	}
	if u.RawPath != "" || !agentMirrorPathRe.MatchString(u.Path) {
		return "", errors.New("base_url path may hold only letters, digits and . _ ~ + - between slashes")
	}
	if agentMirrorPathHasDotSegment(u.Path) {
		return "", errors.New("base_url path must not hold a . or .. segment, which a client resolves away")
	}
	host, err := canonicalAgentMirrorHost(u.Hostname())
	if err != nil {
		return "", err
	}
	if cp, err := url.Parse(strings.TrimSpace(controlPlaneBase)); err == nil && cp.Hostname() != "" &&
		strings.EqualFold(strings.TrimSuffix(cp.Hostname(), "."), host) {
		return "", errors.New("base_url must not be on the control plane's own host: the control plane is a source of its own, and only it is sent the task lease")
	}
	hostport := host
	if strings.Contains(host, ":") {
		hostport = "[" + host + "]"
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", errors.New("base_url port must be a number from 1 to 65535")
		}
		if n != 443 {
			hostport += ":" + port
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return "", errors.New("base_url port must be a number from 1 to 65535")
	}
	return "https://" + hostport + strings.TrimRight(u.Path, "/"), nil
}

// canonicalAgentMirrorHost refuses loopback, unspecified, link-local and
// multicast addresses, localhost, and any numeric host not written in its
// canonical form, which some resolvers would read as one of those.
func canonicalAgentMirrorHost(host string) (string, error) {
	if host == "" {
		return "", errors.New("base_url must name a host")
	}
	if strings.Contains(host, ":") {
		addr, err := netip.ParseAddr(host)
		if err != nil || addr.Zone() != "" || addr.String() != strings.ToLower(host) {
			return "", fmt.Errorf("base_url host %q is not a canonical IPv6 address", host)
		}
		return addr.String(), refuseAgentMirrorAddr(addr)
	}
	lower := strings.ToLower(host)
	labels := strings.Split(lower, ".")
	last := labels[len(labels)-1]
	if last == "" {
		return "", errors.New("base_url host must not end with a dot")
	}
	numeric := agentHexLabelRe.MatchString(last)
	if !numeric {
		numeric = strings.Trim(last, "0123456789") == ""
	}
	if numeric {
		addr, err := netip.ParseAddr(lower)
		if err != nil || !addr.Is4() || addr.String() != lower {
			return "", fmt.Errorf("base_url host %q is not a canonical IPv4 address", host)
		}
		return lower, refuseAgentMirrorAddr(addr)
	}
	if len(lower) > 253 {
		return "", errors.New("base_url host name is too long")
	}
	for _, label := range labels {
		if !agentDNSLabelRe.MatchString(label) {
			return "", fmt.Errorf("base_url host %q is not a plain DNS name", host)
		}
	}
	if last == "localhost" {
		return "", errors.New("base_url must not be localhost")
	}
	return lower, nil
}

func refuseAgentMirrorAddr(addr netip.Addr) error {
	addr = addr.Unmap()
	switch {
	case addr.IsLoopback():
		return errors.New("base_url must not be a loopback address")
	case addr.IsUnspecified():
		return errors.New("base_url must not be an unspecified address")
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		return errors.New("base_url must not be a link-local address")
	case addr.IsMulticast(), addr.IsInterfaceLocalMulticast():
		return errors.New("base_url must not be a multicast address")
	}
	return nil
}

// ── The source order ───────────────────────────────────────────────────────

// agentSourceOrderInput is everything the order depends on. Every input is
// stable: the registry, whether the control plane holds the digest, the
// node's id and the explicit members of static groups. Group selectors,
// stored geo and whether a mirror is up now are not inputs, so a plan does
// not change, and retire its approval, when they do.
type agentSourceOrderInput struct {
	NodeID          string
	Groups          []model.Group
	Mirrors         []model.AgentMirror
	ObjectPath      string
	ControlPlaneURL string
	UpstreamURL     string
	UpstreamReason  string
}

// agentUpdateSourceOrder is the fixed order: mirrors preferred for the node,
// the control plane when it holds the digest, mirrors marked global, then
// upstream, always last. Within a group a smaller priority comes first and
// ties go by id. To stay within maxAgentUpdateSources the mirrors that come
// last are dropped: the global ones first, then the preferred.
func agentUpdateSourceOrder(in agentSourceOrderInput) []model.AgentUpdateSource {
	members := map[string]bool{}
	for _, g := range in.Groups {
		if slices.Contains(g.Members, in.NodeID) {
			members[g.ID] = true
		}
	}
	type ranked struct {
		m      model.AgentMirror
		reason string
	}
	var preferred, global []ranked
	for _, m := range in.Mirrors {
		if !m.Enabled {
			continue
		}
		reason := ""
		for _, ref := range m.PreferFor {
			if ref == in.NodeID {
				reason = "preferred for this node"
				break
			}
		}
		if reason == "" {
			for _, ref := range m.PreferFor {
				if members[ref] {
					reason = "preferred for group " + ref
					break
				}
			}
		}
		switch {
		case reason != "":
			preferred = append(preferred, ranked{m, reason})
		case m.Global:
			global = append(global, ranked{m, "a global mirror"})
		}
	}
	byRank := func(a, b ranked) int {
		if a.m.Priority != b.m.Priority {
			return a.m.Priority - b.m.Priority
		}
		return strings.Compare(a.m.ID, b.m.ID)
	}
	slices.SortStableFunc(preferred, byRank)
	slices.SortStableFunc(global, byRank)
	room := maxAgentUpdateSources
	if in.ControlPlaneURL != "" {
		room--
	}
	if in.UpstreamURL != "" {
		room--
	}
	preferred = preferred[:min(len(preferred), max(room, 0))]
	room -= len(preferred)
	global = global[:min(len(global), max(room, 0))]
	mirrorSource := func(r ranked) model.AgentUpdateSource {
		return model.AgentUpdateSource{Kind: model.AgentSourceKindMirror, URL: r.m.BaseURL + "/" + in.ObjectPath, Mirror: r.m.ID, Reason: r.reason}
	}
	var out []model.AgentUpdateSource
	for _, r := range preferred {
		out = append(out, mirrorSource(r))
	}
	if in.ControlPlaneURL != "" {
		out = append(out, model.AgentUpdateSource{Kind: model.AgentSourceKindControlPlane, URL: in.ControlPlaneURL, Reason: "this control plane holds the pinned bytes"})
	}
	for _, r := range global {
		out = append(out, mirrorSource(r))
	}
	if in.UpstreamURL != "" {
		out = append(out, model.AgentUpdateSource{Kind: model.AgentSourceKindUpstream, URL: in.UpstreamURL, Reason: in.UpstreamReason})
	}
	return out
}

// agentUpdateSourceLabel names a source in an order: mirror:<id>,
// control-plane or upstream.
func agentUpdateSourceLabel(src model.AgentUpdateSource) string {
	if src.Kind == model.AgentSourceKindMirror {
		return "mirror:" + src.Mirror
	}
	return src.Kind
}

func agentUpdateSourceLabels(sources []model.AgentUpdateSource) []string {
	out := make([]string, 0, len(sources))
	for _, src := range sources {
		out = append(out, agentUpdateSourceLabel(src))
	}
	return out
}

// agentUpdateSourcesFor derives a payload's source list from its control
// plane and upstream URLs and the registry, and the manifest when the list
// names a mirror. Mirrors are listed only for bytes with a manifest.
func (s *Server) agentUpdateSourcesFor(node model.Node, payload agentUpdatePayload) ([]model.AgentUpdateSource, *agentChunkManifest) {
	osName, arch, err := agentPlatformForNode(node)
	if err != nil {
		return nil, nil
	}
	cpURL, upURL := "", payload.BinaryURL
	if normalizeAgentBinarySource(payload.BinarySource) == agentBinarySourceControlPlane {
		cpURL, upURL = payload.BinaryURL, payload.FallbackURL
	}
	upReason := "the URL the update policy pins"
	if strings.HasPrefix(upURL, "https://github.com/"+s.agentReleaseRepo+"/releases/download/") {
		upReason = "the release this version names"
	}
	in := agentSourceOrderInput{
		NodeID:          node.ID,
		ObjectPath:      agentArtifactPlatformPrefix(payload.TargetVersion, osName, arch) + payload.SHA256,
		ControlPlaneURL: cpURL,
		UpstreamURL:     upURL,
		UpstreamReason:  upReason,
	}
	var manifest *agentChunkManifest
	reg := s.store.AgentMirrorRegistry()
	// A version whose characters a mirror URL cannot carry (agentVersionRe
	// allows ':') gets no mirror, rather than a payload the validator refuses.
	objectPathOK := agentMirrorPathRe.MatchString("/"+in.ObjectPath) && !agentMirrorPathHasDotSegment("/"+in.ObjectPath)
	if objectPathOK && slices.ContainsFunc(reg.Mirrors, func(m model.AgentMirror) bool { return m.Enabled }) {
		if m, ok := s.agentArtifactManifest(payload.TargetVersion, osName, arch, payload.SHA256); ok {
			in.Mirrors, in.Groups, manifest = reg.Mirrors, s.store.Groups(), &m
		}
	}
	sources := agentUpdateSourceOrder(in)
	if !slices.ContainsFunc(sources, func(src model.AgentUpdateSource) bool { return src.Kind == model.AgentSourceKindMirror }) {
		manifest = nil
	}
	return sources, manifest
}

// noteAgentMirrorsPlanned alerts the first time each mirror appears in any
// plan: a new mirror starts receiving fleet traffic only through a plan, and
// an operator should hear about that once, not discover it in a log.
func (s *Server) noteAgentMirrorsPlanned(node model.Node, payload agentUpdatePayload, approvalID string, now time.Time) {
	var ids []string
	for _, src := range payload.Sources {
		if src.Kind == model.AgentSourceKindMirror {
			ids = append(ids, src.Mirror)
		}
	}
	if len(ids) == 0 {
		return
	}
	fresh, err := s.store.MarkAgentMirrorsPlanned(ids, now)
	if err != nil {
		s.logger.Printf("agent mirror first plan not recorded: %v", err)
	}
	for _, mirrorID := range fresh {
		mirrorURL := ""
		for _, src := range payload.Sources {
			if src.Mirror == mirrorID {
				mirrorURL = src.URL
			}
		}
		s.recordAudit(model.AuditEvent{
			ID: id.New("audit"), NodeID: node.ID, Action: eventAgentMirrorFirstPlan, Decision: "observe",
			Metadata: map[string]string{"mirror": mirrorID, "approval_id": approvalID, "target_version": payload.TargetVersion},
		})
		s.notifyEventTyped(eventAgentMirrorFirstPlan,
			"Agent mirror "+mirrorID+" is in an update plan for the first time",
			fmt.Sprintf("The update plan %s for %s (%s), version %s, lists the mirror %s as a download source: %s. The plan is pending review.",
				approvalID, latencyNodeLabel(node), node.ID, payload.TargetVersion, mirrorID, mirrorURL))
	}
}

// ── The agent.mirrors plan ─────────────────────────────────────────────────

func isAgentMirrorsApproval(approval model.Approval) bool {
	return approval.Plugin == model.AgentMirrorsApprovalPlugin && approval.Action == model.AgentMirrorsPlanKind
}

type agentMirrorPlanError struct {
	status int
	err    error
}

func (e *agentMirrorPlanError) Error() string { return e.err.Error() }

func mirrorPlanErr(status int, format string, args ...any) error {
	return &agentMirrorPlanError{status: status, err: fmt.Errorf(format, args...)}
}

// agentMirrorOrderPreview is a node's source order under a registry, for a
// version the control plane holds and the release names, which is what the
// registry changes.
func agentMirrorOrderPreview(node model.Node, groups []model.Group, mirrors []model.AgentMirror) []string {
	return agentUpdateSourceLabels(agentUpdateSourceOrder(agentSourceOrderInput{
		NodeID: node.ID, Groups: groups, Mirrors: mirrors, ObjectPath: "v/linux/a/s",
		ControlPlaneURL: "cp", UpstreamURL: "up", UpstreamReason: "up",
	}))
}

// agentMirrorPreviewNodes are the nodes whose updates the registry steers:
// those the control plane updates, Linux ones.
func (s *Server) agentMirrorPreviewNodes() []model.Node {
	var out []model.Node
	for _, n := range s.store.Nodes() {
		if _, err := managedAgentUpdateOS(n); err == nil {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func agentMirrorField(m *model.AgentMirror, field string) string {
	if m == nil {
		return "-"
	}
	switch field {
	case "name":
		if m.Name == "" {
			return "-"
		}
		return m.Name
	case "base_url":
		return m.BaseURL
	case "prefer_for":
		if len(m.PreferFor) == 0 {
			return "-"
		}
		return strings.Join(m.PreferFor, ",")
	case "global":
		return strconv.FormatBool(m.Global)
	case "priority":
		return strconv.Itoa(m.Priority)
	case "enabled":
		return strconv.FormatBool(m.Enabled)
	}
	return "-"
}

// buildAgentMirrorPlan renders the plan document for a request against a
// registry. It reads and never writes, so the decision can render it again
// from live state and compare bytes.
func (s *Server) buildAgentMirrorPlan(req model.AgentMirrorPlanRequest, reg store.AgentMirrorRegistry) (model.AgentMirrorPlan, []model.AgentMirror, string, error) {
	plan := model.AgentMirrorPlan{Kind: model.AgentMirrorsPlanKind, Action: req.Action, BaseRevision: reg.Revision, Diff: []string{}, Changes: []model.AgentMirrorOrderChange{}}
	mirrorID := strings.TrimSpace(req.Mirror.ID)
	index := slices.IndexFunc(reg.Mirrors, func(m model.AgentMirror) bool { return m.ID == mirrorID })
	next := slices.Clone(reg.Mirrors)
	var previous *model.AgentMirror
	if index >= 0 {
		p := reg.Mirrors[index]
		p.CreatedAt, p.UpdatedAt = time.Time{}, time.Time{}
		previous = &p
	}
	var after *model.AgentMirror
	switch req.Action {
	case model.AgentMirrorActionCreate, model.AgentMirrorActionChange:
		m, err := validateAgentMirror(req.Mirror, s.publicURL)
		if err != nil {
			return plan, nil, "", mirrorPlanErr(http.StatusBadRequest, "%v", err)
		}
		if req.Action == model.AgentMirrorActionCreate {
			if index >= 0 {
				return plan, nil, "", mirrorPlanErr(http.StatusConflict, "mirror %s already exists; plan a change instead", m.ID)
			}
			if len(reg.Mirrors) >= maxAgentMirrors {
				return plan, nil, "", mirrorPlanErr(http.StatusConflict, "the registry holds at most %d mirrors", maxAgentMirrors)
			}
			next = append(next, m)
		} else {
			if index < 0 {
				return plan, nil, "", mirrorPlanErr(http.StatusNotFound, "mirror %s is not in the registry", m.ID)
			}
			if reflectMirrorEqual(*previous, m) {
				return plan, nil, "", mirrorPlanErr(http.StatusConflict, "mirror %s already reads exactly this", m.ID)
			}
			next[index] = m
		}
		for _, other := range next {
			if other.ID != m.ID && other.BaseURL == m.BaseURL {
				return plan, nil, "", mirrorPlanErr(http.StatusConflict, "mirror %s already uses base_url %s", other.ID, m.BaseURL)
			}
		}
		after = &m
		plan.Mirror = m
	case model.AgentMirrorActionDelete:
		if index < 0 {
			return plan, nil, "", mirrorPlanErr(http.StatusNotFound, "mirror %s is not in the registry", mirrorID)
		}
		next = slices.Delete(next, index, index+1)
		plan.Mirror = *previous
	default:
		return plan, nil, "", mirrorPlanErr(http.StatusBadRequest, "action must be %s, %s or %s",
			model.AgentMirrorActionCreate, model.AgentMirrorActionChange, model.AgentMirrorActionDelete)
	}
	plan.Previous = previous
	for _, field := range []string{"name", "base_url", "prefer_for", "global", "priority", "enabled"} {
		before, now := agentMirrorField(previous, field), agentMirrorField(after, field)
		if before != now {
			plan.Diff = append(plan.Diff, field+": "+before+" -> "+now)
		}
	}
	groups := s.store.Groups()
	for _, node := range s.agentMirrorPreviewNodes() {
		before := agentMirrorOrderPreview(node, groups, reg.Mirrors)
		now := agentMirrorOrderPreview(node, groups, next)
		if !slices.Equal(before, now) {
			plan.Changes = append(plan.Changes, model.AgentMirrorOrderChange{NodeID: node.ID, Name: node.Name, Before: before, After: now})
		}
	}
	raw, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return plan, nil, "", err
	}
	return plan, next, string(raw), nil
}

func reflectMirrorEqual(a, b model.AgentMirror) bool {
	return a.ID == b.ID && a.Name == b.Name && a.BaseURL == b.BaseURL && slices.Equal(a.PreferFor, b.PreferFor) &&
		a.Global == b.Global && a.Priority == b.Priority && a.Enabled == b.Enabled
}

// fleetAgentAdmin is requireFleetAgentAdmin without the response: node:admin
// over the whole fleet, not a node allowlist.
func fleetAgentAdmin(p principal) bool {
	return rbac.Allows(p.Principal, "node:admin", "") && !principalHasNodeRestriction(p)
}

// handleAgentMirrorPlan answers POST /api/nodes/agent-updates/mirrors/plan.
// A mirror steers which host every listed node contacts, learns those nodes'
// addresses and update timing, and could deny their updates, so a registry
// change is a reviewed plan, gated as an artifact is, on the whole fleet.
func (s *Server) handleAgentMirrorPlan(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireFleetAgentAdmin(w, p) || !s.requireScope(w, p, "network:plan") {
		return
	}
	var req model.AgentMirrorPlanRequest
	if !decodeClientJSON(w, r, &req) {
		return
	}
	plan, _, raw, err := s.buildAgentMirrorPlan(req, s.store.AgentMirrorRegistry())
	if err != nil {
		var pe *agentMirrorPlanError
		if errors.As(err, &pe) {
			writeError(w, pe.status, pe.err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	now := s.now().UTC()
	approval, err := s.submitApproval(r.Context(), model.Approval{
		ID:        id.New("approval"),
		Plugin:    model.AgentMirrorsApprovalPlugin,
		Action:    model.AgentMirrorsPlanKind,
		Plan:      raw,
		Status:    model.ApprovalPending,
		ActorID:   p.ActorID,
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: "agent.mirrors.plan", Scope: "node:admin,network:plan",
		Metadata: map[string]string{
			"approval_id": approval.ID, "action": plan.Action, "mirror": plan.Mirror.ID,
			"base_revision": strconv.FormatInt(plan.BaseRevision, 10), "nodes": strconv.Itoa(len(plan.Changes)),
		},
	})
	writeJSON(w, http.StatusOK, model.AgentMirrorPlanResponse{Approval: approval, Plan: plan})
}

// agentMirrorsApprove decides an agent.mirrors approval: the plan is rendered
// again from live state and refused as stale when the bytes differ, and the
// registry change and the decision are written together. Nothing runs on a
// node: the next plan for each node reads the new registry.
func (s *Server) agentMirrorsApprove(ctx context.Context, p principal, approval model.Approval) (model.Approval, error) {
	_ = ctx
	if !fleetAgentAdmin(p) {
		return approval, &approvalDecisionError{status: http.StatusForbidden, err: apiError(model.APIErrorCapabilityDenied,
			"deciding an agent.mirrors plan needs node:admin over the whole fleet; the registry steers every node")}
	}
	var plan model.AgentMirrorPlan
	if err := json.Unmarshal([]byte(approval.Plan), &plan); err != nil || plan.Kind != model.AgentMirrorsPlanKind {
		return approval, &approvalDecisionError{status: http.StatusConflict, err: apiError(model.APIErrorApprovalStale, "the plan is not an agent.mirrors plan")}
	}
	req := model.AgentMirrorPlanRequest{Action: plan.Action, Mirror: plan.Mirror}
	_, next, raw, err := s.buildAgentMirrorPlan(req, s.store.AgentMirrorRegistry())
	if err != nil || raw != approval.Plan {
		return approval, &approvalDecisionError{status: http.StatusConflict, err: apiError(model.APIErrorApprovalStale,
			"the mirror registry, the nodes or their groups changed since this plan was made; re-plan before approving")}
	}
	approval.Status = model.ApprovalApplied
	approval.ApprovedBy = p.ActorID
	committed, err := s.store.ApplyAgentMirrorPlan(approval, plan.BaseRevision, next)
	if !committed {
		if errors.Is(err, store.ErrAgentMirrorRevision) {
			return approval, &approvalDecisionError{status: http.StatusConflict, err: apiError(model.APIErrorApprovalStale,
				"the mirror registry changed while deciding; re-plan before approving")}
		}
		if errors.Is(err, store.ErrTaskTransitionConflict) {
			return approval, &approvalDecisionError{status: http.StatusConflict, err: apiError(model.APIErrorApprovalStale,
				"this plan was decided or changed while deciding; reload it")}
		}
		return approval, &approvalDecisionError{status: http.StatusInternalServerError, err: err}
	}
	if err != nil {
		s.logger.Printf("agent.mirrors approval committed with degraded durability: %v", err)
		return approval, &approvalDecisionError{status: http.StatusInternalServerError, err: err}
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: "agent.mirrors.approve", Scope: approvalDecisionAuditScope(approval),
		Metadata: map[string]string{
			"approval_id": approval.ID, "action": plan.Action, "mirror": plan.Mirror.ID,
			"revision": strconv.FormatInt(plan.BaseRevision+1, 10), "nodes": strconv.Itoa(len(plan.Changes)),
		},
	})
	if fresh, ok := s.store.Approval(approval.ID); ok {
		approval = fresh
	}
	return approval, nil
}

// handleAgentMirrors answers GET /api/nodes/agent-updates/mirrors: the
// registry, every readable node's order, the open plans, and what the nodes'
// last downloads say about each mirror.
func (s *Server) handleAgentMirrors(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireScope(w, p, "node:read") {
		return
	}
	reg := s.store.AgentMirrorRegistry()
	view := model.AgentMirrorsView{
		Mirrors: make([]model.AgentMirror, 0, len(reg.Mirrors)), Revision: reg.Revision,
		Order: []model.AgentMirrorOrder{}, Pending: []string{}, Health: []model.AgentMirrorHealth{},
	}
	restricted := principalHasNodeRestriction(p)
	for _, m := range reg.Mirrors {
		if restricted {
			// A principal confined to some nodes sees which of them an entry
			// prefers, not the rest of the fleet or its groups.
			var mine []string
			for _, target := range m.PreferFor {
				if rbac.Allows(p.Principal, "node:read", target) {
					mine = append(mine, target)
				}
			}
			m.PreferFor = mine
		}
		view.Mirrors = append(view.Mirrors, m)
	}
	groups := s.store.Groups()
	for _, node := range s.agentMirrorPreviewNodes() {
		if !rbac.Allows(p.Principal, "node:read", node.ID) {
			continue
		}
		view.Order = append(view.Order, model.AgentMirrorOrder{NodeID: node.ID, Name: node.Name, Sources: agentMirrorOrderPreview(node, groups, reg.Mirrors)})
	}
	for _, a := range s.store.Approvals() {
		if isAgentMirrorsApproval(a) && a.Status == model.ApprovalPending && s.approvalVisibleToPrincipal(p, a) {
			view.Pending = append(view.Pending, a.ID)
		}
	}
	health := map[string]*model.AgentMirrorHealth{}
	for _, m := range reg.Mirrors {
		h := model.AgentMirrorHealth{Mirror: m.ID}
		health[m.ID] = &h
	}
	for _, policy := range s.store.AgentUpdatePolicies() {
		if policy.LastFetch == nil || !rbac.Allows(p.Principal, "node:read", policy.NodeID) {
			continue
		}
		for _, f := range policy.LastFetch.Fetches {
			mirrorID, ok := strings.CutPrefix(f.Kind, model.AgentFetchKindMirrorPrefix)
			if h := health[mirrorID]; ok && h != nil {
				h.Fetches++
				if f.BadChunks > 0 {
					h.ChunkFailures++
				}
			}
		}
	}
	for _, m := range reg.Mirrors {
		view.Health = append(view.Health, *health[m.ID])
	}
	writeJSON(w, http.StatusOK, view)
}

// ── Payload validation ─────────────────────────────────────────────────────

// validateAgentUpdateSources checks a decoded payload's source list against
// the rest of the payload. The decoder does not know this control plane's
// base; the renderer and the binary route hold the control-plane entry to it.
func validateAgentUpdateSources(p agentUpdatePayload) error {
	if len(p.Sources) == 0 {
		if p.ChunkManifest != nil {
			return errors.New("agent update approval carries a chunk manifest without sources")
		}
		return nil
	}
	if !p.ResumeDownload {
		return errors.New("agent update approval names sources outside a resumable download")
	}
	if len(p.Sources) > maxAgentUpdateSources {
		return fmt.Errorf("agent update approval names more than %d sources", maxAgentUpdateSources)
	}
	cpIndex, upIndex, arch := -1, -1, ""
	mirrors := map[string]bool{}
	for i, src := range p.Sources {
		if len(src.Reason) == 0 || len(src.Reason) > maxAgentUpdateReasonSize {
			return fmt.Errorf("source %d: reason must be 1 to %d characters", i+1, maxAgentUpdateReasonSize)
		}
		for j := 0; j < len(src.Reason); j++ {
			if src.Reason[j] < 0x20 || src.Reason[j] > 0x7e {
				return fmt.Errorf("source %d: reason must be printable ASCII", i+1)
			}
		}
		normalized, err := normalizeAgentUpdateURL(src.URL)
		if err != nil || normalized != src.URL {
			return fmt.Errorf("source %d: url must be a canonical HTTPS URL", i+1)
		}
		u, _ := url.Parse(src.URL)
		switch src.Kind {
		case model.AgentSourceKindControlPlane:
			if cpIndex >= 0 {
				return errors.New("agent update approval names two control-plane sources")
			}
			if src.Mirror != "" {
				return errors.New("a control-plane source names no mirror")
			}
			rest, ok := strings.CutPrefix(u.Path, agentBinaryPathPrefix)
			ref, parsed := parseAgentArtifactPath(rest)
			if !ok || !parsed || u.Path != ref.urlPath() || ref.Version != p.TargetVersion ||
				ref.SHA256 != p.SHA256 || ref.GzipSHA256 != p.CompressedSHA256 {
				return errors.New("the control-plane source must name exactly the pinned bytes on the binary route")
			}
			if arch != "" && arch != ref.Arch {
				return errors.New("the sources name two platforms")
			}
			cpIndex, arch = i, ref.Arch
		case model.AgentSourceKindMirror:
			if !agentMirrorIDRe.MatchString(src.Mirror) {
				return fmt.Errorf("source %d: invalid mirror id", i+1)
			}
			if mirrors[src.Mirror] {
				return fmt.Errorf("source %d: mirror %s is listed twice", i+1, src.Mirror)
			}
			mirrors[src.Mirror] = true
			if u.RawPath != "" || !agentMirrorPathRe.MatchString(u.Path) || agentMirrorPathHasDotSegment(u.Path) {
				return fmt.Errorf("source %d: a mirror URL may hold only letters, digits and . _ ~ + - between slashes, and no . or .. segment", i+1)
			}
			mirrorArch := ""
			for _, a := range []string{"amd64", "arm64"} {
				if strings.HasSuffix(u.Path, "/"+agentArtifactPlatformPrefix(p.TargetVersion, "linux", a)+p.SHA256) {
					mirrorArch = a
				}
			}
			if mirrorArch == "" {
				return fmt.Errorf("source %d: a mirror URL must end with the pinned version, platform and digest", i+1)
			}
			if arch != "" && arch != mirrorArch {
				return errors.New("the sources name two platforms")
			}
			arch = mirrorArch
		case model.AgentSourceKindUpstream:
			if upIndex >= 0 || i != len(p.Sources)-1 {
				return errors.New("the upstream source must be the last, and only one")
			}
			if src.Mirror != "" {
				return errors.New("an upstream source names no mirror")
			}
			upIndex = i
		default:
			return fmt.Errorf("source %d: kind must be control-plane, mirror or upstream", i+1)
		}
	}
	if normalizeAgentBinarySource(p.BinarySource) == agentBinarySourceControlPlane {
		if cpIndex < 0 || p.Sources[cpIndex].URL != p.BinaryURL {
			return errors.New("a control-plane plan's sources must name its binary_url as the control-plane source")
		}
		if p.FallbackURL != "" && (upIndex < 0 || p.Sources[upIndex].URL != p.FallbackURL) {
			return errors.New("a control-plane plan's sources must end with its fallback_url")
		}
		if p.FallbackURL == "" && upIndex >= 0 {
			return errors.New("a control-plane plan without a fallback_url names no upstream source")
		}
	} else if cpIndex >= 0 || upIndex < 0 || p.Sources[upIndex].URL != p.BinaryURL {
		return errors.New("an upstream plan's sources must end with its binary_url and name no control-plane source")
	}
	if (len(mirrors) > 0) != (p.ChunkManifest != nil) {
		return errors.New("a plan lists a mirror exactly when it carries a chunk manifest")
	}
	if p.ChunkManifest != nil {
		if err := p.ChunkManifest.validate(); err != nil {
			return err
		}
		if p.CompressedSHA256 != "" && p.ChunkManifest.Size != p.BinarySize {
			return errors.New("chunk_manifest size must be the pinned binary_size")
		}
	}
	return nil
}

// agentUpdatePayloadEqual is the payload comparison staleness turns on.
// Every field counts; the source list and the manifest by value.
func agentUpdatePayloadEqual(a, b agentUpdatePayload) bool {
	if a.NodeID != b.NodeID || a.CurrentVersion != b.CurrentVersion || a.TargetVersion != b.TargetVersion ||
		a.BinaryURL != b.BinaryURL || a.SHA256 != b.SHA256 || a.InstallPath != b.InstallPath ||
		a.ServiceName != b.ServiceName || a.BinarySource != b.BinarySource || a.FallbackURL != b.FallbackURL ||
		a.ResumeDownload != b.ResumeDownload || a.CompressedSHA256 != b.CompressedSHA256 ||
		a.CompressedSize != b.CompressedSize || a.BinarySize != b.BinarySize {
		return false
	}
	if !slices.Equal(a.Sources, b.Sources) {
		return false
	}
	if (a.ChunkManifest == nil) != (b.ChunkManifest == nil) {
		return false
	}
	return a.ChunkManifest == nil || *a.ChunkManifest == *b.ChunkManifest
}

// agentUpdateSourcesChange is the change summary's sources entry: each list
// as comma-joined labels, an entry that changed in place marked with *.
func agentUpdateSourcesChange(planned, current []model.AgentUpdateSource) string {
	if slices.Equal(planned, current) {
		return ""
	}
	pl, cl := agentUpdateSourceLabels(planned), agentUpdateSourceLabels(current)
	if slices.Equal(pl, cl) {
		for i := range current {
			if current[i] != planned[i] {
				cl[i] += "*"
			}
		}
	}
	return "sources planned=" + strings.Join(pl, ",") + " current=" + strings.Join(cl, ",")
}

func agentChunkManifestDigest(m *agentChunkManifest) string {
	if m == nil {
		return ""
	}
	return m.digest()
}
