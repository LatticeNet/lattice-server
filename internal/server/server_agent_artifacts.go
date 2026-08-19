package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

const (
	// agentArtifactBucket is the reserved Static bucket holding agent release
	// binaries the control plane serves to nodes itself. Static is a
	// record-level bolt-backed object store, so a 12 MiB object is written once
	// and is not rewritten by unrelated state saves. The bucket is reserved: the
	// generic /api/static read and write paths and public static bindings all
	// refuse it, because bytes a node installs as root must not be reachable
	// through a storage scope or an anonymous hostname binding.
	agentArtifactBucket = "agent-releases"

	// maxAgentArtifactBytes caps one decoded binary. The real artifact is about
	// 12 MiB, so this leaves generous headroom while refusing absurd uploads.
	maxAgentArtifactBytes = 48 << 20

	// maxAgentArtifactStoreBytes caps everything the bucket holds, measured on
	// the stored base64 form. Static is read into memory at startup, so this is
	// a resident-memory ceiling as much as a disk one. 128 MiB is roughly four
	// versions across linux/amd64 and linux/arm64. Uploads past it are refused
	// with the current usage named, never silently evicted: evicting a binary a
	// queued approval still needs would strand exactly the nodes this feature
	// exists to unstick.
	maxAgentArtifactStoreBytes = 128 << 20

	agentArtifactContentType = "application/octet-stream"

	// agentBinaryPathPrefix is the node-facing download route. The rest of the
	// path is version/os/arch/sha256, so the request names exactly the bytes it
	// wants and the plan line an operator approves is self-describing.
	agentBinaryPathPrefix = "/api/agent/agent-binary/"

	// The apply script proves its identity with the task lease the agent already
	// exports into every task's environment as LATTICE_TASK_ID and
	// LATTICE_TASK_LEASE_ID. That credential is narrower than the node token in
	// every dimension that matters here: it names one task on one node, the
	// server minted it, and it stops being valid the moment the task leaves the
	// leased state.
	agentTaskIDHeader    = "X-Lattice-Task-Id"
	agentTaskLeaseHeader = "X-Lattice-Task-Lease"

	agentBinarySourceControlPlane = "control-plane"
	agentBinarySourceUpstream     = "upstream"

	// agentArtifactDownloadTimeout bounds the control plane's own fetch when an
	// operator imports a release. This is the one place third-party egress is
	// used, and it is used once per version rather than once per node.
	agentArtifactDownloadTimeout = 5 * time.Minute
)

var (
	errAgentBinaryDenied     = errors.New("agent binary download is not authorized by this task lease")
	errAgentArtifactNotFound = errors.New("the control plane does not hold this agent binary")
)

// agentArtifactRef identifies one stored binary. Every component is validated
// against a fixed pattern before it is ever used to build an object path, so a
// caller cannot walk out of the bucket or address an object it did not name.
type agentArtifactRef struct {
	Version string
	OS      string
	Arch    string
	SHA256  string
}

func (ref agentArtifactRef) validate() error {
	if !agentVersionRe.MatchString(ref.Version) {
		return errors.New("version must be an auditable version string")
	}
	if ref.OS != "linux" {
		return fmt.Errorf("control-plane agent distribution supports linux nodes; got os %q", ref.OS)
	}
	switch ref.Arch {
	case "amd64", "arm64":
	default:
		return fmt.Errorf("control-plane agent distribution supports amd64 and arm64; got arch %q", ref.Arch)
	}
	if !agentSHA256Re.MatchString(ref.SHA256) {
		return errors.New("sha256 must be a 64-character lowercase hex digest")
	}
	return nil
}

func (ref agentArtifactRef) objectPath() string {
	return agentArtifactPlatformPrefix(ref.Version, ref.OS, ref.Arch) + ref.SHA256
}

func (ref agentArtifactRef) urlPath() string {
	return agentBinaryPathPrefix + ref.objectPath()
}

func agentArtifactPlatformPrefix(version, osName, arch string) string {
	return version + "/" + osName + "/" + arch + "/"
}

func parseAgentArtifactPath(objectPath string) (agentArtifactRef, bool) {
	parts := strings.Split(strings.TrimSpace(objectPath), "/")
	if len(parts) != 4 {
		return agentArtifactRef{}, false
	}
	ref := agentArtifactRef{Version: parts[0], OS: parts[1], Arch: parts[2], SHA256: strings.ToLower(parts[3])}
	if ref.validate() != nil {
		return agentArtifactRef{}, false
	}
	return ref, true
}

// agentPlatformForNode reports the release platform a node needs. It is the
// single source of truth for both the upstream artifact name and the stored
// object path, so the two can never disagree about what a node runs.
func agentPlatformForNode(node model.Node) (osName string, arch string, err error) {
	osName, err = managedAgentUpdateOS(node)
	if err != nil {
		return "", "", err
	}
	arch = strings.ToLower(strings.TrimSpace(node.HostFacts.Arch))
	switch arch {
	case "", "x86_64":
		arch = "amd64"
	case "aarch64":
		arch = "arm64"
	}
	switch arch {
	case "amd64", "arm64":
	default:
		return "", "", fmt.Errorf("official lattice-agent releases do not support arch %q", arch)
	}
	return osName, arch, nil
}

func agentArtifactName(osName, arch string) string {
	return "lattice-agent-" + osName + "-" + arch
}

// agentArtifactDecodedSize returns the size of the binary a stored object holds
// without decoding it. Standard base64 is a fixed 4:3 expansion, so the padding
// on the tail is all that is needed to make this exact.
func agentArtifactDecodedSize(encoded string) int {
	n := len(encoded)
	if n == 0 || n%4 != 0 {
		return 0
	}
	size := n / 4 * 3
	switch {
	case strings.HasSuffix(encoded, "=="):
		size -= 2
	case strings.HasSuffix(encoded, "="):
		size--
	}
	return size
}

type agentArtifactView struct {
	Version    string    `json:"version"`
	OS         string    `json:"os"`
	Arch       string    `json:"arch"`
	SHA256     string    `json:"sha256"`
	SizeBytes  int       `json:"size_bytes"`
	StoredSize int       `json:"stored_bytes"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// agentArtifacts lists what the control plane can serve. Content is deliberately
// left out of the view: these objects are megabytes each and a console poll must
// not carry them.
func (s *Server) agentArtifacts() []agentArtifactView {
	objects := s.store.Static(agentArtifactBucket)
	out := make([]agentArtifactView, 0, len(objects))
	for _, obj := range objects {
		ref, ok := parseAgentArtifactPath(obj.Path)
		if !ok {
			continue
		}
		out = append(out, agentArtifactView{
			Version:    ref.Version,
			OS:         ref.OS,
			Arch:       ref.Arch,
			SHA256:     ref.SHA256,
			SizeBytes:  agentArtifactDecodedSize(obj.Content),
			StoredSize: len(obj.Content),
			UpdatedAt:  obj.UpdatedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Version != out[j].Version {
			return out[i].Version > out[j].Version
		}
		if out[i].OS != out[j].OS {
			return out[i].OS < out[j].OS
		}
		return out[i].Arch < out[j].Arch
	})
	return out
}

func (s *Server) agentArtifactStoreBytes() int {
	total := 0
	for _, obj := range s.store.Static(agentArtifactBucket) {
		total += len(obj.Content)
	}
	return total
}

// storedAgentArtifact reports the binary the control plane holds for one version
// and platform. At most one digest is ever stored per triple, because storing a
// new one replaces the whole prefix; "which bytes does this version install" has
// exactly one answer.
func (s *Server) storedAgentArtifact(version, osName, arch string) (agentArtifactRef, bool) {
	prefix := agentArtifactPlatformPrefix(version, osName, arch)
	for _, obj := range s.store.Static(agentArtifactBucket) {
		if !strings.HasPrefix(obj.Path, prefix) {
			continue
		}
		if ref, ok := parseAgentArtifactPath(obj.Path); ok {
			return ref, true
		}
	}
	return agentArtifactRef{}, false
}

// agentBinaryBaseURL is the control plane's own origin, and it is only usable
// when it is a plain HTTPS base. Without one there is no address a node could be
// told to fetch from that also satisfies the HTTPS-only rule the plan pins, so
// distribution falls back to upstream rather than inventing an origin from the
// caller's Host header.
func (s *Server) agentBinaryBaseURL() string {
	return normalizeAgentBinaryBaseURL(s.publicURL)
}

func normalizeAgentBinaryBaseURL(publicURL string) string {
	raw := strings.TrimRight(strings.TrimSpace(publicURL), "/")
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	return raw
}

// controlPlaneAgentBinaryURL returns the node-facing URL when the control plane
// already holds exactly the bytes the plan pins. The stored digest must equal
// the pinned digest: serving from a closer place must never become a way to
// serve different bytes, so a stored artifact that disagrees with the pin is
// ignored rather than substituted.
func (s *Server) controlPlaneAgentBinaryURL(version, osName, arch, sha256Hex string) (string, bool) {
	base := s.agentBinaryBaseURL()
	if base == "" {
		return "", false
	}
	ref, ok := s.storedAgentArtifact(version, osName, arch)
	if !ok || !strings.EqualFold(ref.SHA256, strings.TrimSpace(sha256Hex)) {
		return "", false
	}
	return base + ref.urlPath(), true
}

// requireFleetAgentAdmin gates every operation that changes what the fleet can
// install. node:admin restricted to a server allowlist is not enough: an
// artifact is fleet-wide by construction, so a principal that may only
// administer one node must not be able to publish bytes every node will run.
func (s *Server) requireFleetAgentAdmin(w http.ResponseWriter, p principal) bool {
	if !rbac.Allows(p.Principal, "node:admin", "") {
		writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
		return false
	}
	for _, allowed := range p.Principal.ServerAllowlist {
		if allowed == "*" {
			return true
		}
	}
	if len(p.Principal.ServerAllowlist) == 0 {
		return true
	}
	s.recordAudit(model.AuditEvent{
		ID:            id.New("audit"),
		ActorID:       p.ActorID,
		TokenID:       p.TokenID,
		Action:        "agent.artifact.authorize",
		Scope:         "node:admin",
		Decision:      "deny",
		Reason:        "agent release artifacts are fleet-wide; a node-restricted principal may not publish them",
		CorrelationID: p.CorrelationID,
	})
	writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied,
		"agent release artifacts are fleet-wide; this token is restricted to specific nodes"))
	return false
}

func (s *Server) handleAgentArtifacts(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireScope(w, p, "node:read") {
			return
		}
		// serving_enabled is reported alongside the inventory because a stored
		// artifact that cannot be served is not the same thing as one that can,
		// and the difference is invisible otherwise: the plan quietly stays on
		// the upstream URL and the operator sees a full shelf doing nothing.
		writeJSON(w, http.StatusOK, map[string]any{
			"artifacts":       s.agentArtifacts(),
			"stored_bytes":    s.agentArtifactStoreBytes(),
			"limit_bytes":     maxAgentArtifactStoreBytes,
			"serving_enabled": s.agentBinaryBaseURL() != "",
		})
	case http.MethodPost:
		s.handleAgentArtifactUpload(w, r, p)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

// handleAgentArtifactUpload takes the binary as a raw body so the console can
// stream a picked file straight through instead of base64-ing 12 MiB in the
// browser. The digest the operator declares is authoritative: the bytes are
// hashed on arrival and the upload is refused if they disagree, so a truncated
// transfer cannot become a stored artifact.
func (s *Server) handleAgentArtifactUpload(w http.ResponseWriter, r *http.Request, p principal) {
	if !s.requireFleetAgentAdmin(w, p) {
		return
	}
	query := r.URL.Query()
	ref := agentArtifactRef{
		Version: strings.TrimPrefix(strings.TrimSpace(query.Get("version")), "v"),
		OS:      strings.ToLower(strings.TrimSpace(query.Get("os"))),
		Arch:    strings.ToLower(strings.TrimSpace(query.Get("arch"))),
		SHA256:  strings.ToLower(strings.TrimSpace(query.Get("sha256"))),
	}
	if ref.OS == "" {
		ref.OS = "linux"
	}
	if err := ref.validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	defer r.Body.Close()
	body := http.MaxBytesReader(w, r.Body, maxAgentArtifactBytes+1)
	data, err := io.ReadAll(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("could not read the uploaded binary"))
		return
	}
	if len(data) > maxAgentArtifactBytes {
		writeError(w, http.StatusRequestEntityTooLarge,
			fmt.Errorf("agent binary exceeds the %d byte limit", maxAgentArtifactBytes))
		return
	}
	view, err := s.storeAgentArtifact(ref, data)
	if err != nil {
		s.writeAgentArtifactStoreError(w, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:     id.New("audit"),
		Action: "agent.artifact.put",
		Scope:  "node:admin",
		Metadata: map[string]string{
			"version": ref.Version,
			"os":      ref.OS,
			"arch":    ref.Arch,
			"sha256":  ref.SHA256,
			"bytes":   strconv.Itoa(len(data)),
			"source":  "upload",
		},
	})
	writeJSON(w, http.StatusOK, view)
}

// handleAgentArtifactImport moves the third-party dependency from every node to
// the control plane, once. The server fetches the release itself and verifies it
// against the checksums the release publishes; an import that cannot be verified
// stores nothing.
func (s *Server) handleAgentArtifactImport(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireFleetAgentAdmin(w, p) {
		return
	}
	var req struct {
		Version string `json:"version"`
		OS      string `json:"os"`
		Arch    string `json:"arch"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	target, tag, err := s.officialAgentTargetAndTag(req.Version)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	osName := strings.ToLower(strings.TrimSpace(req.OS))
	if osName == "" {
		osName = "linux"
	}
	arch := strings.ToLower(strings.TrimSpace(req.Arch))
	if arch == "" {
		arch = "amd64"
	}
	ref := agentArtifactRef{Version: target, OS: osName, Arch: arch}
	artifact := agentArtifactName(ref.OS, ref.Arch)
	base := fmt.Sprintf("https://github.com/%s/releases/download/%s", s.agentReleaseRepo, url.PathEscape(tag))
	sums, err := s.fetchAgentReleaseText(base + "/SHA256SUMS")
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	expected, ok := shaFromSums(sums, artifact)
	if !ok {
		writeError(w, http.StatusBadGateway,
			fmt.Errorf("release %s does not publish a checksum for %s", tag, artifact))
		return
	}
	ref.SHA256 = expected
	if err := ref.validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	data, err := s.fetchAgentReleaseBinary(base + "/" + url.PathEscape(artifact))
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	view, err := s.storeAgentArtifact(ref, data)
	if err != nil {
		s.writeAgentArtifactStoreError(w, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:     id.New("audit"),
		Action: "agent.artifact.import",
		Scope:  "node:admin",
		Metadata: map[string]string{
			"version": ref.Version,
			"os":      ref.OS,
			"arch":    ref.Arch,
			"sha256":  ref.SHA256,
			"bytes":   strconv.Itoa(len(data)),
			"release": tag,
		},
	})
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleDeleteAgentArtifact(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireFleetAgentAdmin(w, p) {
		return
	}
	var req struct {
		Version string `json:"version"`
		OS      string `json:"os"`
		Arch    string `json:"arch"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	version := strings.TrimPrefix(strings.TrimSpace(req.Version), "v")
	osName := strings.ToLower(strings.TrimSpace(req.OS))
	if osName == "" {
		osName = "linux"
	}
	arch := strings.ToLower(strings.TrimSpace(req.Arch))
	probe := agentArtifactRef{Version: version, OS: osName, Arch: arch, SHA256: strings.Repeat("0", 64)}
	if err := probe.validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	stored, ok := s.storedAgentArtifact(version, osName, arch)
	if !ok {
		writeError(w, http.StatusNotFound, errAgentArtifactNotFound)
		return
	}
	if err := s.store.DeleteStatic(agentArtifactBucket, stored.objectPath()); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:     id.New("audit"),
		Action: "agent.artifact.delete",
		Scope:  "node:admin",
		Metadata: map[string]string{
			"version": stored.Version,
			"os":      stored.OS,
			"arch":    stored.Arch,
			"sha256":  stored.SHA256,
		},
	})
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "sha256": stored.SHA256})
}

var (
	errAgentArtifactDigestMismatch = errors.New("uploaded bytes do not match the declared sha256 digest")
	errAgentArtifactStoreFull      = errors.New("agent release storage is full")
)

// storeAgentArtifact is the only way bytes enter the bucket. It verifies the
// digest before writing and refuses to grow the bucket past its cap, and it
// replaces any earlier digest for the same version and platform so a version
// never resolves to two different binaries.
func (s *Server) storeAgentArtifact(ref agentArtifactRef, data []byte) (agentArtifactView, error) {
	if err := ref.validate(); err != nil {
		return agentArtifactView{}, err
	}
	if len(data) == 0 {
		return agentArtifactView{}, errors.New("agent binary is empty")
	}
	sum := sha256.Sum256(data)
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(ref.SHA256)) != 1 {
		return agentArtifactView{}, fmt.Errorf("%w: computed %s", errAgentArtifactDigestMismatch, hex.EncodeToString(sum[:]))
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	superseded := []string{}
	used := 0
	prefix := agentArtifactPlatformPrefix(ref.Version, ref.OS, ref.Arch)
	for _, obj := range s.store.Static(agentArtifactBucket) {
		if strings.HasPrefix(obj.Path, prefix) {
			superseded = append(superseded, obj.Path)
			continue
		}
		used += len(obj.Content)
	}
	if used+len(encoded) > maxAgentArtifactStoreBytes {
		return agentArtifactView{}, fmt.Errorf("%w: %d bytes stored plus %d new exceeds the %d byte cap; delete an older version first",
			errAgentArtifactStoreFull, used, len(encoded), maxAgentArtifactStoreBytes)
	}
	if err := s.store.PutStatic(model.StaticObject{
		Bucket:      agentArtifactBucket,
		Path:        ref.objectPath(),
		Content:     encoded,
		ContentType: agentArtifactContentType,
	}); err != nil {
		return agentArtifactView{}, err
	}
	// Superseded digests go only after the replacement is durable, so a failure
	// here leaves the bucket with one extra object rather than none.
	for _, path := range superseded {
		if path == ref.objectPath() {
			continue
		}
		if err := s.store.DeleteStatic(agentArtifactBucket, path); err != nil {
			return agentArtifactView{}, fmt.Errorf("stored %s but could not remove superseded %s: %w", ref.objectPath(), path, err)
		}
	}
	// Read the record back so the answer carries the timestamp the store
	// actually stamped rather than a guess made before the write.
	view := agentArtifactView{
		Version: ref.Version, OS: ref.OS, Arch: ref.Arch, SHA256: ref.SHA256,
		SizeBytes: len(data), StoredSize: len(encoded),
	}
	if stored, ok := s.store.StaticObject(agentArtifactBucket, ref.objectPath()); ok {
		view.UpdatedAt = stored.UpdatedAt
	}
	return view, nil
}

func (s *Server) writeAgentArtifactStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errAgentArtifactDigestMismatch):
		writeError(w, http.StatusBadRequest, err)
	case errors.Is(err, errAgentArtifactStoreFull):
		writeError(w, http.StatusInsufficientStorage, err)
	default:
		writeError(w, http.StatusInternalServerError, err)
	}
}

func (s *Server) fetchAgentReleaseBinary(rawURL string) ([]byte, error) {
	client := &http.Client{Timeout: agentArtifactDownloadTimeout}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("User-Agent", "lattice-server-agent-update")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch agent release binary: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch agent release binary: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAgentArtifactBytes+1))
	if err != nil {
		return nil, fmt.Errorf("fetch agent release binary: %w", err)
	}
	if len(data) > maxAgentArtifactBytes {
		return nil, fmt.Errorf("fetch agent release binary: response exceeds %d bytes", maxAgentArtifactBytes)
	}
	return data, nil
}

// handleAgentBinary serves one agent binary to one node. It takes no query
// parameters and consults no caller-supplied selector beyond the path, which it
// then checks against the approval the requesting task is executing. A node can
// therefore only ever fetch the exact object its own approved update names, and
// cannot enumerate the bucket or reach any other static object through here.
func (s *Server) handleAgentBinary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	ref, ok := parseAgentArtifactPath(strings.TrimPrefix(r.URL.Path, agentBinaryPathPrefix))
	if !ok {
		writeError(w, http.StatusNotFound, errAgentArtifactNotFound)
		return
	}
	node, task, err := s.authorizeAgentBinaryRequest(r, ref)
	if err != nil {
		s.auditAgentBinaryDenied(r, node.ID, ref, err.Error())
		writeError(w, http.StatusForbidden, errAgentBinaryDenied)
		return
	}
	obj, ok := s.store.StaticObject(agentArtifactBucket, ref.objectPath())
	if !ok {
		// Honest degradation: the control plane says plainly that it does not
		// have these bytes. It does not redirect the node upstream, because the
		// approved plan already committed to this source.
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   node.ID,
			Action:   "agent.binary.serve",
			Decision: "deny",
			Reason:   "artifact is not stored on the control plane",
			Metadata: map[string]string{
				"version": ref.Version, "os": ref.OS, "arch": ref.Arch,
				"sha256": ref.SHA256, "task_id": task.ID,
			},
		})
		writeError(w, http.StatusNotFound, errAgentArtifactNotFound)
		return
	}
	data, decodeErr := base64.StdEncoding.DecodeString(obj.Content)
	if decodeErr == nil {
		sum := sha256.Sum256(data)
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(ref.SHA256)) != 1 {
			decodeErr = fmt.Errorf("stored digest %s does not match the pinned %s", hex.EncodeToString(sum[:]), ref.SHA256)
		}
	}
	if decodeErr != nil {
		// A wrong or truncated copy is a control-plane defect, not a node error,
		// and it must never reach a node that is about to install it as root.
		// Refuse loudly: server log, audit deny, and a 500 that names the fault.
		s.logger.Printf("agent binary refused: node_id=%s version=%s os=%s arch=%s: %v",
			node.ID, ref.Version, ref.OS, ref.Arch, decodeErr)
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   node.ID,
			Action:   "agent.binary.serve",
			Decision: "deny",
			Reason:   "stored agent binary failed integrity verification: " + decodeErr.Error(),
			Metadata: map[string]string{
				"version": ref.Version, "os": ref.OS, "arch": ref.Arch,
				"sha256": ref.SHA256, "task_id": task.ID,
			},
		})
		writeError(w, http.StatusInternalServerError,
			errors.New("the stored agent binary failed integrity verification and was not served"))
		return
	}
	s.recordRequestAudit(r, model.AuditEvent{
		ID:     id.New("audit"),
		NodeID: node.ID,
		Action: "agent.binary.serve",
		Metadata: map[string]string{
			"version": ref.Version,
			"os":      ref.OS,
			"arch":    ref.Arch,
			"sha256":  ref.SHA256,
			"bytes":   strconv.Itoa(len(data)),
			"task_id": task.ID,
		},
	})
	w.Header().Set("Content-Type", agentArtifactContentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	if _, err := w.Write(data); err != nil {
		s.logger.Printf("agent binary write failed: node_id=%s version=%s: %v", node.ID, ref.Version, err)
	}
}

// auditAgentBinaryDenied records a download this route refused. The route is
// unauthenticated by construction (the credential is inside the request), so an
// anonymous caller can reach this path at will. It therefore shares the global
// authentication-failure throttle: without it, rotating source addresses would
// turn "record the refusal" into unbounded audit growth, which is the exact
// abuse that throttle exists to stop. Refusals that require a valid lease to
// reach, a missing artifact and a digest mismatch, are never throttled: those
// are control-plane defects and every one of them must be recorded.
func (s *Server) auditAgentBinaryDenied(r *http.Request, nodeID string, ref agentArtifactRef, reason string) {
	sourceIP := s.clientIP(r)
	emit, suppressed, dropped := s.authFailAuditThrottle.Allow("agentbinary|"+auditBucketedIP(sourceIP), s.now())
	if !emit {
		return
	}
	meta := map[string]string{
		"version": ref.Version,
		"os":      ref.OS,
		"arch":    ref.Arch,
		"sha256":  ref.SHA256,
		"task_id": auditTruncate(strings.TrimSpace(r.Header.Get(agentTaskIDHeader)), 64),
	}
	if suppressed > 0 {
		meta["suppressed_repeats"] = strconv.Itoa(suppressed)
	}
	if dropped > 0 {
		meta["global_suppressed"] = strconv.Itoa(dropped)
	}
	s.recordRequestAudit(r, model.AuditEvent{
		ID:       id.New("audit"),
		NodeID:   auditTruncate(nodeID, 64),
		Action:   "agent.binary.serve",
		Decision: "deny",
		Reason:   reason,
		Metadata: meta,
	})
}

// authorizeAgentBinaryRequest proves the caller is the node currently executing
// an approved agent update that names exactly these bytes. Nothing the caller
// says about which artifact it wants is trusted: the version, platform and
// digest all have to match what the approval already committed to.
func (s *Server) authorizeAgentBinaryRequest(r *http.Request, ref agentArtifactRef) (model.Node, model.Task, error) {
	taskID := strings.TrimSpace(r.Header.Get(agentTaskIDHeader))
	lease := strings.TrimSpace(r.Header.Get(agentTaskLeaseHeader))
	if taskID == "" || lease == "" {
		return model.Node{}, model.Task{}, errAgentBinaryDenied
	}
	task, ok := s.store.Task(taskID)
	if !ok || task.Status != model.TaskLeased {
		return model.Node{}, model.Task{}, errAgentBinaryDenied
	}
	nodeID, ok := taskLeaseHolder(task, lease)
	if !ok {
		return model.Node{}, model.Task{}, errAgentBinaryDenied
	}
	node, ok := s.store.Node(nodeID)
	if !ok || node.Disabled {
		return model.Node{}, task, errAgentBinaryDenied
	}
	approval, ok := s.store.Approval(strings.TrimSpace(task.ApprovalID))
	if !ok || approval.Plugin != agentUpdatePlugin || approval.Status != model.ApprovalApproved {
		return node, task, errAgentBinaryDenied
	}
	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil || payload.NodeID != node.ID {
		return node, task, errAgentBinaryDenied
	}
	if payload.BinarySource != agentBinarySourceControlPlane {
		return node, task, errAgentBinaryDenied
	}
	if payload.TargetVersion != ref.Version || !strings.EqualFold(payload.SHA256, ref.SHA256) {
		return node, task, errAgentBinaryDenied
	}
	osName, arch, err := agentPlatformForNode(node)
	if err != nil || osName != ref.OS || arch != ref.Arch {
		return node, task, errAgentBinaryDenied
	}
	return node, task, nil
}

// taskLeaseHolder returns the node whose live lease the caller proved. The
// compare is constant time so a wrong lease cannot be recovered byte by byte
// from response timing.
func taskLeaseHolder(task model.Task, lease string) (string, bool) {
	if strings.TrimSpace(lease) == "" {
		return "", false
	}
	for nodeID, held := range task.TargetLeases {
		if held.LeaseID != "" && subtle.ConstantTimeCompare([]byte(held.LeaseID), []byte(lease)) == 1 {
			return nodeID, true
		}
	}
	if task.LeasedBy != "" && task.LeaseID != "" &&
		subtle.ConstantTimeCompare([]byte(task.LeaseID), []byte(lease)) == 1 {
		return task.LeasedBy, true
	}
	return "", false
}

// reservedAgentArtifactBucket keeps agent binaries out of the generic storage
// surfaces. Those bytes are installed as root by every node in the fleet, so
// they are not ordinary static content: a static:write scope must not be able to
// replace them and an anonymous hostname binding must not be able to publish
// them.
func reservedAgentArtifactBucket(bucket string) bool {
	return strings.TrimSpace(bucket) == agentArtifactBucket
}

func errReservedAgentArtifactBucket() error {
	return fmt.Errorf("bucket %q holds agent release binaries and is managed through /api/nodes/agent-updates/artifacts", agentArtifactBucket)
}
