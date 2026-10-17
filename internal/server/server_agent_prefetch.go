package server

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// Design 31, S4: the agent fetches the binary of its open update in the
// background, with no task deadline, into the very file the apply script
// continues, so the task itself has nothing left to download.
//
// The config pull names the one file to fetch (agent_update.prefetch) and the
// digests the node may keep (agent_update.keep). The agent fetches from
// agentPrefetchPathPrefix with its node credential, which this route accepts
// only for the object the node's open approval names. Nothing executes
// because of a prefetch: the bytes land in a root-only file named by a
// validated digest, and only the approved task's digest and version checks
// decide whether they ever run.
//
// "Open" means pending, or approved and not yet running. A pending approval
// counts, so an operator can see that a node holds the whole file before
// approving and the decision costs no download time; the auto-plan sweep cuts
// a pending plan for every online node on each release, which pre-positions
// the bytes fleet-wide at one fetch per node.
//
// An old agent never calls the route and ignores agent_update. An old server
// sends no agent_update, and an agent then neither fetches nor prunes, so the
// update runs entirely through the task as before.
const (
	agentPrefetchPathPrefix = "/api/agent/prefetch-binary/"

	// agentPrefetchServeSec bounds one prefetch response. Prefetch has no
	// task whose timeout could bound it, and a node on a line that delivers
	// under a kilobyte a second needs hours for the file. The agent resumes
	// where a response ended, so a fixed bound costs one reconnect per half
	// hour on such a line and frees a stuck connection.
	agentPrefetchServeSec = 1800

	// agentPrefetchMaxInFlight is how many prefetch responses one node may
	// have open at once. The agent opens one; the second slot lets it
	// reconnect while a dead connection still waits out its deadline.
	agentPrefetchMaxInFlight = 2

	// agentPrefetchKeepMax bounds the keep list. A node has one open update
	// approval almost always, and two while a newer plan waits behind a
	// running one; each names at most two digests.
	agentPrefetchKeepMax = 8

	// agentPrefetchIndexTTL is how old the config pull's index of open agent
	// update approvals may be. One walk of the approval table then serves
	// every node that pulls inside it.
	agentPrefetchIndexTTL = 5 * time.Second

	// agentPrefetchReportTTL is how long a node's prefetch report is shown.
	// A beat comes every interval, so a report this old is from a node that
	// stopped reporting.
	agentPrefetchReportTTL = 10 * time.Minute

	agentPrefetchReasonMax = 200
)

var errAgentPrefetchDenied = errors.New("agent binary prefetch is not authorized for this node")

// agentUpdateAgentConfig is the agent_update block of the agent config pull.
// It is always present from a server that serves prefetch, which is how an
// agent tells an old server (no block: do nothing) from one with nothing to
// fetch (a block without prefetch: prune what keep does not name).
type agentUpdateAgentConfig struct {
	Prefetch *agentPrefetchTarget `json:"prefetch,omitempty"`
	// Keep lists the digests of every pending or approved agent update for
	// this node, running ones included. The agent removes kept downloads
	// whose digest is not here and never touches one that is, so a running
	// update's partial survives a config pulled while its task runs.
	Keep []string `json:"keep"`
}

// agentPrefetchTarget names the one file the agent fetches. It carries
// digests and sizes, never a URL: the agent builds the URL from its own
// enrolled server address and these validated fields. Size is the size of
// the file fetched, the compressed one when CompressedSHA256 is set, and
// BinarySize that of the binary it installs, which sizes the disk check.
// InstallPath is the plan's, from which the agent resolves the directory the
// apply script will keep the download in, by the script's own rule.
type agentPrefetchTarget struct {
	ApprovalID       string `json:"approval_id"`
	Version          string `json:"version"`
	OS               string `json:"os"`
	Arch             string `json:"arch"`
	SHA256           string `json:"sha256"`
	CompressedSHA256 string `json:"compressed_sha256,omitempty"`
	Size             int    `json:"size"`
	BinarySize       int    `json:"binary_size"`
	InstallPath      string `json:"install_path"`
}

// agentConfigResponse is the config pull's answer: the SDK's agent config
// with the prefetch block beside it. The block is defined here and in the
// agent rather than in the SDK, so S4 ships without an SDK pin bump; the JSON
// is the same either way.
type agentConfigResponse struct {
	model.AgentConfig
	AgentUpdate *agentUpdateAgentConfig `json:"agent_update,omitempty"`
}

// agentPrefetchPlan is what the config and the route both take from the
// node's approvals, so the file the config names and the file the route
// serves can never differ.
type agentPrefetchPlan struct {
	config   agentUpdateAgentConfig
	approval model.Approval
	ref      agentArtifactRef
	ok       bool
}

// agentPrefetchPlanFor reads the node's open agent update approvals, pending
// or approved, and picks the one whose task runs next. An approved plan with
// its apply task queued runs before any newer plan, and its script removes
// every other kept download, so it is the one to fetch; while one is leased
// its script is running and nothing is fetched. Otherwise it is the newest
// open plan, since a new plan supersedes the older ones. That plan is the
// prefetch target when everything holds:
//
//   - task execution is enabled on this server, so the update can run;
//   - the plan fetches from this control plane, under the source walk, whose
//     script finishes a complete kept file instead of asking for a range past
//     its end (curl 7 reports that 416 as a failure, so an S1 script would
//     fail forever on a file prefetch completed);
//   - its update has not already run and wait for the node's confirmation;
//   - the node does not already report the target version;
//   - the control plane holds exactly the pinned object.
//
// fresh reads the store; otherwise the approvals come from an index at most
// agentPrefetchIndexTTL old, which is what the config pull uses. A stale
// index costs nothing: the route reads fresh and refuses a file whose plan
// closed meanwhile, the agent holds every download while a task runs, and
// keep names every open plan's digests, which a few seconds cannot make
// wrong about a plan that already had a kept file.
func (s *Server) agentPrefetchPlanFor(node model.Node, fresh bool) agentPrefetchPlan {
	plan := agentPrefetchPlan{config: agentUpdateAgentConfig{Keep: []string{}}}
	type candidate struct {
		approval model.Approval
		payload  agentUpdatePayload
	}
	var open []candidate
	for _, approval := range s.openAgentUpdateApprovals(node.ID, fresh) {
		payload, err := agentUpdatePayloadFromApproval(approval)
		if err != nil || payload.NodeID != node.ID {
			continue
		}
		for _, digest := range []string{payload.SHA256, payload.CompressedSHA256} {
			if digest != "" && len(plan.config.Keep) < agentPrefetchKeepMax && !slices.Contains(plan.config.Keep, digest) {
				plan.config.Keep = append(plan.config.Keep, digest)
			}
		}
		open = append(open, candidate{approval: approval, payload: payload})
	}
	if len(open) == 0 || s.taskExecutionDisabled {
		return plan
	}
	next := open[0]
	for _, c := range open {
		if c.approval.Status != model.ApprovalApproved {
			continue
		}
		// Only an approved plan can have a task, so the task table is
		// walked for those alone.
		queued, leased := s.store.ApprovalTaskState(c.approval.ID)
		if leased {
			return plan
		}
		if queued {
			next = c
			break
		}
	}
	target, ref, ok := s.agentPrefetchTargetFor(node, next.approval, next.payload)
	if !ok {
		return plan
	}
	plan.config.Prefetch = &target
	plan.approval, plan.ref, plan.ok = next.approval, ref, true
	return plan
}

// openAgentUpdateApprovals is the node's pending and approved agent update
// approvals, newest first.
func (s *Server) openAgentUpdateApprovals(nodeID string, fresh bool) []model.Approval {
	if fresh {
		return s.store.NodeOpenPluginApprovals(nodeID, agentUpdatePlugin)
	}
	b := &s.agentPrefetch
	b.mu.Lock()
	defer b.mu.Unlock()
	now := s.now()
	if b.index == nil || now.Sub(b.indexAt) >= agentPrefetchIndexTTL || now.Before(b.indexAt) {
		b.index, b.indexAt = s.store.OpenPluginApprovals(agentUpdatePlugin), now
	}
	return b.index[nodeID]
}

func (s *Server) agentPrefetchTargetFor(node model.Node, approval model.Approval, payload agentUpdatePayload) (agentPrefetchTarget, agentArtifactRef, bool) {
	if normalizeAgentBinarySource(payload.BinarySource) != agentBinarySourceControlPlane || !agentUpdateWalks(approval.Plan, payload) {
		return agentPrefetchTarget{}, agentArtifactRef{}, false
	}
	if isAgentUpdateAwaitingConfirmation(approval) {
		return agentPrefetchTarget{}, agentArtifactRef{}, false
	}
	if strings.TrimPrefix(strings.TrimSpace(node.AgentVersion), "v") == payload.TargetVersion {
		return agentPrefetchTarget{}, agentArtifactRef{}, false
	}
	osName, arch, err := agentPlatformForNode(node)
	if err != nil {
		return agentPrefetchTarget{}, agentArtifactRef{}, false
	}
	// The plan names the object exactly, so it is looked up by its path
	// rather than by listing the bucket.
	ref := agentArtifactRef{Version: payload.TargetVersion, OS: osName, Arch: arch, SHA256: payload.SHA256, GzipSHA256: payload.CompressedSHA256}
	if ref.validate() != nil {
		return agentPrefetchTarget{}, agentArtifactRef{}, false
	}
	obj, ok := s.store.StaticObject(agentArtifactBucket, ref.objectPath())
	if !ok {
		return agentPrefetchTarget{}, agentArtifactRef{}, false
	}
	// The script fetches binary_url from this control plane; a plan that
	// names another object, or another origin, is not the file it continues.
	if base := s.agentBinaryBaseURL(); base == "" || payload.BinaryURL != base+ref.urlPath() {
		return agentPrefetchTarget{}, agentArtifactRef{}, false
	}
	servedSize := agentArtifactDecodedSize(obj.Content)
	binarySize := servedSize
	if ref.GzipSHA256 != "" {
		if payload.CompressedSize != servedSize {
			return agentPrefetchTarget{}, agentArtifactRef{}, false
		}
		binarySize = payload.BinarySize
	}
	if servedSize <= 0 || servedSize > maxAgentArtifactBytes || binarySize <= 0 || binarySize > maxAgentArtifactBytes {
		return agentPrefetchTarget{}, agentArtifactRef{}, false
	}
	return agentPrefetchTarget{
		ApprovalID: approval.ID, Version: ref.Version, OS: ref.OS, Arch: ref.Arch,
		SHA256: ref.SHA256, CompressedSHA256: ref.GzipSHA256,
		Size: servedSize, BinarySize: binarySize, InstallPath: payload.InstallPath,
	}, ref, true
}

// handleAgentPrefetchBinary serves the object the node's open agent update
// names, to that node, on its node credential. It is the binary route with
// one difference in authorization: the node proves itself with its token
// instead of a task lease, and the object must be the one agentPrefetchPlanFor
// names now. Everything after that is the binary route's own body: integrity
// re-verification, ranges with the digest as ETag, and the audit, here as
// agent.binary.prefetch.
//
// The node credential is long-lived, unlike a lease, but this route hands out
// only a public release binary, and only the one the node's own open approval
// pins, so it reaches nothing a lease would not.
func (s *Server) handleAgentPrefetchBinary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	ref, ok := parseAgentArtifactPath(strings.TrimPrefix(r.URL.Path, agentPrefetchPathPrefix))
	if !ok {
		writeError(w, http.StatusNotFound, errAgentArtifactNotFound)
		return
	}
	// The token travels in the Authorization header only, as on every other
	// agent route; a query-string token would land in access logs.
	node, ok := s.authenticateNode(r, strings.TrimSpace(r.URL.Query().Get("node_id")), bearerToken(r))
	if !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	plan := s.agentPrefetchPlanFor(node, true)
	if !plan.ok || plan.ref != ref {
		reason := "no open agent update approval names this binary for this node"
		if plan.ok {
			reason = "the node's open agent update approval names another binary"
		}
		s.auditAgentPrefetchDenied(r, node.ID, ref, plan.approval.ID, reason)
		writeError(w, http.StatusForbidden, errAgentPrefetchDenied)
		return
	}
	if !s.agentPrefetch.enter(node.ID) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, errors.New("this node already has prefetch downloads in flight"))
		return
	}
	defer s.agentPrefetch.leave(node.ID)
	s.serveAgentArtifact(w, r, agentArtifactServe{
		action: "agent.binary.prefetch", node: node, ref: ref,
		idKey: "approval_id", id: plan.approval.ID,
		deadline: agentPrefetchServeSec * time.Second,
		// A node resumes after every cut, and a node holding its token can
		// ask for ranges as fast as the route limiter lets it, so the serve
		// audit is folded per node and approval: the first one in a minute
		// is written, with the count of those folded since the last.
		audit: s.agentPrefetch.serveAudits, auditKey: "prefetch|" + node.ID + "|" + plan.approval.ID,
	})
}

// auditAgentPrefetchDenied records a prefetch this route refused to an
// authenticated node. The node's credential bounds who can reach it, but a
// node loops on its own retries, so it shares the authentication-failure
// throttle the binary route's refusals use.
func (s *Server) auditAgentPrefetchDenied(r *http.Request, nodeID string, ref agentArtifactRef, approvalID, reason string) {
	emit, suppressed, dropped := s.authFailAuditThrottle.Allow("agentprefetch|"+auditBucketedIP(s.clientIP(r)), s.now())
	if !emit {
		return
	}
	meta := map[string]string{
		"version": ref.Version, "os": ref.OS, "arch": ref.Arch, "sha256": ref.SHA256,
	}
	if ref.GzipSHA256 != "" {
		meta["compressed_sha256"] = ref.GzipSHA256
	}
	if approvalID != "" {
		meta["approval_id"] = approvalID
	}
	if suppressed > 0 {
		meta["suppressed_repeats"] = strconv.Itoa(suppressed)
	}
	if dropped > 0 {
		meta["global_suppressed"] = strconv.Itoa(dropped)
	}
	s.recordRequestAudit(r, model.AuditEvent{
		ID:       id.New("audit"),
		NodeID:   nodeID,
		Action:   "agent.binary.prefetch",
		Decision: "deny",
		Reason:   reason,
		Metadata: meta,
	})
}

// Prefetch states an agent reports.
const (
	agentPrefetchFetching = "fetching"
	agentPrefetchComplete = "complete"
	agentPrefetchWaiting  = "waiting"
	agentPrefetchRefused  = "refused"
)

// agentPrefetchFacts is the "prefetch" key of a heartbeat: what the agent
// holds of the file the config named. The agent sends it while the config
// names a prefetch.
type agentPrefetchFacts struct {
	ApprovalID string `json:"approval_id"`
	SHA256     string `json:"sha256"`
	Bytes      int64  `json:"bytes"`
	Size       int64  `json:"size"`
	State      string `json:"state"`
	Reason     string `json:"reason,omitempty"`
}

// agentPrefetchView is the progress shown beside the approval it is for.
type agentPrefetchView struct {
	State      string    `json:"state"`
	Bytes      int64     `json:"bytes"`
	Size       int64     `json:"size"`
	Reason     string    `json:"reason,omitempty"`
	ReportedAt time.Time `json:"reported_at"`
}

type agentPrefetchRecord struct {
	facts      agentPrefetchFacts
	receivedAt time.Time
}

// agentPrefetchBook holds each node's last prefetch report and its prefetch
// downloads in flight. Guarded by its own mutex, never taken while holding a
// store lock. Reports are kept in memory and replaced per beat: they are a
// fact about now, like loop health.
type agentPrefetchBook struct {
	mu       sync.Mutex
	records  map[string]agentPrefetchRecord
	inFlight map[string]int
	// index is the open agent update approvals by node, read for the config
	// pull at indexAt.
	index   map[string][]model.Approval
	indexAt time.Time
	// serveAudits folds the prefetch route's serve audits; set by New.
	serveAudits *auditFailureThrottle
}

func (b *agentPrefetchBook) enter(nodeID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.inFlight == nil {
		b.inFlight = map[string]int{}
	}
	if b.inFlight[nodeID] >= agentPrefetchMaxInFlight {
		return false
	}
	b.inFlight[nodeID]++
	return true
}

func (b *agentPrefetchBook) leave(nodeID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.inFlight[nodeID] <= 1 {
		delete(b.inFlight, nodeID)
		return
	}
	b.inFlight[nodeID]--
}

// noteAgentPrefetch records a node's prefetch report from one beat. A beat
// without one (an older agent, or nothing to fetch) clears the record, so a
// finished or withdrawn prefetch stops being shown. A report that fails
// validation is dropped and leaves the previous record alone.
func (s *Server) noteAgentPrefetch(nodeID string, facts *agentPrefetchFacts) {
	b := &s.agentPrefetch
	if facts == nil {
		b.mu.Lock()
		delete(b.records, nodeID)
		b.mu.Unlock()
		return
	}
	bounded, ok := boundAgentPrefetchFacts(*facts)
	if !ok {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.records == nil {
		b.records = map[string]agentPrefetchRecord{}
	}
	b.records[nodeID] = agentPrefetchRecord{facts: bounded, receivedAt: s.now()}
}

func (s *Server) forgetAgentPrefetch(nodeID string) {
	b := &s.agentPrefetch
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.records, nodeID)
}

// boundAgentPrefetchFacts accepts a report only in the shape the agent
// sends. The values come from the node and reach the console, so the
// reason keeps printable ASCII only and is cut to a bound.
func boundAgentPrefetchFacts(f agentPrefetchFacts) (agentPrefetchFacts, bool) {
	switch f.State {
	case agentPrefetchFetching, agentPrefetchComplete, agentPrefetchWaiting, agentPrefetchRefused:
	default:
		return agentPrefetchFacts{}, false
	}
	if f.ApprovalID == "" || len(f.ApprovalID) > 64 || strings.IndexFunc(f.ApprovalID, func(r rune) bool {
		return !(r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'))
	}) >= 0 {
		return agentPrefetchFacts{}, false
	}
	if f.SHA256 != "" && !agentSHA256Re.MatchString(f.SHA256) {
		return agentPrefetchFacts{}, false
	}
	if f.Size < 0 || f.Size > maxAgentArtifactBytes || f.Bytes < 0 || f.Bytes > f.Size {
		return agentPrefetchFacts{}, false
	}
	f.Reason = strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return -1
		}
		return r
	}, f.Reason)
	if len(f.Reason) > agentPrefetchReasonMax {
		f.Reason = f.Reason[:agentPrefetchReasonMax]
	}
	return f, true
}

// agentPrefetchViewFor is the progress to show beside an approval: the
// node's last report, when it is recent and is for this approval.
func (s *Server) agentPrefetchViewFor(a model.Approval) *agentPrefetchView {
	if a.Plugin != agentUpdatePlugin || (a.Status != model.ApprovalPending && a.Status != model.ApprovalApproved) {
		return nil
	}
	b := &s.agentPrefetch
	b.mu.Lock()
	rec, ok := b.records[a.NodeID]
	b.mu.Unlock()
	if !ok || rec.facts.ApprovalID != a.ID || s.now().Sub(rec.receivedAt) > agentPrefetchReportTTL {
		return nil
	}
	// The report is the node's own word. It is shown only when it names the
	// file this approval pins, so it cannot stand for another one.
	payload, err := agentUpdatePayloadFromApproval(a)
	if err != nil {
		return nil
	}
	served := payload.SHA256
	if payload.CompressedSHA256 != "" {
		served = payload.CompressedSHA256
		if rec.facts.Size != int64(payload.CompressedSize) {
			return nil
		}
	}
	if rec.facts.SHA256 != served {
		return nil
	}
	return &agentPrefetchView{
		State: rec.facts.State, Bytes: rec.facts.Bytes, Size: rec.facts.Size,
		Reason: rec.facts.Reason, ReportedAt: rec.receivedAt,
	}
}

// annotateAgentPrefetch fills Prefetch on the agent update rows of a page.
func (s *Server) annotateAgentPrefetch(views []approvalView, rows []model.Approval) []approvalView {
	for i := range views {
		if i < len(rows) && rows[i].ID == views[i].ID {
			views[i].Prefetch = s.agentPrefetchViewFor(rows[i])
		}
	}
	return views
}
