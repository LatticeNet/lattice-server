package server

import (
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/notify"
)

// Witness status: what the console shows about the control-plane witness.
//
// The node agent attaches the witness's status file to its heartbeat as
// `witness`. It is kept here in memory beside agentRuntime, never in the
// state: it arrives every heartbeat interval, a restart repopulates it from
// the next beat, and writing it to state.json would be the whole-state write
// storm a101 shipped. What is configured comes from the witness approvals,
// which are already stored.

// witnessReport is the node agent's witness.State as relayed on a heartbeat.
type witnessReport struct {
	Version             int       `json:"version"`
	ConfigSHA256        string    `json:"config_sha256,omitempty"`
	StartedAt           time.Time `json:"started_at,omitzero"`
	Phase               string    `json:"phase"`
	HealthURL           string    `json:"health_url,omitempty"`
	ReferenceCount      int       `json:"reference_count,omitempty"`
	IntervalSeconds     int       `json:"interval_seconds,omitempty"`
	HoldSeconds         int       `json:"hold_seconds,omitempty"`
	LastCheckAt         time.Time `json:"last_check_at,omitzero"`
	LastCheckOK         bool      `json:"last_check_ok"`
	LastCheckDetail     string    `json:"last_check_detail,omitempty"`
	LastOKAt            time.Time `json:"last_ok_at,omitzero"`
	FailingSince        time.Time `json:"failing_since,omitzero"`
	ConsecutiveFailures int       `json:"consecutive_failures,omitempty"`
	NetworkDownSince    time.Time `json:"network_down_since,omitzero"`
	Alerted             bool      `json:"alerted"`
	AlertedAt           time.Time `json:"alerted_at,omitzero"`
	DownSince           time.Time `json:"down_since,omitzero"`
	LastPushAt          time.Time `json:"last_push_at,omitzero"`
	LastPushKind        string    `json:"last_push_kind,omitempty"`
	LastPushOK          bool      `json:"last_push_ok"`
	LastPushError       string    `json:"last_push_error,omitempty"`
	Pushes              int       `json:"pushes,omitempty"`
	// RelayedAt is the node's clock when its agent read the status file.
	// It shares a clock with the times above, so RelayedAt minus the last
	// check is the real age of that check whatever the node's skew.
	RelayedAt time.Time `json:"relayed_at,omitzero"`
}

// witnessPhases are the phases the witness reports; anything else reads as
// unknown.
var witnessPhases = map[string]bool{"starting": true, "watching": true, "failing": true, "down": true, "network_down": true}

var witnessSHARe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// witnessShortText bounds a classified reason ("http 503", "timeout"): the
// witness never sends raw error text, and the server does not trust that it
// never will.
func witnessShortText(v string) string {
	v = strings.TrimSpace(witnessPlanLine(strings.ToValidUTF8(v, "")))
	if len(v) <= 64 {
		return v
	}
	// Cut on a rune boundary, so a multi-byte character is dropped whole
	// rather than sent on as half a character.
	cut := 64
	for cut > 0 && !utf8.RuneStart(v[cut]) {
		cut--
	}
	return v[:cut]
}

// witnessCheckStaleAfter is how old the witness's last check may be, by the
// node's own clock, before the witness counts as stopped: three intervals, and
// never under two minutes, so one slow check (up to 10 s for the control plane,
// 8 s for the references, 10 s for a push) is not mistaken for a dead witness.
func witnessCheckStaleAfter(r witnessReport) time.Duration {
	interval := time.Duration(r.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = witnessDefaultInterval * time.Second
	}
	return max(3*interval, 2*time.Minute)
}

// witnessCheckStale reports whether the relayed status is one the witness
// stopped updating: its service stopped, wedged or was disabled, or it cannot
// save its state. The agent relays the file it finds whether or not the
// witness is alive, so the relay being fresh says nothing about this. Both
// times are the node's, so no skew against this server enters. A report
// without relayed_at cannot be judged and is not called stale.
func witnessCheckStale(r witnessReport) bool {
	if r.RelayedAt.IsZero() {
		return false
	}
	last := r.LastCheckAt
	if r.StartedAt.After(last) {
		last = r.StartedAt
	}
	if last.IsZero() {
		return false
	}
	return r.RelayedAt.Sub(last) > witnessCheckStaleAfter(r)
}

// normalizeWitnessReport bounds every field a node can send.
func normalizeWitnessReport(in witnessReport) witnessReport {
	out := in
	if !witnessPhases[out.Phase] {
		out.Phase = "unknown"
	}
	if !witnessSHARe.MatchString(out.ConfigSHA256) {
		out.ConfigSHA256 = ""
	}
	if len(out.HealthURL) > 512 || checkWitnessWatchURL("health_url", out.HealthURL) != nil {
		out.HealthURL = ""
	}
	out.LastCheckDetail = witnessShortText(out.LastCheckDetail)
	out.LastPushError = witnessShortText(out.LastPushError)
	if out.LastPushKind != "down" && out.LastPushKind != "recovery" {
		out.LastPushKind = ""
	}
	clamp := func(n, hi int) int { return max(0, min(n, hi)) }
	out.ReferenceCount = clamp(out.ReferenceCount, witnessMaxReferences)
	out.IntervalSeconds = clamp(out.IntervalSeconds, witnessMaxInterval)
	out.HoldSeconds = clamp(out.HoldSeconds, witnessMaxHold)
	out.ConsecutiveFailures = clamp(out.ConsecutiveFailures, 1<<20)
	out.Pushes = clamp(out.Pushes, 1<<20)
	return out
}

// witnessReports is the live status per node.
type witnessReports struct {
	mu   sync.RWMutex
	byID map[string]witnessReportEntry
}

type witnessReportEntry struct {
	report     witnessReport
	receivedAt time.Time
}

// noteWitnessReport keeps the latest status a node relayed.
func (s *Server) noteWitnessReport(nodeID string, report *witnessReport) {
	if report == nil || report.Version == 0 {
		return
	}
	entry := witnessReportEntry{report: normalizeWitnessReport(*report), receivedAt: s.now()}
	s.witness.mu.Lock()
	defer s.witness.mu.Unlock()
	if s.witness.byID == nil {
		s.witness.byID = map[string]witnessReportEntry{}
	}
	s.witness.byID[nodeID] = entry
}

func (s *Server) witnessReportFor(nodeID string) (witnessReportEntry, bool) {
	s.witness.mu.RLock()
	defer s.witness.mu.RUnlock()
	e, ok := s.witness.byID[nodeID]
	return e, ok
}

func (s *Server) witnessReportNodes() []string {
	s.witness.mu.RLock()
	defer s.witness.mu.RUnlock()
	out := make([]string, 0, len(s.witness.byID))
	for id := range s.witness.byID {
		out = append(out, id)
	}
	return out
}

// witnessAppliedAt is when an applied witness plan ran: its task result
// stamps UpdatedAt on success.
func witnessAppliedAt(a model.Approval) time.Time {
	if !a.UpdatedAt.IsZero() {
		return a.UpdatedAt
	}
	return a.CreatedAt
}

// latestAppliedWitness is the witness plan that last ran on a node, judged by
// when it ran rather than when it was filed: two plans can wait side by side
// and be approved in either order, and the node runs whichever applied last.
func latestAppliedWitness(approvals []model.Approval, nodeID string) (model.Approval, bool) {
	var latest model.Approval
	found := false
	for _, a := range approvals {
		if a.NodeID != nodeID || !isWitnessApproval(a) || a.Status != model.ApprovalApplied {
			continue
		}
		if !found || witnessAppliedAt(a).After(witnessAppliedAt(latest)) {
			latest, found = a, true
		}
	}
	return latest, found
}

// witnessApprovalView is the witness approval a node's status is read
// against.
type witnessApprovalView struct {
	ApprovalID   string    `json:"approval_id"`
	Action       string    `json:"action"` // configure or remove
	Status       string    `json:"status"`
	Reason       string    `json:"reason,omitempty"`
	ConfigSHA256 string    `json:"config_sha256,omitempty"`
	ChannelID    string    `json:"channel_id,omitempty"`
	ChannelName  string    `json:"channel_name,omitempty"`
	KeyPrefix    string    `json:"key_sha256_prefix,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at,omitzero"`
}

func toWitnessApprovalView(a model.Approval, channels map[string]model.NotifyChannel) witnessApprovalView {
	v := witnessApprovalView{
		ApprovalID: a.ID, Action: "configure", Status: a.Status, Reason: a.Reason,
		CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt,
	}
	if a.Action == witnessRemoveAction {
		v.Action = "remove"
		return v
	}
	v.ConfigSHA256 = approvalPlanField(a.Plan, witnessFieldConfigSHA)
	v.ChannelID = approvalPlanField(a.Plan, witnessFieldChannelID)
	v.KeyPrefix = approvalPlanField(a.Plan, witnessFieldKeyPrefix)
	if c, ok := channels[v.ChannelID]; ok {
		v.ChannelName = notifyChannelLabel(c)
	}
	return v
}

// witnessNodeView is one node's witness: the last applied plan, any plan
// still waiting, and what the witness itself last reported.
type witnessNodeView struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name"`
	// Capable is whether the node's agent advertises witness mode now.
	Capable bool `json:"capable"`
	// Configured is the last applied plan when it configured a witness; nil
	// when none was applied or the last applied one removed it.
	Configured *witnessApprovalView `json:"configured,omitempty"`
	// Pending is the newest plan not yet applied (pending, or approved with
	// its task still to report).
	Pending *witnessApprovalView `json:"pending,omitempty"`
	// LastFailed is the newest plan whose task failed after the last applied
	// one.
	LastFailed *witnessApprovalView `json:"last_failed,omitempty"`
	Report     *witnessReport       `json:"report,omitempty"`
	ReportedAt time.Time            `json:"reported_at,omitzero"`
	// ReportFresh is false when the agent has not relayed the status within
	// witnessReportFreshFor.
	ReportFresh bool `json:"report_fresh"`
	// CheckStale is true when the relayed status is older than the witness
	// would let it get (witnessCheckStaleAfter, by the node's clock): the
	// agent still relays the file, but the witness stopped updating it, so
	// nothing is watching the control plane from this node.
	CheckStale bool `json:"check_stale"`
	// ConfigMatches is whether the witness runs the config the applied plan
	// wrote; false while a node still runs an older one, or none.
	ConfigMatches bool `json:"config_matches"`
}

// witnessStatusResponse is GET /api/notify/witness.
type witnessStatusResponse struct {
	HealthURL     string            `json:"health_url,omitempty"`
	HealthURLHint string            `json:"health_url_error,omitempty"`
	Nodes         []witnessNodeView `json:"nodes"`
	// CapableNodes lists every node whose agent advertises witness mode, for
	// the setup picker.
	CapableNodes []witnessCapableNode `json:"capable_nodes"`
	Defaults     witnessDefaultsView  `json:"defaults"`
}

type witnessCapableNode struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name"`
	Online   bool   `json:"online"`
}

type witnessDefaultsView struct {
	ReferenceURLs   []string `json:"reference_urls"`
	IntervalSeconds int      `json:"interval_seconds"`
	HoldSeconds     int      `json:"hold_seconds"`
	RecoverSeconds  int      `json:"recover_seconds"`
	BarkLevel       string   `json:"bark_level"`
	BarkLevels      []string `json:"bark_levels"`
	KeyFile         string   `json:"key_file"`
	ConfigFile      string   `json:"config_file"`
	Unit            string   `json:"unit"`
}

// witnessReportFreshFor is how long a relayed status stays current: three
// heartbeats at the slowest interval an agent is normally run with (60 s).
const witnessReportFreshFor = 3 * time.Minute

func (s *Server) witnessStatus() witnessStatusResponse {
	resp := witnessStatusResponse{
		Nodes:        []witnessNodeView{},
		CapableNodes: []witnessCapableNode{},
		Defaults: witnessDefaultsView{
			ReferenceURLs: append([]string(nil), witnessDefaultReferences...), IntervalSeconds: witnessDefaultInterval,
			HoldSeconds: witnessDefaultHold, RecoverSeconds: witnessDefaultRecover, BarkLevel: witnessDefaultLevel,
			BarkLevels: append([]string(nil), notify.BarkLevels...), KeyFile: witnessKeyPath, ConfigFile: witnessConfigPath, Unit: witnessUnitName,
		},
	}
	if u, err := s.witnessHealthURL(); err == nil {
		resp.HealthURL = u
	} else {
		resp.HealthURLHint = err.Error()
	}
	channels := map[string]model.NotifyChannel{}
	for _, c := range s.store.NotifyChannels() {
		channels[c.ID] = c
	}
	// Witness approvals per node, newest first.
	byNode := map[string][]model.Approval{}
	for _, a := range s.store.Approvals() {
		if isWitnessApproval(a) {
			byNode[a.NodeID] = append(byNode[a.NodeID], a)
		}
	}
	nodeIDs := map[string]bool{}
	for id := range byNode {
		nodeIDs[id] = true
	}
	for _, id := range s.witnessReportNodes() {
		nodeIDs[id] = true
	}
	now := s.now()
	nodes := map[string]model.Node{}
	for _, n := range s.store.Nodes() {
		nodes[n.ID] = n
		if s.agentHasCapability(n.ID, witnessCapability) {
			resp.CapableNodes = append(resp.CapableNodes, witnessCapableNode{NodeID: n.ID, NodeName: n.Name, Online: n.Online})
		}
	}
	sort.Slice(resp.CapableNodes, func(i, j int) bool { return resp.CapableNodes[i].NodeName < resp.CapableNodes[j].NodeName })
	for id := range nodeIDs {
		node, ok := nodes[id]
		if !ok {
			continue // a deleted node's witness history is the audit trail's
		}
		view := witnessNodeView{NodeID: id, NodeName: node.Name, Capable: s.agentHasCapability(id, witnessCapability)}
		approvals := byNode[id]
		sort.Slice(approvals, func(i, j int) bool { return approvals[i].CreatedAt.After(approvals[j].CreatedAt) })
		// The plan that last ran on the node, by when it ran: plans can be
		// approved in another order than they were filed.
		applied, hasApplied := latestAppliedWitness(approvals, id)
		if hasApplied && applied.Action == witnessConfigureAction {
			v := toWitnessApprovalView(applied, channels)
			view.Configured = &v
		}
		for _, a := range approvals {
			switch {
			case a.Status == model.ApprovalPending || a.Status == model.ApprovalApproved:
				// Still able to change the node, however old.
				if view.Pending == nil {
					v := toWitnessApprovalView(a, channels)
					view.Pending = &v
				}
			case a.Status == model.ApprovalRejected && a.Reason != "" && view.LastFailed == nil:
				// A failure before the last applied plan is history.
				if !hasApplied || a.UpdatedAt.After(witnessAppliedAt(applied)) {
					v := toWitnessApprovalView(a, channels)
					view.LastFailed = &v
				}
			}
		}
		if entry, ok := s.witnessReportFor(id); ok {
			report := entry.report
			view.Report = &report
			view.ReportedAt = entry.receivedAt
			view.ReportFresh = now.Sub(entry.receivedAt) <= witnessReportFreshFor
			view.CheckStale = witnessCheckStale(report)
			view.ConfigMatches = view.Configured != nil && report.ConfigSHA256 != "" && report.ConfigSHA256 == view.Configured.ConfigSHA256
		}
		resp.Nodes = append(resp.Nodes, view)
	}
	sort.Slice(resp.Nodes, func(i, j int) bool { return resp.Nodes[i].NodeName < resp.Nodes[j].NodeName })
	return resp
}

// handleWitnessStatus answers the Notifications page. The status names the
// control plane's URL and the channel the witness pushes to, so it is read
// like the rest of the notify surface: notify:admin, not node-confined.
func (s *Server) handleWitnessStatus(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if s.refuseConfinedNotifyRead(w, p, "notify.witness.status") {
		return
	}
	writeJSON(w, http.StatusOK, s.witnessStatus())
}
