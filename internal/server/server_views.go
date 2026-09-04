package server

import (
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Explicit, secret-free response projections for resources whose handlers
// previously serialized the raw model struct. None of these models carries a
// secret today; the view types ensure that a sensitive field added to the model
// later does not auto-serialize to clients until it is deliberately exposed. [D4]

type approvalView struct {
	ID         string    `json:"id"`
	NodeID     string    `json:"node_id"`
	Plugin     string    `json:"plugin"`
	Action     string    `json:"action"`
	Plan       string    `json:"plan"`
	Status     string    `json:"status"`
	Reason     string    `json:"reason,omitempty"`
	Stale      bool      `json:"stale,omitempty"`
	StaleCode  string    `json:"stale_code,omitempty"`
	ActorID    string    `json:"actor_id"`
	ApprovedBy string    `json:"approved_by,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`

	// RejectedBy and RejectedAt name the principal who rejected this approval
	// and when. Present only when a person or token said no; a rejected
	// approval without them was failed by its own task on the node, and Reason
	// carries that failure. The console used to infer the same split from
	// ApprovedBy being empty, which was a guess dressed as a fact.
	RejectedBy string     `json:"rejected_by,omitempty"`
	RejectedAt *time.Time `json:"rejected_at,omitempty"`

	// Operation binding (§9.3), surfaced so an operator reviews what will actually run:
	// which plugin version, which artifact, which nodes. Non-secret by construction —
	// the plan preview is where the plugin redacts anything sensitive.
	PluginVersion  string   `json:"plugin_version,omitempty"`
	ArtifactDigest string   `json:"artifact_digest,omitempty"`
	Service        string   `json:"service,omitempty"`
	Method         string   `json:"method,omitempty"`
	Targets        []string `json:"targets,omitempty"`

	// Waiting explains why an approved approval has not applied. Additive and
	// omitted for every other status, so a client that predates it sees the
	// shape it already had. Only the listing endpoint fills it in; see
	// server_approval_waiting.go for why the console cannot derive it.
	Waiting *approvalWaitView `json:"waiting,omitempty"`
}

// systemActorID is the recorded creator for approvals the server proposed
// itself (line-metadata discovery syncs, auto-planned agent updates). Early
// deployments stamped these "system" or left the actor empty; the view
// normalises both so readers see one honest identity and stored rows stay
// untouched.
const systemActorID = "lattice-server"

func approvalActorView(actor string) string {
	if actor == "" || actor == "system" {
		return systemActorID
	}
	return actor
}

func toApprovalView(a model.Approval) approvalView {
	action := a.Action
	if a.Plugin == "nftpolicy" {
		action = nftPolicyApprovalDisplayAction(a.Action)
	}
	if a.Plugin == "selfdns" {
		action = selfDNSApprovalDisplayAction(a.Action)
	}
	if a.Plugin == proxyCorePlugin {
		action = proxyCoreApprovalDisplayAction(a.Action)
	}
	if a.Plugin == agentUpdatePlugin {
		action = agentUpdateApprovalDisplayAction(a.Action)
	}
	stale, staleCode := approvalStaleMetadata(a)
	return approvalView{
		ID: a.ID, NodeID: a.NodeID, Plugin: a.Plugin, Action: action,
		// Reason is derived at read time (never migrated into stored rows) so
		// pre-reason approvals also answer a human-readable sentence.
		Plan: a.Plan, Status: a.Status, Reason: approvalDisplayReason(a), Stale: stale, StaleCode: staleCode, ActorID: approvalActorView(a.ActorID),
		ApprovedBy: a.ApprovedBy, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt,
		PluginVersion: a.PluginVersion, ArtifactDigest: a.ArtifactDigest,
		Service: a.Service, Method: a.Method, Targets: a.Targets,
	}
}

func approvalStaleMetadata(a model.Approval) (bool, string) {
	if a.Plugin == agentUpdatePlugin && strings.HasPrefix(a.Reason, errAgentUpdateApprovalStale.Error()) {
		return true, agentUpdateApprovalStaleCode
	}
	if sshGuardApprovalSuperseded(a) {
		// The code names why the row was retired, which the reason prose only
		// implies. Stale stays false: the console lights its freshness marker
		// on that flag, and a dismissed record is history, not a pending
		// decision gone stale.
		return false, sshGuardApprovalStaleCode
	}
	return false, ""
}

func toApprovalViews(in []model.Approval) []approvalView {
	out := make([]approvalView, 0, len(in))
	for _, a := range in {
		out = append(out, toApprovalView(a))
	}
	return out
}

// annotateApprovalRejections fills RejectedBy and RejectedAt from the store's
// rejection records. Only rejected rows are looked up: a record can exist for
// a row whose status write failed after it, and must not surface there.
func (s *Server) annotateApprovalRejections(views []approvalView) []approvalView {
	for i := range views {
		if views[i].Status != model.ApprovalRejected {
			continue
		}
		record, ok := s.store.ApprovalRejection(views[i].ID)
		if !ok {
			continue
		}
		at := record.At
		views[i].RejectedBy = record.ActorID
		views[i].RejectedAt = &at
	}
	return views
}

// approvalViewFor is the single-row form of the listing's projection.
func (s *Server) approvalViewFor(a model.Approval) approvalView {
	return s.annotateApprovalRejections([]approvalView{toApprovalView(a)})[0]
}

type monitorView struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Target      string    `json:"target"`
	IntervalSec int       `json:"interval_sec"`
	TimeoutSec  int       `json:"timeout_sec"`
	AssignAll   bool      `json:"assign_all"`
	NodeIDs     []string  `json:"node_ids,omitempty"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func toMonitorViews(in []model.Monitor) []monitorView {
	out := make([]monitorView, 0, len(in))
	for _, m := range in {
		out = append(out, monitorView{
			ID: m.ID, Name: m.Name, Type: m.Type, Target: m.Target,
			IntervalSec: m.IntervalSec, TimeoutSec: m.TimeoutSec, AssignAll: m.AssignAll,
			NodeIDs: m.NodeIDs, Enabled: m.Enabled, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt,
		})
	}
	return out
}

type tunnelView struct {
	ID              string                `json:"id"`
	Name            string                `json:"name"`
	NodeID          string                `json:"node_id"`
	TunnelID        string                `json:"tunnel_id"`
	CredentialsFile string                `json:"credentials_file,omitempty"`
	Ingress         []model.TunnelIngress `json:"ingress"`
	CreatedAt       time.Time             `json:"created_at"`
	UpdatedAt       time.Time             `json:"updated_at"`
}

func toTunnelViews(in []model.TunnelProfile) []tunnelView {
	out := make([]tunnelView, 0, len(in))
	for _, t := range in {
		out = append(out, tunnelView{
			ID: t.ID, Name: t.Name, NodeID: t.NodeID, TunnelID: t.TunnelID,
			CredentialsFile: t.CredentialsFile, Ingress: t.Ingress,
			CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt,
		})
	}
	return out
}
