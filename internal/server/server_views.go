package server

import (
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
	ActorID    string    `json:"actor_id"`
	ApprovedBy string    `json:"approved_by,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func toApprovalView(a model.Approval) approvalView {
	return approvalView{
		ID: a.ID, NodeID: a.NodeID, Plugin: a.Plugin, Action: a.Action,
		Plan: a.Plan, Status: a.Status, ActorID: a.ActorID,
		ApprovedBy: a.ApprovedBy, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt,
	}
}

func toApprovalViews(in []model.Approval) []approvalView {
	out := make([]approvalView, 0, len(in))
	for _, a := range in {
		out = append(out, toApprovalView(a))
	}
	return out
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
