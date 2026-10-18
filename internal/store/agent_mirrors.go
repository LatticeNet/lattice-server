package store

import (
	"errors"
	"maps"
	"slices"
	"sort"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Design 31, S5: the agent mirror registry and the chunk manifests of the
// agent binaries the control plane has verified.

// AgentMirrorRegistry is the mirror registry with the revision every
// approved change increments. An agent.mirrors plan names the revision it
// was made against and is refused when the registry has moved on.
type AgentMirrorRegistry struct {
	Revision int64               `json:"revision"`
	Mirrors  []model.AgentMirror `json:"mirrors,omitempty"`
	// FirstPlanned records when each mirror first appeared in an agent
	// update plan, so the notify path alerts once per mirror. It is not
	// registry configuration and never feeds the source order.
	FirstPlanned map[string]time.Time `json:"first_planned,omitempty"`
}

// AgentArtifactManifest is the chunk manifest of one verified agent binary:
// the SHA-256 of every ChunkSize bytes, hex, concatenated. It is recorded
// when the control plane verifies the bytes (an import, an upload, or the
// first plan for bytes it already held), whether or not it keeps them, and it
// is never changed afterwards: the key names the bytes.
type AgentArtifactManifest struct {
	Version   string `json:"version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	SHA256    string `json:"sha256"`
	Size      int    `json:"size"`
	ChunkSize int    `json:"chunk_size"`
	Chunks    string `json:"chunks"`
	// Source says how the control plane came to verify the bytes: import,
	// upload or stored.
	Source     string    `json:"source"`
	RecordedAt time.Time `json:"recorded_at"`
}

// AgentArtifactManifestKey is the key a manifest is stored under.
func AgentArtifactManifestKey(version, osName, arch, sha256Hex string) string {
	return version + "/" + osName + "/" + arch + "/" + sha256Hex
}

// ErrAgentMirrorRevision means the registry changed since a plan was made.
var ErrAgentMirrorRevision = errors.New("the agent mirror registry changed since the plan was made")

func cloneAgentMirror(m model.AgentMirror) model.AgentMirror {
	m.PreferFor = slices.Clone(m.PreferFor)
	return m
}

func cloneAgentMirrorRegistry(reg *AgentMirrorRegistry) AgentMirrorRegistry {
	if reg == nil {
		return AgentMirrorRegistry{}
	}
	out := AgentMirrorRegistry{Revision: reg.Revision, FirstPlanned: maps.Clone(reg.FirstPlanned)}
	for _, m := range reg.Mirrors {
		out.Mirrors = append(out.Mirrors, cloneAgentMirror(m))
	}
	return out
}

// AgentMirrorRegistry returns a copy of the registry, mirrors sorted by id.
func (s *Store) AgentMirrorRegistry() AgentMirrorRegistry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneAgentMirrorRegistry(s.state.AgentMirrors)
}

func stampAgentMirrors(previous []model.AgentMirror, next []model.AgentMirror, now time.Time) []model.AgentMirror {
	created := map[string]time.Time{}
	for _, m := range previous {
		created[m.ID] = m.CreatedAt
	}
	out := make([]model.AgentMirror, 0, len(next))
	for _, m := range next {
		m = cloneAgentMirror(m)
		if at, ok := created[m.ID]; ok && !at.IsZero() {
			m.CreatedAt = at
		} else {
			m.CreatedAt = now
		}
		m.UpdatedAt = now
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ReplaceAgentMirrors writes the whole registry and increments its revision.
// The server's only caller is the decision of an approved agent.mirrors plan
// (ApplyAgentMirrorPlan); tests seed with it.
func (s *Store) ReplaceAgentMirrors(mirrors []model.AgentMirror) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reg := cloneAgentMirrorRegistry(s.state.AgentMirrors)
	now := time.Now().UTC()
	forgetAgentMirrorFirstPlans(&reg, mirrors)
	reg.Mirrors = stampAgentMirrors(reg.Mirrors, mirrors, now)
	reg.Revision++
	staged := s.state
	staged.AgentMirrors = &reg
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	return reg.Revision, err
}

// forgetAgentMirrorFirstPlans drops the first-plan mark of every mirror that
// next deletes or points at another host, so an id reused for a new host
// alerts on its first plan again. reg is a clone the caller owns.
func forgetAgentMirrorFirstPlans(reg *AgentMirrorRegistry, next []model.AgentMirror) {
	for _, old := range reg.Mirrors {
		i := slices.IndexFunc(next, func(m model.AgentMirror) bool { return m.ID == old.ID })
		if i < 0 || next[i].BaseURL != old.BaseURL {
			delete(reg.FirstPlanned, old.ID)
		}
	}
}

// ApplyAgentMirrorPlan commits an approved agent.mirrors plan: the registry
// becomes next, its revision moves on from baseRevision, and the approval is
// written as decided, in one write. It refuses when the registry is no longer
// at baseRevision or the approval is no longer the pending one the decision
// read.
func (s *Store) ApplyAgentMirrorPlan(approval model.Approval, baseRevision int64, next []model.AgentMirror) (committed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.state.Approvals[approval.ID]
	if !ok || current.Status != model.ApprovalPending || current.Plugin != approval.Plugin ||
		current.Action != approval.Action || current.Plan != approval.Plan {
		return false, ErrTaskTransitionConflict
	}
	reg := cloneAgentMirrorRegistry(s.state.AgentMirrors)
	if reg.Revision != baseRevision {
		return false, ErrAgentMirrorRevision
	}
	now := time.Now().UTC()
	forgetAgentMirrorFirstPlans(&reg, next)
	reg.Mirrors = stampAgentMirrors(reg.Mirrors, next, now)
	reg.Revision++
	approval.CreatedAt = current.CreatedAt
	approval.UpdatedAt = now
	staged := s.state
	staged.Approvals = maps.Clone(s.state.Approvals)
	staged.Approvals[approval.ID] = approval
	staged.AgentMirrors = &reg
	committed, err = s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	return committed, err
}

// MarkAgentMirrorsPlanned records at as the first plan of every mirror in
// ids that has none yet, and returns those ids, in the order given. A mirror
// no longer in the registry is not recorded.
func (s *Store) MarkAgentMirrorsPlanned(ids []string, at time.Time) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.AgentMirrors == nil {
		return nil, nil
	}
	known := map[string]bool{}
	for _, m := range s.state.AgentMirrors.Mirrors {
		known[m.ID] = true
	}
	var fresh []string
	for _, id := range ids {
		if !known[id] || slices.Contains(fresh, id) {
			continue
		}
		if _, ok := s.state.AgentMirrors.FirstPlanned[id]; ok {
			continue
		}
		fresh = append(fresh, id)
	}
	if len(fresh) == 0 {
		return nil, nil
	}
	reg := cloneAgentMirrorRegistry(s.state.AgentMirrors)
	if reg.FirstPlanned == nil {
		reg.FirstPlanned = map[string]time.Time{}
	}
	for _, id := range fresh {
		reg.FirstPlanned[id] = at.UTC()
	}
	staged := s.state
	staged.AgentMirrors = &reg
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	if !committed {
		return nil, err
	}
	return fresh, err
}

// AgentArtifactManifest returns the manifest recorded for one binary.
func (s *Store) AgentArtifactManifest(version, osName, arch, sha256Hex string) (AgentArtifactManifest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.state.AgentArtifactManifests[AgentArtifactManifestKey(version, osName, arch, sha256Hex)]
	return m, ok
}

// AgentArtifactManifests returns every recorded manifest, by key.
func (s *Store) AgentArtifactManifests() []AgentArtifactManifest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AgentArtifactManifest, 0, len(s.state.AgentArtifactManifests))
	for _, m := range s.state.AgentArtifactManifests {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		return AgentArtifactManifestKey(out[i].Version, out[i].OS, out[i].Arch, out[i].SHA256) <
			AgentArtifactManifestKey(out[j].Version, out[j].OS, out[j].Arch, out[j].SHA256)
	})
	return out
}

// PutAgentArtifactManifest records a manifest. A manifest already recorded
// for the same bytes is kept as it is: it describes the same bytes, and the
// first record says when they were first verified.
func (s *Store) PutAgentArtifactManifest(m AgentArtifactManifest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := AgentArtifactManifestKey(m.Version, m.OS, m.Arch, m.SHA256)
	if _, ok := s.state.AgentArtifactManifests[key]; ok {
		return nil
	}
	if m.RecordedAt.IsZero() {
		m.RecordedAt = time.Now().UTC()
	}
	staged := s.state
	staged.AgentArtifactManifests = maps.Clone(s.state.AgentArtifactManifests)
	if staged.AgentArtifactManifests == nil {
		staged.AgentArtifactManifests = map[string]AgentArtifactManifest{}
	}
	staged.AgentArtifactManifests[key] = m
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	return err
}
