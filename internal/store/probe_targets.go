package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"sort"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Probe targets are the operator's own targets for the outbound probe
// (design 27): URLs the Probe page offers beside the probe's built-in ones.
// The server validates a definition before it reaches here and sends it to
// lattice-probe with each run that names it; the probe validates it again.
// Operator configuration written only on an edit, so the JSON state is its
// home, and the migrate round trip carries it in the meta bucket.

// ProbeTarget is one saved target.
type ProbeTarget struct {
	ID           string    `json:"id"`
	Label        string    `json:"label"`
	URL          string    `json:"url"`
	Method       string    `json:"method"`
	ExpectStatus string    `json:"expect_status"`
	BodyContains string    `json:"body_contains,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	// Version starts at 1 and grows by one on every update. An update or
	// delete names the version it read and is refused when it moved.
	Version int64 `json:"version"`
}

var (
	// ErrProbeTargetNotFound: no saved target has the id.
	ErrProbeTargetNotFound = errors.New("probe target not found")
	// ErrProbeTargetVersion: the target changed since the caller read it.
	ErrProbeTargetVersion = errors.New("probe target changed since it was read")
	// ErrProbeTargetLimit: the list is full.
	ErrProbeTargetLimit = errors.New("probe target list is full")
)

// maxProbeTargetID is lattice-probe's id length limit.
const maxProbeTargetID = 40

// ProbeTargets returns every saved target, oldest first.
func (s *Store) ProbeTargets() []ProbeTarget {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ProbeTarget, 0, len(s.state.ProbeTargets))
	for _, t := range s.state.ProbeTargets {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// ProbeTargetsByID returns the saved targets with the given ids, and the
// ids that are not saved, in the order asked.
func (s *Store) ProbeTargetsByID(ids []string) (found []ProbeTarget, missing []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		if t, ok := s.state.ProbeTargets[id]; ok {
			found = append(found, t)
		} else {
			missing = append(missing, id)
		}
	}
	return found, missing
}

// CreateProbeTarget saves t under t.ID, or under t.ID with the first free
// suffix -2, -3 and so on when the id is taken, keeping it within 40
// characters. It refuses when the list already holds limit targets. The
// stored target has version 1 and both timestamps at now.
func (s *Store) CreateProbeTarget(t ProbeTarget, limit int, now time.Time) (ProbeTarget, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.state.ProbeTargets) >= limit {
		return ProbeTarget{}, ErrProbeTargetLimit
	}
	id, ok := freeProbeTargetID(t.ID, s.state.ProbeTargets)
	if !ok {
		return ProbeTarget{}, fmt.Errorf("no free id for probe target %q", t.ID)
	}
	t.ID = id
	t.Version = 1
	t.CreatedAt = now.UTC()
	t.UpdatedAt = t.CreatedAt
	return t, s.commitProbeTargets(func(next map[string]ProbeTarget) { next[t.ID] = t })
}

func freeProbeTargetID(base string, taken map[string]ProbeTarget) (string, bool) {
	if _, used := taken[base]; !used && base != "" {
		return base, true
	}
	for n := 2; n <= len(taken)+2; n++ {
		suffix := "-" + strconv.Itoa(n)
		stem := base
		if len(stem)+len(suffix) > maxProbeTargetID {
			stem = stem[:maxProbeTargetID-len(suffix)]
		}
		if id := stem + suffix; taken[id].ID == "" {
			return id, true
		}
	}
	return "", false
}

// UpdateProbeTarget replaces the definition of the target t.ID when its
// stored version is expected. ID, CreatedAt and Version are the store's;
// the stored target has the next version and UpdatedAt at now.
func (s *Store) UpdateProbeTarget(t ProbeTarget, expected int64, now time.Time) (ProbeTarget, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.state.ProbeTargets[t.ID]
	if !ok {
		return ProbeTarget{}, ErrProbeTargetNotFound
	}
	if current.Version != expected {
		return ProbeTarget{}, ErrProbeTargetVersion
	}
	t.CreatedAt = current.CreatedAt
	t.Version = current.Version + 1
	t.UpdatedAt = now.UTC()
	return t, s.commitProbeTargets(func(next map[string]ProbeTarget) { next[t.ID] = t })
}

// DeleteProbeTarget removes the target id when its stored version is
// expected and returns what was removed.
func (s *Store) DeleteProbeTarget(id string, expected int64) (ProbeTarget, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.state.ProbeTargets[id]
	if !ok {
		return ProbeTarget{}, ErrProbeTargetNotFound
	}
	if current.Version != expected {
		return ProbeTarget{}, ErrProbeTargetVersion
	}
	return current, s.commitProbeTargets(func(next map[string]ProbeTarget) { delete(next, id) })
}

// commitProbeTargets writes the list as change leaves it, and only then
// installs it, so a failed write leaves memory as the disk has it.
func (s *Store) commitProbeTargets(change func(map[string]ProbeTarget)) error {
	next := maps.Clone(s.state.ProbeTargets)
	if next == nil {
		next = map[string]ProbeTarget{}
	}
	change(next)
	staged := s.state
	staged.ProbeTargets = next
	if committed, err := s.persistState(s.jsonPersistStateFrom(staged)); !committed {
		return err
	}
	s.state.ProbeTargets = next
	return nil
}

// boltKeyProbeTargets holds State.ProbeTargets in the meta bucket, so the
// offline migrate round trip keeps the saved targets, as
// boltKeyNotifyRuleOptions does for rule options.
var boltKeyProbeTargets = []byte("probe_targets")

func putBoltProbeTargets(tx *bolt.Tx, targets map[string]ProbeTarget) error {
	meta := tx.Bucket(boltBucketMeta)
	if len(targets) == 0 {
		return meta.Delete(boltKeyProbeTargets)
	}
	raw, err := json.Marshal(targets)
	if err != nil {
		return err
	}
	return meta.Put(boltKeyProbeTargets, raw)
}

func readBoltProbeTargets(tx *bolt.Tx, into map[string]ProbeTarget) error {
	meta := tx.Bucket(boltBucketMeta)
	if meta == nil {
		return nil
	}
	raw := meta.Get(boltKeyProbeTargets)
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, &into); err != nil {
		return fmt.Errorf("decode probe targets: %w", err)
	}
	return nil
}
