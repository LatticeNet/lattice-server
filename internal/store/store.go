package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
)

// maxSessions bounds how many sessions are retained to keep both memory and the
// on-disk state file from growing without limit. When exceeded, the oldest
// sessions are evicted.
const maxSessions = 4096

type State struct {
	Users     map[string]model.User         `json:"users"`
	Tokens    map[string]model.Token        `json:"tokens"`
	Nodes     map[string]model.Node         `json:"nodes"`
	Tasks     map[string]model.Task         `json:"tasks"`
	Results   []model.TaskResult            `json:"results"`
	Audit     []model.AuditEvent            `json:"audit"`
	KV        map[string]model.KVEntry      `json:"kv"`
	Static    map[string]model.StaticObject `json:"static"`
	Workers   map[string]model.WorkerScript `json:"workers"`
	Approvals map[string]model.Approval     `json:"approvals"`
	Sessions  map[string]auth.Session       `json:"sessions"`
}

type Store struct {
	mu    sync.Mutex
	path  string
	state State
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, state: emptyState()}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(data, &s.state); err != nil {
		return nil, err
	}
	s.ensureMaps()
	return s, nil
}

func emptyState() State {
	return State{
		Users:     map[string]model.User{},
		Tokens:    map[string]model.Token{},
		Nodes:     map[string]model.Node{},
		Tasks:     map[string]model.Task{},
		KV:        map[string]model.KVEntry{},
		Static:    map[string]model.StaticObject{},
		Workers:   map[string]model.WorkerScript{},
		Approvals: map[string]model.Approval{},
		Sessions:  map[string]auth.Session{},
	}
}

func (s *Store) ensureMaps() {
	if s.state.Users == nil {
		s.state.Users = map[string]model.User{}
	}
	if s.state.Tokens == nil {
		s.state.Tokens = map[string]model.Token{}
	}
	if s.state.Nodes == nil {
		s.state.Nodes = map[string]model.Node{}
	}
	if s.state.Tasks == nil {
		s.state.Tasks = map[string]model.Task{}
	}
	if s.state.KV == nil {
		s.state.KV = map[string]model.KVEntry{}
	}
	if s.state.Static == nil {
		s.state.Static = map[string]model.StaticObject{}
	}
	if s.state.Workers == nil {
		s.state.Workers = map[string]model.WorkerScript{}
	}
	if s.state.Approvals == nil {
		s.state.Approvals = map[string]model.Approval{}
	}
	if s.state.Sessions == nil {
		s.state.Sessions = map[string]auth.Session{}
	}
}

func (s *Store) Save() error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) UpsertUser(u model.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Users[u.ID] = u
	return s.Save()
}

func (s *Store) UserByUsername(username string) (model.User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.state.Users {
		if u.Username == username {
			return u, true
		}
	}
	return model.User{}, false
}

func (s *Store) User(id string) (model.User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.state.Users[id]
	return u, ok
}

func (s *Store) UpsertToken(t model.Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Tokens[t.ID] = t
	return s.Save()
}

func (s *Store) Token(id string) (model.Token, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.state.Tokens[id]
	return t, ok
}

func (s *Store) Tokens() []model.Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Token, 0, len(s.state.Tokens))
	for _, t := range s.state.Tokens {
		out = append(out, t)
	}
	return out
}

func (s *Store) UpsertNode(n model.Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n.CreatedAt.IsZero() {
		n.CreatedAt = time.Now().UTC()
	}
	s.state.Nodes[n.ID] = n
	return s.Save()
}

func (s *Store) Node(id string) (model.Node, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.state.Nodes[id]
	return n, ok
}

func (s *Store) Nodes() []model.Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Node, 0, len(s.state.Nodes))
	for _, n := range s.state.Nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Store) UpdateMetrics(nodeID string, metrics model.Metrics, version, publicIP, wgIP string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.state.Nodes[nodeID]
	if !ok {
		return fmt.Errorf("node %q not found", nodeID)
	}
	n.Metrics = metrics
	n.LastSeen = time.Now().UTC()
	n.Online = true
	if version != "" {
		n.AgentVersion = version
	}
	if publicIP != "" {
		n.PublicIP = publicIP
	}
	if wgIP != "" {
		n.WireGuardIP = wgIP
	}
	s.state.Nodes[nodeID] = n
	return s.Save()
}

func (s *Store) CreateTask(t model.Task) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	if t.Status == "" {
		t.Status = model.TaskQueued
	}
	s.state.Tasks[t.ID] = t
	return s.Save()
}

func (s *Store) Tasks() []model.Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Task, 0, len(s.state.Tasks))
	for _, t := range s.state.Tasks {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (s *Store) LeaseTasks(nodeID string, limit int) ([]model.Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	out := []model.Task{}
	for id, t := range s.state.Tasks {
		if len(out) >= limit {
			break
		}
		if t.Status != model.TaskQueued || !contains(t.Targets, nodeID) {
			continue
		}
		t.Status = model.TaskLeased
		t.LeasedBy = nodeID
		t.StartedAt = now
		s.state.Tasks[id] = t
		out = append(out, t)
	}
	if len(out) == 0 {
		return out, nil
	}
	return out, s.Save()
}

func (s *Store) AddTaskResult(r model.TaskResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Results = append(s.state.Results, r)
	if t, ok := s.state.Tasks[r.TaskID]; ok {
		if r.Error != "" || r.ExitCode != 0 {
			t.Status = model.TaskFailed
		} else {
			t.Status = model.TaskFinished
		}
		t.FinishedAt = r.FinishedAt
		s.state.Tasks[t.ID] = t
	}
	return s.Save()
}

func (s *Store) Results() []model.TaskResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]model.TaskResult(nil), s.state.Results...)
	sort.Slice(out, func(i, j int) bool { return out[i].FinishedAt.After(out[j].FinishedAt) })
	return out
}

func (s *Store) AppendAudit(ev model.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Audit = append(s.state.Audit, ev)
	return s.Save()
}

func (s *Store) AuditEvents() []model.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]model.AuditEvent(nil), s.state.Audit...)
	sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out
}

func (s *Store) PutKV(entry model.KVEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry.UpdatedAt = time.Now().UTC()
	s.state.KV[entry.Bucket+"/"+entry.Key] = entry
	return s.Save()
}

func (s *Store) KV(bucket string) []model.KVEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.KVEntry{}
	for _, e := range s.state.KV {
		if e.Bucket == bucket {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func (s *Store) PutStatic(obj model.StaticObject) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	obj.UpdatedAt = time.Now().UTC()
	obj.Size = len(obj.Content)
	s.state.Static[obj.Bucket+"/"+obj.Path] = obj
	return s.Save()
}

func (s *Store) Static(bucket string) []model.StaticObject {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.StaticObject{}
	for _, o := range s.state.Static {
		if o.Bucket == bucket {
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func (s *Store) UpsertWorker(w model.WorkerScript) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.UpdatedAt = time.Now().UTC()
	s.state.Workers[w.ID] = w
	return s.Save()
}

func (s *Store) Workers() []model.WorkerScript {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.WorkerScript, 0, len(s.state.Workers))
	for _, w := range s.state.Workers {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Store) UpsertApproval(a model.Approval) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a.UpdatedAt = time.Now().UTC()
	if a.CreatedAt.IsZero() {
		a.CreatedAt = a.UpdatedAt
	}
	s.state.Approvals[a.ID] = a
	return s.Save()
}

func (s *Store) Approval(id string) (model.Approval, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.state.Approvals[id]
	return a, ok
}

func (s *Store) Approvals() []model.Approval {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Approval, 0, len(s.state.Approvals))
	for _, a := range s.state.Approvals {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// PutSession persists a session, pruning expired entries and enforcing the
// session cap on every write so neither memory nor the state file grows
// unbounded under credential-stuffing or churn.
func (s *Store) PutSession(sess auth.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for id, existing := range s.state.Sessions {
		if !existing.Active(now) {
			delete(s.state.Sessions, id)
		}
	}
	s.state.Sessions[sess.ID] = sess
	if len(s.state.Sessions) > maxSessions {
		s.evictOldestSessionLocked()
	}
	return s.Save()
}

// Session returns an active session by id. Expired or revoked sessions report
// not-found without a write.
func (s *Store) Session(id string) (auth.Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.state.Sessions[id]
	if !ok || !sess.Active(time.Now().UTC()) {
		return auth.Session{}, false
	}
	return sess, true
}

// DeleteSession removes a session (logout / revocation).
func (s *Store) DeleteSession(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Sessions[id]; !ok {
		return nil
	}
	delete(s.state.Sessions, id)
	return s.Save()
}

func (s *Store) evictOldestSessionLocked() {
	var oldestID string
	var oldest time.Time
	first := true
	for id, sess := range s.state.Sessions {
		if first || sess.CreatedAt.Before(oldest) {
			oldestID = id
			oldest = sess.CreatedAt
			first = false
		}
	}
	if !first {
		delete(s.state.Sessions, oldestID)
	}
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
