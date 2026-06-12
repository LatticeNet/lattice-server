package store

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
)

// maxSessions bounds how many sessions are retained to keep both memory and the
// on-disk state file from growing without limit. When exceeded, the oldest
// sessions are evicted.
const maxSessions = 4096

// maxMonitorResults caps the retained history per monitor to bound state growth.
const maxMonitorResults = 500

type State struct {
	Users          map[string]model.User            `json:"users"`
	Tokens         map[string]model.Token           `json:"tokens"`
	Nodes          map[string]model.Node            `json:"nodes"`
	Tasks          map[string]model.Task            `json:"tasks"`
	Results        []model.TaskResult               `json:"results"`
	Audit          []model.AuditEvent               `json:"audit"`
	KV             map[string]model.KVEntry         `json:"kv"`
	Static         map[string]model.StaticObject    `json:"static"`
	Workers        map[string]model.WorkerScript    `json:"workers"`
	Approvals      map[string]model.Approval        `json:"approvals"`
	Sessions       map[string]auth.Session          `json:"sessions"`
	DDNS           map[string]model.DDNSProfile     `json:"ddns"`
	Monitors       map[string]model.Monitor         `json:"monitors"`
	MonResults     map[string][]model.MonitorResult `json:"monitor_results"`
	NotifyChannels map[string]model.NotifyChannel   `json:"notify_channels"`
	Tunnels        map[string]model.TunnelProfile   `json:"tunnels"`
	TOTPChallenges map[string]auth.TOTPChallenge    `json:"totp_challenges"`
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
		Users:          map[string]model.User{},
		Tokens:         map[string]model.Token{},
		Nodes:          map[string]model.Node{},
		Tasks:          map[string]model.Task{},
		KV:             map[string]model.KVEntry{},
		Static:         map[string]model.StaticObject{},
		Workers:        map[string]model.WorkerScript{},
		Approvals:      map[string]model.Approval{},
		Sessions:       map[string]auth.Session{},
		DDNS:           map[string]model.DDNSProfile{},
		Monitors:       map[string]model.Monitor{},
		MonResults:     map[string][]model.MonitorResult{},
		NotifyChannels: map[string]model.NotifyChannel{},
		Tunnels:        map[string]model.TunnelProfile{},
		TOTPChallenges: map[string]auth.TOTPChallenge{},
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
	if s.state.DDNS == nil {
		s.state.DDNS = map[string]model.DDNSProfile{}
	}
	if s.state.Monitors == nil {
		s.state.Monitors = map[string]model.Monitor{}
	}
	if s.state.MonResults == nil {
		s.state.MonResults = map[string][]model.MonitorResult{}
	}
	if s.state.NotifyChannels == nil {
		s.state.NotifyChannels = map[string]model.NotifyChannel{}
	}
	if s.state.Tunnels == nil {
		s.state.Tunnels = map[string]model.TunnelProfile{}
	}
	if s.state.TOTPChallenges == nil {
		s.state.TOTPChallenges = map[string]auth.TOTPChallenge{}
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

func (s *Store) UpdateMetrics(nodeID string, metrics model.Metrics, version, publicIP, publicIPv6, wgIP string) error {
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
	if publicIPv6 != "" {
		n.PublicIPv6 = publicIPv6
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

func (s *Store) Task(id string) (model.Task, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.state.Tasks[id]
	return t, ok
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
		if t.LeaseID == "" {
			leaseSecret, err := auth.NewRandomToken(24)
			if err != nil {
				return nil, err
			}
			t.LeaseID = "lease_" + leaseSecret
		}
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

// maxTOTPChallenges bounds the number of pending 2FA challenges retained.
const maxTOTPChallenges = 4096

// PutTOTPChallenge stores a pending second-factor challenge, sweeping expired or
// used ones first so the set stays bounded (challenges have a short TTL).
func (s *Store) PutTOTPChallenge(c auth.TOTPChallenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for id, existing := range s.state.TOTPChallenges {
		if !existing.Active(now) {
			delete(s.state.TOTPChallenges, id)
		}
	}
	if len(s.state.TOTPChallenges) >= maxTOTPChallenges {
		// Refuse to grow without bound; the caller surfaces this as a transient
		// error and the client may retry after challenges expire.
		return errors.New("too many pending 2fa challenges")
	}
	s.state.TOTPChallenges[c.ID] = c
	return s.Save()
}

// TOTPChallenge returns an active (unused, unexpired) challenge by id.
func (s *Store) TOTPChallenge(id string) (auth.TOTPChallenge, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.state.TOTPChallenges[id]
	if !ok || !c.Active(time.Now().UTC()) {
		return auth.TOTPChallenge{}, false
	}
	return c, true
}

// ConsumeTOTPChallenge marks a challenge spent by deleting it (single-use).
func (s *Store) ConsumeTOTPChallenge(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.TOTPChallenges[id]; !ok {
		return nil
	}
	delete(s.state.TOTPChallenges, id)
	return s.Save()
}

// FailTOTPChallenge records a failed second-factor attempt against a challenge,
// burning it once it reaches maxAttempts so a single challenge cannot serve as an
// unlimited guessing oracle for its whole TTL.
func (s *Store) FailTOTPChallenge(id string, maxAttempts int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.state.TOTPChallenges[id]
	if !ok {
		return nil
	}
	c.Attempts++
	if maxAttempts > 0 && c.Attempts >= maxAttempts {
		delete(s.state.TOTPChallenges, id)
	} else {
		s.state.TOTPChallenges[id] = c
	}
	return s.Save()
}

// ConsumeRecoveryCode atomically verifies and removes a single-use recovery code
// for a user, returning true only if a code matched. The read-modify-write runs
// entirely under the store lock so concurrent requests cannot double-spend one
// code or clobber each other's removal.
func (s *Store) ConsumeRecoveryCode(userID, code string) (bool, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return false, nil
	}
	want := auth.HashRecoveryCode(code)
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.state.Users[userID]
	if !ok {
		return false, nil
	}
	idx := -1
	for i, h := range u.RecoveryCodeHashes {
		if subtle.ConstantTimeCompare([]byte(h), []byte(want)) == 1 {
			idx = i
		}
	}
	if idx < 0 {
		return false, nil
	}
	u.RecoveryCodeHashes = append(u.RecoveryCodeHashes[:idx], u.RecoveryCodeHashes[idx+1:]...)
	s.state.Users[userID] = u
	if err := s.Save(); err != nil {
		return false, err
	}
	return true, nil
}

// UpsertDDNSProfile creates or updates a DDNS profile.
func (s *Store) UpsertDDNSProfile(p model.DDNSProfile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p.UpdatedAt = time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = p.UpdatedAt
	}
	s.state.DDNS[p.ID] = p
	return s.Save()
}

// DDNSProfile returns a profile by id.
func (s *Store) DDNSProfile(id string) (model.DDNSProfile, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.state.DDNS[id]
	return p, ok
}

// DDNSProfiles returns all profiles sorted by creation time.
func (s *Store) DDNSProfiles() []model.DDNSProfile {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.DDNSProfile, 0, len(s.state.DDNS))
	for _, p := range s.state.DDNS {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// DDNSProfilesForNode returns the profiles bound to a node.
func (s *Store) DDNSProfilesForNode(nodeID string) []model.DDNSProfile {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.DDNSProfile{}
	for _, p := range s.state.DDNS {
		if p.NodeID == nodeID {
			out = append(out, p)
		}
	}
	return out
}

// DeleteDDNSProfile removes a profile.
func (s *Store) DeleteDDNSProfile(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.DDNS[id]; !ok {
		return nil
	}
	delete(s.state.DDNS, id)
	return s.Save()
}

// UpsertMonitor creates or updates a monitor.
func (s *Store) UpsertMonitor(m model.Monitor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m.UpdatedAt = time.Now().UTC()
	if m.CreatedAt.IsZero() {
		m.CreatedAt = m.UpdatedAt
	}
	s.state.Monitors[m.ID] = m
	return s.Save()
}

// Monitor returns a monitor by id.
func (s *Store) Monitor(id string) (model.Monitor, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.state.Monitors[id]
	return m, ok
}

// Monitors returns all monitors sorted by creation time.
func (s *Store) Monitors() []model.Monitor {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Monitor, 0, len(s.state.Monitors))
	for _, m := range s.state.Monitors {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// MonitorsForNode returns the enabled monitors a node should run.
func (s *Store) MonitorsForNode(nodeID string) []model.Monitor {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.Monitor{}
	for _, m := range s.state.Monitors {
		if !m.Enabled {
			continue
		}
		if m.AssignAll || contains(m.NodeIDs, nodeID) {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// DeleteMonitor removes a monitor and its result history.
func (s *Store) DeleteMonitor(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Monitors[id]; !ok {
		return nil
	}
	delete(s.state.Monitors, id)
	delete(s.state.MonResults, id)
	return s.Save()
}

// AddMonitorResult appends a probe result, keeping only the most recent
// maxMonitorResults entries per monitor.
func (s *Store) AddMonitorResult(r model.MonitorResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.At.IsZero() {
		r.At = time.Now().UTC()
	}
	series := append(s.state.MonResults[r.MonitorID], r)
	if len(series) > maxMonitorResults {
		series = series[len(series)-maxMonitorResults:]
	}
	s.state.MonResults[r.MonitorID] = series
	return s.Save()
}

// MonitorResults returns the result history for a monitor (oldest first).
func (s *Store) MonitorResults(monitorID string) []model.MonitorResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]model.MonitorResult(nil), s.state.MonResults[monitorID]...)
}

// UpsertNotifyChannel creates or updates a notification channel.
func (s *Store) UpsertNotifyChannel(c model.NotifyChannel) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.UpdatedAt = time.Now().UTC()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = c.UpdatedAt
	}
	s.state.NotifyChannels[c.ID] = c
	return s.Save()
}

// NotifyChannels returns all channels sorted by creation time.
func (s *Store) NotifyChannels() []model.NotifyChannel {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.NotifyChannel, 0, len(s.state.NotifyChannels))
	for _, c := range s.state.NotifyChannels {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// EnabledNotifyChannels returns only channels that are enabled.
func (s *Store) EnabledNotifyChannels() []model.NotifyChannel {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.NotifyChannel{}
	for _, c := range s.state.NotifyChannels {
		if c.Enabled {
			out = append(out, c)
		}
	}
	return out
}

// DeleteNotifyChannel removes a channel.
func (s *Store) DeleteNotifyChannel(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.NotifyChannels[id]; !ok {
		return nil
	}
	delete(s.state.NotifyChannels, id)
	return s.Save()
}

// LastMonitorResultForNode returns a node's most recent result for a monitor.
func (s *Store) LastMonitorResultForNode(monitorID, nodeID string) (model.MonitorResult, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	series := s.state.MonResults[monitorID]
	for i := len(series) - 1; i >= 0; i-- {
		if series[i].NodeID == nodeID {
			return series[i], true
		}
	}
	return model.MonitorResult{}, false
}

// UpsertTunnel creates or updates a tunnel profile.
func (s *Store) UpsertTunnel(t model.TunnelProfile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t.UpdatedAt = time.Now().UTC()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = t.UpdatedAt
	}
	s.state.Tunnels[t.ID] = t
	return s.Save()
}

// Tunnel returns a tunnel profile by id.
func (s *Store) Tunnel(id string) (model.TunnelProfile, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.state.Tunnels[id]
	return t, ok
}

// Tunnels returns all tunnel profiles sorted by creation time.
func (s *Store) Tunnels() []model.TunnelProfile {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.TunnelProfile, 0, len(s.state.Tunnels))
	for _, t := range s.state.Tunnels {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// DeleteTunnel removes a tunnel profile.
func (s *Store) DeleteTunnel(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Tunnels[id]; !ok {
		return nil
	}
	delete(s.state.Tunnels, id)
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
