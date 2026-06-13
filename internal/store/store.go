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
	"github.com/LatticeNet/lattice-server/internal/audit"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/secret"
)

// maxSessions bounds how many sessions are retained to keep both memory and the
// on-disk state file from growing without limit. When exceeded, the oldest
// sessions are evicted.
const maxSessions = 4096

// maxMonitorResults caps the retained history per monitor to bound state growth.
const maxMonitorResults = 500

type State struct {
	Users           map[string]model.User               `json:"users"`
	Tokens          map[string]model.Token              `json:"tokens"`
	Nodes           map[string]model.Node               `json:"nodes"`
	Tasks           map[string]model.Task               `json:"tasks"`
	Results         []model.TaskResult                  `json:"results"`
	Audit           []model.AuditEvent                  `json:"audit"`
	KV              map[string]model.KVEntry            `json:"kv"`
	Static          map[string]model.StaticObject       `json:"static"`
	Workers         map[string]model.WorkerScript       `json:"workers"`
	Plugins         map[string]model.PluginInstallation `json:"plugins"`
	Approvals       map[string]model.Approval           `json:"approvals"`
	Sessions        map[string]auth.Session             `json:"sessions"`
	DDNS            map[string]model.DDNSProfile        `json:"ddns"`
	Monitors        map[string]model.Monitor            `json:"monitors"`
	MonResults      map[string][]model.MonitorResult    `json:"monitor_results"`
	NotifyChannels  map[string]model.NotifyChannel      `json:"notify_channels"`
	Tunnels         map[string]model.TunnelProfile      `json:"tunnels"`
	MachineProfiles map[string]model.MachineProfile     `json:"machine_profiles"`
	NFTInputs       map[string]model.NFTInputs          `json:"nft_inputs"`
	TOTPChallenges  map[string]auth.TOTPChallenge       `json:"totp_challenges"`
	OIDCProviders   map[string]model.OIDCProvider       `json:"oidc_providers"`
	OIDCIdentities  map[string]model.OIDCIdentity       `json:"oidc_identities"`
	OIDCAuthStates  map[string]auth.OIDCAuthState       `json:"oidc_auth_states"`
}

type Store struct {
	mu      sync.Mutex
	path    string
	state   State
	cipher  secret.Cipher // at-rest encryptor for persisted credentials
	wal     *audit.WAL    // append-only tamper-evident audit log; nil for in-memory stores
	walPath string
}

// Open loads (or initializes) the store at path, resolving the at-rest
// encryption cipher from the environment or a key file under the data
// directory (see secret.Resolve). An empty path yields an in-memory store with
// encryption disabled (nothing is persisted).
func Open(path string) (*Store, error) {
	var cph secret.Cipher
	if path == "" {
		cph = secret.Disabled()
	} else {
		res, err := secret.Resolve(filepath.Dir(path), "")
		if err != nil {
			return nil, fmt.Errorf("store: resolve master key: %w", err)
		}
		cph = res.Cipher
	}
	return OpenWithCipher(path, cph)
}

// OpenWithCipher is Open with an explicitly supplied at-rest cipher. main uses
// it after logging the resolved key source; tests use it to inject a known
// cipher. A nil cipher disables encryption.
func OpenWithCipher(path string, cph secret.Cipher) (*Store, error) {
	if cph == nil {
		cph = secret.Disabled()
	}
	s := &Store{path: path, state: emptyState(), cipher: cph}
	if path == "" {
		return s, nil
	}
	walPath := path + ".audit-wal"
	wal, err := audit.OpenWAL(walPath)
	if err != nil {
		return nil, err
	}
	s.wal = wal
	s.walPath = walPath
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
	if err := decryptState(&s.state, s.cipher); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	s.ensureMaps()
	return s, nil
}

func emptyState() State {
	return State{
		Users:           map[string]model.User{},
		Tokens:          map[string]model.Token{},
		Nodes:           map[string]model.Node{},
		Tasks:           map[string]model.Task{},
		KV:              map[string]model.KVEntry{},
		Static:          map[string]model.StaticObject{},
		Workers:         map[string]model.WorkerScript{},
		Plugins:         map[string]model.PluginInstallation{},
		Approvals:       map[string]model.Approval{},
		Sessions:        map[string]auth.Session{},
		DDNS:            map[string]model.DDNSProfile{},
		Monitors:        map[string]model.Monitor{},
		MonResults:      map[string][]model.MonitorResult{},
		NotifyChannels:  map[string]model.NotifyChannel{},
		Tunnels:         map[string]model.TunnelProfile{},
		MachineProfiles: map[string]model.MachineProfile{},
		NFTInputs:       map[string]model.NFTInputs{},
		TOTPChallenges:  map[string]auth.TOTPChallenge{},
		OIDCProviders:   map[string]model.OIDCProvider{},
		OIDCIdentities:  map[string]model.OIDCIdentity{},
		OIDCAuthStates:  map[string]auth.OIDCAuthState{},
	}
}

func (st *State) ensureMaps() {
	if st.Users == nil {
		st.Users = map[string]model.User{}
	}
	if st.Tokens == nil {
		st.Tokens = map[string]model.Token{}
	}
	if st.Nodes == nil {
		st.Nodes = map[string]model.Node{}
	}
	if st.Tasks == nil {
		st.Tasks = map[string]model.Task{}
	}
	if st.KV == nil {
		st.KV = map[string]model.KVEntry{}
	}
	if st.Static == nil {
		st.Static = map[string]model.StaticObject{}
	}
	if st.Workers == nil {
		st.Workers = map[string]model.WorkerScript{}
	}
	if st.Plugins == nil {
		st.Plugins = map[string]model.PluginInstallation{}
	}
	if st.Approvals == nil {
		st.Approvals = map[string]model.Approval{}
	}
	if st.Sessions == nil {
		st.Sessions = map[string]auth.Session{}
	}
	if st.DDNS == nil {
		st.DDNS = map[string]model.DDNSProfile{}
	}
	if st.Monitors == nil {
		st.Monitors = map[string]model.Monitor{}
	}
	if st.MonResults == nil {
		st.MonResults = map[string][]model.MonitorResult{}
	}
	if st.NotifyChannels == nil {
		st.NotifyChannels = map[string]model.NotifyChannel{}
	}
	if st.Tunnels == nil {
		st.Tunnels = map[string]model.TunnelProfile{}
	}
	if st.MachineProfiles == nil {
		st.MachineProfiles = map[string]model.MachineProfile{}
	}
	if st.NFTInputs == nil {
		st.NFTInputs = map[string]model.NFTInputs{}
	}
	if st.TOTPChallenges == nil {
		st.TOTPChallenges = map[string]auth.TOTPChallenge{}
	}
	if st.OIDCProviders == nil {
		st.OIDCProviders = map[string]model.OIDCProvider{}
	}
	if st.OIDCIdentities == nil {
		st.OIDCIdentities = map[string]model.OIDCIdentity{}
	}
	if st.OIDCAuthStates == nil {
		st.OIDCAuthStates = map[string]auth.OIDCAuthState{}
	}
}

func (s *Store) ensureMaps() {
	s.state.ensureMaps()
}

func (s *Store) Save() error {
	if s.path == "" {
		return nil
	}
	// 0o700: this directory holds only the server's private state file and,
	// in the auto-generate case, the master key. It must match the 0o700 used
	// by secret.generateKeyFile so neither path can widen the other (MkdirAll
	// is a no-op once the directory exists, so the first creator's mode wins).
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	persist, err := encryptedState(s.state, s.cipher)
	if err != nil {
		return fmt.Errorf("encrypt state: %w", err)
	}
	data, err := json.MarshalIndent(persist, "", "  ")
	if err != nil {
		return err
	}
	return syncedAtomicWrite(s.path, data, 0o600)
}

// syncedAtomicWrite writes data to a temp file, fsyncs the file, atomically
// renames it into place, then fsyncs the parent directory so the rename is
// durable. Plain WriteFile+Rename makes the *name* atomic but leaves a crash
// window where the file's data blocks or the rename's directory entry may not
// have reached disk (the classic ext4/xfs "renamed-but-zero-length" failure).
// For the primary state file that holds all credentials/secrets, that window is
// total data loss, so we close it the same way the audit WAL already does.
func syncedAtomicWrite(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := writeSyncedFile(tmp, data, perm); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}

// writeSyncedFile writes data to path (creating/truncating) and fsyncs the file
// before closing, so its contents are durable on disk.
func writeSyncedFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// syncDir fsyncs a directory so a rename within it is durable. A directory that
// cannot be opened/synced (rare; some platforms) is reported but non-fatal at
// the call sites that can tolerate it.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *Store) UpsertUser(u model.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Users[u.ID] = u
	return s.Save()
}

// UserByUsername looks up a user by username, case-insensitively. Usernames are
// effectively case-insensitive identifiers (and OIDC binds on a lowercased
// email), so password login and SSO resolve the same account regardless of the
// case used to provision it.
func (s *Store) UserByUsername(username string) (model.User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.state.Users {
		if strings.EqualFold(u.Username, username) {
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

func (s *Store) RotateNodeToken(nodeID, tokenHash string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.state.Nodes[nodeID]
	if !ok {
		return false, nil
	}
	n.TokenHash = tokenHash
	s.state.Nodes[nodeID] = n
	return true, s.Save()
}

// SetNodeDisabled flips a node's revocation flag. A disabled node's token is
// refused by authentication, so this is an immediate revocation without deleting
// history or config.
func (s *Store) SetNodeDisabled(nodeID string, disabled bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.state.Nodes[nodeID]
	if !ok {
		return false, nil
	}
	n.Disabled = disabled
	s.state.Nodes[nodeID] = n
	return true, s.Save()
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

func (s *Store) UpdateMetrics(nodeID string, metrics model.Metrics, version, publicIP, publicIPv6, wgIP string, hostFacts model.HostFacts) error {
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
	if !hostFacts.ReportedAt.IsZero() {
		n.HostFacts = hostFacts
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
	if s.wal != nil {
		if err := s.wal.Append(ev); err != nil {
			return err
		}
	}
	return s.Save()
}

// AuditWALVerify re-reads the append-only audit WAL and validates its hash chain.
// The second return is false when no WAL is configured (in-memory store).
func (s *Store) AuditWALVerify() (audit.Result, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.walPath == "" {
		return audit.Result{}, false, nil
	}
	f, err := os.Open(s.walPath)
	if err != nil {
		return audit.Result{}, true, err
	}
	defer f.Close()
	res, err := audit.Verify(f)
	return res, true, err
}

// AuditWALHead returns the current chain head hash and record count, and whether
// a WAL is configured. The head can be shipped off-box to detect end-truncation.
func (s *Store) AuditWALHead() (string, int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wal == nil {
		return "", 0, false
	}
	h, n := s.wal.Head()
	return h, n, true
}

// Close releases the audit WAL file handle.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wal != nil {
		return s.wal.Close()
	}
	return nil
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

func (s *Store) UpsertPluginInstallation(p model.PluginInstallation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.ID == "" {
		return errors.New("plugin id is required")
	}
	if p.Status == "" {
		p.Status = model.PluginStatusVerified
	}
	if !validPluginStatus(p.Status) {
		return fmt.Errorf("invalid plugin status %q", p.Status)
	}
	now := time.Now().UTC()
	existing, hadExisting := s.state.Plugins[p.ID]
	if hadExisting && !validPluginTransition(existing.Status, p.Status) && existing.Status != p.Status {
		return fmt.Errorf("invalid plugin status transition %s -> %s", existing.Status, p.Status)
	}
	if hadExisting {
		if p.CreatedAt.IsZero() {
			p.CreatedAt = existing.CreatedAt
		}
		if p.VerifiedAt.IsZero() {
			p.VerifiedAt = existing.VerifiedAt
		}
		if p.InstalledAt.IsZero() {
			p.InstalledAt = existing.InstalledAt
		}
		if p.ActivatedAt.IsZero() {
			p.ActivatedAt = existing.ActivatedAt
		}
		if p.DisabledAt.IsZero() {
			p.DisabledAt = existing.DisabledAt
		}
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	p = stampPluginStatusTime(p, now)
	p.Capabilities = append([]string(nil), p.Capabilities...)
	s.state.Plugins[p.ID] = p
	return s.Save()
}

func (s *Store) PluginInstallation(id string) (model.PluginInstallation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.state.Plugins[id]
	return clonePluginInstallation(p), ok
}

func (s *Store) PluginInstallations() []model.PluginInstallation {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.PluginInstallation, 0, len(s.state.Plugins))
	for _, p := range s.state.Plugins {
		out = append(out, clonePluginInstallation(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Store) SetPluginStatus(id, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validPluginStatus(status) {
		return fmt.Errorf("invalid plugin status %q", status)
	}
	p, ok := s.state.Plugins[id]
	if !ok {
		return fmt.Errorf("plugin installation not found: %s", id)
	}
	if p.Status == status {
		return nil
	}
	if !validPluginTransition(p.Status, status) {
		return fmt.Errorf("invalid plugin status transition %s -> %s", p.Status, status)
	}
	now := time.Now().UTC()
	p.Status = status
	p.UpdatedAt = now
	p = stampPluginStatusTime(p, now)
	s.state.Plugins[id] = p
	return s.Save()
}

func validPluginStatus(status string) bool {
	switch status {
	case model.PluginStatusVerified, model.PluginStatusInstalled, model.PluginStatusActive, model.PluginStatusDisabled:
		return true
	default:
		return false
	}
}

func validPluginTransition(from, to string) bool {
	switch from {
	case "":
		return to == model.PluginStatusVerified
	case model.PluginStatusVerified:
		return to == model.PluginStatusInstalled
	case model.PluginStatusInstalled:
		return to == model.PluginStatusActive || to == model.PluginStatusDisabled
	case model.PluginStatusActive:
		return to == model.PluginStatusDisabled
	case model.PluginStatusDisabled:
		return to == model.PluginStatusActive
	default:
		return false
	}
}

func stampPluginStatusTime(p model.PluginInstallation, now time.Time) model.PluginInstallation {
	switch p.Status {
	case model.PluginStatusVerified:
		if p.VerifiedAt.IsZero() {
			p.VerifiedAt = now
		}
	case model.PluginStatusInstalled:
		if p.VerifiedAt.IsZero() {
			p.VerifiedAt = now
		}
		if p.InstalledAt.IsZero() {
			p.InstalledAt = now
		}
	case model.PluginStatusActive:
		if p.VerifiedAt.IsZero() {
			p.VerifiedAt = now
		}
		if p.InstalledAt.IsZero() {
			p.InstalledAt = now
		}
		p.ActivatedAt = now
	case model.PluginStatusDisabled:
		if p.VerifiedAt.IsZero() {
			p.VerifiedAt = now
		}
		if p.InstalledAt.IsZero() {
			p.InstalledAt = now
		}
		p.DisabledAt = now
	}
	return p
}

func clonePluginInstallation(p model.PluginInstallation) model.PluginInstallation {
	p.Capabilities = append([]string(nil), p.Capabilities...)
	return p
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

// AdvanceTOTPStep atomically enforces single-use of a TOTP code: it accepts the
// matched RFC-6238 step only if it is strictly greater than the highest step
// previously accepted for the user, then persists the new high-water mark. The
// compare-and-set runs entirely under the store lock so two concurrent logins
// presenting the same code cannot both succeed (one wins, the other observes a
// non-increasing step and is rejected). Returns true when the step was accepted
// and recorded; false when it was a replay (step <= LastTOTPStep) or the user is
// unknown.
func (s *Store) AdvanceTOTPStep(userID string, step uint64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.state.Users[userID]
	if !ok {
		return false, nil
	}
	if step <= u.LastTOTPStep {
		return false, nil
	}
	u.LastTOTPStep = step
	s.state.Users[userID] = u
	if err := s.Save(); err != nil {
		return false, err
	}
	return true, nil
}

// BumpSecurityEpoch increments the user's SecurityEpoch under the store lock and
// returns the new value. Sessions carry the epoch at which they were minted, so
// bumping it invalidates every previously-issued session for the user (used on
// 2FA disable, password change, and admin revoke). Returns (0, nil) when the
// user is unknown.
func (s *Store) BumpSecurityEpoch(userID string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.state.Users[userID]
	if !ok {
		return 0, nil
	}
	u.SecurityEpoch++
	s.state.Users[userID] = u
	if err := s.Save(); err != nil {
		return 0, err
	}
	return u.SecurityEpoch, nil
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

// UpsertMachineProfile creates or updates operator-authored machine metadata.
func (s *Store) UpsertMachineProfile(p model.MachineProfile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p.UpdatedAt = time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = p.UpdatedAt
	}
	s.state.MachineProfiles[p.ID] = p
	return s.Save()
}

// MachineProfile returns a profile by id.
func (s *Store) MachineProfile(id string) (model.MachineProfile, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.state.MachineProfiles[id]
	return p, ok
}

// MachineProfileForNode returns the profile bound to a node, enforcing the v1
// one-profile-per-node invariant at the API layer.
func (s *Store) MachineProfileForNode(nodeID string) (model.MachineProfile, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.state.MachineProfiles {
		if p.NodeID == nodeID {
			return p, true
		}
	}
	return model.MachineProfile{}, false
}

// MachineProfiles returns all profiles sorted by creation time.
func (s *Store) MachineProfiles() []model.MachineProfile {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.MachineProfile, 0, len(s.state.MachineProfiles))
	for _, p := range s.state.MachineProfiles {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// DeleteMachineProfile removes a machine profile.
func (s *Store) DeleteMachineProfile(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.MachineProfiles[id]; !ok {
		return nil
	}
	delete(s.state.MachineProfiles, id)
	return s.Save()
}

// UpsertNFTInputs stores the authoritative baseline nft input set for a node.
// The key is NodeID so DNS/ACL/proxy providers can compose into one per-node
// lattice_guard render without coordinating a separate id namespace.
func (s *Store) UpsertNFTInputs(inputs model.NFTInputs) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	inputs.UpdatedAt = time.Now().UTC()
	if inputs.CreatedAt.IsZero() {
		inputs.CreatedAt = inputs.UpdatedAt
	}
	inputs.ID = inputs.NodeID
	s.state.NFTInputs[inputs.NodeID] = inputs
	return s.Save()
}

// NFTInputs returns the persisted inputs for a node.
func (s *Store) NFTInputs(nodeID string) (model.NFTInputs, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inputs, ok := s.state.NFTInputs[nodeID]
	return inputs, ok
}

// AllNFTInputs returns all persisted nft inputs sorted by node id.
func (s *Store) AllNFTInputs() []model.NFTInputs {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.NFTInputs, 0, len(s.state.NFTInputs))
	for _, inputs := range s.state.NFTInputs {
		out = append(out, inputs)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// DeleteNFTInputs removes a node's stored baseline nft input set.
func (s *Store) DeleteNFTInputs(nodeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.NFTInputs[nodeID]; !ok {
		return nil
	}
	delete(s.state.NFTInputs, nodeID)
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
