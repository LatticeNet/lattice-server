package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
	bolt "go.etcd.io/bbolt"
)

const boltStateVersion = "1"

var (
	boltBucketMeta           = []byte("_meta")
	boltKeyVersion           = []byte("version")
	boltBucketUsers          = []byte("users")
	boltBucketTokens         = []byte("tokens")
	boltBucketNodes          = []byte("nodes")
	boltBucketTasks          = []byte("tasks")
	boltBucketResults        = []byte("results")
	boltBucketAudit          = []byte("audit")
	boltBucketKV             = []byte("kv")
	boltBucketStatic         = []byte("static")
	boltBucketWorkers        = []byte("workers")
	boltBucketPlugins        = []byte("plugins")
	boltBucketApprovals      = []byte("approvals")
	boltBucketSessions       = []byte("sessions")
	boltBucketDDNS           = []byte("ddns")
	boltBucketMonitors       = []byte("monitors")
	boltBucketMonResults     = []byte("monitor_results")
	boltBucketNotifyChannels = []byte("notify_channels")
	boltBucketTunnels        = []byte("tunnels")
	boltBucketTOTPChallenges = []byte("totp_challenges")
	boltBucketOIDCProviders  = []byte("oidc_providers")
	boltBucketOIDCIdentities = []byte("oidc_identities")
	boltBucketOIDCAuthStates = []byte("oidc_auth_states")
)

var boltStateBuckets = [][]byte{
	boltBucketUsers,
	boltBucketTokens,
	boltBucketNodes,
	boltBucketTasks,
	boltBucketResults,
	boltBucketAudit,
	boltBucketKV,
	boltBucketStatic,
	boltBucketWorkers,
	boltBucketPlugins,
	boltBucketApprovals,
	boltBucketSessions,
	boltBucketDDNS,
	boltBucketMonitors,
	boltBucketMonResults,
	boltBucketNotifyChannels,
	boltBucketTunnels,
	boltBucketTOTPChallenges,
	boltBucketOIDCProviders,
	boltBucketOIDCIdentities,
	boltBucketOIDCAuthStates,
}

// BoltStateStore is the first bbolt-backed persistence boundary. It stores each
// State collection in its own bucket so the future Store migration can move from
// whole-state rewrites to record-level writes without changing handlers.
//
// This type is intentionally not wired into server startup yet: it is the tested
// import/export foundation for the Phase C migration.
type BoltStateStore struct {
	db     *bolt.DB
	cipher secret.Cipher
}

func OpenBoltState(path string, cph secret.Cipher) (*BoltStateStore, error) {
	if path == "" {
		return nil, errors.New("bolt state path is required")
	}
	if cph == nil {
		cph = secret.Disabled()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	bs := &BoltStateStore{db: db, cipher: cph}
	if err := bs.ensureBuckets(); err != nil {
		db.Close()
		return nil, err
	}
	return bs, nil
}

func (bs *BoltStateStore) Close() error {
	if bs == nil || bs.db == nil {
		return nil
	}
	err := bs.db.Close()
	bs.db = nil
	return err
}

func (bs *BoltStateStore) ensureBuckets() error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		meta, err := tx.CreateBucketIfNotExists(boltBucketMeta)
		if err != nil {
			return err
		}
		if v := meta.Get(boltKeyVersion); v != nil && string(v) != boltStateVersion {
			return fmt.Errorf("unsupported bolt state version %q", string(v))
		}
		if err := meta.Put(boltKeyVersion, []byte(boltStateVersion)); err != nil {
			return err
		}
		for _, bucket := range boltStateBuckets {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return err
			}
		}
		return nil
	})
}

// ImportState replaces the entire bbolt state atomically. Secret-bearing fields
// are encrypted before they are written; the input State is not mutated.
func (bs *BoltStateStore) ImportState(st State) error {
	persist, err := encryptedState(st, bs.cipher)
	if err != nil {
		return err
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := resetBoltBuckets(tx); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketUsers, persist.Users); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketTokens, persist.Tokens); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketNodes, persist.Nodes); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketTasks, persist.Tasks); err != nil {
			return err
		}
		if err := putSlice(tx, boltBucketResults, persist.Results); err != nil {
			return err
		}
		if err := putSlice(tx, boltBucketAudit, persist.Audit); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketKV, persist.KV); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketStatic, persist.Static); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketWorkers, persist.Workers); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketPlugins, persist.Plugins); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketApprovals, persist.Approvals); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketSessions, persist.Sessions); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketDDNS, persist.DDNS); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketMonitors, persist.Monitors); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketMonResults, persist.MonResults); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketNotifyChannels, persist.NotifyChannels); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketTunnels, persist.Tunnels); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketTOTPChallenges, persist.TOTPChallenges); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketOIDCProviders, persist.OIDCProviders); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketOIDCIdentities, persist.OIDCIdentities); err != nil {
			return err
		}
		return putMap(tx, boltBucketOIDCAuthStates, persist.OIDCAuthStates)
	})
}

func resetBoltBuckets(tx *bolt.Tx) error {
	meta, err := tx.CreateBucketIfNotExists(boltBucketMeta)
	if err != nil {
		return err
	}
	if err := meta.Put(boltKeyVersion, []byte(boltStateVersion)); err != nil {
		return err
	}
	for _, bucket := range boltStateBuckets {
		if err := tx.DeleteBucket(bucket); err != nil && !errors.Is(err, bolt.ErrBucketNotFound) {
			return err
		}
		if _, err := tx.CreateBucket(bucket); err != nil {
			return err
		}
	}
	return nil
}

// ExportState reads every bbolt bucket and returns a decrypted, initialized
// State. Values returned by bbolt are decoded inside the transaction.
func (bs *BoltStateStore) ExportState() (State, error) {
	st := emptyState()
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketUsers, st.Users); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketTokens, st.Tokens); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketNodes, st.Nodes); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketTasks, st.Tasks); err != nil {
			return err
		}
		if err := readSlice(tx, boltBucketResults, &st.Results); err != nil {
			return err
		}
		if err := readSlice(tx, boltBucketAudit, &st.Audit); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketKV, st.KV); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketStatic, st.Static); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketWorkers, st.Workers); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketPlugins, st.Plugins); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketApprovals, st.Approvals); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketSessions, st.Sessions); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketDDNS, st.DDNS); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketMonitors, st.Monitors); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketMonResults, st.MonResults); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketNotifyChannels, st.NotifyChannels); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketTunnels, st.Tunnels); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketTOTPChallenges, st.TOTPChallenges); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketOIDCProviders, st.OIDCProviders); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketOIDCIdentities, st.OIDCIdentities); err != nil {
			return err
		}
		return readMap(tx, boltBucketOIDCAuthStates, st.OIDCAuthStates)
	})
	if err != nil {
		return State{}, err
	}
	if err := decryptState(&st, bs.cipher); err != nil {
		return State{}, err
	}
	st.ensureMaps()
	return st, nil
}

func checkBoltVersion(tx *bolt.Tx) error {
	meta := tx.Bucket(boltBucketMeta)
	if meta == nil {
		return nil
	}
	if v := meta.Get(boltKeyVersion); v != nil && string(v) != boltStateVersion {
		return fmt.Errorf("unsupported bolt state version %q", string(v))
	}
	return nil
}

func (bs *BoltStateStore) UpsertNode(n model.Node) error {
	if n.CreatedAt.IsZero() {
		n.CreatedAt = time.Now().UTC()
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return putRecord(tx, boltBucketNodes, n.ID, n)
	})
}

func (bs *BoltStateStore) Node(id string) (model.Node, bool, error) {
	var out model.Node
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketNodes, id, &out)
		return err
	})
	return out, ok, err
}

func (bs *BoltStateStore) Nodes() ([]model.Node, error) {
	nodes := []model.Node{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		nodes, err = listMapValues[model.Node](tx, boltBucketNodes)
		return err
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	return nodes, nil
}

func (bs *BoltStateStore) PutKV(entry model.KVEntry) error {
	entry.UpdatedAt = time.Now().UTC()
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return putRecord(tx, boltBucketKV, entry.Bucket+"/"+entry.Key, entry)
	})
}

func (bs *BoltStateStore) KV(bucket string) ([]model.KVEntry, error) {
	entries := []model.KVEntry{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		all, err := listMapValues[model.KVEntry](tx, boltBucketKV)
		if err != nil {
			return err
		}
		for _, entry := range all {
			if entry.Bucket == bucket {
				entries = append(entries, entry)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	return entries, nil
}

func (bs *BoltStateStore) AppendAudit(ev model.AuditEvent) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		b := tx.Bucket(boltBucketAudit)
		if b == nil {
			return fmt.Errorf("missing bucket %q", string(boltBucketAudit))
		}
		next, err := nextSequenceIndex(boltBucketAudit, b)
		if err != nil {
			return err
		}
		data, err := json.Marshal(ev)
		if err != nil {
			return fmt.Errorf("marshal %s[%d]: %w", boltBucketAudit, next, err)
		}
		if err := b.Put(sequenceKey(next), data); err != nil {
			return fmt.Errorf("put %s[%d]: %w", boltBucketAudit, next, err)
		}
		return nil
	})
}

func (bs *BoltStateStore) AuditEvents() ([]model.AuditEvent, error) {
	events := []model.AuditEvent{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return readSlice(tx, boltBucketAudit, &events)
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(events, func(i, j int) bool { return events[i].At.After(events[j].At) })
	return events, nil
}

func (bs *BoltStateStore) PutStatic(obj model.StaticObject) error {
	obj.UpdatedAt = time.Now().UTC()
	obj.Size = len(obj.Content)
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return putRecord(tx, boltBucketStatic, obj.Bucket+"/"+obj.Path, obj)
	})
}

func (bs *BoltStateStore) Static(bucket string) ([]model.StaticObject, error) {
	objects := []model.StaticObject{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		all, err := listMapValues[model.StaticObject](tx, boltBucketStatic)
		if err != nil {
			return err
		}
		for _, obj := range all {
			if obj.Bucket == bucket {
				objects = append(objects, obj)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].Path < objects[j].Path })
	return objects, nil
}

func (bs *BoltStateStore) UpsertWorker(w model.WorkerScript) error {
	w.UpdatedAt = time.Now().UTC()
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return putRecord(tx, boltBucketWorkers, w.ID, w)
	})
}

func (bs *BoltStateStore) Workers() ([]model.WorkerScript, error) {
	workers := []model.WorkerScript{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		workers, err = listMapValues[model.WorkerScript](tx, boltBucketWorkers)
		return err
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(workers, func(i, j int) bool { return workers[i].Name < workers[j].Name })
	return workers, nil
}

func (bs *BoltStateStore) UpsertPluginInstallation(p model.PluginInstallation) error {
	if p.ID == "" {
		return errors.New("plugin id is required")
	}
	if p.Status == "" {
		p.Status = model.PluginStatusVerified
	}
	if !validPluginStatus(p.Status) {
		return fmt.Errorf("invalid plugin status %q", p.Status)
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		now := time.Now().UTC()
		existing, hadExisting, err := getPluginInstallationRecord(tx, p.ID)
		if err != nil {
			return err
		}
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
		return putRecord(tx, boltBucketPlugins, p.ID, p)
	})
}

func (bs *BoltStateStore) PluginInstallation(id string) (model.PluginInstallation, bool, error) {
	var out model.PluginInstallation
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketPlugins, id, &out)
		return err
	})
	return clonePluginInstallation(out), ok, err
}

func (bs *BoltStateStore) PluginInstallations() ([]model.PluginInstallation, error) {
	plugins := []model.PluginInstallation{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		plugins, err = listMapValues[model.PluginInstallation](tx, boltBucketPlugins)
		return err
	})
	if err != nil {
		return nil, err
	}
	for i := range plugins {
		plugins[i] = clonePluginInstallation(plugins[i])
	}
	sort.Slice(plugins, func(i, j int) bool { return plugins[i].ID < plugins[j].ID })
	return plugins, nil
}

func (bs *BoltStateStore) SetPluginStatus(id, status string) error {
	if !validPluginStatus(status) {
		return fmt.Errorf("invalid plugin status %q", status)
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		p, ok, err := getPluginInstallationRecord(tx, id)
		if err != nil {
			return err
		}
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
		return putRecord(tx, boltBucketPlugins, p.ID, p)
	})
}

func getPluginInstallationRecord(tx *bolt.Tx, id string) (model.PluginInstallation, bool, error) {
	var out model.PluginInstallation
	ok, err := getRecord(tx, boltBucketPlugins, id, &out)
	return out, ok, err
}

func (bs *BoltStateStore) UpsertApproval(a model.Approval) error {
	a.UpdatedAt = time.Now().UTC()
	if a.CreatedAt.IsZero() {
		a.CreatedAt = a.UpdatedAt
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return putRecord(tx, boltBucketApprovals, a.ID, a)
	})
}

func (bs *BoltStateStore) Approval(id string) (model.Approval, bool, error) {
	var out model.Approval
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketApprovals, id, &out)
		return err
	})
	return out, ok, err
}

func (bs *BoltStateStore) Approvals() ([]model.Approval, error) {
	approvals := []model.Approval{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		approvals, err = listMapValues[model.Approval](tx, boltBucketApprovals)
		return err
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(approvals, func(i, j int) bool { return approvals[i].CreatedAt.After(approvals[j].CreatedAt) })
	return approvals, nil
}

func putRecord[T any](tx *bolt.Tx, bucket []byte, key string, value T) error {
	b := tx.Bucket(bucket)
	if b == nil {
		return fmt.Errorf("missing bucket %q", string(bucket))
	}
	k, err := boltStringKey(key)
	if err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal %s[%q]: %w", bucket, key, err)
	}
	if err := b.Put(k, data); err != nil {
		return fmt.Errorf("put %s[%q]: %w", bucket, key, err)
	}
	return nil
}

func getRecord[T any](tx *bolt.Tx, bucket []byte, key string, out *T) (bool, error) {
	b := tx.Bucket(bucket)
	if b == nil {
		return false, nil
	}
	k, err := boltStringKey(key)
	if err != nil {
		return false, err
	}
	data := b.Get(k)
	if data == nil {
		return false, nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return false, fmt.Errorf("decode %s[%q]: %w", bucket, key, err)
	}
	return true, nil
}

func listMapValues[T any](tx *bolt.Tx, bucket []byte) ([]T, error) {
	out := []T{}
	b := tx.Bucket(bucket)
	if b == nil {
		return out, nil
	}
	err := b.ForEach(func(k, v []byte) error {
		var value T
		if err := json.Unmarshal(v, &value); err != nil {
			key, keyErr := stringFromBoltKey(k)
			if keyErr != nil {
				key = string(k)
			}
			return fmt.Errorf("decode %s[%q]: %w", bucket, key, err)
		}
		out = append(out, value)
		return nil
	})
	return out, err
}

func putMap[T any](tx *bolt.Tx, bucket []byte, values map[string]T) error {
	b := tx.Bucket(bucket)
	if b == nil {
		return fmt.Errorf("missing bucket %q", string(bucket))
	}
	for key, value := range values {
		k, err := boltStringKey(key)
		if err != nil {
			return err
		}
		data, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("marshal %s[%q]: %w", bucket, key, err)
		}
		if err := b.Put(k, data); err != nil {
			return fmt.Errorf("put %s[%q]: %w", bucket, key, err)
		}
	}
	return nil
}

func readMap[T any](tx *bolt.Tx, bucket []byte, out map[string]T) error {
	b := tx.Bucket(bucket)
	if b == nil {
		return nil
	}
	return b.ForEach(func(k, v []byte) error {
		key, err := stringFromBoltKey(k)
		if err != nil {
			return fmt.Errorf("decode %s key: %w", bucket, err)
		}
		var value T
		if err := json.Unmarshal(v, &value); err != nil {
			return fmt.Errorf("decode %s[%q]: %w", bucket, key, err)
		}
		out[key] = value
		return nil
	})
}

func putSlice[T any](tx *bolt.Tx, bucket []byte, values []T) error {
	b := tx.Bucket(bucket)
	if b == nil {
		return fmt.Errorf("missing bucket %q", string(bucket))
	}
	for i, value := range values {
		data, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("marshal %s[%d]: %w", bucket, i, err)
		}
		if err := b.Put(sequenceKey(i), data); err != nil {
			return fmt.Errorf("put %s[%d]: %w", bucket, i, err)
		}
	}
	return nil
}

func readSlice[T any](tx *bolt.Tx, bucket []byte, out *[]T) error {
	b := tx.Bucket(bucket)
	if b == nil {
		return nil
	}
	values := []T{}
	if err := b.ForEach(func(k, v []byte) error {
		var value T
		if err := json.Unmarshal(v, &value); err != nil {
			return fmt.Errorf("decode %s[%s]: %w", bucket, string(k), err)
		}
		values = append(values, value)
		return nil
	}); err != nil {
		return err
	}
	*out = values
	return nil
}

func nextSequenceIndex(bucketName []byte, b *bolt.Bucket) (int, error) {
	k, _ := b.Cursor().Last()
	if k == nil {
		return 0, nil
	}
	last, err := strconv.Atoi(string(k))
	if err != nil {
		return 0, fmt.Errorf("decode %s sequence key %q: %w", bucketName, string(k), err)
	}
	return last + 1, nil
}

func boltStringKey(key string) ([]byte, error) {
	k, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func stringFromBoltKey(key []byte) (string, error) {
	var out string
	if err := json.Unmarshal(key, &out); err != nil {
		return "", err
	}
	return out, nil
}

func sequenceKey(i int) []byte {
	return []byte(fmt.Sprintf("%020d", i))
}
