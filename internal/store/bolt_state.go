package store

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/secret"
	bolt "go.etcd.io/bbolt"
)

const boltStateVersion = "1"

var (
	boltBucketMeta            = []byte("_meta")
	boltKeyVersion            = []byte("version")
	boltBucketUsers           = []byte("users")
	boltBucketTokens          = []byte("tokens")
	boltBucketNodes           = []byte("nodes")
	boltBucketTasks           = []byte("tasks")
	boltBucketResults         = []byte("results")
	boltBucketAudit           = []byte("audit")
	boltBucketKV              = []byte("kv")
	boltBucketStatic          = []byte("static")
	boltBucketStorageBuckets  = []byte("storage_buckets")
	boltBucketStorageBindings = []byte("storage_bindings")
	boltBucketStorageTokens   = []byte("storage_tokens")
	boltBucketWorkers         = []byte("workers")
	boltBucketPlugins         = []byte("plugins")
	boltBucketApprovals       = []byte("approvals")
	boltBucketSessions        = []byte("sessions")
	boltBucketDDNS            = []byte("ddns")
	boltBucketMonitors        = []byte("monitors")
	boltBucketMonResults      = []byte("monitor_results")
	boltBucketLogSources      = []byte("log_sources")
	boltBucketNotifyChannels  = []byte("notify_channels")
	boltBucketNotifyRules     = []byte("notify_rules")
	boltBucketTunnels         = []byte("tunnels")
	boltBucketMachineProfiles = []byte("machine_profiles")
	boltBucketNFTInputs       = []byte("nft_inputs")
	boltBucketDNSDeployments  = []byte("dns_deployments")
	boltBucketNetPolicies     = []byte("net_policies")
	boltBucketGroups          = []byte("groups")
	boltBucketGroupPolicies   = []byte("group_policies")
	boltBucketGeoRouting      = []byte("geo_routing")
	boltBucketAgentUpdates    = []byte("agent_updates")
	boltBucketProxyInbounds   = []byte("proxy_inbounds")
	boltBucketProxyUsers      = []byte("proxy_users")
	boltBucketProxyProfiles   = []byte("proxy_profiles")
	boltBucketProxyUsage      = []byte("proxy_usage")
	boltBucketTOTPChallenges  = []byte("totp_challenges")
	boltBucketOIDCProviders   = []byte("oidc_providers")
	boltBucketOIDCIdentities  = []byte("oidc_identities")
	boltBucketOIDCAuthStates  = []byte("oidc_auth_states")
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
	boltBucketStorageBuckets,
	boltBucketStorageBindings,
	boltBucketStorageTokens,
	boltBucketWorkers,
	boltBucketPlugins,
	boltBucketApprovals,
	boltBucketSessions,
	boltBucketDDNS,
	boltBucketMonitors,
	boltBucketMonResults,
	boltBucketLogSources,
	boltBucketNotifyChannels,
	boltBucketNotifyRules,
	boltBucketTunnels,
	boltBucketMachineProfiles,
	boltBucketNFTInputs,
	boltBucketDNSDeployments,
	boltBucketNetPolicies,
	boltBucketGroups,
	boltBucketGroupPolicies,
	boltBucketGeoRouting,
	boltBucketAgentUpdates,
	boltBucketProxyInbounds,
	boltBucketProxyUsers,
	boltBucketProxyProfiles,
	boltBucketProxyUsage,
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
//
// EXPERIMENTAL — do not enable as the runtime backend until the Phase C entry
// gates are met (security-audit iter-016 D12/D3): (1) a backup/restore command +
// drill exist; (2) record-level pruning no longer decrypts every record to read
// non-secret timestamps (D3); (3) this store is round-trip/fuzz-validated for
// semantic parity against the JSON store. Until then its method set can silently
// drift from the JSON store, so changes here MUST be mirrored and tested against
// internal/store/store.go.
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
		if err := putMap(tx, boltBucketStorageBuckets, persist.StorageBuckets); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketStorageBindings, persist.StorageBindings); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketStorageTokens, persist.StorageTokens); err != nil {
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
		if err := putMap(tx, boltBucketLogSources, persist.LogSources); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketNotifyChannels, persist.NotifyChannels); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketNotifyRules, persist.NotifyRules); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketTunnels, persist.Tunnels); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketMachineProfiles, persist.MachineProfiles); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketNFTInputs, persist.NFTInputs); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketDNSDeployments, persist.DNSDeployments); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketNetPolicies, persist.NetPolicies); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketGroups, persist.Groups); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketGroupPolicies, persist.GroupPolicies); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketGeoRouting, persist.GeoRouting); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketAgentUpdates, persist.AgentUpdates); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketProxyInbounds, persist.ProxyInbounds); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketProxyUsers, persist.ProxyUsers); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketProxyProfiles, persist.ProxyProfiles); err != nil {
			return err
		}
		if err := putMap(tx, boltBucketProxyUsage, persist.ProxyUsage); err != nil {
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
		if err := readMap(tx, boltBucketStorageBuckets, st.StorageBuckets); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketStorageBindings, st.StorageBindings); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketStorageTokens, st.StorageTokens); err != nil {
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
		if err := readMap(tx, boltBucketLogSources, st.LogSources); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketNotifyChannels, st.NotifyChannels); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketNotifyRules, st.NotifyRules); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketTunnels, st.Tunnels); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketMachineProfiles, st.MachineProfiles); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketNFTInputs, st.NFTInputs); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketDNSDeployments, st.DNSDeployments); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketNetPolicies, st.NetPolicies); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketGroups, st.Groups); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketGroupPolicies, st.GroupPolicies); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketGeoRouting, st.GeoRouting); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketAgentUpdates, st.AgentUpdates); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketProxyInbounds, st.ProxyInbounds); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketProxyUsers, st.ProxyUsers); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketProxyProfiles, st.ProxyProfiles); err != nil {
			return err
		}
		if err := readMap(tx, boltBucketProxyUsage, st.ProxyUsage); err != nil {
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

func (bs *BoltStateStore) TouchNodeToken(nodeID string, at time.Time, minInterval time.Duration) (bool, error) {
	var touched bool
	err := bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var n model.Node
		ok, err := getRecord(tx, boltBucketNodes, nodeID, &n)
		if err != nil || !ok {
			return err
		}
		if at.IsZero() {
			at = time.Now().UTC()
		} else {
			at = at.UTC()
		}
		if minInterval > 0 && !n.TokenLastUsedAt.IsZero() && at.Sub(n.TokenLastUsedAt) < minInterval {
			return nil
		}
		n.TokenLastUsedAt = at
		touched = true
		return putRecord(tx, boltBucketNodes, nodeID, n)
	})
	return touched, err
}

func (bs *BoltStateStore) UpdateNodeGeo(nodeID string, geo *model.NodeGeo) (model.Node, bool, error) {
	var out model.Node
	var ok bool
	err := bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketNodes, nodeID, &out)
		if err != nil || !ok {
			return err
		}
		if geo != nil {
			copyGeo := *geo
			out.Geo = &copyGeo
		} else {
			out.Geo = nil
		}
		return putRecord(tx, boltBucketNodes, out.ID, out)
	})
	return out, ok, err
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

func (bs *BoltStateStore) UpdateMetrics(nodeID string, metrics model.Metrics, version, publicIP, publicIPv6, internalIP, internalIPv6, wgIP string, hostFacts model.HostFacts) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var n model.Node
		ok, err := getRecord(tx, boltBucketNodes, nodeID, &n)
		if err != nil {
			return err
		}
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
		if internalIP != "" {
			n.InternalIP = internalIP
		}
		if internalIPv6 != "" {
			n.InternalIPv6 = internalIPv6
		}
		if wgIP != "" {
			n.WireGuardIP = wgIP
		}
		if !hostFacts.ReportedAt.IsZero() {
			n.HostFacts = hostFacts
		}
		return putRecord(tx, boltBucketNodes, nodeID, n)
	})
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

func (bs *BoltStateStore) CreateTask(t model.Task) error {
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	if t.Status == "" {
		t.Status = model.TaskQueued
	}
	enc, err := encryptTaskRecord(t.ID, t, bs.cipher)
	if err != nil {
		return err
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return putRecord(tx, boltBucketTasks, t.ID, enc)
	})
}

func (bs *BoltStateStore) Task(id string) (model.Task, bool, error) {
	var out model.Task
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketTasks, id, &out)
		return err
	})
	if err != nil || !ok {
		return out, ok, err
	}
	out, err = decryptTaskRecord(id, out, bs.cipher)
	return out, ok, err
}

func (bs *BoltStateStore) Tasks() ([]model.Task, error) {
	tasks := []model.Task{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		tasks, err = listMapValues[model.Task](tx, boltBucketTasks)
		return err
	})
	if err != nil {
		return nil, err
	}
	for i := range tasks {
		dec, err := decryptTaskRecord(tasks[i].ID, tasks[i], bs.cipher)
		if err != nil {
			return nil, err
		}
		tasks[i] = dec
	}
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].CreatedAt.After(tasks[j].CreatedAt) })
	return tasks, nil
}

func (bs *BoltStateStore) LeaseTasks(nodeID string, limit int) ([]model.Task, error) {
	if limit <= 0 {
		return []model.Task{}, nil
	}
	out := []model.Task{}
	err := bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		rawTasks, err := listMapValues[model.Task](tx, boltBucketTasks)
		if err != nil {
			return err
		}
		tasks := make([]model.Task, 0, len(rawTasks))
		for _, task := range rawTasks {
			dec, err := decryptTaskRecord(task.ID, task, bs.cipher)
			if err != nil {
				return err
			}
			tasks = append(tasks, dec)
		}
		sort.Slice(tasks, func(i, j int) bool {
			if tasks[i].CreatedAt.Equal(tasks[j].CreatedAt) {
				return tasks[i].ID < tasks[j].ID
			}
			return tasks[i].CreatedAt.Before(tasks[j].CreatedAt)
		})
		now := time.Now().UTC()
		for _, t := range tasks {
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
					return err
				}
				t.LeaseID = "lease_" + leaseSecret
			}
			t.StartedAt = now
			enc, err := encryptTaskRecord(t.ID, t, bs.cipher)
			if err != nil {
				return err
			}
			if err := putRecord(tx, boltBucketTasks, t.ID, enc); err != nil {
				return err
			}
			out = append(out, t)
		}
		return nil
	})
	return out, err
}

func (bs *BoltStateStore) AddTaskResult(r model.TaskResult) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		b := tx.Bucket(boltBucketResults)
		if b == nil {
			return fmt.Errorf("missing bucket %q", string(boltBucketResults))
		}
		next, err := nextSequenceIndex(boltBucketResults, b)
		if err != nil {
			return err
		}
		data, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("marshal %s[%d]: %w", boltBucketResults, next, err)
		}
		if err := b.Put(sequenceKey(next), data); err != nil {
			return fmt.Errorf("put %s[%d]: %w", boltBucketResults, next, err)
		}
		var t model.Task
		ok, err := getRecord(tx, boltBucketTasks, r.TaskID, &t)
		if err != nil {
			return err
		}
		if ok {
			t, err = decryptTaskRecord(r.TaskID, t, bs.cipher)
			if err != nil {
				return err
			}
			if r.Error != "" || r.ExitCode != 0 {
				t.Status = model.TaskFailed
			} else {
				t.Status = model.TaskFinished
			}
			t.FinishedAt = r.FinishedAt
			enc, err := encryptTaskRecord(t.ID, t, bs.cipher)
			if err != nil {
				return err
			}
			if err := putRecord(tx, boltBucketTasks, t.ID, enc); err != nil {
				return err
			}
		}
		return nil
	})
}

func (bs *BoltStateStore) Results() ([]model.TaskResult, error) {
	results := []model.TaskResult{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return readSlice(tx, boltBucketResults, &results)
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(results, func(i, j int) bool { return results[i].FinishedAt.After(results[j].FinishedAt) })
	return results, nil
}

func (bs *BoltStateStore) UpsertMonitor(m model.Monitor) error {
	m.UpdatedAt = time.Now().UTC()
	if m.CreatedAt.IsZero() {
		m.CreatedAt = m.UpdatedAt
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return putRecord(tx, boltBucketMonitors, m.ID, m)
	})
}

func (bs *BoltStateStore) Monitor(id string) (model.Monitor, bool, error) {
	var out model.Monitor
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketMonitors, id, &out)
		return err
	})
	return out, ok, err
}

func (bs *BoltStateStore) Monitors() ([]model.Monitor, error) {
	monitors := []model.Monitor{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		monitors, err = listMapValues[model.Monitor](tx, boltBucketMonitors)
		return err
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(monitors, func(i, j int) bool { return monitors[i].CreatedAt.Before(monitors[j].CreatedAt) })
	return monitors, nil
}

func (bs *BoltStateStore) MonitorsForNode(nodeID string) ([]model.Monitor, error) {
	monitors := []model.Monitor{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		all, err := listMapValues[model.Monitor](tx, boltBucketMonitors)
		if err != nil {
			return err
		}
		for _, m := range all {
			if !m.Enabled {
				continue
			}
			if m.AssignAll || contains(m.NodeIDs, nodeID) {
				monitors = append(monitors, m)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(monitors, func(i, j int) bool { return monitors[i].ID < monitors[j].ID })
	return monitors, nil
}

func (bs *BoltStateStore) DeleteMonitor(id string) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var m model.Monitor
		ok, err := getRecord(tx, boltBucketMonitors, id, &m)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		if err := deleteRecord(tx, boltBucketMonitors, id); err != nil {
			return err
		}
		return deleteRecord(tx, boltBucketMonResults, id)
	})
}

func (bs *BoltStateStore) AddMonitorResult(r model.MonitorResult) error {
	if r.At.IsZero() {
		r.At = time.Now().UTC()
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		series := []model.MonitorResult{}
		ok, err := getRecord(tx, boltBucketMonResults, r.MonitorID, &series)
		if err != nil {
			return err
		}
		if !ok {
			series = []model.MonitorResult{}
		}
		series = append(series, r)
		if len(series) > maxMonitorResults {
			series = series[len(series)-maxMonitorResults:]
		}
		return putRecord(tx, boltBucketMonResults, r.MonitorID, series)
	})
}

func (bs *BoltStateStore) MonitorResults(monitorID string) ([]model.MonitorResult, error) {
	series := []model.MonitorResult{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		ok, err := getRecord(tx, boltBucketMonResults, monitorID, &series)
		if err != nil {
			return err
		}
		if !ok {
			series = []model.MonitorResult{}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return append([]model.MonitorResult(nil), series...), nil
}

func (bs *BoltStateStore) LastMonitorResultForNode(monitorID, nodeID string) (model.MonitorResult, bool, error) {
	var series []model.MonitorResult
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		ok, err := getRecord(tx, boltBucketMonResults, monitorID, &series)
		if err != nil {
			return err
		}
		if !ok {
			series = nil
		}
		return nil
	})
	if err != nil {
		return model.MonitorResult{}, false, err
	}
	for i := len(series) - 1; i >= 0; i-- {
		if series[i].NodeID == nodeID {
			return series[i], true, nil
		}
	}
	return model.MonitorResult{}, false, nil
}

func (bs *BoltStateStore) UpsertTunnel(t model.TunnelProfile) error {
	t.UpdatedAt = time.Now().UTC()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = t.UpdatedAt
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return putRecord(tx, boltBucketTunnels, t.ID, t)
	})
}

func (bs *BoltStateStore) Tunnel(id string) (model.TunnelProfile, bool, error) {
	var out model.TunnelProfile
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketTunnels, id, &out)
		return err
	})
	return out, ok, err
}

func (bs *BoltStateStore) Tunnels() ([]model.TunnelProfile, error) {
	tunnels := []model.TunnelProfile{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		tunnels, err = listMapValues[model.TunnelProfile](tx, boltBucketTunnels)
		return err
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(tunnels, func(i, j int) bool { return tunnels[i].CreatedAt.Before(tunnels[j].CreatedAt) })
	return tunnels, nil
}

func (bs *BoltStateStore) DeleteTunnel(id string) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return deleteRecord(tx, boltBucketTunnels, id)
	})
}

func (bs *BoltStateStore) UpsertUser(u model.User) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		enc, err := encryptUserRecord(u.ID, u, bs.cipher)
		if err != nil {
			return err
		}
		return putRecord(tx, boltBucketUsers, u.ID, enc)
	})
}

func (bs *BoltStateStore) User(id string) (model.User, bool, error) {
	var out model.User
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketUsers, id, &out)
		if err != nil || !ok {
			return err
		}
		out, err = decryptUserRecord(id, out, bs.cipher)
		return err
	})
	return out, ok, err
}

func (bs *BoltStateStore) UserByUsername(username string) (model.User, bool, error) {
	var out model.User
	var found bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		users, err := listMapValues[model.User](tx, boltBucketUsers)
		if err != nil {
			return err
		}
		for _, u := range users {
			du, err := decryptUserRecord(u.ID, u, bs.cipher)
			if err != nil {
				return err
			}
			if strings.EqualFold(du.Username, username) {
				out = du
				found = true
				return nil
			}
		}
		return nil
	})
	return out, found, err
}

func (bs *BoltStateStore) ConsumeRecoveryCode(userID, code string) (bool, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return false, nil
	}
	want := auth.HashRecoveryCode(code)
	consumed := false
	err := bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var u model.User
		ok, err := getRecord(tx, boltBucketUsers, userID, &u)
		if err != nil || !ok {
			return err
		}
		u, err = decryptUserRecord(userID, u, bs.cipher)
		if err != nil {
			return err
		}
		idx := -1
		for i, h := range u.RecoveryCodeHashes {
			if subtle.ConstantTimeCompare([]byte(h), []byte(want)) == 1 {
				idx = i
			}
		}
		if idx < 0 {
			return nil
		}
		u.RecoveryCodeHashes = append(u.RecoveryCodeHashes[:idx], u.RecoveryCodeHashes[idx+1:]...)
		enc, err := encryptUserRecord(userID, u, bs.cipher)
		if err != nil {
			return err
		}
		if err := putRecord(tx, boltBucketUsers, userID, enc); err != nil {
			return err
		}
		consumed = true
		return nil
	})
	return consumed, err
}

func (bs *BoltStateStore) UpsertToken(t model.Token) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return putRecord(tx, boltBucketTokens, t.ID, t)
	})
}

func (bs *BoltStateStore) Token(id string) (model.Token, bool, error) {
	var out model.Token
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketTokens, id, &out)
		return err
	})
	return out, ok, err
}

func (bs *BoltStateStore) Tokens() ([]model.Token, error) {
	tokens := []model.Token{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		tokens, err = listMapValues[model.Token](tx, boltBucketTokens)
		return err
	})
	return tokens, err
}

func (bs *BoltStateStore) DeleteToken(id string) (model.Token, bool, error) {
	var out model.Token
	var ok bool
	err := bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketTokens, id, &out)
		if err != nil || !ok {
			return err
		}
		return deleteRecord(tx, boltBucketTokens, id)
	})
	return out, ok, err
}

func (bs *BoltStateStore) PutSession(sess auth.Session) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		now := time.Now().UTC()
		sessions, err := listMapValues[auth.Session](tx, boltBucketSessions)
		if err != nil {
			return err
		}
		for _, existing := range sessions {
			dec, err := decryptSessionRecord(existing.ID, existing, bs.cipher)
			if err != nil {
				return err
			}
			if !dec.Active(now) {
				if err := deleteAuthRecord(tx, boltBucketSessions, sessionStorageKey(dec.ID), dec.ID); err != nil {
					return err
				}
			}
		}
		enc, err := encryptSessionRecord(sess.ID, sess, bs.cipher)
		if err != nil {
			return err
		}
		if err := putRecord(tx, boltBucketSessions, sessionStorageKey(sess.ID), enc); err != nil {
			return err
		}
		if count, err := countBucketRecords(tx, boltBucketSessions); err != nil {
			return err
		} else if count > maxSessions {
			return evictOldestSessionRecord(tx, bs.cipher)
		}
		return nil
	})
}

func (bs *BoltStateStore) Session(id string) (auth.Session, bool, error) {
	var out auth.Session
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getAuthRecord(tx, boltBucketSessions, sessionStorageKey(id), id, &out)
		if err != nil || !ok {
			return err
		}
		out, err = decryptSessionRecord(id, out, bs.cipher)
		if err != nil {
			return err
		}
		if !out.Active(time.Now().UTC()) {
			ok = false
			out = auth.Session{}
		}
		return nil
	})
	return out, ok, err
}

func (bs *BoltStateStore) DeleteSession(id string) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return deleteAuthRecord(tx, boltBucketSessions, sessionStorageKey(id), id)
	})
}

func (bs *BoltStateStore) PutTOTPChallenge(c auth.TOTPChallenge) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		now := time.Now().UTC()
		challenges, err := listMapValues[auth.TOTPChallenge](tx, boltBucketTOTPChallenges)
		if err != nil {
			return err
		}
		active := 0
		for _, existing := range challenges {
			dec, err := decryptTOTPChallengeRecord(existing.ID, existing, bs.cipher)
			if err != nil {
				return err
			}
			if !dec.Active(now) {
				if err := deleteAuthRecord(tx, boltBucketTOTPChallenges, totpChallengeStorageKey(dec.ID), dec.ID); err != nil {
					return err
				}
				continue
			}
			active++
		}
		if active >= maxTOTPChallenges {
			return errors.New("too many pending 2fa challenges")
		}
		enc, err := encryptTOTPChallengeRecord(c.ID, c, bs.cipher)
		if err != nil {
			return err
		}
		return putRecord(tx, boltBucketTOTPChallenges, totpChallengeStorageKey(c.ID), enc)
	})
}

func (bs *BoltStateStore) TOTPChallenge(id string) (auth.TOTPChallenge, bool, error) {
	var out auth.TOTPChallenge
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getAuthRecord(tx, boltBucketTOTPChallenges, totpChallengeStorageKey(id), id, &out)
		if err != nil || !ok {
			return err
		}
		out, err = decryptTOTPChallengeRecord(id, out, bs.cipher)
		if err != nil {
			return err
		}
		if !out.Active(time.Now().UTC()) {
			ok = false
			out = auth.TOTPChallenge{}
		}
		return nil
	})
	return out, ok, err
}

func (bs *BoltStateStore) ConsumeTOTPChallenge(id string) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return deleteAuthRecord(tx, boltBucketTOTPChallenges, totpChallengeStorageKey(id), id)
	})
}

func (bs *BoltStateStore) FailTOTPChallenge(id string, maxAttempts int) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var c auth.TOTPChallenge
		ok, err := getAuthRecord(tx, boltBucketTOTPChallenges, totpChallengeStorageKey(id), id, &c)
		if err != nil || !ok {
			return err
		}
		c, err = decryptTOTPChallengeRecord(id, c, bs.cipher)
		if err != nil {
			return err
		}
		c.Attempts++
		if maxAttempts > 0 && c.Attempts >= maxAttempts {
			return deleteAuthRecord(tx, boltBucketTOTPChallenges, totpChallengeStorageKey(id), id)
		}
		enc, err := encryptTOTPChallengeRecord(id, c, bs.cipher)
		if err != nil {
			return err
		}
		return putRecord(tx, boltBucketTOTPChallenges, totpChallengeStorageKey(id), enc)
	})
}

func (bs *BoltStateStore) UpsertDDNSProfile(p model.DDNSProfile) error {
	p.UpdatedAt = time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = p.UpdatedAt
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		enc, err := encryptDDNSRecord(p.ID, p, bs.cipher)
		if err != nil {
			return err
		}
		return putRecord(tx, boltBucketDDNS, p.ID, enc)
	})
}

func (bs *BoltStateStore) DDNSProfile(id string) (model.DDNSProfile, bool, error) {
	var out model.DDNSProfile
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketDDNS, id, &out)
		if err != nil || !ok {
			return err
		}
		out, err = decryptDDNSRecord(id, out, bs.cipher)
		return err
	})
	return out, ok, err
}

func (bs *BoltStateStore) DDNSProfiles() ([]model.DDNSProfile, error) {
	profiles := []model.DDNSProfile{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		all, err := listMapValues[model.DDNSProfile](tx, boltBucketDDNS)
		if err != nil {
			return err
		}
		for _, p := range all {
			dec, err := decryptDDNSRecord(p.ID, p, bs.cipher)
			if err != nil {
				return err
			}
			profiles = append(profiles, dec)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].CreatedAt.Before(profiles[j].CreatedAt) })
	return profiles, nil
}

func (bs *BoltStateStore) DDNSProfilesForNode(nodeID string) ([]model.DDNSProfile, error) {
	profiles := []model.DDNSProfile{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		all, err := listMapValues[model.DDNSProfile](tx, boltBucketDDNS)
		if err != nil {
			return err
		}
		for _, p := range all {
			if p.NodeID != nodeID {
				continue
			}
			dec, err := decryptDDNSRecord(p.ID, p, bs.cipher)
			if err != nil {
				return err
			}
			profiles = append(profiles, dec)
		}
		return nil
	})
	return profiles, err
}

func (bs *BoltStateStore) DeleteDDNSProfile(id string) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return deleteRecord(tx, boltBucketDDNS, id)
	})
}

func (bs *BoltStateStore) UpsertMachineProfile(p model.MachineProfile) error {
	p.UpdatedAt = time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = p.UpdatedAt
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		enc, err := encryptMachineProfileRecord(p.ID, p, bs.cipher)
		if err != nil {
			return err
		}
		return putRecord(tx, boltBucketMachineProfiles, p.ID, enc)
	})
}

func (bs *BoltStateStore) MachineProfile(id string) (model.MachineProfile, bool, error) {
	var out model.MachineProfile
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketMachineProfiles, id, &out)
		if err != nil || !ok {
			return err
		}
		out, err = decryptMachineProfileRecord(id, out, bs.cipher)
		return err
	})
	return out, ok, err
}

func (bs *BoltStateStore) MachineProfileForNode(nodeID string) (model.MachineProfile, bool, error) {
	profiles, err := bs.MachineProfiles()
	if err != nil {
		return model.MachineProfile{}, false, err
	}
	for _, p := range profiles {
		if p.NodeID == nodeID {
			return p, true, nil
		}
	}
	return model.MachineProfile{}, false, nil
}

func (bs *BoltStateStore) MachineProfiles() ([]model.MachineProfile, error) {
	profiles := []model.MachineProfile{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		all, err := listMapValues[model.MachineProfile](tx, boltBucketMachineProfiles)
		if err != nil {
			return err
		}
		for _, p := range all {
			dec, err := decryptMachineProfileRecord(p.ID, p, bs.cipher)
			if err != nil {
				return err
			}
			profiles = append(profiles, dec)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].CreatedAt.Before(profiles[j].CreatedAt) })
	return profiles, nil
}

func (bs *BoltStateStore) DeleteMachineProfile(id string) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return deleteRecord(tx, boltBucketMachineProfiles, id)
	})
}

func (bs *BoltStateStore) UpsertNFTInputs(inputs model.NFTInputs) error {
	inputs.UpdatedAt = time.Now().UTC()
	if inputs.CreatedAt.IsZero() {
		inputs.CreatedAt = inputs.UpdatedAt
	}
	inputs.ID = inputs.NodeID
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return putRecord(tx, boltBucketNFTInputs, inputs.NodeID, inputs)
	})
}

func (bs *BoltStateStore) NFTInputs(nodeID string) (model.NFTInputs, bool, error) {
	var out model.NFTInputs
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketNFTInputs, nodeID, &out)
		return err
	})
	return out, ok, err
}

func (bs *BoltStateStore) AllNFTInputs() ([]model.NFTInputs, error) {
	inputs := []model.NFTInputs{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		inputs, err = listMapValues[model.NFTInputs](tx, boltBucketNFTInputs)
		return err
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(inputs, func(i, j int) bool { return inputs[i].NodeID < inputs[j].NodeID })
	return inputs, nil
}

func (bs *BoltStateStore) DeleteNFTInputs(nodeID string) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return deleteRecord(tx, boltBucketNFTInputs, nodeID)
	})
}

func (bs *BoltStateStore) UpsertDNSDeployment(dep model.DNSDeployment) error {
	dep.UpdatedAt = time.Now().UTC()
	if dep.CreatedAt.IsZero() {
		dep.CreatedAt = dep.UpdatedAt
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		enc, err := encryptDNSDeploymentRecord(dep.ID, dep, bs.cipher)
		if err != nil {
			return err
		}
		return putRecord(tx, boltBucketDNSDeployments, dep.ID, enc)
	})
}

func (bs *BoltStateStore) DNSDeployment(id string) (model.DNSDeployment, bool, error) {
	var out model.DNSDeployment
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketDNSDeployments, id, &out)
		if err != nil || !ok {
			return err
		}
		out, err = decryptDNSDeploymentRecord(id, out, bs.cipher)
		return err
	})
	return out, ok, err
}

func (bs *BoltStateStore) DNSDeployments() ([]model.DNSDeployment, error) {
	deployments := []model.DNSDeployment{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		all, err := listMapValues[model.DNSDeployment](tx, boltBucketDNSDeployments)
		if err != nil {
			return err
		}
		for _, dep := range all {
			dec, err := decryptDNSDeploymentRecord(dep.ID, dep, bs.cipher)
			if err != nil {
				return err
			}
			deployments = append(deployments, dec)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(deployments, func(i, j int) bool { return deployments[i].CreatedAt.Before(deployments[j].CreatedAt) })
	return deployments, nil
}

func (bs *BoltStateStore) DNSDeploymentsForNode(nodeID string) ([]model.DNSDeployment, error) {
	deployments := []model.DNSDeployment{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		all, err := listMapValues[model.DNSDeployment](tx, boltBucketDNSDeployments)
		if err != nil {
			return err
		}
		for _, dep := range all {
			if dep.NodeID != nodeID {
				continue
			}
			dec, err := decryptDNSDeploymentRecord(dep.ID, dep, bs.cipher)
			if err != nil {
				return err
			}
			deployments = append(deployments, dec)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(deployments, func(i, j int) bool { return deployments[i].CreatedAt.Before(deployments[j].CreatedAt) })
	return deployments, nil
}

func (bs *BoltStateStore) DeleteDNSDeployment(id string) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return deleteRecord(tx, boltBucketDNSDeployments, id)
	})
}

func (bs *BoltStateStore) UpsertNetPolicy(policy model.NetPolicy) error {
	policy.UpdatedAt = time.Now().UTC()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = policy.UpdatedAt
	}
	policy.ID = policy.TargetNodeID
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return putRecord(tx, boltBucketNetPolicies, policy.TargetNodeID, policy)
	})
}

func (bs *BoltStateStore) NetPolicy(nodeID string) (model.NetPolicy, bool, error) {
	var out model.NetPolicy
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketNetPolicies, nodeID, &out)
		return err
	})
	return out, ok, err
}

func (bs *BoltStateStore) NetPolicies() ([]model.NetPolicy, error) {
	policies := []model.NetPolicy{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		policies, err = listMapValues[model.NetPolicy](tx, boltBucketNetPolicies)
		return err
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(policies, func(i, j int) bool { return policies[i].TargetNodeID < policies[j].TargetNodeID })
	return policies, nil
}

func (bs *BoltStateStore) DeleteNetPolicy(nodeID string) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return deleteRecord(tx, boltBucketNetPolicies, nodeID)
	})
}

func (bs *BoltStateStore) UpsertGroup(g model.Group) error {
	g.UpdatedAt = time.Now().UTC()
	if g.CreatedAt.IsZero() {
		g.CreatedAt = g.UpdatedAt
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return putRecord(tx, boltBucketGroups, g.ID, cloneGroup(g))
	})
}

func (bs *BoltStateStore) Group(id string) (model.Group, bool, error) {
	var out model.Group
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketGroups, id, &out)
		if err != nil || !ok {
			return err
		}
		out = cloneGroup(out)
		return nil
	})
	return out, ok, err
}

func (bs *BoltStateStore) Groups() ([]model.Group, error) {
	groups := []model.Group{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		groups, err = listMapValues[model.Group](tx, boltBucketGroups)
		if err != nil {
			return err
		}
		for i := range groups {
			groups[i] = cloneGroup(groups[i])
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })
	return groups, nil
}

func (bs *BoltStateStore) DeleteGroup(id string) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var existing model.Group
		ok, err := getRecord(tx, boltBucketGroups, id, &existing)
		if err != nil || !ok {
			return err
		}
		groups, err := listMapValues[model.Group](tx, boltBucketGroups)
		if err != nil {
			return err
		}
		for _, child := range groups {
			if child.ParentID == id {
				return fmt.Errorf("group %q has child group %q; reparent or delete children first", id, child.ID)
			}
		}
		policies, err := listMapValues[model.GroupNetPolicy](tx, boltBucketGroupPolicies)
		if err != nil {
			return err
		}
		for _, gp := range policies {
			if gp.ScopeGroupID == id {
				return fmt.Errorf("group %q is referenced by group policy %q; delete the policy first", id, gp.ID)
			}
		}
		return deleteRecord(tx, boltBucketGroups, id)
	})
}

func (bs *BoltStateStore) UpsertGroupPolicy(p model.GroupNetPolicy) error {
	p.UpdatedAt = time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = p.UpdatedAt
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return putRecord(tx, boltBucketGroupPolicies, p.ID, cloneGroupPolicy(p))
	})
}

func (bs *BoltStateStore) GroupPolicy(id string) (model.GroupNetPolicy, bool, error) {
	var out model.GroupNetPolicy
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketGroupPolicies, id, &out)
		if err != nil || !ok {
			return err
		}
		out = cloneGroupPolicy(out)
		return nil
	})
	return out, ok, err
}

func (bs *BoltStateStore) GroupPolicies() ([]model.GroupNetPolicy, error) {
	policies := []model.GroupNetPolicy{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		policies, err = listMapValues[model.GroupNetPolicy](tx, boltBucketGroupPolicies)
		if err != nil {
			return err
		}
		for i := range policies {
			policies[i] = cloneGroupPolicy(policies[i])
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })
	return policies, nil
}

func (bs *BoltStateStore) DeleteGroupPolicy(id string) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return deleteRecord(tx, boltBucketGroupPolicies, id)
	})
}

func (bs *BoltStateStore) UpsertProxyInbound(in model.ProxyInbound) error {
	in.UpdatedAt = time.Now().UTC()
	if in.CreatedAt.IsZero() {
		in.CreatedAt = in.UpdatedAt
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		enc, err := encryptProxyInboundRecord(in.ID, in, bs.cipher)
		if err != nil {
			return err
		}
		return putRecord(tx, boltBucketProxyInbounds, in.ID, enc)
	})
}

func (bs *BoltStateStore) ProxyInbound(id string) (model.ProxyInbound, bool, error) {
	var out model.ProxyInbound
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketProxyInbounds, id, &out)
		if err != nil || !ok {
			return err
		}
		out, err = decryptProxyInboundRecord(id, out, bs.cipher)
		return err
	})
	return out, ok, err
}

func (bs *BoltStateStore) ProxyInbounds() ([]model.ProxyInbound, error) {
	inbounds := []model.ProxyInbound{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		all, err := listMapValues[model.ProxyInbound](tx, boltBucketProxyInbounds)
		if err != nil {
			return err
		}
		for _, in := range all {
			dec, err := decryptProxyInboundRecord(in.ID, in, bs.cipher)
			if err != nil {
				return err
			}
			inbounds = append(inbounds, dec)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(inbounds, func(i, j int) bool {
		if inbounds[i].CreatedAt.Equal(inbounds[j].CreatedAt) {
			return inbounds[i].ID < inbounds[j].ID
		}
		return inbounds[i].CreatedAt.Before(inbounds[j].CreatedAt)
	})
	return inbounds, nil
}

func (bs *BoltStateStore) DeleteProxyInbound(id string) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return deleteRecord(tx, boltBucketProxyInbounds, id)
	})
}

func (bs *BoltStateStore) UpsertProxyUser(u model.ProxyUser) error {
	u.UpdatedAt = time.Now().UTC()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = u.UpdatedAt
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		enc, err := encryptProxyUserRecord(u.ID, u, bs.cipher)
		if err != nil {
			return err
		}
		return putRecord(tx, boltBucketProxyUsers, u.ID, enc)
	})
}

func (bs *BoltStateStore) ProxyUser(id string) (model.ProxyUser, bool, error) {
	var out model.ProxyUser
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketProxyUsers, id, &out)
		if err != nil || !ok {
			return err
		}
		out, err = decryptProxyUserRecord(id, out, bs.cipher)
		return err
	})
	return out, ok, err
}

func (bs *BoltStateStore) ProxyUsers() ([]model.ProxyUser, error) {
	users := []model.ProxyUser{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		all, err := listMapValues[model.ProxyUser](tx, boltBucketProxyUsers)
		if err != nil {
			return err
		}
		for _, u := range all {
			dec, err := decryptProxyUserRecord(u.ID, u, bs.cipher)
			if err != nil {
				return err
			}
			users = append(users, dec)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(users, func(i, j int) bool {
		if users[i].CreatedAt.Equal(users[j].CreatedAt) {
			return users[i].ID < users[j].ID
		}
		return users[i].CreatedAt.Before(users[j].CreatedAt)
	})
	return users, nil
}

func (bs *BoltStateStore) ProxyUsersForInbound(inboundID string) ([]model.ProxyUser, error) {
	users := []model.ProxyUser{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		all, err := listMapValues[model.ProxyUser](tx, boltBucketProxyUsers)
		if err != nil {
			return err
		}
		for _, u := range all {
			if len(u.InboundIDs) != 0 && !contains(u.InboundIDs, inboundID) {
				continue
			}
			dec, err := decryptProxyUserRecord(u.ID, u, bs.cipher)
			if err != nil {
				return err
			}
			users = append(users, dec)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(users, func(i, j int) bool {
		if users[i].CreatedAt.Equal(users[j].CreatedAt) {
			return users[i].ID < users[j].ID
		}
		return users[i].CreatedAt.Before(users[j].CreatedAt)
	})
	return users, nil
}

func (bs *BoltStateStore) DeleteProxyUser(id string) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return deleteRecord(tx, boltBucketProxyUsers, id)
	})
}

func (bs *BoltStateStore) UpsertProxyNodeProfile(profile model.ProxyNodeProfile) error {
	profile.UpdatedAt = time.Now().UTC()
	if profile.CreatedAt.IsZero() {
		profile.CreatedAt = profile.UpdatedAt
	}
	if profile.ID == "" {
		profile.ID = profile.NodeID
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return putRecord(tx, boltBucketProxyProfiles, profile.NodeID, profile)
	})
}

func (bs *BoltStateStore) ProxyNodeProfile(nodeID string) (model.ProxyNodeProfile, bool, error) {
	var out model.ProxyNodeProfile
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketProxyProfiles, nodeID, &out)
		return err
	})
	return out, ok, err
}

func (bs *BoltStateStore) ProxyNodeProfiles() ([]model.ProxyNodeProfile, error) {
	profiles := []model.ProxyNodeProfile{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		profiles, err = listMapValues[model.ProxyNodeProfile](tx, boltBucketProxyProfiles)
		return err
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].NodeID < profiles[j].NodeID })
	return profiles, nil
}

func (bs *BoltStateStore) DeleteProxyNodeProfile(nodeID string) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return deleteRecord(tx, boltBucketProxyProfiles, nodeID)
	})
}

func (bs *BoltStateStore) UpsertProxyUsageSnapshot(snapshot model.ProxyUsageSnapshot) error {
	if snapshot.At.IsZero() {
		snapshot.At = time.Now().UTC()
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return putRecord(tx, boltBucketProxyUsage, snapshot.NodeID, snapshot)
	})
}

func (bs *BoltStateStore) ApplyProxyUsageUpdate(users []model.ProxyUser, profile *model.ProxyNodeProfile, snapshot *model.ProxyUsageSnapshot) error {
	if len(users) == 0 && profile == nil && snapshot == nil {
		return nil
	}
	now := time.Now().UTC()
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		for _, user := range users {
			user = normalizeProxyUserForStore(user, now)
			enc, err := encryptProxyUserRecord(user.ID, user, bs.cipher)
			if err != nil {
				return err
			}
			if err := putRecord(tx, boltBucketProxyUsers, user.ID, enc); err != nil {
				return err
			}
		}
		if profile != nil {
			normalized := normalizeProxyNodeProfileForStore(*profile, now)
			if err := putRecord(tx, boltBucketProxyProfiles, normalized.NodeID, normalized); err != nil {
				return err
			}
		}
		if snapshot != nil {
			normalized := normalizeProxyUsageSnapshotForStore(*snapshot, now)
			if err := putRecord(tx, boltBucketProxyUsage, normalized.NodeID, normalized); err != nil {
				return err
			}
		}
		return nil
	})
}

func (bs *BoltStateStore) ProxyUsageSnapshot(nodeID string) (model.ProxyUsageSnapshot, bool, error) {
	var out model.ProxyUsageSnapshot
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketProxyUsage, nodeID, &out)
		return err
	})
	return out, ok, err
}

func (bs *BoltStateStore) ProxyUsageSnapshots() ([]model.ProxyUsageSnapshot, error) {
	snapshots := []model.ProxyUsageSnapshot{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		snapshots, err = listMapValues[model.ProxyUsageSnapshot](tx, boltBucketProxyUsage)
		return err
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(snapshots, func(i, j int) bool { return snapshots[i].NodeID < snapshots[j].NodeID })
	return snapshots, nil
}

func (bs *BoltStateStore) DeleteProxyUsageSnapshot(nodeID string) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return deleteRecord(tx, boltBucketProxyUsage, nodeID)
	})
}

func (bs *BoltStateStore) UpsertNotifyChannel(c model.NotifyChannel) error {
	c.UpdatedAt = time.Now().UTC()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = c.UpdatedAt
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		enc, err := encryptNotifyRecord(c.ID, c, bs.cipher)
		if err != nil {
			return err
		}
		return putRecord(tx, boltBucketNotifyChannels, c.ID, enc)
	})
}

func (bs *BoltStateStore) NotifyChannels() ([]model.NotifyChannel, error) {
	channels := []model.NotifyChannel{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		all, err := listMapValues[model.NotifyChannel](tx, boltBucketNotifyChannels)
		if err != nil {
			return err
		}
		for _, c := range all {
			dec, err := decryptNotifyRecord(c.ID, c, bs.cipher)
			if err != nil {
				return err
			}
			channels = append(channels, dec)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(channels, func(i, j int) bool { return channels[i].CreatedAt.Before(channels[j].CreatedAt) })
	return channels, nil
}

func (bs *BoltStateStore) EnabledNotifyChannels() ([]model.NotifyChannel, error) {
	channels := []model.NotifyChannel{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		all, err := listMapValues[model.NotifyChannel](tx, boltBucketNotifyChannels)
		if err != nil {
			return err
		}
		for _, c := range all {
			if !c.Enabled {
				continue
			}
			dec, err := decryptNotifyRecord(c.ID, c, bs.cipher)
			if err != nil {
				return err
			}
			channels = append(channels, dec)
		}
		return nil
	})
	return channels, err
}

func (bs *BoltStateStore) UpsertNotifyRule(rule model.NotifyRule) error {
	rule.UpdatedAt = time.Now().UTC()
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = rule.UpdatedAt
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return putRecord(tx, boltBucketNotifyRules, rule.ID, rule)
	})
}

func (bs *BoltStateStore) NotifyRules() ([]model.NotifyRule, error) {
	rules := []model.NotifyRule{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		rules, err = listMapValues[model.NotifyRule](tx, boltBucketNotifyRules)
		return err
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].CreatedAt.Before(rules[j].CreatedAt) })
	return rules, nil
}

func (bs *BoltStateStore) EnabledNotifyRules() ([]model.NotifyRule, error) {
	rules := []model.NotifyRule{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		all, err := listMapValues[model.NotifyRule](tx, boltBucketNotifyRules)
		if err != nil {
			return err
		}
		for _, rule := range all {
			if rule.Enabled {
				rules = append(rules, rule)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].CreatedAt.Before(rules[j].CreatedAt) })
	return rules, nil
}

func (bs *BoltStateStore) DeleteNotifyRule(id string) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return deleteRecord(tx, boltBucketNotifyRules, id)
	})
}

func (bs *BoltStateStore) DeleteNotifyChannel(id string) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		if err := deleteRecord(tx, boltBucketNotifyChannels, id); err != nil {
			return err
		}
		rules, err := listMapValues[model.NotifyRule](tx, boltBucketNotifyRules)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		for _, rule := range rules {
			next := make([]string, 0, len(rule.ChannelIDs))
			changed := false
			for _, channelID := range rule.ChannelIDs {
				if channelID == id {
					changed = true
					continue
				}
				next = append(next, channelID)
			}
			if changed {
				rule.ChannelIDs = next
				rule.UpdatedAt = now
				if err := putRecord(tx, boltBucketNotifyRules, rule.ID, rule); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (bs *BoltStateStore) UpsertOIDCProvider(p model.OIDCProvider) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		enc, err := encryptOIDCProviderRecord(p.ID, p, bs.cipher)
		if err != nil {
			return err
		}
		return putRecord(tx, boltBucketOIDCProviders, p.ID, enc)
	})
}

func (bs *BoltStateStore) OIDCProvider(id string) (model.OIDCProvider, bool, error) {
	var out model.OIDCProvider
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketOIDCProviders, id, &out)
		if err != nil || !ok {
			return err
		}
		out, err = decryptOIDCProviderRecord(id, out, bs.cipher)
		return err
	})
	return out, ok, err
}

func (bs *BoltStateStore) OIDCProviders() ([]model.OIDCProvider, error) {
	providers := []model.OIDCProvider{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		all, err := listMapValues[model.OIDCProvider](tx, boltBucketOIDCProviders)
		if err != nil {
			return err
		}
		for _, p := range all {
			dec, err := decryptOIDCProviderRecord(p.ID, p, bs.cipher)
			if err != nil {
				return err
			}
			providers = append(providers, dec)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].CreatedAt.Before(providers[j].CreatedAt) })
	return providers, nil
}

func (bs *BoltStateStore) EnabledOIDCProviders() ([]model.OIDCProvider, error) {
	providers := []model.OIDCProvider{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		all, err := listMapValues[model.OIDCProvider](tx, boltBucketOIDCProviders)
		if err != nil {
			return err
		}
		for _, p := range all {
			if !p.Enabled {
				continue
			}
			dec, err := decryptOIDCProviderRecord(p.ID, p, bs.cipher)
			if err != nil {
				return err
			}
			providers = append(providers, dec)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].CreatedAt.Before(providers[j].CreatedAt) })
	return providers, nil
}

func (bs *BoltStateStore) DeleteOIDCProvider(id string) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var p model.OIDCProvider
		ok, err := getRecord(tx, boltBucketOIDCProviders, id, &p)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("oidc provider not found")
		}
		return deleteRecord(tx, boltBucketOIDCProviders, id)
	})
}

func (bs *BoltStateStore) OIDCIdentity(providerID, subject string) (model.OIDCIdentity, bool, error) {
	var out model.OIDCIdentity
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketOIDCIdentities, oidcIdentityKey(providerID, subject), &out)
		return err
	})
	return out, ok, err
}

func (bs *BoltStateStore) PutOIDCIdentity(idn model.OIDCIdentity) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return putRecord(tx, boltBucketOIDCIdentities, oidcIdentityKey(idn.ProviderID, idn.Subject), idn)
	})
}

func (bs *BoltStateStore) PutOIDCAuthState(st auth.OIDCAuthState) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		now := time.Now().UTC()
		states, err := listMapValues[auth.OIDCAuthState](tx, boltBucketOIDCAuthStates)
		if err != nil {
			return err
		}
		active := 0
		for _, existing := range states {
			dec, err := decryptOIDCAuthStateRecord(existing.State, existing, bs.cipher)
			if err != nil {
				return err
			}
			if now.After(dec.ExpiresAt) {
				if err := deleteAuthRecord(tx, boltBucketOIDCAuthStates, oidcAuthStateStorageKey(dec.State), dec.State); err != nil {
					return err
				}
				continue
			}
			active++
		}
		if active >= maxOIDCAuthStates {
			return errors.New("too many pending oidc logins")
		}
		enc, err := encryptOIDCAuthStateRecord(st.State, st, bs.cipher)
		if err != nil {
			return err
		}
		return putRecord(tx, boltBucketOIDCAuthStates, oidcAuthStateStorageKey(st.State), enc)
	})
}

func (bs *BoltStateStore) ConsumeOIDCAuthState(state string) (auth.OIDCAuthState, bool, error) {
	var out auth.OIDCAuthState
	var ok bool
	err := bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var raw auth.OIDCAuthState
		var err error
		ok, err = getAuthRecord(tx, boltBucketOIDCAuthStates, oidcAuthStateStorageKey(state), state, &raw)
		if err != nil || !ok {
			return err
		}
		if err := deleteAuthRecord(tx, boltBucketOIDCAuthStates, oidcAuthStateStorageKey(state), state); err != nil {
			return err
		}
		out, err = decryptOIDCAuthStateRecord(state, raw, bs.cipher)
		if err != nil {
			return err
		}
		if time.Now().UTC().After(out.ExpiresAt) {
			ok = false
			out = auth.OIDCAuthState{}
		}
		return nil
	})
	return out, ok, err
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

func deleteRecord(tx *bolt.Tx, bucket []byte, key string) error {
	b := tx.Bucket(bucket)
	if b == nil {
		return nil
	}
	k, err := boltStringKey(key)
	if err != nil {
		return err
	}
	return b.Delete(k)
}

func getAuthRecord[T any](tx *bolt.Tx, bucket []byte, primaryKey, legacyKey string, out *T) (bool, error) {
	ok, err := getRecord(tx, bucket, primaryKey, out)
	if err != nil || ok || primaryKey == legacyKey {
		return ok, err
	}
	return getRecord(tx, bucket, legacyKey, out)
}

func deleteAuthRecord(tx *bolt.Tx, bucket []byte, primaryKey, legacyKey string) error {
	if err := deleteRecord(tx, bucket, primaryKey); err != nil {
		return err
	}
	if primaryKey != legacyKey {
		return deleteRecord(tx, bucket, legacyKey)
	}
	return nil
}

func countBucketRecords(tx *bolt.Tx, bucket []byte) (int, error) {
	b := tx.Bucket(bucket)
	if b == nil {
		return 0, nil
	}
	count := 0
	err := b.ForEach(func(_, _ []byte) error {
		count++
		return nil
	})
	return count, err
}

func evictOldestSessionRecord(tx *bolt.Tx, c secret.Cipher) error {
	sessions, err := listMapValues[auth.Session](tx, boltBucketSessions)
	if err != nil {
		return err
	}
	var oldest auth.Session
	found := false
	for _, sess := range sessions {
		dec, err := decryptSessionRecord(sess.ID, sess, c)
		if err != nil {
			return err
		}
		if !found || dec.CreatedAt.Before(oldest.CreatedAt) {
			oldest = dec
			found = true
		}
	}
	if found {
		return deleteAuthRecord(tx, boltBucketSessions, sessionStorageKey(oldest.ID), oldest.ID)
	}
	return nil
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
