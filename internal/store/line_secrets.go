package store

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/LatticeNet/lattice-sdk/model"
)

var vpnCredentialProtocols = map[string]bool{"vless": true, "vmess": true, "trojan": true, "shadowsocks": true, "hysteria2": true, "tuic": true, "anytls": true}

const MaxVpnCredentialPasswordBytes = 256

func validSecretUUIDv4(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' || value[14] != '4' || !strings.ContainsRune("89ab", rune(value[19])) {
		return false
	}
	for i, r := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func validRealityKey(value string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == value
}

// ValidateVpnUserCredentialSecret is the shared canonical protocol-shape
// contract used by typed persistence and server request normalization.
func ValidateVpnUserCredentialSecret(credential VpnUserCredentialSecret) error {
	protocol := strings.TrimSpace(credential.Protocol)
	if protocol == "" || credential.Protocol != strings.ToLower(protocol) || !vpnCredentialProtocols[protocol] {
		return fmt.Errorf("unsupported or noncanonical credential protocol %q", credential.Protocol)
	}
	validatePassword := func(required bool) error {
		if (!required && credential.Password != "") || (required && strings.TrimSpace(credential.Password) == "") {
			return errors.New("credential has invalid password presence")
		}
		if len(credential.Password) > MaxVpnCredentialPasswordBytes || strings.ContainsFunc(credential.Password, unicode.IsControl) {
			return errors.New("credential password is invalid or too long")
		}
		return nil
	}
	switch protocol {
	case "vless", "vmess":
		if !validSecretUUIDv4(credential.UUID) {
			return errors.New("credential UUID must be canonical UUIDv4")
		}
		return validatePassword(false)
	case "tuic":
		if !validSecretUUIDv4(credential.UUID) {
			return errors.New("TUIC UUID must be canonical UUIDv4")
		}
		return validatePassword(true)
	default:
		if credential.UUID != "" {
			return errors.New("password credential must not carry UUID")
		}
		return validatePassword(true)
	}
}

const (
	MaxVpnUserRecords            = 100_000
	MaxVpnUserCredentials        = 16
	MaxLineSecretRecordBytes     = 16 << 10
	MaxLineSecretCollectionBytes = 256 << 20
)

// VpnUserPublicRecord is the non-secret half of a vpn-core identity. It is a
// typed store collection so generic KV APIs cannot enumerate or overwrite it.
type VpnUserPublicRecord struct {
	ID                    string                    `json:"id"`
	Email                 string                    `json:"email"`
	Name                  string                    `json:"name,omitempty"`
	Enabled               bool                      `json:"enabled"`
	Credentials           []VpnUserCredentialPublic `json:"credentials"`
	Bindings              []VpnUserLineBinding      `json:"bindings"`
	QuotaBytes            int64                     `json:"quota_bytes,omitempty"`
	ExpiresAt             time.Time                 `json:"expires_at,omitempty"`
	Group                 string                    `json:"group,omitempty"`
	Comment               string                    `json:"comment,omitempty"`
	MigratedFromProxyUser string                    `json:"migrated_from_proxy_user,omitempty"`
	CreatedAt             time.Time                 `json:"created_at"`
	UpdatedAt             time.Time                 `json:"updated_at"`
}

type VpnUserCredentialPublic struct {
	Protocol string `json:"protocol"`
	Flow     string `json:"flow,omitempty"`
	Method   string `json:"method,omitempty"`
	Security string `json:"security,omitempty"`
}

type VpnUserLineBinding struct {
	LineHashID   string `json:"line_hash_id"`
	Enabled      bool   `json:"enabled"`
	FlowOverride string `json:"flow_override,omitempty"`
}

// VpnUserSecretRecord is the independently encrypted private half. It has no
// generic HTTP or plugin surface.
type VpnUserSecretRecord struct {
	Credentials []VpnUserCredentialSecret `json:"credentials"`
	SubID       string                    `json:"sub_id,omitempty"`
}

type VpnUserCredentialSecret struct {
	Protocol string `json:"protocol"`
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
}

type ManagedLinePublicRecord struct {
	LineUUID         string    `json:"line_uuid"`
	NodeID           string    `json:"node_id"`
	LineHashID       string    `json:"line_hash_id"`
	Tag              string    `json:"tag"`
	Port             int       `json:"port"`
	SNI              string    `json:"sni"`
	HandshakeServer  string    `json:"handshake_server"`
	HandshakePort    int       `json:"handshake_port"`
	RealityPublicKey string    `json:"reality_public_key"`
	ShortID          string    `json:"short_id"`
	UserID           string    `json:"user_id"`
	UserName         string    `json:"user_name"`
	FragmentSHA256   string    `json:"fragment_sha256"`
	Status           string    `json:"status"`
	ApprovalID       string    `json:"approval_id"`
	LastError        string    `json:"last_error,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type ManagedLineSecretRecord struct {
	RealityPrivateKey string `json:"reality_private_key"`
}

type LegacyKVKey struct {
	Bucket string
	Key    string
}

type LineSecretMigrationSource struct {
	VpnUsers           map[string]VpnUserPublicRecord
	VpnUserSecrets     map[string]VpnUserSecretRecord
	ManagedLines       map[string]ManagedLinePublicRecord
	ManagedLineSecrets map[string]ManagedLineSecretRecord
	KV                 []model.KVEntry
	ProxyUsers         []model.ProxyUser
}

type LineSecretMigrationBuild struct {
	VpnUsers           map[string]VpnUserPublicRecord
	VpnUserSecrets     map[string]VpnUserSecretRecord
	ManagedLines       map[string]ManagedLinePublicRecord
	ManagedLineSecrets map[string]ManagedLineSecretRecord
	Legacy             []LegacyKVKey
}

func validateVpnUserCollections(public map[string]VpnUserPublicRecord, private map[string]VpnUserSecretRecord) error {
	if len(public) > MaxVpnUserRecords || len(private) > MaxVpnUserRecords {
		return fmt.Errorf("vpn user collection holds more than %d records", MaxVpnUserRecords)
	}
	total := 0
	for id, record := range private {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("vpn user secret has invalid id %q", id)
		}
		if _, ok := public[id]; !ok {
			return fmt.Errorf("vpn user secret %q has no public record", id)
		}
		if len(record.Credentials) > MaxVpnUserCredentials {
			return fmt.Errorf("vpn user %q has more than %d credentials", id, MaxVpnUserCredentials)
		}
		seen := make(map[string]struct{}, len(record.Credentials))
		for _, credential := range record.Credentials {
			protocol := strings.TrimSpace(credential.Protocol)
			if protocol == "" {
				return fmt.Errorf("vpn user %q has credential with empty protocol", id)
			}
			if credential.Protocol != strings.ToLower(protocol) {
				return fmt.Errorf("vpn user %q has noncanonical private protocol %q", id, credential.Protocol)
			}
			if !vpnCredentialProtocols[protocol] {
				return fmt.Errorf("vpn user %q has unsupported private protocol %q", id, protocol)
			}
			if _, ok := seen[protocol]; ok {
				return fmt.Errorf("vpn user %q has duplicate %q credential", id, protocol)
			}
			seen[protocol] = struct{}{}
			if err := ValidateVpnUserCredentialSecret(credential); err != nil {
				return fmt.Errorf("vpn user %q credential %q: %w", id, protocol, err)
			}
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("encode vpn user secret %q: %w", id, err)
		}
		if len(encoded) > MaxLineSecretRecordBytes {
			return fmt.Errorf("vpn user secret %q exceeds %d encoded bytes", id, MaxLineSecretRecordBytes)
		}
		total += len(encoded)
		if total > MaxLineSecretCollectionBytes {
			return fmt.Errorf("vpn user secrets exceed %d aggregate encoded bytes", MaxLineSecretCollectionBytes)
		}
	}
	for id, record := range public {
		if strings.TrimSpace(id) == "" || record.ID != id {
			return fmt.Errorf("vpn user public record %q has mismatched id %q", id, record.ID)
		}
		if len(record.Credentials) > MaxVpnUserCredentials {
			return fmt.Errorf("vpn user %q has more than %d public credentials", id, MaxVpnUserCredentials)
		}
		secretRecord, ok := private[id]
		if !ok && len(record.Credentials) > 0 {
			return fmt.Errorf("vpn user %q is missing private credentials", id)
		}
		publicProtocols := make(map[string]struct{}, len(record.Credentials))
		for _, credential := range record.Credentials {
			protocol := strings.TrimSpace(credential.Protocol)
			if protocol == "" {
				return fmt.Errorf("vpn user %q has public credential with empty protocol", id)
			}
			if credential.Protocol != strings.ToLower(protocol) {
				return fmt.Errorf("vpn user %q has noncanonical public protocol %q", id, credential.Protocol)
			}
			if !vpnCredentialProtocols[protocol] {
				return fmt.Errorf("vpn user %q has unsupported public protocol %q", id, protocol)
			}
			if _, exists := publicProtocols[protocol]; exists {
				return fmt.Errorf("vpn user %q has duplicate public %q credential", id, protocol)
			}
			publicProtocols[protocol] = struct{}{}
		}
		if len(publicProtocols) != len(secretRecord.Credentials) {
			return fmt.Errorf("vpn user %q public/private credential sets differ", id)
		}
		for _, credential := range secretRecord.Credentials {
			if _, exists := publicProtocols[credential.Protocol]; !exists {
				return fmt.Errorf("vpn user %q public/private credential sets differ", id)
			}
		}
	}
	return nil
}

func validateManagedLineCollections(public map[string]ManagedLinePublicRecord, private map[string]ManagedLineSecretRecord) error {
	if len(public) > MaxVpnUserRecords || len(private) > MaxVpnUserRecords {
		return fmt.Errorf("managed line collection holds more than %d records", MaxVpnUserRecords)
	}
	total := 0
	for id, record := range public {
		if strings.TrimSpace(id) == "" || record.LineUUID != id || !validSecretUUIDv4(id) {
			return fmt.Errorf("managed line public record %q has mismatched line uuid %q", id, record.LineUUID)
		}
		if !validRealityKey(record.RealityPublicKey) {
			return fmt.Errorf("managed line %q has invalid reality public key", id)
		}
		if _, ok := private[id]; !ok {
			return fmt.Errorf("managed line %q is missing private material", id)
		}
	}
	for id, record := range private {
		if _, ok := public[id]; !ok {
			return fmt.Errorf("managed line secret %q has no public record", id)
		}
		if !validRealityKey(record.RealityPrivateKey) {
			return fmt.Errorf("managed line secret %q has invalid reality private key", id)
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("encode managed line secret %q: %w", id, err)
		}
		if len(encoded) > MaxLineSecretRecordBytes {
			return fmt.Errorf("managed line secret %q exceeds %d encoded bytes", id, MaxLineSecretRecordBytes)
		}
		total += len(encoded)
		if total > MaxLineSecretCollectionBytes {
			return fmt.Errorf("managed line secrets exceed %d aggregate encoded bytes", MaxLineSecretCollectionBytes)
		}
	}
	return nil
}

func cloneVpnUserPublicRecords(in map[string]VpnUserPublicRecord) map[string]VpnUserPublicRecord {
	out := make(map[string]VpnUserPublicRecord, len(in))
	for id, record := range in {
		record.Credentials = append([]VpnUserCredentialPublic(nil), record.Credentials...)
		record.Bindings = append([]VpnUserLineBinding(nil), record.Bindings...)
		out[id] = record
	}
	return out
}

func cloneVpnUserSecretRecords(in map[string]VpnUserSecretRecord) map[string]VpnUserSecretRecord {
	out := make(map[string]VpnUserSecretRecord, len(in))
	for id, record := range in {
		record.Credentials = append([]VpnUserCredentialSecret(nil), record.Credentials...)
		out[id] = record
	}
	return out
}

func cloneManagedLinePublicRecords(in map[string]ManagedLinePublicRecord) map[string]ManagedLinePublicRecord {
	out := make(map[string]ManagedLinePublicRecord, len(in))
	for id, record := range in {
		out[id] = record
	}
	return out
}

func cloneManagedLineSecretRecords(in map[string]ManagedLineSecretRecord) map[string]ManagedLineSecretRecord {
	out := make(map[string]ManagedLineSecretRecord, len(in))
	for id, record := range in {
		out[id] = record
	}
	return out
}

// MigrateLineSecrets holds the authoritative store lock while the caller
// transforms a revision-consistent source snapshot and while the staged result
// crosses the JSON persistence commit point.
func (s *Store) MigrateLineSecrets(build func(LineSecretMigrationSource) (LineSecretMigrationBuild, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kv := make([]model.KVEntry, 0, len(s.state.KV))
	for _, entry := range s.state.KV {
		kv = append(kv, entry)
	}
	proxyUsers := make([]model.ProxyUser, 0, len(s.state.ProxyUsers))
	for _, user := range s.state.ProxyUsers {
		user.InboundIDs = append([]string(nil), user.InboundIDs...)
		proxyUsers = append(proxyUsers, user)
	}
	source := LineSecretMigrationSource{
		VpnUsers: cloneVpnUserPublicRecords(s.state.VpnUsers), VpnUserSecrets: cloneVpnUserSecretRecords(s.state.VpnUserSecrets),
		ManagedLines: cloneManagedLinePublicRecords(s.state.ManagedLines), ManagedLineSecrets: cloneManagedLineSecretRecords(s.state.ManagedLineSecrets),
		KV: kv, ProxyUsers: proxyUsers,
	}
	result, err := build(source)
	if err != nil {
		return err
	}
	return s.replaceLineSecretRecordsLocked(result.VpnUsers, result.VpnUserSecrets, result.ManagedLines, result.ManagedLineSecrets, result.Legacy)
}

// ReplaceVpnUserRecords migrates public/private identities and removes legacy
// secret-bearing KV entries in one staged JSON persistence transaction.
func (s *Store) ReplaceVpnUserRecords(public map[string]VpnUserPublicRecord, private map[string]VpnUserSecretRecord, legacy []LegacyKVKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.replaceVpnUserRecordsLocked(public, private, legacy)
}

func (s *Store) replaceVpnUserRecordsLocked(public map[string]VpnUserPublicRecord, private map[string]VpnUserSecretRecord, legacy []LegacyKVKey) error {
	return s.replaceLineSecretRecordsLocked(public, private, s.state.ManagedLines, s.state.ManagedLineSecrets, legacy)
}

// ReplaceLineSecretRecords is the one authoritative migration transaction for
// both legacy line-secret domains.
func (s *Store) ReplaceLineSecretRecords(vpnPublic map[string]VpnUserPublicRecord, vpnPrivate map[string]VpnUserSecretRecord, managedPublic map[string]ManagedLinePublicRecord, managedPrivate map[string]ManagedLineSecretRecord, legacy []LegacyKVKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.replaceLineSecretRecordsLocked(vpnPublic, vpnPrivate, managedPublic, managedPrivate, legacy)
}

func (s *Store) replaceLineSecretRecordsLocked(public map[string]VpnUserPublicRecord, private map[string]VpnUserSecretRecord, managedPublic map[string]ManagedLinePublicRecord, managedPrivate map[string]ManagedLineSecretRecord, legacy []LegacyKVKey) error {
	if err := validateVpnUserCollections(public, private); err != nil {
		return err
	}
	if err := validateManagedLineCollections(managedPublic, managedPrivate); err != nil {
		return err
	}
	staged := s.state
	staged.VpnUsers = cloneVpnUserPublicRecords(public)
	staged.VpnUserSecrets = cloneVpnUserSecretRecords(private)
	staged.ManagedLines = cloneManagedLinePublicRecords(managedPublic)
	staged.ManagedLineSecrets = cloneManagedLineSecretRecords(managedPrivate)
	staged.KV = make(map[string]model.KVEntry, len(s.state.KV))
	for id, entry := range s.state.KV {
		staged.KV[id] = entry
	}
	for _, key := range legacy {
		delete(staged.KV, key.Bucket+"/"+key.Key)
	}
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	return err
}

func (s *Store) PutManagedLineRecord(public ManagedLinePublicRecord, private ManagedLineSecretRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	publicRecords := cloneManagedLinePublicRecords(s.state.ManagedLines)
	privateRecords := cloneManagedLineSecretRecords(s.state.ManagedLineSecrets)
	publicRecords[public.LineUUID] = public
	privateRecords[public.LineUUID] = private
	return s.replaceLineSecretRecordsLocked(s.state.VpnUsers, s.state.VpnUserSecrets, publicRecords, privateRecords, nil)
}

func (s *Store) ManagedLineRecord(id string) (ManagedLinePublicRecord, ManagedLineSecretRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	public, ok := s.state.ManagedLines[id]
	if !ok {
		return ManagedLinePublicRecord{}, ManagedLineSecretRecord{}, false
	}
	private, ok := s.state.ManagedLineSecrets[id]
	if !ok {
		return ManagedLinePublicRecord{}, ManagedLineSecretRecord{}, false
	}
	return public, private, true
}

func (s *Store) ManagedLineRecords() (map[string]ManagedLinePublicRecord, map[string]ManagedLineSecretRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneManagedLinePublicRecords(s.state.ManagedLines), cloneManagedLineSecretRecords(s.state.ManagedLineSecrets)
}

func (s *Store) PutVpnUserRecord(public VpnUserPublicRecord, private VpnUserSecretRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	publicRecords := cloneVpnUserPublicRecords(s.state.VpnUsers)
	privateRecords := cloneVpnUserSecretRecords(s.state.VpnUserSecrets)
	publicRecords[public.ID] = public
	privateRecords[public.ID] = private
	return s.replaceVpnUserRecordsLocked(publicRecords, privateRecords, nil)
}

func (s *Store) DeleteVpnUserRecord(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	publicRecords := cloneVpnUserPublicRecords(s.state.VpnUsers)
	privateRecords := cloneVpnUserSecretRecords(s.state.VpnUserSecrets)
	delete(publicRecords, id)
	delete(privateRecords, id)
	return s.replaceVpnUserRecordsLocked(publicRecords, privateRecords, nil)
}

func (s *Store) VpnUserRecord(id string) (VpnUserPublicRecord, VpnUserSecretRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	public, ok := s.state.VpnUsers[id]
	if !ok {
		return VpnUserPublicRecord{}, VpnUserSecretRecord{}, false
	}
	private, ok := s.state.VpnUserSecrets[id]
	if !ok {
		return VpnUserPublicRecord{}, VpnUserSecretRecord{}, false
	}
	return cloneVpnUserPublicRecords(map[string]VpnUserPublicRecord{id: public})[id],
		cloneVpnUserSecretRecords(map[string]VpnUserSecretRecord{id: private})[id], true
}

func (s *Store) VpnUserRecords() (map[string]VpnUserPublicRecord, map[string]VpnUserSecretRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneVpnUserPublicRecords(s.state.VpnUsers), cloneVpnUserSecretRecords(s.state.VpnUserSecrets)
}

func (s *Store) VpnUserPublicRecord(id string) (VpnUserPublicRecord, bool) {
	public, _, ok := s.VpnUserRecord(id)
	return public, ok
}

func (s *Store) VpnUserSecretRecord(id string) (VpnUserSecretRecord, bool) {
	_, private, ok := s.VpnUserRecord(id)
	return private, ok
}

func (s *Store) VpnUserPublicRecords() map[string]VpnUserPublicRecord {
	public, _ := s.VpnUserRecords()
	return public
}

func (s *Store) VpnUserSecretRecords() map[string]VpnUserSecretRecord {
	_, private := s.VpnUserRecords()
	return private
}

func SortedVpnUserRecordIDs(records map[string]VpnUserPublicRecord) []string {
	ids := make([]string, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
