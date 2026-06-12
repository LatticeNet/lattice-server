package plugin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	TypeSystem = "system"
	TypeWasm   = "wasm"
	TypeWorker = "worker"

	RiskRead  = "read"
	RiskWrite = "write"
	RiskHost  = "host"
)

type Manifest struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Type             string   `json:"type"`
	Capabilities     []string `json:"capabilities"`
	Version          string   `json:"version,omitempty"`
	Entrypoint       string   `json:"entrypoint,omitempty"`
	Publisher        string   `json:"publisher,omitempty"`
	DigestSHA256     string   `json:"digest_sha256,omitempty"`
	SignatureEd25519 string   `json:"signature_ed25519,omitempty"`
}

type TrustPolicy struct {
	TrustedPublishers map[string]ed25519.PublicKey
	// AllowUnsignedHostRisk opts OUT of signature enforcement for host-risk
	// plugins. The zero value is fail-closed: host-risk plugins require a trusted
	// publisher signature unless an operator explicitly sets this true (dev only).
	AllowUnsignedHostRisk bool
}

type trustPolicyJSON struct {
	TrustedPublishers     map[string]string `json:"trusted_publishers"`
	AllowUnsignedHostRisk bool              `json:"allow_unsigned_host_risk"`
}

var capabilityRisk = map[string]string{
	"audit:read":    RiskRead,
	"http:egress":   RiskWrite,
	"kv:read":       RiskRead,
	"monitor:read":  RiskRead,
	"node:read":     RiskRead,
	"static:read":   RiskRead,
	"task:read":     RiskRead,
	"kv:write":      RiskWrite,
	"log:write":     RiskWrite,
	"notify:send":   RiskWrite,
	"worker:route":  RiskWrite,
	"ddns:admin":    RiskHost,
	"monitor:admin": RiskHost,
	"network:apply": RiskHost,
	"network:plan":  RiskHost,
	"node:admin":    RiskHost,
	"static:write":  RiskHost,
	"task:run":      RiskHost,
	"tunnel:admin":  RiskHost,
}

var workerCapabilities = map[string]bool{
	"kv:read":      true,
	"static:read":  true,
	"worker:route": true,
}

func ValidateManifest(m Manifest) error {
	if m.ID == "" || m.Name == "" {
		return errors.New("plugin id and name are required")
	}
	if !validPluginID(m.ID) {
		return fmt.Errorf("invalid plugin id %q", m.ID)
	}
	if strings.TrimSpace(m.Name) == "" || hasControl(m.Name) || len(m.Name) > 80 {
		return errors.New("plugin name must be printable and at most 80 characters")
	}
	if m.Publisher != "" && !validPluginID(m.Publisher) {
		return fmt.Errorf("invalid publisher %q", m.Publisher)
	}
	if m.Type != TypeSystem && m.Type != TypeWasm && m.Type != TypeWorker {
		return fmt.Errorf("unsupported plugin type %q", m.Type)
	}
	if len(m.Capabilities) == 0 {
		return errors.New("plugin must declare at least one capability")
	}
	seen := map[string]bool{}
	for _, cap := range m.Capabilities {
		if seen[cap] {
			return fmt.Errorf("capability %q is duplicated", cap)
		}
		seen[cap] = true
		risk, ok := capabilityRisk[cap]
		if !ok {
			return fmt.Errorf("capability %q is not recognized", cap)
		}
		if m.Type != TypeSystem && risk == RiskHost {
			return fmt.Errorf("capability %q requires a system plugin", cap)
		}
		if m.Type == TypeWorker && !workerCapabilities[cap] {
			return fmt.Errorf("capability %q is not available to worker plugins", cap)
		}
	}
	return nil
}

func VerifyManifest(m Manifest, artifact []byte, policy TrustPolicy) error {
	if err := ValidateManifest(m); err != nil {
		return err
	}
	requireSignature := manifestHasRisk(m, RiskHost) && !policy.AllowUnsignedHostRisk
	if m.DigestSHA256 != "" {
		if err := verifyDigest(m.DigestSHA256, artifact); err != nil {
			return err
		}
	}
	if !requireSignature && m.Publisher == "" && m.SignatureEd25519 == "" {
		return nil
	}
	if m.Publisher == "" {
		return errors.New("manifest signature requires publisher")
	}
	pub, ok := policy.TrustedPublishers[m.Publisher]
	if !ok {
		return fmt.Errorf("publisher %q is not trusted publisher", m.Publisher)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("trusted publisher %q has invalid ed25519 key", m.Publisher)
	}
	if m.DigestSHA256 == "" {
		return errors.New("manifest signature requires digest_sha256")
	}
	if err := verifyDigest(m.DigestSHA256, artifact); err != nil {
		return err
	}
	sig, err := decodeSignature(m.SignatureEd25519)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, SigningPayload(m), sig) {
		return errors.New("invalid signature")
	}
	return nil
}

func VerifyInstallManifest(manifestBytes, artifact []byte, policy TrustPolicy) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(manifestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := ensureNoTrailingJSON(dec); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := VerifyManifest(m, artifact, policy); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func ParseTrustPolicyJSON(data []byte) (TrustPolicy, error) {
	var in trustPolicyJSON
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return TrustPolicy{}, fmt.Errorf("decode trust policy: %w", err)
	}
	if err := ensureNoTrailingJSON(dec); err != nil {
		return TrustPolicy{}, fmt.Errorf("decode trust policy: %w", err)
	}
	policy := TrustPolicy{
		TrustedPublishers:     map[string]ed25519.PublicKey{},
		AllowUnsignedHostRisk: in.AllowUnsignedHostRisk,
	}
	for publisher, encoded := range in.TrustedPublishers {
		if !validPluginID(publisher) {
			return TrustPolicy{}, fmt.Errorf("invalid publisher %q", publisher)
		}
		key, err := decodePublicKey(encoded)
		if err != nil {
			return TrustPolicy{}, fmt.Errorf("invalid trusted publisher key for %q: %w", publisher, err)
		}
		policy.TrustedPublishers[publisher] = key
	}
	return policy, nil
}

func DigestSHA256(artifact []byte) string {
	sum := sha256.Sum256(artifact)
	return hex.EncodeToString(sum[:])
}

func SigningPayload(m Manifest) []byte {
	caps := append([]string(nil), m.Capabilities...)
	sort.Strings(caps)
	fields := []string{
		"lattice-plugin-manifest-v1",
		m.ID,
		m.Name,
		m.Type,
		m.Version,
		m.Entrypoint,
		m.Publisher,
		m.DigestSHA256,
		strings.Join(caps, "\x00"),
	}
	return []byte(strings.Join(fields, "\n"))
}

func verifyDigest(want string, artifact []byte) error {
	if len(want) != sha256.Size*2 {
		return fmt.Errorf("invalid digest_sha256 %q", want)
	}
	if _, err := hex.DecodeString(want); err != nil {
		return fmt.Errorf("invalid digest_sha256 %q", want)
	}
	got := DigestSHA256(artifact)
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("digest mismatch: got %s", got)
	}
	return nil
}

func decodeSignature(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("manifest signature requires signature_ed25519")
	}
	if sig, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		if len(sig) != ed25519.SignatureSize {
			return nil, errors.New("invalid ed25519 signature length")
		}
		return sig, nil
	}
	sig, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid signature_ed25519: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, errors.New("invalid ed25519 signature length")
	}
	return sig, nil
}

func decodePublicKey(value string) (ed25519.PublicKey, error) {
	key, err := decodeBytes(value)
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, errors.New("invalid ed25519 public key length")
	}
	return ed25519.PublicKey(key), nil
}

func decodeBytes(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if out, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return out, nil
	}
	if out, err := base64.StdEncoding.DecodeString(value); err == nil {
		return out, nil
	}
	out, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func ensureNoTrailingJSON(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("unexpected trailing json value")
}

func manifestHasRisk(m Manifest, risk string) bool {
	for _, cap := range m.Capabilities {
		if capabilityRisk[cap] == risk {
			return true
		}
	}
	return false
}

func validPluginID(value string) bool {
	if len(value) < 3 || len(value) > 128 {
		return false
	}
	if !isPluginIDAlphaNum(value[0]) || !isPluginIDAlphaNum(value[len(value)-1]) {
		return false
	}
	prevDot := false
	for i := 0; i < len(value); i++ {
		ch := value[i]
		switch {
		case isPluginIDAlphaNum(ch):
			prevDot = false
		case ch == '-':
			prevDot = false
		case ch == '.':
			if prevDot {
				return false
			}
			prevDot = true
		default:
			return false
		}
	}
	return true
}

func isPluginIDAlphaNum(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
}

func hasControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func CapabilityRisk(cap string) (string, bool) {
	risk, ok := capabilityRisk[cap]
	return risk, ok
}

func CapabilityList() []string {
	out := make([]string, 0, len(capabilityRisk))
	for cap := range capabilityRisk {
		out = append(out, cap)
	}
	sort.Strings(out)
	return out
}
