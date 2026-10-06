package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/notify"
)

// The control-plane witness plan.
//
// Lattice cannot report its own outage. The witness is `lattice-agent
// -witness` on one chosen node (lattice-node-agent internal/witness): it polls
// this server's public /readyz, or the health URL the operator set in its
// place, and, when that keeps failing while the node's own network works,
// pushes one message through the bark-server on that node's loopback
// interface. This file is the only way its unit, config and
// device key reach the node: an approved plan, never a hand edit (r1-critic
// X-8).
//
// The plan shows the config and the unit verbatim, the path of the key file
// and a SHA-256 prefix of the key, never the key. The key is read from a
// stored Bark channel when the approval is decided: approval refuses when the
// channel's key no longer matches the prefix the operator reviewed, and the
// apply script, rendered then, is the only place the key appears. Task
// scripts are encrypted at rest and task views expose only their digest and
// size, as for line-user credentials.
//
// The config document is the node agent's witness.Config, version 1. Its
// field names and bounds are a contract with that binary, which refuses
// unknown fields; witnessConfigDoc and validateWitnessConfig mirror it.

const (
	witnessPlugin          = "controlplane-witness"
	witnessConfigureAction = "witness-configure:v1"
	witnessRemoveAction    = "witness-remove:v1"
	// witnessCapability is what an agent with witness mode advertises in
	// hello capabilities and in -compat-json features.
	witnessCapability = "control-plane-witness-v1"

	witnessConfigPath = "/etc/lattice-witness/witness.json"
	witnessKeyPath    = "/etc/lattice-witness/bark-device-key"
	witnessConfigDir  = "/etc/lattice-witness"
	witnessBinaryDir  = "/usr/local/lib/lattice-witness"
	witnessBinaryPath = "/usr/local/lib/lattice-witness/lattice-agent"
	witnessUnitName   = "lattice-witness.service"
	witnessUnitPath   = "/etc/systemd/system/lattice-witness.service"
	witnessStateDir   = "/var/lib/lattice-witness"
	witnessStatePath  = "/var/lib/lattice-witness/status.json"

	// witnessConfigVersion is the agent's witness.ConfigVersion.
	witnessConfigVersion   = 1
	witnessDefaultInterval = 30
	witnessDefaultHold     = 180
	witnessDefaultRecover  = 60
	witnessDefaultLevel    = "critical"
	witnessDefaultGroup    = "lattice-witness"
	witnessMinInterval     = 15
	witnessMaxInterval     = 600
	witnessMaxHold         = 3600
	witnessMaxReferences   = 3

	// witnessKeyPrefixLen is how much of the key's SHA-256 the plan shows:
	// enough to tell two keys apart in review, far too little to matter.
	witnessKeyPrefixLen = 12

	witnessApplyTaskTimeoutSec = 120
)

// witnessDefaultReferences prove the node's own network by paths other than
// the control plane's. Hostnames on purpose: a node whose resolver is broken
// fails these as well as the control plane, and stays quiet, instead of
// reporting the control plane down.
var witnessDefaultReferences = []string{
	"https://www.cloudflare.com/cdn-cgi/trace",
	"https://www.apple.com/library/test/success.html",
}

// witnessBarkKeyRe is the shape the witness accepts for a device key.
var witnessBarkKeyRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)

func isWitnessApproval(a model.Approval) bool {
	return a.Plugin == witnessPlugin && (a.Action == witnessConfigureAction || a.Action == witnessRemoveAction)
}

// witnessConfigDoc is the node agent's witness.Config, field for field.
type witnessConfigDoc struct {
	Version           int      `json:"version"`
	NodeName          string   `json:"node_name"`
	HealthURL         string   `json:"health_url"`
	ReferenceURLs     []string `json:"reference_urls"`
	BarkURL           string   `json:"bark_url"`
	BarkDeviceKeyFile string   `json:"bark_device_key_file"`
	BarkGroup         string   `json:"bark_group,omitempty"`
	BarkLevel         string   `json:"bark_level,omitempty"`
	IntervalSeconds   int      `json:"interval_seconds,omitempty"`
	HoldSeconds       int      `json:"hold_seconds,omitempty"`
	RecoverSeconds    int      `json:"recover_seconds,omitempty"`
	StateFile         string   `json:"state_file,omitempty"`
}

// witnessPlanRequest is what the console sends. Everything but the node and
// the channel has a default.
type witnessPlanRequest struct {
	NodeID          string   `json:"node_id"`
	Remove          bool     `json:"remove,omitempty"`
	ChannelID       string   `json:"channel_id,omitempty"`
	BarkURL         string   `json:"bark_url,omitempty"`
	ReferenceURLs   []string `json:"reference_urls,omitempty"`
	BarkLevel       string   `json:"bark_level,omitempty"`
	IntervalSeconds int      `json:"interval_seconds,omitempty"`
	HoldSeconds     int      `json:"hold_seconds,omitempty"`
	RecoverSeconds  int      `json:"recover_seconds,omitempty"`
	// HealthURL replaces <public URL>/readyz when set: the same readiness
	// endpoint under another name, for a node that cannot reach the control
	// plane's own address (a CDN-proxied hostname whose vhost serves only
	// /readyz). checkWitnessHealthOverride holds it to that shape.
	HealthURL string `json:"health_url,omitempty"`
}

// witnessHealthURL is the control plane's readiness endpoint as any client
// reaches it: the public URL, never the agent's own (possibly private) path.
func (s *Server) witnessHealthURL() (string, error) {
	base := strings.TrimRight(strings.TrimSpace(s.publicURL), "/")
	if base == "" {
		return "", errors.New("this server has no public URL (LATTICE_PUBLIC_URL); the witness watches the control plane the way clients reach it, so set it first")
	}
	return base + "/readyz", nil
}

// checkWitnessHealthOverride is what an operator's health URL must be on top
// of checkWitnessWatchURL: https, the path /readyz exactly, and nothing else,
// so it can only ever name a readiness check, never an arbitrary page whose
// answer would read as "the control plane is up".
func checkWitnessHealthOverride(raw string) error {
	if err := checkWitnessWatchURL("health_url", raw); err != nil {
		return err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("health_url must be an absolute URL")
	}
	if u.Scheme != "https" {
		return errors.New("health_url must use https")
	}
	if u.EscapedPath() != "/readyz" {
		return errors.New("health_url must have the path /readyz and nothing more")
	}
	if strings.ContainsAny(raw, "?#") {
		return errors.New("health_url must not carry a query or a fragment")
	}
	return nil
}

// checkWitnessHealthAgainstServer holds a config whose health URL is not this
// server's own <public URL>/readyz to the override rules, at plan time and
// again when the plan is decided and applied. validateWitnessConfig keeps the
// references off the health URL's host; with an override the control plane
// has a second name, and a reference on its public host proves nothing about
// the node's own network either. A config that watches the default passes
// untouched, so a plan filed before the override existed decides as it did.
func (s *Server) checkWitnessHealthAgainstServer(doc witnessConfigDoc) error {
	derived, _ := s.witnessHealthURL()
	if doc.HealthURL == derived {
		return nil
	}
	if err := checkWitnessHealthOverride(doc.HealthURL); err != nil {
		return err
	}
	if derived == "" {
		return nil
	}
	for i, ref := range doc.ReferenceURLs {
		if witnessSameHost(ref, derived) {
			return fmt.Errorf("reference_urls[%d] is on the control plane's public host; a reference must prove the node's network by another path", i)
		}
	}
	return nil
}

// witnessHealthNote is the plan line under a health URL the operator set;
// empty when the witness watches the default, so such a plan renders exactly
// as it did before the override existed.
func witnessHealthNote(healthURL, derived string) string {
	switch {
	case healthURL == derived:
		return ""
	case derived == "":
		return "Set by the operator; this server has no public URL (LATTICE_PUBLIC_URL) to derive one from"
	default:
		return "Set by the operator, in place of " + witnessPlanLine(derived)
	}
}

// witnessConfigFromRequest fills defaults and validates the document exactly
// as the node will.
func witnessConfigFromRequest(req witnessPlanRequest, nodeName, healthURL string) (witnessConfigDoc, error) {
	refs := make([]string, 0, len(req.ReferenceURLs))
	for _, ref := range req.ReferenceURLs {
		if ref = strings.TrimSpace(ref); ref != "" {
			refs = append(refs, ref)
		}
	}
	if len(refs) == 0 {
		refs = slices.Clone(witnessDefaultReferences)
	}
	doc := witnessConfigDoc{
		Version:           witnessConfigVersion,
		NodeName:          nodeName,
		HealthURL:         healthURL,
		ReferenceURLs:     refs,
		BarkURL:           strings.TrimRight(strings.TrimSpace(req.BarkURL), "/"),
		BarkDeviceKeyFile: witnessKeyPath,
		BarkGroup:         witnessDefaultGroup,
		BarkLevel:         strings.TrimSpace(req.BarkLevel),
		IntervalSeconds:   req.IntervalSeconds,
		HoldSeconds:       req.HoldSeconds,
		RecoverSeconds:    req.RecoverSeconds,
		StateFile:         witnessStatePath,
	}
	if doc.BarkLevel == "" {
		doc.BarkLevel = witnessDefaultLevel
	}
	if doc.IntervalSeconds == 0 {
		doc.IntervalSeconds = witnessDefaultInterval
	}
	if doc.HoldSeconds == 0 {
		doc.HoldSeconds = max(witnessDefaultHold, 2*doc.IntervalSeconds)
	}
	if doc.RecoverSeconds == 0 {
		doc.RecoverSeconds = max(witnessDefaultRecover, doc.IntervalSeconds)
	}
	return doc, validateWitnessConfig(doc)
}

// validateWitnessConfig is the node agent's witness.Config.Validate.
func validateWitnessConfig(c witnessConfigDoc) error {
	if strings.TrimSpace(c.NodeName) == "" {
		return errors.New("node_name is required")
	}
	if err := checkWitnessWatchURL("health_url", c.HealthURL); err != nil {
		return err
	}
	if len(c.ReferenceURLs) == 0 || len(c.ReferenceURLs) > witnessMaxReferences {
		return fmt.Errorf("reference_urls needs 1 to %d URLs", witnessMaxReferences)
	}
	for i, ref := range c.ReferenceURLs {
		if err := checkWitnessWatchURL(fmt.Sprintf("reference_urls[%d]", i), ref); err != nil {
			return err
		}
		if witnessSameHost(ref, c.HealthURL) {
			return fmt.Errorf("reference_urls[%d] is on the control plane's host; a reference must prove the node's network by another path", i)
		}
	}
	if c.BarkURL == "" {
		return errors.New("bark_url is required: the bark-server on that node, on its loopback address (bark-server listens on 8080 unless its unit says otherwise)")
	}
	if err := checkWitnessLoopbackURL("bark_url", c.BarkURL); err != nil {
		return err
	}
	if !slices.Contains(notify.BarkLevels, c.BarkLevel) {
		return fmt.Errorf("bark_level must be one of %s", strings.Join(notify.BarkLevels, ", "))
	}
	if len(c.BarkGroup) > 64 || strings.ContainsAny(c.BarkGroup, "\r\n") {
		return errors.New("bark_group must be one line of at most 64 bytes")
	}
	if c.IntervalSeconds < witnessMinInterval || c.IntervalSeconds > witnessMaxInterval {
		return fmt.Errorf("interval_seconds must be between %d and %d", witnessMinInterval, witnessMaxInterval)
	}
	if c.HoldSeconds < 2*c.IntervalSeconds || c.HoldSeconds > witnessMaxHold {
		return fmt.Errorf("hold_seconds must be at least two intervals (%d) and at most %d", 2*c.IntervalSeconds, witnessMaxHold)
	}
	if c.RecoverSeconds < c.IntervalSeconds || c.RecoverSeconds > witnessMaxHold {
		return fmt.Errorf("recover_seconds must be at least one interval (%d) and at most %d", c.IntervalSeconds, witnessMaxHold)
	}
	return nil
}

func checkWitnessWatchURL(field, raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("%s must be an absolute URL", field)
	}
	if u.User != nil {
		return fmt.Errorf("%s must not carry credentials", field)
	}
	if strings.ContainsAny(raw, " \t\r\n") {
		return fmt.Errorf("%s must not contain spaces", field)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if witnessLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("%s must use https unless it is on loopback", field)
	default:
		return fmt.Errorf("%s must use https", field)
	}
}

func checkWitnessLoopbackURL(field, raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("%s must be an http or https URL", field)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s must be a bare base URL", field)
	}
	if !witnessLoopbackHost(u.Hostname()) {
		return fmt.Errorf("%s must be on that node's loopback interface (127.0.0.1, ::1 or localhost) so the device key never leaves the node", field)
	}
	return nil
}

func witnessLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func witnessSameHost(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	return errA == nil && errB == nil && strings.EqualFold(ua.Hostname(), ub.Hostname())
}

// renderWitnessConfig is the exact file the node reads. Its SHA-256 is what
// the witness reports back, so the console can tell the node runs what was
// approved.
func renderWitnessConfig(doc witnessConfigDoc) (string, error) {
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw) + "\n", nil
}

func witnessConfigSHA(config string) string {
	sum := sha256.Sum256([]byte(config))
	return hex.EncodeToString(sum[:])
}

// renderWitnessUnit is the systemd unit. The witness runs as root because
// its key file is root's; the sandbox narrows what root can do: a read-only
// system except its own state directory, no new privileges, IP and local
// sockets only.
func renderWitnessUnit() string {
	return `[Unit]
Description=Lattice control-plane witness
Documentation=https://github.com/LatticeNet/lattice-node-agent#control-plane-witness
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=` + witnessBinaryPath + ` -witness ` + witnessConfigPath + `
Restart=always
RestartSec=10
StateDirectory=lattice-witness
StateDirectoryMode=0755
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryMax=64M

[Install]
WantedBy=multi-user.target
`
}

// witnessKeyPrefix is the part of the key's SHA-256 a plan shows.
func witnessKeyPrefix(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:witnessKeyPrefixLen]
}

// witnessPlanLine strips control characters from a value printed on one plan
// line, so a node or channel name cannot add lines to the reviewed text.
func witnessPlanLine(v string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, v)
}

// Plan field keys, read back with approvalPlanField when the approval is
// decided.
const (
	witnessFieldChannelID = "device_key_channel_id"
	witnessFieldKeyPrefix = "device_key_sha256_prefix"
	witnessFieldConfigSHA = "config_sha256"
	witnessFileMarker     = "--- file "
	witnessEndMarker      = "--- end"
)

func renderWitnessConfigurePlan(node model.Node, doc witnessConfigDoc, config, unit string, channel model.NotifyChannel, keyPrefix, healthNote string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Control-plane witness: configure on %s (%s)\n\n", witnessPlanLine(node.Name), node.ID)
	fmt.Fprintf(&b, "The witness is `lattice-agent -witness`, its own process under\n%s on this node. Every %d s it asks:\n  %s\n", witnessUnitName, doc.IntervalSeconds, doc.HealthURL)
	if healthNote != "" {
		b.WriteString(healthNote + "\n")
	}
	fmt.Fprintf(&b, "After %d s of failures while a reference URL still answers, it pushes one\n", doc.HoldSeconds)
	fmt.Fprintf(&b, "Bark message (level %s) through the bark-server at %s,\n", doc.BarkLevel, doc.BarkURL)
	fmt.Fprintf(&b, "then one recovery once the control plane has answered for %d s.\n", doc.RecoverSeconds)
	b.WriteString("When the control plane and every reference fail together, the node's own\nnetwork is down and it pushes nothing. References:\n")
	for _, ref := range doc.ReferenceURLs {
		fmt.Fprintf(&b, "  %s\n", ref)
	}
	b.WriteString("It holds no node token, sends no fleet data, and reads nothing but its config\n")
	b.WriteString("and the key file. The agent relays its status file on the heartbeat.\n\n")
	fmt.Fprintf(&b, "%s: %s\n", witnessFieldChannelID, channel.ID)
	fmt.Fprintf(&b, "device_key_channel: %s (%s)\n", witnessPlanLine(notifyChannelLabel(channel)), channel.Kind)
	fmt.Fprintf(&b, "%s: %s\n", witnessFieldKeyPrefix, keyPrefix)
	fmt.Fprintf(&b, "device_key_file: %s (0600, root)\n", witnessKeyPath)
	fmt.Fprintf(&b, "%s: %s\n\n", witnessFieldConfigSHA, witnessConfigSHA(config))
	b.WriteString("The key is not in this plan. Approving re-reads the channel above and refuses\n")
	b.WriteString("when its key no longer matches that prefix; the apply task writes the key to\n")
	b.WriteString("the file and never prints it.\n\n")
	b.WriteString("Steps on the node:\n")
	fmt.Fprintf(&b, "1. Refuse unless systemd runs and the agent binary lists\n   %s in -compat-json.\n", witnessCapability)
	fmt.Fprintf(&b, "2. Copy that binary to %s (0755), so an\n   agent update or rollback never changes the witness; only a new plan does.\n", witnessBinaryPath)
	fmt.Fprintf(&b, "3. Write the key file, then the config below to %s (0600).\n", witnessConfigPath)
	b.WriteString("4. Run the copy with -witness-check on that config; stop if it fails.\n")
	fmt.Fprintf(&b, "5. Write the unit below, daemon-reload, enable and restart %s,\n   and require it active.\n\n", witnessUnitName)
	fmt.Fprintf(&b, "%s%s\n%s", witnessFileMarker, witnessConfigPath, config)
	fmt.Fprintf(&b, "%s%s\n%s", witnessFileMarker, witnessUnitPath, unit)
	b.WriteString(witnessEndMarker + "\n")
	return b.String()
}

func renderWitnessRemovePlan(node model.Node) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Control-plane witness: remove from %s (%s)\n\n", witnessPlanLine(node.Name), node.ID)
	b.WriteString("Afterwards nothing outside the control plane watches it from this node.\n\n")
	b.WriteString("Steps on the node:\n")
	fmt.Fprintf(&b, "1. Stop and disable %s if it exists.\n", witnessUnitName)
	fmt.Fprintf(&b, "2. Remove %s and daemon-reload.\n", witnessUnitPath)
	fmt.Fprintf(&b, "3. Remove %s (config and device key) and %s.\n", witnessConfigDir, witnessBinaryDir)
	fmt.Fprintf(&b, "4. Remove %s, so the agent stops relaying a witness status.\n", witnessStateDir)
	return b.String()
}

// witnessPlanFiles reads the verbatim files back out of a configure plan.
func witnessPlanFiles(plan string) (config, unit string, err error) {
	files := map[string]string{}
	rest := plan
	for {
		i := strings.Index(rest, "\n"+witnessFileMarker)
		if i < 0 {
			break
		}
		rest = rest[i+1+len(witnessFileMarker):]
		path, body, ok := strings.Cut(rest, "\n")
		if !ok {
			return "", "", errors.New("witness plan: a file has no content")
		}
		end := strings.Index(body, "\n"+witnessFileMarker)
		if end < 0 {
			end = strings.Index(body, "\n"+witnessEndMarker+"\n")
		}
		if end < 0 {
			return "", "", errors.New("witness plan: a file is not terminated")
		}
		files[path] = body[:end+1]
		rest = body[end:]
	}
	config, unit = files[witnessConfigPath], files[witnessUnitPath]
	if config == "" || unit == "" || len(files) != 2 {
		return "", "", errors.New("witness plan: expected exactly the config and the unit")
	}
	return config, unit, nil
}

// witnessApprovalKey re-reads the channel a configure plan names and returns
// its key, or why the plan is stale.
func (s *Server) witnessApprovalKey(a model.Approval) (string, error) {
	channelID := approvalPlanField(a.Plan, witnessFieldChannelID)
	prefix := approvalPlanField(a.Plan, witnessFieldKeyPrefix)
	if channelID == "" || prefix == "" {
		return "", errors.New("witness plan names no device key channel; re-plan")
	}
	channel, ok := s.notifyChannelByID(channelID)
	if !ok {
		return "", fmt.Errorf("notification channel %s no longer exists; re-plan the witness", channelID)
	}
	if channel.Kind != "bark" {
		return "", fmt.Errorf("notification channel %s is no longer a Bark channel; re-plan the witness", channelID)
	}
	key := strings.TrimSpace(channel.Config["key"])
	if !witnessBarkKeyRe.MatchString(key) {
		return "", fmt.Errorf("notification channel %s has no usable Bark device key; re-plan the witness", channelID)
	}
	if witnessKeyPrefix(key) != prefix {
		return "", fmt.Errorf("the device key of channel %s changed since this plan was made; re-plan the witness so the new key is reviewed", channelID)
	}
	return key, nil
}

// witnessConfigureFiles reads a configure plan's files back and checks them
// as strictly as when the plan was made: the unit must be the one this server
// renders, the config must be a valid witness config in exactly the form this
// server renders, with the key file and state file the scripts expect, a
// health URL other than the default must still meet the override rules, and
// its SHA-256 must be the one the plan's header shows the reviewer. Only
// handleWitnessPlan files these approvals today, so this is defence in depth:
// the unit runs as root, and the header and the files must not be able to
// say different things.
func (s *Server) witnessConfigureFiles(a model.Approval) (config, unit string, err error) {
	config, unit, err = witnessPlanFiles(a.Plan)
	if err != nil {
		return "", "", err
	}
	if unit != renderWitnessUnit() {
		return "", "", errors.New("witness plan: the unit is not the one this server writes; re-plan the witness")
	}
	var doc witnessConfigDoc
	if err := json.Unmarshal([]byte(config), &doc); err != nil {
		return "", "", fmt.Errorf("witness plan: the config does not parse: %w", err)
	}
	if rendered, err := renderWitnessConfig(doc); err != nil || rendered != config {
		return "", "", errors.New("witness plan: the config is not in the form this server writes; re-plan the witness")
	}
	if doc.Version != witnessConfigVersion || doc.BarkDeviceKeyFile != witnessKeyPath || doc.StateFile != witnessStatePath {
		return "", "", errors.New("witness plan: the config names another version, key file or state file than the scripts write; re-plan the witness")
	}
	if err := validateWitnessConfig(doc); err != nil {
		return "", "", fmt.Errorf("witness plan: %w", err)
	}
	if err := s.checkWitnessHealthAgainstServer(doc); err != nil {
		return "", "", fmt.Errorf("witness plan: %w; re-plan the witness", err)
	}
	if want := approvalPlanField(a.Plan, witnessFieldConfigSHA); want != witnessConfigSHA(config) {
		return "", "", errors.New("witness plan: the config's SHA-256 is not the one the plan shows; re-plan the witness")
	}
	return config, unit, nil
}

// requireCurrentWitnessApproval runs when the approval is decided: a
// configure plan's files must check out and its key must still be the one
// the operator reviewed.
func (s *Server) requireCurrentWitnessApproval(a model.Approval) error {
	if a.Action != witnessConfigureAction {
		return nil
	}
	if _, _, err := s.witnessConfigureFiles(a); err != nil {
		return err
	}
	_, err := s.witnessApprovalKey(a)
	return err
}

// witnessApplyScript renders the task for an approved witness plan.
func (s *Server) witnessApplyScript(a model.Approval) (string, error) {
	switch a.Action {
	case witnessRemoveAction:
		return witnessRemoveScript(), nil
	case witnessConfigureAction:
	default:
		return "", fmt.Errorf("unknown witness action %q", a.Action)
	}
	config, unit, err := s.witnessConfigureFiles(a)
	if err != nil {
		return "", err
	}
	key, err := s.witnessApprovalKey(a)
	if err != nil {
		return "", err
	}
	return witnessConfigureScript(config, unit, key), nil
}

func witnessConfigureScript(config, unit, key string) string {
	var b strings.Builder
	b.WriteString("set -eu\n")
	b.WriteString("export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n")
	b.WriteString("umask 077\n")
	b.WriteString("fail() { echo \"lattice witness: $*\" >&2; exit 1; }\n")
	b.WriteString("command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || fail 'systemd is required'\n")
	b.WriteString("SRC=\"${LATTICE_AGENT_BIN:-}\"\n")
	b.WriteString("case \"$SRC\" in /*) ;; *) fail 'the agent did not name its binary (LATTICE_AGENT_BIN)';; esac\n")
	fmt.Fprintf(&b, "\"$SRC\" -compat-json 2>/dev/null | grep -q '\"%s\"' || fail 'this agent has no witness mode; update the agent first'\n", witnessCapability)
	fmt.Fprintf(&b, "install -d -m 0755 %s\n", witnessBinaryDir)
	fmt.Fprintf(&b, "install -d -m 0700 %s\n", witnessConfigDir)
	fmt.Fprintf(&b, "cp \"$SRC\" %s.new\n", witnessBinaryPath)
	fmt.Fprintf(&b, "chmod 0755 %s.new\n", witnessBinaryPath)
	fmt.Fprintf(&b, "mv -f %s.new %s\n", witnessBinaryPath, witnessBinaryPath)
	// The key goes through a heredoc into a 0600 file and is never echoed.
	b.WriteString(heredocWrite(witnessKeyPath+".new", "LATTICE_WITNESS_KEY_EOF", key))
	fmt.Fprintf(&b, "chmod 0600 %s.new\n", witnessKeyPath)
	fmt.Fprintf(&b, "mv -f %s.new %s\n", witnessKeyPath, witnessKeyPath)
	b.WriteString(heredocWrite(witnessConfigPath+".new", "LATTICE_WITNESS_CONFIG_EOF", config))
	fmt.Fprintf(&b, "chmod 0600 %s.new\n", witnessConfigPath)
	fmt.Fprintf(&b, "%s -witness %s.new -witness-check >/dev/null || fail 'the witness refused its config or key file'\n", witnessBinaryPath, witnessConfigPath)
	fmt.Fprintf(&b, "mv -f %s.new %s\n", witnessConfigPath, witnessConfigPath)
	b.WriteString(heredocWrite(witnessUnitPath+".new", "LATTICE_WITNESS_UNIT_EOF", unit))
	fmt.Fprintf(&b, "chmod 0644 %s.new\n", witnessUnitPath)
	fmt.Fprintf(&b, "mv -f %s.new %s\n", witnessUnitPath, witnessUnitPath)
	b.WriteString("systemctl daemon-reload\n")
	fmt.Fprintf(&b, "systemctl enable %s >/dev/null 2>&1\n", witnessUnitName)
	fmt.Fprintf(&b, "systemctl restart %s\n", witnessUnitName)
	b.WriteString("sleep 3\n")
	fmt.Fprintf(&b, "if ! systemctl is-active --quiet %s; then\n", witnessUnitName)
	fmt.Fprintf(&b, "  journalctl -u %s -n 20 --no-pager >&2 || true\n", witnessUnitName)
	b.WriteString("  fail 'the unit is not active'\n")
	b.WriteString("fi\n")
	fmt.Fprintf(&b, "echo 'lattice witness: active, config sha256 %s'\n", witnessConfigSHA(config))
	return b.String()
}

func witnessRemoveScript() string {
	var b strings.Builder
	b.WriteString("set -eu\n")
	b.WriteString("export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n")
	b.WriteString("if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then\n")
	fmt.Fprintf(&b, "  systemctl disable --now %s >/dev/null 2>&1 || true\n", witnessUnitName)
	fmt.Fprintf(&b, "  rm -f %s\n", witnessUnitPath)
	b.WriteString("  systemctl daemon-reload\n")
	b.WriteString("else\n")
	fmt.Fprintf(&b, "  rm -f %s\n", witnessUnitPath)
	b.WriteString("fi\n")
	fmt.Fprintf(&b, "rm -rf %s %s %s\n", witnessConfigDir, witnessBinaryDir, witnessStateDir)
	b.WriteString("echo 'lattice witness: removed'\n")
	return b.String()
}

// handleWitnessPlan files a witness approval for one node.
//
// Authoring needs notify:admin unconfined, because the plan hands a stored
// channel's credential to a node, plus node:admin and network:plan on that
// node, because it installs a unit there. Deciding needs notify:admin as well
// (approvalDecisionExtraScope), and reading the plan needs it
// (approvalPrimaryScopeAllows).
func (s *Server) handleWitnessPlan(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if s.refuseConfinedFleetWrite(w, p, "notify.witness.plan", "notify:admin") {
		return
	}
	var req witnessPlanRequest
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.NodeID = strings.TrimSpace(req.NodeID)
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	if !s.requireNodeScope(w, p, "node:admin", req.NodeID) || !s.requireNodeScope(w, p, "network:plan", req.NodeID) {
		return
	}
	node, ok := s.store.Node(req.NodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	if !s.requireNodeCapability(w, req.NodeID, witnessPlugin) {
		return
	}
	approval := model.Approval{
		ID:        id.New("approval"),
		NodeID:    node.ID,
		Plugin:    witnessPlugin,
		Status:    model.ApprovalPending,
		ActorID:   p.ActorID,
		CreatedAt: time.Now().UTC(),
	}
	metadata := map[string]string{"node_id": node.ID}
	if req.Remove {
		approval.Action = witnessRemoveAction
		approval.Plan = renderWitnessRemovePlan(node)
		metadata["action"] = "remove"
	} else {
		// Refused before an approval exists: a node whose agent cannot run
		// the witness would only fail the task after someone approved it.
		if !s.agentHasCapability(node.ID, witnessCapability) {
			writeError(w, http.StatusConflict, fmt.Errorf("%s has not advertised %s; update its agent to a release with witness mode and let it heartbeat first", witnessPlanLine(node.Name), witnessCapability))
			return
		}
		// The default is <public URL>/readyz; an operator's health URL
		// replaces it and needs no public URL of its own.
		derived, derivedErr := s.witnessHealthURL()
		healthURL := strings.TrimSpace(req.HealthURL)
		if healthURL == "" {
			if derivedErr != nil {
				writeError(w, http.StatusConflict, derivedErr)
				return
			}
			healthURL = derived
		} else if err := checkWitnessHealthOverride(healthURL); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		channel, ok := s.notifyChannelByID(strings.TrimSpace(req.ChannelID))
		if !ok {
			writeError(w, http.StatusBadRequest, errors.New("channel_id must name a stored Bark channel; its device key is what the witness pushes to"))
			return
		}
		if channel.Kind != "bark" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("channel %q is a %s channel; the witness pushes through a Bark server, so pick a Bark channel", notifyChannelLabel(channel), channel.Kind))
			return
		}
		key := strings.TrimSpace(channel.Config["key"])
		if !witnessBarkKeyRe.MatchString(key) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("channel %q has no device key in the shape the witness accepts (8 to 128 letters, digits, _ or -)", notifyChannelLabel(channel)))
			return
		}
		doc, err := witnessConfigFromRequest(req, node.Name, healthURL)
		if err == nil {
			err = s.checkWitnessHealthAgainstServer(doc)
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		config, err := renderWitnessConfig(doc)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		approval.Action = witnessConfigureAction
		healthNote := witnessHealthNote(doc.HealthURL, derived)
		approval.Plan = renderWitnessConfigurePlan(node, doc, config, renderWitnessUnit(), channel, witnessKeyPrefix(key), healthNote)
		metadata["action"] = "configure"
		metadata["channel_id"] = channel.ID
		metadata["config_sha256"] = witnessConfigSHA(config)
		if healthNote != "" {
			metadata["health_url"] = doc.HealthURL
		}
	}
	approval, err := s.submitApproval(r.Context(), approval)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	metadata["approval_id"] = approval.ID
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), NodeID: node.ID, Action: "notify.witness.plan", Scope: "notify:admin,network:plan", Metadata: metadata,
	})
	writeJSON(w, http.StatusOK, map[string]any{"approval": toApprovalView(approval)})
}

// handleWitnessTaskResult moves a witness approval to applied or rejected
// when its task reports.
func (s *Server) handleWitnessTaskResult(r *http.Request, approval model.Approval, task model.Task, result model.TaskResult) error {
	stage := "configure"
	if approval.Action == witnessRemoveAction {
		stage = "remove"
	}
	metadata := map[string]string{
		"approval_id": approval.ID,
		"task_id":     task.ID,
		"stage":       stage,
		"plan_sha":    approvalPlanSHA(approval),
	}
	if sha := approvalPlanField(approval.Plan, witnessFieldConfigSHA); sha != "" {
		metadata["config_sha256"] = sha
	}
	if result.Error == "" && result.ExitCode == 0 {
		approval.Status = model.ApprovalApplied
		approval.Reason = ""
		approval.UpdatedAt = time.Now().UTC()
		if err := s.store.UpsertApproval(approval); err != nil {
			return fmt.Errorf("mark witness approval applied: %w", err)
		}
		s.recordRequestAudit(r, model.AuditEvent{
			ID: id.New("audit"), NodeID: approval.NodeID, Action: "notify.witness." + stage + ".applied", Decision: "allow", Metadata: metadata,
		})
		return nil
	}
	reason := taskFailureSummary(result)
	if err := s.rejectApprovalWithReason(approval, reason); err != nil {
		return fmt.Errorf("mark witness approval rejected: %w", err)
	}
	s.recordRequestAudit(r, model.AuditEvent{
		ID: id.New("audit"), NodeID: approval.NodeID, Action: "notify.witness." + stage + ".failed", Decision: "deny", Reason: reason, Metadata: metadata,
	})
	return nil
}

// witnessDisplayReason is the one-line title of a witness approval.
func witnessDisplayReason(a model.Approval) string {
	if a.Action == witnessRemoveAction {
		return "Remove the control-plane witness"
	}
	if channel := approvalPlanField(a.Plan, "device_key_channel"); channel != "" {
		return "Set up the control-plane witness, pushing to " + channel
	}
	return "Set up the control-plane witness"
}
