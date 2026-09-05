// Package sshguard renders the reviewable artifacts for one node's SSH
// hardening intent: an sshd drop-in, an independent nftables knock table, and
// an optional knockd sequence. It is deliberately dependency-free and never
// touches a host: the server renders text from validated state, the text goes
// through the existing approval gate, and the node agent runs the script the
// approved text produces.
//
// Why this does not lower into internal/netguard like every other firewall
// surface: the netguard compiler lowers its model into network.NFTPlan, and
// network.GenerateNFTPlan is a fixed template that emits exactly one
// `table inet lattice_guard` with one `chain input` at priority 0, whose only
// named set is wg_peers4. It has no expression for a second named set, for
// `flags timeout`, for a second table, or for a custom hook priority. Port
// knocking is built on all four.
//
// The independence is also a correctness requirement rather than tidiness. The
// knock allowlist has runtime-mutable membership: knockd adds an element every
// time someone knocks. lattice_guard is declarative and re-rendered whole from
// the model on every apply, so an allowlist living inside it would be wiped by
// any unrelated firewall change, disconnecting whoever had just knocked in.
package sshguard

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

const (
	// DropInPath is the only sshd file this package writes. Writing a drop-in
	// rather than editing sshd_config means a rollback is a file removal, and
	// an operator reading the host can see exactly which lines Lattice owns.
	//
	// The name sorts first on purpose. sshd takes the FIRST value it reads for
	// a keyword, and Include comes near the top of sshd_config, so a drop-in
	// that sorts earlier wins outright. At the old `60-` this file lost to the
	// two files nearly every cloud image ships: `50-cloud-init.conf`, which
	// carries whatever `ssh_pwauth` was set to and is rewritten whenever
	// cloud-init re-runs, and `50-redhat.conf`. Eighteen of this fleet's
	// thirty-three nodes have one of those declaring an auth keyword; today
	// they all happen to say `no`, which is the only reason the loss was
	// invisible. One provider image also ships
	// `00-permit-root-password-auth.conf`, which turns root password login
	// back on and beat the guard outright.
	//
	// A guard that can be silently overruled by a file the platform rewrites
	// is not a guard, so it goes first and the apply's effectiveness check
	// stays as the proof.
	DropInPath = "/etc/ssh/sshd_config.d/00-lattice-guard.conf"

	// LegacyDropInPath is where this package wrote before the ordering fix.
	// Every arm removes it, and every revert puts it back, so a node that was
	// hardened under the old name is migrated by the next apply rather than
	// left with two files that both claim to own the same settings.
	LegacyDropInPath = "/etc/ssh/sshd_config.d/60-lattice-guard.conf"

	// KnockTable is deliberately not lattice_guard. See the package comment.
	KnockTable = "lattice_knock"
	// KnockdSection and KnockdPreviousSection name the two stanzas knockd.conf
	// can carry: the sequence in force, and during a rotation the one being
	// retired. The confirm script removes the second by name.
	KnockdSection         = "openSSH"
	KnockdPreviousSection = "openSSH-previous"
	// KnockAllowedSet is where a knock opens the gate; KnockPreviousSet is
	// where the sequence being rotated out opens it. Two sets, not one, so
	// the confirm can tell which sequence admitted the operator.
	KnockAllowedSet  = "allowed"
	KnockPreviousSet = "allowed_previous"
	KnockNFTPath     = "/etc/lattice/sshguard/knock.nft"
	KnockdConf       = "/etc/knockd.conf"
	StateDir         = "/etc/lattice/sshguard"
	// RevertUnit is the transient timer that undoes an unconfirmed change. It
	// really does revert, so the name is accurate.
	RevertUnit = "lattice-sshguard-revert"

	// FirewallUnit restores the gate at boot after a confirm. It is a separate
	// name from RevertUnit because it does the opposite thing: an operator
	// reading `systemctl list-unit-files` on a confirmed node should not find
	// something called "revert" enabled and have to read its ExecStart to learn
	// that it actually reinstalls the firewall.
	FirewallUnit = "lattice-sshguard-firewall"

	// LegacyBootUnit is the name FirewallUnit shipped under before it was
	// separated from RevertUnit. Nodes confirmed under the old name still have
	// it enabled, so every path that installs or removes the boot unit also
	// removes this one; otherwise a re-armed node ends up with two units
	// loading the same ruleset and only one of them documented.
	LegacyBootUnit = "lattice-sshguard-revert-boot"

	// KnockHookPriority puts the knock chain ahead of the ordinary filter
	// chains so its verdict is reached first. It does NOT let an accepted
	// packet skip later chains in the same hook, which is why a node carrying
	// both this table and a policy-drop lattice_guard must open the management
	// port in both. Callers enforce that; this package only renders.
	KnockHookPriority = -10

	// MinConfirmWindowSec is the floor for the human confirmation window. The
	// window exists so an operator can prove they can still get in before the
	// change is made permanent, and a minute is not enough time to open a
	// terminal, knock, and log in.
	MinConfirmWindowSec = 120
	// MaxConfirmWindowSec caps how long a node can sit armed. The task runner
	// silently falls back to a 30s timeout when a task asks for more than ten
	// minutes, but the revert timer is a systemd transient unit that outlives
	// the task, so this bound is about exposure, not the runner.
	MaxConfirmWindowSec     = 3600
	DefaultConfirmWindowSec = 900

	// KnockSequenceLen is fixed rather than configurable. Two ports is a
	// guessable pair under a port scan; more than three adds latency to every
	// login for no meaningful entropy gain over 3 * 16 bits.
	KnockSequenceLen = 3

	knockPortMin = 20000
	knockPortMax = 60000
)

// Stage names the two halves of an apply. A profile reaches a host through
// StageArm, which makes every change and arms an automatic revert, and is made
// permanent by StageConfirm, which cancels it. Splitting them is the whole
// safety property: an operator who cannot get back in after StageArm does
// nothing, and the node returns to its previous state on its own.
type Stage string

const (
	StageArm     Stage = "arm"
	StageConfirm Stage = "confirm"
)

// Hardening is the sshd side of a profile. Every field maps to exactly one
// sshd_config keyword; there is no free-form passthrough, because a profile
// that can write arbitrary sshd directives is a profile that can lock a fleet
// out in ways this package cannot reason about.
type Hardening struct {
	// LoginGraceTimeSec is the single highest-value field here. The sshd
	// default is 120s, and brute-force clients hold that window open to
	// occupy connection slots; dropping it to ~20s removes the noise more
	// cheaply than any ban list.
	LoginGraceTimeSec int
	MaxAuthTries      int
	// MaxStartups is a raw "start:rate:full" triple because sshd's own syntax
	// is the clearest expression of it.
	MaxStartups          string
	PasswordAuth         bool
	KbdInteractiveAuth   bool
	PermitRootLogin      string
	X11Forwarding        bool
	AllowAgentForwarding bool
}

// DefaultHardening is what the one-click path applies. It is the configuration
// verified on gomami-hkg on 2026-08-20, not a guess.
func DefaultHardening() Hardening {
	return Hardening{
		LoginGraceTimeSec:    20,
		MaxAuthTries:         3,
		MaxStartups:          "100:30:200",
		PasswordAuth:         false,
		KbdInteractiveAuth:   false,
		PermitRootLogin:      "prohibit-password",
		X11Forwarding:        false,
		AllowAgentForwarding: false,
	}
}

// KnockPolicy describes the port sequence that opens the SSH port.
//
// The sequence is UDP and the package refuses anything else. This is not a
// preference: knocking a TCP port with no listener makes the kernel retransmit
// the SYN, and a packet capture on gomami-hkg showed nine retransmissions to a
// single port. By the time the second port's packet arrives, knockd's state
// machine has seen the same port repeatedly and never advances past stage one.
// One UDP datagram is one datagram.
type KnockPolicy struct {
	Ports         []int
	SeqTimeoutSec int
	// OpenFor is an nftables timeout literal such as "12h". Membership expires
	// on its own, which is why there is no close sequence: forgetting to close
	// the door is a failure mode this design does not have.
	OpenFor string

	// PreviousPorts is the sequence being rotated out, when this arm is a
	// rotation. It is rendered as a second knockd stanza that opens its own
	// nftables set, so the sequence the operator already holds keeps opening
	// the gate until the confirm approval retires it. Without this a rotation
	// cut over the moment knockd restarted, and an operator who could not
	// produce confirm evidence from a source the node sees had nothing but
	// the revert timer between him and a lockout.
	PreviousPorts []int
}

// Profile is one node's complete SSH guard intent.
type Profile struct {
	NodeID string
	Name   string

	// SSHPort is the port sshd will listen on in addition to 22. Zero means
	// the port is left alone and only the hardening and firewall apply.
	SSHPort int
	// KeepLegacyPort keeps sshd listening on 22. The default is true and the
	// reason is in RenderKnockRuleset: 22 is shrunk to the management sources
	// and knocked-open sources rather than closed, which removes the brute
	// force without removing a way in.
	KeepLegacyPort bool

	Hardening Hardening
	// Knock nil disables knocking entirely; the firewall then only shrinks the
	// ports to MgmtSources.
	Knock *KnockPolicy

	// GatePorts overrides what the gate covers.
	//
	// The escape hatch, and deliberately a small one. The ordinary path derives
	// the ports from what sshd reports, which is right for a normal host; this
	// exists for the ones that are not, without teaching the product about each
	// of them. Set it and the derivation is skipped entirely, including the
	// fallback to 22.
	GatePorts []int

	// ExistingSSHPorts are the ports sshd is observed listening on, from the
	// node's own report. The gate covers these rather than a guess: three
	// machines in this fleet run sshd on 3434, and a profile that gates 22 on
	// one of them protects nothing while reporting success.
	//
	// Empty means the node has not reported, and the profile falls back to 22
	// with a warning rather than silently gating the wrong thing.
	ExistingSSHPorts []int

	// MgmtSources are CIDRs that reach SSH without knocking, forever.
	MgmtSources []string

	// Address is the node's public address, used only to print a knock command
	// an operator can copy. It is reported by the agent, so it is validated as
	// an IP literal before it reaches the document and dropped if it is not
	// one: a plan is read by a human deciding whether to approve, and text a
	// peer chose has no business shaping it.
	Address string

	// OutOfBandFallback says the operator's fallback is a path that does not
	// use SSH at all, which on this fleet means the node's Lattice terminal.
	//
	// It exists because the obvious alternative turned out to be worse. An IP
	// allowlist looks like a safety net and is only as good as the address
	// staying put: the address written into the reference node's allowlist went
	// stale within hours of being written, and a node behind a proxy sees a
	// source that changes with the route. A fallback that silently expires is
	// more dangerous than no fallback, because nobody re-checks it.
	//
	// The Lattice terminal does not care where the operator is. It is verified
	// against the node's reported capability at plan time rather than trusted,
	// because a profile claiming a fallback that is switched off is exactly the
	// failure this field is supposed to prevent.
	OutOfBandFallback bool

	// KeyAccessObserved says the node's own sshd facts show a key path in
	// (see DerivePosture). The server sets it from the last reality report;
	// it is never taken from the request, because it decides whether the
	// arm gets a revert timer at all.
	KeyAccessObserved bool

	ConfirmWindowSec int
}

// Durable reports whether this profile's arm is permanent on its own, with no
// confirm and no automatic revert.
//
// The revert exists for one risk: the operator changes how the node is
// reached and cannot get back in. A hardening-only profile changes no path
// in or out (GatesFirewall is false and SSHPort is zero), and on a node whose
// sshd already shows a key path in, turning password authentication off takes
// nothing away from anyone holding that key. Arming a timer there produced
// the fleet's worst state: an arm that applied, a window nobody was watching,
// and a revert that undid a correct change and left the row red. The apply
// still verifies the key on the host before it skips the timer, so this is
// the plan's claim and the host's check together, never the plan alone.
//
// Anything that installs the knock firewall keeps the confirm-or-revert
// dance, because that is the genuine lockout risk. So does any change to the
// port sshd listens on, with or without 22 kept: the observed key says the
// holder can authenticate, not that the new port is reachable from outside.
// A security group, a NAT that forwards only 22, or a middlebox leaves sshd
// listening locally on a port nobody can get to, the script's own listen
// check passes, and a migration that dropped 22 has no way back. The confirm
// is how the operator proves the new path from where they actually sit.
func (p Profile) Durable() bool {
	return !p.GatesFirewall() && p.SSHPort == 0 && p.KeyAccessObserved
}

// GatesFirewall reports whether this profile installs an nftables gate at all.
//
// A profile with neither a management source nor a knock policy expresses
// "harden sshd, leave reachability alone", and that is the shape a fleet-wide
// rollout should use: it changes no path in or out, so it carries no lockout
// risk of any kind.
//
// Inferring it rather than taking a flag closes a hole rather than adding a
// feature. The combination used to render a chain whose only rule for the SSH
// port was `counter drop`, with no accept anywhere: a guaranteed, permanent
// lockout for anyone who confirmed it without testing first. Treating the same
// input as "no firewall" makes the dangerous configuration unreachable instead
// of merely refused.
func (p Profile) GatesFirewall() bool {
	return len(p.MgmtSources) > 0 || p.Knock != nil
}

// Validate refuses a profile that could strand its own operator. Every check
// here fails closed on purpose.
func (p Profile) Validate() error {
	if err := validateNodeID(p.NodeID); err != nil {
		return err
	}
	if p.SSHPort != 0 && (p.SSHPort < 1 || p.SSHPort > 65535) {
		return fmt.Errorf("ssh_port %d is out of range", p.SSHPort)
	}
	if p.SSHPort == 22 {
		return fmt.Errorf("ssh_port 22 is the legacy port; leave ssh_port unset to keep sshd on 22 only")
	}
	if err := p.Hardening.validate(); err != nil {
		return err
	}
	seen := make(map[string]bool, len(p.MgmtSources))
	for _, raw := range p.MgmtSources {
		norm, err := normalizeCIDR(raw)
		if err != nil {
			return fmt.Errorf("mgmt_source %q: %w", raw, err)
		}
		if seen[norm] {
			return fmt.Errorf("mgmt_source %q is listed twice", raw)
		}
		seen[norm] = true
	}
	for _, port := range p.GatePorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("gate_port %d is out of range", port)
		}
	}
	if p.Knock != nil {
		if len(p.MgmtSources) == 0 && !p.OutOfBandFallback {
			// Refusing rather than warning is deliberate. A knock-only profile
			// with no second path has one way in, and its failure mode (knockd
			// dead, sequence wrong, UDP dropped by a middlebox) is
			// unrecoverable without console access. The second path may be an
			// address allowlist or an out-of-band channel, but there has to be
			// one and the caller has to say which.
			return fmt.Errorf("a knock policy requires either a mgmt_source or an out-of-band fallback")
		}
		if err := p.Knock.validate(); err != nil {
			return err
		}
		// No ssh_port requirement. Knocking gates whatever ports the profile
		// gates, and for most of this fleet that is 22 exactly where it is.
		//
		// Requiring a move was a mistake with a sharp edge: a node reachable
		// only through a provider's port forward loses SSH the moment sshd
		// binds a port nobody forwards, and roughly a third of this fleet is
		// behind NAT. Gating the port that already works is both safer and the
		// larger share of the benefit, because it is the port the brute force
		// is using.
	}
	if p.ConfirmWindowSec != 0 {
		if p.ConfirmWindowSec < MinConfirmWindowSec || p.ConfirmWindowSec > MaxConfirmWindowSec {
			return fmt.Errorf("confirm_window_sec %d is outside [%d, %d]",
				p.ConfirmWindowSec, MinConfirmWindowSec, MaxConfirmWindowSec)
		}
	}
	return nil
}

func (h Hardening) validate() error {
	if h.LoginGraceTimeSec < 5 || h.LoginGraceTimeSec > 600 {
		return fmt.Errorf("login_grace_time %d is outside [5, 600]", h.LoginGraceTimeSec)
	}
	if h.MaxAuthTries < 1 || h.MaxAuthTries > 10 {
		return fmt.Errorf("max_auth_tries %d is outside [1, 10]", h.MaxAuthTries)
	}
	if err := validateMaxStartups(h.MaxStartups); err != nil {
		return err
	}
	switch h.PermitRootLogin {
	case "yes", "no", "prohibit-password", "forced-commands-only":
	default:
		return fmt.Errorf("permit_root_login %q is not an sshd value", h.PermitRootLogin)
	}
	return nil
}

func validateMaxStartups(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("max_startups is required")
	}
	parts := strings.Split(value, ":")
	if len(parts) != 1 && len(parts) != 3 {
		return fmt.Errorf("max_startups %q must be \"start\" or \"start:rate:full\"", value)
	}
	for _, part := range parts {
		n, err := parseUint(part)
		if err != nil || n > 100000 {
			return fmt.Errorf("max_startups %q has a non-numeric or oversized component", value)
		}
	}
	return nil
}

func (k KnockPolicy) validate() error {
	if err := validateKnockPorts(k.Ports); err != nil {
		return err
	}
	if len(k.PreviousPorts) > 0 {
		if err := validateKnockPorts(k.PreviousPorts); err != nil {
			return fmt.Errorf("previous %w", err)
		}
		if joinInts(k.PreviousPorts) == joinInts(k.Ports) {
			// Keeping a sequence alive beside itself is not a rotation, and a
			// plan that says it rotates while changing nothing is the kind of
			// document that gets approved without being read.
			return fmt.Errorf("previous knock sequence is the same as the new one; a rotation needs a fresh sequence")
		}
	}
	if k.SeqTimeoutSec < 3 || k.SeqTimeoutSec > 120 {
		return fmt.Errorf("knock seq_timeout %d is outside [3, 120]", k.SeqTimeoutSec)
	}
	if err := validateNFTTimeout(k.OpenFor); err != nil {
		return err
	}
	return nil
}

func validateKnockPorts(ports []int) error {
	if len(ports) != KnockSequenceLen {
		return fmt.Errorf("knock sequence must be exactly %d ports, got %d", KnockSequenceLen, len(ports))
	}
	seen := make(map[int]bool, len(ports))
	for _, port := range ports {
		if port < knockPortMin || port > knockPortMax {
			return fmt.Errorf("knock port %d is outside [%d, %d]", port, knockPortMin, knockPortMax)
		}
		if seen[port] {
			// A repeated port collapses the sequence: knockd would advance on
			// a single datagram sent twice, which is a shorter secret than it
			// looks.
			return fmt.Errorf("knock port %d appears twice in the sequence", port)
		}
		seen[port] = true
	}
	return nil
}

// validateNFTTimeout accepts the nftables timeout literals this package emits.
// It is a whitelist rather than a parser because the value is interpolated
// into a ruleset, and a permissive parser there is a ruleset injection.
func validateNFTTimeout(value string) error {
	switch strings.TrimSpace(value) {
	case "1h", "2h", "4h", "8h", "12h", "24h", "30m", "15m":
		return nil
	default:
		return fmt.Errorf("open_for %q is not one of the supported nftables timeouts", value)
	}
}

// NewKnockSequence draws a fresh sequence from crypto/rand.
//
// It is drawn rather than derived from the node id on purpose. A derived
// sequence is only as secret as the derivation, and the derivation lives in a
// repository; anyone who reads it and knows a node id knows that node's
// sequence. Drawn ports are stored with the profile and are secret the way a
// credential is.
func NewKnockSequence() ([]int, error) {
	ports := make([]int, 0, KnockSequenceLen)
	seen := make(map[int]bool, KnockSequenceLen)
	span := uint32(knockPortMax - knockPortMin + 1)
	for len(ports) < KnockSequenceLen {
		var buf [4]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return nil, fmt.Errorf("draw knock port: %w", err)
		}
		port := knockPortMin + int(binary.BigEndian.Uint32(buf[:])%span)
		if seen[port] {
			continue
		}
		seen[port] = true
		ports = append(ports, port)
	}
	return ports, nil
}

// nodeIDRe is a whitelist, not a blocklist, because node_id is interpolated
// into a comment line of both the sshd drop-in and the nftables ruleset. A
// node_id carrying a newline injects a directive into a config file that no
// reviewer asked for: "x\nPermitRootLogin yes" renders as a comment followed by
// a live sshd directive. Nothing legitimate needs a character outside this set.
var nodeIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func validateNodeID(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("node_id is required")
	}
	if !nodeIDRe.MatchString(value) {
		return fmt.Errorf("node_id %q must be 1 to 64 characters of letters, digits, dot, dash or underscore", value)
	}
	return nil
}

// SanitizeDisplayText strips anything that could add a line to a rendered
// document. Display strings such as a node's name come from other subsystems
// and are interpolated into the plan header, which the parser reads line by
// line; a newline there is a way to add a header key nobody reviewed.
//
// It sanitizes rather than rejects because a node name is cosmetic: refusing to
// plan because someone put a control character in a label would be a worse
// failure than showing the label with the character removed.
func SanitizeDisplayText(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case r == '`':
			// A backtick is fence syntax in the plan document. It has no place
			// in a label, and dropping it removes the whole class of "did this
			// text open a block" questions rather than answering them.
		case r < 0x20 || r == 0x7f:
			// drop other control characters entirely
		default:
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if len(out) > 120 {
		out = out[:120]
	}
	return out
}

// normalizeCIDR turns a bare address or a prefix into canonical prefix form so
// two spellings of one source cannot both sit in the allowlist.
func normalizeCIDR(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty")
	}
	if strings.Contains(raw, "/") {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return "", fmt.Errorf("not a CIDR")
		}
		return prefix.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return "", fmt.Errorf("not an address")
	}
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(addr, bits).String(), nil
}

// splitMgmtSources separates the allowlist by family, because nftables needs
// `ip saddr` and `ip6 saddr` in different rules.
func splitMgmtSources(sources []string) (v4 []string, v6 []string, err error) {
	for _, raw := range sources {
		norm, nErr := normalizeCIDR(raw)
		if nErr != nil {
			return nil, nil, fmt.Errorf("mgmt_source %q: %w", raw, nErr)
		}
		prefix, pErr := netip.ParsePrefix(norm)
		if pErr != nil {
			return nil, nil, fmt.Errorf("mgmt_source %q: %w", raw, pErr)
		}
		if prefix.Addr().Is4() {
			v4 = append(v4, norm)
		} else {
			v6 = append(v6, norm)
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6, nil
}

func parseUint(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("empty")
	}
	n := 0
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(r-'0')
		if n > 1<<30 {
			return 0, fmt.Errorf("overflow")
		}
	}
	return n, nil
}
