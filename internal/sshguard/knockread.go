package sshguard

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Reading a knock sequence back out of an approval plan.
//
// There is no knock store. The sequence is drawn from crypto/rand at plan time
// (NewKnockSequence), rendered into the knockd.conf that the arm plan carries,
// and then forgotten by the process that drew it. The plan document is the only
// place the control plane keeps it, which is the same document ApplyScriptFromPlan
// parses to build the script that writes the file. So reading the plan back is
// not a workaround: it is reading the same authority the host was configured from.
//
// This lives beside the renderer on purpose. A parser that drifts from
// RenderKnockdConf would report a sequence the node does not have, and being
// confidently wrong about how to reach a machine is worse than saying nothing.

// KnockSequence is what a rendered knockd.conf says about how to open the port.
type KnockSequence struct {
	Ports         []int
	SeqTimeoutSec int
	// OpenFor is the nftables set timeout the knock installs, as written
	// (for example "12h"). Empty when the start_command does not carry one.
	OpenFor string
	// PreviousPorts is the sequence a rotation kept alive beside Ports. It is
	// on the node only until the confirm retires the stanza, so a reader has
	// to pair it with whether the arm was confirmed.
	PreviousPorts []int
}

// ParseKnockdConf reads the sequence back out of a knockd.conf rendered by
// RenderKnockdConf.
//
// It is strict in the same way ParseApprovalPlan is strict. A conf whose
// sequence line is missing, malformed, not UDP, or the wrong length is an
// error rather than a partial answer, because a partial answer here is a
// sequence an operator would knock and then be unable to explain the failure of.
func ParseKnockdConf(conf string) (KnockSequence, error) {
	out := KnockSequence{}
	seqLine, ok := knockdValue(conf, KnockdSection, "sequence")
	if !ok {
		return KnockSequence{}, fmt.Errorf("knockd conf has no sequence")
	}
	ports, err := parseUDPSequence(seqLine)
	if err != nil {
		return KnockSequence{}, err
	}
	out.Ports = ports
	if v, ok := knockdValue(conf, KnockdSection, "seq_timeout"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return KnockSequence{}, fmt.Errorf("knockd seq_timeout %q is not a number: %w", v, err)
		}
		out.SeqTimeoutSec = n
	}
	// OpenFor is not its own key. It is the set timeout inside start_command,
	// which is where the renderer puts it, so it is read from there rather
	// than guessed from the default.
	if cmd, ok := knockdValue(conf, KnockdSection, "start_command"); ok {
		if _, after, found := strings.Cut(cmd, "timeout "); found {
			out.OpenFor = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(after), "}"))
		}
	}
	// The stanza a rotation keeps for the sequence being retired. Read with
	// the same strictness: a previous sequence this code cannot trust is
	// worse than none, because it is the one the operator is relying on.
	if prev, ok := knockdValue(conf, KnockdPreviousSection, "sequence"); ok {
		ports, err := parseUDPSequence(prev)
		if err != nil {
			return KnockSequence{}, fmt.Errorf("previous %w", err)
		}
		out.PreviousPorts = ports
	}
	return out, nil
}

func parseUDPSequence(seqLine string) ([]int, error) {
	ports := []int{}
	for _, part := range strings.Split(seqLine, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// RenderKnockdConf always writes "<port>:udp". A conf that lost the
		// protocol, or carries tcp, did not come from this renderer and the
		// ports in it cannot be trusted to be the ones knockd is watching.
		port, proto, found := strings.Cut(part, ":")
		if !found {
			return nil, fmt.Errorf("knock sequence entry %q has no protocol", part)
		}
		if !strings.EqualFold(strings.TrimSpace(proto), "udp") {
			return nil, fmt.Errorf("knock sequence entry %q is not udp", part)
		}
		n, err := strconv.Atoi(strings.TrimSpace(port))
		if err != nil {
			return nil, fmt.Errorf("knock sequence entry %q has no port: %w", part, err)
		}
		if n < 1 || n > 65535 {
			return nil, fmt.Errorf("knock sequence port %d is out of range", n)
		}
		ports = append(ports, n)
	}
	if len(ports) != KnockSequenceLen {
		return nil, fmt.Errorf("knock sequence must be exactly %d ports, got %d", KnockSequenceLen, len(ports))
	}
	return ports, nil
}

// knockdValue pulls one "key = value" out of one [section] of a knockd conf,
// ignoring comments.
//
// Section-aware because a rotation renders two stanzas with the same keys, and
// the first "sequence" in the file is the answer only by accident of order.
// Comment stripping matters more than it looks: RenderKnockdConf writes a
// comment above the sequence explaining why the knock is UDP, and a naive
// substring match finds the word there first and reads the wrong line.
func knockdValue(conf, section, key string) (string, bool) {
	inSection := false
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inSection = line == "["+section+"]"
			continue
		}
		if !inSection {
			continue
		}
		name, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		if strings.TrimSpace(name) != key {
			continue
		}
		return strings.TrimSpace(value), true
	}
	return "", false
}

// KnockSequenceDigest is the sha256 of a sequence in its canonical "p1,p2,p3"
// form. It lets a plan request name the sequence it rotates from without
// carrying the ports: the reveal hands the digest over with the ports, the
// rotation request hands it back, and the server refuses to rotate from a
// sequence other than the one it holds as installed. It is not a secret
// substitute: three ports in a 40000-wide range are brute-forceable from the
// digest, so it is returned only where the ports themselves already are.
func KnockSequenceDigest(ports []int) string {
	sum := sha256.Sum256([]byte(joinInts(ports)))
	return hex.EncodeToString(sum[:])
}

// KnockInstall is how to get the knock client on one platform.
type KnockInstall struct {
	Platform string `json:"platform"`
	Command  string `json:"command"`
}

// KnockCommand is one way to open the gate and log in.
type KnockCommand struct {
	// ID is what a client keys on: "knock" for the packaged client, "bash"
	// for the form that needs nothing installed.
	ID string `json:"id"`
	// Install lists how to get the tool the command runs. Empty when the
	// command needs only bash.
	Install []KnockInstall `json:"install,omitempty"`
	// Command is one line: the knock, then ssh, joined by && so a knock that
	// could not run does not fall through to a login that hangs on a shut port.
	Command string `json:"command"`
}

// knockAddressPlaceholder stands in for an address the node did not report,
// or reported as something other than an IP literal. Pasted into a shell it is
// a redirection error, so an incomplete command fails before it sends anything.
const knockAddressPlaceholder = "<node-address>"

// knockAddress returns the address a command may carry. The value comes from
// the node's own report and ends up in text a person pastes into a shell, so
// it is accepted only if it parses as an IP literal.
func knockAddress(raw string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return knockAddressPlaceholder
	}
	return a.String()
}

// KnockCommands renders the ways an operator opens the port and logs in.
//
// They are the commands the arm plan prints, kept in one place so the console
// and the plan cannot disagree about how to knock. The first is the knock
// client from the knockd package: -u sends every hit as UDP, which is all the
// gate listens for, and -d 500 spaces the hits so they still arrive in order
// through a proxy. The second needs nothing but bash, whose /dev/udp
// redirection sends the byte printf writes. Both carry a payload (the client
// sends one byte per hit), and that is not decoration: an empty datagram
// advances knockd to stage one and no further, so `nc -u -z` looks like it
// worked and leaves the port shut.
//
// -4 is left off on purpose. knock 0.7, still what Ubuntu 22.04 ships, does
// not know the flag, and the address is already a literal.
func (k KnockSequence) KnockCommands(address string, sshPort int) []KnockCommand {
	addr := knockAddress(address)
	ports := make([]string, 0, len(k.Ports))
	for _, port := range k.Ports {
		ports = append(ports, strconv.Itoa(port))
	}
	seq := strings.Join(ports, " ")
	login := ""
	if sshPort > 0 {
		login = fmt.Sprintf(" && ssh -p %d root@%s", sshPort, addr)
	}
	return []KnockCommand{
		{
			ID: "knock",
			Install: []KnockInstall{
				{Platform: "macOS", Command: "brew install knock"},
				{Platform: "Debian, Ubuntu", Command: "sudo apt install knockd"},
				{Platform: "Fedora", Command: "sudo dnf install knock"},
			},
			Command: fmt.Sprintf("knock -u -d 500 %s %s%s", addr, seq, login),
		},
		{
			ID:      "bash",
			Command: fmt.Sprintf("bash -c 'for p in %s; do printf k >/dev/udp/%s/$p; sleep 0.5; done'%s", seq, addr, login),
		},
	}
}
