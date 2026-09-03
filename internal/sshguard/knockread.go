package sshguard

import (
	"fmt"
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
	seqLine, ok := knockdValue(conf, "sequence")
	if !ok {
		return KnockSequence{}, fmt.Errorf("knockd conf has no sequence")
	}
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
			return KnockSequence{}, fmt.Errorf("knock sequence entry %q has no protocol", part)
		}
		if !strings.EqualFold(strings.TrimSpace(proto), "udp") {
			return KnockSequence{}, fmt.Errorf("knock sequence entry %q is not udp", part)
		}
		n, err := strconv.Atoi(strings.TrimSpace(port))
		if err != nil {
			return KnockSequence{}, fmt.Errorf("knock sequence entry %q has no port: %w", part, err)
		}
		if n < 1 || n > 65535 {
			return KnockSequence{}, fmt.Errorf("knock sequence port %d is out of range", n)
		}
		out.Ports = append(out.Ports, n)
	}
	if len(out.Ports) != KnockSequenceLen {
		return KnockSequence{}, fmt.Errorf("knock sequence must be exactly %d ports, got %d", KnockSequenceLen, len(out.Ports))
	}
	if v, ok := knockdValue(conf, "seq_timeout"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return KnockSequence{}, fmt.Errorf("knockd seq_timeout %q is not a number: %w", v, err)
		}
		out.SeqTimeoutSec = n
	}
	// OpenFor is not its own key. It is the set timeout inside start_command,
	// which is where the renderer puts it, so it is read from there rather
	// than guessed from the default.
	if cmd, ok := knockdValue(conf, "start_command"); ok {
		if _, after, found := strings.Cut(cmd, "timeout "); found {
			out.OpenFor = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(after), "}"))
		}
	}
	return out, nil
}

// knockdValue pulls one "key = value" out of a knockd conf, ignoring comments.
//
// Comment stripping matters more than it looks: RenderKnockdConf writes a
// comment above the sequence explaining why the knock is UDP, and a naive
// substring match finds the word there first and reads the wrong line.
func knockdValue(conf, key string) (string, bool) {
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
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

// KnockCommand renders the shell an operator runs to open the port.
//
// It is the same command the arm plan prints, kept in one place so the console
// and the plan cannot disagree about how to knock. The payload byte is not
// decoration: an empty datagram advances knockd to stage one and no further,
// so `nc -u -z` looks like it worked and leaves the port shut.
func (k KnockSequence) KnockCommand(address string, sshPort int) string {
	addr := strings.TrimSpace(address)
	if addr == "" {
		addr = "HOST"
	}
	ports := make([]string, 0, len(k.Ports))
	for _, port := range k.Ports {
		ports = append(ports, strconv.Itoa(port))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "for p in %s; do printf k | nc -u -w1 %s $p; sleep 1; done", strings.Join(ports, " "), addr)
	if sshPort > 0 {
		fmt.Fprintf(&b, "\nssh -p %d root@%s", sshPort, addr)
	}
	return b.String()
}
