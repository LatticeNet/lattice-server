package sshguard

import "strings"

// Posture is what a node's own sshd says about who can log in. It is derived
// from the facts the agent reports (`sshd -T`, read as root), never from what
// the control plane remembers doing to the node.
//
// The distinction is the whole reason this exists. The SSH Guard board used to
// colour a row by the disposition of the last arm approval: an arm that
// applied and then reverted because nobody confirmed inside the window read as
// red, and so did an arm an operator had rejected weeks earlier. On the fleet
// that produced this, every one of those red rows was a node whose sshd had
// password authentication off and the operator's key installed. The approval
// history said "failed"; the node said "secure". The node is right, and the
// approval is history.
type Posture string

const (
	// PostureSecured: password authentication is off, root cannot log in by
	// password, and a key path is present. This is the state the fleet is
	// meant to be in, and it is a calm state however the last arm ended.
	PostureSecured Posture = "secured"
	// PosturePasswordOpen: sshd accepts passwords. Whatever else is set, the
	// brute force in the auth log can succeed here.
	PosturePasswordOpen Posture = "password_open"
	// PosturePartial: passwords are off, but either root may still log in
	// with one (PermitRootLogin yes, which sshd honours over
	// PasswordAuthentication for the root account on some builds) or the
	// facts show no key path, so key-only cannot be claimed.
	PosturePartial Posture = "partial"
	// PostureUnknown: the node has never reported sshd facts, or its agent
	// could not read them. Nothing is claimed either way.
	PostureUnknown Posture = "unknown"
)

// SSHDFacts is the subset of the agent's sshd report that posture reasons
// about. It is a plain struct rather than the model type so this package keeps
// no dependency on the server's model.
type SSHDFacts struct {
	PasswordAuthentication bool
	PubkeyAuthentication   bool
	// PermitRootLogin is the literal value sshd prints: yes, no,
	// without-password (what -T prints for prohibit-password), or
	// forced-commands-only.
	PermitRootLogin string
	// AuthorizedKeys is how many authorized keys the node reported across the
	// files sshd reads, or nil when the report carries no count. Today's
	// agent reports none, so nil is the normal value; when a count arrives it
	// takes precedence over PubkeyAuthentication as the key evidence, because
	// pubkey auth being enabled with no key on disk is not a way in.
	AuthorizedKeys *int
}

// Key evidence values, so the reader can tell a proven key from an inferred
// one.
const (
	KeyEvidenceAuthorizedKeys = "authorized_keys"
	KeyEvidencePubkeyAuth     = "pubkey_authentication"
)

// SSHPosture is the derived view. Reason is the sentence the console shows;
// it is written here so the API and the page cannot disagree.
type SSHPosture struct {
	State Posture `json:"state"`
	// KeyAccess reports whether the facts show a key path in. KeyEvidence
	// says which fact backed it.
	KeyAccess   bool   `json:"key_access"`
	KeyEvidence string `json:"key_evidence,omitempty"`
	Reason      string `json:"reason"`
}

// DerivePosture reads the facts and says what they add up to. nil facts is
// the honest input for a node that has not reported, and it yields unknown
// rather than a guess in either direction.
func DerivePosture(facts *SSHDFacts) SSHPosture {
	if facts == nil {
		return SSHPosture{
			State:  PostureUnknown,
			Reason: "This node has not reported its sshd configuration, so nothing is claimed about who can log in.",
		}
	}
	out := SSHPosture{}
	switch {
	case facts.AuthorizedKeys != nil:
		out.KeyAccess = *facts.AuthorizedKeys > 0
		out.KeyEvidence = KeyEvidenceAuthorizedKeys
	case facts.PubkeyAuthentication:
		out.KeyAccess = true
		out.KeyEvidence = KeyEvidencePubkeyAuth
	}
	if facts.PasswordAuthentication {
		out.State = PosturePasswordOpen
		out.Reason = "sshd accepts password logins on this node. A brute force against it can succeed; harden it."
		return out
	}
	rootByPassword := strings.EqualFold(strings.TrimSpace(facts.PermitRootLogin), "yes")
	switch {
	case rootByPassword:
		out.State = PosturePartial
		out.Reason = "Password authentication is off, but PermitRootLogin is yes, so root is not held to key-only login."
	case !out.KeyAccess:
		out.State = PosturePartial
		out.Reason = "Password authentication is off and the facts show no key path in, so key-only access cannot be claimed."
	default:
		out.State = PostureSecured
		if out.KeyEvidence == KeyEvidenceAuthorizedKeys {
			out.Reason = "Password authentication is off, root cannot log in by password, and an authorized key is on the node. Only a key opens this node."
		} else {
			out.Reason = "Password authentication is off, root cannot log in by password, and public-key authentication is on. Only a key opens this node."
		}
	}
	return out
}
