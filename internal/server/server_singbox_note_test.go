package server

import "testing"

// The note is the line's own account of an unproven service. It travels only
// with the states an operator must act on.
func TestServiceNoteFollowsTheStatesThatNeedAHand(t *testing.T) {
	reason := "refused sing-box candidate /etc/sing-box/bin/sing-box (pid 3917185): owned by uid 1001, not root"
	if got := serviceNoteFor(serviceStateUnknown, reason); got != reason {
		t.Fatalf("unknown must carry the note: %q", got)
	}
	if got := serviceNoteFor(serviceStateDown, "  ss: exit status 1 "); got != "ss: exit status 1" {
		t.Fatalf("down must carry the trimmed note: %q", got)
	}
	if got := serviceNoteFor(serviceStateRestarting, reason); got != reason {
		t.Fatalf("restarting must carry the note: %q", got)
	}
	if got := serviceNoteFor(serviceStateRunning, "ss: exit status 1"); got != "" {
		t.Fatalf("running must not carry a note: %q", got)
	}
	if got := serviceNoteFor(serviceStateUnknown, ""); got != "" {
		t.Fatalf("no probe error means no note: %q", got)
	}
}
