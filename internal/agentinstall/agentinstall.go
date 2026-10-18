// Package agentinstall carries the node-agent installer this server release
// hands out at /tools/agent/install.sh (design 31, S6), so a new machine
// fetches it from the control plane it is about to enrol with rather than
// from raw.githubusercontent.com, which mainland networks cannot reach.
//
// install.sh beside this file is lattice-node-agent's scripts/install.sh at
// Ref, byte for byte. The tests hold the copy to SHA256, so a hand edit fails
// go test, which CI runs on every pull request; refresh it by copying the
// file from the commit Ref names and updating both constants together.
package agentinstall

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
)

// Ref is the lattice-node-agent commit install.sh was copied from.
const Ref = "LatticeNet/lattice-node-agent@0a3eab6ebe770bd7fdc80f1d609af96d5966f99e"

// SHA256 is the digest of the copy.
const SHA256 = "8bd3b50a0e5a65ae6abce8b1f1a747daa276f893533bede4a1352d913b3b027a"

//go:embed install.sh
var installScript []byte

// Script returns the installer.
func Script() []byte {
	return append([]byte(nil), installScript...)
}

// ScriptSHA256 is the hex sha256 of the embedded installer.
func ScriptSHA256() string {
	sum := sha256.Sum256(installScript)
	return hex.EncodeToString(sum[:])
}
