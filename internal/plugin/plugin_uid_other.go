//go:build !linux

package plugin

// checkServerBinary has nothing to check off Linux, which is the only
// platform with file capabilities.
func checkServerBinary(PluginUIDRange) error { return nil }
