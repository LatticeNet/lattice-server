package store

import (
	"reflect"
	"runtime"
	"strings"
)

// storeFuncPrefix and storeMethodPrefix are how the runtime names a function
// of this package and a method on *Store, read from a function of the package
// so the module path is not written down twice.
var storeFuncPrefix, storeMethodPrefix = func() (string, string) {
	self := runtime.FuncForPC(reflect.ValueOf(exportedName).Pointer()).Name()
	pkg := strings.TrimSuffix(self, "exportedName")
	return pkg, pkg + "(*Store)."
}()

// persistCaller names the store method that asked for a whole-state write,
// for the telemetry that counts writes by caller. It is the first exported
// *Store method on the stack above persistState, past Save, which most writes
// go through. An exported method takes s.mu and so cannot call another one,
// which makes that frame the call the rest of the server made. The names are
// the methods this package has, a fixed set, so the label stays bounded. A
// write made from no exported method (the migrations Open runs) is named after
// the exported function on the stack, and "other" when there is none.
func persistCaller() string {
	var pcs [32]uintptr
	// Skip runtime.Callers, persistCaller and persistState.
	n := runtime.Callers(3, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	function := ""
	for {
		frame, more := frames.Next()
		if name, ok := strings.CutPrefix(frame.Function, storeMethodPrefix); ok {
			if name = exportedName(name); name != "" && name != "Save" {
				return name
			}
		} else if name, ok := strings.CutPrefix(frame.Function, storeFuncPrefix); ok && function == "" {
			function = exportedName(name)
		}
		if !more {
			break
		}
	}
	if function != "" {
		return function
	}
	return "other"
}

// exportedName strips a closure or generic suffix from a runtime function
// name ("UpsertNode.func1" is UpsertNode) and returns it when it is an
// exported identifier, "" otherwise.
func exportedName(name string) string {
	if i := strings.IndexAny(name, ".["); i >= 0 {
		name = name[:i]
	}
	if name == "" || name[0] < 'A' || name[0] > 'Z' {
		return ""
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return ""
		}
	}
	return name
}
