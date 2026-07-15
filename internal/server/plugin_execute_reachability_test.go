package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The whole §9.3 protocol rests on one property: `execute` is reachable ONLY from the
// approval executor. Every guarantee downstream — the plan the operator read, the
// artifact digest it was produced by, the nodes it may touch — is worth nothing if some
// other handler can invoke the action directly.
//
// So this asserts the property structurally rather than trusting a comment: exactly one
// non-test file may name the action, and it must be the operation executor. A future
// handler that reaches for `execute` by reflex trips this before it can ship.
func TestExecuteActionIsInvokedOnlyByTheApprovalExecutor(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	callers := []string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), `"execute"`) {
			callers = append(callers, name)
		}
	}
	if len(callers) != 1 || callers[0] != "server_plugin_operation.go" {
		t.Fatalf("the execute action must be invoked only by the approval executor "+
			"(server_plugin_operation.go), but these files name it: %v", callers)
	}
}

// The raw invoke channel is gated only by plugin:admin. If `execute` ever entered its
// allow-list, an operator holding that one scope could apply host changes with no plan,
// no approval, and no target binding.
func TestDiagnosticActionsNeverIncludeExecute(t *testing.T) {
	for _, forbidden := range []string{"execute", "call", "plan", "migrate"} {
		if diagnosticPluginActions[forbidden] {
			t.Fatalf("%q is reachable through /api/plugins/invoke, which enforces no plan, "+
				"no approval, and no target binding", forbidden)
		}
	}
	for _, allowed := range []string{"describe", "health"} {
		if !diagnosticPluginActions[allowed] {
			t.Fatalf("%q should remain a diagnostic action", allowed)
		}
	}
}
