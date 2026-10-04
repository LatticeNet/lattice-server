package telemetry

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestIntervalWindowCountsAndResets(t *testing.T) {
	r := NewRegistry()
	r.ObserveRoute("/api/nodes", http.StatusOK, 10*time.Millisecond)
	r.ObserveRoute("/api/nodes", http.StatusInternalServerError, 30*time.Millisecond)
	r.ObserveRoute("/api/nodes", http.StatusForbidden, time.Millisecond)
	r.ObserveRoute("", http.StatusOK, time.Millisecond)
	r.ObservePluginCall("p", "svc/m", 50*time.Millisecond, nil)
	r.ObservePluginCall("p", "svc/m", 70*time.Millisecond, errors.New("refused"))
	r.ObservePluginCall("", "svc/m", time.Millisecond, nil) // no plugin: ignored
	r.ObservePluginProcess("p", 2*time.Second, 1<<20)
	r.ObservePluginProcess("p", time.Second, 3<<20)
	r.ObserveStoreSave("UpdateMetrics", 4*time.Millisecond, nil)
	r.ObserveStoreSave("UpdateMetrics", 6*time.Millisecond, errors.New("disk full"))
	r.ObserveAuditAppend(nil)

	w := r.TakeInterval()
	if e := w.Routes["/api/nodes"]; e.Count != 3 || e.Errors != 1 {
		t.Fatalf("route = %+v, want 3 requests and only the 500 a failure", e)
	}
	if e := w.Routes[RouteOther]; e == nil || e.Count != 1 {
		t.Fatalf("unnamed route = %+v", e)
	}
	if e := w.Plugins[PluginCallKey{"p", "svc/m"}]; e.Count != 2 || e.Errors != 1 {
		t.Fatalf("plugin = %+v", e)
	}
	if len(w.Plugins) != 1 {
		t.Fatalf("plugins = %v", w.Plugins)
	}
	if u := w.PluginProcesses["p"]; u.CPU.Count != 2 || u.CPU.Sum != 3 || u.RSS.Max != 3<<20 {
		t.Fatalf("plugin processes = %+v", u)
	}
	if e := w.StoreSaves["UpdateMetrics"]; e.Count != 2 || e.Errors != 1 {
		t.Fatalf("store saves = %+v", e)
	}
	if w.AuditAppends.Count != 1 {
		t.Fatalf("audit appends = %+v", w.AuditAppends)
	}
	if next := r.TakeInterval(); len(next.Routes) != 0 || len(next.Plugins) != 0 || len(next.StoreSaves) != 0 || next.AuditAppends.Count != 0 {
		t.Fatalf("second take = %+v, want empty", next)
	}
	// The cumulative counters /metrics serves are not reset by it.
	if snap := r.Snapshot(); snap.StoreCallers["UpdateMetrics"].Count != 2 {
		t.Fatalf("cumulative store callers = %+v", snap.StoreCallers)
	}
}

func TestIntervalWindowBoundsLabels(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < maxWindowRoutes+20; i++ {
		r.ObserveRoute(fmt.Sprintf("/api/g%d", i), http.StatusOK, time.Millisecond)
	}
	for i := 0; i < maxWindowMethodsPerPlugin+5; i++ {
		r.ObservePluginCall("p", fmt.Sprintf("svc/m%d", i), time.Millisecond, nil)
	}
	w := r.TakeInterval()
	if len(w.Routes) != maxWindowRoutes+1 {
		t.Fatalf("%d route groups in one window, want the cap plus %q", len(w.Routes), RouteOther)
	}
	if e := w.Routes[RouteOther]; e == nil || e.Count != 20 {
		t.Fatalf("other = %+v", e)
	}
	if e := w.Plugins[PluginCallKey{"p", PluginMethodOther}]; e == nil || e.Count != 5 {
		t.Fatalf("plugin other = %+v", e)
	}
}
