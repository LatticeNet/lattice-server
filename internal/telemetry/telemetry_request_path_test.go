package telemetry

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRequestPathForObservabilityMatchesServeMuxSegmentCleaning(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		want   string
	}{
		{
			name:   "escaped first segment",
			method: http.MethodGet,
			path:   "/%73ub/slug/token",
			want:   RedactedSubscriptionPath,
		},
		{
			name:   "escaped segment before cleaned subscription",
			method: http.MethodGet,
			path:   "/x%2Fy/../sub/slug/token",
			want:   RedactedSubscriptionPath,
		},
		{
			name:   "escaped slash stays inside effective first segment",
			method: http.MethodGet,
			path:   "/x%2Fy/../sub%2Fnot-a-sub-segment/ordinary-tail",
			want:   "/x/y/../sub/not-a-sub-segment/ordinary-tail",
		},
		{
			name:   "escaped slash keeps decoded first segment ordinary",
			method: http.MethodGet,
			path:   "/sub%2Fnot-a-sub-segment/ordinary-tail-2",
			want:   "/sub%2Fnot-a-sub-segment/ordinary-tail-2",
		},
		{
			name:   "raw subscription path retains authority after cleaning",
			method: http.MethodGet,
			path:   "/sub/../outside",
			want:   RedactedSubscriptionPath,
		},
		{
			name:   "connect does not clean to subscription",
			method: http.MethodConnect,
			path:   "/outside/../sub/token",
			want:   "/outside/../sub/token",
		},
		{
			name:   "get cleans to subscription",
			method: http.MethodGet,
			path:   "/outside/../sub/token",
			want:   RedactedSubscriptionPath,
		},
		{
			name:   "authority form is not a path",
			method: http.MethodConnect,
			path:   "sub.example:443",
			want:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if got := RequestPathForObservability(req); got != tc.want {
				t.Fatalf("RequestPathForObservability() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestObserveHTTPRequestPreservesMethodAwareSubscriptionClassification(t *testing.T) {
	registry := NewRegistry()
	connectRequest := httptest.NewRequest(http.MethodConnect, "/outside/../sub/token", nil)
	getRequest := httptest.NewRequest(http.MethodGet, "/outside/../sub/token", nil)

	registry.ObserveHTTPRequest(RequestPathForObservability(connectRequest), http.StatusTeapot, time.Millisecond, false)
	registry.ObserveHTTPRequest(RequestPathForObservability(getRequest), http.StatusNoContent, time.Millisecond, false)

	snapshot := registry.Snapshot()
	connectKey := httpKey{Path: "/outside/../sub/token", StatusClass: "4xx"}
	if got := snapshot.HTTP[connectKey].Count; got != 1 {
		t.Fatalf("CONNECT metric count = %d, want 1; metrics = %#v", got, snapshot.HTTP)
	}
	getKey := httpKey{Path: RedactedSubscriptionPath, StatusClass: "2xx"}
	if got := snapshot.HTTP[getKey].Count; got != 1 {
		t.Fatalf("GET metric count = %d, want 1; metrics = %#v", got, snapshot.HTTP)
	}

	prometheus := registry.Prometheus()
	for _, want := range []string{
		`lattice_http_requests_total{path="/outside/../sub/token",status_class="4xx"} 1`,
		`lattice_http_requests_total{path="/sub/:token",status_class="2xx"} 1`,
	} {
		if !strings.Contains(prometheus, want) {
			t.Fatalf("Prometheus metrics do not contain %q:\n%s", want, prometheus)
		}
	}
}
