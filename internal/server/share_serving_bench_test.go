package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// benchDiskShareServer builds the production storage shape a share fetch runs
// against: a sealed disk store, the bolt hot store and the audit WAL. The
// render is a stub, because what is measured is the serving path around it.
func benchDiskShareServer(b *testing.B, shares int) (*Server, string) {
	b.Helper()
	dir := b.TempDir()
	cipher, err := secret.NewAESGCM([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		b.Fatal(err)
	}
	st, err := store.OpenWithCipher(filepath.Join(dir, "state.json"), cipher)
	if err != nil {
		b.Fatal(err)
	}
	if err := st.EnableRuntimeBoltHotStore(filepath.Join(dir, "state-hot.db")); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = st.Close() })
	s, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		b.Fatal(err)
	}
	var target string
	for i := 0; i < shares; i++ {
		token, err := s.newUniqueShareToken()
		if err != nil {
			b.Fatal(err)
		}
		share := model.SubscriptionShare{ID: fmt.Sprintf("share-%04d", i), Slug: fmt.Sprintf("s%04d", i), Token: token, Enabled: true,
			Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "rec"}}
		if err := st.UpsertSubscriptionShare(share); err != nil {
			b.Fatal(err)
		}
		if i == shares-1 {
			target = fmt.Sprintf("/sub/s%04d/%s", i, token)
		}
	}
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "rec",
		Raw: strings.Repeat("vless://x\n", 3000), FetchedAt: s.now()}); err != nil {
		b.Fatal(err)
	}
	body := []byte(strings.Repeat("proxies:\n  - {name: a, type: vless}\n", 1800)) // about 64 KB
	s.subscriptionRender = func(_ context.Context, share model.SubscriptionShare, _, _ string, _ shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		epoch, _ := s.subscriptionSnapshotEpoch(share.Source.PluginID, share.Source.SubscriptionID, snap)
		return renderedSubscription{Body: body, ContentType: "text/yaml", RevalidationVersion: subscriptionRevalidationVersion(snap),
			SourceEpoch: epoch, FetchedAt: snap.FetchedAt}, nil
	}
	return s, target
}

func benchPercentile(samples []time.Duration, p float64) time.Duration {
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[int(float64(len(sorted)-1)*p)]
}

// BenchmarkShareCachedFetch measures a cache hit end to end through the
// subscription limiter and the real handler, which is what a client poll
// costs once its body is cached. Run it with
//
//	go test -run '^$' -bench BenchmarkShareCachedFetch -benchtime 200x ./internal/server/
func BenchmarkShareCachedFetch(b *testing.B) {
	for _, shares := range []int{1, 1000} {
		b.Run(fmt.Sprintf("shares=%d", shares), func(b *testing.B) {
			s, path := benchDiskShareServer(b, shares)
			handler := s.withSubscriptionLimit(s.handleSubscriptionShare)
			client := 0
			fetch := func() (time.Duration, int) {
				client++
				req := httptest.NewRequest(http.MethodGet, path+"?target=ClashMeta", nil)
				req.Header.Set("User-Agent", "clash-verge/v2.2.3")
				req.Header.Set("Accept-Encoding", "gzip")
				req.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:1234", client/62500%250, client/250%250, client%250+1)
				rec := httptest.NewRecorder()
				start := time.Now()
				handler(rec, req)
				return time.Since(start), rec.Code
			}
			if _, code := fetch(); code != http.StatusOK {
				b.Fatalf("warm fetch status %d", code)
			}
			samples := make([]time.Duration, 0, b.N)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				took, code := fetch()
				if code != http.StatusOK {
					b.Fatalf("cached fetch status %d", code)
				}
				samples = append(samples, took)
			}
			b.StopTimer()
			// First-seen audits are written after the answer; let them land
			// before the store's directory is removed.
			s.shareFetchAudits.Wait()
			b.ReportMetric(float64(benchPercentile(samples, 0.5).Microseconds())/1000, "p50-ms")
			b.ReportMetric(float64(benchPercentile(samples, 0.9).Microseconds())/1000, "p90-ms")
			b.ReportMetric(float64(benchPercentile(samples, 1).Microseconds())/1000, "max-ms")
		})
	}
}
