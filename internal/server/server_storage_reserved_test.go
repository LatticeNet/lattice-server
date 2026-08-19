package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// A static binding is anonymous public hosting: whoever knows the URL reads the
// bytes. The bucket holding agent release binaries is authorized per task lease
// instead, so it must stay unreachable through that door even when a binding
// points straight at it. Such a binding can predate the reservation, and the
// storage API refuses new ones, so the serving path has to refuse too rather
// than trust that none exists.
//
// The object below is real content in the reserved bucket, so without the guard
// this route answers 200 with the binary. That is what makes the assertion
// meaningful rather than a 404 for a missing file.
func TestStaticBindingNeverServesTheReservedAgentArtifactBucket(t *testing.T) {
	handler, st := newTestServer(t)

	const secret = "ELF-agent-release-bytes-not-for-anonymous-readers"
	if err := st.PutStatic(model.StaticObject{
		Bucket:      agentArtifactBucket,
		Path:        "lattice-agent-linux-amd64",
		Content:     secret,
		ContentType: "application/octet-stream",
		Size:        len(secret),
	}); err != nil {
		t.Fatalf("stage artifact: %v", err)
	}
	if err := st.UpsertStorageBinding(model.StorageBinding{
		ID:         "binding-predating-the-reservation",
		Kind:       model.StorageKindStatic,
		Bucket:     agentArtifactBucket,
		Hostname:   "downloads.example.com",
		PathPrefix: "/",
		Enabled:    true,
	}); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/lattice-agent-linux-amd64", nil)
	req.Host = "downloads.example.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("the reserved agent bucket was served over an anonymous static binding (status %d)", rec.Code)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatal("agent release bytes leaked through a static binding")
	}
}
