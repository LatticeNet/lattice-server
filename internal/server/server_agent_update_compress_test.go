package server

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// An approval planned after resumable downloads and before the source walk
// renders the script it was approved with, byte for byte: S2 is keyed on a
// plan line, so it changes nothing an open approval runs.
func TestAgentUpdatePreCutoffApprovalsRenderTheScriptTheyWereApprovedWith(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "agent_update_pre_cutoff_approvals.json"))
	if err != nil {
		t.Fatal(err)
	}
	var goldens []preResumeApproval
	if err := json.Unmarshal(raw, &goldens); err != nil {
		t.Fatal(err)
	}
	if len(goldens) != 3 {
		t.Fatalf("want the three pre-cutoff approvals, have %d", len(goldens))
	}
	for _, golden := range goldens {
		t.Run(golden.Name, func(t *testing.T) {
			approval := model.Approval{NodeID: golden.NodeID, Plugin: agentUpdatePlugin, Action: golden.Action, Plan: golden.Plan}
			payload, err := agentUpdatePayloadFromApproval(approval)
			if err != nil {
				t.Fatal(err)
			}
			if !payload.ResumeDownload || payload.CompressedSHA256 != "" || strings.Contains(golden.Plan, agentUpdateCutoffPlanLine) {
				t.Fatal("the golden must be a resumable, uncompressed approval planned before the walk")
			}
			script, err := agentUpdateApplyScript(approval, artifactTestPublicURL)
			if err != nil {
				t.Fatal(err)
			}
			if script != golden.Script {
				t.Fatalf("the script changed under an approval planned before the walk\n--- approved\n%s\n--- rendered now\n%s", golden.Script, script)
			}
		})
	}
}

// An import stores the gzip form, and the same release always stores the same
// bytes, which decompress to exactly the verified binary.
func TestAgentArtifactImportStoresADeterministicCompressedCopy(t *testing.T) {
	data, digest := walkTestBinary("0.3.4", 256<<10)
	ref := agentArtifactRef{Version: "0.3.4", OS: "linux", Arch: "amd64", SHA256: digest}
	var stored []string
	var gz string
	for run := 0; run < 2; run++ {
		srv, _, st := newAgentArtifactServer(t)
		if _, err := srv.storeAgentArtifact(ref, data); err != nil {
			t.Fatal(err)
		}
		view, err := srv.storeCompressedAgentArtifact(ref, data)
		if err != nil {
			t.Fatal(err)
		}
		if !agentSHA256Re.MatchString(view.CompressedSHA256) || view.SizeBytes != len(data) ||
			view.CompressedBytes <= 0 || view.CompressedBytes >= len(data)/2 {
			t.Fatalf("view %+v", view)
		}
		if gz != "" && view.CompressedSHA256 != gz {
			t.Fatalf("two imports of the same bytes stored different compressed digests: %s and %s", gz, view.CompressedSHA256)
		}
		gz = view.CompressedSHA256
		objects := st.Static(agentArtifactBucket)
		if len(objects) != 1 {
			t.Fatalf("the compressed copy must replace the raw one for the same version, have %d objects", len(objects))
		}
		if want := "0.3.4/linux/amd64/" + digest + "/" + gz + ".gz"; objects[0].Path != want {
			t.Fatalf("object path %q, want %q", objects[0].Path, want)
		}
		stored = append(stored, objects[0].Content)

		packed, err := base64.StdEncoding.DecodeString(objects[0].Content)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(packed)
		if hex.EncodeToString(sum[:]) != gz {
			t.Fatal("the path must name the digest of the stored compressed bytes")
		}
		// No name, no modification time: nothing but the input decides the
		// bytes.
		if packed[0] != 0x1f || packed[1] != 0x8b || packed[3]&0x08 != 0 || !bytes.Equal(packed[4:8], []byte{0, 0, 0, 0}) {
			t.Fatalf("gzip header % x carries a name or a time", packed[:10])
		}
		zr, err := gzip.NewReader(bytes.NewReader(packed))
		if err != nil {
			t.Fatal(err)
		}
		back, err := io.ReadAll(zr)
		if err != nil || !bytes.Equal(back, data) {
			t.Fatalf("the compressed copy must decompress to the verified binary: %v", err)
		}
		listed := srv.agentArtifacts()
		if len(listed) != 1 || listed[0].SHA256 != digest || listed[0].CompressedSHA256 != gz ||
			listed[0].SizeBytes != len(data) || listed[0].CompressedBytes != len(packed) {
			t.Fatalf("the listing must report both digests and both sizes: %+v", listed)
		}
		if got, ok := srv.storedAgentArtifact("0.3.4", "linux", "amd64"); !ok || got.GzipSHA256 != gz || got.SHA256 != digest {
			t.Fatalf("stored artifact %+v %t", got, ok)
		}
	}
	if stored[0] != stored[1] {
		t.Fatal("two imports of the same release stored different bytes")
	}
	if _, err := newAgentArtifactServerOnly(t).storeCompressedAgentArtifact(ref, append([]byte("x"), data[1:]...)); err == nil {
		t.Fatal("bytes that do not match the release digest must not be compressed and stored")
	}
}

func newAgentArtifactServerOnly(t *testing.T) *Server {
	srv, _, _ := newAgentArtifactServer(t)
	return srv
}

// A plan pins the compressed form only when the control plane holds it, and
// the fallback stays the uncompressed release binary.
func TestAgentUpdatePlanWithAndWithoutACompressedArtifact(t *testing.T) {
	data, _ := walkTestBinary("0.3.4", 64<<10)
	t.Run("raw", func(t *testing.T) {
		srv, _, st := newAgentArtifactServer(t)
		_, approval, _ := seedWalkUpdate(t, srv, st, data, false)
		payload, err := agentUpdatePayloadFromApproval(approval)
		if err != nil {
			t.Fatal(err)
		}
		if payload.CompressedSHA256 != "" || payload.CompressedSize != 0 || payload.BinarySize != 0 ||
			strings.Contains(approval.Plan, "compressed") {
			t.Fatalf("a raw artifact plans no compression:\n%s", approval.Plan)
		}
	})
	t.Run("compressed", func(t *testing.T) {
		srv, _, st := newAgentArtifactServer(t)
		ref, approval, _ := seedWalkUpdate(t, srv, st, data, true)
		payload, err := agentUpdatePayloadFromApproval(approval)
		if err != nil {
			t.Fatal(err)
		}
		obj, _ := st.StaticObject(agentArtifactBucket, ref.objectPath())
		packedSize := agentArtifactDecodedSize(obj.Content)
		if payload.CompressedSHA256 != ref.GzipSHA256 || payload.BinarySize != len(data) || payload.CompressedSize != packedSize ||
			payload.BinaryURL != artifactTestPublicURL+ref.urlPath() || payload.FallbackURL != fallbackTestReleaseURL ||
			payload.SHA256 != ref.SHA256 || !payload.ResumeDownload {
			t.Fatalf("payload %+v", payload)
		}
		for _, want := range []string{
			"\ncompressed_sha256: " + ref.GzipSHA256 + "\n",
			"\ncompressed_size: " + strconv.Itoa(packedSize) + "\n",
			"\nbinary_size: " + strconv.Itoa(len(data)) + "\n",
			"holds the compressed file to compressed_sha256 before decompressing it, stops decompressing past binary_size bytes",
			"fetches fallback_url, the uncompressed release binary, without the task lease",
			"- a node without a working gzip or head -c skips the compressed download and fetches fallback_url\n",
			"\n" + agentUpdateCutoffPlanLine + "\n",
		} {
			if !strings.Contains(approval.Plan, want) {
				t.Fatalf("plan is missing %q:\n%s", want, approval.Plan)
			}
		}
		if stale, reason := srv.agentUpdateApprovalLocalStaleness(approval); stale {
			t.Fatalf("a compressed plan made now must not be stale: %s", reason)
		}
		if err := srv.requireCurrentAgentUpdateApproval(approval); err != nil {
			t.Fatalf("a compressed plan made now must be approvable: %v", err)
		}
	})
	t.Run("official release", func(t *testing.T) {
		srv, _, st := newAgentArtifactServer(t)
		seedLinuxAgentNode(t, st)
		sum := sha256.Sum256(data)
		ref := agentArtifactRef{Version: "0.3.4", OS: "linux", Arch: "amd64", SHA256: hex.EncodeToString(sum[:])}
		if _, err := srv.storeCompressedAgentArtifact(ref, data); err != nil {
			t.Fatal(err)
		}
		node, _ := st.Node("node-a")
		payload, err := srv.agentUpdatePayloadForPolicy(node, model.AgentUpdatePolicy{NodeID: "node-a", Enabled: true, TargetVersion: "0.3.4"})
		if err != nil {
			t.Fatal(err)
		}
		if payload.CompressedSHA256 == "" || !strings.HasSuffix(payload.BinaryURL, ".gz") ||
			payload.FallbackURL != "https://github.com/LatticeNet/lattice-node-agent/releases/download/v0.3.4/lattice-agent-linux-amd64" {
			t.Fatalf("an official release held compressed pins it and falls back to the release asset: %+v", payload)
		}
	})
	t.Run("a policy pinned to the control plane's own route has no fallback", func(t *testing.T) {
		srv, _, st := newAgentArtifactServer(t)
		seedLinuxAgentNode(t, st)
		sum := sha256.Sum256(data)
		ref := agentArtifactRef{Version: "0.3.4", OS: "linux", Arch: "amd64", SHA256: hex.EncodeToString(sum[:])}
		if _, err := srv.storeCompressedAgentArtifact(ref, data); err != nil {
			t.Fatal(err)
		}
		node, _ := st.Node("node-a")
		payload, err := srv.agentUpdatePayloadForPolicy(node, model.AgentUpdatePolicy{
			NodeID: "node-a", Enabled: true, TargetVersion: "0.3.4", SHA256: ref.SHA256,
			BinaryURL: artifactTestPublicURL + ref.urlPath(),
		})
		if err != nil {
			t.Fatal(err)
		}
		// That route answers only a lease, which a fallback never carries.
		if payload.FallbackURL != "" || payload.CompressedSHA256 == "" {
			t.Fatalf("payload %+v", payload)
		}
	})
}

// The compressed object goes only to a plan that pins exactly it, with its
// own digest as the validator, and ranges address the stored compressed
// bytes.
func TestAgentBinaryServesTheCompressedObjectOnlyToAPlanThatPinsIt(t *testing.T) {
	srv, handler, st := newAgentArtifactServer(t)
	data, _ := walkTestBinary("0.3.4", 64<<10)
	ref, approval, task := seedWalkUpdate(t, srv, st, data, true)
	obj, _ := st.StaticObject(agentArtifactBucket, ref.objectPath())
	packed, _ := base64.StdEncoding.DecodeString(obj.Content)

	res := getAgentBinary(t, handler, ref.urlPath(), task.ID, task.LeaseID)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || !bytes.Equal(body, packed) || res.Header.Get("ETag") != `"`+ref.GzipSHA256+`"` ||
		res.Header.Get("Content-Encoding") != "" {
		t.Fatalf("status %d, %d bytes, etag %q, encoding %q", res.StatusCode, len(body), res.Header.Get("ETag"), res.Header.Get("Content-Encoding"))
	}
	if ev, ok := lastAuditFor(st, "agent.binary.serve"); !ok || ev.Metadata["compressed_sha256"] != ref.GzipSHA256 {
		t.Fatalf("the audit must name the compressed object served: %v", ev.Metadata)
	}
	res = getAgentBinaryWith(t, handler, http.MethodGet, ref.urlPath(), task.ID, task.LeaseID, map[string]string{"Range": "bytes=100-"})
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusPartialContent || !bytes.Equal(body, packed[100:]) {
		t.Fatalf("a range must address the compressed bytes: status %d", res.StatusCode)
	}

	raw := agentArtifactRef{Version: ref.Version, OS: ref.OS, Arch: ref.Arch, SHA256: ref.SHA256}
	res = getAgentBinary(t, handler, raw.urlPath(), task.ID, task.LeaseID)
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("only the compressed copy is held, so the raw route must answer 404, got %d", res.StatusCode)
	}

	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	other := sha256.Sum256([]byte("other"))
	for name, mutate := range map[string]func(p *agentUpdatePayload){
		"an uncompressed plan": func(p *agentUpdatePayload) {
			p.CompressedSHA256, p.CompressedSize, p.BinarySize = "", 0, 0
			p.BinaryURL = artifactTestPublicURL + raw.urlPath()
		},
		"another compressed digest": func(p *agentUpdatePayload) { p.CompressedSHA256 = hex.EncodeToString(other[:]) },
	} {
		p := payload
		mutate(&p)
		bound := approval
		bound.Action = agentUpdateApprovalAction(p)
		if err := st.UpsertApproval(bound); err != nil {
			t.Fatal(err)
		}
		res := getAgentBinary(t, handler, ref.urlPath(), task.ID, task.LeaseID)
		res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("%s must not receive the compressed object, got %d", name, res.StatusCode)
		}
	}
}

// Compression is a form of a resumable control-plane download and nothing
// else, and only the walk may run it.
func TestAgentUpdatePayloadValidatesTheCompressedFields(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	data, _ := walkTestBinary("0.3.4", 64<<10)
	_, approval, _ := seedWalkUpdate(t, srv, st, data, true)
	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(p *agentUpdatePayload){
		"upstream source": func(p *agentUpdatePayload) {
			p.BinarySource, p.BinaryURL, p.FallbackURL = agentBinarySourceUpstream, fallbackTestReleaseURL, ""
		},
		"without resume":   func(p *agentUpdatePayload) { p.ResumeDownload = false },
		"short digest":     func(p *agentUpdatePayload) { p.CompressedSHA256 = p.CompressedSHA256[:63] },
		"path in digest":   func(p *agentUpdatePayload) { p.CompressedSHA256 = "../../" + p.CompressedSHA256[6:] },
		"no binary size":   func(p *agentUpdatePayload) { p.BinarySize = 0 },
		"negative size":    func(p *agentUpdatePayload) { p.CompressedSize = -1 },
		"binary too large": func(p *agentUpdatePayload) { p.BinarySize = maxAgentArtifactBytes + 1 },
		"sizes, no digest": func(p *agentUpdatePayload) { p.CompressedSHA256 = "" },
		"digest, no sizes": func(p *agentUpdatePayload) { p.CompressedSize, p.BinarySize = 0, 0 },
		"shell in digest":  func(p *agentUpdatePayload) { p.CompressedSHA256 = "$(touch pwned)" + p.CompressedSHA256[14:] },
		"space in digest": func(p *agentUpdatePayload) {
			p.CompressedSHA256 = p.CompressedSHA256[:32] + " " + p.CompressedSHA256[33:]
		},
		"compressed is raw": func(p *agentUpdatePayload) { p.CompressedSize = maxAgentArtifactBytes + 1 },
	} {
		bad := payload
		mutate(&bad)
		a := approval
		a.Action = agentUpdateApprovalAction(bad)
		if _, err := agentUpdatePayloadFromApproval(a); err == nil {
			t.Fatalf("%s: must not decode", name)
		}
		if _, err := agentUpdateApplyScript(a, artifactTestPublicURL); err == nil {
			t.Fatalf("%s: must not render", name)
		}
	}
	if _, err := agentUpdateApplyScript(approvalBeforeTheWalk(approval), artifactTestPublicURL); err == nil ||
		!strings.Contains(err.Error(), "predates the source walk") {
		t.Fatalf("a compressed payload under a plan without the walk must not render: %v", err)
	}
	current := payload
	current.CompressedSHA256 = strings.Repeat("b", 64)
	current.CompressedSize++
	current.BinarySize++
	summary := agentUpdatePayloadChangeSummary(payload, current)
	for _, want := range []string{"compressed_sha256 planned=", "compressed_size planned=", "binary_size planned="} {
		if !strings.Contains(summary, want) {
			t.Fatalf("the change summary must name %q: %s", want, summary)
		}
	}
}

// walkBehaviour is what a test server does with one request.
type walkBehaviour struct {
	// rate throttles the body to about this many bytes per second.
	rate int
	// cut drops the connection after this many bytes of the body.
	cut int
	// status answers with this status instead of the body.
	status int
}

// walkServer is a TLS server for real fetches. It runs each request through
// the behaviour at its index (the last one repeats) and records each
// request's headers.
type walkServer struct {
	*httptest.Server
	mu     sync.Mutex
	seen   []http.Header
	behave []walkBehaviour
}

func newWalkServer(t *testing.T, serve http.Handler, behave ...walkBehaviour) *walkServer {
	t.Helper()
	ws := &walkServer{behave: behave}
	ws.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws.mu.Lock()
		n := len(ws.seen)
		ws.seen = append(ws.seen, r.Header.Clone())
		var b walkBehaviour
		if len(ws.behave) > 0 {
			b = ws.behave[min(n, len(ws.behave)-1)]
		}
		ws.mu.Unlock()
		if b.status != 0 {
			http.Error(w, http.StatusText(b.status), b.status)
			return
		}
		if b.rate > 0 || b.cut > 0 {
			left := -1
			if b.cut > 0 {
				left = b.cut
			}
			w = &walkThrottle{ResponseWriter: w, rate: b.rate, left: left}
		}
		serve.ServeHTTP(w, r)
	}))
	t.Cleanup(ws.Close)
	return ws
}

func (ws *walkServer) requests() []http.Header {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	return append([]http.Header(nil), ws.seen...)
}

// walkThrottle sends a body at about rate bytes per second, in slices of an
// eighth of a second, and drops the connection after left bytes when left is
// not negative.
type walkThrottle struct {
	http.ResponseWriter
	rate, left int
}

func (w *walkThrottle) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		if w.left == 0 {
			w.ResponseWriter.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		}
		chunk := len(p)
		if w.rate > 0 {
			chunk = min(chunk, max(w.rate/8, 1))
		}
		if w.left > 0 {
			chunk = min(chunk, w.left)
		}
		n, err := w.ResponseWriter.Write(p[:chunk])
		written += n
		if err != nil {
			return written, err
		}
		if w.left > 0 {
			w.left -= n
		}
		p = p[n:]
		w.ResponseWriter.(http.Flusher).Flush()
		if w.rate > 0 {
			time.Sleep(time.Duration(n) * time.Second / time.Duration(w.rate))
		}
	}
	return written, nil
}

func serveBytes(data []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(data))
	})
}

func walkCAFile(t *testing.T, ws *walkServer) string {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ws.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return caFile
}

// realWalkOverrides shrinks the walk's windows so a real run takes seconds:
// a 2 s cutoff window, a 3 s connect allowance and a one second pause. The
// arithmetic is the script's own.
func realWalkOverrides(budget int) map[string]string {
	return map[string]string{
		"FETCH_BUDGET":     strconv.Itoa(budget),
		"FETCH_CONNECT":    "3",
		"FETCH_CUT_WINDOW": "2",
		"FETCH_PAUSE":      "1",
	}
}

func summaryFields(t *testing.T, summary string) [][]string {
	t.Helper()
	fields := strings.Fields(strings.TrimPrefix(summary, agentFetchSummaryPrefix))
	out := make([][]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, strings.Split(f, ":"))
	}
	return out
}

// The walk with the host's curl against real TLS servers: the control plane's
// own handler and a release server, throttled the way slow paths are.
func TestAgentUpdateWalkAgainstRealSources(t *testing.T) {
	srv, handler, st := newAgentArtifactServer(t)
	data, _ := walkTestBinary("0.3.4", 1<<20)
	ref, approval, task := seedWalkUpdate(t, srv, st, data, false)
	script, _ := walkScript(t, approval, nil)
	lease := []string{"LATTICE_TASK_ID=" + task.ID, "LATTICE_TASK_LEASE_ID=" + task.LeaseID}

	t.Run("a slow source is cut with its bytes kept and the best one finishes", func(t *testing.T) {
		cp := newWalkServer(t, handler, walkBehaviour{rate: 8 << 10}, walkBehaviour{})
		fb := newWalkServer(t, serveBytes(data), walkBehaviour{rate: 2 << 10})
		o := runWalkScript(t, script, walkRun{fetcher: "curl", real: true, clock: "host", caFile: walkCAFile(t, cp),
			cpURL: cp.URL + ref.urlPath(), fbURL: fb.URL + "/lattice-agent-linux-amd64",
			overrides: realWalkOverrides(60), env: lease})
		if o.exit != 0 || !bytes.Equal(o.installed, data) {
			t.Fatalf("exit %d, installed %d bytes, stderr:\n%s", o.exit, len(o.installed), o.stderr)
		}
		f := summaryFields(t, o.summary)
		if len(f) != 4 || f[0][0] != "1" || f[0][2] != "28" || f[1][0] != "2" || f[1][2] != "28" || f[2][0] != "p2" || f[2][1] != "cp" || f[2][2] != "0" {
			t.Fatalf("want both sources cut, then the control plane finishing, got %q", o.summary)
		}
		cpGot, _ := strconv.Atoi(f[0][3])
		fbGot, _ := strconv.Atoi(f[1][3])
		if cpGot <= fbGot || fbGot <= 0 {
			t.Fatalf("the faster source must have delivered more: %q", o.summary)
		}
		cps, fbs := cp.requests(), fb.requests()
		if len(cps) != 2 || len(fbs) != 1 {
			t.Fatalf("want two control-plane requests and one fallback request, got %d and %d", len(cps), len(fbs))
		}
		if fbs[0].Get("Range") != fmt.Sprintf("bytes=%d-", cpGot) || fbs[0].Get(agentTaskLeaseHeader) != "" {
			t.Fatalf("the fallback must continue what the control plane sent, without the lease: %v", fbs[0])
		}
		if cps[1].Get("Range") != fmt.Sprintf("bytes=%d-", cpGot+fbGot) || cps[1].Get(agentTaskLeaseHeader) != task.LeaseID {
			t.Fatalf("the second pass must continue from both sources' bytes, with the lease: %v", cps[1])
		}
	})
	t.Run("the equal share stops a source that stays above the cutoff", func(t *testing.T) {
		cp := newWalkServer(t, handler, walkBehaviour{rate: 96 << 10})
		fb := newWalkServer(t, serveBytes(data))
		o := runWalkScript(t, script, walkRun{fetcher: "curl", real: true, clock: "host", caFile: walkCAFile(t, cp),
			cpURL: cp.URL + ref.urlPath(), fbURL: fb.URL + "/lattice-agent-linux-amd64",
			overrides: realWalkOverrides(10), env: lease})
		if o.exit != 0 || !bytes.Equal(o.installed, data) {
			t.Fatalf("exit %d, stderr:\n%s", o.exit, o.stderr)
		}
		f := summaryFields(t, o.summary)
		if len(f) != 3 || f[0][2] != "28" || f[1][1] != "up" || f[1][2] != "0" {
			t.Fatalf("the control plane must stop at its share and the fallback finish: %q", o.summary)
		}
		took, _ := strconv.Atoi(f[0][4])
		got, _ := strconv.Atoi(f[0][3])
		if took < 4 || took > 6 || got < 192<<10 {
			t.Fatalf("a 96 KiB/s source must run its whole 5 s share, not be cut: %q", o.summary)
		}
	})
}

// The compressed download end to end, with the host's curl and wget against
// the control plane's own handler.
func TestAgentUpdateCompressedDownloadAgainstTheRealHandler(t *testing.T) {
	srv, handler, st := newAgentArtifactServer(t)
	data, _ := walkTestBinary("0.3.4", 512<<10)
	ref, approval, task := seedWalkUpdate(t, srv, st, data, true)
	obj, _ := st.StaticObject(agentArtifactBucket, ref.objectPath())
	packed, _ := base64.StdEncoding.DecodeString(obj.Content)
	script, payload := walkScript(t, approval, nil)
	lease := []string{"LATTICE_TASK_ID=" + task.ID, "LATTICE_TASK_LEASE_ID=" + task.LeaseID}
	packedName := agentUpdatePartialPrefix + ref.GzipSHA256
	rawName := agentUpdatePartialPrefix + ref.SHA256
	gone := func(t *testing.T, o walkOutcome, names ...string) {
		t.Helper()
		for _, name := range names {
			if _, ok := o.kept(name); ok {
				t.Fatalf("%s must not be left behind", name)
			}
		}
	}
	decompressions := func(o walkOutcome) int {
		n := 0
		for _, call := range o.calls {
			if call == "gzip -dc" {
				n++
			}
		}
		return n
	}
	for _, fetcher := range []string{"curl", "wget"} {
		run := func(t *testing.T, script string, cp, fb *walkServer, r walkRun) walkOutcome {
			t.Helper()
			r.fetcher, r.real, r.clock, r.caFile, r.env = fetcher, true, "host", walkCAFile(t, cp), lease
			r.cpURL, r.fbURL = cp.URL+ref.urlPath(), fb.URL+"/lattice-agent-linux-amd64"
			if r.overrides == nil {
				r.overrides = realWalkOverrides(60)
			}
			return runWalkScript(t, script, r)
		}
		t.Run(fetcher+"/resumes after a cut", func(t *testing.T) {
			cut := len(packed) / 3
			cp := newWalkServer(t, handler, walkBehaviour{cut: cut})
			fb := newWalkServer(t, serveBytes(data), walkBehaviour{status: http.StatusNotFound})
			overrides := realWalkOverrides(60)
			overrides["FETCH_RETRIES"] = "0"
			first := run(t, script, cp, fb, walkRun{overrides: overrides})
			kept, ok := first.kept(packedName)
			if first.exit == 0 || !ok || len(kept) == 0 || len(kept) >= len(packed) || !bytes.Equal(kept, packed[:len(kept)]) {
				t.Fatalf("the cut attempt must fail and keep a prefix of the compressed file: exit %d, kept %d of %d, stderr:\n%s", first.exit, len(kept), len(packed), first.stderr)
			}
			gone(t, first, rawName)
			if decompressions(first) != 1 {
				t.Fatalf("nothing may be decompressed before the download is complete: %q", first.calls)
			}
			cp2 := newWalkServer(t, handler)
			second := run(t, script, cp2, fb, walkRun{kept: map[string][]byte{packedName: kept}})
			if second.exit != 0 || !bytes.Equal(second.installed, data) {
				t.Fatalf("the next attempt must finish: exit %d, stderr:\n%s", second.exit, second.stderr)
			}
			seen := cp2.requests()
			if len(seen) != 1 || seen[0].Get("Range") != fmt.Sprintf("bytes=%d-", len(kept)) || seen[0].Get(agentTaskLeaseHeader) != task.LeaseID {
				t.Fatalf("the next attempt must ask for the rest of the compressed file, with the lease: %v", seen)
			}
			if want := fmt.Sprintf("1:cp.gz:0:%d:", len(packed)-len(kept)); !strings.Contains(second.summary, want) || !strings.HasSuffix(second.summary, " result:0:done") {
				t.Fatalf("summary %q, want it to contain %q", second.summary, want)
			}
			gone(t, second, packedName, rawName)
		})
		// A range request for a complete file is answered 416, which curl 7
		// reports as a failure, so a complete kept file is checked, not
		// fetched.
		t.Run(fetcher+"/a complete kept compressed file is used as it is", func(t *testing.T) {
			cp := newWalkServer(t, handler)
			fb := newWalkServer(t, serveBytes(data))
			o := run(t, script, cp, fb, walkRun{kept: map[string][]byte{packedName: packed}})
			if o.exit != 0 || !bytes.Equal(o.installed, data) || len(cp.requests())+len(fb.requests()) != 0 ||
				o.summary != "lattice-agent-fetch v1 result:0:done" {
				t.Fatalf("exit %d, requests %d and %d, summary %q, stderr:\n%s", o.exit, len(cp.requests()), len(fb.requests()), o.summary, o.stderr)
			}
		})
		t.Run(fetcher+"/a kept compressed file of full length with other bytes starts over", func(t *testing.T) {
			wrong := append([]byte(nil), packed...)
			wrong[10] ^= 0xff
			cp := newWalkServer(t, handler)
			fb := newWalkServer(t, serveBytes(data))
			o := run(t, script, cp, fb, walkRun{kept: map[string][]byte{packedName: wrong, rawName: append(data[:len(data):len(data)], 'x')}})
			if o.exit != 0 || !bytes.Equal(o.installed, data) {
				t.Fatalf("exit %d, stderr:\n%s", o.exit, o.stderr)
			}
			if seen := cp.requests(); len(seen) != 1 || seen[0].Get("Range") != "" {
				t.Fatalf("a full-length kept file that fails its digest must be dropped and fetched whole: %v", seen)
			}
		})
		t.Run(fetcher+"/a wrong compressed digest is discarded before decompression", func(t *testing.T) {
			tampered := append([]byte(nil), packed...)
			tampered[len(tampered)/2] ^= 0xff
			cp := newWalkServer(t, serveBytes(tampered))
			fb := newWalkServer(t, serveBytes(data))
			o := run(t, script, cp, fb, walkRun{})
			if o.exit != 1 || !strings.Contains(o.stderr, "compressed sha256 mismatch expected="+ref.GzipSHA256) ||
				!strings.HasSuffix(o.summary, " result:1:verify") {
				t.Fatalf("exit %d summary %q stderr:\n%s", o.exit, o.summary, o.stderr)
			}
			if decompressions(o) != 1 {
				t.Fatalf("only the gzip probe may run; the wrong file must never be decompressed: %q", o.calls)
			}
			gone(t, o, packedName, rawName)
			if o.installed != nil {
				t.Fatal("nothing may be installed")
			}
		})
		t.Run(fetcher+"/a decompressed mismatch is refused", func(t *testing.T) {
			// The compressed file passes its own digest, because the plan
			// pins it, but holds different bytes of the same size.
			other, _ := walkTestBinary("0.3.4", len(data)+1)
			evil := gzipBytes(t, other[1:])
			sum := sha256.Sum256(evil)
			s, _ := walkScript(t, approval, func(p *agentUpdatePayload) {
				p.CompressedSHA256, p.CompressedSize = hex.EncodeToString(sum[:]), len(evil)
			})
			cp := newWalkServer(t, serveBytes(evil))
			fb := newWalkServer(t, serveBytes(data))
			o := run(t, s, cp, fb, walkRun{})
			if o.exit != 1 || !strings.Contains(o.stderr, "sha256 mismatch expected="+ref.SHA256) || o.installed != nil {
				t.Fatalf("exit %d stderr:\n%s", o.exit, o.stderr)
			}
			gone(t, o, agentUpdatePartialPrefix+hex.EncodeToString(sum[:]), rawName)
		})
		t.Run(fetcher+"/an expansion past binary_size stops before it fills the disk", func(t *testing.T) {
			bomb := gzipBytes(t, make([]byte, 64<<20))
			sum := sha256.Sum256(bomb)
			s, _ := walkScript(t, approval, func(p *agentUpdatePayload) {
				p.CompressedSHA256, p.CompressedSize = hex.EncodeToString(sum[:]), len(bomb)
			})
			cp := newWalkServer(t, serveBytes(bomb))
			fb := newWalkServer(t, serveBytes(data))
			o := run(t, s, cp, fb, walkRun{})
			want := fmt.Sprintf("decompressed to %d bytes, where decompression stops at %d, not the %d bytes the plan pins", len(data)+1, len(data)+1, len(data))
			if o.exit != 1 || !strings.Contains(o.stderr, want) || !strings.HasSuffix(o.summary, " result:1:unpack") || o.installed != nil {
				t.Fatalf("exit %d summary %q stderr:\n%s", o.exit, o.summary, o.stderr)
			}
			gone(t, o, agentUpdatePartialPrefix+hex.EncodeToString(sum[:]), rawName)
		})
		t.Run(fetcher+"/a node without gzip takes the uncompressed fallback", func(t *testing.T) {
			cp := newWalkServer(t, handler)
			fb := newWalkServer(t, serveBytes(data))
			o := run(t, script, cp, fb, walkRun{noGzip: true})
			if o.exit != 0 || !bytes.Equal(o.installed, data) || len(cp.requests()) != 0 ||
				!strings.Contains(o.stderr, "skips the compressed control-plane download") {
				t.Fatalf("exit %d, control-plane requests %d, stderr:\n%s", o.exit, len(cp.requests()), o.stderr)
			}
			if want := fmt.Sprintf("lattice-agent-fetch v1 2:up:0:%d:", len(data)); !strings.HasPrefix(o.summary, want) {
				t.Fatalf("summary %q", o.summary)
			}
			if fb.requests()[0].Get(agentTaskLeaseHeader) != "" {
				t.Fatal("the fallback must carry no lease")
			}
		})
		t.Run(fetcher+"/without gzip or a fallback the task says why it fails", func(t *testing.T) {
			s, _ := walkScript(t, approval, func(p *agentUpdatePayload) { p.FallbackURL = "" })
			cp := newWalkServer(t, handler)
			fb := newWalkServer(t, serveBytes(data))
			o := run(t, s, cp, fb, walkRun{noGzip: true})
			if o.exit != 1 || !strings.Contains(o.stderr, "no download source in this plan works on this node") ||
				o.summary != "lattice-agent-fetch v1 result:1:fetch" || len(cp.requests()) != 0 {
				t.Fatalf("exit %d summary %q stderr:\n%s", o.exit, o.summary, o.stderr)
			}
		})
	}
	// A wget-only node, timeout used when it exists, through the whole
	// script to the restart.
	t.Run("wget only", func(t *testing.T) {
		cp := newWalkServer(t, handler)
		fb := newWalkServer(t, serveBytes(data))
		o := runWalkScript(t, script, walkRun{fetcher: "wget", real: true, clock: "host", caFile: walkCAFile(t, cp),
			cpURL: cp.URL + ref.urlPath(), fbURL: fb.URL + "/lattice-agent-linux-amd64", timeout: true,
			overrides: realWalkOverrides(60), env: lease})
		if o.exit != 0 || !bytes.Equal(o.installed, data) {
			t.Fatalf("exit %d stderr:\n%s", o.exit, o.stderr)
		}
		if want := fmt.Sprintf("lattice-agent-fetch v1 1:cp.gz:0:%d:", len(packed)); !strings.HasPrefix(o.summary, want) || !strings.HasSuffix(o.summary, " result:0:done") {
			t.Fatalf("summary %q", o.summary)
		}
		bounded := false
		for _, call := range o.calls {
			if strings.HasPrefix(call, "timeout 60 wget ") && strings.Contains(call, "--max-redirect=0") {
				bounded = true
			}
		}
		if !bounded {
			t.Fatalf("wget must run inside the budget: %q", o.calls)
		}
		if !strings.Contains(strings.Join(o.calls, "\n"), "systemd-run --unit=lattice-agent-delayed-restart-") {
			t.Fatalf("the update must reach its restart: %q", o.calls)
		}
		if payload.CompressedSHA256 != ref.GzipSHA256 {
			t.Fatal("the run must be of the compressed plan")
		}
	})
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
