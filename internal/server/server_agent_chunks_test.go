package server

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Design 31, S5: the chunk manifest. After each fetch the script holds every
// chunk that fetch finished to the plan's manifest and cuts the download back
// to the first chunk that fails, so a source that sends wrong bytes loses its
// own and at most the chunk in flight, never what came before. A source
// whose bytes failed is never given the second pass.

// corrupt returns data with every byte from offset on flipped.
func corrupt(data []byte, offset int) []byte {
	out := append([]byte(nil), data...)
	for i := offset; i < len(out); i++ {
		out[i] ^= 0x5a
	}
	return out
}

// chunkWalk plans an update with a mirror at the given place and returns
// the script, the payload and the binary.
func chunkWalk(t *testing.T, size int, preferred, compressed bool) (string, agentUpdatePayload, []byte) {
	t.Helper()
	srv, _, st := newAgentArtifactServer(t)
	data, _ := walkTestBinary("0.3.4", size)
	m := model.AgentMirror{ID: "r2", BaseURL: mirrorTestBase, Priority: 1, Enabled: true}
	if preferred {
		m.PreferFor = []string{"node-a"}
	} else {
		m.Global = true
	}
	seedAgentMirrors(t, st, m)
	_, approval, _ := seedWalkUpdate(t, srv, st, data, compressed)
	script, payload := walkScript(t, approval, nil)
	if payload.ChunkManifest == nil {
		t.Fatal("a plan that lists a mirror must carry the manifest")
	}
	return script, payload, data
}

func mirrorURLOf(payload agentUpdatePayload) string {
	for _, src := range payload.Sources {
		if src.Kind == model.AgentSourceKindMirror {
			return src.URL
		}
	}
	return ""
}

// A mirror that sends wrong bytes after honest progress loses only its own
// bytes and the chunk in flight, and the next source finishes.
func TestAgentUpdateWalkCutsAMirrorBackToItsLastGoodChunk(t *testing.T) {
	const c = agentChunkSize
	script, payload, data := chunkWalk(t, 4*c+1000, false, false)
	if got := strings.Join(sourceLabels(payload.Sources), ","); got != "control-plane,mirror:r2,upstream" {
		t.Fatalf("a global mirror comes after the control plane, got %s", got)
	}
	run := func(cpSteps, mSteps, fbSteps string) walkOutcome {
		return runWalkScript(t, script, walkRun{
			fetcher: "curl",
			cpURL:   payload.BinaryURL, cpBody: data, cpSteps: cpSteps,
			m1URL: mirrorURLOf(payload), m1Body: corrupt(data, 600000), m1Steps: mSteps,
			fbURL: payload.FallbackURL, fbBody: data, fbSteps: fbSteps,
		})
	}
	// The control plane sends a chunk and a half and is cut. The mirror's
	// first chunk is honest and its second is not: the walk keeps the
	// control plane's whole chunk and the mirror's good one, drops the rest,
	// and the release finishes from there.
	o := run("28:400000:30", "28:900000:30", "0:0:5")
	if o.exit != 0 || !bytes.Equal(o.installed, data) {
		t.Fatalf("exit %d, installed %d bytes, stderr:\n%s", o.exit, len(o.installed), o.stderr)
	}
	want := fmt.Sprintf("lattice-agent-fetch v1 1:cp:28:400000:30 2:m.r2:28:%d:30:x1 3:up:0:%d:5 result:0:done", c, len(data)-2*c)
	if o.summary != want {
		t.Fatalf("summary %q, want %q, stderr:\n%s", o.summary, want, o.stderr)
	}
	ups := o.fetches("curl")
	if len(ups) != 3 {
		t.Fatalf("want three fetches, got %q", ups)
	}
	if !strings.Contains(o.stderr, "failed the plan's chunk manifest") {
		t.Fatalf("the output must say a chunk failed, stderr:\n%s", o.stderr)
	}

	// When nothing finishes, what is kept is exactly the bytes that passed:
	// the control plane's chunk and the mirror's good one.
	o = run("28:400000:30 22:-1:1", "28:900000:30", "22:-1:1")
	if o.exit == 0 {
		t.Fatalf("nothing finished, yet the walk succeeded: %s", o.summary)
	}
	kept, ok := o.kept(agentUpdatePartialPrefix + payload.SHA256)
	if !ok || !bytes.Equal(kept, data[:2*c]) {
		t.Fatalf("kept %d bytes (%t), want the %d that passed the manifest", len(kept), ok, 2*c)
	}
	// The second pass went to the control plane, the source whose bytes
	// survived, never to the mirror whose bytes failed.
	if f := summaryFields(t, o.summary); len(f) < 4 || f[3][0] != "p2" || f[3][1] != "cp" {
		t.Fatalf("the second pass must go to the control plane: %q", o.summary)
	}
}

// A mirror listed first that sends wrong bytes from its first byte loses all
// of them, at full speed or not, and the control plane finishes.
func TestAgentUpdateWalkDropsALyingMirrorListedFirst(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(fmt.Sprintf("compressed=%t", compressed), func(t *testing.T) {
			script, payload, data := chunkWalk(t, 3*agentChunkSize+77, true, compressed)
			if got := strings.Join(sourceLabels(payload.Sources), ","); got != "mirror:r2,control-plane,upstream" {
				t.Fatalf("a preferred mirror comes first, got %s", got)
			}
			cpBody := data
			if compressed {
				packed, err := gzipAgentArtifact(data)
				if err != nil {
					t.Fatal(err)
				}
				cpBody = packed
			}
			o := runWalkScript(t, script, walkRun{
				fetcher: "curl",
				m1URL:   mirrorURLOf(payload), m1Body: corrupt(data, 0), m1Steps: "0:0:1",
				cpURL: payload.BinaryURL, cpBody: cpBody, cpSteps: "0:0:5",
				fbURL: payload.FallbackURL, fbBody: data,
			})
			if o.exit != 0 || !bytes.Equal(o.installed, data) {
				t.Fatalf("exit %d, installed %d bytes, stderr:\n%s", o.exit, len(o.installed), o.stderr)
			}
			kind := "cp"
			if compressed {
				kind = "cp.gz"
			}
			want := fmt.Sprintf("lattice-agent-fetch v1 1:m.r2:0:0:1:x1 2:%s:0:%d:5 result:0:done", kind, len(cpBody))
			if o.summary != want {
				t.Fatalf("summary %q, want %q, stderr:\n%s", o.summary, want, o.stderr)
			}
		})
	}
}

// A fast liar never wins the second pass: a mirror honest for three chunks
// and then not delivers the most surviving bytes, and still the second pass
// goes to a source whose bytes all passed.
func TestAgentUpdateWalkFastLiarNeverWinsTheSecondPass(t *testing.T) {
	const c = agentChunkSize
	script, payload, data := chunkWalk(t, 6*c+500, true, false)
	o := runWalkScript(t, script, walkRun{
		fetcher: "curl",
		m1URL:   mirrorURLOf(payload), m1Body: corrupt(data, 3*c+10), m1Steps: "0:0:1",
		cpURL: payload.BinaryURL, cpBody: data, cpSteps: "28:900000:30",
		fbURL: payload.FallbackURL, fbBody: data, fbSteps: "28:950000:30 0:0:5",
	})
	if o.exit != 0 || !bytes.Equal(o.installed, data) {
		t.Fatalf("exit %d, installed %d bytes, stderr:\n%s", o.exit, len(o.installed), o.stderr)
	}
	// The control plane's unchecked tail is cut back when the release takes
	// over, so the release continues from the mirror's last good chunk.
	want := fmt.Sprintf("lattice-agent-fetch v1 1:m.r2:0:%d:1:x1 2:cp:28:%d:30 3:up:28:%d:30 p2:up:0:%d:5 result:0:done",
		3*c, 900000-3*c, 950000-3*c, len(data)-950000)
	if o.summary != want {
		t.Fatalf("summary %q, want %q, stderr:\n%s", o.summary, want, o.stderr)
	}
	for _, call := range o.fetches("curl")[3:] {
		if strings.HasSuffix(call, mirrorURLOf(payload)) {
			t.Fatalf("the liar was fetched again: %s", call)
		}
	}
}

// A kept file from an earlier attempt is held to the manifest before the
// walk continues it: a bad chunk in it is cut away, and so is the unchecked
// tail, which no source of this attempt wrote.
func TestAgentUpdateWalkChecksAKeptFileAgainstTheManifest(t *testing.T) {
	const c = agentChunkSize
	script, payload, data := chunkWalk(t, 3*c+300, true, false)
	kept := append(append(append([]byte(nil), data[:c]...), corrupt(data[c:2*c], 0)...), data[2*c:2*c+1000]...)
	o := runWalkScript(t, script, walkRun{
		fetcher: "curl",
		m1URL:   mirrorURLOf(payload), m1Body: data, m1Steps: "0:0:4",
		cpURL: payload.BinaryURL, cpBody: data,
		fbURL: payload.FallbackURL, fbBody: data,
		kept: map[string][]byte{agentUpdatePartialPrefix + payload.SHA256: kept},
	})
	if o.exit != 0 || !bytes.Equal(o.installed, data) {
		t.Fatalf("exit %d, installed %d bytes, stderr:\n%s", o.exit, len(o.installed), o.stderr)
	}
	if want := fmt.Sprintf("lattice-agent-fetch v1 1:m.r2:0:%d:4 result:0:done", len(data)-c); o.summary != want {
		t.Fatalf("summary %q, want %q, stderr:\n%s", o.summary, want, o.stderr)
	}
	// A mirror that appends bytes past the pinned size is marked, and the
	// file is cut back to its pinned size.
	o = runWalkScript(t, script, walkRun{
		fetcher: "curl",
		m1URL:   mirrorURLOf(payload), m1Body: append(append([]byte(nil), data...), "trailing"...), m1Steps: "0:0:4",
		cpURL: payload.BinaryURL, cpBody: data, fbURL: payload.FallbackURL, fbBody: data,
	})
	if o.exit != 0 || !bytes.Equal(o.installed, data) || !strings.Contains(o.summary, ":x1 ") {
		t.Fatalf("exit %d summary %q stderr:\n%s", o.exit, o.summary, o.stderr)
	}
}

// A node where dd does not work cannot hold a mirror to the manifest, so it
// skips the mirrors and walks the other sources, and says so.
func TestAgentUpdateWalkSkipsMirrorsWithoutDD(t *testing.T) {
	script, payload, data := chunkWalk(t, 2*agentChunkSize+10, true, false)
	o := runWalkScript(t, script, walkRun{
		fetcher: "curl", without: []string{"dd"},
		m1URL: mirrorURLOf(payload), m1Body: data,
		cpURL: payload.BinaryURL, cpBody: data, cpSteps: "0:0:5",
		fbURL: payload.FallbackURL, fbBody: data,
	})
	if o.exit != 0 || !bytes.Equal(o.installed, data) {
		t.Fatalf("exit %d stderr:\n%s", o.exit, o.stderr)
	}
	if want := fmt.Sprintf("lattice-agent-fetch v1 2:cp:0:%d:5 result:0:done", len(data)); o.summary != want {
		t.Fatalf("summary %q, want %q", o.summary, want)
	}
	if !strings.Contains(o.stderr, "skips the mirrors") {
		t.Fatalf("the output must say why the mirrors were skipped, stderr:\n%s", o.stderr)
	}
}

// The walk with the host's curl and dd against real TLS servers: a mirror
// that answers ranges and lies after its first chunk, and the control plane.
func TestAgentUpdateWalkWithAMirrorAgainstRealSources(t *testing.T) {
	const c = agentChunkSize
	srv, handler, st := newAgentArtifactServer(t)
	data, _ := walkTestBinary("0.3.4", 4*c+123)
	seedAgentMirrors(t, st, model.AgentMirror{ID: "r2", BaseURL: mirrorTestBase, PreferFor: []string{"node-a"}, Priority: 1, Enabled: true})
	ref, approval, task := seedWalkUpdate(t, srv, st, data, false)
	script, payload := walkScript(t, approval, nil)
	mirror := newWalkServer(t, serveBytes(corrupt(data, c+5)))
	cp := newWalkServer(t, handler)
	fb := newWalkServer(t, serveBytes(data))
	o := runWalkScript(t, script, walkRun{fetcher: "curl", real: true, clock: "host", caFile: walkCAFile(t, cp),
		m1URL: mirror.URL + "/0.3.4/linux/amd64/" + payload.SHA256,
		cpURL: cp.URL + ref.urlPath(), fbURL: fb.URL + "/lattice-agent-linux-amd64",
		overrides: realWalkOverrides(60), env: []string{"LATTICE_TASK_ID=" + task.ID, "LATTICE_TASK_LEASE_ID=" + task.LeaseID}})
	if o.exit != 0 || !bytes.Equal(o.installed, data) {
		t.Fatalf("exit %d, installed %d bytes, stderr:\n%s", o.exit, len(o.installed), o.stderr)
	}
	f := summaryFields(t, o.summary)
	if len(f) != 3 || f[0][1] != "m.r2" || f[0][3] != fmt.Sprint(c) || len(f[0]) != 6 || f[0][5] != "x1" || f[1][1] != "cp" || f[1][2] != "0" {
		t.Fatalf("want the mirror cut back to one chunk and marked, then the control plane finishing: %q", o.summary)
	}
	ms, cps := mirror.requests(), cp.requests()
	if len(ms) != 1 || ms[0].Get(agentTaskLeaseHeader) != "" || ms[0].Get(agentTaskIDHeader) != "" {
		t.Fatalf("the mirror must be asked once and never see the lease: %v", ms)
	}
	if len(cps) != 1 || cps[0].Get("Range") != fmt.Sprintf("bytes=%d-", c) || cps[0].Get(agentTaskLeaseHeader) != task.LeaseID {
		t.Fatalf("the control plane must continue from the mirror's good chunk, with the lease: %v", cps)
	}
}

// wget's own timeouts reset on every read, so a mirror fetched with wget runs
// under timeout with an equal share of the budget, and a node without a
// working timeout skips the mirrors rather than let one hold the budget.
func TestAgentUpdateWalkBoundsAMirrorFetchedWithWget(t *testing.T) {
	script, payload, data := chunkWalk(t, 2*agentChunkSize+10, true, false)
	run := func(r walkRun) walkOutcome {
		r.fetcher = "wget"
		r.m1URL, r.m1Body = mirrorURLOf(payload), data
		r.cpURL, r.cpBody, r.fbURL, r.fbBody = payload.BinaryURL, data, payload.FallbackURL, data
		return runWalkScript(t, script, r)
	}
	o := run(walkRun{timeout: true, m1Steps: "4:500:50", cpSteps: "0:0:5"})
	if o.exit != 0 || !bytes.Equal(o.installed, data) {
		t.Fatalf("exit %d stderr:\n%s", o.exit, o.stderr)
	}
	var bounded []string
	for _, call := range o.calls {
		if strings.HasPrefix(call, "timeout ") && !strings.HasPrefix(call, "timeout 5 true") {
			bounded = append(bounded, call)
		}
	}
	// Three sources: the mirror gets a third of 480 s, and the control
	// plane, which wget fetches once, all that is left after it.
	if len(bounded) != 2 || !strings.HasPrefix(bounded[0], "timeout 160 wget ") || !strings.HasPrefix(bounded[1], "timeout 430 wget ") {
		t.Fatalf("a wget mirror must get an equal share under timeout: %q", bounded)
	}
	o = run(walkRun{m1Steps: "0:0:1", cpSteps: "0:0:5"})
	if o.exit != 0 || !bytes.Equal(o.installed, data) {
		t.Fatalf("exit %d stderr:\n%s", o.exit, o.stderr)
	}
	if want := fmt.Sprintf("lattice-agent-fetch v1 2:cp:0:%d:5 result:0:done", len(data)); o.summary != want {
		t.Fatalf("summary %q, want %q", o.summary, want)
	}
	if !strings.Contains(o.stderr, "no timeout command to bound a wget fetch") {
		t.Fatalf("the output must say why the mirrors were skipped, stderr:\n%s", o.stderr)
	}
}

// A mirror that streams far past the pinned size is stopped by the file-size
// cap, marked and cut back, and the walk still installs the honest bytes it
// sent.
func TestAgentUpdateWalkCapsAMirrorThatStreamsPastTheSize(t *testing.T) {
	const c = agentChunkSize
	script, payload, data := chunkWalk(t, 2*c+10, true, false)
	flood := append(append([]byte(nil), data...), make([]byte, 16*c)...)
	o := runWalkScript(t, script, walkRun{
		fetcher: "curl",
		m1URL:   mirrorURLOf(payload), m1Body: flood, m1Steps: "0:0:1",
		cpURL: payload.BinaryURL, cpBody: data, cpSteps: "0:0:5",
		fbURL: payload.FallbackURL, fbBody: data,
	})
	if o.exit != 0 || !bytes.Equal(o.installed, data) || !strings.HasPrefix(o.summary, "lattice-agent-fetch v1 1:m.r2:") || !strings.Contains(o.summary, ":x1") {
		t.Fatalf("exit %d summary %q stderr:\n%s", o.exit, o.summary, o.stderr)
	}
}

// The cap a mirror fetch runs under stops a write that runs past it, in the
// shell the tests run under (dash, busybox ash or macOS sh).
func TestAgentWalkFileCapStopsAnOverrun(t *testing.T) {
	f := filepath.Join(t.TempDir(), "partial")
	err := exec.Command("sh", "-c", "FETCH_FCAP=16\n"+agentWalkFileCap+"head -c 1048576 /dev/zero >\"$1\" )", "sh", f).Run()
	info, statErr := os.Stat(f)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if err == nil || info.Size() == 0 || info.Size() > 16*1024 {
		t.Fatalf("exit %v, wrote %d bytes; a cap of 16 blocks must stop the write with an error", err, info.Size())
	}
}

// A shell that cannot set the file-size cap, here under an inherited hard
// limit below it, never fetches a mirror: it says why and walks the other
// sources as before.
func TestAgentUpdateWalkSkipsMirrorsItCannotCap(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the update script raises the hard limit again when it runs as root")
	}
	const c = agentChunkSize
	script, payload, data := chunkWalk(t, 2*c+10, true, false)
	// Room for the binary, not for the cap one chunk past it.
	limit := (len(data)+c/2)/512 + 1
	o := runWalkScript(t, script, walkRun{
		fetcher: "curl", fileLimit: limit,
		m1URL: mirrorURLOf(payload), m1Body: data,
		cpURL: payload.BinaryURL, cpBody: data, cpSteps: "0:0:5",
		fbURL: payload.FallbackURL, fbBody: data,
	})
	if o.exit != 0 || !bytes.Equal(o.installed, data) {
		t.Fatalf("exit %d stderr:\n%s", o.exit, o.stderr)
	}
	if want := fmt.Sprintf("lattice-agent-fetch v1 2:cp:0:%d:5 result:0:done", len(data)); o.summary != want {
		t.Fatalf("summary %q, want %q", o.summary, want)
	}
	for _, call := range o.fetches("curl") {
		if strings.HasSuffix(call, mirrorURLOf(payload)) {
			t.Fatalf("the mirror was fetched uncapped: %s", call)
		}
	}
	if !strings.Contains(o.stderr, "this shell cannot cap a download at") {
		t.Fatalf("the output must say why the mirrors were skipped, stderr:\n%s", o.stderr)
	}
}
