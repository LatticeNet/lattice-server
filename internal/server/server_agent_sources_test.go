package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Design 31, S5: the payload's source list, how it is validated, and what the
// script and the plan make of it.

// mirrorPlanFixture plans an update for node-a from a stored artifact with a
// mirror preferred for the node, so the plan reads mirror, control plane,
// upstream, with the manifest.
func mirrorPlanFixture(t *testing.T, size int, compressed bool) (*Server, *store.Store, []byte, model.Approval, agentUpdatePayload) {
	t.Helper()
	srv, _, st := newAgentArtifactServer(t)
	data, _ := walkTestBinary("0.3.4", size)
	seedAgentMirrors(t, st, model.AgentMirror{ID: "r2", BaseURL: mirrorTestBase, PreferFor: []string{"node-a"}, Priority: 1, Enabled: true})
	_, approval, _ := seedWalkUpdate(t, srv, st, data, compressed)
	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	if want := "mirror:r2,control-plane,upstream"; strings.Join(sourceLabels(payload.Sources), ",") != want || payload.ChunkManifest == nil {
		t.Fatalf("fixture plan sources %q manifest %v, want %s with a manifest", sourceLabels(payload.Sources), payload.ChunkManifest, want)
	}
	return srv, st, data, approval, payload
}

// withPayload is approval carrying payload, the way a tampered or stale
// action would arrive.
func withPayload(approval model.Approval, payload agentUpdatePayload) model.Approval {
	approval.Action = agentUpdateApprovalAction(payload)
	return approval
}

func cloneSources(in []model.AgentUpdateSource) []model.AgentUpdateSource {
	return append([]model.AgentUpdateSource(nil), in...)
}

// A payload with two control-plane entries, a wrong control-plane URL, more
// than four entries or upstream not last is refused, and so is every other
// shape the server never plans.
func TestAgentUpdateSourcesValidation(t *testing.T) {
	_, _, _, approval, base := mirrorPlanFixture(t, 2*agentChunkSize+10, false)
	mirror, cp, up := base.Sources[0], base.Sources[1], base.Sources[2]
	otherMirror := mirror
	otherMirror.Mirror = "r3"
	otherMirror.URL = strings.Replace(mirror.URL, "dl.example.org", "r3.example.org", 1)
	for _, tc := range []struct {
		name   string
		mutate func(p *agentUpdatePayload)
		// render marks a payload the decoder accepts and the renderer, which
		// knows the control plane's own base, refuses.
		render bool
	}{
		{"two control-plane entries", func(p *agentUpdatePayload) { p.Sources = []model.AgentUpdateSource{mirror, cp, cp, up} }, false},
		{"a control-plane entry that is not binary_url", func(p *agentUpdatePayload) {
			p.Sources = cloneSources(p.Sources)
			p.Sources[1].URL = artifactTestPublicURL + agentBinaryPathPrefix + "0.3.4/linux/amd64/" + strings.Repeat("c", 64)
		}, false},
		{"a control-plane URL on another host", func(p *agentUpdatePayload) {
			p.Sources = cloneSources(p.Sources)
			p.Sources[1].URL = strings.Replace(cp.URL, artifactTestPublicURL, "https://evil.example", 1)
			p.BinaryURL = p.Sources[1].URL
		}, true},
		{"a control-plane URL for other bytes", func(p *agentUpdatePayload) {
			p.Sources = cloneSources(p.Sources)
			p.Sources[1].URL = artifactTestPublicURL + agentBinaryPathPrefix + "0.3.4/linux/amd64/" + strings.Repeat("c", 64)
			p.BinaryURL = p.Sources[1].URL
		}, false},
		{"more than four entries", func(p *agentUpdatePayload) {
			r4, r5 := otherMirror, otherMirror
			r4.Mirror, r5.Mirror = "r4", "r5"
			r4.URL = strings.Replace(mirror.URL, "dl.example.org", "r4.example.org", 1)
			r5.URL = strings.Replace(mirror.URL, "dl.example.org", "r5.example.org", 1)
			p.Sources = []model.AgentUpdateSource{mirror, otherMirror, r4, r5, cp, up}
		}, false},
		{"upstream not last", func(p *agentUpdatePayload) { p.Sources = []model.AgentUpdateSource{mirror, up, cp} }, false},
		{"two upstream entries", func(p *agentUpdatePayload) { p.Sources = []model.AgentUpdateSource{up, cp, up} }, false},
		{"an unknown kind", func(p *agentUpdatePayload) {
			p.Sources = cloneSources(p.Sources)
			p.Sources[0].Kind = "peer"
		}, false},
		{"a mirror without a manifest", func(p *agentUpdatePayload) { p.ChunkManifest = nil }, false},
		{"a manifest without a mirror", func(p *agentUpdatePayload) { p.Sources = []model.AgentUpdateSource{cp, up} }, false},
		{"a manifest whose size does not match its chunks", func(p *agentUpdatePayload) {
			m := *p.ChunkManifest
			m.Size += agentChunkSize
			p.ChunkManifest = &m
		}, false},
		{"a manifest with a short digest list", func(p *agentUpdatePayload) {
			m := *p.ChunkManifest
			m.Chunks = m.Chunks[:len(m.Chunks)-64]
			p.ChunkManifest = &m
		}, false},
		{"a manifest with another chunk size", func(p *agentUpdatePayload) {
			m := *p.ChunkManifest
			m.ChunkSize = 1 << 20
			p.ChunkManifest = &m
		}, false},
		{"an invalid mirror id", func(p *agentUpdatePayload) {
			p.Sources = cloneSources(p.Sources)
			p.Sources[0].Mirror = "R2;x"
		}, false},
		{"the same mirror twice", func(p *agentUpdatePayload) { p.Sources = []model.AgentUpdateSource{mirror, mirror, cp, up} }, false},
		{"a mirror URL that does not name the pinned digest", func(p *agentUpdatePayload) {
			p.Sources = cloneSources(p.Sources)
			p.Sources[0].URL = mirrorTestBase + "/0.3.4/linux/amd64/" + strings.Repeat("d", 64)
		}, false},
		{"a mirror URL for another version", func(p *agentUpdatePayload) {
			p.Sources = cloneSources(p.Sources)
			p.Sources[0].URL = mirrorTestBase + "/0.3.5/linux/amd64/" + p.SHA256
		}, false},
		{"plain http on a mirror", func(p *agentUpdatePayload) {
			p.Sources = cloneSources(p.Sources)
			p.Sources[0].URL = strings.Replace(mirror.URL, "https://", "http://", 1)
		}, false},
		{"shell syntax in a mirror URL", func(p *agentUpdatePayload) {
			p.Sources = cloneSources(p.Sources)
			p.Sources[0].URL = mirrorTestBase + "/$(reboot)/0.3.4/linux/amd64/" + p.SHA256
		}, false},
		{"upstream that is not the fallback", func(p *agentUpdatePayload) {
			p.Sources = cloneSources(p.Sources)
			p.Sources[2].URL = "https://elsewhere.example.com/agent"
		}, false},
		{"a fallback with no upstream entry", func(p *agentUpdatePayload) { p.Sources = []model.AgentUpdateSource{mirror, cp} }, false},
		{"a control-plane plan without its entry", func(p *agentUpdatePayload) { p.Sources = []model.AgentUpdateSource{mirror, up} }, false},
		{"a control character in a reason", func(p *agentUpdatePayload) {
			p.Sources = cloneSources(p.Sources)
			p.Sources[0].Reason = "fine\nSafety: none"
		}, false},
		{"sources without resume", func(p *agentUpdatePayload) { p.ResumeDownload = false }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := base
			tc.mutate(&payload)
			tampered := withPayload(approval, payload)
			_, decodeErr := agentUpdatePayloadFromApproval(tampered)
			_, renderErr := agentUpdateApplyScript(tampered, artifactTestPublicURL)
			if tc.render {
				if decodeErr != nil {
					t.Fatalf("the decoder cannot know the control plane's base and must leave this to the renderer: %v", decodeErr)
				}
				if renderErr == nil {
					t.Fatal("the renderer must refuse a control-plane entry it did not compute")
				}
				return
			}
			if decodeErr == nil {
				t.Fatal("the payload must be refused")
			}
			if renderErr == nil {
				t.Fatal("a refused payload must not render")
			}
		})
	}
	// The plan as made decodes and renders.
	if _, err := agentUpdateApplyScript(approval, artifactTestPublicURL); err != nil {
		t.Fatalf("the plan as made must render: %v", err)
	}
	// A compressed plan pins the binary's size, and the manifest must
	// describe exactly that many bytes.
	_, _, _, packed, packedPayload := mirrorPlanFixture(t, 2*agentChunkSize+10, true)
	m := *packedPayload.ChunkManifest
	m.Size++
	packedPayload.ChunkManifest = &m
	if _, err := agentUpdatePayloadFromApproval(withPayload(packed, packedPayload)); err == nil {
		t.Fatal("a manifest of another size than binary_size must be refused")
	}
}

// The lease appears exactly once per fetcher, on the server-computed
// control-plane entry, and never on a mirror entry, even one that points at
// the control plane's host.
func TestAgentUpdateSourcesSendTheLeaseOnlyToTheControlPlaneEntry(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(fmt.Sprintf("compressed=%t", compressed), func(t *testing.T) {
			_, _, _, approval, payload := mirrorPlanFixture(t, 2*agentChunkSize+10, compressed)
			check := func(t *testing.T, approval model.Approval) {
				t.Helper()
				script, err := agentUpdateApplyScript(approval, artifactTestPublicURL)
				if err != nil {
					t.Fatal(err)
				}
				leased := 0
				for _, line := range strings.Split(script, "\n") {
					line = strings.TrimSpace(line)
					if !strings.HasPrefix(line, "curl ") && !strings.HasPrefix(line, "fetch_bounded wget ") {
						continue
					}
					if strings.Contains(line, agentTaskLeaseHeader) || strings.Contains(line, agentTaskIDHeader) {
						leased++
						if !strings.HasSuffix(line, " \"$URL\"") {
							t.Fatalf("the lease went to a line that is not the control plane's: %s", line)
						}
					}
				}
				if leased != 2 {
					t.Fatalf("want one leased curl line and one leased wget line, found %d:\n%s", leased, script)
				}
			}
			check(t, approval)
			// A mirror entry whose URL is on the control plane's host is
			// still a mirror: it gets no lease. The registry refuses such a
			// base, so only a tampered payload can carry one.
			tampered := payload
			tampered.Sources = cloneSources(payload.Sources)
			tampered.Sources[0].URL = artifactTestPublicURL + "/0.3.4/linux/amd64/" + payload.SHA256
			approval = withPayload(approval, tampered)
			if _, err := agentUpdatePayloadFromApproval(approval); err != nil {
				t.Fatalf("this test needs the tampered payload to decode: %v", err)
			}
			check(t, approval)
		})
	}
}

// Mirror lines never follow a redirect: curl gets no -L and wget gets
// --max-redirect=0, which the upstream line does not need. Both run under the
// file-size cap, so a mirror cannot fill the disk before the chunk check.
func TestAgentUpdateMirrorLinesNeverFollowRedirects(t *testing.T) {
	_, _, _, approval, _ := mirrorPlanFixture(t, 2*agentChunkSize+10, false)
	script, err := agentUpdateApplyScript(approval, artifactTestPublicURL)
	if err != nil {
		t.Fatal(err)
	}
	const capped = agentWalkFileCap
	if !strings.Contains(script, fmt.Sprintf("FETCH_FCAP=%d\n", (2*agentChunkSize+10+agentChunkSize)/512+1)) {
		t.Fatalf("the walk sets no file-size cap one chunk past the pinned size:\n%s", script)
	}
	var curl, wget int
	for _, line := range strings.Split(script, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "\"$MIRROR_URL_1\"") {
			continue
		}
		inner, ok := strings.CutPrefix(line, capped)
		if inner, ok = strings.CutSuffix(inner, " )"); !ok || !strings.HasPrefix(line, capped) {
			t.Fatalf("a mirror fetch must run under the file-size cap: %s", line)
		}
		line = inner
		switch {
		case strings.HasPrefix(line, "curl "):
			curl++
			if strings.Contains(line, " -fsSL ") || strings.Contains(line, " -L ") || !strings.Contains(line, "--proto '=https'") {
				t.Fatalf("a mirror's curl line must not follow redirects and must stay on HTTPS: %s", line)
			}
		case strings.HasPrefix(line, "fetch_bounded wget "):
			wget++
			if !strings.Contains(line, " --max-redirect=0 ") || !strings.Contains(line, " --https-only ") {
				t.Fatalf("a mirror's wget line must carry --max-redirect=0 and --https-only: %s", line)
			}
		}
	}
	if curl != 1 || wget != 1 {
		t.Fatalf("want one curl and one wget line for the mirror, found %d and %d:\n%s", curl, wget, script)
	}
}

// The injection table: nothing operator-entered reaches the script except
// through validation and shellQuote. A URL, a version or a mirror id that
// carries shell syntax is either refused or arrives as one quoted word.
func TestAgentUpdateSourcesInjectionTable(t *testing.T) {
	_, _, data, approval, base := mirrorPlanFixture(t, 2*agentChunkSize+10, false)
	for _, tc := range []struct {
		name    string
		mutate  func(p *agentUpdatePayload)
		refused bool
	}{
		{"command substitution in the upstream URL", func(p *agentUpdatePayload) {
			p.FallbackURL = "https://downloads.example.com/$(touch$IFS'pwned-up')/it's"
			p.Sources = cloneSources(p.Sources)
			p.Sources[2].URL = p.FallbackURL
		}, false},
		{"command substitution in a mirror URL", func(p *agentUpdatePayload) {
			p.Sources = cloneSources(p.Sources)
			p.Sources[0].URL = "https://dl.example.org/$(touch$IFS'pwned-m')/0.3.4/linux/amd64/" + p.SHA256
		}, true},
		{"a quote in a mirror URL", func(p *agentUpdatePayload) {
			p.Sources = cloneSources(p.Sources)
			p.Sources[0].URL = "https://dl.example.org/it's/0.3.4/linux/amd64/" + p.SHA256
		}, true},
		{"shell syntax in the mirror id", func(p *agentUpdatePayload) {
			p.Sources = cloneSources(p.Sources)
			p.Sources[0].Mirror = "r2$(touch pwned-id)"
		}, true},
		{"a newline in the mirror id", func(p *agentUpdatePayload) {
			p.Sources = cloneSources(p.Sources)
			p.Sources[0].Mirror = "r2\ntouch pwned-id"
		}, true},
		{"shell syntax in the version", func(p *agentUpdatePayload) { p.TargetVersion = "0.3.4;touch pwned-v" }, true},
		{"command substitution in the version", func(p *agentUpdatePayload) { p.TargetVersion = "$(touch pwned-v)" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := base
			tc.mutate(&payload)
			tampered := withPayload(approval, payload)
			decoded, err := agentUpdatePayloadFromApproval(tampered)
			if tc.refused {
				if err == nil {
					t.Fatalf("must be refused, decoded %+v", decoded.Sources)
				}
				if _, err := agentUpdateApplyScript(tampered, artifactTestPublicURL); err == nil {
					t.Fatal("a refused payload rendered")
				}
				return
			}
			if err != nil {
				t.Fatalf("the URL must survive validation for this case to mean anything: %v", err)
			}
			script, err := agentUpdateApplyScript(tampered, artifactTestPublicURL)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(script, "\nFALLBACK_URL="+shellQuote(decoded.FallbackURL)+"\n") {
				t.Fatalf("the URL must be assigned single-quoted:\n%s", script)
			}
			o := runWalkScript(t, script, walkRun{
				fetcher: "curl", m1URL: decoded.Sources[0].URL, m1Body: data, m1Steps: "22:-1:1",
				cpURL: decoded.BinaryURL, cpBody: data, cpSteps: "22:-1:1",
				fbURL: decoded.FallbackURL, fbBody: data,
			})
			for _, name := range []string{"pwned-up", "pwned-m", "pwned-id", "pwned-v"} {
				if _, err := os.Stat(filepath.Join(filepath.Dir(o.installDir), name)); err == nil {
					t.Fatalf("a value ran a command on the node and created %s", name)
				}
			}
			if o.exit != 0 {
				t.Fatalf("exit %d stderr:\n%s", o.exit, o.stderr)
			}
			if last := o.fetches("curl"); len(last) == 0 || !strings.HasSuffix(last[len(last)-1], decoded.FallbackURL) {
				t.Fatalf("the fetcher must receive the URL verbatim: %q", last)
			}
		})
	}
}

// The equality function covers every field of the payload, sources and the
// manifest included, and the change summary names both.
func TestAgentUpdatePayloadEqualityCoversSources(t *testing.T) {
	_, _, _, _, base := mirrorPlanFixture(t, 2*agentChunkSize+10, false)
	if !agentUpdatePayloadEqual(base, base) {
		t.Fatal("a payload equals itself")
	}
	copied := base
	copied.Sources = cloneSources(base.Sources)
	m := *base.ChunkManifest
	copied.ChunkManifest = &m
	if !agentUpdatePayloadEqual(base, copied) {
		t.Fatal("equality compares values, not slices or pointers")
	}
	// Every field, by reflection, so a field added later cannot be missed.
	v := reflect.ValueOf(base)
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		changed := base
		changed.Sources = cloneSources(base.Sources)
		f := reflect.ValueOf(&changed).Elem().Field(i)
		switch f.Kind() {
		case reflect.String:
			f.SetString(f.String() + "x")
		case reflect.Int:
			f.SetInt(f.Int() + 1)
		case reflect.Bool:
			f.SetBool(!f.Bool())
		case reflect.Slice:
			changed.Sources[0].Reason += " (changed)"
		case reflect.Pointer:
			mm := *base.ChunkManifest
			mm.Chunks = strings.Repeat("0", len(mm.Chunks))
			changed.ChunkManifest = &mm
		default:
			t.Fatalf("field %s has a kind this test does not change: %s", name, f.Kind())
		}
		if agentUpdatePayloadEqual(base, changed) {
			t.Fatalf("equality misses field %s", name)
		}
	}
	noMirror := base
	noMirror.Sources = base.Sources[1:]
	noMirror.ChunkManifest = nil
	summary := agentUpdatePayloadChangeSummary(base, noMirror)
	for _, want := range []string{
		"sources planned=mirror:r2,control-plane,upstream current=control-plane,upstream",
		"chunk_manifest planned=" + shortDigest(base.ChunkManifest.digest()) + " current=",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary %q lacks %q", summary, want)
		}
	}
	reasons := base
	reasons.Sources = cloneSources(base.Sources)
	reasons.Sources[0].URL = mirrorTestBase + "/x/0.3.4/linux/amd64/" + base.SHA256
	if s := agentUpdatePayloadChangeSummary(base, reasons); !strings.Contains(s, "sources planned=mirror:r2,control-plane,upstream current=mirror:r2*,control-plane,upstream") {
		t.Fatalf("an entry that changed in place is marked: %q", s)
	}
}

// No plan that lists a mirror or GitHub says the node needs no third-party
// egress; only a plan whose one source is the control plane says so.
func TestAgentUpdatePlanNeverClaimsNoEgressWithAMirrorOrUpstream(t *testing.T) {
	const noEgress = "needs no third-party egress"
	_, st, _, approval, _ := mirrorPlanFixture(t, 2*agentChunkSize+10, false)
	if strings.Contains(approval.Plan, noEgress) {
		t.Fatalf("a plan with a mirror and the release claimed no egress:\n%s", approval.Plan)
	}
	for _, want := range []string{"1. mirror r2", "2. this control plane", "3. upstream", "the node contacts dl.example.org, downloads.example.com"} {
		if !strings.Contains(approval.Plan, want) {
			t.Fatalf("the plan must say %q:\n%s", want, approval.Plan)
		}
	}
	node, _ := st.Node("node-a")
	for _, tc := range []struct {
		name    string
		sources []string
		claims  bool
	}{
		{"control plane alone", []string{"control-plane"}, true},
		{"control plane and release", []string{"control-plane", "upstream"}, false},
		{"release alone", []string{"upstream"}, false},
		{"mirror and control plane", []string{"mirror", "control-plane"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := agentUpdatePayloadFromApproval(approval)
			if err != nil {
				t.Fatal(err)
			}
			var sources []model.AgentUpdateSource
			for _, kind := range tc.sources {
				for _, src := range payload.Sources {
					if src.Kind == model.AgentSourceKindMirror && kind == "mirror" || src.Kind == kind {
						sources = append(sources, src)
					}
				}
			}
			payload.Sources = sources
			plan := renderAgentUpdatePlan(node, payload, "manual")
			if strings.Contains(plan, noEgress) != tc.claims {
				t.Fatalf("no-egress line present=%t, want %t:\n%s", !tc.claims, tc.claims, plan)
			}
		})
	}
}

// A registry change re-plans every open approval whose list it changes, and
// an approval planned before sources existed is stale once S5 is deployed.
// The fixture's approval has a leased task; an open one is still pending.
func TestAgentUpdateApprovalIsStaleWhenItsSourcesChange(t *testing.T) {
	srv, st, _, approval, payload := mirrorPlanFixture(t, 2*agentChunkSize+10, false)
	approval.Status = model.ApprovalPending
	if stale, reason := srv.agentUpdateApprovalLocalStaleness(approval); stale {
		t.Fatalf("a fresh plan is not stale: %s", reason)
	}
	seedAgentMirrors(t, st, model.AgentMirror{ID: "r2", BaseURL: mirrorTestBase, PreferFor: []string{"node-a"}, Priority: 1})
	stale, reason := srv.agentUpdateApprovalLocalStaleness(approval)
	if !stale || !strings.Contains(reason, "sources planned=mirror:r2,control-plane,upstream current=control-plane,upstream") {
		t.Fatalf("disabling the mirror must make the plan stale with the sources named: %t %q", stale, reason)
	}
	if err := srv.requireCurrentAgentUpdateApproval(approval); err == nil {
		t.Fatal("the decision must refuse it as well")
	}

	// An approval from before S5: the same payload without sources.
	legacy := payload
	legacy.Sources, legacy.ChunkManifest = nil, nil
	old := withPayload(approval, legacy)
	seedAgentMirrors(t, st)
	stale, reason = srv.agentUpdateApprovalLocalStaleness(old)
	if !stale || !strings.Contains(reason, "sources planned= current=control-plane,upstream") {
		t.Fatalf("an approval planned before sources must be re-planned: %t %q", stale, reason)
	}
}

// The binary route authorizes on the payload's control-plane entry, the one
// the server computed, rather than on the binary_source label.
func TestAgentBinaryAuthorizesOnTheControlPlaneEntry(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	data, _ := walkTestBinary("0.3.4", 2*agentChunkSize+10)
	seedAgentMirrors(t, st, model.AgentMirror{ID: "r2", BaseURL: mirrorTestBase, PreferFor: []string{"node-a"}, Priority: 1, Enabled: true})
	ref, approval, task := seedWalkUpdate(t, srv, st, data, false)
	lease := task.LeaseID
	request := func() *http.Request {
		r, _ := http.NewRequest(http.MethodGet, artifactTestPublicURL+ref.urlPath(), nil)
		r.Header.Set(agentTaskIDHeader, task.ID)
		r.Header.Set(agentTaskLeaseHeader, lease)
		return r
	}
	if _, _, err := srv.authorizeAgentBinaryRequest(request(), ref); err != nil {
		t.Fatalf("the plan's control-plane entry authorizes its object: %v", err)
	}
	payload, _ := agentUpdatePayloadFromApproval(approval)
	payload.Sources = []model.AgentUpdateSource{payload.Sources[0], payload.Sources[2]}
	payload.BinarySource, payload.BinaryURL, payload.FallbackURL = agentBinarySourceUpstream, payload.Sources[1].URL, ""
	approval.Action = agentUpdateApprovalAction(payload)
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	if _, _, err := srv.authorizeAgentBinaryRequest(request(), ref); err == nil {
		t.Fatal("a plan without a control-plane entry must not be served from the control plane")
	}
}
