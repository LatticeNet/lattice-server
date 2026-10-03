package server

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The contract between the line-user apply scripts and the node script they
// call. The golden argv tests pin what the server renders; this runs that
// argv through the fork's own `user add|del` code, vendored byte for byte
// from the tag adopted nodes run (testdata/singbox-fork/cmd_json_user.sh), so
// a change on either side that breaks the other fails here. The a102 removal
// passed every server test while the fork refused each one with
// invalid_payload, because nothing ran the two together.

// forkSB is a stand-in for /usr/local/bin/sb on an adopted node: the vendored
// functions, the fork's paths pointed at a scratch directory, the service
// restart stubbed out, and the entry point's routing, which sends every
// `user` subcommand to cmd_json_user with or without --json.
type forkSB struct {
	t    *testing.T
	sh   string
	bin  string
	root string
	conf string
	// path is the PATH the node script runs with, and flockLog the file
	// the flock stand-in appends its arguments to; empty when the script
	// runs with the test's own PATH.
	path     string
	flockLog string
}

// forkLockModes are the two ways the script's per-node user lock can run.
// From alpha.8 every add, del, park and unpark takes flock on fd 8 when
// flock is on PATH and runs unlocked when it is not. "path" leaves PATH as
// the test has it: unlocked where flock is missing (macOS), util-linux flock
// where it is there (CI). "flock-stand-in" puts a stand-in first on PATH
// that takes the lock the way busybox flock does, with -n on the inherited
// descriptor only, so the locked path runs on every platform.
var forkLockModes = []string{"path", "flock-stand-in"}

// forEachForkLockMode runs fn once per lock mode, each with its own sb.
func forEachForkLockMode(t *testing.T, fn func(t *testing.T, sb *forkSB)) {
	t.Helper()
	for _, mode := range forkLockModes {
		t.Run(mode, func(t *testing.T) { fn(t, newForkSB(t, mode == "flock-stand-in")) })
	}
}

func newForkSB(t *testing.T, flockStandIn bool) *forkSB {
	t.Helper()
	bash, bashErr := exec.LookPath("bash")
	_, jqErr := exec.LookPath("jq")
	sh, shErr := exec.LookPath("sh")
	if bashErr != nil || jqErr != nil || shErr != nil {
		t.Skip("the fork contract test needs bash, jq and sh on PATH to run the node script's user command; CI has all three")
	}
	funcs, err := filepath.Abs(filepath.Join("testdata", "singbox-fork", "cmd_json_user.sh"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	conf := filepath.Join(root, "conf")
	if err := os.MkdirAll(conf, 0o755); err != nil {
		t.Fatal(err)
	}
	// No stats block in config.json, so json_stats_allowlist_sync returns
	// early, as it does on a node without the v2ray API enabled.
	if err := os.WriteFile(filepath.Join(root, "config.json"), []byte(`{"log":{},"dns":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "sb")
	stub := "#!" + bash + "\n" +
		"set -u\n" +
		". " + shellQuote(funcs) + "\n" +
		"is_conf_dir=" + shellQuote(conf) + "\n" +
		"is_config_json=" + shellQuote(filepath.Join(root, "config.json")) + "\n" +
		"is_core_bin=$(command -v true)\n" +
		"is_core=sing-box\n" +
		"manage() { :; }\n" +
		"is_args=()\n" +
		"for arg in \"$@\"; do case $arg in --json) is_json_out=1 ;; *) is_args+=(\"$arg\") ;; esac; done\n" +
		"set -- \"${is_args[@]}\"\n" +
		"case $1 in\n" +
		"user) cmd_json_user \"$2\" \"$3\" \"$4\" ;;\n" +
		"*) echo \"stub sb: only the user subcommand is vendored\" >&2; exit 64 ;;\n" +
		"esac\n"
	if err := os.WriteFile(bin, []byte(stub), 0o700); err != nil { // #nosec G306 -- an executable test stub in a temp dir
		t.Fatal(err)
	}
	sb := &forkSB{t: t, sh: sh, bin: bin, root: root, conf: conf}
	if flockStandIn {
		sb.installFlockStandIn()
	}
	return sb
}

// installFlockStandIn puts a flock first on the script's PATH. It accepts
// only `-n FD`, as busybox's applet is the narrowest the fork supports, and
// locks the descriptor the script opened with perl's flock(2), so the lock
// lives on the script's own fd 8 exactly as with the real tool.
func (f *forkSB) installFlockStandIn() {
	f.t.Helper()
	perl, err := exec.LookPath("perl")
	if err != nil {
		f.t.Skip("the flock stand-in needs perl to lock the inherited descriptor")
	}
	dir := filepath.Join(f.root, "flock-bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.t.Fatal(err)
	}
	f.flockLog = filepath.Join(f.root, "flock.log")
	standIn := "#!" + f.sh + "\n" +
		"echo \"$*\" >> " + shellQuote(f.flockLog) + "\n" +
		"[ $# -eq 2 ] && [ \"$1\" = -n ] || { echo 'flock stand-in: only -n FD' >&2; exit 64; }\n" +
		"exec " + shellQuote(perl) + " -e 'use Fcntl qw(:flock); open(my $fh, \">&=\", $ARGV[0]) or exit 1; flock($fh, LOCK_EX | LOCK_NB) or exit 1; exit 0' \"$2\"\n"
	if err := os.WriteFile(filepath.Join(dir, "flock"), []byte(standIn), 0o700); err != nil { // #nosec G306 -- an executable test stub in a temp dir
		f.t.Fatal(err)
	}
	f.path = dir + string(os.PathListSeparator) + os.Getenv("PATH")
}

// lockCalls returns the arguments of each flock stand-in call, in order.
func (f *forkSB) lockCalls() []string {
	f.t.Helper()
	if f.flockLog == "" {
		return nil
	}
	raw, err := os.ReadFile(f.flockLog)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		f.t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

// expectLocked checks, in the stand-in mode, that the script took the user
// lock on fd 8 once for each of the calls that change a line.
func (f *forkSB) expectLocked(calls int) {
	f.t.Helper()
	if f.flockLog == "" {
		return
	}
	got := f.lockCalls()
	if len(got) != calls {
		f.t.Fatalf("flock calls = %q, want %d", got, calls)
	}
	for _, args := range got {
		if args != "-n 8" {
			f.t.Fatalf("flock called with %q, want -n 8", args)
		}
	}
}

// writeLine writes the conf file for one inbound with the given users.
func (f *forkSB) writeLine(tag, protocol string, users ...map[string]string) {
	f.t.Helper()
	doc := map[string]any{"inbounds": []any{map[string]any{"tag": tag + ".json", "type": protocol, "listen": "::", "listen_port": 443, "users": users}}}
	raw, _ := json.Marshal(doc)
	if err := os.WriteFile(filepath.Join(f.conf, tag+".json"), raw, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *forkSB) users(tag string) []map[string]string {
	f.t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.conf, tag+".json"))
	if err != nil {
		f.t.Fatal(err)
	}
	var doc struct {
		Inbounds []struct {
			Users []map[string]string `json:"users"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Inbounds) != 1 {
		f.t.Fatalf("conf %s: %v %s", tag, err, raw)
	}
	return doc.Inbounds[0].Users
}

// run executes a rendered apply script the way the agent does, with sh.
func (f *forkSB) run(script string) (stdout string, code int) {
	f.t.Helper()
	cmd := exec.Command(f.sh, "-c", script) // #nosec G204 -- runs a script this test rendered
	cmd.Env = append(os.Environ(), "LATTICE_SINGBOX_BIN="+f.bin)
	if f.path != "" {
		cmd.Env = append(cmd.Env, "PATH="+f.path)
	}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	code = 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		f.t.Fatalf("run script: %v", err)
	}
	return out.String() + errOut.String(), code
}

// forkContractCase is one protocol the adopted track mutates, with the
// identity's credential and the line owner's entry the conf starts with.
type forkContractCase struct {
	protocol   string
	credential VpnCredential
	owner      map[string]string
}

var forkContractCases = []forkContractCase{
	{"vless", VpnCredential{Protocol: "vless", UUID: "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d", Flow: "xtls-rprx-vision"}, map[string]string{"uuid": "11111111-1111-4111-8111-111111111111", "flow": "xtls-rprx-vision"}},
	{"vmess", VpnCredential{Protocol: "vmess", UUID: "2c4e6a8b-1d3f-4a5b-8c7d-9e0f1a2b3c4d"}, map[string]string{"uuid": "33333333-3333-4333-8333-333333333333"}},
	{"trojan", VpnCredential{Protocol: "trojan", Password: "id-trojan-secret"}, map[string]string{"password": "owner-trojan"}},
	{"hysteria2", VpnCredential{Protocol: "hysteria2", Password: "id-hy2-secret"}, map[string]string{"password": "owner-hy2"}},
	{"tuic", VpnCredential{Protocol: "tuic", UUID: "5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b", Password: "id-tuic-secret"}, map[string]string{"uuid": "44444444-4444-4444-8444-444444444444", "password": "owner-tuic"}},
	{"anytls", VpnCredential{Protocol: "anytls", Password: "id-anytls-secret"}, map[string]string{"password": "owner-anytls"}},
}

// forkContractServer is a server with one adopted line of protocol on
// node-a, tagged "line-<protocol>", and an unbound identity holding cred.
// The identity's id has the shape Lattice mints, so a removal filed after
// its deletion passes vpnUserIDRe.
func forkContractServer(t *testing.T, protocol string, cred VpnCredential) (*Server, Line, VpnUser) {
	t.Helper()
	srv := newLinemetaTestServer(t, mustOpenStore(t))
	if err := srv.store.UpsertNode(model.Node{ID: "node-a", Name: "Node A", PublicIP: "203.0.113.5"}); err != nil {
		t.Fatal(err)
	}
	tag := "line-" + protocol
	srv.singboxInvMu.Lock()
	srv.singboxInv = map[string]model.SingBoxInventory{"node-a": {NodeID: "node-a", At: srv.now(), Status: "ok",
		Nodes: []model.SingBoxNode{{Name: tag, Protocol: protocol, Network: "tcp", Address: "203.0.113.5", Port: "443", UserKnown: true, UserCount: 1}}}}
	srv.singboxInvMu.Unlock()
	srv.invalidateLineReadModel()
	line := findLine(t, srv.buildLineGroups(), "node-a", tag)
	u := VpnUser{ID: "vpnuser_forkcontractuser", Email: "contract@example.com", Enabled: true, Credentials: []VpnCredential{cred}}
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	return srv, line, u
}

// approvedScript files a plan, approves it, and returns its one task.
func approvedScript(t *testing.T, srv *Server, op, userID string, line Line) (model.Approval, model.Task) {
	t.Helper()
	approval := filePlan(t, srv, op, userID, line.LineHashID)
	if err := approvePlan(t, srv, approval); err != nil {
		t.Fatalf("approve %s: %v", op, err)
	}
	tasks := tasksFor(srv, approval.ID)
	if len(tasks) != 1 {
		t.Fatalf("approve %s queued %d tasks", op, len(tasks))
	}
	return approval, tasks[0]
}

func reportResult(t *testing.T, srv *Server, approval model.Approval, task model.Task, stdout string, code int) model.Approval {
	t.Helper()
	request := httptest.NewRequest("POST", "/api/agent/task-result", nil)
	if err := srv.handleApprovalTaskResult(request, task, model.TaskResult{TaskID: task.ID, NodeID: "node-a", ExitCode: code, Stdout: stdout}); err != nil {
		t.Fatal(err)
	}
	stored, _ := srv.store.Approval(approval.ID)
	return stored
}

// For every protocol the adopted track mutates: the add the server renders
// appends exactly the identity's entry next to the owner's, the removal it
// renders takes exactly that entry back off, and the results the script
// prints reconcile cleanly on the server. Each runs in both lock modes.
func TestLineUserScriptsRunAgainstTheForksUserCommand(t *testing.T) {
	for _, tc := range forkContractCases {
		t.Run(tc.protocol, func(t *testing.T) {
			forEachForkLockMode(t, func(t *testing.T, sb *forkSB) {
				runLineUserAddAndRemove(t, sb, tc)
			})
		})
	}
}

func runLineUserAddAndRemove(t *testing.T, sb *forkSB, tc forkContractCase) {
	t.Helper()
	srv, line, u := forkContractServer(t, tc.protocol, tc.credential)
	sb.writeLine(line.Tag, tc.protocol, tc.owner)
	name := userLineName(u.ID, line.LineUUID)

	addApproval, addTask := approvedScript(t, srv, lineUserOpAdd, u.ID, line)
	out, code := sb.run(addTask.Script)
	if code != 0 {
		t.Fatalf("the fork refused the add (exit %d):\n%s\nscript:\n%s", code, out, addTask.Script)
	}
	users := sb.users(line.Tag)
	if len(users) != 2 || users[1]["name"] != name {
		t.Fatalf("after the add the line holds %v, want the owner then %s", users, name)
	}
	if users[1]["uuid"] != tc.credential.UUID || users[1]["password"] != tc.credential.Password {
		t.Fatalf("the fork wrote %v, want the identity's credential", users[1])
	}
	if users[0]["uuid"] != tc.owner["uuid"] || users[0]["password"] != tc.owner["password"] {
		t.Fatalf("the add changed the owner's entry: %v", users[0])
	}
	if got := reportResult(t, srv, addApproval, addTask, out, code); got.Status != model.ApprovalApplied || got.Reason != "" {
		t.Fatalf("add result: status %q reason %q", got.Status, got.Reason)
	}

	removeApproval, removeTask := approvedScript(t, srv, lineUserOpRemove, u.ID, line)
	out, code = sb.run(removeTask.Script)
	if code != 0 {
		t.Fatalf("the fork refused the removal (exit %d):\n%s\nscript:\n%s", code, out, removeTask.Script)
	}
	if users := sb.users(line.Tag); len(users) != 1 || users[0]["uuid"] != tc.owner["uuid"] || users[0]["password"] != tc.owner["password"] {
		t.Fatalf("after the removal the line holds %v, want only the owner's entry", users)
	}
	got := reportResult(t, srv, removeApproval, removeTask, out, code)
	if got.Status != model.ApprovalApplied || got.Reason != "" || lineUserBoundTo(t, srv, u.ID, line.LineHashID) {
		t.Fatalf("removal result: status %q reason %q", got.Status, got.Reason)
	}
	sb.expectLocked(2)
}

// forkUserResult is the line cmd_json_user prints last.
type forkUserResult struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error"`
	Matched *int   `json:"matched"`
	Match   string `json:"match"`
	Changed *bool  `json:"changed"`
}

func parseForkUserResult(t *testing.T, out string) forkUserResult {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var res forkUserResult
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &res); err != nil {
		t.Fatalf("the fork's last line is not its JSON result: %v\n%s", err, out)
	}
	return res
}

// From alpha.8 the fork removes a user by a payload that carries its name
// and nothing else, which is the only payload a deleted identity's removal
// can carry. It takes the entry with that name and no other: a hand-added
// entry that shares the uuid under another name stays, where a credential
// del would take it. A name the line does not hold changes nothing, and a
// name two entries share is refused rather than guessed. The a102 argv, a
// bare name that is not JSON, is still refused.
func TestTheForkRemovesAUserByNameAloneAndRefusesABareName(t *testing.T) {
	forEachForkLockMode(t, func(t *testing.T, sb *forkSB) {
		owner := map[string]string{"uuid": "11111111-1111-4111-8111-111111111111"}
		lattice := map[string]string{"name": "u_aaaaaaaaaaaaaaaa", "uuid": "22222222-2222-4222-8222-222222222222"}
		twin := map[string]string{"name": "hand-added", "uuid": "22222222-2222-4222-8222-222222222222"}
		sb.writeLine("hub-a", "vless", owner, lattice, twin)
		prelude := "set -e\nSB_BIN=\"${LATTICE_SINGBOX_BIN:-sb}\"\n"
		byName := prelude + `"$SB_BIN" --json user del 'hub-a' '{"name":"u_aaaaaaaaaaaaaaaa"}'` + "\n"

		out, code := sb.run(prelude + `"$SB_BIN" user del 'hub-a' 'u_aaaaaaaaaaaaaaaa'` + "\n")
		if code != 2 || !strings.Contains(out, `"error":"invalid_payload"`) || len(sb.users("hub-a")) != 3 {
			t.Fatalf("bare name: exit %d %q, want exit 2 with invalid_payload and the line unchanged", code, out)
		}

		out, code = sb.run(byName)
		res := parseForkUserResult(t, out)
		if code != 0 || !res.OK || res.Match != "name" || res.Matched == nil || *res.Matched != 1 || res.Changed == nil || !*res.Changed {
			t.Fatalf("name only: exit %d %q, want the one entry named removed", code, out)
		}
		if users := sb.users("hub-a"); len(users) != 2 || !reflect.DeepEqual(users[0], owner) || !reflect.DeepEqual(users[1], twin) {
			t.Fatalf("after the removal by name the line holds %v, want the owner and the hand-added twin", users)
		}

		out, code = sb.run(byName)
		res = parseForkUserResult(t, out)
		if code != 0 || !res.OK || res.Matched == nil || *res.Matched != 0 || res.Changed == nil || *res.Changed {
			t.Fatalf("repeat: exit %d %q, want ok with nothing matched and nothing changed", code, out)
		}

		sb.writeLine("hub-b", "vless", owner,
			map[string]string{"name": "u_bbbbbbbbbbbbbbbb", "uuid": "33333333-3333-4333-8333-333333333333"},
			map[string]string{"name": "u_bbbbbbbbbbbbbbbb", "uuid": "44444444-4444-4444-8444-444444444444"})
		out, code = sb.run(prelude + `"$SB_BIN" --json user del 'hub-b' '{"name":"u_bbbbbbbbbbbbbbbb"}'` + "\n")
		if code != 2 || parseForkUserResult(t, out).Error != "ambiguous_user" || len(sb.users("hub-b")) != 3 {
			t.Fatalf("shared name: exit %d %q, want exit 2 with ambiguous_user and the line unchanged", code, out)
		}
		sb.expectLocked(4)
	})
}

// The over-match the server cannot see before the task runs: an entry
// further down the list, added by hand after Lattice's, holds the same uuid.
// The fork removes both, and the counts it prints make the result say so.
func TestAForkRemovalThatTakesAHandAddedTwinIsFlagged(t *testing.T) {
	forEachForkLockMode(t, func(t *testing.T, sb *forkSB) {
		tc := forkContractCases[0]
		srv, line, u := forkContractServer(t, tc.protocol, tc.credential)
		sb.writeLine(line.Tag, tc.protocol, tc.owner)
		addApproval, addTask := approvedScript(t, srv, lineUserOpAdd, u.ID, line)
		out, code := sb.run(addTask.Script)
		if code != 0 {
			t.Fatalf("add: exit %d %s", code, out)
		}
		reportResult(t, srv, addApproval, addTask, out, code)

		users := sb.users(line.Tag)
		users = append(users, map[string]string{"name": "hand-added", "uuid": tc.credential.UUID})
		sb.writeLine(line.Tag, tc.protocol, users...)

		removeApproval, removeTask := approvedScript(t, srv, lineUserOpRemove, u.ID, line)
		out, code = sb.run(removeTask.Script)
		if code != 0 {
			t.Fatalf("removal: exit %d %s", code, out)
		}
		if left := sb.users(line.Tag); len(left) != 1 {
			t.Fatalf("the fork should have removed both matching entries, left %v", left)
		}
		got := reportResult(t, srv, removeApproval, removeTask, out, code)
		if got.Status != model.ApprovalApplied || !strings.Contains(got.Reason, "removed 2 entries") {
			t.Fatalf("the result must flag the over-match: status %q reason %q", got.Status, got.Reason)
		}
		if flags := lineUserAudit(srv, "vpnuser.line.overmatch", removeApproval.ID); len(flags) != 1 {
			t.Fatalf("over-match audit = %+v", flags)
		}
		sb.expectLocked(2)
	})
}

// A deleted identity's removal, end to end on a node whose agent reports
// sb:user-del-by-name: the plan the server files after the deletion, the
// script it renders at approval, and the fork running it. The fork takes
// Lattice's entry by its name and leaves both the owner and a hand-added
// entry that shares the deleted identity's uuid, which a removal by
// credential would have taken too. The result applies cleanly and brings
// no identity back.
func TestADeletedUsersRemovalByNameRunsOnTheFork(t *testing.T) {
	forEachForkLockMode(t, func(t *testing.T, sb *forkSB) {
		tc := forkContractCases[0]
		srv, line, u := forkContractServer(t, tc.protocol, tc.credential)
		sb.writeLine(line.Tag, tc.protocol, tc.owner)
		addApproval, addTask := approvedScript(t, srv, lineUserOpAdd, u.ID, line)
		out, code := sb.run(addTask.Script)
		if code != 0 {
			t.Fatalf("add: exit %d %s", code, out)
		}
		reportResult(t, srv, addApproval, addTask, out, code)
		twin := map[string]string{"name": "hand-added", "uuid": tc.credential.UUID}
		sb.writeLine(line.Tag, tc.protocol, append(sb.users(line.Tag), twin)...)

		// The store-level delete stands in for one made before the delete
		// refusal existed, the case this removal is for.
		if err := srv.deleteVpnUser(u.ID); err != nil {
			t.Fatal(err)
		}
		srv.replaceAgentCapabilities("node-a", []string{singBoxUserDelByNameCapability})
		removeApproval, removeTask := approvedScript(t, srv, lineUserOpRemove, u.ID, line)
		out, code = sb.run(removeTask.Script)
		res := parseForkUserResult(t, out)
		if code != 0 || !res.OK || res.Match != "name" || res.Matched == nil || *res.Matched != 1 {
			t.Fatalf("the fork refused the removal by name (exit %d):\n%s\nscript:\n%s", code, out, removeTask.Script)
		}
		if users := sb.users(line.Tag); len(users) != 2 || !reflect.DeepEqual(users[0], tc.owner) || !reflect.DeepEqual(users[1], twin) {
			t.Fatalf("after the removal by name the line holds %v, want the owner and the hand-added twin", users)
		}
		got := reportResult(t, srv, removeApproval, removeTask, out, code)
		if got.Status != model.ApprovalApplied || got.Reason != "" {
			t.Fatalf("removal result: status %q reason %q", got.Status, got.Reason)
		}
		if _, ok := srv.getVpnUser(u.ID); ok {
			t.Fatal("recording the removal brought the deleted identity back")
		}
		if err := srv.requireLineUserOnLine(u.ID, line.LineHashID); err == nil || !strings.Contains(err.Error(), "already removed") {
			t.Fatalf("after the applied removal the history must say the user is off the line: %v", err)
		}
		sb.expectLocked(2)
	})
}

// socksContractCredential is an identity's socks credential. The store
// refuses socks credentials (store.ValidateVpnUserCredentialSecret), so no
// plan_add reaches a socks line today; these cases pin what the renderer
// and the fork do with one for the change that admits them, and run the one
// plan that can reach a socks line now, a deleted user's removal by name.
var socksContractCredential = VpnCredential{Protocol: "socks", Password: "id-socks-secret"}

// socksContractLine is a server with one adopted socks line on node-a,
// tagged "line-socks".
func socksContractLine(t *testing.T) (*Server, Line) {
	t.Helper()
	srv := newLinemetaTestServer(t, mustOpenStore(t))
	if err := srv.store.UpsertNode(model.Node{ID: "node-a", Name: "Node A", PublicIP: "203.0.113.5"}); err != nil {
		t.Fatal(err)
	}
	srv.singboxInvMu.Lock()
	srv.singboxInv = map[string]model.SingBoxInventory{"node-a": {NodeID: "node-a", At: srv.now(), Status: "ok",
		Nodes: []model.SingBoxNode{{Name: "line-socks", Protocol: "socks", Network: "tcp", Address: "203.0.113.5", Port: "1080", UserKnown: true, UserCount: 1}}}}
	srv.singboxInvMu.Unlock()
	srv.invalidateLineReadModel()
	return srv, findLine(t, srv.buildLineGroups(), "node-a", "line-socks")
}

// The socks payload the server renders against the fork. A socks user is a
// username and a password: the core decodes it strictly and fails the whole
// file on "name", which is how every Lattice socks add failed on alpha.7
// (config_invalid on a real node). The stub core here accepts anything, so
// the test reads the entry the fork wrote. The add appends exactly that
// entry with the on-box name as its username, the removal takes it back
// off, and removing the line's last user is refused with
// last_user_open_proxy, since sing-box serves a socks inbound with no users
// to anyone.
func TestSocksLineUsersRunAgainstTheFork(t *testing.T) {
	forEachForkLockMode(t, func(t *testing.T, sb *forkSB) {
		_, line := socksContractLine(t)
		u := VpnUser{ID: "vpnuser_forkcontractuser", Credentials: []VpnCredential{socksContractCredential}}
		name := userLineName(u.ID, line.LineUUID)
		payload, err := lineUserCredential(u, "socks", name)
		if err != nil {
			t.Fatal(err)
		}
		script := func(op string) string {
			s, err := adoptedLineUserScript(op, line.Tag, payload)
			if err != nil {
				t.Fatal(err)
			}
			return s
		}
		owner := map[string]string{"username": "owner", "password": "owner-socks"}
		lattice := map[string]string{"username": name, "password": socksContractCredential.Password}
		sb.writeLine(line.Tag, "socks", owner)

		if out, code := sb.run(script(lineUserOpAdd)); code != 0 {
			t.Fatalf("the fork refused the socks add (exit %d):\n%s", code, out)
		}
		if users := sb.users(line.Tag); len(users) != 2 || !reflect.DeepEqual(users[0], owner) || !reflect.DeepEqual(users[1], lattice) {
			t.Fatalf("after the add the line holds %v, want the owner then exactly %v", users, lattice)
		}
		if out, code := sb.run(script(lineUserOpRemove)); code != 0 {
			t.Fatalf("the fork refused the socks removal (exit %d):\n%s", code, out)
		}
		if users := sb.users(line.Tag); len(users) != 1 || !reflect.DeepEqual(users[0], owner) {
			t.Fatalf("after the removal the line holds %v, want only the owner", users)
		}

		sb.writeLine(line.Tag, "socks", lattice)
		out, code := sb.run(script(lineUserOpRemove))
		if code != 2 || parseForkUserResult(t, out).Error != "last_user_open_proxy" {
			t.Fatalf("removing the last socks user: exit %d %q, want exit 2 with last_user_open_proxy", code, out)
		}
		if users := sb.users(line.Tag); len(users) != 1 || !reflect.DeepEqual(users[0], lattice) {
			t.Fatalf("a refused removal changed the line: %v", users)
		}
		sb.expectLocked(3)
	})
}

// The same refusal through an approval: a deleted user's removal by name
// from a socks line it is the last user of. The fork refuses it, and the
// approval goes back to pending with the fork's code and message, so the
// operator reads why and what to do (add another user first, or delete the
// line) rather than an exit code.
func TestRemovingTheLastSocksUserReturnsTheApprovalWithTheForksReason(t *testing.T) {
	forEachForkLockMode(t, func(t *testing.T, sb *forkSB) {
		srv, line := socksContractLine(t)
		userID := "vpnuser_sockslastuserabc"
		name := userLineName(userID, line.LineUUID)
		// The history an applied socks add would leave; see
		// socksContractCredential for why no plan can make it today.
		add := lineUserCredentialPayload{Name: name, Username: name, Password: socksContractCredential.Password}
		sha, err := lineUserCredentialSHA(add)
		if err != nil {
			t.Fatal(err)
		}
		out, err := srv.fileLineUserPlan(lineUserTestPrincipal(), lineUserPlan{
			Op: lineUserOpAdd, Track: lineUserTrackAdopted, NodeID: line.NodeID, Line: line.Tag, LineHashID: line.LineHashID,
			LineUUID: line.LineUUID, UserID: userID, UserName: name, Protocol: "socks", CredentialSHA256: sha, Summary: "socks add",
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		var filed struct {
			Approval model.Approval `json:"approval"`
		}
		if err := json.Unmarshal(out, &filed); err != nil {
			t.Fatal(err)
		}
		filed.Approval.Status, filed.Approval.UpdatedAt = model.ApprovalApplied, srv.now()
		if err := srv.store.UpsertApproval(filed.Approval); err != nil {
			t.Fatal(err)
		}
		lattice := map[string]string{"username": name, "password": socksContractCredential.Password}
		sb.writeLine(line.Tag, "socks", lattice)

		srv.replaceAgentCapabilities("node-a", []string{singBoxUserDelByNameCapability})
		removeApproval, removeTask := approvedScript(t, srv, lineUserOpRemove, userID, line)
		stdout, code := sb.run(removeTask.Script)
		if code != 2 || parseForkUserResult(t, stdout).Error != "last_user_open_proxy" {
			t.Fatalf("the fork must refuse removing the last socks user: exit %d\n%s", code, stdout)
		}
		if users := sb.users(line.Tag); len(users) != 1 || !reflect.DeepEqual(users[0], lattice) {
			t.Fatalf("a refused removal changed the line: %v", users)
		}
		got := reportResult(t, srv, removeApproval, removeTask, stdout, code)
		if got.Status != model.ApprovalPending || !strings.Contains(got.Reason, "exited 2: the node script refused with last_user_open_proxy: ") ||
			!strings.Contains(got.Reason, "would leave it open to anyone; add another user first, or delete the line") {
			t.Fatalf("approval after the refusal: status %q reason %q, want pending with the fork's code and message", got.Status, got.Reason)
		}
		failed := lineUserAudit(srv, "vpnuser.line.failed", removeApproval.ID)
		if len(failed) != 1 || failed[0].Metadata["script_error"] != "last_user_open_proxy" {
			t.Fatalf("failed audit = %+v, want one naming the script's error", failed)
		}
		sb.expectLocked(1)
	})
}

// lineUserScriptError takes the node script's refusal from the end of the
// task's output and nothing else: a last JSON line that is not a refusal,
// a code that is not one, and output with no JSON line give nothing; a long message is cut, and
// control characters from the node never reach the approval.
func TestLineUserScriptErrorReadsOnlyTheScriptsRefusal(t *testing.T) {
	long := strings.Repeat("x", 600)
	for _, tc := range []struct {
		stdout, code, message string
		ok                    bool
	}{
		{`{"ok":false,"error":"busy","message":"another sb user call on this node holds the user lock"}`, "busy", "another sb user call on this node holds the user lock", true},
		{"progress\n" + `{"ok":false,"error":"invalid_user","message":"payload does not contain the credential"}` + "\n", "invalid_user", "payload does not contain the credential", true},
		{`{"ok":false,"error":"parked_stale","message":"repeat the del"}` + "\n" + `{"ok":true,"action":"del"}`, "", "", false},
		{`{"ok":true,"action":"del","user_count_before":2,"user_count_after":1}`, "", "", false},
		{`{"ok":false,"error":"Not A Code; rm -rf","message":"x"}`, "", "", false},
		{`{"error":"busy"}`, "", "", false},
		{"sb: command not found", "", "", false},
		{`{"ok":false,"error":"config_invalid","message":"` + long + `"}`, "config_invalid", strings.Repeat("x", 240) + "...", true},
		{`{"ok":false,"error":"busy","message":"held \u001b[2J by\u0000 another\ncall"}`, "busy", "held [2J by another call", true},
	} {
		code, message, ok := lineUserScriptError(tc.stdout)
		if code != tc.code || message != tc.message || ok != tc.ok {
			t.Fatalf("lineUserScriptError(%.60q) = %q %q %v, want %q %q %v", tc.stdout, code, message, ok, tc.code, tc.message, tc.ok)
		}
	}
}
