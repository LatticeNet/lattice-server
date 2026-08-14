//go:build linechain_lifecycle_e2e

package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func runLifecycleAgentHelper(t *testing.T, cmd *exec.Cmd) []byte {
	t.Helper()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("agent helper start: %v", err)
	}
	err := cmd.Wait()
	if err != nil {
		t.Fatalf("agent helper failed: %v: %s", err, out.Bytes())
	}
	return out.Bytes()
}

func TestLineChainPersistentServerAgentLifecycleE2E(t *testing.T) {
	agent := requireE2EFile(t, "LATTICE_AGENT_E2E_BIN")
	agentTest := requireE2EFile(t, "LATTICE_AGENT_E2E_TEST_BIN")
	singbox := requireE2EFile(t, "LATTICE_SINGBOX_E2E_BIN")
	root := strings.TrimSpace(os.Getenv("LATTICE_LINECHAIN_E2E_RUNTIME_ROOT"))
	if root == "" || !filepath.IsAbs(root) {
		t.Fatal("LATTICE_LINECHAIN_E2E_RUNTIME_ROOT must be an absolute path")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	origin := lifecycleEchoOrigin(t)
	aPort, bPort, clientPort := lifecycleFreePort(t), lifecycleFreePort(t), lifecycleFreePort(t)
	decoy := httptest.NewTLSServer(nil)
	t.Cleanup(decoy.Close)
	decoyHost, decoyPortText, err := net.SplitHostPort(strings.TrimPrefix(decoy.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	decoyPort, _ := strconv.Atoi(decoyPortText)
	realityPrivate, realityPublic := lifecycleRealityKeypair(t, singbox)
	sourceRealityPrivate, sourceRealityPublic := lifecycleRealityKeypair(t, singbox)

	e5Fixture := newE5PluginServerFixture(t, root)
	srv := e5Fixture.server
	sourceUUID, targetUUID, user, target := seedLineChainFixtureIntoAtSourcePort(t, srv, bPort)
	observerPort := lifecycleFreePort(t)
	observer := newLifecycleObserverAtPort(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(aPort)), observerPort)
	credential, ok := vpnCredentialForProtocol(user.Credentials, model.ProxyProtocolVLESS)
	if !ok {
		t.Fatal("managed target credential missing")
	}
	sourceHash := ""
	for _, group := range srv.buildLineGroups() {
		for _, line := range group.Lines {
			if line.LineUUID == sourceUUID {
				sourceHash = line.LineHashID
			}
		}
	}
	if sourceHash == "" {
		t.Fatal("source line hash authority missing")
	}
	sourceDef := managedLineDef{
		LineUUID: sourceUUID, NodeID: "node-b", LineHashID: sourceHash, Tag: "source-b", Port: bPort,
		SNI: "source.e5.lattice.invalid", HandshakeServer: decoyHost, HandshakePort: decoyPort,
		RealityPrivateKey: sourceRealityPrivate, RealityPublicKey: sourceRealityPublic, ShortID: "fedcba9876543210",
		UserID: user.ID, UserName: userLineName(user.ID, sourceUUID), Status: managedLineStatusApplied,
	}
	if err := srv.putManagedLineDef(sourceDef); err != nil {
		t.Fatal(err)
	}
	target.SNI = "e2e.lattice.invalid"
	target.Tag = "target-a"
	target.Port = observerPort
	target.HandshakeServer = decoyHost
	target.HandshakePort = decoyPort
	target.RealityPrivateKey = realityPrivate
	target.RealityPublicKey = realityPublic
	target.ShortID = "0123456789abcdef"
	// Preserve the fixture-owned line-hash authority when rewriting target
	// runtime metadata; linemeta rejects reusing a UUID under a new hash key.
	for _, entry := range srv.store.KV(lineUUIDKVBucket) {
		if strings.EqualFold(strings.TrimSpace(entry.Value), targetUUID) {
			target.LineHashID = entry.Key
			break
		}
	}
	if err := srv.putManagedLineDef(target); err != nil {
		t.Fatal(err)
	}
	nodeA, _ := srv.store.Node("node-a")
	nodeA.PublicIP = "127.0.0.1"
	if err := srv.store.UpsertNode(nodeA); err != nil {
		t.Fatal(err)
	}
	nodeB, _ := srv.store.Node("node-b")
	nodeB.PublicIP = "127.0.0.1"
	if err := srv.store.UpsertNode(nodeB); err != nil {
		t.Fatal(err)
	}
	seedManagedLineNode(t, srv, "node-a", []model.SingBoxNode{{
		Name: target.Tag, Protocol: "vless", Network: "tcp", Address: "127.0.0.1",
		Port: strconv.Itoa(observerPort), SNI: target.SNI, LineUUID: targetUUID, LineID: strings.TrimPrefix(target.LineHashID, "line_"),
	}})
	seedManagedLineNode(t, srv, "node-b", []model.SingBoxNode{{
		Name: sourceDef.Tag, Protocol: "vless", Network: "tcp", Address: "127.0.0.1",
		Port: strconv.Itoa(bPort), SNI: sourceDef.SNI, LineUUID: sourceUUID, LineID: strings.TrimPrefix(sourceHash, "line_"),
	}})
	// Inventory seeding persists the fixture's default public address; restore
	// loopback after every seed so the official E2E share endpoint reaches the
	// local sing-box process rather than the documentation address.
	nodeA, _ = srv.store.Node("node-a")
	nodeA.PublicIP = "127.0.0.1"
	if err := srv.store.UpsertNode(nodeA); err != nil {
		t.Fatal(err)
	}
	nodeB, _ = srv.store.Node("node-b")
	nodeB.PublicIP = "127.0.0.1"
	if err := srv.store.UpsertNode(nodeB); err != nil {
		t.Fatal(err)
	}
	_ = srv.buildLineGroups()
	seedE5ConvergedTerminalDefinition(t, srv, target)
	taskBaseline := len(srv.store.Tasks())

	aDir := filepath.Join(root, "a")
	configDir := filepath.Join(root, "conf")
	clientDir := filepath.Join(root, "client")
	txnDir := filepath.Join(root, "txn")
	outboxDir := filepath.Join(root, "outbox")
	sidecar := filepath.Join(root, "lattice-metadata.json")
	binDir := filepath.Join(root, "bin")
	for _, dir := range []string{aDir, configDir, clientDir, txnDir, outboxDir, binDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	lifecycleWrite(t, filepath.Join(aDir, "config.json"), fmt.Sprintf(`{"log":{"level":"error"},"inbounds":[{"type":"vless","tag":"target-a","listen":"127.0.0.1","listen_port":%d,"users":[{"uuid":%q,"flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"e2e.lattice.invalid","reality":{"enabled":true,"handshake":{"server":%q,"server_port":%d},"private_key":%q,"short_id":["0123456789abcdef"]}}}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`, aPort, credential.UUID, decoyHost, decoyPort, realityPrivate))
	lifecycleWrite(t, filepath.Join(configDir, "config.json"), fmt.Sprintf(`{"log":{"level":"error"},"inbounds":[{"type":"vless","tag":"source-b","listen":"127.0.0.1","listen_port":%d,"users":[{"uuid":%q,"flow":%q}],"tls":{"enabled":true,"server_name":%q,"reality":{"enabled":true,"handshake":{"server":%q,"server_port":%d},"private_key":%q,"short_id":[%q]}}}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`, bPort, credential.UUID, credential.Flow, sourceDef.SNI, decoyHost, decoyPort, sourceRealityPrivate, sourceDef.ShortID))
	lifecycleWrite(t, filepath.Join(clientDir, "config.json"), fmt.Sprintf(`{"log":{"level":"error"},"inbounds":[{"type":"socks","tag":"client","listen":"127.0.0.1","listen_port":%d}],"outbounds":[{"type":"vless","tag":"to-b","server":"127.0.0.1","server_port":%d,"uuid":%q,"flow":%q,"tls":{"enabled":true,"server_name":%q,"utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":%q,"short_id":%q}}}],"route":{"rules":[{"inbound":["client"],"outbound":"to-b"}]}}`, clientPort, bPort, credential.UUID, credential.Flow, sourceDef.SNI, sourceRealityPublic, sourceDef.ShortID))
	lifecycleStartProcess(t, singbox, root, "a", aDir, aPort)
	lifecycleStartProcess(t, singbox, root, "b", configDir, bPort)
	lifecycleStartProcess(t, singbox, root, "client", clientDir, clientPort)
	lifecycleSOCKSEcho(t, clientPort, origin)
	observer.reset()
	if observer.accepted() != 0 {
		t.Fatal("B traversed A before the server-issued chain was applied")
	}
	handler := srv.Handler()
	httpServer := httptest.NewServer(handler)
	t.Cleanup(func() { httpServer.Close() })
	cookies, csrf := loginSession(t, handler)
	activateE5Plugin(t, handler, cookies, csrf, "latticenet.vpn-core")
	activateE5Plugin(t, handler, cookies, csrf, "latticenet.sub-store")

	planBody := fmt.Sprintf(`{"source_line_uuid":%q,"target_line_uuid":%q}`, sourceUUID, targetUUID)
	t.Logf("lifecycle source=%s target=%s", sourceUUID, targetUUID)
	var planned struct {
		Approval model.Approval `json:"approval"`
	}
	persistentJSON(t, httpServer.Client(), http.MethodPost, httpServer.URL+"/api/network/lines/chains/plan", planBody, cookies, csrf, &planned)
	if planned.Approval.ID == "" {
		t.Fatal("persistent plan returned no approval")
	}
	planSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(planned.Approval.Plan)))
	approveBody := fmt.Sprintf(`{"approval_id":%q,"queue_apply":true,"plan_sha256":%q}`, planned.Approval.ID, planSHA)
	persistentJSON(t, httpServer.Client(), http.MethodPost, httpServer.URL+"/api/network/approvals/approve", approveBody, cookies, csrf, nil)

	originalNode, _ := srv.store.Node("node-b")
	nodeToken := enrollNamedNodeToken(t, handler, cookies, csrf, "node-b", "Node B")
	enrolledNode, _ := srv.store.Node("node-b")
	originalNode.TokenHash = enrolledNode.TokenHash
	if err := srv.store.UpsertNode(originalNode); err != nil {
		t.Fatal(err)
	}
	srv.replaceAgentCapabilities("node-b", []string{lineChainDurableCapability})

	req, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/api/agent/tasks?node_id=node-b", nil)
	req.Header.Set("Authorization", "Bearer "+nodeToken)
	req.Header.Set(agentCapabilitiesHeader, lineChainDurableCapability)
	res, err := httpServer.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var leased []agentTaskView
	if res.StatusCode != http.StatusOK || json.NewDecoder(res.Body).Decode(&leased) != nil || len(leased) != 1 || leased[0].DurableProtocol != store.DurableProtocolLineChainV2 {
		t.Fatalf("lease=%d %+v", res.StatusCode, leased)
	}
	if strings.Contains(leased[0].Script, "credential-canary") {
		t.Fatal("leased script leaked secret canary")
	}
	const encodedPrefix = "printf '%s' '"
	encodedStart := strings.Index(leased[0].Script, encodedPrefix)
	encodedEnd := strings.Index(leased[0].Script, "' | base64 -d")
	if encodedStart < 0 || encodedEnd <= encodedStart {
		t.Fatal("leased script did not contain the canonical document wrapper")
	}
	documentBytes, err := base64.StdEncoding.DecodeString(leased[0].Script[encodedStart+len(encodedPrefix) : encodedEnd])
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Fragment *string `json:"fragment"`
	}
	if err := json.Unmarshal(documentBytes, &document); err != nil || document.Fragment == nil {
		t.Fatalf("leased document fragment: %v", err)
	}
	fragmentProbe := filepath.Join(root, "server-issued-fragment.json")
	if err := os.WriteFile(fragmentProbe, []byte(*document.Fragment), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(singbox, "check", "-c", fragmentProbe).CombinedOutput(); err != nil {
		t.Fatalf("server-issued fragment rejected by official sing-box: %v: %s", err, out)
	}

	if err := os.WriteFile(sidecar, []byte(fmt.Sprintf(`{"schema":"lattice.singbox-metadata.v2","unknown_root":{"keep":true},"inbounds":[{"tag":"before","line_uuid":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},{"tag":"source-b","line_uuid":%q,"ordinary":"keep"},{"tag":"after","line_uuid":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}]}`, sourceUUID)), 0o600); err != nil {
		t.Fatal(err)
	}
	systemctl := filepath.Join(binDir, "systemctl")
	systemctlBody := fmt.Sprintf("#!/bin/sh\ncase \"$1\" in\n  restart) exec %q -test.run=^TestLinechainE2ERestartHelper$ -- %q;;\n  is-active) exec %q -test.run=^TestLinechainE2EActiveHelper$ -- %q;;\n  *) exit 2;;\nesac\n", agentTest, root, agentTest, root)
	if err := os.WriteFile(systemctl, []byte(systemctlBody), 0o700); err != nil {
		t.Fatal(err)
	}
	taskJSON := filepath.Join(root, "task1.json")
	taskBytes, _ := json.Marshal(struct {
		ID          string `json:"id"`
		LeaseID     string `json:"lease_id"`
		Interpreter string `json:"interpreter"`
		Script      string `json:"script"`
		TimeoutSec  int    `json:"timeout_sec"`
		OutputLimit int    `json:"output_limit"`
	}{leased[0].ID, leased[0].LeaseID, leased[0].Interpreter, leased[0].Script, leased[0].TimeoutSec, leased[0].OutputLimit})
	if err := os.WriteFile(taskJSON, taskBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	beginResult := filepath.Join(root, "begin-result.json")
	beginCmd := exec.Command(agentTest, "-test.run=^TestLinechainE2EBeginHelper$", "--", root)
	beginCmd.Env = append(os.Environ(), "LATTICE_LINECHAIN_E2E_ROOT="+root, "LATTICE_LINECHAIN_E2E_TASK_JSON="+taskJSON, "LATTICE_LINECHAIN_E2E_OUTBOX="+outboxDir, "LATTICE_LINECHAIN_E2E_TASK="+leased[0].ID, "LATTICE_LINECHAIN_E2E_LEASE="+leased[0].LeaseID, "LATTICE_LINECHAIN_E2E_BEGIN_RESULT="+beginResult)
	_ = runLifecycleAgentHelper(t, beginCmd)
	if raw, err := os.ReadFile(beginResult); err != nil || !bytes.Contains(raw, []byte(`"committed":true`)) {
		t.Fatalf("begin durability missing: %v %s", err, raw)
	}
	cmd := exec.Command("sh", "-c", leased[0].Script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	crashMarker := filepath.Join(root, "crash.marker")
	cmd.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"), "LATTICE_AGENT_BIN="+agent, "LATTICE_LINECHAIN_TXN_DIR="+txnDir, "LATTICE_LINECHAIN_CONFIG_DIR="+configDir, "LATTICE_LINECHAIN_SIDECAR_PATH="+sidecar, "LATTICE_TASK_ID="+leased[0].ID, "LATTICE_TASK_LEASE_ID="+leased[0].LeaseID, "LATTICE_LINECHAIN_TASK_SCRIPT_SHA256="+fmt.Sprintf("%x", sha256.Sum256([]byte(leased[0].Script))), "LATTICE_LINECHAIN_E2E_ROOT="+root, "LATTICE_LINECHAIN_E2E_BIN="+singbox, "LATTICE_LINECHAIN_E2E_CONFIG_DIR="+configDir, "LATTICE_LINECHAIN_E2E_SIDECAR="+sidecar, "LATTICE_LINECHAIN_E2E_B_PORT="+strconv.Itoa(bPort), "LATTICE_LINECHAIN_E2E_CRASH_MARKER="+crashMarker)
	// The production Manager resolves sing-box by name. The wrapper executes only
	// the official binary and preserves its diagnostics for an actionable failure.
	checkLog := filepath.Join(root, "sing-box-check.log")
	wrapper := fmt.Sprintf("#!/bin/sh\n%q \"$@\" 2>%q\nstatus=$?\ncat %q >&2\nexit $status\n", singbox, checkLog, checkLog)
	if err := os.WriteFile(filepath.Join(binDir, "sing-box"), []byte(wrapper), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	markerDeadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(crashMarker); err == nil {
			break
		}
		if time.Now().After(markerDeadline) {
			t.Fatal("leased helper did not reach deterministic crash marker")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("crash attempt unexpectedly completed successfully")
	}
	recoveryResult := filepath.Join(root, "recovery-result.json")
	recoverCmd := exec.Command(agentTest, "-test.run=^TestLinechainE2ERecoverHelper$", "--", root)
	recoverCmd.Env = append(os.Environ(), "LATTICE_LINECHAIN_E2E_ROOT="+root, "LATTICE_LINECHAIN_E2E_BIN="+singbox, "LATTICE_LINECHAIN_E2E_CONFIG_DIR="+configDir, "LATTICE_LINECHAIN_E2E_SIDECAR="+sidecar, "LATTICE_LINECHAIN_E2E_B_PORT="+strconv.Itoa(bPort), "LATTICE_LINECHAIN_E2E_CRASH_MARKER="+crashMarker, "LATTICE_LINECHAIN_E2E_RECOVERY_RESULT="+recoveryResult, "LATTICE_LINECHAIN_E2E_OUTBOX="+outboxDir, "LATTICE_LINECHAIN_E2E_TASK_JSON="+taskJSON, "LATTICE_LINECHAIN_E2E_TASK="+leased[0].ID, "LATTICE_LINECHAIN_E2E_LEASE="+leased[0].LeaseID)
	_ = runLifecycleAgentHelper(t, recoverCmd)
	if raw, err := os.ReadFile(recoveryResult); err != nil || !bytes.Contains(raw, []byte(leased[0].ID)) {
		t.Fatalf("recovery result missing leased task: err=%v raw=%s", err, raw)
	}
	// Recovery is the only authority for the interrupted attempt. Post its
	// exact non-success result before any inventory or observable traffic.
	recoveryRaw, _ := os.ReadFile(recoveryResult)
	recoveryBody := []byte(fmt.Sprintf(`{"node_id":"node-b","result":%s}`, recoveryRaw))
	if !bytes.Contains(recoveryRaw, []byte(`"exit_code":-1`)) || !bytes.Contains(recoveryRaw, []byte(`"error":"`)) {
		t.Fatalf("recovery result was not an interrupted failure: %s", recoveryRaw)
	}
	for attempt := 0; attempt < 2; attempt++ {
		postAgentJSON(t, httpServer.Client(), httpServer.URL+"/api/agent/task-result", nodeToken, recoveryBody)
	}
	ackResult := filepath.Join(root, "ack-task1.json")
	ackCmd := exec.Command(agentTest, "-test.run=^TestLinechainE2EAckHelper$", "--", root)
	ackCmd.Env = append(os.Environ(), "LATTICE_LINECHAIN_E2E_OUTBOX="+outboxDir, "LATTICE_LINECHAIN_E2E_TASK="+leased[0].ID, "LATTICE_LINECHAIN_E2E_LEASE="+leased[0].LeaseID, "LATTICE_LINECHAIN_E2E_ACK_RESULT="+ackResult)
	_ = runLifecycleAgentHelper(t, ackCmd)
	// The interrupted lease is terminally failed; obtain a fresh approval and
	// lease before any retry resolve. The server must reproduce the exact
	// approved document bytes rather than allowing a new authority.
	var retryPlanned struct {
		Approval model.Approval `json:"approval"`
	}
	persistentJSON(t, httpServer.Client(), http.MethodPost, httpServer.URL+"/api/network/lines/chains/plan", planBody, cookies, csrf, &retryPlanned)
	retryPlanSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(retryPlanned.Approval.Plan)))
	persistentJSON(t, httpServer.Client(), http.MethodPost, httpServer.URL+"/api/network/approvals/approve", fmt.Sprintf(`{"approval_id":%q,"queue_apply":true,"plan_sha256":%q}`, retryPlanned.Approval.ID, retryPlanSHA), cookies, csrf, nil)
	retryReq, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/api/agent/tasks?node_id=node-b", nil)
	retryReq.Header.Set("Authorization", "Bearer "+nodeToken)
	retryReq.Header.Set(agentCapabilitiesHeader, lineChainDurableCapability)
	retryRes, err := httpServer.Client().Do(retryReq)
	if err != nil {
		t.Fatal(err)
	}
	defer retryRes.Body.Close()
	var retryLeased []agentTaskView
	if retryRes.StatusCode != http.StatusOK || json.NewDecoder(retryRes.Body).Decode(&retryLeased) != nil || len(retryLeased) != 1 {
		t.Fatalf("retry lease=%d %+v", retryRes.StatusCode, retryLeased)
	}
	if retryLeased[0].Script != leased[0].Script {
		t.Fatal("retry lease document bytes differ from the original approved artifact")
	}
	retryTaskJSON := filepath.Join(root, "task2.json")
	retryTaskBytes, _ := json.Marshal(struct {
		ID          string `json:"id"`
		LeaseID     string `json:"lease_id"`
		Interpreter string `json:"interpreter"`
		Script      string `json:"script"`
		TimeoutSec  int    `json:"timeout_sec"`
		OutputLimit int    `json:"output_limit"`
	}{retryLeased[0].ID, retryLeased[0].LeaseID, retryLeased[0].Interpreter, retryLeased[0].Script, retryLeased[0].TimeoutSec, retryLeased[0].OutputLimit})
	if err := os.WriteFile(retryTaskJSON, retryTaskBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	retryBegin := filepath.Join(root, "begin-task2.json")
	retryBeginCmd := exec.Command(agentTest, "-test.run=^TestLinechainE2EBeginHelper$", "--", root)
	retryBeginCmd.Env = append(os.Environ(), "LATTICE_LINECHAIN_E2E_TASK_JSON="+retryTaskJSON, "LATTICE_LINECHAIN_E2E_OUTBOX="+outboxDir, "LATTICE_LINECHAIN_E2E_TASK="+retryLeased[0].ID, "LATTICE_LINECHAIN_E2E_LEASE="+retryLeased[0].LeaseID, "LATTICE_LINECHAIN_E2E_BEGIN_RESULT="+retryBegin)
	_ = runLifecycleAgentHelper(t, retryBeginCmd)
	retryCmd := exec.Command("sh", "-c", retryLeased[0].Script)
	retryCmd.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"), "LATTICE_AGENT_BIN="+agent, "LATTICE_LINECHAIN_TXN_DIR="+txnDir, "LATTICE_LINECHAIN_CONFIG_DIR="+configDir, "LATTICE_LINECHAIN_SIDECAR_PATH="+sidecar, "LATTICE_TASK_ID="+retryLeased[0].ID, "LATTICE_TASK_LEASE_ID="+retryLeased[0].LeaseID, "LATTICE_LINECHAIN_TASK_SCRIPT_SHA256="+fmt.Sprintf("%x", sha256.Sum256([]byte(retryLeased[0].Script))), "LATTICE_LINECHAIN_E2E_ROOT="+root, "LATTICE_LINECHAIN_E2E_BIN="+singbox, "LATTICE_LINECHAIN_E2E_CONFIG_DIR="+configDir, "LATTICE_LINECHAIN_E2E_SIDECAR="+sidecar, "LATTICE_LINECHAIN_E2E_B_PORT="+strconv.Itoa(bPort))
	if out, err := retryCmd.CombinedOutput(); err != nil {
		t.Fatalf("retry leased helper failed: %v: %s", err, out)
	} else if len(out) > 0 {
		t.Logf("retry leased helper: %s", out)
	}
	sidecarBytes, _ := os.ReadFile(sidecar)
	if !bytes.Contains(sidecarBytes, []byte(`"unknown_root":{"keep":true}`)) || !bytes.Contains(sidecarBytes, []byte(`"ordinary":"keep"`)) {
		t.Fatalf("host fields lost: %s", sidecarBytes)
	}
	// The exact leased server document is now live: B's real outbound must
	// traverse observer -> A -> origin, proving the applied artifact rather
	// than a separately hand-built client document.
	lifecycleSOCKSEcho(t, clientPort, origin)
	if observer.accepted() == 0 {
		configBytes, _ := os.ReadFile(filepath.Join(configDir, "config.json"))
		t.Fatalf("server-issued chain produced no B -> observer -> A traffic; config=%s", configBytes)
	}
	// Exercise deterministic process-group recovery before reporting the task
	// result. The recovered B must preserve the applied server-issued config.
	lifecycleSOCKSEcho(t, clientPort, origin)
	if observer.accepted() < 2 {
		t.Fatal("recovered B did not traverse observer -> A")
	}

	resolveResult := filepath.Join(root, "resolve-result.json")
	resolveCmd := exec.Command(agentTest, "-test.run=^TestLinechainE2EResolveHelper$", "--", root)
	resolveCmd.Env = append(os.Environ(), "LATTICE_LINECHAIN_E2E_ROOT="+root, "LATTICE_LINECHAIN_E2E_BIN="+singbox, "LATTICE_LINECHAIN_E2E_CONFIG_DIR="+configDir, "LATTICE_LINECHAIN_E2E_SIDECAR="+sidecar, "LATTICE_LINECHAIN_E2E_B_PORT="+strconv.Itoa(bPort), "LATTICE_LINECHAIN_E2E_TASK="+retryLeased[0].ID, "LATTICE_LINECHAIN_E2E_LEASE="+retryLeased[0].LeaseID, "LATTICE_LINECHAIN_E2E_RESOLVE_RESULT="+resolveResult, "LATTICE_LINECHAIN_E2E_OUTBOX="+outboxDir)
	_ = runLifecycleAgentHelper(t, resolveCmd)
	resolveRaw, err := os.ReadFile(resolveResult)
	if err != nil || !bytes.Contains(resolveRaw, []byte(retryLeased[0].ID)) {
		t.Fatalf("resolve result missing leased task: err=%v raw=%s", err, resolveRaw)
	}
	resultBody := fmt.Sprintf(`{"node_id":"node-b","result":%s}`, resolveRaw)
	// First 200 is deliberately ignored; exact replay must remain idempotent.
	for attempt := 0; attempt < 2; attempt++ {
		req, _ := http.NewRequest(http.MethodPost, httpServer.URL+"/api/agent/task-result", strings.NewReader(resultBody))
		req.Header.Set("Authorization", "Bearer "+nodeToken)
		req.Header.Set("Content-Type", "application/json")
		got, err := httpServer.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, got.Body)
		got.Body.Close()
		if got.StatusCode != http.StatusOK {
			t.Fatalf("result replay %d", got.StatusCode)
		}
	}
	ack2 := filepath.Join(root, "ack-task2.json")
	ack2Cmd := exec.Command(agentTest, "-test.run=^TestLinechainE2EAckHelper$", "--", root)
	ack2Cmd.Env = append(os.Environ(), "LATTICE_LINECHAIN_E2E_OUTBOX="+outboxDir, "LATTICE_LINECHAIN_E2E_TASK="+retryLeased[0].ID, "LATTICE_LINECHAIN_E2E_LEASE="+retryLeased[0].LeaseID, "LATTICE_LINECHAIN_E2E_ACK_RESULT="+ack2)
	_ = runLifecycleAgentHelper(t, ack2Cmd)
	snapshot := srv.store.LineChainSnapshot()
	if snapshot.Definitions[sourceUUID].Status != store.LineChainStatusAppliedUnobserved || len(srv.store.Tasks()) != taskBaseline+2 {
		t.Fatalf("promotion/task mismatch: %+v tasks=%d", snapshot, len(srv.store.Tasks()))
	}

	// Reconcile the server against an ordinary agent inventory while the same
	// HTTP server remains alive. This observation is metadata-only and must not
	// create another E3 task or rewrite the target definition.
	inventoryResult := filepath.Join(root, "inventory-result.json")
	invCmd := exec.Command(agentTest, "-test.run=^TestLinechainE2EInventoryHelper$", "--", root)
	invCmd.Env = append(os.Environ(), "LATTICE_LINECHAIN_E2E_ROOT="+root, "LATTICE_LINECHAIN_E2E_CONFIG_DIR="+configDir, "LATTICE_LINECHAIN_E2E_SIDECAR="+sidecar, "LATTICE_LINECHAIN_E2E_INVENTORY_RESULT="+inventoryResult)
	_ = runLifecycleAgentHelper(t, invCmd)
	actualInventory, err := os.ReadFile(inventoryResult)
	if err != nil || len(actualInventory) == 0 {
		t.Fatalf("inventory helper result missing: %v", err)
	}
	inventoryRaw := []byte(fmt.Sprintf(`{"node_id":"node-b","inventory":%s}`, actualInventory))
	postAgentJSON(t, httpServer.Client(), httpServer.URL+"/api/agent/singbox-inventory", nodeToken, inventoryRaw)
	if len(srv.store.Tasks()) != taskBaseline+2 {
		t.Fatalf("inventory queued an extra E3 task: %d", len(srv.store.Tasks()))
	}
	if got := srv.store.LineChainSnapshot().Definitions[sourceUUID]; got.Status != store.LineChainStatusConverged || len(srv.store.Tasks()) != taskBaseline+2 {
		t.Fatalf("observed apply did not converge: %+v", got)
	}
	assertDeclaredE2EEdge(t, srv.buildLineGroups(), sourceUUID, targetUUID, true)
	// E5 Phase A-D runs only after the server has observed the exact issued
	// chain. The real signed vpn-core and SubStore runtimes must agree on one
	// immutable graph projection, preview without writing, persist the explicit
	// selection, publish the same bytes, and serve them through the public share.
	e5Graph := exerciseE5GraphAtConvergence(t, srv, handler, httpServer, cookies, csrf, user, sourceUUID)
	shareClientPort := lifecycleFreePort(t)
	startE5ClientFromShareURI(t, singbox, root, e5Graph.URI, shareClientPort)
	beforeShareTraffic := observer.accepted()
	lifecycleSOCKSEcho(t, shareClientPort, origin)
	if observer.accepted() <= beforeShareTraffic {
		t.Fatal("public share URI client did not traverse B -> observer -> A")
	}
	const e5SubStorePluginID = "latticenet.sub-store"
	const e5SubscriptionID = "e5-graph"
	lastGood, ok := srv.store.SubscriptionSnapshot(e5SubStorePluginID, e5SubscriptionID)
	if !ok || lastGood.Stale || lastGood.SourceVersion != e5Graph.SourceVersion || lastGood.FetchedAt.IsZero() || lastGood.Raw == "" {
		t.Fatalf("initial durable E5 snapshot mismatch: ok=%t stale=%t source=%s graph=%s fetched=%s bytes=%d", ok, lastGood.Stale, lastGood.SourceVersion, e5Graph.SourceVersion, lastGood.FetchedAt, len(lastGood.Raw))
	}
	// Force an inventory drift while the physical chain remains configured.
	driftSidecar, err := os.ReadFile(sidecar)
	if err != nil {
		t.Fatal(err)
	}
	driftSidecar = bytes.Replace(driftSidecar, []byte(targetUUID), []byte("33333333-3333-4333-8333-333333333333"), 1)
	if err := os.WriteFile(sidecar, driftSidecar, 0o600); err != nil {
		t.Fatal(err)
	}
	driftInventory := filepath.Join(root, "drift-inventory-result.json")
	driftInventoryCmd := exec.Command(agentTest, "-test.run=^TestLinechainE2EInventoryHelper$", "--", root)
	driftInventoryCmd.Env = append(os.Environ(), "LATTICE_LINECHAIN_E2E_ROOT="+root, "LATTICE_LINECHAIN_E2E_CONFIG_DIR="+configDir, "LATTICE_LINECHAIN_E2E_SIDECAR="+sidecar, "LATTICE_LINECHAIN_E2E_INVENTORY_RESULT="+driftInventory)
	_ = runLifecycleAgentHelper(t, driftInventoryCmd)
	driftInventoryRaw, err := os.ReadFile(driftInventory)
	if err != nil || len(driftInventoryRaw) == 0 {
		t.Fatalf("drift inventory helper result missing: %v", err)
	}
	postAgentJSON(t, httpServer.Client(), httpServer.URL+"/api/agent/singbox-inventory", nodeToken, []byte(fmt.Sprintf(`{"node_id":"node-b","inventory":%s}`, driftInventoryRaw)))
	refreshReq, _ := http.NewRequest(http.MethodPost, httpServer.URL+"/api/subscription-shares/"+e5Graph.Share.ID+"/refresh", nil)
	refreshReq.Header.Set("X-Lattice-CSRF", csrf)
	for _, c := range cookies {
		refreshReq.AddCookie(c)
	}
	refreshRes, err := httpServer.Client().Do(refreshReq)
	if err != nil {
		t.Fatal(err)
	}
	refreshRaw, _ := io.ReadAll(refreshRes.Body)
	refreshRes.Body.Close()
	if refreshRes.StatusCode != http.StatusOK || !bytes.Contains(refreshRaw, []byte(`"stale":true`)) {
		t.Fatalf("drift refresh status=%d body=%s", refreshRes.StatusCode, refreshRaw)
	}
	staleLastGood, ok := srv.store.SubscriptionSnapshot(e5SubStorePluginID, e5SubscriptionID)
	if !ok || !staleLastGood.Stale || staleLastGood.FetchError == "" || staleLastGood.SourceVersion != lastGood.SourceVersion ||
		staleLastGood.Raw != lastGood.Raw || !staleLastGood.FetchedAt.Equal(lastGood.FetchedAt) || !staleLastGood.LastAttemptAt.After(lastGood.FetchedAt) {
		t.Fatalf("inventory drift did not preserve durable last-good authority: ok=%t stale=%t error=%q source=%s want_source=%s fetched=%s want_fetched=%s bytes=%d want_bytes=%d attempt=%s", ok, staleLastGood.Stale, staleLastGood.FetchError, staleLastGood.SourceVersion, lastGood.SourceVersion, staleLastGood.FetchedAt, lastGood.FetchedAt, len(staleLastGood.Raw), len(lastGood.Raw), staleLastGood.LastAttemptAt)
	}
	// Restore the converged observation and force refresh again; stale state
	// must clear and the provider must publish the recovered snapshot.
	recoveredSidecar := bytes.Replace(driftSidecar, []byte("33333333-3333-4333-8333-333333333333"), []byte(targetUUID), 1)
	if err := os.WriteFile(sidecar, recoveredSidecar, 0o600); err != nil {
		t.Fatal(err)
	}
	recoveredInventory := filepath.Join(root, "recovered-inventory-result.json")
	recoveredInventoryCmd := exec.Command(agentTest, "-test.run=^TestLinechainE2EInventoryHelper$", "--", root)
	recoveredInventoryCmd.Env = append(os.Environ(), "LATTICE_LINECHAIN_E2E_ROOT="+root, "LATTICE_LINECHAIN_E2E_CONFIG_DIR="+configDir, "LATTICE_LINECHAIN_E2E_SIDECAR="+sidecar, "LATTICE_LINECHAIN_E2E_INVENTORY_RESULT="+recoveredInventory)
	_ = runLifecycleAgentHelper(t, recoveredInventoryCmd)
	recoveredInventoryRaw, err := os.ReadFile(recoveredInventory)
	if err != nil || len(recoveredInventoryRaw) == 0 {
		t.Fatalf("recovered inventory helper result missing: %v", err)
	}
	postAgentJSON(t, httpServer.Client(), httpServer.URL+"/api/agent/singbox-inventory", nodeToken, []byte(fmt.Sprintf(`{"node_id":"node-b","inventory":%s}`, recoveredInventoryRaw)))
	recoverReq, _ := http.NewRequest(http.MethodPost, httpServer.URL+"/api/subscription-shares/"+e5Graph.Share.ID+"/refresh", nil)
	recoverReq.Header.Set("X-Lattice-CSRF", csrf)
	for _, c := range cookies {
		recoverReq.AddCookie(c)
	}
	recoverRes, err := httpServer.Client().Do(recoverReq)
	if err != nil {
		t.Fatal(err)
	}
	recoverRaw, _ := io.ReadAll(recoverRes.Body)
	recoverRes.Body.Close()
	if recoverRes.StatusCode != http.StatusOK || bytes.Contains(recoverRaw, []byte(`"stale":true`)) {
		t.Fatalf("recovery refresh status=%d body=%s", recoverRes.StatusCode, recoverRaw)
	}
	recoveredSnapshot, ok := srv.store.SubscriptionSnapshot(e5SubStorePluginID, e5SubscriptionID)
	if !ok || recoveredSnapshot.Stale || recoveredSnapshot.FetchError != "" || recoveredSnapshot.SourceVersion == "" || recoveredSnapshot.SourceVersion == lastGood.SourceVersion ||
		recoveredSnapshot.Raw != lastGood.Raw || !recoveredSnapshot.FetchedAt.After(lastGood.FetchedAt) || !recoveredSnapshot.LastAttemptAt.Equal(recoveredSnapshot.FetchedAt) {
		t.Fatalf("inventory recovery did not publish fresh durable authority: ok=%t stale=%t error=%q source=%s old_source=%s fetched=%s old_fetched=%s bytes=%d want_bytes=%d attempt=%s", ok, recoveredSnapshot.Stale, recoveredSnapshot.FetchError, recoveredSnapshot.SourceVersion, lastGood.SourceVersion, recoveredSnapshot.FetchedAt, lastGood.FetchedAt, len(recoveredSnapshot.Raw), len(lastGood.Raw), recoveredSnapshot.LastAttemptAt)
	}

	// A real server restart must reap both persistent plugin workers before the
	// encrypted JSON store and its hot Bolt sidecar are closed. Reopening the
	// same durable files with the same cipher, bundles, runtime roots, and trust
	// policy must restore active lifecycle state and arm fresh worker processes.
	httpServer.Close()
	oldPluginPGIDs := lifecyclePluginRuntimeProcessGroups(t, e5Fixture.runtimeDir)
	if len(oldPluginPGIDs) != 2 {
		t.Fatalf("expected two live E5 plugin process groups before restart, got %v", oldPluginPGIDs)
	}
	e5Fixture = e5Fixture.reopen(t, func() {
		assertLifecycleProcessGroupsGone(t, oldPluginPGIDs)
	})
	srv = e5Fixture.server
	handler = srv.Handler()
	httpServer = httptest.NewServer(handler)
	cookies, csrf = loginSession(t, handler)
	for _, pluginID := range []string{e5SubStorePluginID, vpnCorePluginID} {
		installation, installed := srv.store.PluginInstallation(pluginID)
		runtimeStatus, armed := srv.pluginRuntime.Status(pluginID)
		if !installed || installation.Status != model.PluginStatusActive || !armed || runtimeStatus.State != "armed" {
			t.Fatalf("plugin did not auto-rearm after restart: id=%s installed=%t status=%s armed=%t runtime=%s", pluginID, installed, installation.Status, armed, runtimeStatus.State)
		}
	}
	newPluginPGIDs := lifecyclePluginRuntimeProcessGroups(t, e5Fixture.runtimeDir)
	if len(newPluginPGIDs) != 2 {
		t.Fatalf("expected two fresh E5 plugin process groups after restart, got %v", newPluginPGIDs)
	}
	for _, pgid := range newPluginPGIDs {
		for _, oldPGID := range oldPluginPGIDs {
			if pgid == oldPGID {
				t.Fatalf("plugin process group %d was reused across server restart", pgid)
			}
		}
	}
	persistedShare, shareOK := srv.store.SubscriptionShare(e5Graph.Share.ID)
	persistedSnapshot, snapshotOK := srv.store.SubscriptionSnapshot(e5SubStorePluginID, e5SubscriptionID)
	persistedDefinition := srv.store.LineChainSnapshot().Definitions[sourceUUID]
	if !shareOK || persistedShare.Token != e5Graph.Share.Token || !snapshotOK || persistedSnapshot.SourceVersion != recoveredSnapshot.SourceVersion ||
		persistedSnapshot.Raw != recoveredSnapshot.Raw || !persistedSnapshot.FetchedAt.Equal(recoveredSnapshot.FetchedAt) || persistedDefinition.TargetLineUUID != targetUUID ||
		persistedDefinition.Status != store.LineChainStatusConverged || len(srv.store.Tasks()) != taskBaseline+2 {
		t.Fatalf("E5 durable state did not survive restart: share=%t snapshot=%t source=%s want_source=%s fetched=%s want_fetched=%s target=%s status=%s tasks=%d", shareOK, snapshotOK, persistedSnapshot.SourceVersion, recoveredSnapshot.SourceVersion, persistedSnapshot.FetchedAt, recoveredSnapshot.FetchedAt, persistedDefinition.TargetLineUUID, persistedDefinition.Status, len(srv.store.Tasks()))
	}
	walResult, walEnabled, walErr := srv.store.AuditWALVerify()
	if walErr != nil || !walEnabled || walResult.Count == 0 || walResult.Anchor == nil {
		t.Fatalf("reopened E5 AuditWAL verification failed: enabled=%t count=%d anchor=%t err=%v", walEnabled, walResult.Count, walResult.Anchor != nil, walErr)
	}
	e5Fixture.assertNoPlaintextCanaries(t, credential.UUID, e5Graph.Share.Token, nodeToken, recoveredSnapshot.Raw)

	// An independent ordinary metadata writer may change unrelated fields. The
	// subsequent server-issued remove must preserve that drift and only remove
	// the managed chain declaration.
	projected, err := srv.renderLineMetadataJSON("node-b")
	if err != nil || !bytes.Contains(projected, []byte(sourceUUID)) || !bytes.Contains(projected, []byte(targetUUID)) {
		t.Fatalf("ordinary metadata projection lost committed chain: %s err=%v", projected, err)
	}
	var ordinary map[string]any
	if err := json.Unmarshal(projected, &ordinary); err != nil {
		t.Fatal(err)
	}
	ordinary["ordinary_sync_generation"] = float64(7)
	ordinary["unknown_root"] = map[string]any{"keep": true}
	ordinaryBytes, _ := json.Marshal(ordinary)
	if err := os.WriteFile(sidecar, ordinaryBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	var removePlanned struct {
		Approval model.Approval `json:"approval"`
	}
	persistentJSON(t, httpServer.Client(), http.MethodPost, httpServer.URL+"/api/network/lines/chains/remove-plan", fmt.Sprintf(`{"source_line_uuid":%q}`, sourceUUID), cookies, csrf, &removePlanned)
	removePlanSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(removePlanned.Approval.Plan)))
	persistentJSON(t, httpServer.Client(), http.MethodPost, httpServer.URL+"/api/network/approvals/approve", fmt.Sprintf(`{"approval_id":%q,"queue_apply":true,"plan_sha256":%q}`, removePlanned.Approval.ID, removePlanSHA), cookies, csrf, nil)

	removeReq, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/api/agent/tasks?node_id=node-b", nil)
	removeReq.Header.Set("Authorization", "Bearer "+nodeToken)
	removeReq.Header.Set(agentCapabilitiesHeader, lineChainDurableCapability)
	removeRes, err := httpServer.Client().Do(removeReq)
	if err != nil {
		t.Fatal(err)
	}
	defer removeRes.Body.Close()
	var removeLeased []agentTaskView
	if removeRes.StatusCode != http.StatusOK || json.NewDecoder(removeRes.Body).Decode(&removeLeased) != nil || len(removeLeased) != 1 || removeLeased[0].DurableProtocol != store.DurableProtocolLineChainV2 {
		t.Fatalf("remove lease=%d %+v", removeRes.StatusCode, removeLeased)
	}
	removeTaskJSON := filepath.Join(root, "task3.json")
	removeTaskBytes, _ := json.Marshal(struct {
		ID          string `json:"id"`
		LeaseID     string `json:"lease_id"`
		Interpreter string `json:"interpreter"`
		Script      string `json:"script"`
		TimeoutSec  int    `json:"timeout_sec"`
		OutputLimit int    `json:"output_limit"`
	}{removeLeased[0].ID, removeLeased[0].LeaseID, removeLeased[0].Interpreter, removeLeased[0].Script, removeLeased[0].TimeoutSec, removeLeased[0].OutputLimit})
	if err := os.WriteFile(removeTaskJSON, removeTaskBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	removeBegin := filepath.Join(root, "begin-task3.json")
	removeBeginCmd := exec.Command(agentTest, "-test.run=^TestLinechainE2EBeginHelper$", "--", root)
	removeBeginCmd.Env = append(os.Environ(), "LATTICE_LINECHAIN_E2E_TASK_JSON="+removeTaskJSON, "LATTICE_LINECHAIN_E2E_OUTBOX="+outboxDir, "LATTICE_LINECHAIN_E2E_TASK="+removeLeased[0].ID, "LATTICE_LINECHAIN_E2E_LEASE="+removeLeased[0].LeaseID, "LATTICE_LINECHAIN_E2E_BEGIN_RESULT="+removeBegin)
	_ = runLifecycleAgentHelper(t, removeBeginCmd)
	removeCmd := exec.Command("sh", "-c", removeLeased[0].Script)
	removeCmd.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"), "LATTICE_AGENT_BIN="+agent, "LATTICE_LINECHAIN_TXN_DIR="+txnDir, "LATTICE_LINECHAIN_CONFIG_DIR="+configDir, "LATTICE_LINECHAIN_SIDECAR_PATH="+sidecar, "LATTICE_TASK_ID="+removeLeased[0].ID, "LATTICE_TASK_LEASE_ID="+removeLeased[0].LeaseID, "LATTICE_LINECHAIN_TASK_SCRIPT_SHA256="+fmt.Sprintf("%x", sha256.Sum256([]byte(removeLeased[0].Script))))
	if out, err := removeCmd.CombinedOutput(); err != nil {
		t.Fatalf("real agent remove helper failed: %v: %s", err, out)
	}
	removedSidecar, _ := os.ReadFile(sidecar)
	if !bytes.Contains(removedSidecar, []byte(`"ordinary_sync_generation":7`)) || !bytes.Contains(removedSidecar, []byte(`"unknown_root":{"keep":true}`)) || bytes.Contains(removedSidecar, []byte(`"downstream_line_uuid"`)) {
		t.Fatalf("remove lost ordinary metadata or retained chain: %s", removedSidecar)
	}
	removeResolve := filepath.Join(root, "remove-resolve-result.json")
	removeResolveCmd := exec.Command(agentTest, "-test.run=^TestLinechainE2EResolveHelper$", "--", root)
	removeResolveCmd.Env = append(os.Environ(), "LATTICE_LINECHAIN_E2E_ROOT="+root, "LATTICE_LINECHAIN_E2E_BIN="+singbox, "LATTICE_LINECHAIN_E2E_CONFIG_DIR="+configDir, "LATTICE_LINECHAIN_E2E_SIDECAR="+sidecar, "LATTICE_LINECHAIN_E2E_B_PORT="+strconv.Itoa(bPort), "LATTICE_LINECHAIN_E2E_TASK="+removeLeased[0].ID, "LATTICE_LINECHAIN_E2E_LEASE="+removeLeased[0].LeaseID, "LATTICE_LINECHAIN_E2E_RESOLVE_RESULT="+removeResolve, "LATTICE_LINECHAIN_E2E_OUTBOX="+outboxDir)
	_ = runLifecycleAgentHelper(t, removeResolveCmd)
	removeResult, err := os.ReadFile(removeResolve)
	if err != nil || !bytes.Contains(removeResult, []byte(removeLeased[0].ID)) {
		t.Fatalf("remove result missing: %v", err)
	}
	removeBody := []byte(fmt.Sprintf(`{"node_id":"node-b","result":%s}`, removeResult))
	for attempt := 0; attempt < 2; attempt++ {
		postAgentJSON(t, httpServer.Client(), httpServer.URL+"/api/agent/task-result", nodeToken, removeBody)
	}
	ack3 := filepath.Join(root, "ack-task3.json")
	ack3Cmd := exec.Command(agentTest, "-test.run=^TestLinechainE2EAckHelper$", "--", root)
	ack3Cmd.Env = append(os.Environ(), "LATTICE_LINECHAIN_E2E_OUTBOX="+outboxDir, "LATTICE_LINECHAIN_E2E_TASK="+removeLeased[0].ID, "LATTICE_LINECHAIN_E2E_LEASE="+removeLeased[0].LeaseID, "LATTICE_LINECHAIN_E2E_ACK_RESULT="+ack3)
	_ = runLifecycleAgentHelper(t, ack3Cmd)
	removed := srv.store.LineChainSnapshot().Definitions[sourceUUID]
	if removed.TargetLineUUID != "" || removed.Status != store.LineChainStatusAppliedUnobserved || len(srv.store.Tasks()) != taskBaseline+3 {
		t.Fatalf("remove promotion/task mismatch: %+v tasks=%d", removed, len(srv.store.Tasks()))
	}
	beforeRemoveTraffic := observer.accepted()
	// The same client path now resolves directly after the server-issued remove;
	// no additional observer hop is permitted.
	lifecycleSOCKSEcho(t, clientPort, origin)
	if observer.accepted() != beforeRemoveTraffic {
		t.Fatal("removed chain still traversed observer/A")
	}
	removeInventory := filepath.Join(root, "remove-inventory-result.json")
	removeInventoryCmd := exec.Command(agentTest, "-test.run=^TestLinechainE2EInventoryHelper$", "--", root)
	removeInventoryCmd.Env = append(os.Environ(), "LATTICE_LINECHAIN_E2E_ROOT="+root, "LATTICE_LINECHAIN_E2E_CONFIG_DIR="+configDir, "LATTICE_LINECHAIN_E2E_SIDECAR="+sidecar, "LATTICE_LINECHAIN_E2E_INVENTORY_RESULT="+removeInventory)
	_ = runLifecycleAgentHelper(t, removeInventoryCmd)
	removeInventoryRaw, err := os.ReadFile(removeInventory)
	if err != nil || len(removeInventoryRaw) == 0 {
		t.Fatalf("remove inventory result missing: %v", err)
	}
	postAgentJSON(t, httpServer.Client(), httpServer.URL+"/api/agent/singbox-inventory", nodeToken, []byte(fmt.Sprintf(`{"node_id":"node-b","inventory":%s}`, removeInventoryRaw)))
	if got := srv.store.LineChainSnapshot().Definitions[sourceUUID]; got.Status != store.LineChainStatusConverged || len(srv.store.Tasks()) != taskBaseline+3 {
		t.Fatalf("remove inventory did not converge: %+v tasks=%d", got, len(srv.store.Tasks()))
	}
	assertDeclaredE2EEdge(t, srv.buildLineGroups(), sourceUUID, targetUUID, false)
}

func assertDeclaredE2EEdge(t *testing.T, groups []LineGroup, sourceUUID, targetUUID string, want bool) {
	t.Helper()
	var source, target *Line
	for gi := range groups {
		for li := range groups[gi].Lines {
			line := &groups[gi].Lines[li]
			switch line.LineUUID {
			case sourceUUID:
				source = line
			case targetUUID:
				target = line
			}
		}
	}
	if source == nil || target == nil {
		t.Fatalf("source/target missing from line projection: source=%v target=%v", source, target)
	}
	got := len(source.JumpEdges) == 1 && source.JumpEdges[0] == target.LineHashID &&
		len(source.DeclaredJumpEdges) == 1 && source.DeclaredJumpEdges[0] == target.LineHashID
	if got != want {
		t.Fatalf("declared edge want=%v source=%+v target=%+v", want, source, target)
	}
}

func mergeLifecycleFragmentIntoConfig(t *testing.T, configDir string) {
	t.Helper()
	baseRaw, err := os.ReadFile(filepath.Join(configDir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var base map[string]any
	if err := json.Unmarshal(baseRaw, &base); err != nil {
		t.Fatal(err)
	}
	entries, err := filepath.Glob(filepath.Join(configDir, "lattice-linechain-*.json"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected one server-issued fragment, got %v (%v)", entries, err)
	}
	fragmentRaw, err := os.ReadFile(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	var fragment map[string]any
	if err := json.Unmarshal(fragmentRaw, &fragment); err != nil {
		t.Fatal(err)
	}
	if existing, ok := base["outbounds"].([]any); ok {
		if fragmentOutbounds, ok := fragment["outbounds"].([]any); ok && len(fragmentOutbounds) > 0 {
			if first, ok := fragmentOutbounds[0].(map[string]any); ok {
				wantTag, _ := first["tag"].(string)
				for _, item := range existing {
					if row, ok := item.(map[string]any); ok && row["tag"] == wantTag {
						return
					}
				}
			}
		}
	}
	for _, key := range []string{"outbounds", "route"} {
		base[key] = fragment[key]
	}
	merged, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), merged, 0o600); err != nil {
		t.Fatal(err)
	}
}

func postAgentJSON(t *testing.T, client *http.Client, url, token string, body []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("%s: %d %s", url, res.StatusCode, raw)
	}
}

func persistentJSON(t *testing.T, client *http.Client, method, url, body string, cookies []*http.Cookie, csrf string, out any) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Lattice-CSRF", csrf)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("%s: %d %s", url, res.StatusCode, raw)
	}
	if out != nil && json.Unmarshal(raw, out) != nil {
		t.Fatalf("decode %s", raw)
	}
}

func lifecyclePluginRuntimeProcessGroups(t *testing.T, runtimeDir string) []int {
	t.Helper()
	out, err := exec.Command("ps", "-axo", "pid=,pgid=,command=").CombinedOutput()
	if err != nil {
		t.Fatalf("scan plugin runtime processes: %v: %s", err, out)
	}
	want := filepath.Clean(runtimeDir) + string(filepath.Separator)
	seen := map[int]bool{}
	var pgids []int
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.Contains(strings.Join(fields[2:], " "), want) {
			continue
		}
		pgid, err := strconv.Atoi(fields[1])
		if err != nil || pgid <= 0 || seen[pgid] {
			continue
		}
		seen[pgid] = true
		pgids = append(pgids, pgid)
	}
	return pgids
}

func assertLifecycleProcessGroupsGone(t *testing.T, pgids []int) {
	t.Helper()
	for _, pgid := range pgids {
		if err := syscall.Kill(-pgid, 0); !errors.Is(err, syscall.ESRCH) {
			t.Fatalf("plugin process group %d survived Server.Close: %v", pgid, err)
		}
	}
}

func requireE2EFile(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if !filepath.IsAbs(value) {
		t.Fatalf("%s must be absolute", name)
	}
	if _, err := os.Stat(value); err != nil {
		t.Fatal(err)
	}
	return value
}
