//go:build linechain_lifecycle_e2e

package server

import (
	"bytes"
	"context"
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
		t.Fatalf("agent helper failed: err=%v output_len=%d", err, out.Len())
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
	pluginRuntimeRoot := filepath.Join(root, "plugin-runtime")
	if processes := lifecycleRuntimeRootProcesses(t, pluginRuntimeRoot); len(processes) != 0 {
		t.Fatalf("E5 plugin runtime root was not empty before start: %+v", processes)
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
		t.Fatalf("lease status=%d count=%d durable_protocol_match=%t", res.StatusCode, len(leased), len(leased) == 1 && leased[0].DurableProtocol == store.DurableProtocolLineChainV2)
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
		t.Fatalf("server-issued fragment rejected by official sing-box: err=%v output_len=%d", err, len(out))
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
		t.Fatalf("begin durability missing: err=%v raw_len=%d", err, len(raw))
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
		t.Fatalf("recovery result missing leased task: err=%v raw_len=%d", err, len(raw))
	}
	// Recovery is the only authority for the interrupted attempt. Post its
	// exact non-success result before any inventory or observable traffic.
	recoveryRaw, _ := os.ReadFile(recoveryResult)
	recoveryBody := []byte(fmt.Sprintf(`{"node_id":"node-b","result":%s}`, recoveryRaw))
	if !bytes.Contains(recoveryRaw, []byte(`"exit_code":-1`)) || !bytes.Contains(recoveryRaw, []byte(`"error":"`)) {
		t.Fatalf("recovery result was not an interrupted failure: raw_len=%d", len(recoveryRaw))
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
		t.Fatalf("retry lease status=%d count=%d", retryRes.StatusCode, len(retryLeased))
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
		t.Fatalf("retry leased helper failed: err=%v output_len=%d", err, len(out))
	}
	sidecarBytes, _ := os.ReadFile(sidecar)
	if !bytes.Contains(sidecarBytes, []byte(`"unknown_root":{"keep":true}`)) || !bytes.Contains(sidecarBytes, []byte(`"ordinary":"keep"`)) {
		t.Fatalf("host fields lost: bytes=%d", len(sidecarBytes))
	}
	// The exact leased server document is now live: B's real outbound must
	// traverse observer -> A -> origin, proving the applied artifact rather
	// than a separately hand-built client document.
	lifecycleSOCKSEcho(t, clientPort, origin)
	if observer.accepted() == 0 {
		configBytes, _ := os.ReadFile(filepath.Join(configDir, "config.json"))
		t.Fatalf("server-issued chain produced no B -> observer -> A traffic; config_len=%d", len(configBytes))
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
		t.Fatalf("resolve result missing leased task: err=%v raw_len=%d", err, len(resolveRaw))
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
		d := snapshot.Definitions[sourceUUID]
		t.Fatalf("promotion/task mismatch: revision=%d tasks=%d status=%s target_present=%t", snapshot.Revision, len(srv.store.Tasks()), d.Status, d.TargetLineUUID != "")
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
		t.Fatalf("observed apply did not converge: status=%s target_present=%t task_count=%d", got.Status, got.TargetLineUUID != "", len(srv.store.Tasks()))
	}
	assertDeclaredE2EEdge(t, srv.buildLineGroups(), sourceUUID, targetUUID, true)
	// E5 Phase A-D runs only after the server has observed the exact issued
	// chain. The real signed vpn-core and SubStore runtimes must agree on one
	// immutable graph projection, preview without writing, persist the explicit
	// selection, publish the same bytes, and serve them through the public share.
	e5Graph := exerciseE5GraphAtConvergence(t, srv, handler, httpServer, cookies, csrf, user, sourceUUID)
	shareClientPort := lifecycleFreePort(t)
	startE5ClientFromShareURI(t, singbox, root, "e5-share-client", e5Graph.URI, shareClientPort)
	beforeShareTraffic := observer.accepted()
	lifecycleSOCKSEcho(t, shareClientPort, origin)
	if observer.accepted() <= beforeShareTraffic {
		t.Fatal("public share URI client did not traverse B -> observer -> A")
	}
	const e5SubStorePluginID = "latticenet.sub-store"
	const e5SubscriptionID = "e5-graph"
	const e5SubscriptionService = "latticenet.sub-store/subscription"
	lastGood, ok := srv.store.SubscriptionSnapshot(e5SubStorePluginID, e5SubscriptionID)
	if !ok || lastGood.Stale || lastGood.SourceVersion != e5Graph.SourceVersion || lastGood.FetchedAt.IsZero() || lastGood.Raw == "" {
		t.Fatalf("initial durable E5 snapshot mismatch: ok=%t stale=%t source=%s graph=%s fetched=%s bytes=%d", ok, lastGood.Stale, lastGood.SourceVersion, e5Graph.SourceVersion, lastGood.FetchedAt, len(lastGood.Raw))
	}
	secretCanaries := []string{
		credential.UUID,
		realityPrivate,
		sourceRealityPrivate,
		e5Graph.Share.Token,
		nodeToken,
		lastGood.Raw,
		e5Graph.URI,
		string(e5Graph.Published),
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
	postAgentJSON(t, httpServer.Client(), httpServer.URL+"/api/agent/singbox-inventory", nodeToken, inventoryWithLocalAddress(t, driftInventoryRaw, sourceUUID))
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
	var refreshView struct {
		Stale bool   `json:"stale"`
		Error string `json:"error"`
	}
	if json.Unmarshal(refreshRaw, &refreshView) != nil || refreshRes.StatusCode != http.StatusOK || !refreshView.Stale || refreshView.Error != "provider_fetch_failed" {
		t.Fatalf("drift refresh status=%d body_len=%d", refreshRes.StatusCode, len(refreshRaw))
	}
	assertNoE5SecretCanaries(t, refreshRaw, secretCanaries)
	staleGET, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/sub/"+e5Graph.Share.Slug+"/"+e5Graph.Share.Token+"?format=plain", nil)
	staleResp, err := httpServer.Client().Do(staleGET)
	if err != nil {
		t.Fatal(err)
	}
	staleBody := readAndClose(t, staleResp)
	if staleResp.StatusCode != http.StatusOK || staleResp.Header.Get("X-Lattice-Subscription-Stale") != "true" || strings.TrimSpace(string(staleBody)) != strings.TrimSpace(e5Graph.URI) {
		t.Fatalf("stale public share mismatch: status=%d header=%q body_len=%d", staleResp.StatusCode, staleResp.Header.Get("X-Lattice-Subscription-Stale"), len(staleBody))
	}
	staleLastGood, ok := srv.store.SubscriptionSnapshot(e5SubStorePluginID, e5SubscriptionID)
	if !ok || !staleLastGood.Stale || staleLastGood.FetchError == "" || staleLastGood.SourceVersion != lastGood.SourceVersion ||
		staleLastGood.Raw != lastGood.Raw || !staleLastGood.FetchedAt.Equal(lastGood.FetchedAt) || !staleLastGood.LastAttemptAt.After(lastGood.FetchedAt) {
		t.Fatalf("inventory drift did not preserve durable last-good authority: ok=%t stale=%t error=%q source=%s want_source=%s fetched=%s want_fetched=%s bytes=%d want_bytes=%d attempt=%s", ok, staleLastGood.Stale, staleLastGood.FetchError, staleLastGood.SourceVersion, lastGood.SourceVersion, staleLastGood.FetchedAt, lastGood.FetchedAt, len(staleLastGood.Raw), len(lastGood.Raw), staleLastGood.LastAttemptAt)
	}
	if staleLastGood.FetchError != "provider_fetch_failed" {
		t.Fatalf("unexpected stale fetch error: %q", staleLastGood.FetchError)
	}
	secretCanaries = append(secretCanaries, staleLastGood.Raw)
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
	postAgentJSON(t, httpServer.Client(), httpServer.URL+"/api/agent/singbox-inventory", nodeToken, inventoryWithLocalAddress(t, recoveredInventoryRaw, sourceUUID))
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
	assertNoE5SecretCanaries(t, recoverRaw, secretCanaries)
	var recoverView struct {
		Stale bool   `json:"stale"`
		Error string `json:"error"`
	}
	if json.Unmarshal(recoverRaw, &recoverView) != nil || recoverRes.StatusCode != http.StatusOK || recoverView.Stale || recoverView.Error != "" {
		t.Fatalf("recovery refresh status=%d body_len=%d", recoverRes.StatusCode, len(recoverRaw))
	}
	recoveredSnapshot, ok := srv.store.SubscriptionSnapshot(e5SubStorePluginID, e5SubscriptionID)
	if !ok || recoveredSnapshot.Stale || recoveredSnapshot.FetchError != "" || recoveredSnapshot.SourceVersion == "" || recoveredSnapshot.SourceVersion == lastGood.SourceVersion ||
		recoveredSnapshot.Raw != lastGood.Raw || !recoveredSnapshot.FetchedAt.After(lastGood.FetchedAt) || !recoveredSnapshot.LastAttemptAt.Equal(recoveredSnapshot.FetchedAt) {
		t.Fatalf("inventory recovery did not publish fresh durable authority: ok=%t stale=%t error=%q source=%s old_source=%s fetched=%s old_fetched=%s bytes=%d want_bytes=%d attempt=%s", ok, recoveredSnapshot.Stale, recoveredSnapshot.FetchError, recoveredSnapshot.SourceVersion, lastGood.SourceVersion, recoveredSnapshot.FetchedAt, lastGood.FetchedAt, len(recoveredSnapshot.Raw), len(lastGood.Raw), recoveredSnapshot.LastAttemptAt)
	}
	secretCanaries = append(secretCanaries, recoveredSnapshot.Raw)
	freshGET, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/sub/"+e5Graph.Share.Slug+"/"+e5Graph.Share.Token+"?format=plain", nil)
	freshResp, err := httpServer.Client().Do(freshGET)
	if err != nil {
		t.Fatal(err)
	}
	freshBody := readAndClose(t, freshResp)
	if freshResp.StatusCode != http.StatusOK || freshResp.Header.Get("X-Lattice-Subscription-Stale") != "" || strings.TrimSpace(string(freshBody)) != strings.TrimSpace(e5Graph.URI) {
		t.Fatalf("fresh public share mismatch: status=%d header=%q body_len=%d", freshResp.StatusCode, freshResp.Header.Get("X-Lattice-Subscription-Stale"), len(freshBody))
	}

	// A real server restart must reap the persistent SubStore worker before the
	// encrypted JSON store and its hot Bolt sidecar are closed. Reopening the
	// same durable files with the same cipher, bundles, runtime roots, and trust
	// policy must restore active lifecycle state and arm a fresh worker; the
	// already-successful vpn-core calls cover its v1 fork/reap path.
	oldPluginPGIDs := requirePersistentSubStoreWorker(t, e5Fixture.runtimeDir)
	httpServer.Close()
	beforeRestartKV := srv.store.KV("plugin:" + e5SubStorePluginID)
	e5Fixture = e5Fixture.reopen(t, func() {
		assertLifecycleProcessGroupsGone(t, oldPluginPGIDs)
		walResult, walEnabled, walErr := e5Fixture.store.AuditWALVerify()
		if walErr != nil || !walEnabled || walResult.Count == 0 || walResult.Anchor == nil {
			t.Fatalf("pre-close AuditWAL verification failed: enabled=%t count=%d anchor=%t err=%v", walEnabled, walResult.Count, walResult.Anchor != nil, walErr)
		}
	}, func() {
		e5Fixture.assertNoPlaintextCanaries(t, secretCanaries...)
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
	newPluginPGIDs := requirePersistentSubStoreWorker(t, e5Fixture.runtimeDir)
	for pluginID, pgid := range newPluginPGIDs {
		if pgid == oldPluginPGIDs[pluginID] {
			t.Fatalf("plugin process group %d was reused across server restart for %s", pgid, pluginID)
		}
	}
	persistedShare, shareOK := srv.store.SubscriptionShare(e5Graph.Share.ID)
	if !equalE5JSON(beforeRestartKV, srv.store.KV("plugin:"+e5SubStorePluginID)) {
		t.Fatal("SubStore plugin KV changed across restart")
	}
	var reopenedGet struct {
		Subscription struct {
			ID string `json:"id"`
		} `json:"subscription"`
	}
	callE5Plugin(t, handler, cookies, csrf, e5SubStorePluginID, e5SubscriptionService, "get", map[string]any{"subscription_id": e5SubscriptionID}, &reopenedGet)
	if reopenedGet.Subscription.ID != e5SubscriptionID {
		t.Fatalf("reopened SubStore get mismatch: got_id_len=%d", len(reopenedGet.Subscription.ID))
	}
	postRestartGET, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/sub/"+e5Graph.Share.Slug+"/"+e5Graph.Share.Token+"?format=plain", nil)
	postRestartResp, err := httpServer.Client().Do(postRestartGET)
	if err != nil {
		t.Fatal(err)
	}
	postRestartBody := readAndClose(t, postRestartResp)
	if postRestartResp.StatusCode != http.StatusOK || postRestartResp.Header.Get("X-Lattice-Subscription-Stale") != "" || strings.TrimSpace(string(postRestartBody)) != strings.TrimSpace(e5Graph.URI) {
		t.Fatalf("post-reopen public share mismatch: status=%d header=%q body_len=%d", postRestartResp.StatusCode, postRestartResp.Header.Get("X-Lattice-Subscription-Stale"), len(postRestartBody))
	}
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
	e5Fixture.assertNoPlaintextCanaries(t, secretCanaries...)
	// Reconnect the agent after restart so the ephemeral inventory projection is
	// repopulated before ordinary metadata/remove assertions.
	reconnectInventory := filepath.Join(root, "reconnect-inventory-result.json")
	reconnectCmd := exec.Command(agentTest, "-test.run=^TestLinechainE2EInventoryHelper$", "--", root)
	reconnectCmd.Env = append(os.Environ(), "LATTICE_LINECHAIN_E2E_ROOT="+root, "LATTICE_LINECHAIN_E2E_CONFIG_DIR="+configDir, "LATTICE_LINECHAIN_E2E_SIDECAR="+sidecar, "LATTICE_LINECHAIN_E2E_INVENTORY_RESULT="+reconnectInventory)
	_ = runLifecycleAgentHelper(t, reconnectCmd)
	reconnectRaw, err := os.ReadFile(reconnectInventory)
	if err != nil || len(reconnectRaw) == 0 {
		t.Fatalf("reconnect inventory result missing: %v", err)
	}
	tasksBeforeReconnect := len(srv.store.Tasks())
	reconnectReq, _ := http.NewRequest(http.MethodPost, httpServer.URL+"/api/agent/singbox-inventory", bytes.NewReader(inventoryWithLocalAddress(t, reconnectRaw, sourceUUID)))
	reconnectReq.Header.Set("Authorization", "Bearer "+nodeToken)
	reconnectReq.Header.Set(agentCapabilitiesHeader, lineChainDurableCapability)
	reconnectResp, err := httpServer.Client().Do(reconnectReq)
	if err != nil {
		t.Fatal(err)
	}
	if reconnectResp.StatusCode != http.StatusOK {
		body := readAndClose(t, reconnectResp)
		t.Fatalf("reconnect inventory failed: status=%d body_len=%d", reconnectResp.StatusCode, len(body))
	}
	reconnectResp.Body.Close()
	postAgentJSON(t, httpServer.Client(), httpServer.URL+"/api/agent/hello", nodeToken, []byte(`{"node_id":"node-b","version":"e2e-reconnect","capabilities":["durable-task-result-v1"]}`))
	reconnectedNodeB, reconnectedNodeOK := srv.store.Node("node-b")
	if !reconnectedNodeOK || reconnectedNodeB.PublicIP != "" {
		t.Fatalf("reconnected node public IP: present=%t nonempty=%t", reconnectedNodeOK, reconnectedNodeB.PublicIP != "")
	}
	compileAfterHello, compileAfterHelloErr := srv.captureLineChainCompileSnapshot()
	if compileAfterHelloErr != nil {
		t.Fatal(compileAfterHelloErr)
	}
	if len(compileAfterHello.Lines[sourceUUID]) != 1 || compileAfterHello.Lines[sourceUUID][0].PublicHost != "127.0.0.1" {
		firstHost := ""
		if len(compileAfterHello.Lines[sourceUUID]) > 0 {
			firstHost = compileAfterHello.Lines[sourceUUID][0].PublicHost
		}
		t.Fatalf("inventory authority compile mismatch: line_count=%d first_host=%s", len(compileAfterHello.Lines[sourceUUID]), firstHost)
	}
	if len(srv.store.Tasks()) != tasksBeforeReconnect || srv.store.LineChainSnapshot().Definitions[sourceUUID].Status != store.LineChainStatusConverged {
		d := srv.store.LineChainSnapshot().Definitions[sourceUUID]
		t.Fatalf("agent reconnect changed durable state: tasks=%d want=%d status=%s target_present=%t", len(srv.store.Tasks()), tasksBeforeReconnect, d.Status, d.TargetLineUUID != "")
	}
	capReq, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/api/agent/tasks?node_id=node-b", nil)
	capReq.Header.Set("Authorization", "Bearer "+nodeToken)
	capReq.Header.Set(agentCapabilitiesHeader, lineChainDurableCapability)
	capResp, err := httpServer.Client().Do(capReq)
	if err != nil {
		t.Fatal(err)
	}
	var capTasks []agentTaskView
	if capResp.StatusCode != http.StatusOK || json.NewDecoder(capResp.Body).Decode(&capTasks) != nil {
		capResp.Body.Close()
		t.Fatalf("capability re-advertisement failed: status=%d", capResp.StatusCode)
	}
	capResp.Body.Close()
	if len(capTasks) != 0 {
		t.Fatalf("reconnect capability GET leased unexpected tasks: count=%d", len(capTasks))
	}

	// An independent ordinary metadata writer may change unrelated fields. The
	// subsequent server-issued remove must preserve that drift and only remove
	// the managed chain declaration.
	projected, err := srv.renderLineMetadataJSON("node-b")
	if err != nil || !bytes.Contains(projected, []byte(sourceUUID)) || !bytes.Contains(projected, []byte(targetUUID)) {
		t.Fatalf("ordinary metadata projection lost committed chain: bytes=%d err=%v", len(projected), err)
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
		t.Fatalf("remove lease status=%d count=%d durable_protocol_match=%t", removeRes.StatusCode, len(removeLeased), len(removeLeased) == 1 && removeLeased[0].DurableProtocol == store.DurableProtocolLineChainV2)
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
		t.Fatalf("real agent remove helper failed: err=%v output_len=%d", err, len(out))
	}
	removedSidecar, _ := os.ReadFile(sidecar)
	if !bytes.Contains(removedSidecar, []byte(`"ordinary_sync_generation":7`)) || !bytes.Contains(removedSidecar, []byte(`"unknown_root":{"keep":true}`)) || bytes.Contains(removedSidecar, []byte(`"downstream_line_uuid"`)) {
		t.Fatalf("remove lost ordinary metadata or retained chain: bytes=%d", len(removedSidecar))
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
		t.Fatalf("remove promotion/task mismatch: tasks=%d status=%s target_present=%t", len(srv.store.Tasks()), removed.Status, removed.TargetLineUUID != "")
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
	postAgentJSON(t, httpServer.Client(), httpServer.URL+"/api/agent/singbox-inventory", nodeToken, inventoryWithLocalAddress(t, removeInventoryRaw, sourceUUID))
	if got := srv.store.LineChainSnapshot().Definitions[sourceUUID]; got.Status != store.LineChainStatusConverged || len(srv.store.Tasks()) != taskBaseline+3 {
		t.Fatalf("remove inventory did not converge: revision=%d tasks=%d status=%s target_present=%t", srv.store.LineChainSnapshot().Revision, len(srv.store.Tasks()), got.Status, got.TargetLineUUID != "")
	}
	assertDeclaredE2EEdge(t, srv.buildLineGroups(), sourceUUID, targetUUID, false)
	// G: tombstone convergence must force a fresh public projection and direct
	// client path without reintroducing the observer hop.
	preG, ok := srv.store.SubscriptionSnapshot(e5SubStorePluginID, e5SubscriptionID)
	if !ok {
		t.Fatal("missing pre-G subscription snapshot")
	}
	terminalCompile, err := srv.captureLineChainCompileSnapshot()
	if err != nil {
		t.Fatalf("terminal compile capture: %v", err)
	}
	terminalReq := graphSubscriptionRequest{SchemaVersion: 1, IdentityID: user.ID, EntryRoots: []string{sourceUUID}}
	terminalComposed, err := composeGraphSubscription(terminalCompile, terminalReq, srv.now())
	if err != nil {
		t.Fatalf("terminal graph compile: err=%v line_count=%d definition_status=%s", err, len(terminalCompile.Lines[sourceUUID]), terminalCompile.Definitions[sourceUUID].Status)
	}
	if len(terminalComposed.Entries) != 1 || terminalComposed.Entries[0] != terminalComposed.Raw || terminalComposed.SourceVersion == "" {
		t.Fatalf("terminal graph manifest incomplete: entries=%d raw_len=%d source_len=%d", len(terminalComposed.Entries), len(terminalComposed.Raw), len(terminalComposed.SourceVersion))
	}
	var terminalCore graphSubscriptionResponse
	callE5Plugin(t, handler, cookies, csrf, vpnCorePluginID, vpnCoreSubscriptionSourcesService, "compose", terminalReq, &terminalCore)
	if !terminalCore.OK || len(terminalCore.Entries) != 1 || terminalCore.SourceVersion == "" {
		t.Fatalf("vpn-core terminal compose failed: ok=%t entries=%d raw_len=%d", terminalCore.OK, len(terminalCore.Entries), len(terminalCore.Raw))
	}
	gReq, _ := http.NewRequest(http.MethodPost, httpServer.URL+"/api/subscription-shares/"+e5Graph.Share.ID+"/refresh", nil)
	gReq.Header.Set("X-Lattice-CSRF", csrf)
	for _, c := range cookies {
		gReq.AddCookie(c)
	}
	gResp, err := httpServer.Client().Do(gReq)
	if err != nil {
		t.Fatal(err)
	}
	gRaw := readAndClose(t, gResp)
	var gView struct {
		Stale bool   `json:"stale"`
		Error string `json:"error"`
	}
	if gResp.StatusCode != http.StatusOK || json.Unmarshal(gRaw, &gView) != nil || gView.Stale || gView.Error != "" {
		t.Fatalf("G refresh failed: status=%d body_len=%d", gResp.StatusCode, len(gRaw))
	}
	postG, ok := srv.store.SubscriptionSnapshot(e5SubStorePluginID, e5SubscriptionID)
	if !ok || postG.Stale || postG.FetchError != "" || len(postG.SourceManifest) == 0 || postG.SourceVersion == preG.SourceVersion || !postG.FetchedAt.After(preG.FetchedAt) || !postG.LastAttemptAt.Equal(postG.FetchedAt) {
		t.Fatalf("G snapshot did not advance: before_source=%s after_source=%s before_stale=%t after_stale=%t before_fetched=%s after_fetched=%s before_raw_len=%d after_raw_len=%d", preG.SourceVersion, postG.SourceVersion, preG.Stale, postG.Stale, preG.FetchedAt, postG.FetchedAt, len(preG.Raw), len(postG.Raw))
	}
	manifest, err := model.DecodeSubscriptionSourceManifest(postG.SourceManifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.EntryRoots) != 1 || manifest.EntryRoots[0] != sourceUUID || len(manifest.Entries) != 1 || manifest.Entries[0].Root != sourceUUID || len(manifest.Entries[0].Path) != 0 || manifest.Entries[0].Terminal.LineUUID != sourceUUID || manifest.Entries[0].Terminal.Status != store.LineChainStatusConverged {
		t.Fatalf("G terminal manifest mismatch: roots=%d entries=%d", len(manifest.EntryRoots), len(manifest.Entries))
	}
	gGet, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/sub/"+e5Graph.Share.Slug+"/"+e5Graph.Share.Token+"?format=plain", nil)
	gPublic, err := httpServer.Client().Do(gGet)
	if err != nil {
		t.Fatal(err)
	}
	gBody := readAndClose(t, gPublic)
	if postG.Raw == "" {
		t.Fatal("G snapshot raw is empty")
	}
	if gPublic.StatusCode != http.StatusOK {
		t.Fatalf("G public share status=%d", gPublic.StatusCode)
	}
	if gPublic.Header.Get("X-Lattice-Subscription-Stale") != "" {
		t.Fatalf("G public share stale header=%q", gPublic.Header.Get("X-Lattice-Subscription-Stale"))
	}
	if strings.TrimSpace(postG.Raw) != strings.TrimSpace(terminalCore.Raw) || strings.TrimSpace(terminalCore.Raw) != strings.TrimSpace(terminalComposed.Raw) {
		t.Fatal("G provider authority mismatch")
	}
	if strings.TrimSpace(string(gBody)) != strings.TrimSpace(e5Graph.URI) {
		t.Fatalf("G canonical public rendering mismatch: body_len=%d expected_len=%d", len(bytes.TrimSpace(gBody)), len(strings.TrimSpace(e5Graph.URI)))
	}
	gPort := lifecycleFreePort(t)
	beforeGTraffic := observer.accepted()
	startE5ClientFromShareURI(t, singbox, root, "e5-direct-client", strings.TrimSpace(string(gBody)), gPort)
	lifecycleSOCKSEcho(t, gPort, origin)
	if observer.accepted() != beforeGTraffic {
		t.Fatal("G direct client traversed observer/A")
	}

	// The reopened server is an explicit lifecycle phase, not cleanup-only state.
	// Close its HTTP listener, require the freshly armed worker group to be
	// extinct, then close the store. The registered cleanup remains idempotent.
	httpServer.Close()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	e5Fixture.cleanup.closeServer(shutdownCtx)
	shutdownCancel()
	if e5Fixture.cleanup.serverErr != nil {
		t.Fatalf("close reopened E5 server: %v", e5Fixture.cleanup.serverErr)
	}
	assertLifecycleProcessGroupsGone(t, newPluginPGIDs)
	if processes := lifecycleRuntimeRootProcesses(t, e5Fixture.runtimeDir); len(processes) != 0 {
		t.Fatalf("E5 plugin runtime root retained processes after close: %+v", processes)
	}
	e5Fixture.cleanup.closeStore()
	if e5Fixture.cleanup.storeErr != nil {
		t.Fatalf("close reopened E5 store: %v", e5Fixture.cleanup.storeErr)
	}
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
	if source == nil || (target == nil && want) {
		t.Fatalf("source/target missing from line projection: source=%v target=%v", source, target)
	}
	if !want && target == nil {
		if len(source.JumpEdges) != 0 || len(source.DeclaredJumpEdges) != 0 {
			t.Fatalf("removed source still has edges: %+v", source)
		}
		return
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

func inventoryWithLocalAddress(t *testing.T, raw []byte, sourceUUID string) []byte {
	t.Helper()
	// 127.0.0.1 is the E2E equivalent of production Source.Addr, not hello public_ip.
	var inv model.SingBoxInventory
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatal(err)
	}
	if inv.NodeID != "node-b" || inv.Status != "ok" || len(inv.Nodes) == 0 {
		t.Fatalf("invalid inventory authority: node_id=%s status=%s nodes=%d", inv.NodeID, inv.Status, len(inv.Nodes))
	}
	found := false
	for i := range inv.Nodes {
		n := &inv.Nodes[i]
		if n.LineUUID == sourceUUID {
			found = true
		}
		if n.Address != "" && n.Address != "127.0.0.1" {
			t.Fatalf("unexpected inventory address: nonempty=%t", n.Address != "")
		}
		n.Address = "127.0.0.1"
	}
	if !found {
		t.Fatalf("inventory missing source line %s", sourceUUID)
	}
	out, err := json.Marshal(struct {
		NodeID    string                 `json:"node_id"`
		Inventory model.SingBoxInventory `json:"inventory"`
	}{NodeID: "node-b", Inventory: inv})
	if err != nil {
		t.Fatal(err)
	}
	return out
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
		t.Fatalf("%s: status=%d raw_len=%d", url, res.StatusCode, len(raw))
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
		t.Fatalf("%s: status=%d raw_len=%d", url, res.StatusCode, len(raw))
	}
	if out != nil && json.Unmarshal(raw, out) != nil {
		t.Fatalf("decode response: raw_len=%d", len(raw))
	}
}

type lifecycleRuntimeProcess struct {
	PID     int
	PGID    int
	Command string
}

func lifecycleRuntimeRootProcesses(t *testing.T, runtimeDir string) []lifecycleRuntimeProcess {
	t.Helper()
	out, err := exec.Command("ps", "-axo", "pid=,pgid=,command=").CombinedOutput()
	if err != nil {
		t.Fatalf("scan plugin runtime processes: %v: %s", err, out)
	}
	return parseLifecycleRuntimeProcesses(string(out), runtimeDir)
}

func parseLifecycleRuntimeProcesses(output, runtimeDir string) []lifecycleRuntimeProcess {
	want := filepath.Clean(runtimeDir) + string(filepath.Separator)
	var processes []lifecycleRuntimeProcess
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.Contains(strings.Join(fields[2:], " "), want) {
			continue
		}
		pid, pidErr := strconv.Atoi(fields[0])
		pgid, err := strconv.Atoi(fields[1])
		if pidErr != nil || err != nil || pid <= 0 || pgid <= 0 {
			continue
		}
		processes = append(processes, lifecycleRuntimeProcess{PID: pid, PGID: pgid, Command: strings.Join(fields[2:], " ")})
	}
	return processes
}

func persistentSubStoreWorkerMap(processes []lifecycleRuntimeProcess, runtimeDir string) (map[string]int, error) {
	if len(processes) != 1 {
		return nil, fmt.Errorf("expected exactly one persistent SubStore worker and no other runtime-root processes, got %+v", processes)
	}
	process := processes[0]
	marker := filepath.Clean(runtimeDir) + string(filepath.Separator) + "latticenet.sub-store" + string(filepath.Separator)
	if !strings.Contains(process.Command, marker) {
		return nil, fmt.Errorf("persistent runtime-root process is not SubStore: %+v", process)
	}
	if process.PGID <= 0 {
		return nil, fmt.Errorf("persistent SubStore worker has invalid process group: %+v", process)
	}
	return map[string]int{"latticenet.sub-store": process.PGID}, nil
}

func requirePersistentSubStoreWorker(t *testing.T, runtimeDir string) map[string]int {
	t.Helper()
	workers, err := persistentSubStoreWorkerMap(lifecycleRuntimeRootProcesses(t, runtimeDir), runtimeDir)
	if err != nil {
		t.Fatal(err)
	}
	return workers
}

func lifecycleProcessGroupMembers(t *testing.T, pgid int) []int {
	t.Helper()
	out, err := exec.Command("ps", "-axo", "pid=,pgid=").CombinedOutput()
	if err != nil {
		t.Fatalf("scan process group %d: %v: %s", pgid, err, out)
	}
	return parseLifecycleProcessGroupMembers(string(out), pgid)
}

func parseLifecycleProcessGroupMembers(output string, pgid int) []int {
	var members []int
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		pid, pidErr := strconv.Atoi(fields[0])
		candidatePGID, pgidErr := strconv.Atoi(fields[1])
		if pidErr == nil && pgidErr == nil && pid > 0 && candidatePGID == pgid {
			members = append(members, pid)
		}
	}
	return members
}

func assertLifecycleProcessGroupsGone(t *testing.T, workers map[string]int) {
	t.Helper()
	for pluginID, pgid := range workers {
		deadline := time.Now().Add(10 * time.Second)
		for {
			err := syscall.Kill(-pgid, 0)
			members := lifecycleProcessGroupMembers(t, pgid)
			// macOS can report EPERM for a group that has already lost every
			// member. Empty enumeration is the portable extinction proof; EPERM
			// with any member is never treated as extinct.
			if len(members) == 0 {
				break
			}
			if err != nil && !errors.Is(err, syscall.ESRCH) && !errors.Is(err, syscall.EPERM) {
				t.Fatalf("probe process group for %s pgid=%d: %v members=%v", pluginID, pgid, err, members)
			}
			if time.Now().After(deadline) {
				t.Fatalf("plugin process group extinction unproved after Server.Close: plugin=%s pgid=%d probe=%v members=%v (EPERM is failure)", pluginID, pgid, err, members)
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
}

func assertNoE5SecretCanaries(t *testing.T, raw []byte, canaries []string) {
	t.Helper()
	for i, canary := range canaries {
		if canary != "" && bytes.Contains(raw, []byte(canary)) {
			t.Fatalf("secret canary %d exposed in response", i+1)
		}
	}
}

func TestParseLifecycleRuntimeProcessesMapsPluginIDs(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "tmp", "e5", "plugin-runtime")
	output := fmt.Sprintf("102 102 %s\n103 103 /bin/unrelated\n",
		filepath.Join(root, "latticenet.sub-store", "generation-1", "artifact"))
	processes := parseLifecycleRuntimeProcesses(output, root)
	if len(processes) != 1 || processes[0].PID != 102 || processes[0].PGID != 102 {
		t.Fatalf("runtime process parse mismatch: %+v", processes)
	}
	workers, err := persistentSubStoreWorkerMap(processes, root)
	if err != nil || workers["latticenet.sub-store"] != 102 {
		t.Fatalf("runtime plugin mapping mismatch: workers=%v err=%v", workers, err)
	}
	vpnCore := lifecycleRuntimeProcess{PID: 101, PGID: 101, Command: filepath.Join(root, "latticenet.vpn-core", "generation-1", "artifact")}
	if _, err := persistentSubStoreWorkerMap(append(processes, vpnCore), root); err == nil {
		t.Fatal("persistent worker mapping accepted a vpn-core v1 process")
	}
}

func TestParseLifecycleProcessGroupMembers(t *testing.T) {
	if members := parseLifecycleProcessGroupMembers("101 55\n102 77\n103 55\n", 55); len(members) != 2 || members[0] != 101 || members[1] != 103 {
		t.Fatalf("process-group member parse mismatch: %v", members)
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
