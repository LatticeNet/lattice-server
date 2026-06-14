# lattice-server

The Lattice control plane server.

Responsibilities:

- Admin login, sessions, CSRF checks, and secure cookie defaults.
- Scope and server allowlist authorization.
- Node enrollment and outbound-agent APIs.
- Fleet metrics and HostFacts inventory telemetry ingestion.
- Server-only machine inventory profiles: vendor, region, encrypted console/detail links,
  cost, renewal cycles, and renewal reminders.
- Batch task scheduling and result collection.
- KV/static/Worker control APIs.
- nftables plan and approval workflow with persisted per-node baseline inputs
  (public TCP/UDP, WireGuard TCP/UDP, interface, WireGuard CIDR).
- NetPolicy APIs, reachability graph, rollback-protected egress nft apply, and
  ingress policy composition into the Network Guard input table.
- Self-host DNS deployment intent CRUD with encrypted Cloudflare token storage
  and secret-free read views. CoreDNS apply/publish is a later slice.
- Operator-owned NodeGeo API for the dashboard Fleet Map.
- Append-only audit events.

## Run Locally

```sh
LATTICE_ADMIN_PASSWORD='change-this-passphrase' \
LATTICE_WEB_ROOT=../lattice-dashboard \
go run ./cmd/lattice-server
```

Open `http://127.0.0.1:8088`.

## Build

From the organization workspace:

```sh
cd ../lattice
make build
```

Standalone builds require `github.com/LatticeNet/lattice-sdk` to be available at
the version in `go.mod`; during local multi-repo development, use the
`lattice/go.work` workspace.

## Security Defaults

- First-run password is random unless `LATTICE_ADMIN_PASSWORD` is set.
- Management APIs are intended for localhost, WireGuard, or a hardened reverse proxy.
- Agent APIs authenticate node tokens only through the `Authorization: Bearer`
  header; JSON body tokens are rejected so credentials do not enter request
  logs, traces, or failure captures.
- Agent HostFacts (OS, arch, cores, memory, platform, kernel, boot time) are
  advisory telemetry only. They are sanitized and clamped server-side and must
  not be used for authorization or policy decisions.
- MachineProfile cost/vendor/renewal data is server-only and is never sent to
  agents. Console/detail links are encrypted at rest and list APIs return only
  `has_console_url` / `has_detail_url` booleans.
- API failures use a structured JSON envelope:
  `{"error":{"code":"unauthorized","message":"invalid credentials","request_id":"req_..."}}`.
  Every HTTP response includes `X-Lattice-Request-ID`; error envelopes carry the
  same id so dashboard, plugins and operators can correlate failures without
  parsing log text.
  Authorization denial audit events, authenticated allow audit events, login
  events, and agent task/event audits use the same value as `correlation_id`,
  covering node, task, token, KV/static, Worker, notification, monitor, DDNS,
  tunnel, and network approval changes.
  `/api/audit` remains backward-compatible as an array when called without
  query parameters; filtered calls return `{events,total,limit,offset}` and
  support `action`, `decision`, `node_id`, `actor_id`, `token_id`, `scope`,
  `correlation_id`, `limit`, and `offset`. `limit` defaults to 100 and is capped
  at 500 so dashboards and plugins do not accidentally fetch unbounded audit
  history.
  Server-side `5xx` responses deliberately return generic public messages
  (`internal server error` or `upstream service error`) rather than raw provider,
  filesystem, database, or token-bearing error strings.
  Security-sensitive denials use stable business codes such as
  `capability_denied`, `invalid_node_token`, `invalid_task_lease`, and
  `task_output_limit_exceeded`.
- nft baseline inputs are persisted per node and normalized before plan
  generation. The plan still becomes an approval before agent-side validation;
  actual firewall mutation remains behind `network:apply`.
- NetPolicy state (`/api/netpolicy`, `/api/netpolicy/graph`) is server-validated
  operator intent. Writes and `/api/netpolicy/plan` require `netpolicy:admin`;
  list/graph require `netpolicy:read`; per-node PAT allowlists filter target
  nodes. The current `nftpolicy` apply path commits a dedicated
  `inet lattice_policy` output table for egress policy with a 60s rollback
  watchdog, control-plane selfcheck, IPv4/IPv6 control-plane domain named sets,
  operator-authored IPv4/IPv6 CIDR/node remotes, and egress domain remotes
  backed by node-filled nft sets refreshed through systemd or cron.d. Ingress
  deny/allow rules compose into Network Guard's single `lattice_guard` input
  render rather than a competing input table.
- DNS deployment state (`/api/dns/deployments`) is server-owned intent for
  future CoreDNS deployment. Writes require `dns:admin` on the target node,
  node existence is checked, Cloudflare tokens are write-only and encrypted at
  rest, and read views expose only `has_credential`. Stored DNS intent does not
  yet mutate nftables, publish Cloudflare records, or deploy CoreDNS.
- NodeGeo state (`GET/POST /api/nodes/geo`) is operator-owned display metadata
  for the Fleet Map. Writes require `node:admin` on the target node, reads
  require `node:read` and are per-node allowlist-filtered, coordinates/country/
  ASN are validated server-side, and update/clear actions are audited. Geo must
  not be used as node identity, authorization input, or nft compiler input.
- PAT server allowlists are enforced against the actual node resources in request
  bodies, not only URL query parameters.
- Node/task/monitor/DDNS/tunnel list APIs return only resources visible to the
  caller's scopes and server allowlist.
- Control-plane task views expose script hash and byte size, not the full script
  body or agent-only lease credential.
- Task read and run permissions are split: `task:read` lists task metadata and
  results, while `task:run` queues remote execution.
- Task creation is validated at the control plane: interpreter allowlist
  (`sh`, `bash`, `python3`, `node`), timeout 1-600 seconds, output cap 1-256
  KiB, and script body up to 64 KiB.
- Agent task leases expose only execution fields, script body, limits, and
  `lease_id`; actor/token metadata and full target lists stay control-plane only.
- Task result writes require the node token, the matching leased node, and the
  per-lease `lease_id`; stale, missing, cross-node, or output-over-limit results
  are rejected before storage.
- Accepted task results are stored and returned through the control plane without
  the agent-only `lease_id`.
- Operator-configured outbound webhooks use a guarded HTTP client that rejects
  loopback, private, link-local, metadata, CGNAT, and documentation ranges.
- Plugin manifests require stable lowercase ids and non-empty duplicate-free
  capability lists before any plugin can be trusted by the control plane.
  Host-risk/system plugins can be verified with an operator trust policy:
  trusted `publisher` Ed25519 keys, artifact `digest_sha256`, and
  `signature_ed25519` over the canonical Lattice plugin signing payload.
  Plugin installation/loading code should use the strict verifier path:
  decode manifest JSON with unknown fields rejected, verify artifact digest, then
  verify publisher signature when host-risk capabilities are present.
  Operators and dashboards can preflight a candidate plugin without installing
  it through `POST /api/plugins/verify` with scope `plugin:verify`. The endpoint
  accepts a manifest object and `artifact_base64`, applies the server-side trust
  policy, returns the manifest with `signature_ed25519` stripped plus capability
  risk labels, and never writes the artifact to disk or registers it in
  `/api/plugins`.
- Plugin host APIs are brokered through `internal/plugin.Broker`, which is built
  from a verified `plugin.Loaded` entry and checks the manifest's declared
  capabilities on every host call. The broker currently defines guarded facades
  for KV (`kv:read`/`kv:write`), notifications (`notify:send`), outbound HTTP
  (`http:egress`), plugin logs (`log:write`), and host-call audit events. It is a
  contract and enforcement point only; plugin execution/installation lifecycle is
  intentionally separate.
  The server-owned adapter (`plugin_host.go`) wires those facades to the real
  store, notification dispatcher, guarded outbound HTTP client, logger, and audit
  sink. Broker capability allow/deny decisions are written as `plugin.host.*`
  audit events with the plugin id, capability, decision, and correlation id.
  Plugin HTTP request and response bodies are capped at 256 KiB, and outbound
  HTTP uses the same SSRF/egress guard as webhooks.

## Storage

- The default server store is still the encrypted JSON state file plus the
  append-only hash-chained audit WAL (`<state>.audit-wal`).
- `internal/store.BoltStateStore` is the Phase C bbolt foundation. It can import
  and export the full `State`, stores each top-level collection in its own
  bucket, reuses the existing AES-256-GCM secret encryption boundary, and now
  has record-level APIs for nodes, KV entries, audit events, static objects,
  Worker scripts, plugin lifecycle records, approvals, tasks, task results,
  monitors, monitor results, tunnels, users, PAT tokens, sessions, TOTP
  challenges, DDNS profiles, notification channels, machine profiles, nft
  inputs, DNS deployments, net policies, OIDC providers, OIDC identities, and
  OIDC auth states.
- The local ops CLI can migrate the encrypted JSON file to bbolt and export
  bbolt back to encrypted JSON:

  ```sh
  lattice-server migrate json-to-bolt \
    -json /var/lib/lattice/state.json \
    -bolt /var/lib/lattice/state.db

  lattice-server migrate bolt-to-json \
    -bolt /var/lib/lattice/state.db \
    -json /var/lib/lattice/state.rollback.json
  ```

  The CLI requires explicit `-json` and `-bolt` paths, refuses to overwrite
  targets unless `-overwrite` is set, reuses the normal master key source, and
  will not generate a new key during migration. If the key is not under the JSON
  state directory as `master.key`, pass `-master-key-file` or set
  `LATTICE_MASTER_KEY_FILE`.
- bbolt is not the default runtime store yet. The next storage slice should be
  an explicit startup switch plus backup/restore workflow depth before the
  server path moves off JSON.

Example plugin trust policy JSON:

```json
{
  "allow_unsigned_host_risk": false,
  "trusted_publishers": {
    "latticenet": "base64-raw-ed25519-public-key"
  }
}
```

> Fail-closed by default: omitting `allow_unsigned_host_risk` (or setting it
> `false`) requires a trusted-publisher Ed25519 signature for **every** host-risk
> plugin. Set it `true` only for local development on a host you fully control.

Example plugin preflight request:

```http
POST /api/plugins/verify
Authorization: Bearer <token with plugin:verify>
Content-Type: application/json

{
  "manifest": {
    "id": "latticenet.nft",
    "name": "nft Guard",
    "type": "system",
    "version": "0.1.0",
    "entrypoint": "system-go/latticenet-nft",
    "capabilities": ["network:plan"],
    "publisher": "latticenet",
    "digest_sha256": "hex-sha256-of-artifact",
    "signature_ed25519": "base64-raw-ed25519-signature"
  },
  "artifact_base64": "base64-raw-artifact-bytes"
}
```

Successful response:

```json
{
  "trusted": true,
  "artifact_sha256": "hex-sha256-of-artifact",
  "manifest": {
    "id": "latticenet.nft",
    "name": "nft Guard",
    "type": "system",
    "version": "0.1.0",
    "entrypoint": "system-go/latticenet-nft",
    "capabilities": ["network:plan"],
    "publisher": "latticenet",
    "digest_sha256": "hex-sha256-of-artifact"
  },
  "capabilities": [
    {"name": "network:plan", "risk": "host"}
  ]
}
```
