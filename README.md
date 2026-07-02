# lattice-server

The Lattice control plane server.

Responsibilities:

- Admin login, sessions, CSRF checks, and secure cookie defaults.
- Scope and server allowlist authorization.
- Node enrollment and outbound-agent APIs.
- Operator-owned node metadata: name, role, sorted tags, and control-plane-only
  comments.
- Fleet metrics and HostFacts inventory telemetry ingestion.
- Server-only machine inventory profiles: vendor, region, encrypted console/detail links,
  cost, renewal cycles, and renewal reminders.
- Batch task scheduling and result collection.
- KV/static/Worker control APIs.
- nftables plan and approval workflow with persisted per-node baseline inputs
  (public TCP/UDP, WireGuard TCP/UDP, interface, WireGuard CIDR).
- NetPolicy APIs, reachability graph, rollback-protected egress nft apply, and
  ingress policy composition into the Network Guard input table.
- Self-host DNS deployment intent CRUD with encrypted Cloudflare token storage,
  secret-free read views, CoreDNS/nft plan generation, rollback-protected apply,
  task-result status reconciliation, and Cloudflare hostname publication through
  the existing DDNS provider.
- Proxy-core/subscription persistence foundation: encrypted Reality private
  keys, user UUID/password credentials, subscription tokens, redacted proto view
  contracts, JSON/bbolt store parity, and the first fail-closed sing-box
  `vless`+TCP+REALITY renderer, plus scoped CRUD/read APIs with secret-free
  views, a redacted reviewed plan endpoint, and secret-safe queue/apply through
  encrypted task scripts, `sing-box check`, atomic config swap, reload/restart,
  task-result status reconciliation, public subscription serving, audited
  subscription-token rotation, sing-box JSON plus Clash/Mihomo YAML subscription
  output, and baseline proxy usage rollup.
- Operator-owned NodeGeo API and optional server-side GeoIP lookup for the
  dashboard Fleet Map.
- Append-only audit events with a hash-chained WAL and sidecar head anchor.

## Run Locally

```sh
LATTICE_ADMIN_PASSWORD='change-this-passphrase' \
LATTICE_ADMIN_USERNAME='admin' \
LATTICE_WEB_ROOT=../lattice-dashboard \
go run ./cmd/lattice-server
```

Open `http://127.0.0.1:8088`.

Self-host DNS can optionally install a pinned CoreDNS executable during an
approved `selfdns` apply. Leave these unset to keep the stricter precondition
that `coredns` must already exist on the node:

```sh
LATTICE_COREDNS_BINARY_VERSION='1.12.4' \
LATTICE_COREDNS_BINARY_URL='https://example.com/releases/coredns-1.12.4-linux-amd64' \
LATTICE_COREDNS_BINARY_SHA256='<64 hex chars>' \
go run ./cmd/lattice-server
```

The URL must be HTTPS and point directly to an executable binary. The reviewed
approval plan includes the version, URL, SHA-256, and fixed install path
(`/usr/local/bin/coredns`); the node installs only after digest verification.

Fleet Map automatic node placement is enabled by default with the no-token
`https://ipwho.is/{ip}` HTTPS JSON API. You do not need an IPInfo token for the
normal Nezha-like auto-location flow. To disable external lookup entirely:

```sh
LATTICE_GEOIP_LOOKUP_URL=off \
go run ./cmd/lattice-server
```

To use a self-hosted or internal provider instead, set
`LATTICE_GEOIP_LOOKUP_URL` to an HTTPS URL template containing `{ip}`. The
response must be JSON with common `country_code`, `region`, `city`,
`latitude`/`longitude`, and optional ASN/provider fields. Manual map coordinates
work even when automatic lookup is disabled.

## Build

From the organization workspace:

```sh
cd ../lattice
make build
```

Standalone builds require `github.com/LatticeNet/lattice-sdk` to be available at
the version in `go.mod`; during local multi-repo development, use the
`lattice/go.work` workspace.

## Docker

The server image embeds `lattice-dashboard` and keeps runtime state under
`/var/lib/lattice`.

Local multi-repo build:

```sh
cd ..
DOCKER_BUILDKIT=1 docker build \
  -f lattice-server/Dockerfile \
  --build-context lattice-sdk=./lattice-sdk \
  --build-context lattice-dashboard=./lattice-dashboard \
  -t lattice-server:local \
  ./lattice-server
```

Published image:

```txt
ghcr.io/latticenet/lattice-server
```

Image publication is tag-driven. The moving `latest` git tag publishes
`:latest`, the moving `alpha` git tag publishes `:alpha`, and stable `v*` tags
publish immutable version tags. Source pushes to `main` run CI but do not
publish a `main` image channel. Build provenance/SBOM attestations are disabled
for the image workflow, and the `package cleanup` workflow prunes old untagged
container package versions. The cleanup job protects child manifests referenced
by the active `latest` and `alpha` manifest lists, then deletes stale untagged
digests by default.

The container leaves `LATTICE_MASTER_KEY_FILE` unset by default so first boot can
generate `/var/lib/lattice/master.key` automatically. Set it only when restoring
or mounting a pre-existing key. The entrypoint fixes ownership of the mounted
data directory before dropping privileges to the `lattice` user.

Dashboard static serving is cache-aware: `index.html`, SPA fallback routes, and
`theme-init.js` are served with `Cache-Control: no-cache`; content-hashed Vite
assets under `/assets/` are served with `Cache-Control: public, max-age=31536000,
immutable`.

Use the compose file and deployment guide in the umbrella repository:
`lattice/compose/docker-compose.yml` and `lattice/docs/tutorials/docker-server.md`.

## Security Defaults

- First-run username defaults to `admin` unless `LATTICE_ADMIN_USERNAME` is set.
  First-run password is random unless `LATTICE_ADMIN_PASSWORD` is set. After
  state contains any user, both variables remain bootstrap-only; rotate the
  current operator password with authenticated `POST /api/auth/password`.
- `GET /api/version` returns the server build version, server commit/date, and
  the embedded dashboard ref exposed in the dashboard About page.
- Password login sends username/password as JSON over HTTPS. Do not expose the
  dashboard over remote cleartext `http://`; use TLS, secure cookies, and HSTS in
  production.
- Set `LATTICE_REQUIRE_TOTP=1` or `-require-totp` to enforce TOTP for
  interactive operator sessions. Password/SSO login still creates a constrained
  session so an operator can open `/settings/security`, enroll, and activate
  TOTP; all other session-backed APIs return the stable `mfa_required` error
  until enrollment is complete. Bearer PAT automation is not an interactive
  session and is not gated by this policy.
- Container images embed the dashboard commit pinned in `dashboard.ref`;
  update that file when intentionally rolling a new dashboard into the server
  image.
- Management APIs are intended for localhost, WireGuard, or a hardened reverse proxy.
- Agent APIs authenticate node tokens only through the `Authorization: Bearer`
  header; JSON body tokens are rejected so credentials do not enter request
  logs, traces, or failure captures. Successful node-token authentication
  updates `token_last_used_at` on the node record with a short write-throttle,
  giving operators lifecycle telemetry without turning every poll into a full
  state-file rewrite. Nodes may also set `agent_source_allowlist` with exact IPs
  or CIDR prefixes; the token is then accepted only from those sources. Direct
  deployments use the socket remote address, while `CF-Connecting-IP` /
  `X-Forwarded-For` are honored only when the server is explicitly configured
  with `TrustProxy`.
- Agent HostFacts (OS, arch, cores, memory, platform, kernel, boot time) are
  advisory telemetry only. They are sanitized and clamped server-side and must
  not be used for authorization or policy decisions.
- Node comments are operator-owned control-plane notes. They are returned to the
  dashboard, editable through `POST /api/nodes/update`, and never sent to the
  node-agent. Do not store secrets in comments and do not use comments as policy
  input.
- Node tags are normalized on metadata writes: trimmed, deduplicated, and sorted
  for stable display and selector behavior. Tags can feed group smart selectors,
  but group membership remains a separate canonical model.
- Internal IP/IPv6 fields are agent-reported informational telemetry. On many
  VPS providers the primary interface address is also the public address; when a
  dashboard needs a distinct LAN address it must treat equality with the public
  IP as "not separately reported" rather than as proof of private addressing.
- Fleet Map GeoIP lookup defaults to the no-token `ipwho.is` HTTPS provider so
  nodes can be placed without extra setup. Set `LATTICE_GEOIP_LOOKUP_URL=off`
  to prevent the server from sending node public IPs to an external service, or
  set it to an internal HTTPS template containing `{ip}`. Automatically resolved
  NodeGeo is marked `source=auto` and manual saves are marked `source=operator`.
- Node-agent update policies have two modes. Legacy policies may pin an explicit
  HTTPS binary URL and SHA-256 digest; the URL must not contain userinfo, query
  parameters, or fragments because the reviewed approval plan displays it. The
  dashboard's primary node detail UI
  uses the official-release mode by leaving `binary_url` and `sha256` empty:
  the server resolves `LATTICE_AGENT_RELEASE_REPO` (default
  `LatticeNet/lattice-node-agent`), maps the node OS/arch to
  `lattice-agent-linux-amd64` or `lattice-agent-linux-arm64`, reads the release
  `SHA256SUMS` (bounded to 512 KiB), and creates the reviewed update task with
  the concrete URL and digest. `target_version=latest` resolves to the latest
  `v*` GitHub release at plan time. `/api/nodes/agent-updates/releases` exposes
  a read-only snapshot of the current latest tag and published checksums for
  dashboard guidance; the approval plan remains authoritative because it binds
  the concrete URL and SHA-256 server-side. Editing or deleting a policy closes
  pending and
  approved-without-active-task update approvals for that node; active queued or
  leased update tasks remain in flight until their task result closes the
  approval. If a node already reports the current target before a pending update
  approval is applied, the scheduler closes the no-op approval as rejected
  instead of leaving stale host-mutation work in the inbox. Automatically closed
  update approvals include a plain-text rejection reason so operators can
  re-plan without guessing which policy or node state changed. Approval and
  node-side exec/root-exec requirements still apply.
  Default install targets are treated as auto-detectable: the task script
  inspects the running agent parent process and systemd cgroup, then updates the
  currently executing `lattice-agent` path and restarts the detected service
  unit. This keeps current `/opt/lattice/lattice-agent` installs and older
  custom `/opt/lattice/node-agent/lattice-agent` layouts working. A successful
  task result records `last_applied_version`; the live source of truth remains
  the next node heartbeat's reported `agent_version`.
- Node reconfigure commands source both the canonical
  `/opt/lattice/lattice-agent.env` and legacy `/opt/lattice/node-agent/agent.env`
  before rerunning the installer. Operators can therefore reconfigure or upgrade
  old nodes without copying the node token again, while the installer still
  refuses node-id/token mismatches.
- Browser Terminal uses scoped, in-memory server sessions and outbound
  node-agent polling. It is not inbound SSH, and the server does not store SSH
  keys. Operators need `terminal:open`; nodes must run `lattice-agent` with
  `LATTICE_AGENT_ALLOW_TERMINAL=1`. Session open/close events are audited, while
  live terminal I/O is kept in bounded process memory for the active session.
  The broker limits each node to four active sessions, expires unaccepted
  sessions after 10 minutes, expires idle sessions after four hours, and prunes
  closed transcripts after 30 minutes.
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
  history. Personal access tokens with a non-global `server_allowlist` see only
  audit rows whose `node_id` is explicitly inside that allowlist; global audit
  rows are reserved for unrestricted operators.
  Server-side `5xx` responses deliberately return generic public messages
  (`internal server error` or `upstream service error`) rather than raw provider,
  filesystem, database, or token-bearing error strings.
  Security-sensitive denials use stable business codes such as
  `capability_denied`, `invalid_node_token`, `invalid_task_lease`, and
  `task_output_limit_exceeded`. Approval workflows also expose stable conflict
  codes such as `approval_stale` for changed reviewed plans and
  `agent_update_noop` when an agent update plan is a no-op because the node
  already reports the target version.
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
- Approval-backed task results close failed approvals as `rejected` with a
  bounded plain-text `reason`, so the approvals inbox shows why a reviewed
  mutation did not apply instead of leaving it indefinitely `approved`.
- Approval decisions always require `network:apply`; domain-specific host
  mutations also require their owning admin scope (`dns:admin` for selfdns,
  `netpolicy:admin` for nftpolicy, `proxy:admin` for proxycore, `node:admin`
  for agentupdate, and `tunnel:admin` for cftunnel) on the target node.
- DNS deployment state (`/api/dns/deployments`) is server-owned intent for
  CoreDNS deployment. Writes require `dns:admin` on the target node, node
  existence is checked, Cloudflare tokens are write-only and encrypted at rest,
  and read views expose only `has_credential`. `/api/dns/plan` requires both
  `dns:admin` and same-node `network:plan`, renders a secret-free CoreDNS
  Corefile plus composed `lattice_guard` nft candidate into a pending `selfdns`
  approval, and queueing apply writes the reviewed artifacts, commits nft with
  rollback, manages `lattice-selfdns.service`, and updates deployment status
  from task results. `/api/dns/publish` reuses the existing Cloudflare DDNS
  provider server-side, never sends CF tokens to agents, records the last
  published A/AAAA values on the DNSDeployment, and is also triggered when the
  bound node's observed public IP changes. Service apply status
  (`last_applied_at` / `last_error`) is separate from hostname publication
  status (`last_published_at` / `last_publish_error`) so failures stay
  attributable to the right layer. Optional CoreDNS install is server-configured
  and plan-bound: the approval text contains the HTTPS URL and SHA-256, and the
  agent applies exactly that reviewed artifact metadata.
- Proxy-core state currently exists as a persistence/model foundation plus a
  narrow server-side sing-box renderer, scoped CRUD/read APIs, a redacted
  reviewed plan endpoint, reviewed queue/apply, public subscription serving,
  audited subscription-token rotation, and baseline usage accounting.
  `ProxyInbound.RealityPrivateKey` and `ProxyUser.UUID`/`Password`/`SubToken`
  are encrypted at rest, and proto/read contracts expose only `has_*` presence
  booleans. `internal/proxycore` renders a canonical SHA-256-addressed
  sing-box `vless`+TCP+REALITY config from server-owned inbounds, profiles, and
  users; the artifact contains the REALITY private key and eligible VLESS UUIDs
  and must be treated as node-scoped secret material. The current JSON APIs
  return `ProxyInboundView`, `ProxyUserView`, and `ProxyNodeProfileView` shapes:
  global inbounds/users require unrestricted `proxy:read`/`proxy:admin`, while
  profiles are node-allowlist filtered. `POST /api/proxy/nodes/{node_id}/plan`
  stores a redacted review plan and binds the real rendered config SHA in the
  approval action; `queue_apply:true` re-renders the current config, rejects
  stale SHA, and queues a node-owned `sh` task that writes a same-directory
  candidate config, runs `sing-box check -c`, atomically swaps, and reloads or
  restarts the service. Because that queued script carries the real rendered
  proxy config, `model.Task.Script` is encrypted at rest in JSON and bbolt
  stores. Control-plane task views expose only script hash/size; only the
  authenticated owning node receives the script through the agent lease API.
  Future proxy APIs must not serialize the secret-bearing model structs or
  render artifacts directly. The public `/sub/{token}` route uses a
  constant-time full scan over decrypted subscription tokens, rate-limits before
  credential lookup, fails closed on duplicate tokens, records only token
  SHA-256 hashes in audit metadata, and deliberately does not persist raw
  subscription tokens as map keys. It currently supports `format=base64`
  (default), `format=plain`, `format=sing-box` (`application/json` client
  outbounds), and `format=clash` / `format=clash-meta` (`text/yaml` Mihomo
  `proxies:` list) for the supported VLESS+REALITY+TCP path. These bodies are
  derived from a secret-free `VLESSRealityEndpoint` projection; Clash/Mihomo YAML
  is emitted by a fixed-shape writer with quoted scalars, so no YAML dependency
  is introduced. `ProxyInbound.Fingerprint` is accepted only as a constrained
  safe token and is subscription metadata, not a secret. `POST
  /api/proxy/users/rotate-sub-token`
  returns the new subscription URL/path only in the explicit rotate response and
  uses `LATTICE_PUBLIC_URL` when configured instead of reflecting request
  `Host`. `POST /api/agent/proxy-usage` accepts low-trust node usage snapshots
  only through bearer node-token auth, filters counters to users eligible for
  the node's profile, treats the first snapshot as a baseline, advances usage
  monotonically under a dedicated mutex, and rejects malformed/negative input.
  `GET /api/proxy/usage` returns only secret-free counters/status for the
  dashboard.
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
- Operator-configured outbound webhooks and OIDC IdP calls use guarded HTTP
  clients that reject loopback, private, link-local, metadata, CGNAT, and
  documentation ranges. This applies to OIDC discovery, JWKS fetches, and token
  exchange, so an admin-supplied issuer cannot make the server reach internal
  services.
- Plugin manifests require stable lowercase ids and non-empty duplicate-free
  capability lists before any plugin can be trusted by the control plane.
  Host-risk/system plugins can be verified with an operator trust policy:
  trusted `publisher` Ed25519 keys, artifact `digest_sha256`, and
  standard-base64 `signature_ed25519` over the canonical Lattice plugin signing
  payload.
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
  append-only hash-chained audit WAL (`<state>.audit-wal`) and a local sidecar
  head anchor (`<state>.audit-anchor`) that detects end-truncation on open and
  through `/api/audit/verify`.
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
    "latticenet": "standard-base64-of-32-byte-ed25519-public-key"
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
    "signature_ed25519": "standard-base64-of-64-byte-ed25519-signature"
  },
  "artifact_base64": "standard-base64-artifact-bytes"
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
