# Node delete residue audit, 2026-08-20

Coverage note for two manual node deletions on the production control plane at
https://lattice.roobli.org, running `alpha-0.2.2a31`. The operator deleted
`[cd]-OHNO-aca-NAT` and `[cd]-nmcloud-tw-hinet-nat` and asked whether the
deletions actually completed, whether they removed the right set, and whether
the plugin side was cleaned up.

This is an audit, not a repair. Nothing on production was modified, applied,
approved or removed. Every residue named below is still there.

Reviewed against `integration` at `713205f`. Live evidence read from the HK host
on 2026-08-20 around 12:20 host time.

## Identity, resolved first

Names and ids differ in this fleet, and both nodes had to be resolved from the
audit log because their records are gone:

- `[cd]-OHNO-aca-NAT` is node id `node_eewaewf267gp45wo`, deleted
  2026-08-20T03:46:50.344Z by `user_admin`, correlation `req_wgvdpilf3nludyqb`,
  audit event `audit_4mwttxxdmuni5wm5` at WAL seq 444120.
- `[cd]-nmcloud-tw-hinet-nat` is node id `nmcloud-tw`, deleted
  2026-08-20T03:47:46.663Z by `user_admin`, correlation `req_3kbbgtaz7okcwqs7`,
  audit event `audit_ujj34fhcgjxqpwle` at WAL seq 444268.

The short id `nmcloud-tw` is a substring of its own display name and of several
unrelated strings, so every count below for that node was verified by
classifying each hit rather than by counting matches.

This reconciles with the fleet going 35 to 33: the `nodes` map now holds 33
entries and neither name nor id is among them.

## What was opened

Code, in `lattice-server` at `713205f`:

- `internal/store/cascade.go` in full, all 573 lines. This is the deletion
  engine: `DeleteNode`, `PlanDeleteNode` and the shared
  `buildNodeCascadeLocked`.
- `internal/store/store.go` for the `State` struct (the authoritative list of
  every collection a node id can hide in), `persistState`, `Save`,
  `jsonPersistStateFrom`, `mergeRuntimeBoltHotState`,
  `EnableRuntimeBoltHotStore`, and `invalidateGuardBindingsForNodeLocked`.
- `internal/store/bolt_state.go` for the sidecar bucket list.
- `internal/server/server_node_delete.go` for the server-layer wrapper and the
  audit metadata it emits.
- `lattice-sdk/model/model.go` for `Task`, `TaskLease`, `Node`, `NodeGeo`,
  `NodeInventory` and the node-id-bearing record types.
- The four plugin repos, for where each plugin actually persists node-scoped
  state: `lattice-plugin-vpn-core`, `lattice-plugin-netguard`,
  `lattice-plugin-wireguard`, `lattice-plugin-sub-store`, including their
  manifests and their `system-go` entrypoints.

Live state on the HK host, read-only:

- `/opt/lattice/server/compose/data/state.json`, the authoritative JSON store,
  swept twice: once for both node ids as keys and as substrings of any string
  value at any depth, once for the node names and their fragments (`ohno`,
  `nmcloud`, `hinet`, `aca-nat`), and then a third structured pass resolving
  every node-keyed map and every node-valued field against the 33 surviving ids.
- `/opt/lattice/server/compose/data/state-hot.db`, the 354 MB bolt sidecar.
  This mattered: `jsonPersistStateFrom` blanks `kv`, `static`, `proxy_users`,
  `proxy_profiles`, `proxy_usage`, `subscription_shares`,
  `subscription_snapshots`, `sessions` and `audit` out of `state.json`, so those
  nine domains exist only in bolt. An audit that read only the JSON file would
  have missed every plugin KV record, which is where the one real plugin leak
  turned out to be.
- `/opt/lattice/server/compose/data/state.json.audit-wal`, 219 MB, 449486
  entries, for the delete events and their cascade reports.
- `/opt/lattice/server/compose/data/logs.db`, 32 KB and empty, consistent with
  `log_sources: 0` on both delete reports.
- `/opt/lattice/server/compose/data/plugin-runtime/` and `plugin-bundles/`,
  which hold only verified plugin binaries per generation. No plugin state on
  disk there.

## What was NOT opened

Name these to the operator rather than working around them.

**Anything requiring an authenticated session.** No credentials were handled, so
every statement here comes from on-disk state, not from the running server's
read model. The specific checks that were not made, and that someone logged in
should make:

- `GET /api/kv` for the live KV view, to confirm the bolt findings below match
  what the server currently serves.
- The sub-store UI subscription list, specifically the `cdcd-self-host`
  subscription and the `merge-cd-openjobs` collection, to confirm the stale
  proxy entries render to a client.
- The vpn-core lines view and `nodes/list`.
- The netguard bindings and zones views.
- The dashboard graph and inventory pages, which may compute their display from
  sources this audit did not model.
- Any node-delete plan preview (`PlanDeleteNode`) run against a live node, which
  would confirm the cascade report shape independently.

**vpn-core `nodes/list` proves nothing and was deliberately not used as
evidence.** It is built from live inventory reported by running agents, so a
deleted node vanishes from it automatically whether or not stored state was
cleaned. Every vpn-core conclusion below comes from stored records instead: the
`vpnmeta/lineuuid` and `vpnmeta/lineuuid-owner` KV buckets and the core
collections.

**`SingBoxInventory`.** It is explicitly in-memory only and never persisted
(`lattice-sdk/model/model.go`, the type comment says a restart simply waits for
the next report). There is no on-disk copy to inspect, and it self-clears
because nothing reports for a gone node.

**Live versus freed bolt pages.** A raw scan of `state-hot.db` cannot tell a
live record from a page on the free list awaiting reuse. This only weakens
positive findings, never negative ones, so every "no residue" statement below is
conservative. The one positive finding is attributable to a named record, and
its apparent duplication is explained in place.

**166 of the 310 `vpnmeta/lineuuid` entries.** That bucket maps a line hash id
to a UUID and carries no node reference. Only the sibling bucket
`vpnmeta/lineuuid-owner` (144 entries) carries the owner node id. Neither
deleted node appears as an owner, but for the 166 line ids with no owner record
there is no way left to tell whose lines they were. This is an unresolvable
attribution gap, not a clean result.

**The node agent side.** Whether an agent that was still running on either host
holds local config naming the control plane is outside what was inspected.

## What the cascade is designed to remove

`buildNodeCascadeLocked` is one critical section with numbered steps. Read in
full so that "what should have been touched" is a list from the code and not a
guess:

Line-chain authority is settled before anything else. An issued, non-failed
source lease blocks the delete outright (`ErrLineChainDeleteConflict`); issued
target-side candidates survive so their frozen result can still commit;
everything unissued is cancelled, its approval rejected with
`line_chain_dependency_deleted`, and its tasks cancelled. Definitions with the
node as source are deleted, definitions with it as target are marked drifted
with `target_missing`. Managed lines owned by the node, and their secrets, are
deleted. The graph revision is bumped if anything changed.

Then, in order: tasks (step 1, `Targets` stripped, task deleted only when it was
the sole target); task results and result receipts (step 2, both this node's
results and the results of tasks deleted in step 1); DDNS profiles (3); machine
profiles (4); NFT inputs (5); DNS deployments (6); the node's own net policy
wholesale (7); node-ref rules stripped out of every other node's net policy and
out of every group policy (7b); geo-routing entries stripped, and deleted if
stripping empties them (8); agent update policies (9); proxy node profiles (10);
proxy usage snapshots (11); monitor assignments stripped and monitor results
removed (12); log sources, with the ids handed back so the server can purge the
separate bolt log db (13); group membership and leadership (14); approvals (15);
tunnel profiles (16); the guard reality snapshot (17); the node's own guard
binding (17b); and finally the node record itself, after
`invalidateGuardBindingsForNodeLocked` clears the compiled-plan anchor on any
surviving binding that resolves the gone node.

Audit rows are never touched, deliberately: deleting them would break the
append-only hash-chained WAL. Residue in audit is correct behavior, not a leak,
and every audit hit reported below is counted as clean.

Step 17b carries a comment saying it was added because it had been missed. That
is the reason this audit did not trust the cascade and swept the state
independently.

## Both deletions completed

Both `node.delete` events recorded `decision: allow` and a complete cascade
report. Counters as recorded:

| counter | OHNO | nmcloud |
| --- | --- | --- |
| tasks_deleted | 3 | 26 |
| tasks_stripped | 1 | 1 |
| task_results | 2 | 25 |
| approvals | 9 | 31 |
| agent_updates | 1 | 1 |
| machine_profiles | 1 | 1 |
| groups | 1 | 1 |

Every other counter was zero for both nodes, including `guard_bindings`,
`guard_reality_snapshots`, `proxy_profiles`, `proxy_usage`, `nft`,
`net_policies`, `net_peer_rules`, `group_policy_rules`, `geo_stripped`,
`geo_deleted`, `ddns`, `dns_deployments`, `log_sources`, `log_purge_errors`,
`monitors_stripped`, `monitor_results`, `tunnels`, `terminal_sessions` and
`proxy_drift_cleared`. No error was recorded on either delete.

## Core state: clean except one field

Every node-keyed map and every node-valued field in the live `state.json` was
resolved against the 33 surviving node ids. Result, for the whole fleet and not
just these two nodes:

- No orphan keys in `nft_inputs` (1 record), `agent_updates` (33),
  `guard_bindings` (0), `guard_reality_snapshots` (26), `net_policies` (0).
- No orphan `node_id` references in `machine_profiles` (33), `approvals` (802),
  `managed_lines` (0), `ddns` (0), `tunnels` (0), `log_sources` (0),
  `dns_deployments` (0).
- No orphan members or leaders in `groups` (3).
- No orphan `node_id` in `results`, and no orphan entries in `tasks.targets`
  or `tasks.rerun_of_node_id` across all tasks. Record counts are a snapshot
  from the sweep (665 tasks, 679 results, 802 approvals) and move constantly,
  since the fleet is live; the orphan result is what matters, not the totals.
- `storage_buckets`, `storage_bindings`, `storage_tokens`, `workers`,
  `subscription_shares`, `subscription_snapshots`, `geo_routing`, `monitors`,
  `monitor_results`, `notify_channels`, `notify_rules`, `security_groups`,
  `guard_zones`, `group_policies`, `line_chain_definitions` and
  `line_chain_attempts` are all empty, so there is nothing there to leak. The
  line-chain graph is empty and `line_chain_graph_revision` is still 0.
- Geo and inventory data are embedded in `model.Node` (`NodeGeo`,
  `NodeInventory`), so they were removed with the node record. The full-text
  sweep confirms no fragment survives.

The single exception, and the only orphan reference of any kind in the entire
core state:

**Task `task_uo4kywjqyxvkqvbs` still carries `target_leases` entries for both
deleted nodes.** It is a `failed` 25-target task created 2026-07-04T09:20:03Z.
Its `targets` array correctly no longer lists either node (this is the
`tasks_stripped: 1` on both delete reports), but
`target_leases["node_eewaewf267gp45wo"]` and `target_leases["nmcloud-tw"]` are
still present, each holding a `lease_id` and a `started_at`.

Cause: step 1 rewrites `Task.Targets` and never touches `Task.TargetLeases`,
which is a sibling map on the same struct keyed by node id
(`lattice-sdk/model/model.go`, `Task.TargetLeases map[string]TaskLease`).
`Task.RerunOfNodeID` has the identical exposure and is simply empty fleet-wide
right now.

This is the same class of miss as step 17b. Impact today is cosmetic because the
task is terminal, but a stripped in-flight task would retain a lease record for
a node that can no longer return a result, which is exactly the kind of dangling
authority step 17b's comment warns about.

Proposed fix, not applied: in step 1, alongside the `Targets` strip, delete the
`TargetLeases` entry for the gone node and clear `RerunOfNodeID` when it names
it, for both the strip branch and the delete branch, and add the counts to
`NodeCascadeReport` so the audit metadata shows them.

## Plugins

The user asked about this specifically and it is where the one real leak is.

Structural fact that shaped the search: three of the four plugins persist
nothing of their own. vpn-core, netguard and wireguard are `describe/health/plan`
stdio fronts whose manifests declare no `kv:*` or `secret:*` capability and
whose every interface is `backing: core`. Their state is core collections. Only
sub-store is `backing: runtime` and holds plugin KV.

### vpn-core: clean, with one attribution gap

Its stored state is the core collections plus two KV buckets, both bolt-resident:
`vpnmeta/lineuuid` (310 records, line hash id to UUID) and
`vpnmeta/lineuuid-owner` (144 records, line hash id to node id).

Neither deleted id appears in either bucket. All 23 distinct owner values are
live node ids. `managed_lines`, `managed_line_secrets`,
`line_chain_definitions` and `line_chain_attempts` are empty, `proxy_profiles`
and `proxy_usage` hold no record for either node (verified in bolt, not in the
blanked JSON copy), and `proxy_inbounds` carries no node id by design.

Two things this does not prove. First, the attribution gap above: 166 line ids
have no owner record, so if either node's lines are among them there is no way
to tell. Second, the cascade never touches KV at all, so
`vpnmeta/lineuuid-owner` has no purge path in code. It is clean here as a matter
of fact, not as a matter of guarantee.

The last `linemeta.sync` cycle ran 2026-08-20T04:26 to 04:27Z, after both
deletes, and applied to live nodes only.

### netguard: nothing to leak in this deployment

`guard_bindings`, `security_groups` and `guard_zones` are all empty. `nft_inputs`
holds one record and it belongs to a live node. The 26 guard reality snapshots
all map to live nodes; both delete reports recorded zero for both
`guard_bindings` and `guard_reality_snapshots`, meaning neither node had one at
delete time. No netguard approval exists (approvals are only `agentupdate`, 348,
and `singbox-linemeta`, 454).

One latent gap worth recording even though it could not fire here: unlike net
policies and group policies, which step 7b strips, nothing removes a dangling
`remote.node_id` from `security_groups[*].rules[*]` or from
`guard_bindings[*].overrides[*]`. `invalidateGuardBindingsForNodeLocked` clears
the affected binding's compiled-plan anchor but leaves the reference in place.
With zero groups and zero bindings on this deployment there was nothing to
observe.

### wireguard: nothing to leak in this deployment

The dangling-peer scenario cannot occur here: no node in the fleet has
`wireguard_ip`, `wireguard_public_key`, `wireguard_endpoint` or
`wireguard_port` set, so no mesh exists. The plugin stores nothing; `BuildMesh`
recomputes peers from the live `nodes` map at plan time, so a removed node
disappears from the next plan by construction.

The place a removed peer would survive is a frozen plan: the rendered `wg0.conf`
inside a surviving node's `approvals[].plan` and the matching `tasks[].script`.
Those peer blocks carry no node id, so they would have to be found by the dead
node's public key, its `AllowedIPs` address, or its name in the `# <name>`
comment. There are no wireguard approvals on this deployment, so there was no
frozen plan to search. The matching task search could not be made: all 686 task
scripts are encrypted at rest (every one is a `lat$1$` envelope), so searching
them for a peer block would have to run through the server with a session rather
than over the file.

### sub-store: one real leak

The KV record `plugin:latticenet.sub-store / subscriptions-v1` holds an
operator-imported subscription, id `imported-cdcd-self-host`, name
`cdcd-self-host`, `source: sub-store`, `kind: subscription`. Its static clash
YAML still defines five proxies belonging to the two deleted nodes, with live
hostnames, ports and credentials:

- `ohno-aca-nat-HOME_vless`, `ohno-aca.nat.roobli.org:49701`
- `ohno-aca-nat-HOME_hy2`, `ohno-aca.nat.roobli.org:49702`
- `mkcloud-iplc->ohno-aca-nat-HOME_vless`, `beijing.aliyun.roobli.org:34104`
- `nmcloud-tw-Hinet-nat_vless`, `tw-hinet-std.nmcloud.roobli.org:17897`
- `mkcloud-iplc->nmcloud-tw-Hinet-nat_vless`, `beijing.aliyun.roobli.org:34106`

Each appears twice in the record because it keeps both the working `content` and
the `origin.raw` copy of the imported text. None of the five is referenced by a
proxy-group inside that document, but the subscription is a member of the
collection `imported-col-merge-cd-openjobs` (`merge-cd-openjobs`, whose
`members` are `imported-cdcd-self-host` and `imported-openjobs-host`), so the
entries propagate to anything fetching that collection.

This is not a cascade bug. The content is operator-authored static text and node
deletion should never rewrite it. It is also not self-healing. sub-store has no
node-delete hook, no event subscription and no reconcile or prune path; the SDK
host API has no event mechanism at all, and the host exposes no KV delete
(`clearFileScript` writes a zero-byte tombstone rather than removing a key).
Nothing will ever remove these entries on its own.

The fleet-derived sub-store paths that would have self-corrected are not in use:
there are no `vpn-core-graph` subscriptions with pinned `entry_roots` (zero
occurrences of `entry_roots` anywhere in bolt), and the `subscription_snapshots`
bucket is empty (zero occurrences of `source_manifest`), so there is no cached
manifest naming either node.

Remediation is an operator edit, not a code change: remove those five proxy
blocks from the `cdcd-self-host` subscription content. Doing so also revokes the
two dead nodes' credentials from every client still fetching
`merge-cd-openjobs`.

## Audit residue, which is correct

For completeness, since it dominates any raw scan. In `state-hot.db`,
`node_eewaewf267gp45wo` occurs 9492 times and every single occurrence is an
audit event (9380 of them `singbox.discover.report`). `nmcloud-tw` occurs 11070
times, of which 11066 are audit events and 4 are the sub-store record above.
This is the append-only WAL doing its job and is not residue.

## Findings, none applied

1. `Task.TargetLeases` and `Task.RerunOfNodeID` are not cleaned by cascade step
   1. Live residue confirmed on `task_uo4kywjqyxvkqvbs` for both nodes. Fix is
   in `internal/store/cascade.go` step 1, plus two report counters.
2. Cascade steps 10 and 11 delete `ProxyProfiles[nodeID]` and
   `ProxyUsage[nodeID]` from memory only. `DeleteNode` persists through
   `persistState(jsonPersistStateFrom(staged))`, which blanks both domains out
   of the JSON, and the cascade deliberately avoids the `DeleteProxyNodeProfile`
   and `DeleteProxyUsageSnapshot` helpers because they take `s.mu` and
   `sync.Mutex` is not reentrant. The bolt copy therefore survives, and
   `mergeRuntimeBoltHotState` reads it back into memory on the next start. This
   is a resurrection path, not a stale row. It did not fire for these two nodes
   because both had zero profiles and zero usage snapshots. The same reasoning
   applies to any future cascade step touching a bolt-authoritative domain.
3. Cascade never touches KV, so `vpnmeta/lineuuid-owner/<line>` holding a node
   id has no purge path. Clean today by luck of the data, not by design.
4. netguard node-refs in `security_groups[*].rules[*].remote.node_id` and
   `guard_bindings[*].overrides[*].remote.node_id` are invalidated but not
   stripped, unlike the equivalent refs in net policies and group policies. Not
   exercised on this deployment.

## Bottom line

Both deletions completed and removed the right set. Core state holds exactly one
leaked field, the two `target_leases` keys on one terminal task. Of the four
plugins, vpn-core, netguard and wireguard hold nothing naming either node, in
two of those cases because the feature is unused here rather than because the
cleanup was proven. sub-store holds five stale proxy definitions with live
credentials inside one operator-imported subscription, which no code path will
ever clean and which propagate into a collection.
