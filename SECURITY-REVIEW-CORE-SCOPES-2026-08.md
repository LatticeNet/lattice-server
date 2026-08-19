# In-core plugin method scope review, 2026-08-19

Coverage note for the in-core implementations of plugin-declared methods. This
is the gap the sidecar review named and could not close from where it stood:
every interface in the four first-party plugin manifests is `backing: core`, so
the methods those manifests declare, and the scopes they declare them at, are
implemented here.

The question is the one that produced three findings in
lattice-plugin-sub-store, asked on the other side of the boundary: does the
implementation reach further than the scope on its declaration.

Reviewed against `origin/integration` at `75b9411`.

## What was opened

All 38 methods declared by the three network plugin manifests, plus sub-store's
core-backed `shares/list`, traced from their registration to their handler:

- `internal/server/server_vpncore.go`, the registration table (lines 45-70) and
  the nodes, lines and subscription-sources handlers
- `internal/server/vpnusers.go`, the users and users-admin handlers
- `internal/server/lineusers.go`, the plan and rotate paths
- `internal/server/profiles.go`, the profiles handler and its per-node check
- `internal/server/usage.go`, the usage handler
- `internal/server/server_network_plugins.go`, both netguard and wireguard
- `internal/server/server_substore_plugins.go`, the shares handler
- `internal/plugin/rpc.go` in full, the bus that authorizes both entry paths
- `internal/server/server_plugin_invoke.go`, the operator gateway and its scope
  check, and `internal/server/server_plugin_grants.go`, which materializes
  plugin-to-plugin grants
- `internal/rbac/rbac.go` for the scope hierarchy and the legacy aliases
- `internal/proxycore/links.go` for what a rendered subscription link contains

## What was not opened

The node agent side. A plan compiled here is applied by the agent under the
approval flow, and nothing in this note says whether that execution path is
safe. In particular vpn-core advertises `sb --json add/del` on nodes, so an
operator-supplied string does reach a shell somewhere; that construction lives
in the agent and the approval executor, not in the handlers reviewed here, and
it is unexamined.

The dashboard. A separate lane owned it.

Non-plugin REST surfaces. Only the methods reachable as plugin-declared
interfaces were traced, though several of them share a handler with their REST
equivalent by design.

## The two entry paths, which is the frame for everything below

An in-core service has two callers, and they authorize differently.

The operator path (`handlePluginCall`) looks up the target method's contract in
the signed manifest and checks the caller's principal against its declared
scopes (`server_plugin_invoke.go:211-224`). An undeclared service is refused
even when the registry has it.

The plugin path (`RPCRegistry.CallGranted`, `internal/plugin/rpc.go:255`) checks
only that the calling plugin holds a grant for that service and method. The
grant comes straight from the caller's own signed manifest `host_access`, which
`applyPluginHostAccess` materializes on activation with the comment "the
manifest remains the sole owner of these edges". No principal is passed and the
target's declared scopes are never consulted.

So the effective authorization for any core-backed method is the union of "a
principal holding the declared scope" and "an installed plugin whose own
manifest asked for the edge, with no principal at all". Every scope on a
core-backed declaration is therefore a statement about one of the two paths.

## Findings

### HIGH — `latticenet.vpn-core/nodes` hands subscriber credentials to a read-scoped principal

`export` is declared `vpncore:read`. `vpnCoreExportNodes`
(`server_vpncore.go:322`) takes no principal, its caller discards the context
(`server_vpncore.go:283`), and with no `user_id` it walks `s.store.ProxyUsers()`
and renders `VLESSRealityLinks` for every one of them. A link is
`"vless://" + UUID + "@" + host` (`internal/proxycore/links.go:245`), and for
VLESS that UUID is the entire credential. `list` has the same shape for the
other branch: it returns the `share_url` each agent reported, which carries the
adopted machine's own credential.

Failure scenario: a principal holding `vpncore:read`, or the legacy `proxy:read`
that `rbac.compatibleScopes` maps onto it, posts
`{"id":"latticenet.vpn-core","service":"latticenet.vpn-core/nodes","method":"export"}`
to the plugin call gateway and receives one working credential per subscriber,
plus one per adopted on-box node.

What makes this a finding rather than a design choice is that the same manifest
answers the same question the other way at the same scope. `users/list` and
`users/get` are also `vpncore:read`, and `toVpnUserView` (`vpnusers.go:104-122`)
deliberately reduces every credential to `HasSecret bool`. Two methods at one
scope cannot both be right about whether credentials cross it.

Four failing tests in `internal/server/audit_core_scope_test.go`, driving the
real gateway with a real principal:

- `TestNodesExportWithholdsCredentialsFromAReadScopedPrincipal`
- `TestNodesExportWithholdsCredentialsFromLegacyProxyRead`
- `TestNodesListWithholdsDiscoveredShareCredentials`
- `TestNodesExportWithholdsDiscoveredShareCredentials`

`TestUsersListWithholdsCredentialsFromTheSameScope` is the control and passes,
so the failures are the export path and not the harness.

### MEDIUM — the plugin path reaches admin mutations with no principal, and can choose the credential

`users-admin` is declared `vpncore:admin`. Five of its nine methods (`create`,
`update`, `delete`, `bind`, `unbind`) take no principal, so on the plugin path
they run for any plugin holding a grant, with nobody attributed and no scope
consulted. `create` additionally accepts a caller-supplied UUID:
`normalizeCredentials` (`vpnusers.go:686-700`) takes a well-formed uuid verbatim
and only generates one when the field is empty. The result is not a stray
record, it is working VPN access whose secret the caller already knows.

Nothing exploits this today. No shipped plugin declares `host_access` to a
mutating service: sub-store's asks only for `nodes.export` and
`subscription-sources`, and netguard, wireguard and vpn-core declare no
`host_access` at all. It is recorded because installing any signed plugin is the
only step between the current state and that one, and because sub-store has just
demonstrated that a plugin's own gating of its own methods can be wrong.

`TestGrantedPluginPathReachesAdminMutationsWithNoPrincipal` fails and shows the
planted credential reaching the store.

The contrast is in the same service. `rotate` and the three `plan_*` methods
call `pluginOperatorPrincipal` and fail closed without one, which
`TestRotateAlreadyFailsClosedWithoutAPrincipal` pins and which passes. Half of
`users-admin` already has the property.

### LOW — a registered service the manifest does not declare

`latticenet.vpn-core/subscription-sources` is registered on the bus
(`server_vpncore.go:67`) with `compose` and `graph_options`, and the shipped
vpn-core manifest does not declare it. It therefore has no declared scopes and
is invisible to the operator-facing contract.

Not exploitable. The operator path refuses an undeclared service outright, so
the only caller is sub-store through its `host_access` grant. It is recorded
because it means the manifest is not a complete description of the plugin's
surface, which is the document everything else in this review treats as
authoritative.

## Checked and found clean, with the reason

**netguard, all 10 methods.** Every one routes through `invokePluginOperation`
or `invokePluginQuery` (`server_network_plugins.go:104-160`), both of which call
`pluginOperatorPrincipal` first and fail closed, then run the same handler as
the REST API with that principal passed explicitly. There is no second
authorization path to get wrong.

**wireguard, both methods.** `plan` goes through `invokePluginOperation`.
`overview` requires a principal and then filters per node with
`rbac.Allows(p.Principal, "wireguard:read", node.ID)`, which is the strongest
pattern in the tree: principal required and per-resource filtering, not just an
entry check.

**sub-store `shares/list`.** This is the reference implementation and its
comment states the principle the export finding rests on: "The gateway already
enforced the manifest scopes, but this method hands out URLs embedding share
tokens ... Re-checking here means a manifest mistake can never widen who reads
them" (`server_substore_plugins.go:54-60`). It re-checks `proxy:admin` inside the
handler.

**vpn-core `profiles`.** `settings` and `configure` call
`requireVPNCoreProfileNodeScope` (`profiles.go:287-300`), which requires a
principal, re-checks the scope against the specific node, and records an audit
event on denial.

**vpn-core `lines` writes.** `sync_metadata`, `reattach` and `rollout` require a
principal. The reads (`list`, `get`, `managed`, `chains`) do not, but their read
model carries line identity UUIDs rather than subscriber credentials, so the
`vpncore:read` declaration matches what they return.

**vpn-core `usage/query`.** No principal, declared `vpncore:read`, returns
aggregate counters by user and node. No credential material.

**vpn-core `users/list` and `users/get`.** Correct, and the reason the export
finding is a finding.

## On whether the RPC bus should carry the calling principal

It already does, on the paths that have one, and this is cheaper than it looks.

The gateway stamps the principal onto the invocation context
(`server_plugin_invoke.go:227`). `runCtx` derives from that context
(`system_runner.go:974`) and is what the host-call pump passes to
`dispatchHostCall`, so a plugin's `rpc.call` reaches the target handler with the
originating operator still in the context. `pluginOperatorPrincipal` is the
accessor, it fails closed, and eleven handlers across four services already use
it. No change to the `RPCHandler` signature, the wire protocol, or any plugin is
required to read the principal in a handler that does not read it today.

What is genuinely missing is smaller and more specific than a contract change.

First, three call sites invoke a plugin with no operator at all: the public share
serve path (`server_subscription_share.go:603`), the background refresh
(`subscription_refresh.go:401`) and the sub-store auto-sync
(`substore_sync.go:262`). These are legitimate and they are why `nodes.export`
cannot simply start requiring a principal: a public share of a vpn-core-sourced
subscription resolves through exactly that chain. Today those origins are
indistinguishable from a programming error, because both present as "no
principal". Giving them an explicit system identity is the prerequisite for
letting a sensitive handler demand one, and it is the piece I would schedule
first. It is an internal change with no plugin-visible surface.

Second, `CallGranted` does not consult the target's declared scopes even when a
principal is present. If the intent is that a plugin can never reach further
than the operator driving it, the enforcement point is that function, and it
needs the principal from the context plus the target method's declared scopes
from the target's manifest. Both are already reachable from there. That is still
an internal change rather than a contract change, but it is a behaviour change
for any plugin whose grant currently exceeds its caller's scopes, so it wants a
deliberate decision rather than a quiet fix.

My recommendation, in order. Fix the export exposure on its own merits first,
because it is reachable today by a read-scoped operator and does not depend on
any of the above: either narrow `nodes/export` and `nodes/list` to
`vpncore:admin`, or re-check inside the handler the way `shares/list` does, which
is the option that survives a future manifest mistake. Then give the three
principal-less origins an explicit system identity. Then decide the
`CallGranted` question, which is the only one of the three that changes an
existing plugin's reach and therefore the only one that needs scheduling rather
than fixing.

## What is on this branch

`internal/server/audit_core_scope_test.go`, seven tests. Five fail and are the
findings; two pass and are the controls that prove the harness and the contrast.
No production code is changed. Running the package shows those five as the only
failures.
