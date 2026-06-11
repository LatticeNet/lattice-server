# lattice-server

The Lattice control plane server.

Responsibilities:

- Admin login, sessions, CSRF checks, and secure cookie defaults.
- Scope and server allowlist authorization.
- Node enrollment and outbound-agent APIs.
- Fleet metrics ingestion.
- Batch task scheduling and result collection.
- KV/static/Worker control APIs.
- nftables plan and approval workflow.
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
- nft operations are generated as approvals before agent-side validation.

