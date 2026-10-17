# syntax=docker/dockerfile:1.7

FROM golang:1.26-bookworm AS build

WORKDIR /src

# lattice-server, lattice-sdk, and lattice-dashboard live in separate
# repositories. BuildKit named contexts keep that split intact while still
# producing a single server image with the dashboard embedded.
COPY . /src/lattice-server
COPY --from=lattice-sdk . /src/lattice-sdk

RUN go work init ./lattice-sdk ./lattice-server

WORKDIR /src/lattice-server
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /out/lattice-server \
    ./cmd/lattice-server

FROM node:22-bookworm AS dashboard
ARG VERSION=dev
ARG DASHBOARD_COMMIT=unknown
ENV VITE_APP_VERSION=${VERSION} \
    VITE_GIT_COMMIT=${DASHBOARD_COMMIT}

WORKDIR /src/dashboard
COPY --from=lattice-dashboard . .
RUN corepack enable \
    && corepack prepare pnpm@10.33.0 --activate \
    && pnpm install --frozen-lockfile \
    && pnpm build

FROM alpine:3.22
ARG VERSION=dev
ARG COMMIT=unknown
ARG DASHBOARD_COMMIT=unknown
ARG DATE=unknown

# lattice-probe (design 27) runs as 65532:65532 and serves a 0660 socket in a
# volume shared at /run/lattice-probe. The server reaches it through group
# 65532, and the directory ships owned by the probe so whichever container
# first fills the named volume leaves it writable for the probe.
RUN apk add --no-cache ca-certificates su-exec tzdata \
    && addgroup -S lattice \
    && adduser -S -G lattice -h /var/lib/lattice lattice \
    && addgroup -S -g 65532 lattice-probe \
    && addgroup lattice lattice-probe \
    && mkdir -p /app/dashboard /var/lib/lattice /plugins /run/lattice-probe \
    && chown -R lattice:lattice /var/lib/lattice /plugins \
    && chown 65532:65532 /run/lattice-probe \
    && chmod 0770 /run/lattice-probe

# Design 30: the server runs each plugin child as its own uid, which needs
# CAP_SETUID and CAP_SETGID, and reaps that child across the uid with
# CAP_KILL. The three are file capabilities on the binary, permitted and
# effective but never inheritable or ambient, so a plugin child's execve of
# an artifact without file capabilities computes an empty set. File
# capabilities land on whoever execs the file, whatever their uid, so the
# binary is 0750 root:lattice: the server (uid lattice, gid lattice, through
# su-exec or directly) execs it, and a plugin child (its own uid as its gid,
# no supplementary groups) gets EACCES instead of the three capabilities.
# chown clears file capabilities, so install sets owner and mode first and
# setcap runs last. They apply only while the container keeps
# no-new-privileges off; with it on, the server starts with none and every
# plugin drop fails closed. setcap comes from libcap and is removed again in
# the same step. The binary is installed in the layer that sets the
# capability, so the image carries one copy. Until S2's compose drops every
# other capability, a server compromise could use CAP_SETUID to become
# container root inside Docker's default capability set.
RUN --mount=type=bind,from=build,source=/out/lattice-server,target=/tmp/lattice-server \
    apk add --no-cache --virtual .setcap libcap-utils \
    && install -o root -g lattice -m 0750 /tmp/lattice-server /usr/local/bin/lattice-server \
    && setcap cap_setuid,cap_setgid,cap_kill+ep /usr/local/bin/lattice-server \
    && apk del .setcap
COPY --from=dashboard /src/dashboard/dist /app/dashboard
COPY docker-entrypoint.sh /usr/local/bin/lattice-entrypoint
RUN chmod 0755 /usr/local/bin/lattice-entrypoint

LABEL org.opencontainers.image.title="Lattice Server" \
    org.opencontainers.image.description="Lattice control-plane server with embedded dashboard assets" \
    org.opencontainers.image.source="https://github.com/LatticeNet/lattice-server" \
    org.opencontainers.image.version="${VERSION}" \
    org.opencontainers.image.revision="${COMMIT}" \
    org.opencontainers.image.created="${DATE}" \
    org.opencontainers.image.licenses="MIT" \
    org.opencontainers.image.vendor="LatticeNet" \
    org.opencontainers.image.latticenet.dashboard-revision="${DASHBOARD_COMMIT}"

ENV LATTICE_LISTEN=0.0.0.0:8088 \
    LATTICE_DATA=/var/lib/lattice/state.json \
    LATTICE_WEB_ROOT=/app/dashboard \
    LATTICE_PLUGIN_DIR=/plugins \
    LATTICE_DASHBOARD_COMMIT=${DASHBOARD_COMMIT} \
    LATTICE_DASHBOARD_BUILT_AT=${DATE}

EXPOSE 8088
VOLUME ["/var/lib/lattice", "/plugins"]

ENTRYPOINT ["/usr/local/bin/lattice-entrypoint"]
CMD ["/usr/local/bin/lattice-server"]
