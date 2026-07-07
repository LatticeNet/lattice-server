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

RUN apk add --no-cache ca-certificates su-exec tzdata \
    && addgroup -S lattice \
    && adduser -S -G lattice -h /var/lib/lattice lattice \
    && mkdir -p /app/dashboard /var/lib/lattice /plugins \
    && chown -R lattice:lattice /var/lib/lattice /plugins

COPY --from=build /out/lattice-server /usr/local/bin/lattice-server
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
