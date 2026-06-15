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

FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S lattice \
    && adduser -S -G lattice -h /var/lib/lattice lattice \
    && mkdir -p /app/dashboard /var/lib/lattice /plugins \
    && chown -R lattice:lattice /var/lib/lattice /plugins

COPY --from=build /out/lattice-server /usr/local/bin/lattice-server
COPY --from=lattice-dashboard index.html /app/dashboard/index.html
COPY --from=lattice-dashboard assets /app/dashboard/assets

USER lattice

ENV LATTICE_LISTEN=0.0.0.0:8088 \
    LATTICE_DATA=/var/lib/lattice/state.json \
    LATTICE_WEB_ROOT=/app/dashboard \
    LATTICE_MASTER_KEY_FILE=/var/lib/lattice/master.key \
    LATTICE_PLUGIN_DIR=/plugins

EXPOSE 8088
VOLUME ["/var/lib/lattice", "/plugins"]

ENTRYPOINT ["/usr/local/bin/lattice-server"]
