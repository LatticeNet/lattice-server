#!/usr/bin/env sh
set -eu

dockerfile="Dockerfile"
entrypoint="docker-entrypoint.sh"

if [ ! -f "$dockerfile" ]; then
  echo "missing $dockerfile" >&2
  exit 1
fi

if [ ! -f "$entrypoint" ]; then
  echo "missing $entrypoint" >&2
  exit 1
fi

if grep -Fq "LATTICE_MASTER_KEY_FILE" "$dockerfile"; then
  echo "Dockerfile must not set LATTICE_MASTER_KEY_FILE by default." >&2
  echo "Leaving it unset lets the server auto-generate /var/lib/lattice/master.key on first boot." >&2
  exit 1
fi

if grep -Fxq "USER lattice" "$dockerfile"; then
  echo "Dockerfile must start as root and let docker-entrypoint.sh drop privileges after fixing bind mount ownership." >&2
  exit 1
fi

for required in \
  "su-exec" \
  "COPY docker-entrypoint.sh /usr/local/bin/lattice-entrypoint" \
  "RUN chmod 0755 /usr/local/bin/lattice-entrypoint" \
  "LATTICE_DATA=/var/lib/lattice/state.json" \
  "LATTICE_WEB_ROOT=/app/dashboard" \
  "LATTICE_PLUGIN_DIR=/plugins" \
  'ENTRYPOINT ["/usr/local/bin/lattice-entrypoint"]' \
  'CMD ["/usr/local/bin/lattice-server"]'
do
  if ! grep -Fq "$required" "$dockerfile"; then
    echo "Dockerfile missing runtime default: $required" >&2
    exit 1
  fi
done

for required in \
  'chown -R lattice:lattice "$data_dir"' \
  'exec su-exec lattice:lattice "$@"'
do
  if ! grep -Fq "$required" "$entrypoint"; then
    echo "$entrypoint missing bind-mount ownership handoff: $required" >&2
    exit 1
  fi
done

sh -n "$entrypoint"
