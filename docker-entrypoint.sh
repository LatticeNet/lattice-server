#!/usr/bin/env sh
set -eu

if [ "$#" -eq 0 ]; then
  set -- /usr/local/bin/lattice-server
fi

if [ "$(id -u)" = "0" ]; then
  data_path="${LATTICE_DATA:-/var/lib/lattice/state.json}"
  data_dir="$(dirname "$data_path")"
  mkdir -p "$data_dir"
  chown -R lattice:lattice "$data_dir"
  exec su-exec lattice:lattice "$@"
fi

exec "$@"
