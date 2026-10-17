#!/usr/bin/env sh
set -eu

if [ "$#" -eq 0 ]; then
  set -- /usr/local/bin/lattice-server
fi

if [ "$(id -u)" = "0" ]; then
  data_path="${LATTICE_DATA:-/var/lib/lattice/state.json}"
  data_dir="$(dirname "$data_path")"
  mkdir -p "$data_dir"
  # Only a data directory lattice does not own yet is chowned (a fresh bind
  # mount). A directory it already owns is left as it is, so the container
  # needs no CAP_CHOWN for an ordinary boot and its bounding set can stay at
  # the three capabilities design 30 needs.
  if [ "$(stat -c %u "$data_dir")" != "$(id -u lattice)" ]; then
    chown -R lattice:lattice "$data_dir"
  fi
  # The user alone, not user:group: su-exec then keeps lattice's
  # supplementary groups, and lattice-probe is how the server opens the
  # probe's socket.
  exec su-exec lattice "$@"
fi

exec "$@"
