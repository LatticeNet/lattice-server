#!/usr/bin/env sh
set -eu

if [ "$#" -eq 0 ]; then
  set -- /usr/local/bin/lattice-server
fi

if [ "$(id -u)" = "0" ]; then
  data_path="${LATTICE_DATA:-/var/lib/lattice/state.json}"
  data_dir="$(dirname "$data_path")"
  mkdir -p "$data_dir"
  # The data directory is chowned to lattice when anything in it, the
  # directory included, has another owner or group: a fresh bind mount, or a
  # restore, docker cp or extract run as another user. A plugin uid that
  # owned a file there would own the server's secrets (design 30). A tree
  # lattice owns throughout is left alone, so an ordinary boot needs no
  # CAP_CHOWN and the bounding set can stay at the three capabilities design
  # 30 needs. find runs as lattice, which can read its own 0700 directories
  # without CAP_DAC_READ_SEARCH and still reports a foreign directory it
  # cannot enter. The trailing slash follows a symlinked data directory.
  if [ -n "$(su-exec lattice find "$data_dir/" \( ! -user lattice -o ! -group lattice \) -print -quit 2>/dev/null)" ]; then
    chown -R lattice:lattice "$data_dir"
  fi
  # The user alone, not user:group: su-exec then keeps lattice's
  # supplementary groups, and lattice-probe is how the server opens the
  # probe's socket.
  exec su-exec lattice "$@"
fi

exec "$@"
