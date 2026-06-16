#!/usr/bin/env sh
set -eu

dockerfile="Dockerfile"

if [ ! -f "$dockerfile" ]; then
  echo "missing $dockerfile" >&2
  exit 1
fi

if grep -Fq "LATTICE_MASTER_KEY_FILE" "$dockerfile"; then
  echo "Dockerfile must not set LATTICE_MASTER_KEY_FILE by default." >&2
  echo "Leaving it unset lets the server auto-generate /var/lib/lattice/master.key on first boot." >&2
  exit 1
fi

for required in \
  "LATTICE_DATA=/var/lib/lattice/state.json" \
  "LATTICE_WEB_ROOT=/app/dashboard" \
  "LATTICE_PLUGIN_DIR=/plugins"
do
  if ! grep -Fq "$required" "$dockerfile"; then
    echo "Dockerfile missing runtime default: $required" >&2
    exit 1
  fi
done
