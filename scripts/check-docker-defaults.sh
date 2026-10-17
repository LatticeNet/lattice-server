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

# The handoff names the user alone: su-exec given user:group discards the
# supplementary groups, and group lattice-probe (65532) is how the server opens
# lattice-probe's 0660 socket.
for required in \
  'chown -R lattice:lattice "$data_dir"' \
  'exec su-exec lattice "$@"'
do
  if ! grep -Fq "$required" "$entrypoint"; then
    echo "$entrypoint missing bind-mount ownership handoff: $required" >&2
    exit 1
  fi
done

for required in \
  "addgroup -S -g 65532 lattice-probe" \
  "addgroup lattice lattice-probe"
do
  if ! grep -Fq "$required" "$dockerfile"; then
    echo "Dockerfile missing the probe socket group: $required" >&2
    exit 1
  fi
done

# Design 30: the server binary carries exactly the three file capabilities
# the plugin uid drop needs, and only the server's own identity can exec it:
# file capabilities land on whoever execs the file, so a binary a plugin uid
# could exec would hand the plugin CAP_SETUID back. It is installed 0750
# root:lattice before setcap runs, because chown clears file capabilities,
# and nothing touches it afterwards.
# scripts/check-image-isolation.sh checks the same on a built image.
install_line='install -o root -g lattice -m 0750 /tmp/lattice-server /usr/local/bin/lattice-server'
setcap_line='setcap cap_setuid,cap_setgid,cap_kill+ep /usr/local/bin/lattice-server'
install_at="$(grep -nF "$install_line" "$dockerfile" | head -n 1 | cut -d: -f1)"
setcap_at="$(grep -nF "$setcap_line" "$dockerfile" | head -n 1 | cut -d: -f1)"
if [ -z "$setcap_at" ]; then
  echo "Dockerfile must set cap_setuid,cap_setgid,cap_kill+ep on /usr/local/bin/lattice-server (design 30)." >&2
  exit 1
fi
if [ -z "$install_at" ] || [ "$install_at" -ge "$setcap_at" ]; then
  echo "Dockerfile must install the server binary with '$install_line' before setcap: a plugin uid must not be able to exec a binary that carries file capabilities." >&2
  exit 1
fi
if grep -nE "(chmod|chown|install|COPY|ADD)[^#]*/usr/local/bin/lattice-server" "$dockerfile" | grep -vF "$install_line" | grep -q .; then
  echo "Dockerfile must not copy, chmod or chown /usr/local/bin/lattice-server except through '$install_line'." >&2
  exit 1
fi
if grep -Eq "setcap [^ ]*(\+[a-z]*i|=[a-z]*i)" "$dockerfile"; then
  echo "Dockerfile must not grant the server inheritable capabilities: a plugin child could inherit them." >&2
  exit 1
fi
# The entrypoint decides on the content of the data directory, not on its
# top-level owner, so a file a plugin uid owns inside it is chowned back.
if ! grep -Fq 'if [ -n "$(su-exec lattice find "$data_dir/" \( ! -user lattice -o ! -group lattice \) -print -quit 2>/dev/null)" ]; then' "$entrypoint"; then
  echo "$entrypoint must chown the data directory when anything in it is not owned by lattice:lattice (design 30)." >&2
  exit 1
fi

sh -n "$entrypoint"
