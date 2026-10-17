#!/usr/bin/env sh
# Design 30: checks a built lattice-server image for what the plugin uid
# boundary rests on, on a real kernel. scripts/check-docker-defaults.sh checks
# the Dockerfile text; this checks what the build produced.
#
#   sh scripts/check-image-isolation.sh IMAGE
#
# Needs docker, and network access for one throwaway container that adds
# libcap-utils to list file capabilities. It creates and removes its own
# named volumes.
set -eu

image="${1:?usage: check-image-isolation.sh IMAGE}"
bin=/usr/local/bin/lattice-server
# A uid from a plugin range with the same gid and no supplementary groups,
# which is what a dropped plugin child is.
plugin=200007:200007
s2_caps="--cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add KILL"
failures=0
volume_prefix="lattice-image-check-$$-"

pass() { echo "ok: $*"; }
fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}
cleanup() {
  docker volume ls -q --filter "name=$volume_prefix" | while read -r v; do
    docker volume rm -f "$v" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

# 1. The capped binary is 0750 root:lattice.
got="$(docker run --rm --entrypoint stat "$image" -c '%a %U:%G' "$bin")"
if [ "$got" = "750 root:lattice" ]; then
  pass "$bin is $got"
else
  fail "$bin is $got, want 750 root:lattice"
fi

# 2. A plugin identity cannot exec it, so it cannot pick up the file
# capabilities that land on whoever execs it.
rc="$(docker run --rm --user "$plugin" --entrypoint sh "$image" -c "$bin -version >/dev/null 2>&1; echo \$?")"
if [ "$rc" = 126 ]; then
  pass "uid $plugin is refused exec of $bin"
else
  fail "uid $plugin exec of $bin exited $rc, want 126 (permission denied)"
fi

# 3. The server's own identity still execs it, through the real entrypoint.
if out="$(docker run --rm "$image" "$bin" -version 2>&1)"; then
  pass "the entrypoint starts the server as lattice: $out"
else
  fail "the entrypoint could not start the server: $out"
fi

# 4. No setuid or setgid file anywhere in the image: one would hand a plugin
# a way back to a privileged uid inside the bounding set the drop keeps.
suid="$(docker run --rm --entrypoint find "$image" / -xdev -type f '(' -perm -4000 -o -perm -2000 ')' -print)"
if [ -z "$suid" ]; then
  pass "no setuid or setgid file"
else
  fail "setuid or setgid files in the image: $suid"
fi

# 5. The only file capabilities in the image are the server's three.
caps="$(docker run --rm --entrypoint sh "$image" -c 'apk add --no-cache -q libcap-utils >/dev/null && find / -xdev -type f -exec getcap {} + 2>/dev/null')"
want="$bin cap_kill,cap_setgid,cap_setuid=ep"
if [ "$caps" = "$want" ]; then
  pass "file capabilities: $caps"
else
  fail "file capabilities are [$caps], want [$want]"
fi

# 6. The entrypoint repairs the data tree by its content, not by the owner of
# its top directory, and a tree lattice owns throughout boots without
# CAP_CHOWN under S2's capability set.
ids="$(docker run --rm --entrypoint sh "$image" -c 'echo "$(id -u lattice):$(id -g lattice)"')"
fresh_volume() {
  v="$volume_prefix$1"
  docker volume create "$v" >/dev/null
  docker run --rm -v "$v:/d" --entrypoint sh "$image" -c "$2" >/dev/null
  echo "$v"
}
owner_of() {
  docker run --rm -v "$1:/var/lib/lattice" --entrypoint stat "$image" -c '%u:%g' "/var/lib/lattice/$2"
}
lattice_tree='chown lattice:lattice /d && mkdir /d/plugin-bundles && touch /d/state.json /d/master.key /d/plugin-bundles/bundle && chown -R lattice:lattice /d && chmod 0700 /d/plugin-bundles && chmod 0600 /d/master.key'

v="$(fresh_volume inner "$lattice_tree && chown 200007:200007 /d/master.key && chown 0:0 /d/plugin-bundles/bundle")"
docker run --rm -v "$v:/var/lib/lattice" "$image" true || fail "boot over a data tree with foreign files failed"
key="$(owner_of "$v" master.key)"
bundle="$(owner_of "$v" plugin-bundles/bundle)"
if [ "$key" = "$ids" ] && [ "$bundle" = "$ids" ]; then
  pass "files owned by a plugin uid and by root inside a lattice-owned data directory are chowned back"
else
  fail "after boot master.key is $key and plugin-bundles/bundle is $bundle, want $ids"
fi

v="$(fresh_volume fresh 'chown 0:0 /d && chmod 0700 /d')"
docker run --rm -v "$v:/var/lib/lattice" "$image" true || fail "boot over a fresh root-owned data directory failed"
top="$(owner_of "$v" .)"
if [ "$top" = "$ids" ]; then
  pass "a fresh root-owned 0700 data directory is chowned"
else
  fail "a fresh root-owned data directory is $top after boot, want $ids"
fi

v="$(fresh_volume clean "$lattice_tree")"
# shellcheck disable=SC2086
if docker run --rm $s2_caps -v "$v:/var/lib/lattice" "$image" true; then
  pass "a data tree lattice owns throughout boots without CAP_CHOWN"
else
  fail "a clean data tree did not boot under cap_drop ALL with SETUID, SETGID and KILL"
fi

v="$(fresh_volume s2foreign "$lattice_tree && chown 0:0 /d/master.key")"
# shellcheck disable=SC2086
if docker run --rm $s2_caps -v "$v:/var/lib/lattice" "$image" true 2>/dev/null; then
  fail "a data tree with a root-owned master.key booted without CAP_CHOWN, so the entrypoint did not see it"
else
  pass "without CAP_CHOWN, a data tree that needs repair stops the boot"
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures image check(s) failed" >&2
  exit 1
fi
echo "image isolation checks passed"
