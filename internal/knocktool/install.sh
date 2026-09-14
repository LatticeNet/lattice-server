#!/bin/sh
# Install lattice-knock, the UDP port-knock client for Lattice SSH Guard.
#
# From GitHub:
#   curl -fsSL https://raw.githubusercontent.com/LatticeNet/lattice-knock/v0.1.0-alpha.1/install.sh | sh
# From a Lattice control plane, for networks that cannot reach GitHub:
#   curl -fsSL https://lattice.example.com/tools/knock/install.sh | sh
# Through a GitHub mirror:
#   curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/LatticeNet/lattice-knock/v0.1.0-alpha.1/install.sh \
#     | sh -s -- --github-mirror https://ghfast.top/ --sha256 <hash>
#
# What the checks are worth: SHA256SUMS comes from the same place as the script
# it describes, so on its own it catches corruption in transit, not a source
# that lies. --sha256 is the check that holds against a bad mirror: give it the
# value the Lattice console shows, which reaches you behind your login. A
# control plane's own install.sh already carries its sha256.
set -eu

KNOCK_RELEASE="v0.1.0-alpha.1"
MARKER="lattice-knock"

repo="${KNOCK_REPO:-LatticeNet/lattice-knock}"
version="${KNOCK_VERSION:-$KNOCK_RELEASE}"
server="${KNOCK_SERVER:-}"
mirror="${KNOCK_GITHUB_MIRROR:-}"
pin="${KNOCK_SHA256:-}"
dir="${KNOCK_INSTALL_DIR:-${HOME:?HOME is not set}/.local/bin}"
name="${KNOCK_NAME:-knock}"
force=0
action=install

die() { printf 'lattice-knock: %s\n' "$1" >&2; exit 1; }
log() { printf '  %s\n' "$*"; }
warn() { printf '  warning: %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat <<EOF
Install lattice-knock ($KNOCK_RELEASE).

  install.sh [--server URL | --github-mirror PREFIX] [--version TAG]
             [--sha256 HASH] [--dir DIR] [--name NAME] [--force]
  install.sh --uninstall [--dir DIR] [--name NAME]

  --server URL           download from a Lattice control plane (URL/tools/knock/)
  --github-mirror PREFIX download GitHub release assets through a prefix mirror,
                         for example https://ghfast.top/
  --version TAG          GitHub release to install (default $KNOCK_RELEASE)
  --sha256 HASH          require this sha256 for the knock script; the check that
                         holds against a mirror or server serving wrong bytes
  --dir DIR              install directory (default \$HOME/.local/bin)
  --name NAME            installed command name (default knock)
  --force                replace an existing file at DIR/NAME that is not lattice-knock
  --uninstall            remove DIR/NAME if it is lattice-knock

SHA256SUMS from the same source only catches corruption in transit.
Each option can also come from the environment: KNOCK_SERVER, KNOCK_GITHUB_MIRROR,
KNOCK_VERSION, KNOCK_SHA256, KNOCK_INSTALL_DIR, KNOCK_NAME.
EOF
}

need_value() {
  if [ $# -lt 2 ] || [ -z "$2" ]; then
    die "$1 needs a value"
  fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --server) need_value "$@"; server="$2"; shift 2 ;;
    --server=*) server="${1#*=}"; shift ;;
    --github-mirror) need_value "$@"; mirror="$2"; shift 2 ;;
    --github-mirror=*) mirror="${1#*=}"; shift ;;
    --version) need_value "$@"; version="$2"; shift 2 ;;
    --version=*) version="${1#*=}"; shift ;;
    --sha256) need_value "$@"; pin="$2"; shift 2 ;;
    --sha256=*) pin="${1#*=}"; shift ;;
    --dir) need_value "$@"; dir="$2"; shift 2 ;;
    --dir=*) dir="${1#*=}"; shift ;;
    --name) need_value "$@"; name="$2"; shift 2 ;;
    --name=*) name="${1#*=}"; shift ;;
    --force) force=1; shift ;;
    --uninstall) action=uninstall; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

case "$name" in ''|*/*|.|..|.*) die "--name must be a plain file name" ;; esac
target="$dir/$name"

# The installed script carries this line; a file without it is somebody else's.
is_ours() {
  [ -f "$1" ] && grep -q "^# $MARKER:" "$1" 2>/dev/null
}

if [ "$action" = uninstall ]; then
  if [ ! -e "$target" ] && [ ! -L "$target" ]; then
    log "nothing installed at $target"
    exit 0
  fi
  if [ -L "$target" ] || ! is_ours "$target"; then
    die "$target is not lattice-knock; leaving it alone"
  fi
  rm -f "$target"
  log "removed $target"
  exit 0
fi

have bash || die "lattice-knock needs bash, which is not installed"

if [ -n "$pin" ]; then
  pin=$(printf '%s' "$pin" | tr 'A-F' 'a-f')
  case "$pin" in
    *[!0-9a-f]*) die "--sha256 must be 64 hex characters" ;;
  esac
  [ "${#pin}" -eq 64 ] || die "--sha256 must be 64 hex characters"
fi

# Plain http is refused except for a loopback test server with
# KNOCK_ALLOW_HTTP=1, which the test suite sets.
allow_http=0
check_url() {
  case "$1" in
    https://*) ;;
    http://127.0.0.1:*|http://127.0.0.1/*|http://localhost:*|http://localhost/*)
      [ "${KNOCK_ALLOW_HTTP:-}" = 1 ] || die "refusing plain http: $1"
      allow_http=1 ;;
    *) die "refusing a URL that is not https: $1" ;;
  esac
}

if [ -n "$server" ]; then
  server="${server%/}"
  check_url "$server/"
  base="$server/tools/knock"
  from="the control plane at $server"
else
  if [ -n "$mirror" ]; then
    case "$mirror" in */) ;; *) mirror="$mirror/" ;; esac
    check_url "$mirror"
  fi
  case "$version" in ''|*[!A-Za-z0-9._-]*) die "--version must be a release tag" ;; esac
  base="${mirror}https://github.com/$repo/releases/download/$version"
  from="GitHub release $version${mirror:+ through $mirror}"
fi

if have curl; then
  dl() {
    if [ "$allow_http" -eq 1 ]; then
      curl -fsSL --retry 2 --connect-timeout 15 "$1" -o "$2"
    else
      # --proto-redir as well: --proto alone still lets a redirect drop to http.
      curl -fsSL --retry 2 --connect-timeout 15 --proto '=https' --proto-redir '=https' --tlsv1.2 "$1" -o "$2"
    fi
  }
elif have wget; then
  # wget cannot refuse an http redirect, so without --sha256 the bytes are
  # only as good as every hop; that is said below.
  via_wget=1
  dl() {
    if [ "$allow_http" -eq 1 ]; then
      wget -q -O "$2" "$1"
    else
      wget -q --https-only -O "$2" "$1"
    fi
  }
else
  die "need curl or wget to download"
fi

if have sha256sum; then
  sha256_of() { sha256sum "$1" | awk '{ print $1 }'; }
elif have shasum; then
  sha256_of() { shasum -a 256 "$1" | awk '{ print $1 }'; }
elif have sha256; then
  sha256_of() { sha256 -q "$1"; }
else
  die "need sha256sum, shasum or sha256 to verify the download"
fi

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t lattice-knock)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' INT TERM

log "downloading knock from $from"
dl "$base/knock" "$tmp/knock" || die "download failed: $base/knock"
dl "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "download failed: $base/SHA256SUMS; refusing to install unverified bytes"

want=$(awk '$2 == "knock" || $2 == "*knock" { print $1; exit }' "$tmp/SHA256SUMS")
[ -n "$want" ] || die "SHA256SUMS has no entry for knock"
got=$(sha256_of "$tmp/knock")
[ "$got" = "$want" ] || die "checksum mismatch: SHA256SUMS says $want, the download is $got"
if [ -n "$pin" ]; then
  [ "$got" = "$pin" ] || die "checksum mismatch: --sha256 says $pin, the download is $got"
  log "sha256 $got matches --sha256"
else
  log "sha256 $got matches SHA256SUMS from the same source"
  if [ -n "$mirror" ] || [ -n "$server" ] || [ "${via_wget:-0}" = 1 ]; then
    warn "no --sha256 given. SHA256SUMS came from $from, the same place as"
    warn "the script, so it proves the download is intact, not that the source is honest."
    warn "Compare $got with the value in the Lattice console."
  fi
fi
is_ours "$tmp/knock" || die "the download is not the lattice-knock script"

mkdir -p "$dir" || die "cannot create $dir"
if { [ -e "$target" ] || [ -L "$target" ]; } && { [ -L "$target" ] || ! is_ours "$target"; } && [ "$force" -ne 1 ]; then
  die "$target exists and is not lattice-knock; use --name to install beside it, or --force to replace it"
fi
# Written beside the target and renamed over it: rename replaces the directory
# entry, where cp or install would follow a symlink planted at the target.
staged="$dir/.$name.$$.new"
cp "$tmp/knock" "$staged" || die "cannot write in $dir"
chmod 0755 "$staged"
mv -f "$staged" "$target" || { rm -f "$staged"; die "cannot install $target"; }
log "installed $target ($("$target" --version 2>/dev/null || echo 'version unknown'))"

case ":${PATH:-}:" in
  *":$dir:"*) ;;
  *) log "note: $dir is not on PATH; for example: export PATH=\"$dir:\$PATH\"" ;;
esac
first=$(command -v "$name" 2>/dev/null || true)
if [ -n "$first" ] && [ "$first" != "$target" ]; then
  log "note: $first comes first on PATH and runs instead of $target"
fi
