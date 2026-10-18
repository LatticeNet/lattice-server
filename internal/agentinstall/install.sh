#!/bin/sh
# Lattice node-agent installer.
#
# Cross-platform (Linux systemd/openrc, macOS launchd, FreeBSD best-effort).
# Everything lives under /opt/lattice (binary, env file, state); nothing is
# scattered into system paths. Idempotent: a re-run upgrades in place. Supports
# `--uninstall`. The enrollment token is kept OUT of the process argv (it is read
# from the 0600 env file / launchd plist), so it never shows up in `ps`.
set -eu

LATTICE_HOME="${LATTICE_HOME:-/opt/lattice}"
repo="${LATTICE_AGENT_REPO:-LatticeNet/lattice-node-agent}"
version="${LATTICE_AGENT_VERSION:-latest}"
server="${LATTICE_SERVER:-}"
node_id="${LATTICE_NODE_ID:-}"
token="${LATTICE_NODE_TOKEN:-}"
bin_path="${LATTICE_AGENT_BIN:-$LATTICE_HOME/lattice-agent}"
env_path="${LATTICE_AGENT_ENV:-$LATTICE_HOME/lattice-agent.env}"
state_dir="${LATTICE_AGENT_STATE:-$LATTICE_HOME/state}"
linechain_txn_dir="${LATTICE_LINECHAIN_TXN_DIR:-$state_dir/linechain-txn}"
service_name="${LATTICE_AGENT_SERVICE:-lattice-agent}"
run_user="${LATTICE_AGENT_RUN_USER:-}"
run_group="${LATTICE_AGENT_RUN_GROUP:-}"
create_run_user="${LATTICE_AGENT_CREATE_USER:-1}"
action="install"
input_node_id="$node_id"

for a in "$@"; do
  case "$a" in
    --uninstall) action="uninstall" ;;
    --help|-h)
      echo "Usage: install.sh [--uninstall]"
      echo "Env: LATTICE_SERVER, LATTICE_NODE_ID, LATTICE_NODE_TOKEN (required for install)"
      echo "     LATTICE_HOME (default /opt/lattice), LATTICE_AGENT_VERSION (default latest)"
      echo "     LATTICE_AGENT_RUN_USER / LATTICE_AGENT_RUN_GROUP for optional non-root systemd service"
      echo "     LATTICE_AGENT_SOURCES (\"m=<mirror base> r=<release base> ...\", tried in order)"
      echo "     LATTICE_AGENT_SHA256 (\"os/arch=<sha256> ...\"; mirrors are used only with it)"
      exit 0 ;;
  esac
done
[ "${LATTICE_AGENT_UNINSTALL:-}" = "1" ] && action="uninstall"

log()  { echo "  ▸ $*"; }
ok()   { echo "  ✓ $*"; }
die()  { echo "lattice-agent: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---- OS / arch detection (borrows nezha's broad matching) -------------------
case "$(uname -s)" in
  Linux)   os="linux" ;;
  Darwin)  os="darwin" ;;
  FreeBSD) os="freebsd" ;;
  *) die "unsupported OS: $(uname -s) (supported: Linux, Darwin, FreeBSD)" ;;
esac
case "$(uname -m)" in
  x86_64|amd64)            arch="amd64" ;;
  aarch64|arm64)           arch="arm64" ;;
  armv7l|armv7|armv6l|arm) arch="arm" ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

unit_path="${LATTICE_AGENT_UNIT:-/etc/systemd/system/${service_name}.service}"
openrc_path="/etc/init.d/${service_name}"
plist_label="net.lattice.agent"
plist_path="${LATTICE_AGENT_PLIST:-/Library/LaunchDaemons/${plist_label}.plist}"

# ---- root: friendly check + sudo elevation (re-exec preserving config) ------
if [ "$(id -u)" -ne 0 ]; then
  echo "lattice-agent installer needs root to write $LATTICE_HOME and register a boot service."
  if have sudo; then
    log "re-running with sudo ..."
    exec sudo \
      LATTICE_HOME="$LATTICE_HOME" LATTICE_AGENT_REPO="$repo" LATTICE_AGENT_VERSION="$version" \
      LATTICE_AGENT_SOURCES="${LATTICE_AGENT_SOURCES:-}" LATTICE_AGENT_SHA256="${LATTICE_AGENT_SHA256:-}" \
      LATTICE_SERVER="$server" LATTICE_NODE_ID="$node_id" LATTICE_NODE_TOKEN="$token" \
      LATTICE_AGENT_BIN="$bin_path" LATTICE_AGENT_ENV="$env_path" LATTICE_AGENT_STATE="$state_dir" \
      LATTICE_AGENT_SERVICE="$service_name" \
      LATTICE_AGENT_RUN_USER="${LATTICE_AGENT_RUN_USER:-}" \
      LATTICE_AGENT_RUN_GROUP="${LATTICE_AGENT_RUN_GROUP:-}" \
      LATTICE_AGENT_CREATE_USER="${LATTICE_AGENT_CREATE_USER:-}" \
      LATTICE_AGENT_ALLOW_EXEC="${LATTICE_AGENT_ALLOW_EXEC:-}" \
      LATTICE_AGENT_ALLOW_ROOT_EXEC="${LATTICE_AGENT_ALLOW_ROOT_EXEC:-}" \
      LATTICE_NO_EXEC="${LATTICE_NO_EXEC:-}" \
      LATTICE_NO_BEACON="${LATTICE_NO_BEACON:-}" \
      LATTICE_NO_PREFETCH="${LATTICE_NO_PREFETCH:-}" \
      LATTICE_TASK_CGROUP_ROOT="${LATTICE_TASK_CGROUP_ROOT:-}" \
      LATTICE_TASK_CGROUP_MEMORY_MAX="${LATTICE_TASK_CGROUP_MEMORY_MAX:-}" \
      LATTICE_TASK_CGROUP_PIDS_MAX="${LATTICE_TASK_CGROUP_PIDS_MAX:-}" \
      LATTICE_TASK_CGROUP_CPU_MAX="${LATTICE_TASK_CGROUP_CPU_MAX:-}" \
      LATTICE_TASK_WORK_ROOT="${LATTICE_TASK_WORK_ROOT:-}" \
      LATTICE_TASK_OUTBOX_DIR="${LATTICE_TASK_OUTBOX_DIR:-}" \
      LATTICE_LINECHAIN_TXN_DIR="$linechain_txn_dir" \
      LATTICE_AGENT_ALLOW_TERMINAL="${LATTICE_AGENT_ALLOW_TERMINAL:-}" \
      LATTICE_TERMINAL_TRANSPORT="${LATTICE_TERMINAL_TRANSPORT:-}" \
      LATTICE_IP_MODE="${LATTICE_IP_MODE:-}" LATTICE_IP_RESOLVERS="${LATTICE_IP_RESOLVERS:-}" \
      LATTICE_IP_SCRIPT="${LATTICE_IP_SCRIPT:-}" LATTICE_PUBLIC_IP="${LATTICE_PUBLIC_IP:-}" \
      LATTICE_PUBLIC_IP6="${LATTICE_PUBLIC_IP6:-}" LATTICE_AGENT_UNINSTALL="${LATTICE_AGENT_UNINSTALL:-}" \
      LATTICE_SSH_ALERTS="${LATTICE_SSH_ALERTS:-}" \
      LATTICE_SINGBOX_DISCOVER="${LATTICE_SINGBOX_DISCOVER:-}" LATTICE_SINGBOX_BIN="${LATTICE_SINGBOX_BIN:-}" \
      LATTICE_PROXY_USAGE_FILE="${LATTICE_PROXY_USAGE_FILE:-}" LATTICE_PROXY_USAGE_URL="${LATTICE_PROXY_USAGE_URL:-}" \
      LATTICE_PROXY_USAGE_XRAY_API="${LATTICE_PROXY_USAGE_XRAY_API:-}" LATTICE_PROXY_USAGE_XRAY_BIN="${LATTICE_PROXY_USAGE_XRAY_BIN:-}" \
      LATTICE_PROXY_USAGE_XRAY_PATTERN="${LATTICE_PROXY_USAGE_XRAY_PATTERN:-}" \
      sh "$0" "$@"
  fi
  die "please re-run as root (e.g. sudo sh $0)"
fi

# ---- existing install adoption ---------------------------------------------
# New installs use:
#   binary:  /opt/lattice/lattice-agent
#   env:     /opt/lattice/lattice-agent.env
#   service: lattice-agent.service
#
# Older beta nodes used:
#   binary:  /opt/lattice/node-agent/lattice-agent
#   env:     /opt/lattice/node-agent/agent.env
#   service: lattice-node-agent.service
#
# Earlier manual docs also showed /etc/lattice/agent.env. Adopt it when present
# so those nodes can migrate into the current /opt/lattice layout without losing
# their token during an installer re-run.
#
# Re-running the installer must upgrade the service that is already installed
# instead of creating a second agent for the same machine. Explicit env values
# (LATTICE_AGENT_BIN, LATTICE_AGENT_ENV, LATTICE_AGENT_SERVICE, etc.) still win.
read_env_value() {
  key="$1"
  file="$2"
  (
    set -a
    # shellcheck disable=SC1090
    . "$file"
    set +a
    eval "printf '%s' \"\${$key:-}\""
  ) 2>/dev/null || true
}

detect_systemd_install() {
  [ "$os" = "linux" ] || return 0
  have systemctl || return 0
  [ -d /run/systemd/system ] || return 0
  [ -z "${LATTICE_AGENT_SERVICE:-}" ] || return 0

  for candidate in lattice-agent lattice-node-agent; do
    unit="/etc/systemd/system/${candidate}.service"
    [ -f "$unit" ] || continue
    detected_bin="$(sed -n 's/^ExecStart=//p' "$unit" | sed -n '1p' | awk '{print $1}')"
    case "$detected_bin" in
      */lattice-agent) ;;
      *) continue ;;
    esac
    service_name="$candidate"
    [ -n "${LATTICE_AGENT_BIN:-}" ] || bin_path="$detected_bin"
    if [ -z "${LATTICE_AGENT_ENV:-}" ]; then
      detected_env="$(sed -n 's/^EnvironmentFile=-\{0,1\}//p' "$unit" | sed -n '1p' | awk '{print $1}')"
      [ -n "$detected_env" ] && env_path="$detected_env"
    fi
    if [ -z "${LATTICE_AGENT_STATE:-}" ] && [ "$env_path" = "/opt/lattice/node-agent/agent.env" ]; then
      state_dir="/opt/lattice/node-agent/state"
    fi
    if [ -z "${LATTICE_AGENT_RUN_USER:-}" ]; then
      detected_user="$(sed -n 's/^User=//p' "$unit" | sed -n '1p')"
      [ -n "$detected_user" ] && run_user="$detected_user"
    fi
    if [ -z "${LATTICE_AGENT_RUN_GROUP:-}" ]; then
      detected_group="$(sed -n 's/^Group=//p' "$unit" | sed -n '1p')"
      [ -n "$detected_group" ] && run_group="$detected_group"
    fi
    log "adopting existing service ${service_name}.service"
    log "effective binary -> $bin_path"
    log "effective env -> $env_path"
    return 0
  done
}

load_existing_config() {
  existing_env=""
  for candidate in "$env_path" "$LATTICE_HOME/lattice-agent.env" "/opt/lattice/node-agent/agent.env" "/etc/lattice/agent.env"; do
    [ -f "$candidate" ] || continue
    existing_env="$candidate"
    break
  done
  [ -n "$existing_env" ] || return 0

  existing_server="$(read_env_value LATTICE_SERVER "$existing_env")"
  existing_node_id="$(read_env_value LATTICE_NODE_ID "$existing_env")"
  existing_token="$(read_env_value LATTICE_NODE_TOKEN "$existing_env")"
  log "loading existing credentials/config -> $existing_env"

  [ -n "$server" ] || server="$existing_server"
  [ -n "$node_id" ] || node_id="$existing_node_id"
  if [ -n "$input_node_id" ] && [ -n "$existing_node_id" ] && [ "$input_node_id" != "$existing_node_id" ] && [ -n "$existing_token" ]; then
    if [ -z "$token" ] || [ "$token" = "$existing_token" ]; then
      die "existing token belongs to node $existing_node_id but this command targets $input_node_id; use the correct node reconfigure command or provide a matching LATTICE_NODE_TOKEN"
    fi
  fi
  if [ -z "$token" ] && [ -n "$existing_token" ]; then
    token="$existing_token"
  fi

  for key in \
    LATTICE_AGENT_RUN_USER LATTICE_AGENT_RUN_GROUP LATTICE_AGENT_CREATE_USER \
    LATTICE_AGENT_ALLOW_EXEC LATTICE_AGENT_ALLOW_ROOT_EXEC LATTICE_NO_EXEC LATTICE_NO_BEACON LATTICE_NO_PREFETCH \
    LATTICE_TASK_CGROUP_ROOT LATTICE_TASK_CGROUP_MEMORY_MAX \
    LATTICE_TASK_CGROUP_PIDS_MAX LATTICE_TASK_CGROUP_CPU_MAX \
    LATTICE_TASK_WORK_ROOT LATTICE_TASK_OUTBOX_DIR LATTICE_LINECHAIN_TXN_DIR \
    LATTICE_AGENT_ALLOW_TERMINAL LATTICE_TERMINAL_TRANSPORT LATTICE_IP_MODE \
    LATTICE_IP_RESOLVERS LATTICE_IP_SCRIPT LATTICE_PUBLIC_IP LATTICE_PUBLIC_IP6 \
    LATTICE_SSH_ALERTS LATTICE_SINGBOX_DISCOVER LATTICE_SINGBOX_BIN \
    LATTICE_PROXY_USAGE_FILE LATTICE_PROXY_USAGE_URL LATTICE_PROXY_USAGE_XRAY_API \
    LATTICE_PROXY_USAGE_XRAY_BIN LATTICE_PROXY_USAGE_XRAY_PATTERN
  do
    eval "current=\${$key:-}"
    [ -z "$current" ] || continue
    existing_value="$(read_env_value "$key" "$existing_env")"
    [ -n "$existing_value" ] || continue
    export "$key=$existing_value"
  done
}

detect_systemd_install
unit_path="${LATTICE_AGENT_UNIT:-/etc/systemd/system/${service_name}.service}"
openrc_path="/etc/init.d/${service_name}"
load_existing_config
run_user="${LATTICE_AGENT_RUN_USER:-$run_user}"
run_group="${LATTICE_AGENT_RUN_GROUP:-$run_group}"
create_run_user="${LATTICE_AGENT_CREATE_USER:-$create_run_user}"

validate_account_name() {
  name="$1"
  label="$2"
  case "$name" in
    ""|-*|*[!A-Za-z0-9_.-]*) die "$label contains unsupported characters: $name" ;;
  esac
}

group_exists() {
  if have getent; then getent group "$1" >/dev/null 2>&1; return $?; fi
  [ -r /etc/group ] || return 1
  while IFS=: read -r name _; do
    [ "$name" = "$1" ] && return 0
  done </etc/group
  return 1
}

create_group_if_needed() {
  group="$1"
  group_exists "$group" && return 0
  [ "$create_run_user" != "0" ] || die "group $group does not exist; create it or unset LATTICE_AGENT_CREATE_USER=0"
  if have groupadd; then
    groupadd --system "$group" 2>/dev/null || groupadd "$group"
  elif have addgroup; then
    addgroup -S "$group" 2>/dev/null || addgroup "$group"
  else
    die "cannot create group $group (missing groupadd/addgroup)"
  fi
}

create_user_if_needed() {
  user="$1"
  group="$2"
  if id -u "$user" >/dev/null 2>&1; then
    return 0
  fi
  [ "$create_run_user" != "0" ] || die "user $user does not exist; create it or unset LATTICE_AGENT_CREATE_USER=0"
  shell="/usr/sbin/nologin"
  [ -x "$shell" ] || shell="/sbin/nologin"
  [ -x "$shell" ] || shell="/bin/false"
  if have useradd; then
    useradd --system --no-create-home --home-dir "$LATTICE_HOME" --shell "$shell" --gid "$group" "$user" 2>/dev/null || \
      useradd -r -M -d "$LATTICE_HOME" -s "$shell" -g "$group" "$user"
  elif have adduser; then
    adduser -S -D -H -h "$LATTICE_HOME" -s "$shell" -G "$group" "$user" 2>/dev/null || \
      adduser --system --no-create-home --home "$LATTICE_HOME" --shell "$shell" --ingroup "$group" "$user"
  else
    die "cannot create user $user (missing useradd/adduser)"
  fi
}

prepare_service_identity() {
  [ -n "$run_user" ] || return 0
  [ "$os" = "linux" ] || die "LATTICE_AGENT_RUN_USER is supported only on Linux systemd installs"
  validate_account_name "$run_user" "LATTICE_AGENT_RUN_USER"
  if id -u "$run_user" >/dev/null 2>&1; then
    if [ -z "$run_group" ]; then
      run_group="$(id -gn "$run_user" 2>/dev/null || true)"
    fi
    [ -n "$run_group" ] || die "cannot resolve primary group for $run_user"
    validate_account_name "$run_group" "LATTICE_AGENT_RUN_GROUP"
    group_exists "$run_group" || die "group $run_group does not exist"
    return 0
  fi
  [ -n "$run_group" ] || run_group="$run_user"
  validate_account_name "$run_group" "LATTICE_AGENT_RUN_GROUP"
  create_group_if_needed "$run_group"
  create_user_if_needed "$run_user" "$run_group"
}

apply_service_identity_permissions() {
  [ -n "$run_user" ] || return 0
  chgrp "$run_group" "$LATTICE_HOME" || die "cannot set $LATTICE_HOME group to $run_group"
  chmod 0750 "$LATTICE_HOME" 2>/dev/null || true
  chown "$run_user:$run_group" "$state_dir" || die "cannot assign $state_dir to $run_user:$run_group"
  chmod 0750 "$state_dir" 2>/dev/null || true
  if [ -n "${LATTICE_TASK_WORK_ROOT:-}" ]; then
    chown "$run_user:$run_group" "$LATTICE_TASK_WORK_ROOT" || die "cannot assign $LATTICE_TASK_WORK_ROOT to $run_user:$run_group"
    chmod 0700 "$LATTICE_TASK_WORK_ROOT" 2>/dev/null || true
  fi
  if [ -n "${task_outbox_leaf:-}" ]; then
    chown "$run_user:$run_group" "$task_outbox_leaf" || die "cannot assign $task_outbox_leaf to $run_user:$run_group"
    chmod 0700 "$task_outbox_leaf" 2>/dev/null || true
  fi
  chown "$run_user:$run_group" "$linechain_txn_dir" || die "cannot assign $linechain_txn_dir to $run_user:$run_group"
  chmod 0700 "$linechain_txn_dir" 2>/dev/null || true
}

prepare_linechain_txn_dir() {
  case "$linechain_txn_dir" in
    /|/bin|/boot|/dev|/etc|/lib|/lib32|/lib64|/proc|/root|/sbin|/sys|/usr|/var)
      die "LATTICE_LINECHAIN_TXN_DIR must not be a filesystem or system root: $linechain_txn_dir" ;;
    /*) ;;
    *) die "LATTICE_LINECHAIN_TXN_DIR must be an absolute path" ;;
  esac
  [ ! -L "$linechain_txn_dir" ] || die "LATTICE_LINECHAIN_TXN_DIR must not be a symlink: $linechain_txn_dir"
  if [ -e "$linechain_txn_dir" ] && [ ! -d "$linechain_txn_dir" ]; then
    die "LATTICE_LINECHAIN_TXN_DIR must be a directory: $linechain_txn_dir"
  fi
  mkdir -p "$linechain_txn_dir" || die "cannot create LATTICE_LINECHAIN_TXN_DIR=$linechain_txn_dir"
  chmod 0700 "$linechain_txn_dir" 2>/dev/null || true
}

prepare_task_work_root() {
  [ -n "${LATTICE_TASK_WORK_ROOT:-}" ] || return 0
  case "$LATTICE_TASK_WORK_ROOT" in
    /*) ;;
    *) die "LATTICE_TASK_WORK_ROOT must be an absolute path" ;;
  esac
  mkdir -p "$LATTICE_TASK_WORK_ROOT" || die "cannot create LATTICE_TASK_WORK_ROOT=$LATTICE_TASK_WORK_ROOT"
  chmod 0700 "$LATTICE_TASK_WORK_ROOT" 2>/dev/null || true
}

prepare_task_outbox_root() {
  task_outbox_leaf=""
  [ -n "${LATTICE_TASK_OUTBOX_DIR:-}" ] || return 0
  case "$LATTICE_TASK_OUTBOX_DIR" in
    /|/bin|/boot|/dev|/etc|/lib|/lib32|/lib64|/proc|/root|/sbin|/sys|/usr|/var)
      die "LATTICE_TASK_OUTBOX_DIR must not be a filesystem or system root: $LATTICE_TASK_OUTBOX_DIR" ;;
    /*) ;;
    *) die "LATTICE_TASK_OUTBOX_DIR must be an absolute path" ;;
  esac
  [ ! -L "$LATTICE_TASK_OUTBOX_DIR" ] || die "LATTICE_TASK_OUTBOX_DIR must not traverse symlinks: $LATTICE_TASK_OUTBOX_DIR"
  if [ -e "$LATTICE_TASK_OUTBOX_DIR" ] && [ ! -d "$LATTICE_TASK_OUTBOX_DIR" ]; then
    die "LATTICE_TASK_OUTBOX_DIR must be a directory: $LATTICE_TASK_OUTBOX_DIR"
  fi
  mkdir -p "$LATTICE_TASK_OUTBOX_DIR" || die "cannot create LATTICE_TASK_OUTBOX_DIR=$LATTICE_TASK_OUTBOX_DIR"
  current="$LATTICE_TASK_OUTBOX_DIR"
  while [ "$current" != "/" ]; do
    if [ -L "$current" ]; then
      root_owned_link="$(find "$current" -prune -user root -print 2>/dev/null || true)"
      [ "$root_owned_link" = "$current" ] || die "LATTICE_TASK_OUTBOX_DIR must not traverse a non-root-owned symlink: $current"
    fi
    current="${current%/*}"
    [ -n "$current" ] || current="/"
  done
  case "$LATTICE_TASK_OUTBOX_DIR/" in
    "$LATTICE_HOME/"*|"$state_dir/"*) ;;
    *)
      secure_base="$(find "$LATTICE_TASK_OUTBOX_DIR" -prune -user root ! -perm -022 -print 2>/dev/null || true)"
      [ "$secure_base" = "$LATTICE_TASK_OUTBOX_DIR" ] || \
        die "external LATTICE_TASK_OUTBOX_DIR must be root-owned and not group/world writable: $LATTICE_TASK_OUTBOX_DIR"
      ;;
  esac
  task_outbox_leaf="$LATTICE_TASK_OUTBOX_DIR/task-outbox"
  if [ -e "$task_outbox_leaf" ] || [ -L "$task_outbox_leaf" ]; then
    [ ! -L "$task_outbox_leaf" ] && [ -d "$task_outbox_leaf" ] || die "task outbox leaf must be a real directory: $task_outbox_leaf"
  else
    mkdir "$task_outbox_leaf" || die "cannot create task outbox leaf=$task_outbox_leaf"
  fi
  chmod 0700 "$task_outbox_leaf" || die "cannot secure task outbox leaf=$task_outbox_leaf"
}

# ---- service helpers (systemd / openrc / launchd) --------------------------
svc_kind() {
  if [ "$os" = "darwin" ]; then echo launchd; return; fi
  if have systemctl && [ -d /run/systemd/system ]; then echo systemd; return; fi
  if have rc-service && have rc-update; then echo openrc; return; fi
  echo none
}

svc_stop() {
  case "$(svc_kind)" in
    systemd) systemctl stop "$service_name" 2>/dev/null || true ;;
    openrc)  rc-service "$service_name" stop 2>/dev/null || true ;;
    launchd) launchctl bootout system "$plist_path" 2>/dev/null || launchctl unload "$plist_path" 2>/dev/null || true ;;
  esac
}

# ---- uninstall -------------------------------------------------------------
if [ "$action" = "uninstall" ]; then
  log "stopping service ..."
  svc_stop
  case "$(svc_kind)" in
    systemd) systemctl disable "$service_name" 2>/dev/null || true; rm -f "$unit_path" "/etc/systemd/system/${service_name}.service.d/10-lattice-keepalive.conf"; systemctl daemon-reload 2>/dev/null || true ;;
    openrc)  rc-update del "$service_name" 2>/dev/null || true; rm -f "$openrc_path" ;;
    launchd) rm -f "$plist_path" ;;
  esac
  rm -f "$bin_path" "$env_path"
  ok "lattice-agent uninstalled. Kept $LATTICE_HOME (incl. backups/state); remove it manually if desired."
  exit 0
fi

# ---- install: validate enrollment inputs -----------------------------------
if [ -z "$server" ] || [ -z "$node_id" ] || [ -z "$token" ]; then
  die "set LATTICE_SERVER, LATTICE_NODE_ID, and LATTICE_NODE_TOKEN (copy the enroll command from the dashboard)"
fi

# ---- install: download sources and expected digests ------------------------
# The control plane renders two optional variables into the enrollment
# command; without them the installer downloads and verifies as it always has.
#
#   LATTICE_AGENT_SHA256   "os/arch=<64 lowercase hex> ..."
#   LATTICE_AGENT_SOURCES  "m=<base> r=<base> ..."  (tried in this order)
#
# m= is a mirror holding <base>/<version>/<os>/<arch>/<sha256>, with <version>
# the tag without its leading v. r= is a release base holding
# <base>/lattice-agent-<os>-<arch> and SHA256SUMS. Without LATTICE_AGENT_SOURCES
# the one source is the GitHub release. The digest is the table's entry for
# this platform; when the table is unset or has no such entry, it comes from
# SHA256SUMS on the first r= source, as before. A mirror must never supply the
# digest it is checked against, so m= sources are used only with a rendered
# digest. Both values are checked character by character and split on spaces
# only; nothing in them is evaluated.
artifact="lattice-agent-${os}-${arch}"
platform="$os/$arch"
# Both go into the release URL, which is split on spaces with the sources, so
# a space or another character a URL path does not need would add a source.
case "$repo" in
  */*/*|/*|*/|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/-]*) die "LATTICE_AGENT_REPO must be owner/repo: $repo" ;;
  */*) ;;
  *) die "LATTICE_AGENT_REPO must be owner/repo: $repo" ;;
esac
case "$version" in
  ""|.*|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+-]*) die "LATTICE_AGENT_VERSION must be latest or a release tag: $version" ;;
esac
if [ "$version" = "latest" ]; then
  base="https://github.com/${repo}/releases/latest/download"
else
  base="https://github.com/${repo}/releases/download/${version}"
fi
split_ifs="$IFS"
expected_sha=""
if [ -n "${LATTICE_AGENT_SHA256:-}" ]; then
  sha_seen=" "
  IFS=' '
  set -f
  for entry in $LATTICE_AGENT_SHA256; do
    case "$entry" in
      *=*) ;;
      *) die "LATTICE_AGENT_SHA256 entry is not os/arch=<sha256>: $entry" ;;
    esac
    sha_key="${entry%%=*}"
    sha_value="${entry#*=}"
    case "$sha_key" in
      */*/*|/*|*/|*[!abcdefghijklmnopqrstuvwxyz0123456789/]*) sha_key="" ;;
    esac
    case "$sha_key" in
      */*) ;;
      *) die "LATTICE_AGENT_SHA256 entry has a malformed os/arch: $entry" ;;
    esac
    case "$sha_value" in
      *[!0123456789abcdef]*) die "LATTICE_AGENT_SHA256 digest must be 64 lowercase hex characters: $entry" ;;
    esac
    [ "${#sha_value}" -eq 64 ] || die "LATTICE_AGENT_SHA256 digest must be 64 lowercase hex characters: $entry"
    case "$sha_seen" in
      *" $sha_key "*) die "LATTICE_AGENT_SHA256 lists $sha_key twice" ;;
    esac
    sha_seen="$sha_seen$sha_key "
    if [ "$sha_key" = "$platform" ]; then expected_sha="$sha_value"; fi
  done
  IFS="$split_ifs"
  set +f
  if [ -z "$expected_sha" ]; then
    log "LATTICE_AGENT_SHA256 has no digest for $platform; skipping mirrors and verifying against SHA256SUMS"
  fi
fi

sources="${LATTICE_AGENT_SOURCES:-}"
sources_label="LATTICE_AGENT_SOURCES"
if [ -z "$sources" ]; then
  sources="r=$base"
  sources_label="the release URL from LATTICE_AGENT_REPO and LATTICE_AGENT_VERSION"
fi
mirror_version="${version#v}"
fetch_list=""
sums_base=""
IFS=' '
set -f
for src in $sources; do
  case "$src" in
    m=https://?*|r=https://?*) ;;
    *) die "$sources_label: a source must be m=https://<base> or r=https://<base>: $src" ;;
  esac
  src_base="${src#?=}"
  case "$src_base" in
    *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~:/+-]*)
      die "$sources_label: a base may hold only the characters A-Z a-z 0-9 . _ ~ : / + -: $src" ;;
  esac
  src_base="${src_base%/}"
  case "$src" in
    r=*)
      [ -n "$sums_base" ] || sums_base="$src_base"
      fetch_list="$fetch_list r=$src_base/$artifact"
      ;;
    *)
      if [ -z "$expected_sha" ]; then
        log "skipping mirror $src_base: a mirror is used only with a digest for $platform in LATTICE_AGENT_SHA256"
      elif [ "$version" = "latest" ]; then
        log "skipping mirror $src_base: a mirror needs an exact LATTICE_AGENT_VERSION, not latest"
      else
        case "$mirror_version" in
          ""|.*|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+-]*)
            die "LATTICE_AGENT_VERSION cannot name a mirror path: $version" ;;
        esac
        fetch_list="$fetch_list m=$src_base/$mirror_version/$os/$arch/$expected_sha"
      fi
      ;;
  esac
done
IFS="$split_ifs"
set +f
[ -n "$fetch_list" ] || die "$sources_label leaves no source to download from (every mirror was skipped, see above)"

# download tool (curl preferred, wget fallback). No total time limit, so a new
# machine on a slow line can finish; a connect timeout and a stall cutoff
# (curl: under 1 KiB/s for 60 s; wget: 60 s without data) end a dead source
# instead. Every fetch continues the file it is given, and a caller that wants
# a fresh file removes it first. A mirror (m) never follows a redirect, so it
# cannot send root on this machine to an address of its choosing; a release
# base (r) follows redirects, HTTPS only, as GitHub's release downloads need.
# A mirror is optional and the release follows it, so a mirror fetch is also
# cut after 600 s: one that trickles bytes just above the stall cutoff cannot
# hold the install, and what it delivered is kept for the next source. wget
# has no total limit of its own, so without a working timeout command the
# mirrors are skipped.
if have curl; then
  dl_tool="curl"
  fetch() {
    if [ "$1" = m ]; then
      curl -fsS --proto '=https' --tlsv1.2 --max-time 600 --connect-timeout 20 --speed-limit 1024 --speed-time 60 -C - -o "$2" "$3"
    else
      curl -fsSL --proto '=https' --tlsv1.2 --proto-redir '=https' --connect-timeout 20 --speed-limit 1024 --speed-time 60 -C - -o "$2" "$3"
    fi
  }
elif have wget; then
  dl_tool="wget"
  wget_bound=0
  if have timeout && timeout 5 true >/dev/null 2>&1; then wget_bound=1; fi
  fetch() {
    if [ "$1" = m ]; then
      timeout 600 wget --https-only -q --max-redirect=0 --connect-timeout=20 --read-timeout=60 --tries=2 -c -O "$2" "$3"
    else
      wget --https-only -q --connect-timeout=20 --read-timeout=60 --tries=2 -c -O "$2" "$3"
    fi
  }
else die "need curl or wget to download the agent"; fi
# Every fetch runs under a file-size limit of 131072 blocks, so a source that
# streams without end cannot fill the disk and the walk moves past it. That is
# 64 MiB where the shell counts 512-byte blocks (dash, busybox ash, bash 4 and
# later as sh) and 128 MiB under macOS's bash 3.2, which counts 1024; the agent
# binary is about 14 MiB. XFSZ is ignored so the overrun is a write error, not
# a core dump.
# yagni: a fixed cap; raise it if the agent binary ever nears 64 MiB.
# A shell that cannot set the cap fetches a release anyway, as before, but
# never a mirror, which is optional and the one source the cap is for.
fetch_capped() {
  ( trap '' XFSZ
    if ! ulimit -f 131072 2>/dev/null && [ "$1" = m ]; then exit 1; fi
    fetch "$@" )
}
# mirror_skip says why this machine cannot use a mirror at all, or is empty:
# a mirror is fetched only under the size cap and, with wget, under timeout.
mirror_skip=""
if ! ( ulimit -f 131072 ) 2>/dev/null; then
  mirror_skip="this shell cannot cap the download's size"
elif [ "$dl_tool" = wget ] && [ "$wget_bound" = 0 ]; then
  mirror_skip="no working timeout command to bound a wget fetch"
fi

# checksum tool (sha256sum on Linux, shasum on macOS/BSD, sha256 on FreeBSD)
if have sha256sum; then sha256_file() { sha256sum "$1" | awk '{ print $1 }'; }
elif have shasum;   then sha256_file() { shasum -a 256 "$1" | awk '{ print $1 }'; }
elif have sha256;   then sha256_file() { sha256 -q "$1"; }
else die "need sha256sum, shasum, or sha256 to verify release checksums"; fi

have install || die "missing required command: install"
kind="$(svc_kind)"
if [ -n "$run_user" ] && [ "$kind" != "systemd" ]; then
  die "LATTICE_AGENT_RUN_USER is supported only for systemd installs"
fi
prepare_service_identity

# ---- base dir under /opt/lattice -------------------------------------------
if [ ! -d "$LATTICE_HOME" ]; then
  log "creating $LATTICE_HOME ..."
  mkdir -p "$LATTICE_HOME" || die "cannot create $LATTICE_HOME (insufficient permissions?)"
fi
[ -w "$LATTICE_HOME" ] || die "$LATTICE_HOME is not writable"
mkdir -p "$state_dir"
prepare_task_work_root
prepare_task_outbox_root
prepare_linechain_txn_dir
chmod 0750 "$LATTICE_HOME" 2>/dev/null || true
apply_service_identity_permissions

# ---- download + verify + install binary ------------------------------------
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
part="$tmp_dir/$artifact"
if [ -n "$expected_sha" ]; then
  log "expected sha256 for $platform from LATTICE_AGENT_SHA256: $expected_sha"
else
  fetch_capped r "$tmp_dir/SHA256SUMS" "$sums_base/SHA256SUMS" 2>/dev/null || \
    die "SHA256SUMS not available; refusing to install without checksum manifest"
  expected_sha="$(awk -v name="$artifact" '$2 == name { print tolower($1); n++ } END { if (n != 1) exit 1 }' "$tmp_dir/SHA256SUMS")" || \
    die "SHA256SUMS has no single entry for $artifact; refusing to install"
  case "$expected_sha" in
    ""|*[!0123456789abcdef]*) die "SHA256SUMS entry for $artifact is not a sha256 digest" ;;
  esac
  [ "${#expected_sha}" -eq 64 ] || die "SHA256SUMS entry for $artifact is not a sha256 digest"
fi

# Walk the sources in order into one partial file, each fetch continuing it,
# so a source that fails keeps the progress honest sources made. A source can
# also splice wrong bytes onto honest ones, which only the finished file's
# digest shows. So a mismatch deletes the partial and starts a second round in
# which each source in order fetches a fresh file from byte zero and is
# verified on its own; the first that verifies wins. The second round also
# runs when nothing verified after a source continued another's partial: bytes
# past the real end make every later resume fail without a mismatch.
nl='
'
fetch_report=""
fetch_mismatch=0
fetch_resumed=0
fetch_ok=0
# try_source ROUND KIND=URL: 0 verified, 1 digest mismatch (file removed),
# 2 download failed (partial kept).
try_source() {
  try_kind="${2%%=*}"
  try_url="${2#?=}"
  if [ "$try_kind" = m ] && [ -n "$mirror_skip" ]; then
    log "round $1: skipping mirror $try_url: $mirror_skip"
    fetch_report="$fetch_report${nl}  round $1, $try_url: skipped ($mirror_skip)"
    return 2
  fi
  log "round $1: downloading $artifact ($version) from $try_url ..."
  if [ -s "$part" ]; then fetch_resumed=1; fi
  if fetch_capped "$try_kind" "$part" "$try_url"; then
    try_got="$(sha256_file "$part")"
    if [ "$try_got" = "$expected_sha" ]; then
      fetch_report="$fetch_report${nl}  round $1, $try_url: verified"
      return 0
    fi
    rm -f "$part"
    fetch_mismatch=1
    log "round $1: $try_url delivered a file with the wrong digest; deleted it"
    fetch_report="$fetch_report${nl}  round $1, $try_url: digest mismatch (got ${try_got:-nothing})"
    return 1
  else
    try_rc=$?
  fi
  log "round $1: $try_url failed ($dl_tool exit $try_rc)"
  fetch_report="$fetch_report${nl}  round $1, $try_url: download failed ($dl_tool exit $try_rc)"
  return 2
}
for src in $fetch_list; do
  fetch_rc=0
  try_source 1 "$src" || fetch_rc=$?
  case "$fetch_rc" in
    0) fetch_ok=1; break ;;
    1) break ;;
  esac
done
if [ "$fetch_ok" != 1 ] && { [ "$fetch_mismatch" = 1 ] || [ "$fetch_resumed" = 1 ]; }; then
  log "second round: each source again from byte zero, each verified on its own"
  for src in $fetch_list; do
    rm -f "$part"
    if try_source 2 "$src"; then fetch_ok=1; break; fi
  done
fi
if [ "$fetch_ok" != 1 ]; then
  [ "$fetch_mismatch" != 1 ] || \
    die "checksum verification failed: no source delivered $artifact with sha256 $expected_sha:$fetch_report"
  die "download failed: no source delivered $artifact:$fetch_report"
fi
ok "checksum verified (sha256 $expected_sha)"

# Upgrade in place: stop a running instance before replacing the binary.
svc_stop
install -m 0755 "$tmp_dir/$artifact" "$bin_path"
ok "installed binary -> $bin_path"

# ---- env file (0600; holds the token, NOT passed on the command line) ------
quote_env() { printf "%s" "$1" | sed "s/'/'\\\\''/g; s/^/'/; s/\$/'/"; }
xml_escape() {
  printf "%s" "$1" | sed \
    -e 's/&/\&amp;/g' \
    -e 's/</\&lt;/g' \
    -e 's/>/\&gt;/g' \
    -e 's/"/\&quot;/g' \
    -e "s/'/\&apos;/g"
}
umask 077
cat >"$env_path" <<EOF
LATTICE_SERVER=$(quote_env "$server")
LATTICE_NODE_ID=$(quote_env "$node_id")
LATTICE_NODE_TOKEN=$(quote_env "$token")
LATTICE_LOG_STATE_DIR=$(quote_env "$state_dir")
LATTICE_AGENT_RUN_USER=$(quote_env "$run_user")
LATTICE_AGENT_RUN_GROUP=$(quote_env "$run_group")
LATTICE_AGENT_CREATE_USER=$(quote_env "$create_run_user")
LATTICE_AGENT_ALLOW_EXEC=$(quote_env "${LATTICE_AGENT_ALLOW_EXEC:-0}")
LATTICE_AGENT_ALLOW_ROOT_EXEC=$(quote_env "${LATTICE_AGENT_ALLOW_ROOT_EXEC:-0}")
LATTICE_NO_EXEC=$(quote_env "${LATTICE_NO_EXEC:-0}")
LATTICE_NO_BEACON=$(quote_env "${LATTICE_NO_BEACON:-0}")
LATTICE_NO_PREFETCH=$(quote_env "${LATTICE_NO_PREFETCH:-0}")
LATTICE_TASK_CGROUP_ROOT=$(quote_env "${LATTICE_TASK_CGROUP_ROOT:-}")
LATTICE_TASK_CGROUP_MEMORY_MAX=$(quote_env "${LATTICE_TASK_CGROUP_MEMORY_MAX:-536870912}")
LATTICE_TASK_CGROUP_PIDS_MAX=$(quote_env "${LATTICE_TASK_CGROUP_PIDS_MAX:-64}")
LATTICE_TASK_CGROUP_CPU_MAX=$(quote_env "${LATTICE_TASK_CGROUP_CPU_MAX:-100000 100000}")
LATTICE_TASK_WORK_ROOT=$(quote_env "${LATTICE_TASK_WORK_ROOT:-}")
LATTICE_TASK_OUTBOX_DIR=$(quote_env "${LATTICE_TASK_OUTBOX_DIR:-}")
LATTICE_LINECHAIN_TXN_DIR=$(quote_env "$linechain_txn_dir")
LATTICE_AGENT_ALLOW_TERMINAL=$(quote_env "${LATTICE_AGENT_ALLOW_TERMINAL:-0}")
LATTICE_TERMINAL_TRANSPORT=$(quote_env "${LATTICE_TERMINAL_TRANSPORT:-poll}")
LATTICE_IP_MODE=$(quote_env "${LATTICE_IP_MODE:-auto}")
LATTICE_IP_RESOLVERS=$(quote_env "${LATTICE_IP_RESOLVERS:-}")
LATTICE_IP_SCRIPT=$(quote_env "${LATTICE_IP_SCRIPT:-}")
LATTICE_PUBLIC_IP=$(quote_env "${LATTICE_PUBLIC_IP:-}")
LATTICE_PUBLIC_IP6=$(quote_env "${LATTICE_PUBLIC_IP6:-}")
LATTICE_SSH_ALERTS=$(quote_env "${LATTICE_SSH_ALERTS:-0}")
LATTICE_SINGBOX_DISCOVER=$(quote_env "${LATTICE_SINGBOX_DISCOVER:-0}")
LATTICE_SINGBOX_BIN=$(quote_env "${LATTICE_SINGBOX_BIN:-sb}")
LATTICE_PROXY_USAGE_FILE=$(quote_env "${LATTICE_PROXY_USAGE_FILE:-}")
LATTICE_PROXY_USAGE_URL=$(quote_env "${LATTICE_PROXY_USAGE_URL:-}")
LATTICE_PROXY_USAGE_XRAY_API=$(quote_env "${LATTICE_PROXY_USAGE_XRAY_API:-}")
LATTICE_PROXY_USAGE_XRAY_BIN=$(quote_env "${LATTICE_PROXY_USAGE_XRAY_BIN:-}")
LATTICE_PROXY_USAGE_XRAY_PATTERN=$(quote_env "${LATTICE_PROXY_USAGE_XRAY_PATTERN:-}")
EOF
chmod 0600 "$env_path"
ok "wrote env -> $env_path"

# ---- register + start the boot service -------------------------------------
case "$kind" in
  systemd)
    unit_identity=""
    if [ -n "$run_user" ]; then
      unit_identity="User=$run_user
Group=$run_group"
    fi
    cat >"$unit_path" <<EOF
[Unit]
Description=Lattice node agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
$unit_identity
EnvironmentFile=$env_path
ExecStart=$bin_path
Delegate=yes
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    # Keepalive drop-in for a binary that advertises sd-notify-v1. It grants
    # the agent a notify socket; the agent then arms a 120 s watchdog itself
    # (WATCHDOG_USEC=) and pets it only while its own loops make progress, so
    # an unreachable control plane never restarts it and a wedged loop does.
    # The runtime directory holds the health marker an agent update's
    # dead-man timer reads. The unit stays Type=simple without WatchdogSec,
    # so an older binary installed under this drop-in later runs as before.
    # Agent updates write the same file.
    keepalive_dropin_dir="/etc/systemd/system/${service_name}.service.d"
    keepalive_dropin="$keepalive_dropin_dir/10-lattice-keepalive.conf"
    if "$bin_path" -compat-json 2>/dev/null | grep -Fq '"sd-notify-v1"'; then
      mkdir -p "$keepalive_dropin_dir"
      cat >"$keepalive_dropin" <<EOF
# Written by the Lattice agent installer or an agent update.
[Service]
NotifyAccess=main
RuntimeDirectory=$service_name
RuntimeDirectoryMode=0700
EOF
      ok "keepalive drop-in -> $keepalive_dropin"
    else
      rm -f "$keepalive_dropin"
    fi
    systemctl daemon-reload
    systemctl enable --now "$service_name"
    ok "systemd service enabled (boot autostart) + started"
    systemctl --no-pager --lines=15 status "$service_name" || true
    ;;
  openrc)
    # supervise-daemon restarts a crashed agent, as systemd's Restart=always
    # and launchd's KeepAlive do; command_background alone left it down.
    # OpenRC older than 0.21 has no supervise-daemon and keeps the old form.
    if have supervise-daemon; then
      openrc_supervision='supervisor=supervise-daemon
respawn_delay=10
respawn_max=0'
    else
      openrc_supervision='command_background=true'
    fi
    cat >"$openrc_path" <<EOF
#!/sbin/openrc-run
name="lattice-agent"
command="$bin_path"
$openrc_supervision
pidfile="/run/${service_name}.pid"
output_log="$state_dir/agent.log"
error_log="$state_dir/agent.log"
start_pre() { set -a; . "$env_path"; set +a; }
depend() { need net; }
EOF
    chmod +x "$openrc_path"
    rc-update add "$service_name" default
    rc-service "$service_name" restart
    ok "openrc service added (boot autostart) + started"
    ;;
  launchd)
    # launchd: token lives in EnvironmentVariables (plist is 0600), not argv.
    # Every value is XML-escaped so enrollment commands with URL query
    # delimiters or generated token punctuation cannot corrupt the plist.
    cat >"$plist_path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$(xml_escape "$plist_label")</string>
  <key>ProgramArguments</key><array><string>$(xml_escape "$bin_path")</string></array>
  <key>EnvironmentVariables</key><dict>
    <key>LATTICE_SERVER</key><string>$(xml_escape "$server")</string>
    <key>LATTICE_NODE_ID</key><string>$(xml_escape "$node_id")</string>
    <key>LATTICE_NODE_TOKEN</key><string>$(xml_escape "$token")</string>
    <key>LATTICE_LOG_STATE_DIR</key><string>$(xml_escape "$state_dir")</string>
    <key>LATTICE_AGENT_ALLOW_EXEC</key><string>$(xml_escape "${LATTICE_AGENT_ALLOW_EXEC:-0}")</string>
    <key>LATTICE_AGENT_ALLOW_ROOT_EXEC</key><string>$(xml_escape "${LATTICE_AGENT_ALLOW_ROOT_EXEC:-0}")</string>
    <key>LATTICE_NO_EXEC</key><string>$(xml_escape "${LATTICE_NO_EXEC:-0}")</string>
    <key>LATTICE_NO_BEACON</key><string>$(xml_escape "${LATTICE_NO_BEACON:-0}")</string>
    <key>LATTICE_NO_PREFETCH</key><string>$(xml_escape "${LATTICE_NO_PREFETCH:-0}")</string>
    <key>LATTICE_TASK_CGROUP_ROOT</key><string>$(xml_escape "${LATTICE_TASK_CGROUP_ROOT:-}")</string>
    <key>LATTICE_TASK_CGROUP_MEMORY_MAX</key><string>$(xml_escape "${LATTICE_TASK_CGROUP_MEMORY_MAX:-536870912}")</string>
    <key>LATTICE_TASK_CGROUP_PIDS_MAX</key><string>$(xml_escape "${LATTICE_TASK_CGROUP_PIDS_MAX:-64}")</string>
    <key>LATTICE_TASK_CGROUP_CPU_MAX</key><string>$(xml_escape "${LATTICE_TASK_CGROUP_CPU_MAX:-100000 100000}")</string>
    <key>LATTICE_TASK_WORK_ROOT</key><string>$(xml_escape "${LATTICE_TASK_WORK_ROOT:-}")</string>
    <key>LATTICE_TASK_OUTBOX_DIR</key><string>$(xml_escape "${LATTICE_TASK_OUTBOX_DIR:-}")</string>
    <key>LATTICE_LINECHAIN_TXN_DIR</key><string>$(xml_escape "$linechain_txn_dir")</string>
    <key>LATTICE_AGENT_ALLOW_TERMINAL</key><string>$(xml_escape "${LATTICE_AGENT_ALLOW_TERMINAL:-0}")</string>
    <key>LATTICE_TERMINAL_TRANSPORT</key><string>$(xml_escape "${LATTICE_TERMINAL_TRANSPORT:-poll}")</string>
    <key>LATTICE_IP_MODE</key><string>$(xml_escape "${LATTICE_IP_MODE:-auto}")</string>
    <key>LATTICE_IP_RESOLVERS</key><string>$(xml_escape "${LATTICE_IP_RESOLVERS:-}")</string>
    <key>LATTICE_IP_SCRIPT</key><string>$(xml_escape "${LATTICE_IP_SCRIPT:-}")</string>
    <key>LATTICE_PUBLIC_IP</key><string>$(xml_escape "${LATTICE_PUBLIC_IP:-}")</string>
    <key>LATTICE_PUBLIC_IP6</key><string>$(xml_escape "${LATTICE_PUBLIC_IP6:-}")</string>
    <key>LATTICE_SSH_ALERTS</key><string>$(xml_escape "${LATTICE_SSH_ALERTS:-0}")</string>
    <key>LATTICE_SINGBOX_DISCOVER</key><string>$(xml_escape "${LATTICE_SINGBOX_DISCOVER:-0}")</string>
    <key>LATTICE_SINGBOX_BIN</key><string>$(xml_escape "${LATTICE_SINGBOX_BIN:-sb}")</string>
    <key>LATTICE_PROXY_USAGE_FILE</key><string>$(xml_escape "${LATTICE_PROXY_USAGE_FILE:-}")</string>
    <key>LATTICE_PROXY_USAGE_URL</key><string>$(xml_escape "${LATTICE_PROXY_USAGE_URL:-}")</string>
    <key>LATTICE_PROXY_USAGE_XRAY_API</key><string>$(xml_escape "${LATTICE_PROXY_USAGE_XRAY_API:-}")</string>
    <key>LATTICE_PROXY_USAGE_XRAY_BIN</key><string>$(xml_escape "${LATTICE_PROXY_USAGE_XRAY_BIN:-}")</string>
    <key>LATTICE_PROXY_USAGE_XRAY_PATTERN</key><string>$(xml_escape "${LATTICE_PROXY_USAGE_XRAY_PATTERN:-}")</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$(xml_escape "$state_dir")/agent.log</string>
  <key>StandardErrorPath</key><string>$(xml_escape "$state_dir")/agent.log</string>
</dict>
</plist>
EOF
    chmod 0600 "$plist_path"
    launchctl bootout system "$plist_path" 2>/dev/null || true
    launchctl bootstrap system "$plist_path" 2>/dev/null || launchctl load -w "$plist_path"
    ok "launchd daemon installed (RunAtLoad boot autostart) + started"
    ;;
  none)
    die "no supported service manager found (need systemd, openrc, or launchd). Binary is at $bin_path; run it manually with the env in $env_path."
    ;;
esac

echo
ok "lattice-agent ${version} installed under $LATTICE_HOME for node ${node_id}"
