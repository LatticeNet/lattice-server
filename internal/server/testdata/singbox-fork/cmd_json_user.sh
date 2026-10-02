# Vendored from lr00rl/sing-box, tag v1.24.3-alpha.7, commit
# 46f4bd068865b39d294f56f5a200ca572ecead68: the node script every adopted
# Lattice node runs (rolled to 25 nodes on 2026-09-04). Only the functions
# behind `sb [--json] user add|del <line> <payload>` are here, copied
# byte for byte; nothing below this header is edited.
#
#   src/init.sh blob 736d4e5b017e116229f5132f7d5351faaae9d445: json_err
#   src/core.sh blob 79a00f64be2896ed3dbd6713349b3d33811e2dfd: json_resolve_config_file,
#     json_line_user_obj, json_line_user_valid, json_line_user_matches_filter,
#     json_write_config_atomically, json_stats_allowlist_sync, cmd_json_user
#
# lineuser_fork_contract_test.go sources this file and runs the argv
# lineUserApplyScript renders against it. To refresh it after a fork release,
# check out the new tag in a sing-box clone and run, from this directory:
#
#   CORE=<clone>/src/core.sh INIT=<clone>/src/init.sh
#   extract() { awk "/^$1\\(\\) \\{/,/^\\}/" "$2"; echo; }
#   { extract json_err "$INIT"
#     for f in json_resolve_config_file json_line_user_obj json_line_user_valid; do extract $f "$CORE"; done
#     awk "/^json_line_user_matches_filter='/,/^'/" "$CORE"; echo
#     for f in json_write_config_atomically json_stats_allowlist_sync cmd_json_user; do extract $f "$CORE"; done
#   } > body.sh
#
# then replace everything below the header with body.sh and update the tag,
# commit and blob ids above.

json_err() {
    # $1=code  $2=message  $3=exit code (default 1)
    if type -P jq &>/dev/null; then
        jq -nc --arg e "${1:-error}" --arg m "${2:-}" '{ok:false,error:$e,message:$m}'
    else
        printf '{"ok":false,"error":"%s","message":"%s"}\n' "${1:-error}" "${2:-}"
    fi
    exit "${3:-1}"
}

json_resolve_config_file() {
    local name="$1"
    local matches=() cleaned=() f exact= is_ln
    [[ ! $name ]] && json_err "missing_name" "line name is required" 2
    [[ $name == "${name##*/}" && $name != "." && $name != ".." && $name != *$'\n'* && $name != *$'\r'* ]] \
        || json_err "invalid_name" "line name must be a basename" 2
    if [[ $name == *.json && -f "$is_conf_dir/$name" ]]; then
        exact="$name"
    elif [[ $name != *.json && -f "$is_conf_dir/$name.json" ]]; then
        exact="$name.json"
    fi
    if [[ $exact ]]; then
        matches=("$exact")
    elif [[ -d $is_conf_dir ]]; then
        # read -r loop rather than readarray: bash 3.2 ships on some hosts and has
        # neither readarray nor mapfile. Exact drop-in, verified against readarray
        # on bash 5 for multi-line, single, empty, blank-mid and trailing-blank
        # input: empty output still yields one empty element, because $( ) strips
        # the trailing newlines and <<< adds exactly one back. Every caller below
        # was already written against that shape, so none of them change.
        while IFS= read -r is_ln; do matches+=("$is_ln"); done <<<"$(ls "$is_conf_dir" 2>/dev/null | grep -F -i -- "$name" | sed '/dynamic-port-.*-link/d')"
    fi
    for f in "${matches[@]}"; do
        [[ $f == "${f##*/}" && $f == *.json ]] && cleaned+=("$f")
    done
    [[ ${#cleaned[@]} -eq 0 ]] && json_err "not_found" "no line matches: $name" 2
    [[ ${#cleaned[@]} -gt 1 ]] && json_err "ambiguous" "multiple lines match: $name" 2
    printf '%s' "${cleaned[0]}"
}

json_line_user_obj() {
    local raw_file="$1" payload="$2"
    jq -nc --slurpfile cfg "$raw_file" --argjson p "$payload" '
        def compact_obj:
            with_entries(select(.value != "" and .value != null and .value != [] and .value != {}));
        ($cfg[0].inbounds[0].type // "") as $type
        | if ($type == "vless" or $type == "vmess") then
            {name:($p.name // ""), uuid:($p.uuid // ""), flow:($p.flow // "")} | compact_obj
          elif ($type == "tuic") then
            {name:($p.name // ""), uuid:($p.uuid // ""), password:($p.password // "")} | compact_obj
          elif ($type == "trojan" or $type == "hysteria2" or $type == "anytls") then
            {name:($p.name // ""), password:($p.password // "")} | compact_obj
          elif ($type == "socks") then
            {name:($p.name // ""), username:($p.username // $p.email // $p.user_id // ""), password:($p.password // "")} | compact_obj
          else
            null
          end
    '
}

json_line_user_valid() {
    local user_json="$1"
    jq -e '
        type == "object" and (
            ((.uuid // "") != "") or
            ((.password // "") != "") or
            (((.username // "") != "") and ((.password // "") != ""))
        )
    ' >/dev/null <<<"$user_json"
}

json_line_user_matches_filter='
    def same_nonempty($a; $b): (($a // "") != "" and ($a // "") == ($b // ""));
    (same_nonempty(.name; $user.name)
     or same_nonempty(.uuid; $user.uuid)
     or same_nonempty(.username; $user.username)
     or same_nonempty(.password; $user.password))
'

json_write_config_atomically() {
    local raw_file="$1" filter="$2" user_json="$3"
    local tmp backup errf
    # A sibling of the target: mv is atomic only within one filesystem, and
    # $TMPDIR is often elsewhere, which would turn a crash mid-write into a
    # truncated config file with no rollback.
    tmp=$(mktemp "$raw_file.user-new.XXXXXX") || json_err "tmp_failed" "cannot create temp file" 2
    backup="$raw_file.backup-$(date -u +%Y%m%d-%H%M%S)"
    errf=$(mktemp "${TMPDIR:-/tmp}/lattice-sb-check.XXXXXX") || { rm -f "$tmp"; json_err "tmp_failed" "cannot create temp file" 2; }
    cp -p "$raw_file" "$backup" || { rm -f "$tmp" "$errf"; json_err "backup_failed" "cannot backup $raw_file" 2; }
    if ! jq --argjson user "$user_json" "$filter" "$raw_file" >"$tmp"; then
        rm -f "$tmp" "$errf"
        json_err "jq_failed" "failed to update $raw_file" 2
    fi
    mv "$tmp" "$raw_file" || { rm -f "$tmp" "$errf"; json_err "write_failed" "failed to replace $raw_file" 2; }
    if ! "$is_core_bin" check -c "$raw_file" >"$errf" 2>&1; then
        mv "$backup" "$raw_file" 2>/dev/null || true
        local check_error
        check_error=$(tail -n 20 "$errf" 2>/dev/null)
        rm -f "$errf"
        jq -nc --arg error "config_invalid" --arg message "sing-box rejected updated config; rolled back" --arg detail "$check_error" \
            '{ok:false,error:$error,message:$message,detail:$detail}'
        exit 1
    fi
    # The backup exists to roll the file back if the core rejects the result. Once
    # the core has accepted it the backup has no further job, and leaving it is
    # not free: for a conf file it is a permanent plaintext copy of that line's
    # user credentials sitting next to the live one, and one is written on every
    # single user add and delete, without bound. Remove it on the success path,
    # which is what json_stats_allowlist_sync already does.
    rm -f "$errf" "$backup"
}

json_stats_allowlist_sync() {
    [[ -f $is_config_json ]] || return 0
    jq -e '.experimental.v2ray_api.stats.enabled == true' "$is_config_json" >/dev/null 2>&1 || return 0

    local files=("$is_config_json") f allow tmp backup
    for f in "$is_conf_dir"/*.json; do
        [[ -f $f ]] && files+=("$f")
    done
    # Only users carrying a name: the allowlist matches on name, so an unnamed
    # legacy user cannot be counted individually and its traffic stays in the
    # inbound total.
    allow=$(jq -sc '{
        inbounds:  [.[] | (.inbounds  // [])[] | .tag  | select(type == "string" and . != "")] | unique,
        outbounds: [.[] | (.outbounds // [])[] | .tag  | select(type == "string" and . != "")] | unique,
        users:     [.[] | (.inbounds  // [])[] | (.users // [])[] | .name | select(type == "string" and . != "")] | unique
    }' "${files[@]}" 2>/dev/null) || return 1
    [[ $allow ]] || return 1

    if [[ $(jq -cS '.experimental.v2ray_api.stats' "$is_config_json" 2>/dev/null) \
       == $(jq -cS --argjson a "$allow" '{enabled:true} + $a' <<<'{}' 2>/dev/null) ]]; then
        return 0
    fi

    # A sibling of the target, not $TMPDIR: mv is only atomic within one
    # filesystem, and $TMPDIR is frequently somewhere else (the agent gives a
    # task its own /tmp). Across filesystems mv falls back to copy-then-unlink,
    # which turns a crash mid-write into a truncated config.json with no
    # rollback, on the one file the node cannot start without.
    tmp=$(mktemp "$is_config_json.stats-new.XXXXXX") || return 1
    backup="$is_config_json.backup-$(date -u +%Y%m%d-%H%M%S)"
    cp -p "$is_config_json" "$backup" || { rm -f "$tmp"; return 1; }
    if ! jq --argjson a "$allow" '.experimental.v2ray_api.stats = ({enabled:true} + $a)' "$is_config_json" >"$tmp"; then
        rm -f "$tmp" "$backup"
        return 1
    fi
    mv "$tmp" "$is_config_json" || { rm -f "$tmp" "$backup"; return 1; }
    if ! "$is_core_bin" check -c "$is_config_json" -C "$is_conf_dir" >/dev/null 2>&1; then
        mv "$backup" "$is_config_json" 2>/dev/null || true
        return 1
    fi
    rm -f "$backup"
    return 0
}

cmd_json_user() {
    is_json_out=1
    local op="$1" name="$2" payload="$3"
    [[ $op == "add" || $op == "del" ]] || json_err "invalid_action" "user action must be add or del" 2
    [[ $payload ]] || json_err "missing_payload" "user payload json is required" 2
    jq -e . >/dev/null <<<"$payload" || json_err "invalid_payload" "user payload must be valid json" 2

    local config_file resolve_out resolve_rc raw_file user_json filter count_before count_after stats_sync=ok
    resolve_out=$(json_resolve_config_file "$name")
    resolve_rc=$?
    if [[ $resolve_rc != 0 ]]; then
        printf '%s\n' "$resolve_out"
        exit "$resolve_rc"
    fi
    config_file="$resolve_out"
    raw_file="$is_conf_dir/$config_file"
    [[ -f $raw_file ]] || json_err "not_found" "config file not found: $config_file" 2
    user_json=$(json_line_user_obj "$raw_file" "$payload") || json_err "payload_failed" "failed to derive sing-box user object" 2
    [[ $user_json != "null" && $user_json ]] || json_err "unsupported_protocol" "this line protocol does not support dashboard user mutation" 2
    json_line_user_valid "$user_json" || json_err "invalid_user" "payload does not contain the credential required by this line" 2

    count_before=$(jq '(.inbounds[0].users // []) | length' "$raw_file" 2>/dev/null)
    [[ $count_before =~ ^[0-9]+$ ]] || count_before=0
    if [[ $op == "add" ]]; then
        filter='
            .inbounds[0].users = (((.inbounds[0].users // []) | map(select(('"$json_line_user_matches_filter"') | not))) + [$user])
        '
    else
        filter='
            .inbounds[0].users = ((.inbounds[0].users // []) | map(select(('"$json_line_user_matches_filter"') | not)))
        '
    fi
    json_write_config_atomically "$raw_file" "$filter" "$user_json"
    count_after=$(jq '(.inbounds[0].users // []) | length' "$raw_file" 2>/dev/null)
    [[ $count_after =~ ^[0-9]+$ ]] || count_after=0
    # Before the restart, so the new user list and the counter allowlist reach
    # the core together and a user add costs one restart, not two.
    #
    # A failure here must not skip the restart. The user row is already written
    # to disk at this point, and on `user del` that row is a revoked credential
    # that stays live on the running proxy until something restarts it. Stale
    # counters are the smaller problem by a wide margin, so warn and carry on;
    # the caller learns about it from stats_allowlist_stale in the result.
    stats_sync=ok
    json_stats_allowlist_sync || stats_sync=stale
    manage restart "$is_core" >/dev/null 2>&1 || json_err "restart_failed" "configuration changed but sing-box restart failed" 1
    jq -nc --arg action "$op" --arg line "$config_file" --argjson before "$count_before" --argjson after "$count_after" \
        --argjson stale "$([ "$stats_sync" = stale ] && echo true || echo false)" \
        '{ok:true,action:$action,line:$line,user_count_before:$before,user_count_after:$after}
         + (if $stale then {stats_allowlist_stale:true} else {} end)'
    exit 0
}

