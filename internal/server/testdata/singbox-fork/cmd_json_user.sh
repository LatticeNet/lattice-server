# Vendored from lr00rl/sing-box, tag v1.24.3-alpha.8, commit
# ccf8317901349f528f29e5f77acde82754f6e3b4: the node script adopted Lattice
# nodes run once they are rolled from alpha.7. Only the functions behind
# `sb [--json] user add|del|park|unpark|parked <line> <payload>` are here,
# copied byte for byte; nothing below this header is edited.
#
#   src/init.sh blob 3792d05d3f37342090e2b29e7201f72d9b53c3c6: json_err
#   src/core.sh blob e386c49921b49b7f6c032511167deaee0ba34700: json_resolve_config_file,
#     json_line_user_obj, json_line_user_valid, json_line_user_matches_filter,
#     json_line_user_select_defs, json_write_config_atomically,
#     json_stats_allowlist_sync, json_line_user_opens_proxy, json_parked_file,
#     json_parked_read, json_parked_write, json_parked_summary,
#     json_line_user_plan, json_user_lock_available, json_user_lock,
#     cmd_json_user, cmd_json_user_park, cmd_json_user_parked
#
# cmd_json_user refuses to run with script_incomplete when any helper it calls
# is missing, so a refresh that leaves one out fails every contract test
# instead of skipping the open-proxy guard or the lock in silence.
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
#     awk "/^json_line_user_select_defs='/,/^'/" "$CORE"; echo
#     for f in json_write_config_atomically json_stats_allowlist_sync json_line_user_opens_proxy \
#              json_parked_file json_parked_read json_parked_write json_parked_summary json_line_user_plan \
#              json_user_lock_available json_user_lock \
#              cmd_json_user cmd_json_user_park cmd_json_user_parked; do extract $f "$CORE"; done
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
            # A socks user is a username and a password and nothing else:
            # the core decodes it strictly and fails the whole file on
            # "name". The username is the user name on these lines.
            {username:($p.username // $p.email // $p.user_id // $p.name // ""), password:($p.password // "")} | compact_obj
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

json_line_user_select_defs='
    def user_key($proto):
        if ($proto == "socks" or $proto == "http" or $proto == "mixed") then (.username // "") else (.name // "") end;
    def same_nonempty($a; $b): (($a // "") != "" and ($a // "") == ($b // ""));
    def selects($s; $proto):
        ($s | user_key($proto)) as $k
        | if ($k | type) == "string" and $k != "" then user_key($proto) == $k
          else same_nonempty(.uuid; $s.uuid) or same_nonempty(.username; $s.username) or same_nonempty(.password; $s.password)
          end;
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

json_line_user_opens_proxy() {
    local raw_file="$1" before="$2" after="$3" type
    [[ $before -gt 0 && $after -eq 0 ]] || return 1
    type=$(jq -r '.inbounds[0].type // ""' "$raw_file" 2>/dev/null)
    [[ $type == socks || $type == http || $type == mixed ]]
}

json_parked_file() {
    printf '%s/%s' "${is_lattice_parked_dir:-${is_conf_dir%/*}/lattice-parked}" "$1"
}

json_parked_read() {
    local f
    f=$(json_parked_file "$1")
    if [[ ! -e $f ]]; then
        printf '%s\n' '{"schema":"lattice.singbox-parked.v1","users":[]}'
        return 0
    fi
    jq -ce 'if .schema == "lattice.singbox-parked.v1" and (.users | type) == "array"
               and all(.users[]; type == "object" and (.user | type) == "object")
            then . else empty end' "$f" 2>/dev/null
}

json_parked_write() {
    local line="$1" doc="$2" f dir tmp
    f=$(json_parked_file "$line")
    dir=${f%/*}
    if [[ $(jq '.users | length' <<<"$doc" 2>/dev/null) == 0 ]]; then
        rm -f "$f"
        return
    fi
    mkdir -p "$dir" && chmod 700 "$dir" || return 1
    tmp=$(mktemp "$dir/.$line.XXXXXX") || return 1
    chmod 600 "$tmp"
    if ! jq . <<<"$doc" >"$tmp" 2>/dev/null; then
        rm -f "$tmp"
        return 1
    fi
    mv "$tmp" "$f" || { rm -f "$tmp"; return 1; }
}

json_parked_summary() {
    jq -c '[.users[].user | (.name // .username // "")] as $n
        | {parked_users:($n | length),
           parked_names:[$n[] | select(type == "string" and test("^u_[0-9a-f]{16}$"))]}'
}

json_line_user_plan() {
    local op="$1" raw_file="$2" parked="$3" sels="$4"
    jq -c --arg op "$op" --argjson parked "$parked" --argjson sels "$sels" \
        --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$json_line_user_select_defs"'
        (.inbounds[0].type // "") as $type
        | def hits($list; $s): [range(0; $list | length) as $j | select($list[$j] | selects($s; $type)) | $j];
          def drop($idx): [range(0; length) as $j | select(any($idx[]; . == $j) | not) | .[$j]];
          def result_for($i; $s):
              {selector:$i} + (($s | user_key($type)) as $k
                  | if ($k | type) == "string" and ($k | test("^u_[0-9a-f]{16}$")) then {name:$k} else {} end);
          reduce range(0; $sels | length) as $i
              ({users:(.inbounds[0].users // []), parked:($parked.users // []), results:[], error:null};
               if .error != null then . else
                   $sels[$i] as $s
                   | hits(.users; $s) as $a
                   | hits(.parked | map(.user); $s) as $p
                   | result_for($i; $s) as $r
                   | if $op == "park" then
                         if ($a | length) > 1 then
                             .error = {error:"ambiguous_user", message:"selector \($i) matches \($a | length) users on this line"}
                         elif ($a | length) == 1 then
                             .users[$a[0]] as $u
                             | if ($p | length) == 0 then
                                   .parked += [{user:$u, parked_at:$now}] | .users |= drop($a)
                                   | .results += [$r + {state:"parked"}]
                               elif ($p | length) == 1 and .parked[$p[0]].user == $u then
                                   .users |= drop($a) | .results += [$r + {state:"parked"}]
                               else
                                   .error = {error:"conflict", message:"selector \($i): this line already has a different parked copy of that user; resolve it by hand"}
                               end
                         elif ($p | length) > 0 then
                             .results += [$r + {state:"already_parked"}]
                         else
                             .results += [$r + {state:"absent"}]
                         end
                     elif $op == "unpark" then
                         if ($p | length) > 1 then
                             .error = {error:"ambiguous_user", message:"selector \($i) matches \($p | length) parked users on this line"}
                         elif ($p | length) == 1 then
                             .parked[$p[0]].user as $u
                             | if ($a | length) == 0 then
                                   .users += [$u] | .parked |= drop($p)
                                   | .results += [$r + {state:"restored"}]
                               elif ($a | length) == 1 and .users[$a[0]] == $u then
                                   .parked |= drop($p) | .results += [$r + {state:"already_active"}]
                               elif ($a | length) == 1 then
                                   .error = {error:"conflict", message:"selector \($i): the line holds a different entry for that user; resolve it by hand"}
                               else
                                   .error = {error:"ambiguous_user", message:"selector \($i) matches \($a | length) users on this line"}
                               end
                         elif ($a | length) > 0 then
                             .results += [$r + {state:"already_active"}]
                         else
                             .results += [$r + {state:"absent"}]
                         end
                     elif $op == "del" then
                         if ($a | length) > 1 then
                             .error = {error:"ambiguous_user", message:"the name matches \($a | length) users on this line; remove it by credential instead"}
                         else
                             .users |= drop($a) | .parked |= drop($p)
                             | .results += [$r + {state:(if ($a | length) == 1 then "removed" elif ($p | length) > 0 then "removed_parked" else "absent" end)}]
                         end
                     elif $op == "purge" then
                         .parked |= drop($p)
                     else
                         .error = {error:"invalid_action", message:"no plan for \($op)"}
                     end
               end)
    ' "$raw_file"
}

json_user_lock_available() {
    command -v flock >/dev/null 2>&1
}

json_user_lock() {
    local lock="${is_lattice_user_lock:-${is_conf_dir%/*}/lattice-user.lock}" end
    json_user_lock_available || return 0
    exec 8>>"$lock" || json_err "lock_failed" "cannot open the user lock $lock" 2
    end=$((SECONDS + ${is_lattice_user_lock_wait:-20}))
    until flock -n 8 2>/dev/null; do
        [[ $SECONDS -lt $end ]] ||
            json_err "busy" "another sb user call on this node holds the user lock; nothing was changed, try again" 2
        sleep 0.2 2>/dev/null || sleep 1
    done
}

cmd_json_user() {
    is_json_out=1
    local op="$1" name="$2" payload="$3"
    # Lattice's contract test runs a copy of this command built by extracting
    # functions from this file. A helper left out of such a copy must fail the
    # call, not vanish: bash prints "command not found" and carries on, so the
    # open-proxy guard tests false, the lock is skipped, and every parked read
    # looks damaged, all with ok:true.
    declare -F json_resolve_config_file json_line_user_obj json_line_user_valid json_line_user_plan \
        json_line_user_opens_proxy json_write_config_atomically json_stats_allowlist_sync \
        json_parked_file json_parked_read json_parked_write json_parked_summary \
        json_user_lock_available json_user_lock cmd_json_user_park cmd_json_user_parked >/dev/null &&
        [[ ${json_line_user_matches_filter:-} && ${json_line_user_select_defs:-} ]] ||
        json_err "script_incomplete" "this copy of the node script lacks functions that sb user calls" 2
    case $op in
    add | del) json_user_lock ;;
    park | unpark) json_user_lock; cmd_json_user_park "$op" "$name" "$payload" ;;
    parked) cmd_json_user_parked "$name" ;;
    *) json_err "invalid_action" "user action must be add, del, park, unpark or parked" 2 ;;
    esac
    [[ $payload ]] || json_err "missing_payload" "user payload json is required" 2
    jq -e . >/dev/null <<<"$payload" || json_err "invalid_payload" "user payload must be valid json" 2

    local config_file resolve_out resolve_rc raw_file user_json filter count_before count_after stats_sync=ok
    local by_name= plan plan_error write_arg users_changed=true
    local parked_before parked_after= parked_invalid= parked_stale= pcount_before=0 pcount_after=0
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
    if ! json_line_user_valid "$user_json"; then
        # A user name alone is enough to delete. A deleted identity has no
        # credential left to send, and matching by name cannot take a
        # hand-added entry that happens to share a uuid or password. The name
        # must pick out exactly one entry; the plan refuses otherwise.
        [[ $op == "del" ]] && jq -e '[.name, .username] | any(type == "string" and . != "")' >/dev/null 2>&1 <<<"$user_json" ||
            json_err "invalid_user" "payload does not contain the credential required by this line" 2
        by_name=1
    fi
    write_arg=$user_json
    # A damaged parked file is reported and left alone: add and del still do
    # their job on the line, which for del is the revocation that matters.
    if ! parked_before=$(json_parked_read "$config_file"); then
        parked_invalid=1
        parked_before='{"schema":"lattice.singbox-parked.v1","users":[]}'
    fi
    pcount_before=$(jq '.users | length' <<<"$parked_before")
    pcount_after=$pcount_before

    count_before=$(jq '(.inbounds[0].users // []) | length' "$raw_file" 2>/dev/null)
    [[ $count_before =~ ^[0-9]+$ ]] || count_before=0
    if [[ $by_name ]]; then
        plan=$(json_line_user_plan del "$raw_file" "$parked_before" "[$user_json]") || json_err "jq_failed" "failed to plan the removal" 2
        plan_error=$(jq -c '.error // empty' <<<"$plan")
        [[ $plan_error ]] && json_err "$(jq -r .error <<<"$plan_error")" "$(jq -r .message <<<"$plan_error")" 2
        write_arg=$(jq -c .users <<<"$plan")
        [[ $write_arg == "$(jq -c '.inbounds[0].users // []' "$raw_file")" ]] && users_changed=false
        parked_after=$(jq -c --argjson doc "$parked_before" '$doc + {users:.parked}' <<<"$plan")
        filter='.inbounds[0].users = $user'
    elif [[ $op == "add" ]]; then
        filter='
            .inbounds[0].users = (((.inbounds[0].users // []) | map(select(('"$json_line_user_matches_filter"') | not))) + [$user])
        '
    else
        # A del that carries a credential revokes that credential, so it takes
        # every entry holding it, even when the payload also names the user: an
        # entry sharing the uuid or the password admits the same client, and
        # keeping it would keep the credential working. matched says how many
        # went. A caller that must keep such an entry removes by name alone,
        # and accepts that the credential still works through it.
        filter='
            .inbounds[0].users = ((.inbounds[0].users // []) | map(select(('"$json_line_user_matches_filter"') | not)))
        '
    fi
    if [[ $op == "del" ]]; then
        count_after=$(jq --argjson user "$write_arg" "$filter"' | (.inbounds[0].users // []) | length' "$raw_file" 2>/dev/null)
        json_line_user_opens_proxy "$raw_file" "$count_before" "${count_after:-0}" &&
            json_err "last_user_open_proxy" "removing the last user of a socks, http or mixed line would leave it open to anyone; add another user first, or delete the line" 2
    fi
    # A by-name removal of a user the line does not hold changes nothing, and
    # restarting would drop every connection on the node for no reason. Every
    # other call keeps its old shape: write, sync, restart.
    if [[ $users_changed == true ]]; then
        json_write_config_atomically "$raw_file" "$filter" "$write_arg"
    fi
    count_after=$(jq '(.inbounds[0].users // []) | length' "$raw_file" 2>/dev/null)
    [[ $count_after =~ ^[0-9]+$ ]] || count_after=0
    # Parked copies of the same user. del takes them as well, or a revoked user
    # would come back on the next unpark. add drops the copy it supersedes, so
    # the line never holds an active and a parked entry for one name. A credential
    # del matches parked copies with the same selector rule as park (the name
    # when there is one), and an add without a name leaves them alone.
    if [[ ! $parked_invalid && $pcount_before -gt 0 && ! $parked_after ]]; then
        if [[ $op == "del" ]] || jq -e '[.name, .username] | any(type == "string" and . != "")' >/dev/null 2>&1 <<<"$user_json"; then
            plan=$(json_line_user_plan purge "$raw_file" "$parked_before" "[$user_json]") &&
                parked_after=$(jq -c --argjson doc "$parked_before" '$doc + {users:.parked}' <<<"$plan")
        fi
    fi
    if [[ ! $parked_invalid && $parked_after ]]; then
        pcount_after=$(jq '.users | length' <<<"$parked_after")
        if [[ $pcount_after != "$pcount_before" ]]; then
            json_parked_write "$config_file" "$parked_after" || { parked_stale=1; pcount_after=$pcount_before; }
        fi
    fi
    # Before the restart, so the new user list and the counter allowlist reach
    # the core together and a user add costs one restart, not two.
    #
    # A failure here must not skip the restart. The user row is already written
    # to disk at this point, and on `user del` that row is a revoked credential
    # that stays live on the running proxy until something restarts it. Stale
    # counters are the smaller problem by a wide margin, so warn and carry on;
    # the caller learns about it from stats_allowlist_stale in the result.
    #
    # The restart runs with fd 8, the user lock, closed: an init system that
    # starts the core as a child of this call would otherwise hand it the lock,
    # and every later user call would wait on the running proxy.
    stats_sync=ok
    if [[ $users_changed == true ]]; then
        json_stats_allowlist_sync || stats_sync=stale
        manage restart "$is_core" >/dev/null 2>&1 8>&- || json_err "restart_failed" "configuration changed but sing-box restart failed" 1
    fi
    # matched is how many entries the payload hit: del removes every one of
    # them, add replaces every one and appends its own. More than one means
    # the call took entries that were not the caller's, which the counts let
    # a control plane see after the fact. Parked counts appear only when the
    # line has or had parked users.
    #
    # A del is a revocation, and a parked copy of the user is the same
    # credential waiting for an unpark. When that copy could not be removed the
    # del is not done, so the call fails (parked_stale, exit 1) even though the
    # line no longer serves the user and the core has restarted: a caller that
    # took ok:true would drop its record of the user and leave the copy for the
    # next unpark to bring back. Repeating the del finds the user gone from the
    # line and retries the purge. add keeps ok:true with parked_stale: its stale
    # copy is an older credential of a user who is active again, which unpark
    # refuses as a conflict rather than restore. A damaged parked file
    # (parked_invalid) also stays ok:true, since no repeat can fix it and unpark
    # refuses that file outright; `user parked` and list metadata report it.
    local fail=false
    [[ $op == del && $parked_stale ]] && fail=true
    jq -nc --arg action "$op" --arg line "$config_file" --argjson before "$count_before" --argjson after "$count_after" \
        --argjson pbefore "$pcount_before" --argjson pafter "$pcount_after" \
        --argjson stale "$([ "$stats_sync" = stale ] && echo true || echo false)" \
        --argjson pstale "$([ "$parked_stale" ] && echo true || echo false)" \
        --argjson pinvalid "$([ "$parked_invalid" ] && echo true || echo false)" \
        --argjson by_name "$([ "$by_name" ] && echo true || echo false)" \
        --argjson changed "$([ "$users_changed" = true ] || [ "$pcount_after" != "$pcount_before" ] && echo true || echo false)" \
        --argjson fail "$fail" \
        '{ok:true,action:$action,line:$line,user_count_before:$before,user_count_after:$after,
          matched:(if $action == "add" then $before - $after + 1 else $before - $after end)}
         + (if $by_name then {match:"name",changed:$changed} else {} end)
         + (if $pbefore > 0 or $pafter > 0 then {parked_count_before:$pbefore,parked_count_after:$pafter} else {} end)
         + (if $stale then {stats_allowlist_stale:true} else {} end)
         + (if $pstale then {parked_stale:true} else {} end)
         + (if $pinvalid then {parked_invalid:true} else {} end)
         + (if $fail then {ok:false,error:"parked_stale",
              message:"the line no longer serves this user, but its parked copy could not be removed; repeat the del"} else {} end)'
    [[ $fail == true ]] && exit 1
    exit 0
}

cmd_json_user_park() {
    local op="$1" name="$2" payload="$3"
    local resolve_out resolve_rc config_file raw_file sel sels='[]' parked_before parked_after plan plan_error
    local users_before users_after count_before count_after pcount_before pcount_after
    local users_changed=false parked_changed=false parked_stale= out rc stats_sync=ok
    [[ $payload ]] || json_err "missing_payload" "user payload json is required" 2
    jq -e 'type == "object" or (type == "array" and length > 0 and all(.[]; type == "object"))' >/dev/null 2>&1 <<<"$payload" ||
        json_err "invalid_payload" "user payload must be a json object or a non-empty array of objects" 2
    resolve_out=$(json_resolve_config_file "$name")
    resolve_rc=$?
    if [[ $resolve_rc != 0 ]]; then
        printf '%s\n' "$resolve_out"
        exit "$resolve_rc"
    fi
    config_file="$resolve_out"
    raw_file="$is_conf_dir/$config_file"
    [[ -f $raw_file ]] || json_err "not_found" "config file not found: $config_file" 2
    while IFS= read -r sel; do
        sel=$(json_line_user_obj "$raw_file" "$sel") || json_err "payload_failed" "failed to derive sing-box user object" 2
        [[ $sel != "null" && $sel ]] || json_err "unsupported_protocol" "this line protocol does not support dashboard user mutation" 2
        jq -e '[.name, .username, .uuid, .password] | any(type == "string" and . != "")' >/dev/null 2>&1 <<<"$sel" ||
            json_err "invalid_user" "every selector needs a user name or a credential" 2
        sels=$(jq -c --argjson s "$sel" '. + [$s]' <<<"$sels")
    done <<<"$(jq -c 'if type == "array" then .[] else . end' <<<"$payload")"

    parked_before=$(json_parked_read "$config_file") ||
        json_err "parked_invalid" "the parked file for $config_file is not a parked-user document; refusing to touch it" 2
    plan=$(json_line_user_plan "$op" "$raw_file" "$parked_before" "$sels") || json_err "jq_failed" "failed to plan the $op" 2
    plan_error=$(jq -c '.error // empty' <<<"$plan")
    [[ $plan_error ]] && json_err "$(jq -r .error <<<"$plan_error")" "$(jq -r .message <<<"$plan_error")" 2

    users_before=$(jq -c '.inbounds[0].users // []' "$raw_file")
    users_after=$(jq -c .users <<<"$plan")
    parked_after=$(jq -c --argjson doc "$parked_before" '$doc + {users:.parked}' <<<"$plan")
    count_before=$(jq length <<<"$users_before")
    count_after=$(jq length <<<"$users_after")
    pcount_before=$(jq '.users | length' <<<"$parked_before")
    pcount_after=$(jq '.users | length' <<<"$parked_after")
    [[ $users_after == "$users_before" ]] || users_changed=true
    [[ $(jq -c .users <<<"$parked_after") == "$(jq -c .users <<<"$parked_before")" ]] || parked_changed=true
    if [[ $op == "park" ]] && json_line_user_opens_proxy "$raw_file" "$count_before" "$count_after"; then
        json_err "last_user_open_proxy" "parking the last user of a socks, http or mixed line would leave it open to anyone; add another user first" 2
    fi

    if [[ $op == "park" ]]; then
        if [[ $parked_changed == true ]]; then
            json_parked_write "$config_file" "$parked_after" || json_err "parked_write_failed" "cannot write the parked file for $config_file" 2
        fi
        if [[ $users_changed == true ]]; then
            out=$(json_write_config_atomically "$raw_file" '.inbounds[0].users = $user' "$users_after")
            rc=$?
            if [[ $rc != 0 ]]; then
                json_parked_write "$config_file" "$parked_before" || true
                printf '%s\n' "$out"
                exit "$rc"
            fi
        fi
    else
        if [[ $users_changed == true ]]; then
            out=$(json_write_config_atomically "$raw_file" '.inbounds[0].users = $user' "$users_after")
            rc=$?
            [[ $rc == 0 ]] || { printf '%s\n' "$out"; exit "$rc"; }
        fi
        if [[ $parked_changed == true ]]; then
            json_parked_write "$config_file" "$parked_after" || { parked_stale=1; pcount_after=$pcount_before; }
        fi
    fi
    if [[ $users_changed == true ]]; then
        json_stats_allowlist_sync || stats_sync=stale
        manage restart "$is_core" >/dev/null 2>&1 8>&- || json_err "restart_failed" "configuration changed but sing-box restart failed" 1
    fi
    jq -nc --arg action "$op" --arg line "$config_file" \
        --argjson before "$count_before" --argjson after "$count_after" \
        --argjson pbefore "$pcount_before" --argjson pafter "$pcount_after" \
        --argjson changed "$([ "$users_changed" = true ] || [ "$parked_changed" = true ] && echo true || echo false)" \
        --argjson restarted "$users_changed" \
        --argjson results "$(jq -c .results <<<"$plan")" \
        --argjson stale "$([ "$stats_sync" = stale ] && echo true || echo false)" \
        --argjson pstale "$([ "$parked_stale" ] && echo true || echo false)" \
        '{ok:true,action:$action,line:$line,changed:$changed,restarted:$restarted,
          user_count_before:$before,user_count_after:$after,
          matched:(if $action == "park" then $before - $after else $after - $before end),
          parked_count_before:$pbefore,parked_count_after:$pafter,results:$results}
         + (if $stale then {stats_allowlist_stale:true} else {} end)
         + (if $pstale then {parked_stale:true} else {} end)'
    exit 0
}

cmd_json_user_parked() {
    local name="$1" dir f doc out lines=
    local -a entries=()
    if [[ $name ]]; then
        f=$(json_resolve_config_file "$name") || { printf '%s\n' "$f"; exit 2; }
        entries=("$f")
    else
        # A glob, not ls: the names come back whole whatever they contain.
        dir=$(json_parked_file "")
        for f in "${dir%/}"/*.json; do
            [[ -f $f ]] && entries+=("${f##*/}")
        done
    fi
    for f in ${entries[@]+"${entries[@]}"}; do
        if doc=$(json_parked_read "$f"); then
            out=$(json_parked_summary <<<"$doc" | jq -c --arg line "$f" \
                --argjson orphaned "$([[ -f $is_conf_dir/$f ]] && echo false || echo true)" \
                '{line:$line} + . + (if $orphaned then {orphaned:true} else {} end)')
            # The script removes a parked file when its last user leaves, so a
            # file with none is a hand-made leftover with nothing to report.
            [[ ! $name ]] && jq -e '.parked_users == 0' >/dev/null <<<"$out" && continue
        else
            out=$(jq -nc --arg line "$f" '{line:$line,error:"parked_invalid"}')
        fi
        lines+="$out"$'\n'
    done
    printf '%s' "$lines" | jq -sc '{ok:true,count:length,lines:.}'
    exit 0
}

