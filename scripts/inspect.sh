#!/usr/bin/env bash
#
# Look inside SpiceDB: what the model is, what the facts are, and who is
# actually authorized for what.
#
#   scripts/inspect.sh                 full report — schema, facts, authorization matrix
#   scripts/inspect.sh why  <resource> <permission> <subject>
#   scripts/inspect.sh who  <resource> <permission> [subject-type]
#   scripts/inspect.sh what <type> <permission> <subject>
#   scripts/inspect.sh consent [user]
#   scripts/inspect.sh watch
#   scripts/inspect.sh shell           hold the port-forward open and print recipes
#
# mvp_docs/06 §1 calls `zed ... --explain` "the single most useful debugging tool
# in this stack", and it is: it turns "why was this denied" from guesswork into a
# two-second query that prints the actual decision tree.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
trap cleanup_port_forwards EXIT

k get ns id >/dev/null 2>&1 || die "the cluster is not up. Run: make up"
port_forward id svc/spicedb 50051:50051 >/dev/null

Z=(zed --endpoint localhost:50051 --token gerege-mvp-key --insecure)
zq() { "${Z[@]}" "$@" 2>/dev/null || true; }

# The schema's permissions, by object type. Kept here rather than parsed so the
# report stays readable when the schema grows.
PERMS_user_profile="view edit"
PERMS_home="administrate operate view"
PERMS_device="view operate operate_lock"

hdr() { printf '\n%s%s%s\n%s\n' "$B" "$*" "$R" "$(printf '─%.0s' $(seq 1 ${#1}))"; }

objects_of() {   # objects_of <type> — distinct object ids that have any relationship
  zq relationship read "gerege/$1" | awk '{print $1}' | sed 's/^[^:]*://' | sort -u || true
}

report() {
  hdr "Model"
  zq schema read | grep -E '^definition|^\s+(relation|permission)' | sed 's/^/  /'

  hdr "Facts — every relationship in the system"
  local t
  for t in user_profile home device consent_grant agent delegation; do
    local rows; rows=$(zq relationship read "gerege/$t" || true)
    [[ -z "$rows" ]] && continue
    printf '\n  %s%s%s\n' "$CYN" "$t" "$R"
    echo "$rows" | sed 's/^/    /'
  done

  hdr "Who is authorized for what"
  printf '  %sComputed, not stored. Each line is a lookup-subjects query against the live graph.%s\n' "$DIM" "$R"
  local type perms obj perm subs
  for type in user_profile home device; do
    eval "perms=\$PERMS_${type}"
    for obj in $(objects_of "$type"); do
      printf '\n  %s%s:%s%s\n' "$CYN" "$type" "$obj" "$R"
      for perm in $perms; do
        subs=$(zq permission lookup-subjects "gerege/$type:$obj" "$perm" gerege/user \
               | sed 's|gerege/user:||' | tr '\n' ' ' | sed 's/ *$//' || true)
        if [[ -z "$subs" ]]; then
          printf '    %-14s %s— nobody —%s\n' "$perm" "$DIM" "$R"
        else
          printf '    %-14s %s\n' "$perm" "$subs"
        fi
      done
    done
  done

  # Non-human principals are a different subject type, so they need their own pass.
  local sp
  for obj in $(objects_of device); do
    sp=$(zq permission lookup-subjects "gerege/device:$obj" push_telemetry gerege/system_principal \
         | sed 's|gerege/system_principal:||' | tr '\n' ' ' | sed 's/ *$//' || true)
    [[ -n "$sp" ]] && printf '\n  %sdevice:%s%s\n    %-14s %s %s(non-human principal)%s\n' \
      "$CYN" "$obj" "$R" "push_telemetry" "$sp" "$DIM" "$R"
  done

  hdr "Consent — what each application may touch"
  local grants; grants=$(zq relationship read gerege/consent_grant granted || true)
  if [[ -z "$grants" ]]; then
    printf '  %snone granted. This is the state Scenario 3a starts from.%s\n' "$DIM" "$R"
  else
    echo "$grants" | sed 's|gerege/consent_grant:||; s|gerege/capability:||; s/ granted / → /' | sed 's/^/  /'
  fi
}

case "${1:-report}" in
  report) report ;;
  why)
    [[ $# -eq 4 ]] || die "usage: inspect.sh why <resource> <permission> <subject>"
    zq permission check "$2" "$3" "$4" --explain ;;
  who)
    [[ $# -ge 3 ]] || die "usage: inspect.sh who <resource> <permission> [subject-type]"
    zq permission lookup-subjects "$2" "$3" "${4:-gerege/user}" ;;
  what)
    [[ $# -eq 4 ]] || die "usage: inspect.sh what <type> <permission> <subject>"
    zq permission lookup-resources "$2" "$3" "$4" | grep -v '^Last cursor:' ;;
  consent)
    zq relationship read gerege/consent_grant granted \
      | { [[ -n "${2:-}" ]] && grep "consent_grant:$2|" || cat; } ;;
  watch)
    info "watching for relationship changes — ctrl-c to stop"
    "${Z[@]}" relationship watch ;;
  shell)
    cat <<EOF

  SpiceDB is on localhost:50051 for as long as this command runs.

    export ZED_ENDPOINT=localhost:50051 ZED_TOKEN=gerege-mvp-key ZED_INSECURE=true

    zed schema read
    zed relationship read gerege/device
    zed permission check gerege/device:lock-1 operate_lock gerege/user:alice --explain
    zed permission lookup-subjects gerege/device:lock-1 operate_lock gerege/user
    zed permission lookup-resources gerege/device operate gerege/user:alice
    zed permission expand operate_lock gerege/device:lock-1     # note: permission first
    zed relationship watch

EOF
    port_forward id svc/spicedb 8443:8443 >/dev/null
    info "HTTP API on localhost:8443 — curl -H 'authorization: Bearer gerege-mvp-key' ..."
    info "ctrl-c to stop"
    while true; do sleep 3600; done ;;
  *) die "unknown command '$1' (try: report why who what consent watch shell)" ;;
esac
