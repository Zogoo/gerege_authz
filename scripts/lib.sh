#!/usr/bin/env bash
# Shared helpers for the bootstrap, demo and teardown scripts.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER="${CLUSTER:-gerege-idp}"
KCTX="kind-${CLUSTER}"
IMAGE="${IMAGE:-gerege/idp-mvp:dev}"

# Hostnames the demo is addressed by. SSO across *different* origins is the
# claim, so these are separate hosts rather than paths on one.
HOSTS=(id.local.test profile.local.test smarthome.local.test account.local.test device.local.test)

if [[ -t 1 ]]; then
  B=$'\033[1m'; DIM=$'\033[2m'; R=$'\033[0m'
  GRN=$'\033[32m'; RED=$'\033[31m'; YEL=$'\033[33m'; CYN=$'\033[36m'
else
  B=''; DIM=''; R=''; GRN=''; RED=''; YEL=''; CYN=''
fi

step()  { printf '\n%s==> %s%s\n' "$B$CYN" "$*" "$R"; }
info()  { printf '    %s\n' "$*"; }
ok()    { printf '    %s✓%s %s\n' "$GRN" "$R" "$*"; }
warn()  { printf '    %s!%s %s\n' "$YEL" "$R" "$*"; }
die()   { printf '\n%serror:%s %s\n' "$RED" "$R" "$*" >&2; exit 1; }

k() { kubectl --context "$KCTX" "$@"; }

need() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is not installed. Run: make prereqs"
}

# wait_rollout <namespace> <resource> [timeout]
wait_rollout() {
  local ns="$1" res="$2" timeout="${3:-300s}"
  k -n "$ns" rollout status "$res" --timeout="$timeout" >/dev/null \
    || die "$res in $ns did not become ready. Try: kubectl --context $KCTX -n $ns describe $res"
  ok "$res ready"
}

# port_forward <namespace> <target> <local:remote> — returns the pid on stdout
#
# A port-forward left behind by an interrupted run holds the local port and
# makes the next run fail with a message that says nothing useful. Reap ours
# first, then retry a few times: the target pod may have only just been rolled.
PF_PIDS=()
port_forward() {
  local ns="$1" target="$2" ports="$3"
  local lport="${ports%%:*}"
  reap_stale_forward "$lport"

  local attempt pid
  for attempt in 1 2 3 4 5; do
    kubectl --context "$KCTX" -n "$ns" port-forward "$target" "$ports" >/dev/null 2>&1 &
    pid=$!
    # Detach from job control so that terminating it later does not print a
    # "Terminated" line in the middle of a demo.
    disown "$pid" 2>/dev/null || true
    sleep 2
    if kill -0 "$pid" 2>/dev/null; then
      PF_PIDS+=("$pid")
      echo "$pid"
      return 0
    fi
    sleep 2
  done
  die "could not port-forward $ports to $target in namespace $ns"
}

# reap_stale_forward <local-port> — terminate only our own leftover forwards
reap_stale_forward() {
  local lport="$1" pid
  for pid in $(pgrep -f "port-forward .*${lport}:" 2>/dev/null); do
    # Only kill kubectl port-forwards aimed at this cluster.
    if ps -o command= -p "$pid" 2>/dev/null | grep -q "kubectl .*$KCTX .*port-forward"; then
      kill "$pid" 2>/dev/null || true
      warn "reaped a stale port-forward on :$lport (pid $pid)"
    fi
  done
  sleep 1
}

cleanup_port_forwards() {
  for pid in "${PF_PIDS[@]:-}"; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  done
  PF_PIDS=()
}

# hosts_are_mapped — true when every demo hostname resolves to loopback
hosts_are_mapped() {
  local h
  for h in "${HOSTS[@]}"; do
    grep -qE "^[^#]*[[:space:]]${h}([[:space:]]|$)" /etc/hosts || return 1
  done
  return 0
}

hosts_instructions() {
  cat <<EOF

  The demo is addressed by hostname, because single sign-on across *different*
  origins is the point — two apps on one hostname would share a cookie and prove
  nothing. Add the entries with:

      ${B}sudo make hosts${R}

  or by hand, appending to /etc/hosts:

      127.0.0.1 ${HOSTS[*]}

EOF
}
