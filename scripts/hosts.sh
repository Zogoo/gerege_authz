#!/usr/bin/env bash
#
# Adds the demo hostnames to /etc/hosts. Needs root, so run it as
#   sudo make hosts
#
# Five separate hostnames, not five paths on one, because claim C2 is single
# sign-on across *different origins*. Two applications sharing a hostname would
# share a cookie, and the demonstration would prove nothing about the identity
# layer (mvp_docs/06 §3).
#
# `.local.test` is used rather than `.local`, which macOS routes through mDNS
# and treats specially.

set -euo pipefail

MARK="# gerege-idp-mvp"
HOSTS=(id.local.test profile.local.test smarthome.local.test account.local.test device.local.test)

if [[ "${1:-}" == "--remove" ]]; then
  [[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
  cp /etc/hosts "/etc/hosts.gerege-backup.$(date +%s)"
  sed -i.bak "/${MARK}/d" /etc/hosts
  echo "removed the gerege-idp entries from /etc/hosts"
  exit 0
fi

missing=()
for h in "${HOSTS[@]}"; do
  grep -qE "^[^#]*[[:space:]]${h}([[:space:]]|$)" /etc/hosts || missing+=("$h")
done

if [[ ${#missing[@]} -eq 0 ]]; then
  echo "all demo hostnames already resolve to loopback — nothing to do"
  exit 0
fi

if [[ $EUID -ne 0 ]]; then
  cat <<EOF
These hostnames are missing from /etc/hosts:

    ${missing[*]}

Run:

    sudo make hosts

or append this line to /etc/hosts yourself:

    127.0.0.1 ${HOSTS[*]}  ${MARK}
EOF
  exit 1
fi

cp /etc/hosts "/etc/hosts.gerege-backup.$(date +%s)"
printf '127.0.0.1 %s  %s\n' "${HOSTS[*]}" "$MARK" >> /etc/hosts
echo "added: 127.0.0.1 ${HOSTS[*]}"
echo "a backup of the previous /etc/hosts was saved alongside it"
