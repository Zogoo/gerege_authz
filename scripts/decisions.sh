#!/usr/bin/env bash
#
# The authorization decision log, one line per decision.
#
# mvp_docs/04 §8: every denial carries a machine-readable reason, because "403
# Forbidden" with no explanation makes a demo impossible to narrate and a
# production incident impossible to triage.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

N="${1:-30}"
FOLLOW=""
[[ "${1:-}" == "-f" ]] && { FOLLOW="-f"; N=30; }

fmt() {
  python3 -c '
import sys, json
hdr = "%-22s %-7s %-26s %-30s %-14s %-9s %-9s %-22s %s"
print(hdr % ("ENFORCER","METHOD","PATH","RESOURCE","PERMISSION","PRINCIPAL","ACTOR","REASON","VERDICT"))
print("-"*162)
for line in sys.stdin:
    try: d = json.loads(line)
    except Exception: continue
    if d.get("msg") != "authz.decision": continue
    print(hdr % (
        (d.get("enforcer") or "-")[:22],
        (d.get("method") or "-")[:7],
        (d.get("path") or "-")[:26],
        (d.get("resource") or ("rule:"+(d.get("rule") or "-")))[:30],
        (d.get("permission") or "-")[:14],
        (d.get("principal") or "-")[:9],
        (d.get("actor") or "\u2014")[:9],
        (d.get("reason") or "-")[:22],
        "ALLOW" if d.get("allowed") else "DENY"))
    sys.stdout.flush()'
}

if [[ -n "$FOLLOW" ]]; then
  k -n id logs -f deploy/ext-authz --tail=20 | fmt
else
  k -n id logs deploy/ext-authz --tail=800 | fmt | tail -n "$((N+2))"
fi
