#!/usr/bin/env bash
#
# The five scenarios from mvp_docs/05, driven from the terminal one keypress at
# a time. Everything here can also be done in a browser; this exists so the
# decisions are visible as data rather than as pages.
#
#   scripts/demo.sh            all scenarios
#   scripts/demo.sh 2 3b 5     the three a sceptical reviewer should ask for
#   scripts/demo.sh 6          the agent
#   NOPAUSE=1 scripts/demo.sh  no keypresses

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
trap cleanup_port_forwards EXIT

RESOLVE=()
for h in "${HOSTS[@]}"; do RESOLVE+=(--resolve "${h}:80:127.0.0.1"); done
BODY=$(mktemp); HDRS=$(mktemp)
trap 'cleanup_port_forwards; rm -f "$BODY" "$HDRS"' EXIT

pause() { [[ "${NOPAUSE:-}" == "1" ]] && return 0; printf '\n    %s[enter]%s ' "$DIM" "$R"; read -r _ || true; }
say()   { printf '\n%s%s%s\n' "$B" "$*" "$R"; }
why()   { printf '%s    %s%s\n' "$DIM" "$*" "$R"; }
cmd()   { printf '    %s$ %s%s\n' "$CYN" "$*" "$R"; }

# req <method> <url> [token] [body]
req() {
  local method="$1" url="$2" token="${3:-}" body="${4:-}"
  local args=(-s -o "$BODY" -D "$HDRS" -w '%{http_code}' -X "$method" "${RESOLVE[@]}"
              -H 'accept: application/json' "$url")
  [[ -n "$token" ]] && args+=(-H "authorization: Bearer $token")
  [[ -n "$body"  ]] && args+=(-H 'content-type: application/json' -d "$body")
  LAST_CODE=$(curl "${args[@]}")
  LAST_REASON=$(tr -d '\r' < "$HDRS" | awk -F': ' 'tolower($1)=="x-authz-reason"{print $2}' | tail -1)
  local verdict="${RED} DENIED   ${R}"
  [[ "$LAST_CODE" =~ ^2 ]] && verdict="${GRN} PERMITTED${R}"
  printf '    %s  %sHTTP %s%s  reason=%s\n' "$verdict" "$DIM" "$LAST_CODE" "$R" "${LAST_REASON:--}"
  head -c 320 "$BODY" | sed 's/^/      /'; echo
}

token() {
  curl -s "${RESOLVE[@]}" -X POST \
    "http://id.local.test/realms/gerege/protocol/openid-connect/token" \
    -d grant_type=password -d "client_id=$1" -d "client_secret=$2" \
    -d "username=$3" -d "password=$4" \
  | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}

client_token() {
  curl -s "${RESOLVE[@]}" -X POST \
    "http://id.local.test/realms/gerege/protocol/openid-connect/token" \
    -d grant_type=client_credentials -d "client_id=$1" -d "client_secret=$2" \
  | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}

ZED=(zed --endpoint localhost:50051 --token gerege-mvp-key --insecure)
zed_up()   { port_forward id svc/spicedb 50051:50051 >/dev/null; }
zed_down() { cleanup_port_forwards; }

grant_all() {
  "${ZED[@]}" relationship touch "gerege/consent_grant:alice|smarthome-app" subject gerege/user:alice >/dev/null
  "${ZED[@]}" relationship touch "gerege/consent_grant:alice|smarthome-app" grantee gerege/application:smarthome-app >/dev/null
  local c
  for c in profile_read devices_view devices_control devices_unlock; do
    "${ZED[@]}" relationship touch "gerege/consent_grant:alice|smarthome-app" granted "gerege/capability:$c" >/dev/null
  done
}

decisions() {
  local n="${1:-20}"
  k -n id logs deploy/ext-authz --tail=600 2>/dev/null \
    | grep '"msg":"authz.decision"' | tail -"$n" \
    | python3 -c '
import sys, json
hdr = "      %-22s %-7s %-30s %-14s %-9s %-21s %s"
print(hdr % ("ENFORCER","METHOD","RESOURCE / RULE","PERMISSION","ACTOR","REASON","VERDICT"))
for line in sys.stdin:
    try: d = json.loads(line)
    except Exception: continue
    print(hdr % (
        (d.get("enforcer") or "-")[:22], d.get("method","-"),
        (d.get("resource") or ("rule:"+(d.get("rule") or "-")))[:30],
        (d.get("permission") or "-")[:14],
        (d.get("actor") or "—")[:9],
        (d.get("reason") or "-")[:21],
        "ALLOW" if d.get("allowed") else "DENY"))'
}

# ---------------------------------------------------------------------------
scenario_1() {
  say "Scenario 1 — authentication and single sign-on   (C1, C2)"
  why "Run this one in a browser; the redirect chain is the evidence."
  cat <<EOF

    1. Open http://profile.local.test in a fresh browser window
       → redirected to Keycloak. Log in as alice / alice
    2. You land back on the profile app, which renders Alice's profile
    3. Reload — no redirect; the session cookie is enough
    4. Open http://smarthome.local.test in the SAME browser
       → it renders immediately. No login page.
    5. Sign out from either app → both require login again

    Step 4 is the claim. The smart-home app is a different origin and holds no
    cookie of its own. ext-authz starts a complete OIDC flow and Keycloak
    answers with an authorization code without prompting, because it still holds
    Alice's realm SSO session.

    A shared-cookie trick would look identical here while proving nothing about
    the identity layer. Watch the browser network panel: the redirect chain
    through Keycloak is the difference.

    Step 5 is the counterpart — single sign-on implies single sign-out.

    The scripted form of this is A1-A3 in 'make verify'.
EOF
  pause
}

scenario_2() {
  say "Scenario 2 — authorization is data, not deployed code   (C4)"
  why "The step that matters is 3 → 4: one relationship, no redeploy, same token."
  zed_up
  local BOB ALICE
  ALICE=$(token profile-app profile-app-secret alice alice)
  BOB=$(token profile-app profile-app-secret bob bob)

  echo; cmd "GET /profile/alice      as alice"
  req GET "http://profile.local.test/profile/alice" "$ALICE"
  pause

  echo; cmd "GET /profile/alice      as bob"
  req GET "http://profile.local.test/profile/alice" "$BOB"
  why "Bob holds a perfectly valid token. He has no relationship to that profile."
  pause

  echo; cmd "zed relationship create gerege/user_profile:alice reader gerege/user:bob"
  "${ZED[@]}" relationship create gerege/user_profile:alice reader gerege/user:bob | sed 's/^/      /'
  why "One relationship written. Nothing rebuilt, restarted, reloaded or reissued."
  pause

  echo; cmd "GET /profile/alice      as bob — the same token as before"
  req GET "http://profile.local.test/profile/alice" "$BOB"
  why "This is what separates relationship-based authorization from roles in a token:"
  why "with roles, this change means editing a role, reissuing tokens, and waiting out the old ones."
  pause

  echo; cmd "zed relationship delete gerege/user_profile:alice reader gerege/user:bob"
  "${ZED[@]}" relationship delete gerege/user_profile:alice reader gerege/user:bob | sed 's/^/      /'
  req GET "http://profile.local.test/profile/alice" "$BOB"
  why "Revocation is deletion and it takes effect on the next request — the MVP does not cache."
  zed_down; pause
}

scenario_3a() {
  say "Scenario 3a — consent gates a third-party application   (C5, C6)"
  why "Same user, same record, same permission. Different application, different answer."
  zed_up
  local VIA_PROFILE VIA_SMART
  VIA_PROFILE=$(token profile-app profile-app-secret alice alice)
  VIA_SMART=$(token smarthome-app smarthome-app-secret alice alice)
  "${ZED[@]}" relationship delete "gerege/consent_grant:alice|smarthome-app" granted gerege/capability:profile_read >/dev/null 2>&1 || true

  echo; cmd "profile-app reads Alice's profile        (first-party)"
  req GET "http://profile.local.test/profile/alice" "$VIA_PROFILE"
  why "No consent prompt. Alice acting on her own data through her own app is not a disclosure."
  pause

  echo; cmd "smarthome-app reads the same record      (third-party)"
  req GET "http://smarthome.local.test/myprofile" "$VIA_SMART"
  why "The only variable is the azp claim — the application the user would be consenting to."
  why "In a browser the denial carries a link to the consent screen."
  pause

  echo; cmd "Alice consents   (in a browser: http://account.local.test)"
  "${ZED[@]}" relationship touch "gerege/consent_grant:alice|smarthome-app" subject gerege/user:alice >/dev/null
  "${ZED[@]}" relationship touch "gerege/consent_grant:alice|smarthome-app" grantee gerege/application:smarthome-app >/dev/null
  "${ZED[@]}" relationship touch "gerege/consent_grant:alice|smarthome-app" granted gerege/capability:profile_read | sed 's/^/      /'
  pause

  echo; cmd "smarthome-app retries the identical request"
  req GET "http://smarthome.local.test/myprofile" "$VIA_SMART"
  why "The token was never reissued. Consent is evaluated at the resource, not carried in the credential."
  pause

  echo; cmd "Alice revokes"
  "${ZED[@]}" relationship delete "gerege/consent_grant:alice|smarthome-app" granted gerege/capability:profile_read | sed 's/^/      /'
  req GET "http://smarthome.local.test/myprofile" "$VIA_SMART"
  zed_down; pause
}

scenario_3b() {
  say "Scenario 3b — the internal hop is independently authorized   (C3)"
  why "The proof that internal enforcement is real and not decorative."
  zed_up
  local ALICE; ALICE=$(token smarthome-app smarthome-app-secret alice alice)
  grant_all

  echo; cmd "POST /home/alice-home/devices/lock-1/unlock      as alice, owner of the home"
  req POST "http://smarthome.local.test/home/alice-home/devices/lock-1/unlock" "$ALICE"
  pause

  echo; cmd "the decision log for that one click"
  decisions 6
  why "Three decisions for one click, at three enforcement points: the ingress gateway,"
  why "smarthome-service's sidecar, and device-service's sidecar."
  why ""
  why "They ask different questions. The first two ask whether Alice may see this home."
  why "The third asks whether she may unlock this particular lock — and that is the one"
  why "a gateway-only architecture never gets to ask."
  pause

  echo; cmd "Downgrade Alice from owner to guest of her own home"
  "${ZED[@]}" relationship delete gerege/home:alice-home owner gerege/user:alice | sed 's/^/      /'
  "${ZED[@]}" relationship create gerege/home:alice-home guest gerege/user:alice | sed 's/^/      /'
  pause

  echo; cmd "GET /home/alice-home        — can she still see the home?"
  req GET "http://smarthome.local.test/home/alice-home" "$ALICE"
  why "Yes. A guest may view, so the edge check passes and the request reaches smarthome-service."
  echo; cmd "POST .../lock-1/unlock      — can she still open the door?"
  req POST "http://smarthome.local.test/home/alice-home/devices/lock-1/unlock" "$ALICE"
  why "No. operate_lock derives from administrate, and a guest is not an administrator."
  why "The external call succeeded and the internal one did not."
  why "A gateway-only architecture would have opened the door here."
  pause

  echo; cmd "Restore Alice as owner"
  "${ZED[@]}" relationship delete gerege/home:alice-home guest gerege/user:alice >/dev/null
  "${ZED[@]}" relationship create gerege/home:alice-home owner gerege/user:alice | sed 's/^/      /'
  req POST "http://smarthome.local.test/home/alice-home/devices/lock-1/unlock" "$ALICE"
  zed_down; pause
}

scenario_3c() {
  say "Scenario 3c — token replay is contained   (C3)"
  why "Nothing about the token is wrong. It is valid, unexpired, and Alice's."
  local ALICE; ALICE=$(token smarthome-app smarthome-app-secret alice alice)

  echo; cmd "Replay Alice's token straight at device-service, bypassing smarthome-service"
  req POST "http://device.local.test/internal/devices/lock-1/unlock" "$ALICE"
  why "Refused: workload_not_registered. The route's caller list holds smarthome-service"
  why "and nothing else, and the mesh proves the caller's identity with mTLS —"
  why "which is why a compromised peer cannot forge it."
  why ""
  why "Replay is contained by the consent graph and the workload registry, not by"
  why "anything about the token's scope or audience. That is a stronger property"
  why "than audience-restricted tokens: it is enforced at the resource, evaluated"
  why "fresh, and revocable in seconds."
  pause
}

scenario_4() {
  say "Scenario 4 — device identity   (C7)"
  why "A non-human principal, authorized on its own relationships. No user, no consent."
  local SENSOR; SENSOR=$(client_token sensor-1 sensor-1-secret)

  echo; cmd "sensor-1 obtains a token with the client-credentials grant"
  printf '      subject: %s\n' \
    "$(echo "$SENSOR" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | sed -n 's/.*"preferred_username":"\([^"]*\)".*/\1/p')"
  why "A service account, not a person. Consent does not apply: there is no user in the loop,"
  why "and a consent record nobody granted is one nobody can revoke."
  pause

  echo; cmd "POST /telemetry/sensor-1        — its own readings"
  req POST "http://device.local.test/telemetry/sensor-1" "$SENSOR" '{"temperature":21.4,"humidity":47}'
  pause

  echo; cmd "POST /telemetry/thermostat-1    — another device's readings"
  req POST "http://device.local.test/telemetry/thermostat-1" "$SENSOR" '{"temperature":21.4,"humidity":47}'
  echo; cmd "GET  /profile/alice             — a user's data"
  req GET "http://profile.local.test/profile/alice" "$SENSOR"
  why "A device identity is not a skeleton key: sensor-1 holds exactly one relationship,"
  why "to exactly one device."
  echo; cmd "POST /telemetry/sensor-1        — with no credentials at all"
  req POST "http://device.local.test/telemetry/sensor-1" "" '{"temperature":21.4}'
  pause
}

scenario_5() {
  say "Scenario 5 — fail closed   (C8)"
  why "Short, unambiguous, and the property most systems get wrong."
  local ALICE; ALICE=$(token profile-app profile-app-secret alice alice)

  echo; cmd "A working request, to establish the baseline"
  req GET "http://profile.local.test/profile/alice" "$ALICE"
  pause

  echo; cmd "kubectl -n id scale deploy/spicedb --replicas=0"
  k -n id scale deploy/spicedb --replicas=0 >/dev/null
  k -n id wait --for=delete pod -l app=spicedb --timeout=120s >/dev/null 2>&1 || sleep 10
  why "The authorization backend is now gone."
  pause

  echo; cmd "The same request, six times"
  local permitted=0 i
  for i in 1 2 3 4 5 6; do
    req GET "http://profile.local.test/profile/alice" "$ALICE"
    [[ "$LAST_CODE" =~ ^2 ]] && permitted=$((permitted+1))
  done
  if [[ $permitted -eq 0 ]]; then
    printf '\n    %s✓ never permitted, not once%s\n' "$GRN" "$R"
  else
    printf '\n    %s✗ PERMITTED %d of 6 — claim C8 is broken%s\n' "$RED" "$permitted" "$R"
  fi
  why "A system that permits when it cannot decide is worse than no authorization at all,"
  why "because the confidence it creates is false exactly when things are going wrong."
  pause

  echo; cmd "An endpoint with no authorization rule"
  req GET "http://profile.local.test/undeclared-endpoint" "$ALICE"
  why "Deny by default. The commonest real mistake in this architecture — shipping an"
  why "endpoint without a rule — becomes a 403 someone notices in minutes, rather than"
  why "an open endpoint nobody finds for months."
  pause

  echo; cmd "kubectl -n id scale deploy/spicedb --replicas=1"
  k -n id scale deploy/spicedb --replicas=1 >/dev/null
  k -n id rollout status deploy/spicedb --timeout=180s >/dev/null
  sleep 4
  req GET "http://profile.local.test/profile/alice" "$ALICE"
  pause
}

scenario_6() {
  say "Scenario 6 — an agent acting for Alice   (C9)"
  why "The agent holds Alice's token and Alice's consent. That is not enough."
  zed_up
  local ALICE; ALICE=$(token smarthome-app smarthome-app-secret alice alice)
  grant_all
  "${ZED[@]}" relationship bulk-delete gerege/delegation --force >/dev/null 2>&1 || true

  ask_agent() {
    curl -s "${RESOLVE[@]}" -H 'accept: application/json' -H "authorization: Bearer $ALICE" \
      "http://smarthome.local.test/assistant?task=${1}" \
    | python3 -c "
import sys,json
d=json.load(sys.stdin)
if 'steps' not in d: print('      ' + json.dumps(d)[:220]); raise SystemExit
print('      acting for %s  as  %s   (token exchanged: %s)' % (d['principal'], d['agent'], d['token_exchanged']))
for s in d.get('steps') or []:
    print('      %s  %-16s %-16s %s' % ('PERMITTED' if s['permitted'] else 'REFUSED  ',
          s['action'], s['capability'], s.get('reason') or ''))"
  }

  echo; cmd "The agent obtains an identity of its own — RFC 8693 token exchange"
  why "sub stays alice. azp becomes assistant-agent. The person who is accountable and"
  why "the actor that is running are now two different things in one token."
  pause

  echo; cmd "Ask the assistant to do everything it can think of"
  ask_agent everything
  why "Every one of those refusals is a delegation_required. Alice's own permissions are"
  why "intact and her consent to Smart Home is granted — the agent simply holds no"
  why "delegation. This is the difference between an agent and a service account."
  pause

  echo; cmd "Alice delegates two capabilities, for five minutes"
  EXP=$(python3 -c "import datetime;print((datetime.datetime.now(datetime.UTC)+datetime.timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ'))")
  "${ZED[@]}" relationship touch "gerege/delegation:alice|assistant" delegator gerege/user:alice >/dev/null
  "${ZED[@]}" relationship touch "gerege/delegation:alice|assistant" delegate gerege/agent:assistant >/dev/null
  "${ZED[@]}" relationship touch "gerege/delegation:alice|assistant" granted "gerege/capability:profile_read[expiration:$EXP]" | sed 's/^/      /'
  "${ZED[@]}" relationship touch "gerege/delegation:alice|assistant" granted "gerege/capability:devices_control[expiration:$EXP]" >/dev/null
  why "In a browser: http://account.local.test/delegate?agent=assistant"
  pause

  echo; cmd "Ask again"
  ask_agent everything
  why "Exactly what was delegated, and nothing else. The agent never gained the ability"
  why "to look at the devices or open the door — those were not delegated."
  pause

  echo; cmd "The door, specifically"
  why "devices_unlock is a step-up capability: it requires a person who authenticated"
  why "deliberately. An agent cannot re-authenticate the human behind it, so this route"
  why "is closed to it by construction — not by a policy that could be granted later."
  echo; cmd "Alice does the same unlock herself"
  req POST "http://smarthome.local.test/home/alice-home/devices/lock-1/unlock" "$ALICE"
  why "Same user, same lock, same permission. The difference is that a person is here."
  pause

  echo; cmd "The decision log"
  decisions 8
  why "principal=alice throughout — she stays accountable. The ACTOR column is what"
  why "separates the hops she made herself from the hops the agent made for her."
  why "That column is the thing legacy IAM cannot produce."
  pause

  echo; cmd "Alice withdraws the delegation"
  "${ZED[@]}" relationship bulk-delete gerege/delegation --force 2>&1 | sed 's/^/      /'
  ask_agent everything
  why "Withdrawal is deletion, and it lands on the next call. The delegations would also"
  why "have expired on their own — which is the part that matters, because nobody has to"
  why "remember to do this."
  zed_down; pause
}

main() {
  local want=("$@")
  [[ ${#want[@]} -eq 0 ]] && want=(1 2 3a 3b 3c 4 5 6)
  local s
  for s in "${want[@]}"; do
    case "$s" in
      1)  scenario_1 ;;
      2)  scenario_2 ;;
      3a) scenario_3a ;;
      3b) scenario_3b ;;
      3c) scenario_3c ;;
      3)  scenario_3a; scenario_3b; scenario_3c ;;
      4)  scenario_4 ;;
      5)  scenario_5 ;;
      6)  scenario_6 ;;
      *)  die "unknown scenario '$s' (try: 1 2 3a 3b 3c 4 5)" ;;
    esac
  done
  say "Done."
  why "'make verify' runs all of this unattended, as assertions."
}

main "$@"
