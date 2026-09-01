#!/usr/bin/env bash
#
# Onboarding and offboarding for non-human identities.
#
#   scripts/lifecycle.sh onboard-device  NAME OPERATOR [HOME]
#   scripts/lifecycle.sh offboard-device NAME
#   scripts/lifecycle.sh onboard-agent   NAME OPERATOR CLIENT WORKLOAD
#   scripts/lifecycle.sh enrol-agent     NAME USER
#   scripts/lifecycle.sh offboard-agent  NAME
#   scripts/lifecycle.sh inventory
#
# Registering a device used to mean editing four things by hand across Keycloak,
# the authorizer's config, SpiceDB and a Kubernetes manifest, in an order nobody
# had written down, with no record of who did it or why. That is IBM's
# "fragmented controls across identity and secrets" gap, and it is the one this
# project demonstrated the other three while still having.
#
# Two rules hold throughout:
#
#   * Nothing non-human is created without a named human operator. Onboarding
#     refuses; `inventory` fails if one ever appears unowned.
#   * Offboarding deletes the SpiceDB relationships FIRST. That is the moment
#     the thing stops working — everything after it is cleanup, because the
#     authority was never in the credential.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
trap cleanup_port_forwards EXIT

REALM=gerege
KC_HOST=id.local.test
RESOLVE=(--resolve "${KC_HOST}:80:127.0.0.1")
ZED=(zed --endpoint localhost:50051 --token gerege-mvp-key --insecure --skip-version-check)

# Every verification below passes --consistency-full. A check immediately after a
# write must read its own write, and the default consistency reads at a quantized
# revision — so a freshly written relationship is briefly invisible. Verifying at
# anything less would report a correct onboarding as a failure, and would
# eventually report a failed one as a success (mvp_docs/03 §6).

connect() {
  k get ns id >/dev/null 2>&1 || die "the cluster is not up. Run: make up"
  port_forward id svc/spicedb 50051:50051 >/dev/null
}

# --- Keycloak admin API. Incremental: no realm re-import, nothing destroyed. -
kc_token() {
  curl -s "${RESOLVE[@]}" -X POST "http://$KC_HOST/realms/master/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=admin-cli -d username=admin -d password=admin \
    | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}

kc_client_id() {  # kc_client_id <token> <clientId> → internal uuid, or empty
  curl -s "${RESOLVE[@]}" -H "authorization: Bearer $1" \
    "http://$KC_HOST/admin/realms/$REALM/clients?clientId=$2" \
    | python3 -c "import sys,json;d=json.load(sys.stdin);print(d[0]['id'] if d else '')"
}

# kc_upsert_client <token> <clientId> <json-file>
#
# Creates the client, or updates it if it already exists. "Already exists" is not
# the same as "already correct": offboarding disables the client rather than
# deleting it, so re-onboarding a decommissioned device would otherwise leave a
# disabled identity behind and report success. Onboarding has to converge on the
# configuration it declares, not merely observe that something is there.
#
# The body comes from a file rather than an inline string: a JSON document built
# by interpolating into a shell command substitution is one quoting mistake away
# from being silently mangled, and the failure surfaces as an opaque 500.
kc_upsert_client() {
  local token="$1" client_id="$2" body="$3" uuid code
  uuid=$(kc_client_id "$token" "$client_id")

  if [[ -n "$uuid" ]]; then
    code=$(curl -s -o /dev/null -w '%{http_code}' "${RESOLVE[@]}" -X PUT \
      -H "authorization: Bearer $token" -H 'content-type: application/json' \
      "http://$KC_HOST/admin/realms/$REALM/clients/$uuid" --data-binary "@$body")
    [[ "$code" == "204" ]] || die "Keycloak refused to update the client ($code)"
    return
  fi

  code=$(curl -s -o /dev/null -w '%{http_code}' "${RESOLVE[@]}" -X POST \
    -H "authorization: Bearer $token" -H 'content-type: application/json' \
    "http://$KC_HOST/admin/realms/$REALM/clients" --data-binary "@$body")
  [[ "$code" == "201" ]] || die "Keycloak refused the client ($code)"
}

# kc_assert_enabled <token> <clientId> — onboarding claims a working identity,
# so it verifies one rather than assuming the write landed.
kc_assert_enabled() {
  local state
  state=$(curl -s "${RESOLVE[@]}" -H "authorization: Bearer $1" \
    "http://$KC_HOST/admin/realms/$REALM/clients?clientId=$2" \
    | python3 -c "import sys,json;d=json.load(sys.stdin);print(d[0]['enabled'] if d else 'missing')")
  [[ "$state" == "True" ]] || die "Keycloak client $2 is not usable (enabled=$state)"
}

kc_disable_client() {  # kc_disable_client <token> <clientId>
  local uuid; uuid=$(kc_client_id "$1" "$2")
  [[ -z "$uuid" ]] && { info "no Keycloak client $2"; return; }
  curl -s -o /dev/null -w '' "${RESOLVE[@]}" -X PUT \
    -H "authorization: Bearer $1" -H 'content-type: application/json' \
    "http://$KC_HOST/admin/realms/$REALM/clients/$uuid" -d '{"enabled":false}'
  ok "Keycloak client $2 disabled (no new tokens)"
}

# --- the authorizer's registry ----------------------------------------------
# ext-authz re-reads this file on a timer, so onboarding never restarts the one
# component every request depends on.
patch_registry() {  # patch_registry <python-snippet>
  mark_reload_point
  local tmp; tmp=$(mktemp)
  k -n id get configmap ext-authz-config -o jsonpath='{.data.config\.yaml}' > "$tmp"
  python3 - "$tmp" "$1" <<'PY'
import sys, re
path, op = sys.argv[1], sys.argv[2]
s = open(path).read()
kind, name, obj, workload = (op.split("|") + ["", "", ""])[:4]

if kind == "add-device":
    if re.search(r"^\s+%s:\s" % re.escape(name), s, re.M):
        pass
    else:
        s = s.replace("systemPrincipals:\n", "systemPrincipals:\n  %s: %s\n" % (name, name), 1)
elif kind == "del-device":
    s = re.sub(r"^\s+%s:\s.*\n" % re.escape(name), "", s, flags=re.M)
elif kind == "add-agent":
    if ("name: %s" % name) not in s:
        entry = "  - name: %s\n    object: %s\n    displayName: %s\n" % (name, obj, obj)
        if workload:
            entry += "    workload: %s\n" % workload
        s = s.replace("agents:\n", "agents:\n" + entry, 1)
elif kind == "del-agent":
    s = re.sub(r"  - name: %s\n(?:    .*\n)*" % re.escape(name), "", s)
open(path, "w").write(s)
PY
  k -n id create configmap ext-authz-config --from-file=config.yaml="$tmp" \
    --dry-run=client -o yaml | k apply -f - >/dev/null
  rm -f "$tmp"
}

# wait_for_reload waits for a reload that happened *after* the change was made.
#
# The marker matters. Matching any recent "configuration reloaded" line will
# happily match a previous one and report success before the new registry is
# live — which then surfaces as a freshly onboarded device being refused with
# `unknown_application`, a long way from the cause.
RELOAD_MARK=""
mark_reload_point() { RELOAD_MARK=$(date -u +%Y-%m-%dT%H:%M:%SZ); }

wait_for_reload() {
  [[ -n "$RELOAD_MARK" ]] || mark_reload_point
  info "waiting for ext-authz to pick up the registry change…"
  local i
  for i in $(seq 1 30); do
    if k -n id logs deploy/ext-authz --since-time="$RELOAD_MARK" 2>/dev/null \
       | grep -q '"msg":"configuration reloaded"'; then
      ok "authorizer reloaded — no restart"
      return 0
    fi
    sleep 5
  done
  die "the authorizer did not reload within 150s; the registry change is not live"
}

# ---------------------------------------------------------------------------
onboard_device() {
  local name="$1" operator="$2" home="${3:-alice-home}"
  [[ -n "$name" && -n "$operator" ]] || die "usage: onboard-device NAME OPERATOR [HOME]"
  connect
  step "Onboarding device '$name', operated by '$operator'"

  local at; at=$(kc_token)
  [[ -n "$at" ]] || die "cannot authenticate to Keycloak"

  local body; body=$(mktemp)
  cat > "$body" <<JSON
{
  "clientId": "$name",
  "name": "$name (IoT device identity)",
  "description": "Non-human principal. Client credentials only — no browser flow.",
  "enabled": true,
  "protocol": "openid-connect",
  "publicClient": false,
  "secret": "$name-secret",
  "standardFlowEnabled": false,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "serviceAccountsEnabled": true,
  "consentRequired": false,
  "redirectUris": [],
  "webOrigins": []
}
JSON
  kc_upsert_client "$at" "$name" "$body"
  rm -f "$body"
  kc_assert_enabled "$at" "$name"
  ok "Keycloak client '$name' registered and enabled (client_credentials only)"

  patch_registry "add-device|$name"
  ok "authorizer registry updated"

  # Ownership first, and in the same breath as the identity. A non-human
  # identity that exists without an operator is the thing that becomes
  # ungoverned (docs/09 §4 rule 2).
  "${ZED[@]}" relationship touch "gerege/system_principal:$name" operator "gerege/user:$operator" >/dev/null
  "${ZED[@]}" relationship touch "gerege/device:$name" home "gerege/home:$home" >/dev/null
  "${ZED[@]}" relationship touch "gerege/device:$name" self "gerege/system_principal:$name" >/dev/null
  ok "relationships written: owned by $operator, in $home, authorized for its own telemetry"

  local got
  got=$("${ZED[@]}" permission check --consistency-full "gerege/device:$name" push_telemetry "gerege/system_principal:$name" 2>/dev/null | tail -1)
  [[ "$got" == "true" ]] || die "verification failed: the device cannot push its own telemetry"
  ok "verified: $name may push its own telemetry"
  got=$("${ZED[@]}" permission check --consistency-full "gerege/system_principal:$name" administrate "gerege/user:$operator" 2>/dev/null | tail -1)
  [[ "$got" == "true" ]] || die "verification failed: $operator is not recorded as the operator"
  ok "verified: $operator is accountable for $name"
  wait_for_reload
  echo; info "the device's credential is ${B}$name-secret${R} — deliver it out of band"
}

offboard_device() {
  local name="$1"
  [[ -n "$name" ]] || die "usage: offboard-device NAME"
  connect
  step "Offboarding device '$name'"

  # Authority first. This is the moment it stops working.
  "${ZED[@]}" relationship bulk-delete "gerege/device:$name" --force >/dev/null 2>&1 || true
  "${ZED[@]}" relationship bulk-delete "gerege/system_principal:$name" --force >/dev/null 2>&1 || true
  ok "relationships deleted — the device is powerless as of the next request"

  local got
  got=$("${ZED[@]}" permission check --consistency-full "gerege/device:$name" push_telemetry "gerege/system_principal:$name" 2>/dev/null | tail -1)
  [[ "$got" == "false" ]] || die "the device can still act — offboarding did not take effect"
  ok "verified: $name can no longer push telemetry"

  kc_disable_client "$(kc_token)" "$name"
  patch_registry "del-device|$name"
  ok "authorizer registry cleaned up"
  wait_for_reload
}

onboard_agent() {
  local name="$1" operator="$2" client="${3:-$name-agent}" workload="$4"
  [[ -n "$name" && -n "$operator" ]] || die "usage: onboard-agent NAME OPERATOR [CLIENT] [WORKLOAD-SPIFFE]"
  connect
  step "Onboarding agent '$name' (client '$client'), operated by '$operator'"

  local at; at=$(kc_token)
  [[ -n "$at" ]] || die "cannot authenticate to Keycloak"

  local body; body=$(mktemp)
  cat > "$body" <<JSON
{
  "clientId": "$client",
  "name": "$name (AI agent)",
  "description": "A delegated actor. Obtains its identity by exchanging a user's token (RFC 8693).",
  "enabled": true,
  "protocol": "openid-connect",
  "publicClient": false,
  "secret": "$client-secret",
  "standardFlowEnabled": false,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "serviceAccountsEnabled": false,
  "consentRequired": false,
  "redirectUris": [],
  "webOrigins": [],
  "attributes": { "standard.token.exchange.enabled": "true" }
}
JSON
  kc_upsert_client "$at" "$client" "$body"
  rm -f "$body"
  kc_assert_enabled "$at" "$client"
  ok "Keycloak client '$client' registered and enabled (token exchange only — no browser flow, no service account)"

  patch_registry "add-agent|$client|$name|$workload"
  ok "authorizer registry updated${workload:+ (bound to $workload)}"

  "${ZED[@]}" relationship touch "gerege/agent:$name" operator "gerege/user:$operator" >/dev/null
  ok "relationship written: owned by $operator"

  local got
  got=$("${ZED[@]}" permission check --consistency-full "gerege/agent:$name" administrate "gerege/user:$operator" 2>/dev/null | tail -1)
  [[ "$got" == "true" ]] || die "verification failed: $operator is not recorded as the operator"
  ok "verified: $operator is accountable for $name"
  got=$("${ZED[@]}" permission check --consistency-full "gerege/agent:$name" act_for "gerege/user:$operator" 2>/dev/null | tail -1)
  [[ "$got" == "false" ]] || die "the agent is already enrolled — it should start enrolled for nobody"
  ok "verified: enrolled for nobody yet — it can act for no one until enrolled"
  wait_for_reload
  echo; info "enrol it for a user with: ${B}make enrol-agent NAME=$name USER=<user>${R}"
}

enrol_agent() {
  local name="$1" user="$2"
  [[ -n "$name" && -n "$user" ]] || die "usage: enrol-agent NAME USER"
  connect
  step "Enrolling agent '$name' to act for '$user'"
  "${ZED[@]}" relationship touch "gerege/agent:$name" enrolled_for "gerege/user:$user" >/dev/null
  local got
  got=$("${ZED[@]}" permission check --consistency-full "gerege/agent:$name" act_for "gerege/user:$user" 2>/dev/null | tail -1)
  [[ "$got" == "true" ]] || die "enrolment did not take effect"
  ok "verified: $name may act for $user — subject to whatever they delegate"
}

offboard_agent() {
  local name="$1" client="${2:-$name-agent}"
  [[ -n "$name" ]] || die "usage: offboard-agent NAME [CLIENT]"
  connect
  step "Offboarding agent '$name'"

  "${ZED[@]}" relationship bulk-delete "gerege/agent:$name" --force >/dev/null 2>&1 || true
  "${ZED[@]}" relationship bulk-delete gerege/delegation --subject-filter "gerege/agent:$name" --force >/dev/null 2>&1 || true
  ok "relationships and delegations deleted — the agent is powerless as of the next request"

  kc_disable_client "$(kc_token)" "$client"
  patch_registry "del-agent|$client"
  ok "authorizer registry cleaned up"
  wait_for_reload
}

# ---------------------------------------------------------------------------
# inventory answers "what non-human identities exist and who answers for them",
# and fails if anything is unowned. Runnable in CI.
inventory() {
  connect
  step "Non-human identities"
  local unowned=0

  printf '\n  %-22s %-18s %s\n' "IDENTITY" "KIND" "OPERATOR"
  printf '  %s\n' "$(printf '%.0s-' {1..62})"

  local line obj op kind
  for kind in agent system_principal; do
    while read -r line; do
      [[ -z "$line" ]] && continue
      obj=$(echo "$line" | awk '{print $1}' | cut -d: -f2-)
      op=$(echo "$line" | awk '{print $3}' | cut -d: -f2-)
      printf '  %-22s %-18s %s\n' "$obj" "$kind" "$op"
    done < <("${ZED[@]}" relationship read "gerege/$kind" 2>/dev/null | grep ' operator ' || true)

    # anything of this kind with no operator at all
    while read -r obj; do
      [[ -z "$obj" ]] && continue
      if ! "${ZED[@]}" relationship read "gerege/$kind:$obj" 2>/dev/null | grep -q ' operator '; then
        printf '  %-22s %-18s %s\n' "$obj" "$kind" "${RED}NONE${R}"
        unowned=$((unowned+1))
      fi
    done < <("${ZED[@]}" relationship read "gerege/$kind" 2>/dev/null | awk '{print $1}' | cut -d: -f2- | sort -u)
  done

  echo
  if [[ $unowned -gt 0 ]]; then
    die "$unowned non-human identity/identities have no operator. docs/09 §4 rule 2: accountability is a relationship, not a spreadsheet."
  fi
  ok "every non-human identity has a named operator"

  step "Live delegations"
  local rows
  rows=$("${ZED[@]}" relationship read gerege/delegation 2>/dev/null | grep ' granted ' || true)
  if [[ -z "$rows" ]]; then
    info "none — no agent currently holds authority from anyone"
  else
    printf '\n  %-26s %-18s %s\n' "DELEGATION" "CAPABILITY" "EXPIRES"
    printf '  %s\n' "$(printf '%.0s-' {1..70})"
    echo "$rows" | while read -r line; do
      printf '  %-26s %-18s %s\n' \
        "$(echo "$line" | awk '{print $1}' | cut -d: -f2-)" \
        "$(echo "$line" | awk '{print $3}' | cut -d: -f2- | cut -d'[' -f1)" \
        "$(echo "$line" | grep -o 'expiration:[^]]*' | cut -d: -f2- || echo 'never — this should not happen')"
    done
  fi
}

case "${1:-}" in
  onboard-device)  shift; onboard_device "$@" ;;
  offboard-device) shift; offboard_device "$@" ;;
  onboard-agent)   shift; onboard_agent "$@" ;;
  enrol-agent)     shift; enrol_agent "$@" ;;
  offboard-agent)  shift; offboard_agent "$@" ;;
  inventory)       shift; inventory "$@" ;;
  *) die "usage: $0 {onboard-device|offboard-device|onboard-agent|enrol-agent|offboard-agent|inventory} …" ;;
esac
