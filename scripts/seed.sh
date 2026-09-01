#!/usr/bin/env bash
#
# Applies the permission schema and the seed relationships, then verifies them.
#
# Deliberately not `zed import`. That command reads the schema already on the
# server, infers a definition prefix from it, and then prepends that prefix to
# every relationship in the file — so a file whose relationships are already
# written as `gerege/user_profile:...` imports cleanly into an empty SpiceDB and
# fails on every later run with `gerege/gerege/user_profile not found`. Writing
# the schema and touching each relationship explicitly is a few more lines and
# behaves the same way every time.
#
# `touch` rather than `create`: re-seeding an existing world must be idempotent.
#
# Expects a port-forward to SpiceDB to already be open on $ZED_LOCAL.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

ZED_LOCAL="${ZED_LOCAL:-localhost:50051}"
ZED=(zed --endpoint "$ZED_LOCAL" --token gerege-mvp-key --insecure --skip-version-check)

# retire_removed_relations deletes relationships belonging to relations that the
# schema no longer declares.
#
# SpiceDB refuses to remove a relation while relationships exist under it, and
# that is the right behaviour: a schema change that silently dropped data would
# be an authorization change nobody reviewed. So a rename is a two-step
# operation, and the steps are listed here rather than discovered when a
# bootstrap fails.
#
# Format: "<definition> <relation>   # why it went away"
RETIRED_RELATIONS=(
  "gerege/agent controller"   # split into `operator` (accountability) and
                              # `enrolled_for` (which users it may act for)
)

retire_removed_relations() {
  local entry definition relation
  for entry in "${RETIRED_RELATIONS[@]}"; do
    definition=$(echo "$entry" | awk '{print $1}')
    relation=$(echo "$entry" | awk '{print $2}')
    if "${ZED[@]}" relationship read "$definition" 2>/dev/null | grep -q " $relation "; then
      "${ZED[@]}" relationship bulk-delete "$definition" "$relation" --force >/dev/null 2>&1 || true
      ok "retired $definition#$relation"
    fi
  done
}

seed_schema() {
  retire_removed_relations
  "${ZED[@]}" schema write "$ROOT/spicedb/schema.zed" >/dev/null \
    || die "could not write the permission schema"
  ok "schema applied"
}

# seed_relationships reads the tuple lines out of seed.yaml, so the file that
# `zed validate` checks offline is the same file that seeds the running system.
# One artifact, not two that can drift apart.
seed_relationships() {
  local count=0 line res rest rel sub
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" || "$line" == //* ]] && continue
    [[ "$line" == gerege/*"#"*"@"* ]] || continue
    res="${line%%#*}"; rest="${line#*#}"; rel="${rest%%@*}"; sub="${rest#*@}"
    "${ZED[@]}" relationship touch "$res" "$rel" "$sub" >/dev/null \
      || die "could not write relationship: $line"
    count=$((count+1))
  done < <(sed -n '/^relationships:/,$p' "$ROOT/spicedb/seed.yaml")
  [[ $count -gt 0 ]] || die "no relationships found in spicedb/seed.yaml"
  ok "$count relationships seeded"
}

# mvp_docs/06 §4: "Step 9 should verify, not just write." Seeding without
# checking leaves three places to look when a later demo fails — bad seed data,
# bad schema, or bad ext-authz logic — instead of one.
verify_seed() {
  local probe want expr got
  for probe in \
    "true|gerege/user_profile:alice view gerege/user:alice" \
    "false|gerege/user_profile:alice view gerege/user:bob" \
    "true|gerege/home:alice-home administrate gerege/user:alice" \
    "true|gerege/device:lock-1 operate_lock gerege/user:alice" \
    "false|gerege/device:lock-1 operate_lock gerege/user:bob" \
    "true|gerege/device:thermostat-1 operate gerege/user:alice" \
    "true|gerege/device:sensor-1 push_telemetry gerege/system_principal:sensor-1" \
    "false|gerege/device:thermostat-1 push_telemetry gerege/system_principal:sensor-1" \
    "true|gerege/system_principal:sensor-1 administrate gerege/user:alice" \
    "true|gerege/agent:assistant administrate gerege/user:alice" \
    "true|gerege/agent:assistant act_for gerege/user:alice" \
    "false|gerege/agent:assistant act_for gerege/user:bob" \
    "false|gerege/consent_grant:alice|smarthome-app includes gerege/capability:profile_read"
  do
    want="${probe%%|*}"; expr="${probe#*|}"
    # stdout only, last line only: zed writes operational notices to stderr, and
    # folding those into the compared value turns an upstream release into a
    # bootstrap failure.
    got=$("${ZED[@]}" permission check --consistency-full ${expr} 2>/dev/null | tr -d '\r' | tail -1)
    if [[ "$got" == "$want" ]]; then
      ok "$expr → $got"
    else
      die "seed check failed: $expr → '$got', expected '$want'"
    fi
  done
  info "${DIM}the last check is the point: no consent is seeded, so Scenario 3a starts from a denial${R}"
}

clear_consent() {
  "${ZED[@]}" relationship bulk-delete gerege/consent_grant --force >/dev/null 2>&1 || true
  ok "consent grants cleared"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  seed_schema
  seed_relationships
  verify_seed
fi
