#!/usr/bin/env bash
#
# Resets the demo world: re-applies the schema and the seed relationships, and
# deletes every consent grant so Scenario 3a starts from a denial again.
#
# mvp_docs/06 §7: resetting the demo world takes seconds, because the state that
# matters lives in relationships rather than in deployed configuration. That is
# the same property Scenario 2 demonstrates, used for housekeeping.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
trap cleanup_port_forwards EXIT

k get ns id >/dev/null 2>&1 || die "the cluster is not up. Run: make up"

step "Connecting to SpiceDB"
port_forward id svc/spicedb 50051:50051 >/dev/null
source "$ROOT/scripts/seed.sh"

step "Clearing consent grants"
clear_consent

step "Re-applying schema and seed relationships"
seed_schema
seed_relationships

step "Spot checks"
verify_seed

echo
ok "demo world reset"
