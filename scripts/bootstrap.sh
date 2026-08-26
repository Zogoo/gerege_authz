#!/usr/bin/env bash
#
# Brings up the whole MVP on a local kind cluster.
#
# The order below is not arbitrary; several steps depend on the previous one
# having *completed*, not merely started (mvp_docs/06 §4):
#
#   * Istio's extension provider is mesh configuration, so it must exist before
#     any workload starts. Adding it later requires restarting every sidecar,
#     which produces a confusing "why is nothing being checked" phase.
#   * SpiceDB's datastore migration is a separate operation from serving. The
#     server will not run against an unmigrated database.
#   * The CUSTOM AuthorizationPolicy goes on last. Enabling it before ext-authz
#     is ready denies all traffic — including the traffic needed to finish the
#     bootstrap. That is the difference between a clean start and a deadlock.
#   * STRICT mTLS goes on after the workloads have sidecars, or traffic to
#     un-injected pods breaks (mvp_docs/06 hazard 6).
#
# Re-running is safe: every step is idempotent.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
trap cleanup_port_forwards EXIT

step "Preflight"
for t in docker kind kubectl istioctl zed; do need "$t"; done
docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable. Start Docker/OrbStack and retry."
ok "docker $(docker version --format '{{.Server.Version}}')"
ok "kind $(kind version | awk '{print $2}')"
ok "istioctl $(istioctl version --remote=false 2>/dev/null)"
ok "zed $(zed version --skip-version-check 2>/dev/null | head -1 | awk '{print $3}')"

if ! hosts_are_mapped; then
  warn "the demo hostnames are not in /etc/hosts yet"
  hosts_instructions
  info "continuing — the cluster will come up, but browser and curl access will not work until they are added"
fi

step "1. kind cluster"
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  ok "cluster '$CLUSTER' already exists"
else
  kind create cluster --config "$ROOT/kind/cluster.yaml" --wait 180s
  ok "cluster '$CLUSTER' created"
fi
k cluster-info >/dev/null || die "cannot reach the cluster"

step "2. Istio, with the ext-authz extension provider registered up front"
if k -n istio-system get deploy istiod >/dev/null 2>&1; then
  ok "istiod already installed"
else
  istioctl install --context "$KCTX" -f "$ROOT/istio/istio.yaml" -y --verify=false
  ok "istio installed"
fi
wait_rollout istio-system deploy/istiod
wait_rollout istio-system deploy/istio-ingressgateway
# The extension provider must be present before any sidecar starts.
k -n istio-system get configmap istio -o jsonpath='{.data.mesh}' | grep -q 'gerege-ext-authz' \
  || die "the gerege-ext-authz extension provider is missing from the mesh config"
ok "extension provider 'gerege-ext-authz' registered in mesh config"

step "3. Namespaces"
k apply -f "$ROOT/deploy/00-namespaces.yaml" >/dev/null
ok "id, apps, devices"

step "4. Build the service image and load it into the cluster"
docker build -q -t "$IMAGE" "$ROOT/services" >/dev/null
ok "built $IMAGE (route config validated during the build)"
kind load docker-image "$IMAGE" --name "$CLUSTER" >/dev/null
ok "loaded into the kind node"

step "5. Databases"
k apply -f "$ROOT/deploy/10-databases.yaml" >/dev/null
wait_rollout id deploy/keycloak-db
wait_rollout id deploy/spicedb-db

step "6. Keycloak, with the realm imported"
k -n id create configmap keycloak-realm \
  --from-file=realm-gerege.json="$ROOT/keycloak/realm-gerege.json" \
  --dry-run=client -o yaml | k apply -f - >/dev/null
k apply -f "$ROOT/deploy/20-keycloak.yaml" >/dev/null
k -n id rollout restart deploy/keycloak >/dev/null 2>&1 || true
wait_rollout id deploy/keycloak 420s

step "7. SpiceDB: migrate the datastore, then serve"
# The migration Job is immutable once created, so a re-run replaces it.
k -n id delete job spicedb-migrate --ignore-not-found >/dev/null
k apply -f "$ROOT/deploy/30-spicedb.yaml" >/dev/null
k -n id wait --for=condition=complete job/spicedb-migrate --timeout=300s >/dev/null \
  || die "the SpiceDB datastore migration did not complete. kubectl --context $KCTX -n id logs job/spicedb-migrate"
ok "datastore migration complete"
wait_rollout id deploy/spicedb

step "8. Permission schema and seed relationships"
PF=$(port_forward id svc/spicedb 50051:50051)
source "$ROOT/scripts/seed.sh"
seed_schema
seed_relationships
verify_seed
cleanup_port_forwards

step "9. External authorizer"
k -n id create configmap ext-authz-config \
  --from-file=config.yaml="$ROOT/services/config/ext-authz.yaml" \
  --dry-run=client -o yaml | k apply -f - >/dev/null
k apply -f "$ROOT/deploy/40-ext-authz.yaml" >/dev/null
k -n id rollout restart deploy/ext-authz >/dev/null 2>&1 || true
wait_rollout id deploy/ext-authz

step "10. Routing and application workloads"
k apply -f "$ROOT/deploy/60-gateway.yaml" >/dev/null
k apply -f "$ROOT/deploy/50-apps.yaml" >/dev/null
for d in profile-app profile-service smarthome-service device-service agent-runner; do
  wait_rollout apps "deploy/$d"
done
wait_rollout id deploy/account-app

step "11. Enforcement — CUSTOM authorization and STRICT mTLS"
# Deliberately last. Before this point nothing is checked; after it, nothing is
# unchecked.
k apply -f "$ROOT/deploy/70-enforcement.yaml" >/dev/null
ok "ext-authz is now on the path of every request to every application"
sleep 5

step "12. IoT device"
k apply -f "$ROOT/deploy/80-telemetry-simulator.yaml" >/dev/null
wait_rollout devices deploy/telemetry-simulator

step "Ready"
cat <<EOF

  ${B}Open in a browser${R}
    http://profile.local.test        profile app        — sign in as alice / alice
    http://smarthome.local.test      smart home app     — SSO, no second login
    http://account.local.test        consent console    — grant and revoke
    http://id.local.test             Keycloak           — admin / admin

  ${B}From the terminal${R}
    make verify        run the full assertion suite (A1–A13)
    make demo          walk the five scenarios one keypress at a time
    make decisions     tail the authorization decision log
    make sensor        watch the IoT device being allowed once and refused three times

EOF
if ! hosts_are_mapped; then
  warn "hostnames are still not mapped — nothing above will resolve"
  hosts_instructions
fi
