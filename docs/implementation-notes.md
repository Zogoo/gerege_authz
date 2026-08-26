# Implementation Notes

Where the build differs from [`mvp_docs/`](../../mvp_docs/README.md), and why. Each entry
is either a constraint the design documents could not have known about, or a decision
they left open.

---

## 1. Capability and consent-grant identifiers

**Design:** capabilities are written `profile.read`; consent grants are
`<user>~<application>`.

**Constraint:** SpiceDB object IDs are restricted to `[a-zA-Z0-9/_|\-=+]`
([`pkg/tuple/parsing.go`](https://github.com/authzed/spicedb/blob/main/pkg/tuple/parsing.go),
`resourceIDExpr`). Neither `.` nor `~` is permitted.

**Built:** capabilities are `profile_read`, `profile_write`, `devices_view`,
`devices_control`, `devices_unlock`; consent grants are `alice|smarthome-app`.

The human-readable label — "See your name, email, phone and address" — lives in the
consent console next to the screen that shows it, which is where it belongs anyway.
Nothing else changes: capabilities are still objects rather than schema permissions, so
adding one is still data rather than a schema rollout.

---

## 2. A consent console was added

**Design:** four demonstration workloads. Consent is granted "via the IdP".

**Problem:** [`mvp_docs/04 §1`](../../mvp_docs/04-ext-authz-service-design.md) puts
relationship writes explicitly out of scope for ext-authz — "a component that both
decides and mutates authorization state is a component where a request-handling bug can
escalate privilege". Keycloak cannot write SpiceDB relationships either; its own consent
screen writes Keycloak state, which by M-001 holds no authorization at all.

**Built:** `account-app`, a fifth workload in the `id` namespace on
`account.local.test`, with its own ServiceAccount and its own OAuth client. It serves the
consent screen and the account page, and it is the only component in the system holding a
SpiceDB write client.

This keeps the property the design was protecting: ext-authz remains structurally
incapable of changing what it decides on.

---

## 3. Three rule kinds, not one

**Design:** every rule names a resource, a permission and optionally a capability.

**Problem:** two kinds of route do not fit. A stylesheet has no user and no resource. A
dashboard shell that renders only what its own authorized sub-requests return has a user
but still no resource. Inventing a resource for either would put a meaningless permission
in the schema and make the model harder to read than the thing it describes.

**Built:** `public: true` (no principal required) and `authenticatedOnly: true`
(principal required, no resource check), alongside the full form. Both are declared
per-route in the same document, and the config loader rejects a rule that declares a
permission alongside either flag.

The property that matters is untouched: there is still no implicit allow anywhere. A
static asset is permitted because a rule says so, not because nothing said otherwise.

---

## 4. Assertion A10 is demonstrated by downgrade, not by Bob

**Design:** A10 — "Same call for Bob → denied at the internal hop even with a valid
token."

**Problem:** Bob has no relationship to Alice's home, so he is refused at the *first*
hop. That demonstrates a denial, but not an internal one — and A10 exists to prove that
internal enforcement is real.

**Built:** the suite downgrades Alice from `owner` to `guest` of her own home. She can
still view it, so the edge check passes and the request reaches smarthome-service;
`operate_lock` derives from `administrate`, so device-service refuses. The external call
succeeds and the internal one does not, which is exactly what
[Scenario 3b](../../mvp_docs/05-demo-scenarios.md#3b--the-internal-hop-is-independently-authorized)
describes.

Bob is still exercised, as A10c.

---

## 5. Consistency: `at_least_as_fresh` needs a ZedToken from somewhere

**Design:** `fully_consistent` for consent operations, `at_least_as_fresh` as the default
for resource access, `minimize_latency` never.

**Problem:** `at_least_as_fresh` takes a ZedToken, and ext-authz never writes, so it has
no token of its own. `minimize_latency` is excluded by
[`mvp_docs/03 §6`](../../mvp_docs/03-authorization-and-consent-model.md#6-consistency)
precisely because it would make revocation assertions flaky.

**Built:** the SpiceDB client remembers the most recent `checked_at` ZedToken SpiceDB
returns and offers that as the freshness floor for `at_least_as_fresh` rules. Before the
first successful check there is no token and it falls back to `fully_consistent` — never
to something weaker.

In practice every rule that any assertion depends on is configured `fully_consistent`, so
that A5 and A8 are deterministic rather than timing-dependent. Telemetry ingest uses
`at_least_as_fresh`, which keeps that code path exercised.

---

## 6. Enforcement points: three, not two

Requests to a demonstration application are checked at the ingress gateway *and* at the
receiving workload's sidecar. The design's component diagram shows both, but Scenario 3b
describes "two decisions" for the internal-hop walkthrough; in practice there are three,
because the edge is also an enforcement point.

The decision log names each one, so this reads as more evidence rather than as a
discrepancy. The gateway policy is scoped by host so that `id.local.test` — Keycloak —
is *not* routed through the authorizer; sending the login page through the component that
depends on Keycloak to authenticate anyone would be circular.

---

## 7. What is not in the mesh, and why

| Component | Sidecar | Reason |
|---|---|---|
| Keycloak, SpiceDB, both databases | No | Identity plane, not applications. SpiceDB in particular must stay reachable through `kubectl port-forward` for `zed`, which STRICT mTLS would refuse — and `zed ... --explain` is the most useful debugging tool in this stack |
| ext-authz | No | Every sidecar calls it on every request. A sidecar governed by the same CUSTOM policy would mean authorizing the authorization request. It also removes a bootstrap ordering hazard: the policy is applied after ext-authz is ready, which a self-referential dependency would make impossible rather than merely important |
| telemetry-simulator | No | A real IoT device is not a mesh member. Running it inside the mesh would make Scenario 4 dishonest |

Both namespaces have injection enabled and the exceptions opt out individually with
`sidecar.istio.io/inject: "false"`, so the default is "in the mesh" and every exception is
visible next to the workload it applies to.

---

## 8. Agents: what reality dictated

The agent design is written up in [agent-identity.md](agent-identity.md). Four things
there were decided by what actually works rather than by preference, and all four were
verified against the running system rather than assumed.

**Keycloak V2 token exchange emits no `act` claim.** RFC 8693 carries the delegation
chain in `act`, and Keycloak's *standard* token exchange — the one enabled by default in
26.7 — does not populate it; `act`/`may_act` belong to the separate experimental
delegation feature. The exchanged token does keep `sub` = the human and set `azp` = the
agent, which is enough to reconstruct a single-hop actor from the agent registry. It is
not enough for a chain, which is why the MVP has one agent and
[says so](agent-identity.md#7-what-this-does-not-solve).

**The exchange has an audience gate, and it is useful.** Keycloak refuses to mint a token
for a client that is not already in the subject token's `aud`, so an audience mapper on
`smarthome-app` is a prerequisite rather than a detail. The upside is a real control: a
token issued without contemplating an agent cannot later be turned into that agent's
authority. Assertion A20 exercises it.

**Delegation replaces consent for agents rather than adding to it.** The first draft
checked both, on the reasoning that they answer different questions. They do — but each
actor kind only needs one binding grant, and delegation is stricter than consent in every
dimension (per-capability, per-task, expiring). Requiring a durable consent to an agent
as well would have reintroduced exactly the standing privilege the expiry exists to
remove. Consent and delegation still both appear in one flow, at different hops.

**Step-up is enforced structurally, not by claim inspection.** The obvious implementation
— require a high enough `acr` — does not work, because the exchanged token *inherits* the
human's `acr`, so the claim says nothing about whether a person is present now. Agents
are refused on step-up routes unconditionally, before SpiceDB is consulted, because no
grant could change the answer.

---

## 9. Expiry is observed at a revision, not at a wall clock

The first version of assertion A17 delegated a capability for two seconds, waited four,
and asserted the grant was gone. It passed most of the time.

Expiry is enforced by the datastore and evaluated at whatever revision a check resolves
to, so it becomes visible within a few seconds of the deadline rather than at the instant
the clock passes it. A two-second margin was inside that window.

The mechanism is sound — `TestBulkVsSingleCheckOnExpiry` confirms `CheckPermission` and
`CheckBulkPermissions` agree, and `TestDelegationExpiresAgainstRealSpiceDB` exercises the
whole write-and-lapse path against a live server. What was wrong was the assertion, which
now allows a margin comfortably larger than the observation window.

The general form of the lesson: an assertion that races a distributed system's clock
fails occasionally and *truthfully*, which is worse than a slower one that is
deterministic. It is the same reasoning as M-005, applied to time instead of caching.

---

## 10. Things that went wrong during the build, kept as warnings

These cost time and would cost it again.

**A placeholder ConfigMap in a manifest, overwritten at bootstrap.** The Keycloak realm
was generated from a JSON file and then immediately replaced by the placeholder declared
in `20-keycloak.yaml`, because the manifest was applied second. The realm silently did
not import; the only symptom was a 404 on the discovery document several steps later. The
manifest no longer declares it, and says so.

**An image-wide `ENV HEALTH_ADDR`.** One image holds seven programs. The demo services
listen on 8081 for health, ext-authz on 9002. An `ENV` default in the Dockerfile
overrode the right value for one of them; ext-authz logged "ready" while its health port
was on the wrong number, and the kubelet restarted it in a loop. Each binary now carries
its own defaults and the Dockerfile sets none.

**A blocking dependency check before the health listener started.** ext-authz waits for
Keycloak before serving. With the health server started *after* that wait, the liveness
probe failed during it and the pod was killed and restarted forever. Liveness and
readiness answer different questions: the process is alive from the first line of `main`,
and ready only once it can serve.

**`zed import` is not idempotent for prefixed schemas.** It reads the schema already on
the server, infers a definition prefix from it, and prepends that prefix to every
relationship in the file. A file whose relationships read `gerege/user_profile:...`
imports cleanly into an empty SpiceDB and fails on every later run with
`gerege/gerege/user_profile not found`. Bootstrap writes the schema and touches each
relationship explicitly instead.

**Realm import will not add a client to a realm that already exists.** The import
strategy is `IGNORE_EXISTING`, so adding `assistant-agent` to `realm-gerege.json` and
restarting Keycloak changes nothing at all, silently. The realm has to be deleted first —
which is fine here, because every piece of realm state is in the file, and is exactly the
sort of thing that is obvious in hindsight and costs an hour in the moment.

**`zed validate` and `zed import` disagree about prefixes.** The assertion suite in
`validation.yaml` uses fully-prefixed names and passes; `zed import` does not accept the
same form against a non-empty server. Both files are checked in, and `make schema-test`
runs the one that behaves predictably offline.
