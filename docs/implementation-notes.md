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

## 10. Ownership, and making it load-bearing

The first agent implementation gave the agent a `controller` relation and the
device nothing at all — which violated the project's own design doc
([docs/09 §4](../../docs/09-zero-trust-enforcement-and-consent.md) rule 2:
"every system principal has a named human operator") while quoting it in a
comment two lines above. The device could act; the graph could not say who was
answerable for it.

Fixing it properly meant deciding *where* ownership is enforced, and the answer
is different for each of the three questions it raises.

| Question | Where it is answered | Why not elsewhere |
|---|---|---|
| Is this thing owned at all? | onboarding, and `make inventory` in CI | Not expressible as a single permission check — "does an operator exist" has no subject to ask about. And it is a registration invariant, not a fact about a request |
| May this agent act for *this* user? | per request, `agent:X#act_for@user:sub` | It **is** a fact about the request: two named parties, and their pairing may or may not have been intended |
| May this person decommission it? | write path, `administrate` | Only the operator holds it. This is the point of recording an operator at all |

Renaming `controller` into `operator` + `enrolled_for` also produced the first
real schema migration: SpiceDB refuses to remove a relation while relationships
exist under it. That is the right behaviour — a schema change that silently
dropped authorization data would be a policy change nobody reviewed — so retired
relations are listed explicitly in `scripts/seed.sh` and their relationships
deleted first.

---

## 11. Read-your-writes, in the other direction

[§9](#9-expiry-is-observed-at-a-revision-not-at-a-wall-clock) was about a check
seeing a relationship for too long. The onboarding scripts hit the mirror image:
a check that verified a *just-written* relationship reported failure, because
`zed`'s default consistency reads at a quantized revision and the write was not
visible yet.

Both are the same fact from opposite sides — a check is evaluated at a revision,
not at an instant — and both have the same fix. Every verification that follows a
write passes `--consistency-full`. Anything less would report a correct
onboarding as a failure, and would eventually report a failed one as a success.

---

## 12. Onboarding must converge, not merely observe

Offboarding disables a Keycloak client rather than deleting it, so a
re-onboarded device meets an existing-but-disabled identity. The first version
treated the resulting `409 Conflict` as success — and reported a working device
that could not obtain a token, because "already exists" is not "already correct".

Registration is now an upsert that ends by *asking Keycloak whether the client is
enabled*, rather than assuming the write landed. The general form: a provisioning
step that reports success without verifying the state it claims to have created
is a step that will eventually lie.

---

## 13. `at_least_as_fresh` cost more than it bought

Telemetry ingest was the one route configured `at_least_as_fresh` rather than
`fully_consistent`, on the reasoning that it is high-frequency and no assertion
depended on observing a revocation there ([§5](#5-consistency-at_least_as_fresh-needs-a-zedtoken-from-somewhere)).

That was wrong, and assertion A25 caught it: telemetry is the one route a
*device* uses, so it is exactly the route where decommissioning has to bite
immediately. Reading at a slightly stale revision let a captured token keep
working after its own device had been decommissioned — the single property the
whole offboarding design exists to provide.

It is now `fully_consistent` like everything else. The implementation and its
ZedToken tracking stay in `internal/spicedb`, unused: the seam is worth keeping,
the configuration is not.

The general shape: "no assertion depends on this" is a statement about the tests,
not about the system. It was true when written and stopped being true the moment
offboarding existed.

---

## 14. Waiting for the right event, not a similar one

Onboarding waits for the authorizer to reload before reporting success. The first
version grepped the last 90 seconds of log for `configuration reloaded` — which
cheerfully matched a *previous* reload and returned immediately, before the new
registry was live. The symptom appeared much later and somewhere else: a freshly
onboarded device refused with `unknown_application`.

It now records a timestamp before writing the ConfigMap and only accepts a reload
after it. A wait that can be satisfied by an event from before the thing it is
waiting for is not a wait.

---

## 15. Things that went wrong during the build, kept as warnings

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

**`zed` writes operational notices to stderr, and a new patch release broke a
bootstrap.** The seed checks compared `$(zed permission check ... 2>&1)` against
`"true"`. When SpiceDB 1.56.1 shipped, `zed` began prefixing every invocation
with an out-of-date warning, which the `2>&1` folded into the compared value —
turning an upstream release into a bootstrap failure with a baffling error. Never
merge stderr into a value you are going to compare.

**`zed validate` and `zed import` disagree about prefixes.** The assertion suite in
`validation.yaml` uses fully-prefixed names and passes; `zed import` does not accept the
same form against a non-empty server. Both files are checked in, and `make schema-test`
runs the one that behaves predictably offline.
