# Lifecycle of Non-Human Identities

Onboarding and offboarding agents and devices. Both act for people, so both have
owners, and neither exists without one.

---

## 1. The shape of the problem

An agent or a device needs four things to exist, in four different systems:

| | System | Kind of state |
|---|---|---|
| An OAuth identity | Keycloak | who it is |
| A registry entry | ext-authz config | what kind of actor it is |
| Relationships | SpiceDB | what it may do, and who answers for it |
| A credential | delivered out of band | how it proves itself |

Before this was a command, it was a checklist across all four, in an order nobody
had written down, with no record of who registered a thing or why. That is
exactly IBM's fourth gap — *fragmented controls across identity and secrets* —
in a system built to demonstrate the other three.

Two properties make the difference between a checklist and a lifecycle:

**Nothing non-human is created without a named operator.** Onboarding refuses,
and `make inventory` fails if one ever appears unowned. docs/09 §4 rule 2:
accountability is a relationship, not a spreadsheet.

**Offboarding deletes relationships first.** That is the moment the thing stops
working. Everything after it — disabling the client, cleaning the registry — is
tidying, because the authority was never in the credential.

---

## 2. Onboarding a device

```bash
make onboard-device NAME=sensor-2 OPERATOR=alice HOME_ID=alice-home
```

```
✓ Keycloak client 'sensor-2' registered and enabled (client_credentials only)
✓ authorizer registry updated
✓ relationships written: owned by alice, in alice-home, authorized for its own telemetry
✓ verified: sensor-2 may push its own telemetry
✓ verified: alice is accountable for sensor-2
✓ authorizer reloaded — no restart

  the device's credential is sensor-2-secret — deliver it out of band
```

Four steps, one command, and it **verifies rather than assumes**: it asks SpiceDB
whether the device can actually do the one thing it exists to do, and whether the
operator is really recorded, before reporting success.

It is also idempotent in the way that matters. Offboarding disables the Keycloak
client rather than deleting it, so re-onboarding a decommissioned device has to
*converge on* the declared configuration, not merely observe that something is
there. An earlier version treated "already exists" as success and left a disabled
identity behind, reporting a working device that could not obtain a token.

---

## 3. Onboarding an agent

An agent takes one more step than a device, because it acts for people:

```bash
make onboard-agent NAME=helper OPERATOR=alice CLIENT=helper-agent \
     WORKLOAD=spiffe://cluster.local/ns/apps/sa/helper
make enrol-agent  NAME=helper USER=bob
```

Onboarding gives it an identity and an owner. It can act for **nobody** until it
is enrolled — the command verifies that too:

```
✓ verified: alice is accountable for helper
✓ verified: enrolled for nobody yet — it can act for no one until enrolled
```

The `WORKLOAD` is the SPIFFE identity of the process that runs it, and it is the
binding described in [agent-identity.md §6](agent-identity.md). Without it the
agent's own workload could decline to exchange its token and act as the
application instead.

### Three grants, three questions

Onboarding an agent creates the first; the other two come later and from
different people.

| Grant | Question | Who makes it | Lifetime |
|---|---|---|---|
| `operator` | who answers for this thing? | whoever runs it | until decommissioned |
| `enrolled_for` | may it act for this user at all? | onboarding, per user | durable |
| `delegation` | what may it do for them right now? | the user, per task | **expires** |

All three are required, and none substitutes for another. An agent with an owner
and an enrolment and no delegation can do nothing. An agent with a delegation and
no enrolment is refused with `agent_not_enrolled` — which is why the account
console refuses to *write* a delegation to an agent that was never enrolled for
you, rather than letting you believe you granted something.

---

## 4. Offboarding

```bash
make offboard-device NAME=sensor-2
```

```
✓ relationships deleted — the device is powerless as of the next request
✓ verified: sensor-2 can no longer push telemetry
✓ Keycloak client sensor-2 disabled (no new tokens)
✓ authorizer registry cleaned up
```

The ordering is the design. A token captured moments before offboarding, with
299 seconds of validity left and a perfectly good signature, is refused on the
very next request:

```
telemetry with the pre-offboard token   403
```

Nothing waited for the token to expire, and nothing had to reach the device. That
is what it means for authority to live in the graph rather than in the
credential.

A user can also do this for themselves, from the account console — the
**Non-human identities you operate** section. Decommissioning is gated on
`administrate`, which only the operator holds.

---

## 5. Seeing it work

```bash
make demo S=7
```

Scenario 7 walks the whole cycle: a device that does not exist, one command that
makes it real across four systems, proof that it can do exactly one thing, the
authorizer's pod showing the same restart count before and after, a token
captured while the device is alive, and that token refused the moment the device
is decommissioned.

It also says what it does **not** show, which is the part worth reading — see
[§9](#9-what-is-still-missing).

Assertions A24–A25 run the same cycle unattended, by driving this script rather
than reimplementing it: the thing being asserted is that *the command* works, and
a test that rebuilt the steps in Go would keep passing after the script broke.

---

## 6. Doing it by hand

`make onboard-device` exists so nobody has to do this. It is written out here
because a command whose steps you cannot see is a command you cannot audit, and
because onboarding a device on a system that is not this one means doing exactly
these four things somewhere else.

Every command below has been run verbatim.

### Before anything

```bash
kubectl config use-context kind-gerege-idp
```

The single most common way to waste ten minutes here is running these against
whatever cluster `kubectl` was already pointed at, and getting
`namespaces "id" not found` from step 3.

These also assume the demo hostnames resolve (`sudo make hosts`). Without them,
add `--resolve id.local.test:80:127.0.0.1` to each `curl`.

```bash
DEVICE=sensor-2
OWNER=alice
HOME_ID=alice-home
KC=http://id.local.test
```

### 1. An identity — Keycloak

```bash
ADMIN=$(curl -s -X POST "$KC/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli \
  -d username=admin -d password=admin | jq -r .access_token)

curl -s -o /dev/null -w 'HTTP %{http_code}\n' -X POST \
  -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  "$KC/admin/realms/gerege/clients" -d '{
    "clientId": "'"$DEVICE"'",
    "name": "'"$DEVICE"' (IoT device identity)",
    "enabled": true,
    "protocol": "openid-connect",
    "publicClient": false,
    "secret": "'"$DEVICE"'-secret",
    "standardFlowEnabled": false,
    "directAccessGrantsEnabled": false,
    "serviceAccountsEnabled": true,
    "redirectUris": [], "webOrigins": []
  }'
```

`serviceAccountsEnabled` with every browser flow off is what makes this a device
rather than an application: it can obtain a token for itself with
`client_credentials`, and it can do nothing else.

### 2. A kind — the authorizer's registry

```bash
kubectl -n id get configmap ext-authz-config \
  -o jsonpath='{.data.config\.yaml}' > /tmp/ext-authz.yaml

MARK=$(date -u +%Y-%m-%dT%H:%M:%SZ)
sed -i '' "s|^systemPrincipals:|systemPrincipals:\n  $DEVICE: $DEVICE|" /tmp/ext-authz.yaml

kubectl -n id create configmap ext-authz-config \
  --from-file=config.yaml=/tmp/ext-authz.yaml \
  --dry-run=client -o yaml | kubectl apply -f -
```

This is what tells ext-authz that a token whose `azp` is `sensor-2` belongs to a
non-human principal rather than an application — so consent is never evaluated
and the subject becomes `gerege/system_principal:sensor-2`.

Wait for the authorizer to pick it up. **It does not restart:**

```bash
kubectl -n id logs deploy/ext-authz --since-time="$MARK" -f | grep "configuration reloaded"
```

Note `--since-time`. Grepping recent logs without it will match a *previous*
reload and tell you the change is live before it is.

### 3. Authority and an owner — SpiceDB

```bash
kubectl -n id port-forward svc/spicedb 50051:50051 &
sleep 3
alias zedc='zed --endpoint localhost:50051 --token gerege-mvp-key --insecure'

zedc relationship touch gerege/system_principal:$DEVICE operator gerege/user:$OWNER
zedc relationship touch gerege/device:$DEVICE          home     gerege/home:$HOME_ID
zedc relationship touch gerege/device:$DEVICE          self     gerege/system_principal:$DEVICE
```

The **first** line is the one that matters most and the one easiest to skip. A
device without an operator is an identity nobody answers for — `make inventory`
exists to fail when that happens.

The other two are the whole of its authority: it belongs to a home, and it is
itself. `push_telemetry` derives from `self`, so it may report its own readings
and nothing else.

### 4. Verify, rather than assume

```bash
zedc permission check --consistency-full gerege/device:$DEVICE push_telemetry gerege/system_principal:$DEVICE   # true
zedc permission check --consistency-full gerege/system_principal:$DEVICE administrate gerege/user:$OWNER        # true
zedc permission check --consistency-full gerege/device:sensor-1 push_telemetry gerege/system_principal:$DEVICE  # false
```

`--consistency-full` is not optional here. A check immediately after a write must
read its own write, and the default consistency reads at a quantized revision —
so a freshly written relationship is briefly invisible and a correct onboarding
reports as a failure.

Then prove it end to end:

```bash
TOKEN=$(curl -s -X POST "$KC/realms/gerege/protocol/openid-connect/token" \
  -d grant_type=client_credentials \
  -d "client_id=$DEVICE" -d "client_secret=$DEVICE-secret" | jq -r .access_token)

curl -s -o /dev/null -w 'own telemetry:      HTTP %{http_code}\n' \
  -X POST http://device.local.test/telemetry/$DEVICE \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{"temperature":21.0}'

curl -s -o /dev/null -w 'someone elses:      HTTP %{http_code}\n' \
  -X POST http://device.local.test/telemetry/sensor-1 \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{"temperature":21.0}'
```

```
own telemetry:      HTTP 202
someone elses:      HTTP 403
```

### Taking it away

Reverse order, and **relationships first** — that is the kill switch:

```bash
zedc relationship bulk-delete gerege/device:$DEVICE --force
zedc relationship bulk-delete gerege/system_principal:$DEVICE --force

# now it is powerless. the rest is tidying.
UUID=$(curl -s -H "authorization: Bearer $ADMIN" \
  "$KC/admin/realms/gerege/clients?clientId=$DEVICE" | jq -r '.[0].id')
curl -s -X PUT -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  "$KC/admin/realms/gerege/clients/$UUID" -d '{"enabled":false}'
```

A token issued seconds earlier, still correctly signed and minutes from expiry,
stops working on the very next request.

---

## 7. Inventory

```bash
make inventory
```

```
IDENTITY               KIND               OPERATOR
--------------------------------------------------------------
assistant              agent              alice
sensor-1               system_principal   alice

✓ every non-human identity has a named operator
```

It exits non-zero if anything is unowned, so it belongs in CI as well as in a
terminal. It also lists live delegations with their expiry, which answers the
question a person actually has: *what is currently acting on my behalf, and until
when?*

---

## 8. Why onboarding does not restart the authorizer

Registry changes used to require restarting ext-authz — the one component every
request in the mesh depends on. With a single replica that is a brief total
outage, triggered by the routine act of enrolling a sensor. An architecture where
adding a device means an authorization outage is one that discourages the thing
it should make easy.

ext-authz now re-reads its configuration on a timer and swaps it atomically. Two
rules keep that safe against a live authorizer:

- A configuration that fails to load or compile is **not installed**; the
  previous one keeps serving. A bad edit cannot take the authorizer down, and it
  cannot open it either.
- A request reads the snapshot once and is decided entirely against it, so a
  reload never applies halfway through a decision.

Polling rather than a filesystem watch, because a ConfigMap update replaces a
symlink rather than writing the file — precisely the case watchers handle worst.

---

## 9. What is still missing

**The claiming ceremony.** Onboarding is operator-driven: someone with Keycloak
admin credentials runs a command and *asserts* that Alice owns the device. A
user-claimed device should instead use the OAuth 2.0 device authorization grant
(RFC 8628) — the device shows a code or a QR, the owner authenticates and
approves, and ownership is **proven by that authentication** rather than asserted
by whoever ran the command. Keycloak already supports it in this realm; what is
missing is the claim endpoint that turns the approval into a per-device identity.
The two patterns are complementary: device flow for consumer devices with a
display, operator provisioning for headless fleets.

**Attestation.** A device proves itself with a shared secret delivered out of
band. Nothing establishes that the thing presenting `sensor-2-secret` is the
sensor. Real device onboarding uses attestation — SPIRE node attestation, a TPM,
or an X.509 device certificate — and that is the honest boundary of this MVP: it
demonstrates what a device *may do*, not that it is what it claims to be.

**Registration expiry.** Delegations expire; registrations do not. A
decommissioned sensor nobody remembers stays registered. The mechanism already
exists — `with expiration` — and applying it to `device#self` would force
re-attestation rather than assuming it.

**Approval.** Onboarding records the operator but not who performed it, or under
what authorisation. There is no second pair of eyes on granting a new non-human
identity, which for a wildcard grant is the review docs/09 §4 rule 3 asks for.
