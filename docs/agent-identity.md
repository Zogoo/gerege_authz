# Agent Identity

How the MVP handles an **agent**: something that holds a user's identity, decides at
runtime what to do with it, and must not inherit that user's authority.

This extends [`mvp_docs/`](../../mvp_docs/README.md) rather than replacing it. Everything
in the original design still holds; agents add one actor kind, one grant type and one
gate.

---

## 1. The problem, precisely

An agent presents a token whose `sub` is the human. Every permission check therefore
passes on the human's own authority, and every audit record shows the human's name.
Nothing in the classical model distinguishes "Alice read her profile" from "something
Alice once installed read her profile while she was asleep".

That is the whole of it. The rest of this document is the consequence.

> **Ungoverned persistent access · Privilege escalation without review · No attribution,
> no accountability** — IBM's [four gaps in agentic identity
> security](https://www.ibm.com/solutions/agentic-ai-identity-management), which are the
> right four.

---

## 2. Four actor kinds, not three

| Kind | Human behind it | Decides at runtime | Grant that binds it |
|---|---|---|---|
| `user` | is one | — | permission |
| `application` | acts for one | no | **consent** — durable |
| `agent` | acts for one | **yes** | **delegation** — expiring |
| `system_principal` | none | no | its own relationships |

An agent is deliberately neither of its neighbours. An application is a name on a consent
screen with no runtime behaviour of its own. A system principal is a sensor reporting its
own readings, with no user in the loop at all. An agent has a human behind it *and*
decides for itself — which is exactly the combination nothing else in the model covers.

```zed
definition gerege/agent {
	relation controller: gerege/user
	permission act = controller
}

definition gerege/delegation {
	relation delegator: gerege/user
	relation delegate: gerege/agent
	relation granted: gerege/capability with expiration

	permission includes = granted
	permission revoke = delegator
}
```

`with expiration` is the load-bearing part. SpiceDB enforces the expiry itself, so a
delegation nobody remembers to remove stops working anyway.

---

## 3. How an agent gets an identity

RFC 8693 token exchange, which Keycloak calls *standard token exchange*:

```
POST /realms/gerege/protocol/openid-connect/token
  grant_type          = urn:ietf:params:oauth:grant-type:token-exchange
  client_id           = assistant-agent
  subject_token       = <Alice's access token>
  subject_token_type  = urn:ietf:params:oauth:token-type:access_token
```

The result keeps `sub = alice` and sets `azp = assistant-agent`. The person who is
accountable and the actor that is running are now two different things inside one token,
which is the minimum requirement for everything downstream.

**The audience gate.** Keycloak refuses to mint an agent token from a subject token that
does not already carry that agent in its `aud`. That is a control worth naming: a token
issued for one purpose cannot be repurposed into agent authority later. It is configured
as an audience mapper on `smarthome-app`, and assertion A20 checks that a `profile-app`
token — which has no such mapper — cannot be exchanged.

**What is missing, and why.** RFC 8693 carries the delegation chain in the `act` claim,
and the IETF is extending it further
([actor profile](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-actor-profile-00),
[delegation chain](https://www.ietf.org/archive/id/draft-liu-oauth-chain-delegation-00.html)).
Keycloak's V2 standard exchange emits **no `act` claim** — verified against 26.7.2, not
assumed. So ext-authz reconstructs the actor from `azp` plus the agent registry.

That is sufficient for one hop and only one hop. A chain of agents would need `act`, and
the known attack on chains — *delegation chain splicing*, inserting yourself between two
legitimate hops — is exactly what an unauthenticated reconstruction cannot detect. The
MVP has one agent and says so; see [§7](#7-what-this-does-not-solve).

---

## 4. The decision

An agent-borne request runs the same pipeline as anything else, with two additions:

```
 ├─ 2. principal ← sub (the human)      actor ← azp (the agent)
 ├─ 5. workload registered?
 ├─ 6. step-up gate          sensitive capability → a human must be present
 └─ 7. CheckBulkPermissions [ permission, delegation ]
```

**Delegation replaces consent for an agent; it does not add to it.** Each actor kind gets
exactly one binding grant. Consent is durable and asked of the user once, because an
application is a durable relationship. Delegation is expiring and asked per task, because
an agent's authority should not outlive the task. Pairing a durable consent *with* an
agent would put back the standing privilege the expiry exists to remove.

Both still appear in one end-to-end flow, at different hops:

| Hop | Actor | Bound by |
|---|---|---|
| browser → smarthome-service | Alice, via `smarthome-app` | consent |
| smarthome-service → agent-runner | Alice, via `smarthome-app` | consent |
| agent-runner → profile-service | Alice, via `assistant` | **delegation** |
| agent-runner → device-service | Alice, via `assistant` | **delegation** |

The boundary in the decision log is precisely where the token exchange happened.

---

## 5. Step-up: the one an agent can never pass

`devices_unlock` is marked `stepUp: true`. The gate refuses:

- **an agent, unconditionally** — not because its `acr` is too low, but because it
  inherits the human's `acr` through the exchange, so the claim proves nothing about
  whether a person is present *now*;
- **a human whose `acr` is below the threshold** — Keycloak issues `acr=1` for an actual
  authentication and `acr=0` when answering from an existing SSO session without
  prompting.

The refusal is structural rather than a policy that could later be granted. "A human must
be here for this one" and "an agent may do this alone" are contradictory requirements, so
the account console does not even offer `devices_unlock` as delegatable. The denial
carries a challenge, which is what puts the human back in the loop.

The gate runs **before** SpiceDB is consulted — assertion in
`failclosed_test.go` checks that no permission question is asked at all, because there is
nothing a grant could say that would change the answer.

---

## 6. What the audit record now says

```
ENFORCER               RESOURCE                    PRINCIPAL  ACTOR      REASON
apps/agent-runner      gerege/home:alice-home      alice      —          permitted
apps/profile-service   gerege/user_profile:alice   alice      assistant  permitted
apps/device-service    gerege/device:thermostat-1  alice      assistant  delegation_required
apps/device-service    rule:device-unlock          alice      assistant  step_up_required
apps/device-service    gerege/device:lock-1        alice      —          permitted
```

`principal` stays `alice` throughout — she remains accountable, which is correct. The
`actor` column separates the hops she made herself from the hops something made on her
behalf. That column is the thing legacy IAM cannot produce, and producing it is most of
what "agent identity" means in practice.

---

## 7. What this does not solve

Stated plainly, because a demonstration that oversells is worse than one that is narrow.

| Gap | Why it is open |
|---|---|
| **Multi-hop chains** | One agent, one hop. A chain needs `act`, which Keycloak V2 does not emit, and chain splicing is undetectable without it |
| **Cross-domain delegation** | Everything here is one realm and one mesh. [ID-JAG](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant) is the mechanism for crossing trust domains and is not implemented |
| **Intent** | The delegation binds *capabilities*, not purpose. "Read my profile" is enforced; "read my profile in order to book a table" is not. CSA's *Mean Time to Understand* is about this gap and the MVP does not close it |
| **Prompt injection** | Out of scope by construction rather than by defence: the agent is never trusted to report its own authority, so a hijacked agent can only do what was already delegated. That bounds the blast radius; it does not prevent the hijack |
| **Agent provenance** | `gerege/agent:assistant` is a name in a config file. No attestation, no verifiable credential, nothing proving the running code is the agent it claims to be |

The last one is the largest. Everything above assumes the workload identity is honest,
which the mesh does guarantee for *which pod* is calling — but "this pod is agent-runner"
and "this agent is behaving as its author intended" are different claims, and only the
first is proven.

---

## 8. Trying it

```bash
make demo S=6          # the walkthrough
make verify            # assertions A14-A20
```

In a browser: sign in at `http://smarthome.local.test`, open **Ask the Assistant**, then
delegate at `http://account.local.test/delegate?agent=assistant` and ask again.

The sequence worth watching is: ask before delegating (everything refused, with Alice's
own consent already granted), delegate two capabilities for five minutes, ask again
(exactly those two permitted), then try the door — refused for the agent, permitted for
Alice, on the same lock with the same permission.

---

## Sources

- [IBM — Agentic AI Identity Management](https://www.ibm.com/solutions/agentic-ai-identity-management)
- [CSA — Agentic AI Identity and Access Management: A New Approach](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach)
- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [Keycloak — Token Exchange](https://www.keycloak.org/securing-apps/token-exchange)
- [SpiceDB — Relationships that Expire](https://authzed.com/docs/spicedb/concepts/expiring-relationships)
- [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant)
- [draft-mcguinness-oauth-actor-profile](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-actor-profile-00)
- [draft-liu-oauth-chain-delegation](https://www.ietf.org/archive/id/draft-liu-oauth-chain-delegation-00.html)
