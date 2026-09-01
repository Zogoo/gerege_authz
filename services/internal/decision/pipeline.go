// Package decision implements the authorization pipeline.
//
// Every request runs the same steps in the same order (mvp_docs/04 §3). There
// is no per-route handler dispatch: the matched rule supplies parameters, it
// does not select code. That removes the "which handler runs when two patterns
// match" question the cityos sample was mid-transition on.
//
//	Check(request)
//	 ├─ 1. special paths: OIDC callback, logout
//	 ├─ 2. establish the principal   (bearer → session → start OIDC / deny)
//	 ├─ 3. establish application (azp) and workload (source.principal)
//	 ├─ 4. match a route rule        — no match → DENY
//	 ├─ 5. verify the workload is registered to serve the application
//	 ├─ 6. CheckBulkPermissions [permission, consent-if-required]
//	 └─ 7. emit the decision log
//
// The invariant that outranks everything else: **no path through this file
// returns Permit as a result of an error.** Claim C8 is that property, and
// pipeline_test.go asserts it over every error branch.
package decision

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/gerege/idp-mvp/internal/config"
	"github.com/gerege/idp-mvp/internal/logx"
	"github.com/gerege/idp-mvp/internal/oidcauth"
	"github.com/gerege/idp-mvp/internal/routes"
	"github.com/gerege/idp-mvp/internal/session"
	"github.com/gerege/idp-mvp/internal/spicedb"
)

// Request is the transport-independent view of an Envoy CheckRequest.
type Request struct {
	Method  string
	Path    string
	Host    string
	Scheme  string
	Headers map[string]string
	// SourcePrincipal is attributes.source.principal — the SPIFFE identity
	// Istio derives from the mTLS peer certificate. mvp_docs/02 §3 and M-007:
	// this replaces the sample's positional parsing of x-forwarded-client-cert,
	// which needed a hard-coded value for local development.
	SourcePrincipal string
	// DestinationPrincipal identifies the enforcement point in the log.
	DestinationPrincipal string
	RequestID            string
}

func (r Request) header(name string) string { return r.Headers[strings.ToLower(name)] }

// Outcome is what Envoy should do.
type Outcome int

const (
	// Permit — forward upstream, with the headers in Response.Headers added.
	Permit Outcome = iota
	// Deny — reject with Response.Status.
	Deny
	// Redirect — 302 to Response.Location, setting Response.SetCookie.
	Redirect
)

// Response is the pipeline's answer.
type Response struct {
	Outcome   Outcome
	Status    int
	Reason    string
	Location  string
	SetCookie string
	Headers   map[string]string
	Body      string
	// ConsentChallenge is set when the denial is `consent_required`, so a
	// client knows where to send the user.
	ConsentChallenge string
}

// Snapshot is a validated configuration and the route table compiled from it.
// The two always travel together: a table compiled from one config and used
// with another would authorize against rules nobody wrote.
type Snapshot struct {
	cfg   *config.Config
	table *routes.Table
}

// NewSnapshot compiles a configuration into a servable snapshot.
func NewSnapshot(cfg *config.Config) (*Snapshot, error) {
	table, err := routes.Compile(cfg.Rules)
	if err != nil {
		return nil, err
	}
	return &Snapshot{cfg: cfg, table: table}, nil
}

// Rules reports how many rules the snapshot serves, for logging.
func (s *Snapshot) Rules() int { return len(s.cfg.Rules) }

// Pipeline is the decision point. It is read-only with respect to SpiceDB.
type Pipeline struct {
	// snapshot is swapped atomically so that onboarding a device or an agent —
	// which adds an entry to a registry — does not require restarting the one
	// component every request depends on. A request reads the snapshot once and
	// is decided entirely against it; a reload never applies to a request
	// already in flight.
	snapshot atomic.Pointer[Snapshot]

	oidc     *oidcauth.Provider
	sessions session.Store
	perms    spicedb.Checker
	// consentBase is the account console's external base URL, used to build
	// the consent and delegation challenges.
	consentBase string
}

// New wires the pipeline.
func New(snap *Snapshot, op *oidcauth.Provider, st session.Store, pc spicedb.Checker, consentBase string) *Pipeline {
	p := &Pipeline{oidc: op, sessions: st, perms: pc, consentBase: consentBase}
	p.snapshot.Store(snap)
	return p
}

// Swap installs a new configuration for subsequent requests.
//
// Callers must only ever pass a snapshot that compiled cleanly. A configuration
// that fails to load leaves the previous one serving — a bad edit must not be
// able to take the authorizer down, and it must not be able to open it either.
func (p *Pipeline) Swap(snap *Snapshot) { p.snapshot.Store(snap) }

const (
	callbackPath = "/_id/callback"
	logoutPath   = "/_id/logout"
)

// Check runs the pipeline. It never returns an error: an error inside becomes a
// denial, because the alternative is a permit produced by a bug.
func (p *Pipeline) Check(ctx context.Context, req Request) Response {
	started := time.Now()
	d := logx.Decision{
		DecisionID: uuid.NewString(),
		Enforcer:   enforcer(req.DestinationPrincipal),
		Host:       hostOnly(req.Host),
		Method:     req.Method,
		Path:       pathOnly(req.Path),
		Workload:   req.SourcePrincipal,
	}
	resp := p.check(ctx, req, &d)
	d.Allowed = resp.Outcome == Permit
	d.Reason = resp.Reason
	d.LatencyMS = float64(time.Since(started).Microseconds()) / 1000.0
	logx.Log(d)
	if resp.Headers == nil {
		resp.Headers = map[string]string{}
	}
	resp.Headers["x-authz-decision-id"] = d.DecisionID
	return resp
}

func (p *Pipeline) check(ctx context.Context, req Request, d *logx.Decision) Response {
	snap := p.snapshot.Load()
	cfg, table := snap.cfg, snap.table

	// ---- step 1: special paths -------------------------------------------
	// OIDC mechanics must not be subject to the authorization they establish
	// (mvp_docs/07 §5, item 3).
	switch pathOnly(req.Path) {
	case callbackPath:
		return p.handleCallback(ctx, cfg, req, d)
	case logoutPath:
		return p.handleLogout(ctx, cfg, req, d)
	}

	// ---- step 4 (early, for public routes) --------------------------------
	// Public routes are still rules. Matching them before authentication is
	// what lets an unauthenticated landing page and static assets exist
	// without an implicit allow anywhere in the system.
	rule, params, matched := table.Match(req.Host, req.Method, req.Path)
	if matched {
		d.Rule = rule.ID
	}
	if matched && rule.Public {
		return Response{Outcome: Permit, Reason: logx.ReasonPermitted}
	}

	// ---- steps 2 and 3: principal, application, workload ------------------
	id, resp := p.identify(ctx, cfg, req, rule, matched, d)
	if resp != nil {
		return *resp
	}
	d.Principal = id.subject
	d.Kind = id.kind
	d.Actor = id.agent
	d.Application = id.application

	// ---- the workload must be bound to the actor it presents ---------------
	// mTLS proves which process is calling; the token only claims what it is
	// acting as. Checking them independently let a process registered to run an
	// agent decline to exchange its token and act as the application instead,
	// skipping delegation and step-up. Binding them closes that generally,
	// rather than route by route.
	if resp := checkActorBinding(cfg, req.SourcePrincipal, id); resp != nil {
		return *resp
	}

	// ---- step 4: no matching rule denies (M-006) --------------------------
	if !matched {
		logx.Error("no route rule matched — configuration error",
			"host", d.Host, "method", d.Method, "path", d.Path)
		return Response{Outcome: Deny, Status: 403, Reason: logx.ReasonNoRouteMatch,
			Body: denyBody(logx.ReasonNoRouteMatch, "no authorization rule matches this endpoint")}
	}

	// ---- step 5: is this workload registered to serve this application? ---
	if resp := checkWorkload(rule, req.SourcePrincipal); resp != nil {
		return *resp
	}

	// A route that owns no resource stops here: the principal is established
	// and the workload is registered, and there is nothing further to ask.
	if rule.AuthenticatedOnly {
		return Response{Outcome: Permit, Reason: logx.ReasonPermitted, Headers: upstreamHeaders(id)}
	}

	// ---- step 6: step-up ---------------------------------------------------
	if resp := stepUp(rule, id); resp != nil {
		if rule.Capability != "" {
			d.Capability = rule.Capability
		}
		resp.ConsentChallenge = p.stepUpChallenge(req)
		resp.Headers = map[string]string{
			"www-authenticate": fmt.Sprintf(
				`Step-Up realm="gerege", capability=%q, acr=%q, authorize_uri=%q`,
				rule.Capability, fmt.Sprint(rule.StepUpMinACR), resp.ConsentChallenge),
		}
		return *resp
	}

	// ---- step 7: permission (+ consent) (+ delegation) in one bulk call ----
	resourceID, err := resolveResourceID(rule, params, id.subject)
	if err != nil {
		logx.Error("cannot resolve resource id", "rule", rule.ID, "err", err.Error())
		return Response{Outcome: Deny, Status: 403, Reason: logx.ReasonInternalError,
			Body: denyBody(logx.ReasonInternalError, "resource could not be resolved")}
	}
	d.Resource = rule.ResourceType + ":" + resourceID
	d.Permission = rule.Permission

	// The questions are built as a list of named checks rather than positional
	// slots. There are up to four of them now, and indexing outcomes by hand is
	// exactly the sort of bookkeeping that silently reads the wrong answer.
	plan := []check{{
		kind:   checkPermission,
		reason: logx.ReasonPermissionDenied,
		detail: fmt.Sprintf("%s:%s#%s is not granted", rule.ResourceType, resourceID, rule.Permission),
		query: spicedb.Query{
			ResourceType: rule.ResourceType,
			ResourceID:   resourceID,
			Permission:   rule.Permission,
			SubjectType:  id.subjectType,
			SubjectID:    id.subject,
		},
	}}

	if consentApplies(cfg, rule, id) {
		d.Capability = rule.Capability
		d.ConsentSeen = true
		plan = append(plan, check{
			kind:   checkConsent,
			reason: logx.ReasonConsentRequired,
			detail: fmt.Sprintf("%s has not been granted %s", id.application, rule.Capability),
			query: spicedb.Query{
				ResourceType: "gerege/consent_grant",
				ResourceID:   consentGrantID(id.subject, id.application),
				Permission:   "includes",
				SubjectType:  "gerege/capability",
				SubjectID:    rule.Capability,
			},
		})
	}

	if id.kind == kindAgent {
		// Enrolment: may this agent act for this user at all? Durable, and
		// distinct from the delegation, which says what it may do for them. A
		// delegation names a user and an agent but says nothing about whether
		// that pairing was ever intended — so an agent handed somebody else's
		// token would otherwise only be caught if that person happened to have
		// no delegation.
		plan = append(plan, check{
			kind:   checkEnrolment,
			reason: logx.ReasonAgentNotEnrolled,
			detail: fmt.Sprintf("%s is not enrolled to act for %s", id.agent, id.subject),
			query: spicedb.Query{
				ResourceType: "gerege/agent",
				ResourceID:   id.agent,
				Permission:   "act_for",
				SubjectType:  "gerege/user",
				SubjectID:    id.subject,
			},
		})

		if rule.Capability != "" {
			d.Capability = rule.Capability
			d.Delegated = true
			plan = append(plan, check{
				kind:   checkDelegation,
				reason: logx.ReasonDelegationRequired,
				detail: fmt.Sprintf("%s was not delegated %s by %s, or the delegation has expired",
					id.agent, rule.Capability, id.subject),
				query: spicedb.Query{
					ResourceType: "gerege/delegation",
					ResourceID:   DelegationID(id.subject, id.agent),
					Permission:   "includes",
					SubjectType:  "gerege/capability",
					SubjectID:    rule.Capability,
				},
			})
		}
	}

	queries := make([]spicedb.Query, len(plan))
	for i, c := range plan {
		queries[i] = c.query
	}

	outcomes, err := p.perms.CheckBulk(ctx, d.DecisionID, rule.Consistency == config.ConsistencyFull, queries...)
	if err != nil {
		// Claim C8. SpiceDB unreachable is a denial, every time, with no
		// stale-serve window in the MVP.
		logx.Error("spicedb check failed", "err", err.Error(), "decision_id", d.DecisionID)
		return Response{Outcome: Deny, Status: 403, Reason: logx.ReasonBackendUnavailable,
			Body: denyBody(logx.ReasonBackendUnavailable, "the authorization backend could not be reached")}
	}

	for i, c := range plan {
		r := classify(outcomes[i], c.reason, c.detail)
		if r == nil {
			continue
		}
		switch c.kind {
		case checkConsent:
			r.ConsentChallenge = p.challenge(id.application, rule.Capability, req)
			r.Headers = map[string]string{"www-authenticate": fmt.Sprintf(
				`Consent realm="gerege", application=%q, capability=%q, consent_uri=%q`,
				id.application, rule.Capability, r.ConsentChallenge)}
			r.Body = consentBody(id.application, rule.Capability, r.ConsentChallenge)
		case checkDelegation:
			r.ConsentChallenge = p.delegationChallenge(id.agent, rule.Capability, req)
			r.Headers = map[string]string{"www-authenticate": fmt.Sprintf(
				`Delegation realm="gerege", agent=%q, capability=%q, delegate_uri=%q`,
				id.agent, rule.Capability, r.ConsentChallenge)}
			r.Body = delegationBody(id.agent, rule.Capability, r.ConsentChallenge)
		}
		return *r
	}

	// ---- permit ------------------------------------------------------------
	return Response{Outcome: Permit, Reason: logx.ReasonPermitted, Headers: upstreamHeaders(id)}
}

// upstreamHeaders are mvp_docs/04 §2.2, plus the relayed access token.
func upstreamHeaders(id identity) map[string]string {
	h := map[string]string{
		"x-user-id":     id.subject,
		"x-user-name":   id.display,
		"x-application": id.application,
	}
	if id.accessToken != "" {
		// Token relay. The internal hop must carry the same principal and the
		// same `azp`, which is what lets device-service evaluate Alice's
		// permission and Smart Home's consent independently (mvp_docs/02 §4.3).
		// The token still never reaches the browser — only upstream.
		h["authorization"] = "Bearer " + id.accessToken
	}
	return h
}

// check is one question put to SpiceDB, with what to say if the answer is no.
type check struct {
	kind   checkKind
	query  spicedb.Query
	reason string
	detail string
}

type checkKind int

const (
	checkPermission checkKind = iota
	checkConsent
	checkEnrolment
	checkDelegation
)

// checkActorBinding enforces the pairing of workload and actor in both
// directions: a workload registered to run an agent may present only that
// agent's token, and an agent's token is accepted only from its own workload.
//
// The asymmetry it fixes is worth stating. mTLS proves the workload and cannot
// be forged by a compromised peer. The token merely claims the actor. Checking
// them separately means the strong identity never constrains the weak one — so
// the process holding a user's token could simply choose not to exchange it.
func checkActorBinding(cfg *config.Config, sourcePrincipal string, id identity) *Response {
	bound, isAgentWorkload := cfg.AgentByWorkload(sourcePrincipal)

	if isAgentWorkload && (id.kind != kindAgent || id.agent != bound.Object) {
		logx.Error("agent workload presented a token that is not its agent's",
			"workload", sourcePrincipal, "expected_agent", bound.Object,
			"presented_kind", id.kind, "presented_actor", id.agent,
			"presented_azp", id.application)
		return &Response{Outcome: Deny, Status: 403, Reason: logx.ReasonActorNotBound,
			Body: denyBody(logx.ReasonActorNotBound,
				"this workload may act only as its registered agent; forwarding the user's own token is not permitted")}
	}

	if id.kind == kindAgent && !isAgentWorkload {
		if ag, ok := cfg.AgentByClient(id.application); ok && ag.Workload != "" {
			logx.Error("agent token presented from a workload it is not bound to",
				"agent", id.agent, "bound_to", ag.Workload, "source_principal", sourcePrincipal)
			return &Response{Outcome: Deny, Status: 403, Reason: logx.ReasonActorNotBound,
				Body: denyBody(logx.ReasonActorNotBound,
					"this agent's token is only accepted from the workload it is bound to")}
		}
	}
	return nil
}

func classify(o spicedb.Outcome, denyReason, detail string) *Response {
	switch o {
	case spicedb.Permitted:
		return nil
	case spicedb.Conditional:
		// M-008. A caveated relationship with missing context denies, and is
		// logged as a configuration error rather than an authorization result.
		logx.Error("conditional result treated as denied (M-008)", "detail", detail)
		return &Response{Outcome: Deny, Status: 403, Reason: logx.ReasonConditionalResult,
			Body: denyBody(logx.ReasonConditionalResult, "caveat context missing — configuration error")}
	default:
		return &Response{Outcome: Deny, Status: 403, Reason: denyReason, Body: denyBody(denyReason, detail)}
	}
}

// checkWorkload is mvp_docs/04 R6. It is a static lookup in configuration, not
// a SpiceDB query: deployment topology changes at deploy time, not at request
// time (mvp_docs/03 §4).
func checkWorkload(rule *config.Rule, source string) *Response {
	if len(rule.Callers) == 0 {
		return nil
	}
	for _, allowed := range rule.Callers {
		if allowed == source {
			return nil
		}
	}
	logx.Error("workload not registered for this route",
		"rule", rule.ID, "source_principal", source, "allowed", strings.Join(rule.Callers, ","))
	return &Response{Outcome: Deny, Status: 403, Reason: logx.ReasonWorkloadNotRegistered,
		Body: denyBody(logx.ReasonWorkloadNotRegistered,
			"the calling workload is not registered to serve this application")}
}

// consentApplies encodes mvp_docs/03 §4.
//
//	Alice via profile-app on her own profile   → no   (first-party)
//	smarthome-app reading Alice's profile      → yes
//	sensor-1 pushing its own telemetry         → no   (no user in the loop)
//	internal hop carrying azp=smarthome-app    → yes  (the hop does not change
//	                                                   the application)
func consentApplies(cfg *config.Config, rule *config.Rule, id identity) bool {
	if !rule.ConsentRequired {
		return false
	}
	if id.kind != kindUser {
		return false
	}
	if app, ok := cfg.AppByName(id.application); ok && app.FirstParty {
		return false
	}
	return true
}

// stepUp refuses a sensitive route to anyone who cannot show a recent,
// deliberate human authentication.
//
// An agent is refused unconditionally, and not because its `acr` is too low —
// it inherits the human's acr through token exchange, so the claim proves
// nothing about whether a person is present now. The refusal is structural: an
// agent cannot re-authenticate the person behind it, so "a human must be here
// for this one" and "an agent may do this alone" are contradictory
// requirements. Returning the challenge to the caller is what puts the human
// back in the loop.
func stepUp(rule *config.Rule, id identity) *Response {
	if !rule.StepUp {
		return nil
	}
	switch id.kind {
	case kindAgent:
		logx.Error("agent refused a step-up route",
			"agent", id.agent, "principal", id.subject, "capability", rule.Capability)
		return &Response{Outcome: Deny, Status: 403, Reason: logx.ReasonStepUpRequired,
			Body: denyBody(logx.ReasonStepUpRequired,
				"this capability requires a person to authenticate; an agent cannot")}
	case kindSystem:
		return &Response{Outcome: Deny, Status: 403, Reason: logx.ReasonStepUpRequired,
			Body: denyBody(logx.ReasonStepUpRequired,
				"this capability requires a human principal")}
	}
	if id.acr < rule.StepUpMinACR {
		return &Response{Outcome: Deny, Status: 403, Reason: logx.ReasonStepUpRequired,
			Body: denyBody(logx.ReasonStepUpRequired,
				fmt.Sprintf("this capability requires acr >= %d; the session presents %d",
					rule.StepUpMinACR, id.acr))}
	}
	return nil
}

func (p *Pipeline) stepUpChallenge(req Request) string {
	q := url.Values{}
	q.Set("return_to", externalURL(req))
	return strings.TrimRight(p.consentBase, "/") + "/reauthenticate?" + q.Encode()
}

func (p *Pipeline) delegationChallenge(agent, capability string, req Request) string {
	q := url.Values{}
	q.Set("agent", agent)
	q.Set("capability", capability)
	q.Set("return_to", externalURL(req))
	return strings.TrimRight(p.consentBase, "/") + "/delegate?" + q.Encode()
}

// DelegationID is the `<user>|<agent>` object id, matching consentGrantID.
func DelegationID(subject, agent string) string { return subject + "|" + agent }

func (p *Pipeline) challenge(application, capability string, req Request) string {
	q := url.Values{}
	q.Set("application", application)
	q.Set("capability", capability)
	q.Set("return_to", externalURL(req))
	return strings.TrimRight(p.consentBase, "/") + "/consent?" + q.Encode()
}

// consentGrantID is the `<user>|<application>` pattern from mvp_docs/03 §3.
// The document writes it with `~`; SpiceDB object ids do not permit that
// character (pkg/tuple/parsing.go), so `|` is used, which does.
func consentGrantID(subject, application string) string { return subject + "|" + application }

func resolveResourceID(rule *config.Rule, params map[string]string, principal string) (string, error) {
	switch {
	case rule.ResourceIDFrom == "principal":
		return principal, nil
	case strings.HasPrefix(rule.ResourceIDFrom, "literal:"):
		return strings.TrimPrefix(rule.ResourceIDFrom, "literal:"), nil
	case strings.HasPrefix(rule.ResourceIDFrom, "path:"):
		name := strings.TrimPrefix(rule.ResourceIDFrom, "path:")
		v, ok := params[name]
		if !ok || v == "" {
			return "", fmt.Errorf("path parameter %q not present", name)
		}
		return v, nil
	}
	return "", errors.New("unsupported resourceIdFrom")
}

// enforcer names the point that made the decision, so the log tells the reader
// *where* a request was refused as well as why.
//
// Istio populates destination.principal from the receiving workload's own
// certificate, which happens for every sidecar. The ingress gateway terminates a
// plaintext connection from outside the mesh and has no such peer, so an empty
// value identifies the edge — the only enforcement point in this topology that
// is not a sidecar.
func enforcer(destinationPrincipal string) string {
	if destinationPrincipal == "" {
		return "ingress-gateway"
	}
	// spiffe://cluster.local/ns/apps/sa/device-service → apps/device-service
	parts := strings.Split(destinationPrincipal, "/")
	if len(parts) >= 7 && parts[3] == "ns" && parts[5] == "sa" {
		return parts[4] + "/" + parts[6]
	}
	return destinationPrincipal
}

func hostOnly(h string) string { return strings.Split(h, ":")[0] }

func pathOnly(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		return p[:i]
	}
	return p
}

func externalURL(req Request) string {
	scheme := req.Scheme
	if v := req.header("x-forwarded-proto"); v != "" {
		// mvp_docs/06 hazard 1: the sample hard-coded http for local
		// development. The scheme comes from the forwarded header, with the
		// configured default as the fallback — not a code edit.
		scheme = v
	}
	if scheme == "" {
		scheme = "http"
	}
	return scheme + "://" + req.Host + req.Path
}

// queryValues parses the query string out of the raw ":path" pseudo-header,
// which Envoy delivers complete with query.
func queryValues(path string) url.Values {
	if i := strings.Index(path, "?"); i >= 0 {
		v, _ := url.ParseQuery(path[i+1:])
		return v
	}
	return url.Values{}
}
