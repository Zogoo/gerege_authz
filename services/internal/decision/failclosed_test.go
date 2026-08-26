package decision

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/gerege/idp-mvp/internal/config"
	"github.com/gerege/idp-mvp/internal/logx"
	"github.com/gerege/idp-mvp/internal/oidcauth"
	"github.com/gerege/idp-mvp/internal/routes"
	"github.com/gerege/idp-mvp/internal/session"
	"github.com/gerege/idp-mvp/internal/spicedb"
)

// TestFailsClosed is the executable form of claim C8.
//
// mvp_docs/04 §9: "The fail-closed unit test is the one that must exist before
// any other. It is the executable form of claim C8, and every subsequent change
// is measured against it."
//
// The table walks every branch that can go wrong and asserts the same thing
// each time: the outcome is not Permit.
func TestFailsClosed(t *testing.T) {
	env := newEnv(t)

	aliceProfile := "/api/profile/alice"

	cases := []struct {
		name       string
		req        Request
		checker    spicedb.Checker
		wantReason string
	}{
		{
			name:       "spicedb unreachable",
			req:        env.bearerReq("GET", aliceProfile, env.token(t, "alice", "smarthome-app")),
			checker:    erroringChecker{},
			wantReason: logx.ReasonBackendUnavailable,
		},
		{
			name:       "spicedb returns a conditional result",
			req:        env.bearerReq("GET", aliceProfile, env.token(t, "alice", "smarthome-app")),
			checker:    fixedChecker{spicedb.Conditional, spicedb.Conditional},
			wantReason: logx.ReasonConditionalResult,
		},
		{
			name:       "spicedb returns fewer results than asked for",
			req:        env.bearerReq("GET", aliceProfile, env.token(t, "alice", "smarthome-app")),
			checker:    shortChecker{},
			wantReason: logx.ReasonBackendUnavailable,
		},
		{
			name:       "permission denied",
			req:        env.bearerReq("GET", aliceProfile, env.token(t, "bob", "smarthome-app")),
			checker:    fixedChecker{spicedb.Denied, spicedb.Permitted},
			wantReason: logx.ReasonPermissionDenied,
		},
		{
			name:       "consent missing",
			req:        env.bearerReq("GET", aliceProfile, env.token(t, "alice", "smarthome-app")),
			checker:    fixedChecker{spicedb.Permitted, spicedb.Denied},
			wantReason: logx.ReasonConsentRequired,
		},
		{
			name:       "no rule matches the endpoint",
			req:        env.bearerReq("GET", "/api/undeclared-endpoint", env.token(t, "alice", "smarthome-app")),
			checker:    fixedChecker{spicedb.Permitted, spicedb.Permitted},
			wantReason: logx.ReasonNoRouteMatch,
		},
		{
			name:       "no credentials at all on an API route",
			req:        Request{Method: "GET", Path: aliceProfile, Host: "profile-service", Headers: map[string]string{}},
			checker:    fixedChecker{spicedb.Permitted, spicedb.Permitted},
			wantReason: logx.ReasonNoSession,
		},
		{
			name:       "token with a broken signature",
			req:        env.bearerReq("GET", aliceProfile, env.token(t, "alice", "smarthome-app")+"tampered"),
			checker:    fixedChecker{spicedb.Permitted, spicedb.Permitted},
			wantReason: logx.ReasonTokenInvalid,
		},
		{
			name:       "expired token",
			req:        env.bearerReq("GET", aliceProfile, env.expiredToken(t, "alice", "smarthome-app")),
			checker:    fixedChecker{spicedb.Permitted, spicedb.Permitted},
			wantReason: logx.ReasonTokenInvalid,
		},
		{
			name:       "token from an unregistered application",
			req:        env.bearerReq("GET", aliceProfile, env.token(t, "alice", "attacker-app")),
			checker:    fixedChecker{spicedb.Permitted, spicedb.Permitted},
			wantReason: logx.ReasonUnknownApplication,
		},
		{
			name: "valid token replayed from an unregistered workload",
			req: env.withSource(
				env.bearerReq("POST", "/internal/devices/lock-1/unlock", env.token(t, "alice", "smarthome-app")),
				"spiffe://cluster.local/ns/apps/sa/some-other-service"),
			checker:    fixedChecker{spicedb.Permitted, spicedb.Permitted},
			wantReason: logx.ReasonWorkloadNotRegistered,
		},
		{
			name: "valid token replayed from outside the mesh with no peer identity",
			req: env.withSource(
				env.bearerReq("POST", "/internal/devices/lock-1/unlock", env.token(t, "alice", "smarthome-app")),
				""),
			checker:    fixedChecker{spicedb.Permitted, spicedb.Permitted},
			wantReason: logx.ReasonWorkloadNotRegistered,
		},
		{
			name:       "session cookie that refers to nothing, on a non-browser request",
			req:        env.cookieReq("GET", aliceProfile, "does-not-exist"),
			checker:    fixedChecker{spicedb.Permitted, spicedb.Permitted},
			wantReason: logx.ReasonNoSession,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := env.pipeline(tc.checker)
			got := p.Check(context.Background(), tc.req)
			if got.Outcome == Permit {
				t.Fatalf("PERMITTED an error path — claim C8 is broken. reason=%q", got.Reason)
			}
			if got.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", got.Reason, tc.wantReason)
			}
			if got.Outcome == Deny && got.Status == 0 {
				t.Errorf("deny with no HTTP status")
			}
		})
	}
}

// TestPermitsTheHappyPath exists so that TestFailsClosed cannot pass by
// denying everything, which would be the easiest possible false green.
func TestPermitsTheHappyPath(t *testing.T) {
	env := newEnv(t)
	p := env.pipeline(fixedChecker{spicedb.Permitted, spicedb.Permitted})

	got := p.Check(context.Background(), env.bearerReq("GET", "/api/profile/alice", env.token(t, "alice", "smarthome-app")))
	if got.Outcome != Permit {
		t.Fatalf("outcome = %v (reason %q), want Permit", got.Outcome, got.Reason)
	}
	if got.Headers["x-user-id"] != "alice" {
		t.Errorf("x-user-id = %q, want alice", got.Headers["x-user-id"])
	}
	if got.Headers["x-application"] != "smarthome-app" {
		t.Errorf("x-application = %q, want smarthome-app", got.Headers["x-application"])
	}
	if !strings.HasPrefix(got.Headers["authorization"], "Bearer ") {
		t.Errorf("access token was not relayed upstream; the internal hop would lose the principal")
	}
}

// TestFirstPartySkipsConsent is the contrast that makes Scenario 3a land: same
// user, same data, same permission, different application, different answer.
func TestFirstPartySkipsConsent(t *testing.T) {
	env := newEnv(t)
	// Only one outcome is supplied. If the pipeline asked SpiceDB a consent
	// question for a first-party application, countingChecker would see two
	// queries and the assertion below would fail.
	c := &countingChecker{outcomes: []spicedb.Outcome{spicedb.Permitted, spicedb.Permitted}}
	p := env.pipeline(c)

	got := p.Check(context.Background(), env.bearerReq("GET", "/api/profile/alice", env.token(t, "alice", "profile-app")))
	if got.Outcome != Permit {
		t.Fatalf("outcome = %v (reason %q), want Permit", got.Outcome, got.Reason)
	}
	if c.lastCount != 1 {
		t.Errorf("sent %d checks for a first-party application, want 1 (no consent question)", c.lastCount)
	}
}

// TestSystemPrincipalSkipsConsent — a sensor reporting its own readings has no
// user in the loop, so there is no consent to evaluate (mvp_docs/02 §4.4).
func TestSystemPrincipalSkipsConsent(t *testing.T) {
	env := newEnv(t)
	c := &countingChecker{outcomes: []spicedb.Outcome{spicedb.Permitted}}
	p := env.pipeline(c)

	got := p.Check(context.Background(), env.bearerReq("POST", "/telemetry/sensor-1", env.token(t, "service-account-sensor-1", "sensor-1")))
	if got.Outcome != Permit {
		t.Fatalf("outcome = %v (reason %q), want Permit", got.Outcome, got.Reason)
	}
	if c.lastCount != 1 {
		t.Errorf("sent %d checks for a device identity, want 1", c.lastCount)
	}
	if c.lastQueries[0].SubjectType != "gerege/system_principal" {
		t.Errorf("subject type = %q, want gerege/system_principal", c.lastQueries[0].SubjectType)
	}
	if c.lastQueries[0].SubjectID != "sensor-1" {
		t.Errorf("subject id = %q, want sensor-1", c.lastQueries[0].SubjectID)
	}
}

// TestDeviceIdentityIsNotASkeletonKey — the sensor's token is valid, but the
// resource id comes from the path, so it can only ever authorize what the
// relationship graph allows.
func TestDeviceIdentityIsNotASkeletonKey(t *testing.T) {
	env := newEnv(t)
	c := &countingChecker{outcomes: []spicedb.Outcome{spicedb.Denied}}
	p := env.pipeline(c)

	got := p.Check(context.Background(), env.bearerReq("POST", "/telemetry/thermostat-1", env.token(t, "service-account-sensor-1", "sensor-1")))
	if got.Outcome == Permit {
		t.Fatal("sensor-1 was permitted to push telemetry for a device it has no relationship to")
	}
	if c.lastQueries[0].ResourceID != "thermostat-1" {
		t.Errorf("resource id = %q, want thermostat-1", c.lastQueries[0].ResourceID)
	}
}

// ---------------------------------------------------------------------------
// test environment
// ---------------------------------------------------------------------------

type env struct {
	cfg   *config.Config
	table *routes.Table
	oidc  *oidcauth.Provider
	key   *rsa.PrivateKey
	iss   string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: key.Public(), KeyID: "test", Algorithm: "RS256", Use: "sig",
	}}}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(ts.Close)

	external := "http://id.local.test/realms/gerege"
	cfg := &config.Config{
		Issuer:        config.Issuer{External: external, Internal: ts.URL + "/realms/gerege"},
		Cookie:        config.Cookie{Name: "gerege_session", TTL: time.Hour, PendTTL: time.Minute},
		SpiceDB:       config.SpiceDB{Endpoint: "unused", Timeout: time.Second},
		DefaultAction: "DENY",
		Applications: []config.Application{
			{Name: "profile-app", ClientSecret: "s", Hosts: []string{"profile.local.test"}, FirstParty: true},
			{Name: "smarthome-app", ClientSecret: "s", Hosts: []string{"smarthome.local.test"}},
		},
		SystemPrincipals: map[string]string{"sensor-1": "sensor-1"},
		Agents:           []config.Agent{{Name: "assistant-agent", Object: "assistant"}},
		Rules: []config.Rule{
			{
				ID: "profile-read", Methods: []string{"GET"}, Path: "/api/profile/{userId}",
				ResourceType: "gerege/user_profile", ResourceIDFrom: "path:userId", Permission: "view",
				Capability: "profile_read", ConsentRequired: true,
				AuthMode: config.AuthModeEither, Consistency: config.ConsistencyFull,
			},
			{
				ID: "device-unlock", Methods: []string{"POST"}, Path: "/internal/devices/{deviceId}/unlock",
				ResourceType: "gerege/device", ResourceIDFrom: "path:deviceId", Permission: "operate_lock",
				Capability: "devices_unlock", ConsentRequired: true,
				StepUp: true, StepUpMinACR: 1,
				AuthMode: config.AuthModeBearer, Consistency: config.ConsistencyFull,
				Callers: []string{"spiffe://cluster.local/ns/apps/sa/smarthome-service"},
			},
			{
				ID: "device-state", Methods: []string{"POST"}, Path: "/internal/devices/{deviceId}/state",
				ResourceType: "gerege/device", ResourceIDFrom: "path:deviceId", Permission: "operate",
				Capability: "devices_control", ConsentRequired: true,
				AuthMode: config.AuthModeBearer, Consistency: config.ConsistencyFull,
				Callers: []string{"spiffe://cluster.local/ns/apps/sa/smarthome-service"},
			},
			{
				ID: "telemetry", Methods: []string{"POST"}, Path: "/telemetry/{deviceId}",
				ResourceType: "gerege/device", ResourceIDFrom: "path:deviceId", Permission: "push_telemetry",
				AuthMode: config.AuthModeBearer, Consistency: config.ConsistencyFull,
			},
		},
	}
	table, err := routes.Compile(cfg.Rules)
	if err != nil {
		t.Fatal(err)
	}
	return &env{cfg: cfg, table: table, oidc: oidcauth.New(cfg.Issuer, ts.Client()), key: key, iss: external}
}

func (e *env) pipeline(c spicedb.Checker) *Pipeline {
	return New(e.cfg, e.table, e.oidc, session.NewMemoryStore(), c, "http://account.local.test")
}

func (e *env) token(t *testing.T, sub, azp string) string {
	return e.mint(t, sub, azp, time.Now().Add(5*time.Minute), "1")
}

// agentToken is what RFC 8693 token exchange produces: the human is still the
// subject, the agent is the authorized party.
func (e *env) agentToken(t *testing.T, sub string) string {
	return e.mint(t, sub, "assistant-agent", time.Now().Add(5*time.Minute), "1")
}

func (e *env) ssoToken(t *testing.T, sub, azp string) string {
	return e.mint(t, sub, azp, time.Now().Add(5*time.Minute), "0")
}

func (e *env) expiredToken(t *testing.T, sub, azp string) string {
	return e.mint(t, sub, azp, time.Now().Add(-5*time.Minute), "1")
}

func (e *env) mint(t *testing.T, sub, azp string, exp time.Time, acr string) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: e.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"iss": e.iss, "sub": sub, "azp": azp,
		"exp": exp.Unix(), "iat": time.Now().Add(-time.Minute).Unix(),
		"preferred_username": sub, "acr": acr,
	})
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (e *env) bearerReq(method, path, token string) Request {
	return Request{
		Method: method, Path: path, Host: "profile-service.apps.svc.cluster.local", Scheme: "http",
		Headers:         map[string]string{"authorization": "Bearer " + token},
		SourcePrincipal: "spiffe://cluster.local/ns/apps/sa/smarthome-service",
	}
}

func (e *env) cookieReq(method, path, sid string) Request {
	return Request{
		Method: method, Path: path, Host: "profile-service.apps.svc.cluster.local", Scheme: "http",
		Headers: map[string]string{"cookie": "gerege_session=" + sid},
	}
}

func (e *env) withSource(r Request, principal string) Request {
	r.SourcePrincipal = principal
	return r
}

// ---------------------------------------------------------------------------
// checker doubles
// ---------------------------------------------------------------------------

type erroringChecker struct{}

func (erroringChecker) CheckBulk(context.Context, string, bool, ...spicedb.Query) ([]spicedb.Outcome, error) {
	return nil, spicedb.ErrBackendUnavailable
}
func (erroringChecker) Close() error { return nil }

type shortChecker struct{}

func (shortChecker) CheckBulk(_ context.Context, _ string, _ bool, q ...spicedb.Query) ([]spicedb.Outcome, error) {
	if len(q) < 2 {
		return []spicedb.Outcome{spicedb.Permitted}, nil
	}
	return nil, spicedb.ErrBackendUnavailable
}
func (shortChecker) Close() error { return nil }

type fixedChecker []spicedb.Outcome

func (f fixedChecker) CheckBulk(_ context.Context, _ string, _ bool, q ...spicedb.Query) ([]spicedb.Outcome, error) {
	out := make([]spicedb.Outcome, len(q))
	for i := range q {
		if i < len(f) {
			out[i] = f[i]
		}
	}
	return out, nil
}
func (fixedChecker) Close() error { return nil }

type countingChecker struct {
	outcomes    []spicedb.Outcome
	lastCount   int
	lastQueries []spicedb.Query
}

func (c *countingChecker) CheckBulk(_ context.Context, _ string, _ bool, q ...spicedb.Query) ([]spicedb.Outcome, error) {
	c.lastCount = len(q)
	c.lastQueries = q
	out := make([]spicedb.Outcome, len(q))
	for i := range q {
		if i < len(c.outcomes) {
			out[i] = c.outcomes[i]
		}
	}
	return out, nil
}
func (c *countingChecker) Close() error { return nil }

// ---------------------------------------------------------------------------
// agents
// ---------------------------------------------------------------------------

// TestAgentDoesNotInheritTheUsersAuthority is the whole point of the agent
// model, in one test.
//
// The token an agent presents has `sub` = alice. The permission check therefore
// passes on Alice's own authority, and consent — which she granted to the
// application — passes too. Nothing in the classical model can distinguish this
// request from one Alice made herself. What refuses it is the delegation check.
func TestAgentDoesNotInheritTheUsersAuthority(t *testing.T) {
	env := newEnv(t)
	// permission ✓  delegation ✗
	c := &countingChecker{outcomes: []spicedb.Outcome{spicedb.Permitted, spicedb.Denied}}
	p := env.pipeline(c)

	got := p.Check(context.Background(),
		env.bearerReq("GET", "/api/profile/alice", env.agentToken(t, "alice")))

	if got.Outcome == Permit {
		t.Fatal("an agent inherited the user's authority — the delegation check is not being applied")
	}
	if got.Reason != logx.ReasonDelegationRequired {
		t.Errorf("reason = %q, want %q", got.Reason, logx.ReasonDelegationRequired)
	}
	if c.lastCount != 2 {
		t.Fatalf("sent %d checks, want 2 (permission, delegation)", c.lastCount)
	}
	d := c.lastQueries[1]
	if d.ResourceType != "gerege/delegation" || d.ResourceID != "alice|assistant" {
		t.Errorf("delegation check was %s, want gerege/delegation:alice|assistant", d)
	}
	if d.SubjectID != "profile_read" {
		t.Errorf("delegation asked for capability %q, want profile_read", d.SubjectID)
	}
}

// TestAgentActsWhenDelegated — the positive control. Without it the test above
// could pass by refusing agents outright, which would be a different system.
func TestAgentActsWhenDelegated(t *testing.T) {
	env := newEnv(t)
	c := &countingChecker{outcomes: []spicedb.Outcome{spicedb.Permitted, spicedb.Permitted}}
	p := env.pipeline(c)

	got := p.Check(context.Background(),
		env.bearerReq("GET", "/api/profile/alice", env.agentToken(t, "alice")))
	if got.Outcome != Permit {
		t.Fatalf("outcome = %v (reason %q), want Permit", got.Outcome, got.Reason)
	}
	if got.Headers["x-user-id"] != "alice" {
		t.Errorf("principal = %q, want alice — the human stays accountable", got.Headers["x-user-id"])
	}
}

// TestConsentAndDelegationApplyToDifferentActors.
//
// Consent is a grant to an *application* — durable, and asked of the human once.
// Delegation is a grant to an *agent* — expiring, and asked of the human per
// task. Each actor kind gets exactly one of them, which is why an agent request
// does not also carry a consent question: delegation is the stricter grant in
// every dimension, and adding a durable consent to an agent would reintroduce
// the standing privilege the expiry exists to prevent.
//
// Both still appear in one end-to-end flow, at different hops: the application
// hop that asks the agent to act is consent-checked, and the agent's own calls
// are delegation-checked.
func TestConsentAndDelegationApplyToDifferentActors(t *testing.T) {
	env := newEnv(t)

	t.Run("an application request asks about consent, not delegation", func(t *testing.T) {
		c := &countingChecker{outcomes: []spicedb.Outcome{spicedb.Permitted, spicedb.Permitted}}
		p := env.pipeline(c)
		p.Check(context.Background(),
			env.bearerReq("GET", "/api/profile/alice", env.token(t, "alice", "smarthome-app")))
		if c.lastCount != 2 {
			t.Fatalf("sent %d checks, want 2 (permission, consent)", c.lastCount)
		}
		if got := c.lastQueries[1].ResourceType; got != "gerege/consent_grant" {
			t.Errorf("second check was %s, want a consent_grant", got)
		}
	})

	t.Run("an agent request asks about delegation, not consent", func(t *testing.T) {
		c := &countingChecker{outcomes: []spicedb.Outcome{spicedb.Permitted, spicedb.Permitted}}
		p := env.pipeline(c)
		p.Check(context.Background(),
			env.bearerReq("GET", "/api/profile/alice", env.agentToken(t, "alice")))
		if c.lastCount != 2 {
			t.Fatalf("sent %d checks, want 2 (permission, delegation)", c.lastCount)
		}
		if got := c.lastQueries[1].ResourceType; got != "gerege/delegation" {
			t.Errorf("second check was %s, want a delegation", got)
		}
	})

	t.Run("delegation cannot substitute for the user's own permission", func(t *testing.T) {
		p := env.pipeline(fixedChecker{spicedb.Denied, spicedb.Permitted})
		got := p.Check(context.Background(),
			env.bearerReq("GET", "/api/profile/alice", env.agentToken(t, "alice")))
		if got.Reason != logx.ReasonPermissionDenied {
			t.Errorf("reason = %q, want permission_denied — an agent cannot exceed its principal", got.Reason)
		}
	})
}

// TestAgentCannotStepUp — a route that requires a person to have authenticated
// deliberately is closed to agents by construction, not by policy.
//
// Note what is supplied: every SpiceDB answer is Permitted. The agent has the
// permission, the consent and the delegation, and it is still refused, because
// no amount of delegation can produce a human at a keyboard.
func TestAgentCannotStepUp(t *testing.T) {
	env := newEnv(t)
	c := &countingChecker{outcomes: []spicedb.Outcome{spicedb.Permitted, spicedb.Permitted}}
	p := env.pipeline(c)

	got := p.Check(context.Background(),
		env.withSource(
			env.bearerReq("POST", "/internal/devices/lock-1/unlock", env.agentToken(t, "alice")),
			"spiffe://cluster.local/ns/apps/sa/smarthome-service"))

	if got.Outcome == Permit {
		t.Fatal("an agent walked through a step-up route")
	}
	if got.Reason != logx.ReasonStepUpRequired {
		t.Errorf("reason = %q, want %q", got.Reason, logx.ReasonStepUpRequired)
	}
	if c.lastCount != 0 {
		t.Errorf("SpiceDB was consulted %d times; the step-up gate should refuse before asking", c.lastCount)
	}
	if got.ConsentChallenge == "" {
		t.Error("no challenge returned — the human has no way back into the loop")
	}
}

// TestHumanStepUpNeedsFreshAuthentication — the same route, for a person, turns
// on how they authenticated. acr=0 is Keycloak answering from an existing SSO
// session without re-prompting; acr=1 is an actual authentication.
func TestHumanStepUpNeedsFreshAuthentication(t *testing.T) {
	env := newEnv(t)
	req := func(tok string) Request {
		return env.withSource(
			env.bearerReq("POST", "/internal/devices/lock-1/unlock", tok),
			"spiffe://cluster.local/ns/apps/sa/smarthome-service")
	}

	p := env.pipeline(fixedChecker{spicedb.Permitted, spicedb.Permitted})
	if got := p.Check(context.Background(), req(env.ssoToken(t, "alice", "smarthome-app"))); got.Outcome == Permit {
		t.Error("acr=0 was permitted on a step-up route")
	} else if got.Reason != logx.ReasonStepUpRequired {
		t.Errorf("reason = %q, want step_up_required", got.Reason)
	}

	p = env.pipeline(fixedChecker{spicedb.Permitted, spicedb.Permitted})
	if got := p.Check(context.Background(), req(env.token(t, "alice", "smarthome-app"))); got.Outcome != Permit {
		t.Errorf("acr=1 was refused: %q", got.Reason)
	}
}

// TestAgentIsDistinguishableInTheAuditRecord — IBM's "no attribution, no
// accountability" gap. The decision record must separate the person who is
// accountable from the actor that ran.
func TestAgentIsDistinguishableInTheAuditRecord(t *testing.T) {
	env := newEnv(t)
	p := env.pipeline(fixedChecker{spicedb.Permitted, spicedb.Permitted})

	before := len(logx.Recent())
	p.Check(context.Background(),
		env.bearerReq("GET", "/api/profile/alice", env.agentToken(t, "alice")))
	recs := logx.Recent()
	if len(recs) <= before {
		t.Fatal("no decision was recorded")
	}
	d := recs[len(recs)-1]
	if d.Principal != "alice" {
		t.Errorf("principal = %q, want alice", d.Principal)
	}
	if d.Actor != "assistant" {
		t.Errorf("actor = %q, want assistant — an agent's action must not look like the human's", d.Actor)
	}
	if d.Kind != "agent" {
		t.Errorf("principal_kind = %q, want agent", d.Kind)
	}
	if !d.Delegated {
		t.Error("delegation_checked was false on an agent request")
	}
}
