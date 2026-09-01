// Package config loads and validates the external authorizer's configuration
// document.
//
// mvp_docs/04 §6: "Route config missing or unparseable → Deny all, refuse to
// start. A running authorizer with no rules is worse than one that will not
// start." Every Validate() failure here is fatal at startup by design.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the whole configuration document.
type Config struct {
	Issuer       Issuer        `yaml:"issuer"`
	Cookie       Cookie        `yaml:"cookie"`
	SpiceDB      SpiceDB       `yaml:"spicedb"`
	Applications []Application `yaml:"applications"`
	// SystemPrincipals maps an OAuth client id (the token `azp`) to a
	// gerege/system_principal object id. A token whose azp appears here is a
	// non-human caller: the principal is the system principal, and consent is
	// never evaluated (mvp_docs/03 §4, C7).
	SystemPrincipals map[string]string `yaml:"systemPrincipals"`
	// Agents maps an OAuth client id to a gerege/agent object id. A token whose
	// azp appears here was produced by RFC 8693 token exchange: `sub` is still
	// the human, but the actor is the agent. See Agent.
	Agents []Agent `yaml:"agents"`
	// DefaultAction is always DENY. It is spelled out in the document rather
	// than assumed, so that reading the config answers the question (M-006).
	DefaultAction string `yaml:"defaultAction"`
	Rules         []Rule `yaml:"rules"`
}

// Issuer records the two URLs Keycloak is reachable at.
//
// mvp_docs/06 hazard 4: "Keycloak reachable at two different URLs ... the
// issuer must match what the browser sees or token validation fails."
// External is what appears in the `iss` claim and what the browser is
// redirected to. Internal is used for back-channel calls from inside the
// cluster. ext-authz refuses to start if the internal discovery document does
// not report External as its issuer.
type Issuer struct {
	External string `yaml:"external"`
	Internal string `yaml:"internal"`
}

func (i Issuer) AuthorizationURL() string { return i.External + "/protocol/openid-connect/auth" }
func (i Issuer) EndSessionURL() string    { return i.External + "/protocol/openid-connect/logout" }
func (i Issuer) TokenURL() string         { return i.Internal + "/protocol/openid-connect/token" }
func (i Issuer) JWKSURL() string          { return i.Internal + "/protocol/openid-connect/certs" }
func (i Issuer) DiscoveryURL() string     { return i.Internal + "/.well-known/openid-configuration" }

// Cookie describes the opaque session cookie. It never carries a token
// (mvp_docs/04 §5).
type Cookie struct {
	Name    string        `yaml:"name"`
	Secure  bool          `yaml:"secure"`
	TTL     time.Duration `yaml:"ttl"`
	PendTTL time.Duration `yaml:"pendingTTL"`
}

// SpiceDB is the permission backend connection.
type SpiceDB struct {
	Endpoint string        `yaml:"endpoint"`
	Token    string        `yaml:"token"`
	Insecure bool          `yaml:"insecure"`
	Timeout  time.Duration `yaml:"timeout"`
}

// Application is an OAuth client a user can hold a session with.
type Application struct {
	// Name is the gerege/application object id and must equal the token `azp`.
	Name         string `yaml:"name"`
	ClientSecret string `yaml:"clientSecret"`
	// Hosts are the browser-facing hostnames served by this application. A
	// request arriving on one of these hosts with no session starts an OIDC
	// flow for this client.
	Hosts []string `yaml:"hosts"`
	// FirstParty suppresses the consent check. mvp_docs/03 §4: a user acting on
	// their own data through their own application is not a third-party
	// disclosure. This is a policy choice, and it is what makes the contrast in
	// Scenario 3a visible.
	FirstParty bool `yaml:"firstParty"`
	// DisplayName is shown on the consent screen.
	DisplayName string `yaml:"displayName"`
}

// Agent is a delegated actor: something that holds a user's identity and acts
// with it, but must not inherit that user's authority.
//
// An agent obtains its token through RFC 8693 token exchange, so the token it
// presents has `sub` = the human and `azp` = the agent. Every permission check
// would therefore pass exactly as if the human had made the call. What stops
// that is the delegation check: a separate, expiring grant naming this agent
// and this capability (see decision.Pipeline).
//
// Registering agents here rather than sniffing the token is the same decision
// as for system principals: "is this an agent" is a deployment fact, and a
// heuristic that guesses wrong in the permissive direction is a bypass.
type Agent struct {
	// Name is the OAuth client id and must equal the token `azp`.
	Name string `yaml:"name"`
	// Object is the gerege/agent object id.
	Object string `yaml:"object"`
	// Workload is the SPIFFE identity of the process that runs this agent.
	//
	// It binds the two halves that were previously checked independently: the
	// workload (non-forgeable, from mTLS) and the actor (a bearer claim). A
	// process registered here may present *only* this agent's token — it cannot
	// decline to exchange and act as the application whose token it was handed,
	// which would bypass delegation and step-up entirely.
	//
	// Empty means unbound, which is permitted but should be rare: it leaves the
	// agent's token acceptable from any workload.
	Workload string `yaml:"workload"`
	// DisplayName is shown on the delegation screen.
	DisplayName string `yaml:"displayName"`
}

// Rule maps a request to an authorization question (mvp_docs/04 §4).
type Rule struct {
	ID      string   `yaml:"id"`
	Hosts   []string `yaml:"hosts"`
	Methods []string `yaml:"methods"`
	// Path supports {named} parameters and a single trailing * wildcard.
	Path string `yaml:"path"`

	// Public marks a route that carries no user data and needs no principal:
	// static assets, an unauthenticated landing page. It is still a rule —
	// there is no implicit allow anywhere (M-006).
	Public bool `yaml:"public"`

	// AuthenticatedOnly marks a route that needs an established principal but
	// touches no resource: a dashboard shell that owns nothing and renders
	// only what its own authorized sub-requests return.
	//
	// This is the honest way to express "authentication without authorization".
	// The alternative — inventing a resource for such a page — would put a
	// meaningless permission in the model and make the schema harder to read
	// than the thing it describes.
	AuthenticatedOnly bool `yaml:"authenticatedOnly"`

	ResourceType string `yaml:"resourceType"`
	// ResourceIDFrom is `path:<param>`, `principal`, or `literal:<id>`.
	ResourceIDFrom string `yaml:"resourceIdFrom"`
	Permission     string `yaml:"permission"`

	Capability      string `yaml:"capability"`
	ConsentRequired bool   `yaml:"consentRequired"`

	// StepUp marks a capability sensitive enough to require a human who
	// authenticated recently and deliberately.
	//
	// An agent can never satisfy it. That is the point rather than a
	// limitation: an agent holding a delegated token cannot re-authenticate the
	// person behind it, so a route that demands fresh human authentication is
	// exactly a route an agent must not walk through alone. The denial carries a
	// challenge for the human to act on
	// (docs/09 §5.4 — step-up for sensitive capabilities).
	StepUp bool `yaml:"stepUp"`
	// StepUpMinACR is the lowest acceptable `acr` claim when StepUp is set.
	// Keycloak issues acr=1 for an active authentication and acr=0 when a
	// request is answered from an existing SSO session without re-prompting.
	StepUpMinACR int `yaml:"stepUpMinAcr"`

	// AuthMode is session | bearer | either.
	AuthMode string `yaml:"authMode"`
	// Consistency is fully_consistent | at_least_as_fresh.
	Consistency string `yaml:"consistency"`

	// Callers is the set of SPIFFE identities permitted to make this call
	// (mvp_docs/04 R6). Empty means the route is an entry point reached from
	// outside the mesh, where there is no peer identity to verify.
	Callers []string `yaml:"callers"`

	// specificity is computed at load time; see routes.Match.
	specificity int `yaml:"-"`
}

func (r *Rule) Specificity() int     { return r.specificity }
func (r *Rule) SetSpecificity(n int) { r.specificity = n }

const (
	AuthModeSession = "session"
	AuthModeBearer  = "bearer"
	AuthModeEither  = "either"

	ConsistencyFull  = "fully_consistent"
	ConsistencyFresh = "at_least_as_fresh"
)

// Load reads and validates the configuration document.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	if c.Issuer.External == "" || c.Issuer.Internal == "" {
		return fmt.Errorf("issuer.external and issuer.internal are both required")
	}
	if c.DefaultAction != "DENY" {
		return fmt.Errorf("defaultAction must be DENY, got %q (M-006)", c.DefaultAction)
	}
	if c.Cookie.Name == "" {
		return fmt.Errorf("cookie.name is required")
	}
	if c.Cookie.TTL <= 0 {
		c.Cookie.TTL = 8 * time.Hour
	}
	if c.Cookie.PendTTL <= 0 {
		c.Cookie.PendTTL = 10 * time.Minute
	}
	if c.SpiceDB.Endpoint == "" {
		return fmt.Errorf("spicedb.endpoint is required")
	}
	if c.SpiceDB.Timeout <= 0 {
		c.SpiceDB.Timeout = 3 * time.Second
	}
	if len(c.Rules) == 0 {
		return fmt.Errorf("no rules configured: refusing to start (mvp_docs/04 §6)")
	}

	hostToApp := map[string]string{}
	for i := range c.Applications {
		a := &c.Applications[i]
		if a.Name == "" {
			return fmt.Errorf("applications[%d]: name is required", i)
		}
		if len(a.Hosts) == 0 && a.ClientSecret == "" {
			return fmt.Errorf("application %q: needs hosts or a clientSecret", a.Name)
		}
		for _, h := range a.Hosts {
			if prev, dup := hostToApp[h]; dup {
				return fmt.Errorf("host %q is claimed by both %q and %q", h, prev, a.Name)
			}
			hostToApp[h] = a.Name
		}
	}

	seen := map[string]bool{}
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.ID == "" {
			return fmt.Errorf("rules[%d]: id is required", i)
		}
		if seen[r.ID] {
			return fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		if r.Path == "" || !strings.HasPrefix(r.Path, "/") {
			return fmt.Errorf("rule %q: path must start with /", r.ID)
		}
		if r.AuthMode == "" {
			r.AuthMode = AuthModeEither
		}
		switch r.AuthMode {
		case AuthModeSession, AuthModeBearer, AuthModeEither:
		default:
			return fmt.Errorf("rule %q: unknown authMode %q", r.ID, r.AuthMode)
		}
		if r.Consistency == "" {
			r.Consistency = ConsistencyFresh
		}
		switch r.Consistency {
		case ConsistencyFull, ConsistencyFresh:
		default:
			// minimize_latency is excluded from the MVP entirely
			// (mvp_docs/03 §6): it would make revocation assertions flaky.
			return fmt.Errorf("rule %q: unsupported consistency %q", r.ID, r.Consistency)
		}
		if r.Public && r.AuthenticatedOnly {
			return fmt.Errorf("rule %q: public and authenticatedOnly are mutually exclusive", r.ID)
		}
		if r.Public || r.AuthenticatedOnly {
			if r.ResourceType != "" || r.Permission != "" || r.ConsentRequired {
				return fmt.Errorf("rule %q: %s rules must not declare a permission or consent",
					r.ID, map[bool]string{true: "public", false: "authenticatedOnly"}[r.Public])
			}
			continue
		}
		if r.ResourceType == "" || r.Permission == "" || r.ResourceIDFrom == "" {
			return fmt.Errorf("rule %q: resourceType, resourceIdFrom and permission are required", r.ID)
		}
		if !strings.HasPrefix(r.ResourceIDFrom, "path:") &&
			r.ResourceIDFrom != "principal" &&
			!strings.HasPrefix(r.ResourceIDFrom, "literal:") {
			return fmt.Errorf("rule %q: resourceIdFrom must be path:<param>, principal or literal:<id>", r.ID)
		}
		if r.ConsentRequired && r.Capability == "" {
			return fmt.Errorf("rule %q: consentRequired needs a capability", r.ID)
		}
		if r.StepUp {
			if r.Capability == "" {
				return fmt.Errorf("rule %q: stepUp needs a capability to name in the challenge", r.ID)
			}
			if r.StepUpMinACR == 0 {
				r.StepUpMinACR = 1
			}
		}
	}
	return nil
}

// AppForHost returns the application that serves a browser-facing hostname.
func (c *Config) AppForHost(host string) (*Application, bool) {
	host = strings.ToLower(strings.Split(host, ":")[0])
	for i := range c.Applications {
		for _, h := range c.Applications[i].Hosts {
			if strings.ToLower(h) == host {
				return &c.Applications[i], true
			}
		}
	}
	return nil, false
}

// AgentByWorkload returns the agent a calling workload is bound to run.
func (c *Config) AgentByWorkload(spiffeID string) (*Agent, bool) {
	if spiffeID == "" {
		return nil, false
	}
	for i := range c.Agents {
		if c.Agents[i].Workload != "" && c.Agents[i].Workload == spiffeID {
			return &c.Agents[i], true
		}
	}
	return nil, false
}

// AgentByClient returns the agent registered under an `azp` value.
func (c *Config) AgentByClient(clientID string) (*Agent, bool) {
	for i := range c.Agents {
		if c.Agents[i].Name == clientID {
			return &c.Agents[i], true
		}
	}
	return nil, false
}

// AppByName returns the application registered under an `azp` value.
func (c *Config) AppByName(name string) (*Application, bool) {
	for i := range c.Applications {
		if c.Applications[i].Name == name {
			return &c.Applications[i], true
		}
	}
	return nil, false
}
