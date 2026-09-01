// Package catalogue holds the human-facing description of capabilities,
// applications and agents: what each capability means in words, who may ask for
// it, and how long a delegation may last.
//
// It is separate from the authorizer's route configuration because it answers a
// different question. The route config says which permission guards an
// endpoint; this says what a person is agreeing to when they approve it. Both
// are data, and neither belongs in a compiled binary.
package catalogue

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Capability is one named thing a user can grant.
type Capability struct {
	ID      string `yaml:"id"`
	Display string `yaml:"display"`
	// Sensitive marks a capability that requires a person to authenticate
	// deliberately at the moment of use. It is the single source of truth for
	// step-up: a sensitive capability must be guarded by a route with
	// `stepUp: true`, and it is never offered for delegation to an agent.
	Sensitive bool `yaml:"sensitive"`
}

// Party is an application or an agent — something that can ask for capabilities.
type Party struct {
	Name     string   `yaml:"name"`
	Display  string   `yaml:"display"`
	Requests []string `yaml:"requests"`
}

// TTL is one delegation duration a person may choose.
type TTL struct {
	Label string        `yaml:"label"`
	Value time.Duration `yaml:"value"`
}

// Catalogue is the whole document.
type Catalogue struct {
	Capabilities   []Capability `yaml:"capabilities"`
	Applications   []Party      `yaml:"applications"`
	Agents         []Party      `yaml:"agents"`
	DelegationTTLs []TTL        `yaml:"delegationTTLs"`
}

// Load reads and validates the catalogue.
func Load(path string) (*Catalogue, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read catalogue: %w", err)
	}
	var c Catalogue
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse catalogue: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Catalogue) validate() error {
	if len(c.Capabilities) == 0 {
		return fmt.Errorf("no capabilities defined")
	}
	seen := map[string]bool{}
	for _, cap := range c.Capabilities {
		if cap.ID == "" || cap.Display == "" {
			return fmt.Errorf("capability %q: id and display are both required", cap.ID)
		}
		if seen[cap.ID] {
			return fmt.Errorf("duplicate capability %q", cap.ID)
		}
		seen[cap.ID] = true
	}
	for _, group := range [][]Party{c.Applications, c.Agents} {
		for _, p := range group {
			if p.Name == "" {
				return fmt.Errorf("a party is missing a name")
			}
			for _, id := range p.Requests {
				if !seen[id] {
					return fmt.Errorf("%s requests unknown capability %q", p.Name, id)
				}
			}
		}
	}
	if len(c.DelegationTTLs) == 0 {
		return fmt.Errorf("no delegation durations offered: a delegation must be able to expire")
	}
	for _, t := range c.DelegationTTLs {
		if t.Value <= 0 {
			return fmt.Errorf("delegation duration %q must be positive — there is no 'forever'", t.Label)
		}
	}
	return nil
}

// Describe returns the human wording for a capability, or the id if unknown.
func (c *Catalogue) Describe(id string) string {
	for _, cap := range c.Capabilities {
		if cap.ID == id {
			return cap.Display
		}
	}
	return id
}

// IsSensitive reports whether a capability requires step-up.
func (c *Catalogue) IsSensitive(id string) bool {
	for _, cap := range c.Capabilities {
		if cap.ID == id {
			return cap.Sensitive
		}
	}
	return false
}

// SensitiveIDs lists every capability that requires step-up.
func (c *Catalogue) SensitiveIDs() []string {
	var out []string
	for _, cap := range c.Capabilities {
		if cap.Sensitive {
			out = append(out, cap.ID)
		}
	}
	return out
}

// Application returns the named application.
func (c *Catalogue) Application(name string) (Party, bool) { return find(c.Applications, name) }

// Agent returns the named agent.
func (c *Catalogue) Agent(name string) (Party, bool) { return find(c.Agents, name) }

func find(ps []Party, name string) (Party, bool) {
	for _, p := range ps {
		if p.Name == name {
			return p, true
		}
	}
	return Party{}, false
}

// DisplayApplication names an application for a person.
func (c *Catalogue) DisplayApplication(name string) string { return display(c.Applications, name) }

// DisplayAgent names an agent for a person.
func (c *Catalogue) DisplayAgent(name string) string { return display(c.Agents, name) }

func display(ps []Party, name string) string {
	if p, ok := find(ps, name); ok && p.Display != "" {
		return p.Display
	}
	return name
}

// Delegatable is what an agent may actually be granted: everything it asks for,
// minus the sensitive capabilities.
//
// Computed rather than listed, so the offered set and the step-up boundary
// cannot drift apart. Offering to delegate something an agent can never use
// would be offering a grant that silently does nothing.
func (c *Catalogue) Delegatable(agent string) (allowed, refused []string) {
	p, ok := c.Agent(agent)
	if !ok {
		return nil, nil
	}
	for _, id := range p.Requests {
		if c.IsSensitive(id) {
			refused = append(refused, id)
			continue
		}
		allowed = append(allowed, id)
	}
	return allowed, refused
}
