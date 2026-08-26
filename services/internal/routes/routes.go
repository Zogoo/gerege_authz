// Package routes matches an incoming request to exactly one configured rule.
//
// mvp_docs/04 §4: matching stays linear — with this many routes it is not a
// bottleneck and it is far easier to debug when a demo misbehaves. Two rules
// keep the sample's documented hazards away:
//
//  1. Most specific rule wins, by explicit specificity rather than file order.
//  2. Static assets live under their own prefix with their own rule, so a
//     parameterised pattern can never capture them.
//
// Ambiguity — two rules with equal specificity that can match the same request
// — is a load-time error, not a runtime coin toss.
package routes

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gerege/idp-mvp/internal/config"
)

// Table is a compiled, specificity-ordered rule set.
type Table struct {
	rules []compiled
}

type compiled struct {
	rule     *config.Rule
	segments []segment
	wildcard bool // trailing "*"
	hosts    map[string]bool
	methods  map[string]bool
	score    int
}

type segment struct {
	literal string
	param   string // non-empty when the segment is {param}
}

// Compile builds the match table and rejects an ambiguous configuration.
func Compile(rules []config.Rule) (*Table, error) {
	t := &Table{}
	for i := range rules {
		c, err := compileRule(&rules[i])
		if err != nil {
			return nil, err
		}
		t.rules = append(t.rules, c)
	}
	sort.SliceStable(t.rules, func(i, j int) bool {
		return t.rules[i].score > t.rules[j].score
	})
	if err := t.checkAmbiguity(); err != nil {
		return nil, err
	}
	return t, nil
}

func compileRule(r *config.Rule) (compiled, error) {
	c := compiled{rule: r, hosts: map[string]bool{}, methods: map[string]bool{}}
	for _, h := range r.Hosts {
		c.hosts[strings.ToLower(h)] = true
	}
	for _, m := range r.Methods {
		c.methods[strings.ToUpper(m)] = true
	}

	path := strings.TrimSuffix(r.Path, "/")
	if path == "" {
		path = "/"
	}
	if strings.HasSuffix(path, "/*") {
		c.wildcard = true
		path = strings.TrimSuffix(path, "/*")
	} else if path == "/*" {
		c.wildcard = true
		path = ""
	}

	// Score: host scoping dominates, then literal segments, then parameters.
	// A trailing wildcard subtracts, so /static/* never beats /static/logo.png.
	score := 0
	if len(c.hosts) > 0 {
		score += 10000
	}
	if len(c.methods) > 0 {
		score += 1000
	}
	for _, raw := range strings.Split(strings.Trim(path, "/"), "/") {
		if raw == "" {
			continue
		}
		switch {
		case strings.HasPrefix(raw, "{") && strings.HasSuffix(raw, "}"):
			name := raw[1 : len(raw)-1]
			if name == "" {
				return c, fmt.Errorf("rule %q: empty path parameter", r.ID)
			}
			c.segments = append(c.segments, segment{param: name})
			score += 10
		case strings.ContainsAny(raw, "{}*"):
			return c, fmt.Errorf("rule %q: malformed path segment %q", r.ID, raw)
		default:
			c.segments = append(c.segments, segment{literal: raw})
			score += 100
		}
	}
	if c.wildcard {
		score -= 5
	}
	c.score = score
	r.SetSpecificity(score)
	return c, nil
}

func (t *Table) checkAmbiguity() error {
	for i := 0; i < len(t.rules); i++ {
		for j := i + 1; j < len(t.rules); j++ {
			a, b := t.rules[i], t.rules[j]
			if a.score != b.score {
				continue
			}
			if overlaps(a, b) {
				return fmt.Errorf("ambiguous configuration: rules %q and %q have equal specificity (%d) and can match the same request",
					a.rule.ID, b.rule.ID, a.score)
			}
		}
	}
	return nil
}

func overlaps(a, b compiled) bool {
	if !hostsOverlap(a, b) || !methodsOverlap(a, b) {
		return false
	}
	if len(a.segments) != len(b.segments) && !a.wildcard && !b.wildcard {
		return false
	}
	n := len(a.segments)
	if len(b.segments) < n {
		n = len(b.segments)
	}
	for i := 0; i < n; i++ {
		sa, sb := a.segments[i], b.segments[i]
		if sa.param != "" || sb.param != "" {
			continue
		}
		if sa.literal != sb.literal {
			return false
		}
	}
	return true
}

func hostsOverlap(a, b compiled) bool {
	if len(a.hosts) == 0 || len(b.hosts) == 0 {
		return true
	}
	for h := range a.hosts {
		if b.hosts[h] {
			return true
		}
	}
	return false
}

func methodsOverlap(a, b compiled) bool {
	if len(a.methods) == 0 || len(b.methods) == 0 {
		return true
	}
	for m := range a.methods {
		if b.methods[m] {
			return true
		}
	}
	return false
}

// Match returns the most specific rule for a request, plus its extracted path
// parameters. A false second return is a default-deny (`no_route_match`).
func (t *Table) Match(host, method, path string) (*config.Rule, map[string]string, bool) {
	host = strings.ToLower(strings.Split(host, ":")[0])
	method = strings.ToUpper(method)
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	parts := splitPath(path)

	for _, c := range t.rules {
		if len(c.hosts) > 0 && !c.hosts[host] {
			continue
		}
		if len(c.methods) > 0 && !c.methods[method] {
			continue
		}
		params, ok := matchSegments(c, parts)
		if !ok {
			continue
		}
		return c.rule, params, true
	}
	return nil, nil, false
}

func splitPath(p string) []string {
	out := []string{}
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func matchSegments(c compiled, parts []string) (map[string]string, bool) {
	if c.wildcard {
		if len(parts) < len(c.segments) {
			return nil, false
		}
	} else if len(parts) != len(c.segments) {
		return nil, false
	}
	params := map[string]string{}
	for i, seg := range c.segments {
		if seg.param != "" {
			params[seg.param] = parts[i]
			continue
		}
		if seg.literal != parts[i] {
			return nil, false
		}
	}
	return params, true
}
