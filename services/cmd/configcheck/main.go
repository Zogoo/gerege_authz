// Command configcheck loads the route configuration exactly as ext-authz does
// and prints the rule each probe request would match.
//
// It exists because the most common operational failure in this architecture is
// an endpoint shipped without a rule (M-006), and the second most common is a
// rule that matches more than its author intended (mvp_docs/06 hazard 3). Both
// are cheap to catch before a deploy and expensive to diagnose after one.
//
// Exit status is non-zero if the configuration would stop ext-authz starting,
// so this runs in CI as well as by hand.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gerege/idp-mvp/internal/catalogue"
	"github.com/gerege/idp-mvp/internal/config"
	"github.com/gerege/idp-mvp/internal/routes"
)

// probes are the requests whose routing must not drift. Each one is a claim
// about the system that a reader can check in a second.
var probes = []struct {
	host, method, path, note string
}{
	{"profile.local.test", "GET", "/", "dashboard shell — authenticated, owns no resource"},
	{"profile.local.test", "GET", "/static/app.css", "asset rule must win over any parameterised pattern"},
	{"profile.local.test", "GET", "/profile/alice", "first-party read — consent declared but suppressed"},
	{"smarthome.local.test", "GET", "/myprofile", "third-party read of the same record — consent enforced"},
	{"smarthome.local.test", "GET", "/home/alice-home", "device list at the edge"},
	{"smarthome.local.test", "POST", "/home/alice-home/devices/lock-1/unlock", "edge check: coarse, on the home"},
	{"device-service.apps.svc.cluster.local", "POST", "/internal/devices/lock-1/unlock", "internal hop: operate_lock on the device"},
	{"device-service.apps.svc.cluster.local", "POST", "/internal/devices/thermostat-1/state", "thermostat needs only operate"},
	{"device.local.test", "POST", "/telemetry/sensor-1", "device identity — no consent, no peer identity, revocation immediate"},
	{"account.local.test", "POST", "/revoke", "consent revocation"},
	{"profile.local.test", "GET", "/undeclared", "no rule → default deny"},
	{"anything.example.com", "GET", "/internal/devices/lock-1", "unknown host still matches the unscoped device rule"},
	{"agent-runner.apps.svc.cluster.local", "POST", "/agent/tasks/everything", "asking the agent to act is itself authorized"},
	{"smarthome.local.test", "GET", "/assistant", "the assistant page"},
	{"account.local.test", "POST", "/delegations", "creating a delegation"},
}

func main() {
	path := "config/ext-authz.yaml"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	catPath := filepath.Join(filepath.Dir(path), "catalogue.yaml")
	if len(os.Args) > 2 {
		catPath = os.Args[2]
	}

	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration is not usable — ext-authz would refuse to start:")
		fmt.Fprintln(os.Stderr, "  "+err.Error())
		os.Exit(1)
	}
	table, err := routes.Compile(cfg.Rules)
	if err != nil {
		fmt.Fprintln(os.Stderr, "route table is not usable — ext-authz would refuse to start:")
		fmt.Fprintln(os.Stderr, "  "+err.Error())
		os.Exit(1)
	}

	fmt.Printf("%s\n", path)
	fmt.Printf("  defaultAction  %s\n", cfg.DefaultAction)
	fmt.Printf("  issuer         %s  (back-channel: %s)\n", cfg.Issuer.External, cfg.Issuer.Internal)
	fmt.Printf("  applications   %d   rules %d   system principals %d   agents %d\n",
		len(cfg.Applications), len(cfg.Rules), len(cfg.SystemPrincipals), len(cfg.Agents))
	for _, a := range cfg.Agents {
		fmt.Printf("  agent          azp %-18s → gerege/agent:%s\n", a.Name, a.Object)
	}
	var stepUp []string
	for i := range cfg.Rules {
		if cfg.Rules[i].StepUp {
			stepUp = append(stepUp, cfg.Rules[i].ID)
		}
	}
	if len(stepUp) > 0 {
		fmt.Printf("  step-up routes %s   (closed to agents by construction)\n", strings.Join(stepUp, ", "))
	}
	fmt.Println()

	fmt.Printf("%-8s %-38s %-46s %s\n", "METHOD", "HOST", "PATH", "RULE")
	fmt.Println(strings.Repeat("-", 128))
	failed := false
	for _, p := range probes {
		rule, params, ok := table.Match(p.host, p.method, p.path)
		if !ok {
			fmt.Printf("%-8s %-38s %-46s %s\n", p.method, p.host, p.path, "DENY (no_route_match)")
			fmt.Printf("%-8s %-38s %-46s   ↳ %s\n", "", "", "", p.note)
			continue
		}
		fmt.Printf("%-8s %-38s %-46s %s\n", p.method, p.host, p.path, describe(rule))
		fmt.Printf("%-8s %-38s %-46s   ↳ %s", "", "", "", p.note)
		if len(params) > 0 {
			fmt.Printf("   params=%v", params)
		}
		fmt.Println()
	}
	if !crossCheck(cfg, catPath) {
		os.Exit(1)
	}
	if failed {
		os.Exit(1)
	}
}

// crossCheck holds the two configuration documents to each other.
//
// `sensitive` in the catalogue and `stepUp` in the route config describe the
// same boundary from two sides: what a person is told requires their presence,
// and what the authorizer actually refuses without it. Nothing keeps them
// aligned except this check, and a capability marked sensitive but not enforced
// is a promise the system does not keep.
func crossCheck(cfg *config.Config, catPath string) bool {
	cat, err := catalogue.Load(catPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "\ncatalogue is not usable — the account console would refuse to start:")
		fmt.Fprintln(os.Stderr, "  "+err.Error())
		return false
	}

	guarded := map[string]bool{}
	declared := map[string]bool{}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if r.Capability != "" {
			declared[r.Capability] = true
		}
		if r.StepUp {
			guarded[r.Capability] = true
		}
	}

	ok := true
	fmt.Printf("\n%s\n", catPath)
	for _, cap := range cat.Capabilities {
		note := ""
		switch {
		case cap.Sensitive && !guarded[cap.ID]:
			note = "  ✗ marked sensitive but no route enforces stepUp"
			ok = false
		case !cap.Sensitive && guarded[cap.ID]:
			note = "  ✗ a route enforces stepUp but the catalogue does not call it sensitive"
			ok = false
		case cap.Sensitive:
			note = "  sensitive · step-up enforced · never delegatable"
		case !declared[cap.ID]:
			note = "  (no route uses this capability yet)"
		}
		fmt.Printf("  %-18s %s%s\n", cap.ID, cap.Display, note)
	}

	for _, a := range cat.Agents {
		allowed, refused := cat.Delegatable(a.Name)
		fmt.Printf("\n  agent %q may be delegated: %s\n", a.Name, strings.Join(allowed, ", "))
		if len(refused) > 0 {
			fmt.Printf("  agent %q may never be delegated: %s   (step-up)\n", a.Name, strings.Join(refused, ", "))
		}
	}
	if !ok {
		fmt.Fprintln(os.Stderr, "\nthe catalogue and the route configuration disagree about which capabilities are sensitive")
	}
	return ok
}

func describe(r *config.Rule) string {
	switch {
	case r.Public:
		return fmt.Sprintf("%s  [public, no principal]", r.ID)
	case r.AuthenticatedOnly:
		return fmt.Sprintf("%s  [authenticated, no resource]", r.ID)
	}
	s := fmt.Sprintf("%s  %s#%s", r.ID, r.ResourceType, r.Permission)
	if r.ConsentRequired {
		s += "  +consent:" + r.Capability
	}
	if r.StepUp {
		s += "  +stepUp"
	}
	if len(r.Callers) > 0 {
		s += fmt.Sprintf("  callers=%d", len(r.Callers))
	}
	return s
}
