package routes

import (
	"strings"
	"testing"

	"github.com/gerege/idp-mvp/internal/config"
)

// TestStaticAssetsAreNotCapturedByParameterisedPatterns is mvp_docs/06 hazard 3
// and mvp_docs/07 §5 item 5: the cityos README documents an over-broad
// `/:user/:attribute` pattern swallowing static asset paths. Specificity
// ordering is what stops it here.
func TestStaticAssetsAreNotCapturedByParameterisedPatterns(t *testing.T) {
	table := compile(t,
		config.Rule{ID: "broad", Path: "/{user}/{attribute}", ResourceType: "x", Permission: "p", ResourceIDFrom: "path:user"},
		config.Rule{ID: "assets", Path: "/static/*", Public: true},
	)
	r, _, ok := table.Match("profile.local.test", "GET", "/static/app.css")
	if !ok || r.ID != "assets" {
		t.Fatalf("matched %v, want the static asset rule", ruleID(r, ok))
	}
	r, params, ok := table.Match("profile.local.test", "GET", "/alice/email")
	if !ok || r.ID != "broad" {
		t.Fatalf("matched %v, want the parameterised rule", ruleID(r, ok))
	}
	if params["user"] != "alice" || params["attribute"] != "email" {
		t.Errorf("params = %v", params)
	}
}

func TestMostSpecificRuleWinsRegardlessOfFileOrder(t *testing.T) {
	// Declared least-specific first on purpose.
	table := compile(t,
		config.Rule{ID: "any-device", Path: "/internal/devices/{id}/{action}", ResourceType: "x", Permission: "operate", ResourceIDFrom: "path:id"},
		config.Rule{ID: "unlock", Path: "/internal/devices/{id}/unlock", ResourceType: "x", Permission: "operate_lock", ResourceIDFrom: "path:id"},
	)
	r, _, ok := table.Match("device-service", "POST", "/internal/devices/lock-1/unlock")
	if !ok || r.ID != "unlock" {
		t.Fatalf("matched %v, want unlock — a lock must not fall through to the generic rule", ruleID(r, ok))
	}
	if r.Permission != "operate_lock" {
		t.Errorf("permission = %q, want operate_lock", r.Permission)
	}
}

func TestHostScopingSeparatesIdenticalPaths(t *testing.T) {
	table := compile(t,
		config.Rule{ID: "profile-home", Hosts: []string{"profile.local.test"}, Path: "/", Public: true},
		config.Rule{ID: "smarthome-home", Hosts: []string{"smarthome.local.test"}, Path: "/", Public: true},
	)
	for host, want := range map[string]string{
		"profile.local.test":      "profile-home",
		"smarthome.local.test":    "smarthome-home",
		"profile.local.test:8080": "profile-home",
	} {
		r, _, ok := table.Match(host, "GET", "/")
		if !ok || r.ID != want {
			t.Errorf("host %s matched %v, want %s", host, ruleID(r, ok), want)
		}
	}
}

// TestAmbiguityIsRejectedAtLoadTime — two rules that can match the same request
// with equal specificity is a configuration bug. Finding it at startup beats
// finding it when a demo behaves differently on two runs.
func TestAmbiguityIsRejectedAtLoadTime(t *testing.T) {
	_, err := Compile([]config.Rule{
		{ID: "a", Path: "/api/{x}", ResourceType: "t", Permission: "p", ResourceIDFrom: "path:x"},
		{ID: "b", Path: "/api/{y}", ResourceType: "t", Permission: "p", ResourceIDFrom: "path:y"},
	})
	if err == nil {
		t.Fatal("expected an ambiguity error")
	}
	if !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("error = %v, want it to mention ambiguity", err)
	}
}

func TestUnmatchedRequestReturnsNoRule(t *testing.T) {
	table := compile(t, config.Rule{ID: "only", Path: "/known", Public: true})
	if _, _, ok := table.Match("h", "GET", "/unknown"); ok {
		t.Fatal("an unconfigured endpoint matched a rule — default-deny is broken")
	}
}

func TestMethodScoping(t *testing.T) {
	table := compile(t,
		config.Rule{ID: "read", Methods: []string{"GET"}, Path: "/api/profile/{id}", ResourceType: "t", Permission: "view", ResourceIDFrom: "path:id"},
		config.Rule{ID: "write", Methods: []string{"PUT"}, Path: "/api/profile/{id}", ResourceType: "t", Permission: "edit", ResourceIDFrom: "path:id"},
	)
	r, _, _ := table.Match("h", "PUT", "/api/profile/alice")
	if r == nil || r.Permission != "edit" {
		t.Fatalf("PUT matched %v, want the edit rule", ruleID(r, r != nil))
	}
	r, _, _ = table.Match("h", "GET", "/api/profile/alice")
	if r == nil || r.Permission != "view" {
		t.Fatalf("GET matched %v, want the view rule", ruleID(r, r != nil))
	}
}

func compile(t *testing.T, rules ...config.Rule) *Table {
	t.Helper()
	table, err := Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	return table
}

func ruleID(r *config.Rule, ok bool) string {
	if !ok || r == nil {
		return "<no match>"
	}
	return r.ID
}
