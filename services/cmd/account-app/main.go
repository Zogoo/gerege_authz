// Command account-app is the consent and account console.
//
// It exists because consent has to be granted by a person, and because
// ext-authz must stay read-only on SpiceDB. Writing consent from the request
// path would put a mutation inside the component that also decides — the one
// place where a handler bug becomes privilege escalation (mvp_docs/04 §1).
// Keeping the write path in a separate process with its own identity makes that
// class of bug structurally impossible rather than merely unlikely.
//
// mvp_docs/03 §7: no consent relationships are seeded. Consent must be granted
// live, here, or Scenario 3a has nothing to show.
package main

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/gerege/idp-mvp/internal/logx"
	"github.com/gerege/idp-mvp/internal/spicedb"
	"github.com/gerege/idp-mvp/internal/svc"
	"github.com/gerege/idp-mvp/internal/webui"
)

// capabilityCatalogue turns an object id into something a person can decide
// about. mvp_docs/03 §2 keeps capabilities as SpiceDB objects so that adding
// one is data rather than a schema rollout; the wording that goes in front of
// the user lives here, next to the screen that shows it.
var capabilityCatalogue = map[string]string{
	"profile_read":    "See your name, email, phone and address",
	"profile_write":   "Update your address and phone number",
	"devices_view":    "See the devices in your home and their state",
	"devices_control": "Turn your devices on and off",
	"devices_unlock":  "Lock and unlock your doors",
}

// applicationCatalogue names the consent counterparty. Alice consents to
// "Smart Home", the product — not to a pod (docs/09 §2).
var applicationCatalogue = map[string]string{
	"smarthome-app": "Smart Home",
	"profile-app":   "Profile App",
	"account-app":   "Account Console",
}

// bundles are what an application asks for when a user starts from the account
// page rather than from a challenge.
var bundles = map[string][]string{
	"smarthome-app": {"profile_read", "devices_view", "devices_control", "devices_unlock"},
}

// agentCatalogue names the delegated actors a user can grant authority to.
var agentCatalogue = map[string]string{"assistant": "Assistant"}

// agentBundles are the capabilities an agent may be delegated. devices_unlock
// is absent on purpose: it is a step-up capability, and a route that requires a
// person to authenticate is one an agent must not be able to walk through, so
// offering to delegate it would be offering something that cannot work.
var agentBundles = map[string][]string{
	"assistant": {"profile_read", "devices_view", "devices_control"},
}

// delegationTTLs are the durations a person can choose from. There is no
// "forever" — a delegation that does not expire is a standing privilege, which
// is the failure mode the whole mechanism exists to prevent.
var delegationTTLs = []struct {
	Label string
	TTL   time.Duration
}{
	{"5 minutes", 5 * time.Minute},
	{"1 hour", time.Hour},
	{"8 hours", 8 * time.Hour},
}

var writer *spicedb.Writer

func main() {
	w, err := spicedb.NewWriter(
		svc.Env("SPICEDB_ENDPOINT", "spicedb.id.svc.cluster.local:50051"),
		svc.Env("SPICEDB_TOKEN", "gerege-mvp-key"),
		svc.Env("SPICEDB_INSECURE", "true") == "true",
		5*time.Second,
	)
	if err != nil {
		logx.Error("cannot connect to SpiceDB", "err", err.Error())
		panic(err)
	}
	writer = w
	defer writer.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", account)
	mux.HandleFunc("/consent", consent)
	mux.HandleFunc("/grant", grant)
	mux.HandleFunc("/revoke", revoke)
	mux.HandleFunc("/delegate", delegateScreen)
	mux.HandleFunc("/delegations", createDelegation)
	mux.HandleFunc("/undelegate", withdrawDelegation)
	svc.Run("account-app", svc.Env("ADDR", ":8080"), svc.Env("HEALTH_ADDR", ":8081"), mux)
}

func account(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	id := webui.From(r)
	grants, err := writer.Grants(r.Context(), id.UserID)
	if err != nil {
		svc.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if strings.Contains(r.Header.Get("accept"), "application/json") {
		svc.WriteJSON(w, http.StatusOK, grants)
		return
	}

	var body strings.Builder
	if len(grants) == 0 {
		body.WriteString(`<p>You have not granted any application access to your data.</p>
<p class="note">Nothing is seeded here on purpose. Until a grant exists, the smart-home
application is refused with reason <code>consent_required</code> — which is the state
Scenario 3a starts from.</p>`)
	} else {
		sort.Slice(grants, func(i, j int) bool { return grants[i].Application < grants[j].Application })
		body.WriteString(`<table><tr><th>Application</th><th>Granted</th><th></th></tr>`)
		for _, g := range grants {
			sort.Strings(g.Capabilities)
			var caps strings.Builder
			for _, c := range g.Capabilities {
				fmt.Fprintf(&caps, `<div>%s <span class="tag">%s</span></div>`,
					webui.Esc(describe(c)), webui.Esc(c))
			}
			fmt.Fprintf(&body, `<tr><td>%s</td><td>%s</td>
<td><form method="post" action="/revoke"><input type="hidden" name="application" value="%s">
<button class="danger">Revoke all</button></form></td></tr>`,
				webui.Esc(displayApp(g.Application)), caps.String(), webui.Esc(g.Application))
		}
		body.WriteString(`</table><p class="note">Revoking deletes relationships. The next request
from that application is refused — no restart, no redeploy, no token reissue.</p>`)
	}

	dels, err := writer.Delegations(r.Context(), id.UserID)
	if err != nil {
		svc.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	var agentBody strings.Builder
	if len(dels) == 0 {
		agentBody.WriteString(`<p>No agent currently holds authority from you.</p>
<p class="note">Consent and delegation are separate on purpose. Consent says an application
may ever touch your data; a delegation says an agent may act right now, for a while. An agent
holding your token and your consent still cannot do anything you have not delegated.</p>`)
	} else {
		sort.Slice(dels, func(i, j int) bool { return dels[i].Agent < dels[j].Agent })
		agentBody.WriteString(`<table><tr><th>Agent</th><th>May do</th><th>Expires</th><th></th></tr>`)
		for _, d := range dels {
			sort.Slice(d.Capabilities, func(i, j int) bool { return d.Capabilities[i].Capability < d.Capabilities[j].Capability })
			var caps strings.Builder
			var soonest time.Time
			for _, c := range d.Capabilities {
				fmt.Fprintf(&caps, `<div>%s <span class="tag">%s</span></div>`,
					webui.Esc(describe(c.Capability)), webui.Esc(c.Capability))
				if soonest.IsZero() || c.ExpiresAt.Before(soonest) {
					soonest = c.ExpiresAt
				}
			}
			fmt.Fprintf(&agentBody, `<tr><td>%s</td><td>%s</td><td>%s</td>
<td><form method="post" action="/undelegate"><input type="hidden" name="agent" value="%s">
<button class="danger">Withdraw</button></form></td></tr>`,
				webui.Esc(displayAgent(d.Agent)), caps.String(), webui.Esc(remaining(soonest)),
				webui.Esc(d.Agent))
		}
		agentBody.WriteString(`</table><p class="note">These expire by themselves. Nothing has to
remember to remove them, which is what stops a task grant from quietly becoming a standing one.</p>`)
	}
	agentBody.WriteString(webui.Links("/delegate?agent=assistant", "Delegate to the Assistant →"))

	page := webui.Card("Applications with access to your data", body.String())
	page += webui.Card("Agents acting on your behalf", agentBody.String())
	page += webui.Card("Grant access", fmt.Sprintf(
		`<p>You can also grant consent before an application asks for it.</p>%s`,
		webui.Links("/consent?application=smarthome-app", "Review Smart Home's request →")))
	page += webui.Links(
		svc.Env("PROFILE_APP_URL", "http://profile.local.test"), "Profile app",
		svc.Env("SMARTHOME_URL", "http://smarthome.local.test"), "Smart Home",
		"/_id/logout", "Sign out")

	webui.Page(w, "Account & Consent", "identity plane", id, page)
}

func consent(w http.ResponseWriter, r *http.Request) {
	id := webui.From(r)
	q := r.URL.Query()
	app := q.Get("application")
	if app == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	requested := bundles[app]
	if c := q.Get("capability"); c != "" && !contains(requested, c) {
		requested = append([]string{c}, requested...)
	}
	if len(requested) == 0 {
		requested = []string{q.Get("capability")}
	}
	returnTo := q.Get("return_to")

	var checks strings.Builder
	for _, c := range requested {
		if c == "" {
			continue
		}
		checked := ""
		if c == q.Get("capability") || q.Get("capability") == "" {
			checked = " checked"
		}
		fmt.Fprintf(&checks, `<label style="display:block;margin:7px 0">
<input type="checkbox" name="capability" value="%s"%s> %s <span class="tag">%s</span></label>`,
			webui.Esc(c), checked, webui.Esc(describe(c)), webui.Esc(c))
	}

	body := webui.Card(displayApp(app)+" is asking for access", fmt.Sprintf(
		`<p><strong>%s</strong> wants to access your data. Choose what to allow.</p>
<form method="post" action="/grant">
<input type="hidden" name="application" value="%s">
<input type="hidden" name="return_to" value="%s">
%s
<div class="row" style="margin-top:14px">
<button class="primary" type="submit">Allow</button>
<a class="btn" href="/">Cancel</a></div></form>
<p class="note">Approving writes relationships into SpiceDB. It does not change your token:
the very same access token that was refused a moment ago will now be accepted, because consent
is evaluated at the resource rather than carried in the credential.</p>`,
		webui.Esc(displayApp(app)), webui.Esc(app), webui.Esc(returnTo), checks.String()))

	webui.Page(w, "Consent", "identity plane", id, body)
}

func delegateScreen(w http.ResponseWriter, r *http.Request) {
	id := webui.From(r)
	q := r.URL.Query()
	agent := q.Get("agent")
	if agent == "" {
		agent = "assistant"
	}
	requested := agentBundles[agent]
	asked := q.Get("capability")

	var checks strings.Builder
	offered := false
	for _, c := range requested {
		checked := ""
		if c == asked || asked == "" {
			checked = " checked"
		}
		offered = true
		fmt.Fprintf(&checks, `<label style="display:block;margin:7px 0">
<input type="checkbox" name="capability" value="%s"%s> %s <span class="tag">%s</span></label>`,
			webui.Esc(c), checked, webui.Esc(describe(c)), webui.Esc(c))
	}

	body := webui.Card(displayAgent(agent)+" is asking to act for you", fmt.Sprintf(
		`<p>An agent acts with <strong>your</strong> identity. Everything below is something you
can already do yourself — delegating decides which of it the agent may do, and for how long.</p>
<form method="post" action="/delegations">
<input type="hidden" name="agent" value="%s">
<input type="hidden" name="return_to" value="%s">
%s
<div style="margin:14px 0 4px"><strong>Expires after</strong></div>
%s
<div class="row" style="margin-top:14px">
<button class="primary" type="submit">Delegate</button>
<a class="btn" href="/">Cancel</a></div></form>`,
		webui.Esc(agent), webui.Esc(q.Get("return_to")), checks.String(), ttlChooser()))

	if asked != "" && !contains(requested, asked) {
		body += webui.Card("Not available to delegate", fmt.Sprintf(
			`<p>%s The agent asked for <code>%s</code>, which cannot be delegated: it requires a
person to authenticate at the moment of use, and an agent cannot re-authenticate you.</p>
<p class="note">This is the step-up boundary. It is not that the agent is untrusted — it is that
"a human must be present for this one" and "an agent may do this alone" cannot both be true.
Do it yourself in the smart-home app.</p>`,
			webui.Pill("warn", "step-up required"), webui.Esc(asked)))
	}
	if !offered {
		body += webui.Card("Nothing to delegate", `<p>This agent has no delegatable capabilities.</p>`)
	}

	webui.Page(w, "Delegate", "identity plane", id, body)
}

func ttlChooser() string {
	var b strings.Builder
	b.WriteString(`<div class="row">`)
	for i, t := range delegationTTLs {
		checked := ""
		if i == 0 {
			checked = " checked"
		}
		fmt.Fprintf(&b, `<label><input type="radio" name="ttl" value="%s"%s> %s</label>`,
			t.TTL.String(), checked, webui.Esc(t.Label))
	}
	b.WriteString(`</div>`)
	return b.String()
}

func createDelegation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		svc.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := r.ParseForm(); err != nil {
		svc.WriteError(w, http.StatusBadRequest, "malformed form")
		return
	}
	id := webui.From(r)
	agent := r.FormValue("agent")
	caps := r.Form["capability"]
	if agent == "" || len(caps) == 0 {
		svc.WriteError(w, http.StatusBadRequest, "agent and at least one capability are required")
		return
	}
	// Only what this agent is allowed to be asked for. A form field is not a
	// place to widen an agent's reach.
	allowed := agentBundles[agent]
	for _, c := range caps {
		if !contains(allowed, c) {
			svc.WriteError(w, http.StatusBadRequest, "capability cannot be delegated: "+c)
			return
		}
	}
	ttl, err := time.ParseDuration(r.FormValue("ttl"))
	if err != nil || ttl <= 0 || ttl > 24*time.Hour {
		ttl = delegationTTLs[0].TTL
	}

	// The delegator is always the authenticated principal, exactly as for
	// consent. Nobody delegates on anybody else's behalf.
	expires, err := writer.Delegate(r.Context(), id.UserID, agent, caps, ttl)
	if err != nil {
		logx.Error("delegation failed", "err", err.Error(), "principal", id.UserID, "agent", agent)
		svc.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	logx.Info("delegated", "principal", id.UserID, "agent", agent,
		"capabilities", strings.Join(caps, ","), "expires", expires.Format(time.RFC3339))

	if rt := r.FormValue("return_to"); isSafeReturn(rt) {
		http.Redirect(w, r, rt, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func withdrawDelegation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		svc.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := r.ParseForm(); err != nil {
		svc.WriteError(w, http.StatusBadRequest, "malformed form")
		return
	}
	id := webui.From(r)
	agent := r.FormValue("agent")
	if agent == "" {
		svc.WriteError(w, http.StatusBadRequest, "agent is required")
		return
	}
	if err := writer.Undelegate(r.Context(), id.UserID, agent, r.Form["capability"]...); err != nil {
		logx.Error("withdraw failed", "err", err.Error(), "principal", id.UserID, "agent", agent)
		svc.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	logx.Info("delegation withdrawn", "principal", id.UserID, "agent", agent)
	http.Redirect(w, r, "/", http.StatusFound)
}

func displayAgent(a string) string {
	if d, ok := agentCatalogue[a]; ok {
		return d
	}
	return a
}

// remaining renders how long an agent's authority has left, which is the thing
// a person actually wants to know.
func remaining(t time.Time) string {
	if t.IsZero() {
		return "never — this should not happen"
	}
	d := time.Until(t).Round(time.Second)
	if d <= 0 {
		return "expired"
	}
	if d < time.Minute {
		return fmt.Sprintf("in %ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("in %dm", int(d.Minutes()))
	}
	return fmt.Sprintf("in %dh %dm", int(d.Hours()), int(d.Minutes())%60)
}

func grant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		svc.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := r.ParseForm(); err != nil {
		svc.WriteError(w, http.StatusBadRequest, "malformed form")
		return
	}
	id := webui.From(r)
	app := r.FormValue("application")
	caps := r.Form["capability"]
	if app == "" || len(caps) == 0 {
		svc.WriteError(w, http.StatusBadRequest, "application and at least one capability are required")
		return
	}
	// The subject is always the authenticated principal. A consent grant is
	// something a user makes for themselves; taking the subject from the form
	// would let anyone consent on anyone's behalf.
	if err := writer.Grant(r.Context(), id.UserID, app, caps); err != nil {
		logx.Error("consent grant failed", "err", err.Error(), "principal", id.UserID, "application", app)
		svc.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	logx.Info("consent granted", "principal", id.UserID, "application", app, "capabilities", strings.Join(caps, ","))

	if rt := r.FormValue("return_to"); isSafeReturn(rt) {
		http.Redirect(w, r, rt, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func revoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		svc.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := r.ParseForm(); err != nil {
		svc.WriteError(w, http.StatusBadRequest, "malformed form")
		return
	}
	id := webui.From(r)
	app := r.FormValue("application")
	if app == "" {
		svc.WriteError(w, http.StatusBadRequest, "application is required")
		return
	}
	if err := writer.Revoke(r.Context(), id.UserID, app, r.Form["capability"]...); err != nil {
		logx.Error("consent revoke failed", "err", err.Error(), "principal", id.UserID, "application", app)
		svc.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	logx.Info("consent revoked", "principal", id.UserID, "application", app)
	http.Redirect(w, r, "/", http.StatusFound)
}

// isSafeReturn keeps the consent screen from becoming an open redirect. Only
// the demo hosts are accepted, and only over the scheme they are served on.
func isSafeReturn(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	allowed := strings.Split(svc.Env("ALLOWED_RETURN_HOSTS",
		"profile.local.test,smarthome.local.test,account.local.test"), ",")
	for _, h := range allowed {
		if strings.EqualFold(strings.TrimSpace(h), u.Hostname()) {
			return true
		}
	}
	return false
}

func describe(capability string) string {
	if d, ok := capabilityCatalogue[capability]; ok {
		return d
	}
	return capability
}

func displayApp(app string) string {
	if d, ok := applicationCatalogue[app]; ok {
		return d
	}
	return app
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
