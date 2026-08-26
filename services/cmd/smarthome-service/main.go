// Command smarthome-service is the third-party application, and the one that
// makes the architecture worth its complexity.
//
// Everything it does, it does on Alice's behalf and through a second service.
// The dashboard is a shell; each panel is a separate call to device-service or
// profile-service, each one independently authorized at the callee's own
// sidecar. When a panel shows a denial, that denial was produced somewhere
// else, by a decision this process did not make and cannot override.
//
// Scenario 3b lives here: unlocking a door is authorized once at this service's
// edge — coarsely, "may this principal see this home at all" — and again at
// device-service, precisely, "may this principal unlock this particular lock".
// Downgrade Alice from owner to guest and the first check still passes while
// the second refuses. A gateway-only architecture would have opened the door.
package main

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"

	"github.com/gerege/idp-mvp/internal/svc"
	"github.com/gerege/idp-mvp/internal/webui"
)

var (
	deviceSvc  *svc.Upstream
	profileSvc *svc.Upstream
	agentSvc   *svc.Upstream
	homeID     = svc.Env("HOME_ID", "alice-home")
	account    = svc.Env("ACCOUNT_URL", "http://account.local.test")
	profileApp = svc.Env("PROFILE_APP_URL", "http://profile.local.test")
)

type device struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	State   string `json:"state"`
	Reading string `json:"reading,omitempty"`
}

func main() {
	deviceSvc = svc.NewUpstream(svc.Env("DEVICE_SERVICE_URL", "http://device-service.apps.svc.cluster.local"))
	profileSvc = svc.NewUpstream(svc.Env("PROFILE_SERVICE_URL", "http://profile-service.apps.svc.cluster.local"))
	agentSvc = svc.NewUpstream(svc.Env("AGENT_RUNNER_URL", "http://agent-runner.apps.svc.cluster.local"))

	mux := http.NewServeMux()
	mux.HandleFunc("/", dashboard)
	mux.HandleFunc("/home/", homeRoutes)
	mux.HandleFunc("/myprofile", myProfile)
	mux.HandleFunc("/assistant", assistant)
	svc.Run("smarthome-service", svc.Env("ADDR", ":8080"), svc.Env("HEALTH_ADDR", ":8081"), mux)
}

func dashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	id := webui.From(r)
	body := webui.Card("Your home", fmt.Sprintf(`<p>Devices and profile data are fetched from
other services. Each fetch is authorized independently at the service that owns the data.</p>%s`,
		webui.Links(
			"/home/"+homeID, "Devices",
			"/myprofile", "Read my profile via Smart Home",
			"/assistant", "Ask the Assistant",
			account, "Account &amp; consent",
			profileApp, "Profile app",
			"/_id/logout", "Sign out")))

	body += webui.Card("What to watch", `<p>Opening <strong>Read my profile via Smart Home</strong>
before granting consent produces a denial with reason <code>consent_required</code> and a link to
the consent screen. The profile application reads exactly the same record with no prompt at all.
Same user, same data, same permission — different application, different answer.</p>`)

	webui.Page(w, "Smart Home", "third-party", id, body)
}

func homeRoutes(w http.ResponseWriter, r *http.Request) {
	hid, rest := svc.PathTail(r.URL.Path, "/home")
	if hid == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	switch {
	case rest == "":
		listDevices(w, r, hid)
	case strings.HasPrefix(rest, "devices/"):
		parts := strings.Split(strings.TrimPrefix(rest, "devices/"), "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		deviceAction(w, r, hid, parts[0], parts[1])
	default:
		http.NotFound(w, r)
	}
}

func listDevices(w http.ResponseWriter, r *http.Request, hid string) {
	id := webui.From(r)
	res, err := deviceSvc.Do(r.Context(), r, http.MethodGet, "/internal/homes/"+hid+"/devices", nil)
	if err != nil {
		svc.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if wantsJSON(r) {
		relay(w, res)
		return
	}
	if !res.OK() {
		webui.Page(w, "Smart Home", "third-party", id, denialCard("Devices", res))
		return
	}
	var devices []device
	if err := res.JSON(&devices); err != nil {
		svc.WriteError(w, http.StatusBadGateway, "malformed upstream response")
		return
	}

	var rows strings.Builder
	rows.WriteString(`<table><tr><th>Device</th><th>Kind</th><th>State</th><th>Actions</th></tr>`)
	for _, d := range devices {
		actions := ""
		switch d.Kind {
		case "lock":
			actions = fmt.Sprintf(
				`<form method="post" action="/home/%s/devices/%s/unlock" style="display:inline">
<button class="primary">Unlock</button></form>
<form method="post" action="/home/%s/devices/%s/lock" style="display:inline">
<button>Lock</button></form>`,
				webui.Esc(hid), webui.Esc(d.ID), webui.Esc(hid), webui.Esc(d.ID))
		case "thermostat":
			actions = fmt.Sprintf(
				`<form method="post" action="/home/%s/devices/%s/state" style="display:inline">
<button>Set 23&deg;C</button></form>`, webui.Esc(hid), webui.Esc(d.ID))
		default:
			actions = `<span class="tag">telemetry only</span>`
		}
		state := webui.Esc(d.State)
		if d.Reading != "" {
			state += ` <span class="tag">` + webui.Esc(d.Reading) + `</span>`
		}
		fmt.Fprintf(&rows, `<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			webui.Esc(d.ID), webui.Esc(d.Kind), state, actions)
	}
	rows.WriteString(`</table><p class="note">Unlocking asks a stricter permission than
adjusting the thermostat: <code>operate_lock</code> derives from <code>administrate</code> on the
home, while <code>operate</code> also accepts a resident. A guest who may change the temperature
must not be able to open the front door.</p>`)

	webui.Page(w, "Smart Home", "third-party", id,
		webui.Card("Devices in "+webui.Esc(hid), rows.String())+webui.Links("/", "← Back"))
}

func deviceAction(w http.ResponseWriter, r *http.Request, hid, deviceID, action string) {
	id := webui.From(r)
	var (
		res svc.Result
		err error
	)
	switch action {
	case "unlock", "lock":
		res, err = deviceSvc.Do(r.Context(), r, http.MethodPost, "/internal/devices/"+deviceID+"/"+action, nil)
	case "state":
		res, err = deviceSvc.Do(r.Context(), r, http.MethodPost, "/internal/devices/"+deviceID+"/state",
			bytes.NewBufferString(`{"state":"23°C"}`))
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		svc.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if wantsJSON(r) {
		relay(w, res)
		return
	}
	if !res.OK() {
		webui.Page(w, "Smart Home", "third-party", id,
			denialCard("Denied at the internal hop", res)+webui.Links("/home/"+hid, "← Devices"))
		return
	}
	webui.Page(w, "Smart Home", "third-party", id, webui.Card("Done", fmt.Sprintf(
		`<p>%s <code>%s</code> on <code>%s</code>.</p>%s
<p class="note">Three authorization decisions were made for this click, at three
enforcement points: the ingress gateway, this service's sidecar, and device-service's
sidecar. Run <code>make decisions</code> to see all three.</p>%s`,
		webui.Pill("ok", "permitted"), webui.Esc(action), webui.Esc(deviceID),
		webui.Pre(string(res.Body)), webui.Links("/home/"+hid, "← Devices"))))
}

// assistant hands the task to an agent, which acts with Alice's identity but
// not with her authority. This service does nothing clever here: it forwards
// her token and renders whatever the agent reports back, refusals included.
func assistant(w http.ResponseWriter, r *http.Request) {
	id := webui.From(r)
	task := r.URL.Query().Get("task")
	if task == "" {
		task = "everything"
	}

	res, err := agentSvc.Do(r.Context(), r, http.MethodPost, "/agent/tasks/"+task, nil)
	if err != nil {
		svc.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if wantsJSON(r) {
		relay(w, res)
		return
	}
	if !res.OK() {
		webui.Page(w, "Smart Home", "third-party", id,
			denialCard("The Assistant could not act", res)+webui.Links("/", "← Back"))
		return
	}

	var t struct {
		Task      string `json:"task"`
		Principal string `json:"principal"`
		Agent     string `json:"agent"`
		Exchanged bool   `json:"token_exchanged"`
		Error     string `json:"error"`
		Steps     []struct {
			Action     string `json:"action"`
			Capability string `json:"capability"`
			Status     int    `json:"status"`
			Reason     string `json:"reason"`
			Detail     string `json:"detail"`
			Permitted  bool   `json:"permitted"`
		} `json:"steps"`
	}
	if err := res.JSON(&t); err != nil {
		svc.WriteError(w, http.StatusBadGateway, "malformed agent response")
		return
	}

	var rows strings.Builder
	rows.WriteString(`<table><tr><th>The agent tried</th><th>Capability</th><th>Outcome</th><th>Why</th></tr>`)
	for _, s := range t.Steps {
		pill := webui.Pill("no", "refused")
		if s.Permitted {
			pill = webui.Pill("ok", "permitted")
		} else if s.Reason == "delegation_required" || s.Reason == "step_up_required" {
			pill = webui.Pill("warn", strings.ReplaceAll(s.Reason, "_", " "))
		}
		fmt.Fprintf(&rows, `<tr><td>%s</td><td><span class="tag">%s</span></td><td>%s</td><td>%s</td></tr>`,
			webui.Esc(s.Action), webui.Esc(s.Capability), pill, webui.Esc(s.Detail))
	}
	rows.WriteString(`</table>`)

	body := webui.Card("What the Assistant did with your identity", fmt.Sprintf(
		`<dl><dt>Acting for</dt><dd>%s</dd><dt>Acting as</dt><dd>%s</dd>
<dt>Token exchanged</dt><dd>%v — RFC 8693</dd></dl>%s
<p class="note">The agent holds a token whose subject is you. Every permission check below
passed on <em>your</em> authority — what stopped the rest was the delegation check: a separate,
expiring grant naming this agent and this capability. Nothing about your own access changed.</p>`,
		webui.Esc(t.Principal), webui.Esc(t.Agent), t.Exchanged, rows.String()))

	body += webui.Card("Try it", webui.Links(
		"/assistant?task=everything", "Everything",
		"/assistant?task=read-profile", "Read profile",
		"/assistant?task=check-home", "Check home",
		"/assistant?task=set-thermostat", "Set thermostat",
		"/assistant?task=unlock-door", "Unlock the door",
		account+"/delegate?agent=assistant", "Delegate →",
		"/", "← Back"))

	webui.Page(w, "Smart Home", "third-party", id, body)
}

// myProfile is the consent demonstration. The smart-home application asks for
// the same record the profile application shows without a prompt.
func myProfile(w http.ResponseWriter, r *http.Request) {
	id := webui.From(r)
	userID := r.Header.Get("x-user-id")
	res, err := profileSvc.Do(r.Context(), r, http.MethodGet, "/api/profile/"+userID, nil)
	if err != nil {
		svc.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if wantsJSON(r) {
		relay(w, res)
		return
	}
	if !res.OK() {
		card := denialCard("Profile", res)
		if uri := res.ConsentURI(); uri != "" {
			card += webui.Card("Consent required", fmt.Sprintf(
				`<p>The authorizer returned a consent challenge rather than a bare refusal, so the
application knows where to send you.</p>%s`,
				webui.Links(uri, "Review and grant consent →")))
		}
		webui.Page(w, "Smart Home", "third-party", id, card+webui.Links("/", "← Back"))
		return
	}
	webui.Page(w, "Smart Home", "third-party", id, webui.Card("Profile", fmt.Sprintf(
		`<p>%s Consent was granted, so profile-service returned the record to this
third-party application.</p>%s<p class="note">Revoke consent in the account console and reload
this page: the next request is refused, with no restart and no redeploy.</p>%s`,
		webui.Pill("ok", "permitted"), webui.Pre(string(res.Body)),
		webui.Links(account, "Account console", "/", "← Back"))))
}

func denialCard(title string, res svc.Result) string {
	kind, label := "no", "denied"
	if res.Reason == "consent_required" {
		kind, label = "warn", "consent required"
	}
	return webui.Card(title, fmt.Sprintf(
		`<p>%s</p><dl><dt>Status</dt><dd>%d</dd><dt>Reason</dt><dd>%s</dd>
<dt>Detail</dt><dd>%s</dd></dl>`,
		webui.Pill(kind, label), res.Status, webui.Esc(res.Reason), webui.Esc(res.Detail())))
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("accept"), "application/json")
}

func relay(w http.ResponseWriter, res svc.Result) {
	w.Header().Set("content-type", "application/json")
	if res.Reason != "" {
		w.Header().Set("x-authz-reason", res.Reason)
	}
	w.WriteHeader(res.Status)
	_, _ = w.Write(res.Body)
}
